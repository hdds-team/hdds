// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SQLite persistence backend
//!
//! Production-ready persistent storage with zero external dependencies.

use crate::store::{PersistenceStore, RetentionPolicy, Sample};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// SQLite persistence store
///
/// Stores DDS samples in a SQLite database with efficient indexing.
///
/// Thread-safe via internal Mutex (SQLite Connection is not Sync).
///
/// # Schema
///
/// ```sql
/// CREATE TABLE samples (
///     id INTEGER PRIMARY KEY AUTOINCREMENT,
///     topic TEXT NOT NULL,
///     type_name TEXT NOT NULL,
///     payload BLOB NOT NULL,
///     timestamp_ns INTEGER NOT NULL,
///     sequence INTEGER NOT NULL,
///     source_guid BLOB NOT NULL
/// );
/// CREATE INDEX idx_topic ON samples(topic);
/// CREATE INDEX idx_timestamp ON samples(timestamp_ns);
/// ```
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Create a new SQLite store with a file-based database
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open SQLite database at {}", path))?;

        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Create an in-memory SQLite store (for testing)
    pub fn new_in_memory() -> Result<Self> {
        let conn =
            Connection::open_in_memory().context("Failed to create in-memory SQLite database")?;

        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Initialize database schema
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                topic TEXT NOT NULL,
                type_name TEXT NOT NULL,
                payload BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                sequence INTEGER NOT NULL,
                source_guid BLOB NOT NULL
            )",
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_topic ON samples(topic)", [])?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON samples(timestamp_ns)",
            [],
        )?;

        Ok(())
    }

    /// Helper function to map a row to a Sample
    fn row_to_sample(row: &rusqlite::Row) -> rusqlite::Result<Sample> {
        let source_guid_blob: Vec<u8> = row.get(5)?;
        let mut source_guid = [0u8; 16];
        source_guid.copy_from_slice(&source_guid_blob);

        Ok(Sample {
            topic: row.get(0)?,
            type_name: row.get(1)?,
            payload: row.get(2)?,
            timestamp_ns: row.get::<_, i64>(3)? as u64,
            sequence: row.get::<_, i64>(4)? as u64,
            source_guid,
        })
    }
}

impl PersistenceStore for SqliteStore {
    fn save(&self, sample: &Sample) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO samples (topic, type_name, payload, timestamp_ns, sequence, source_guid)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                sample.topic,
                sample.type_name,
                sample.payload,
                sample.timestamp_ns as i64,
                sample.sequence as i64,
                &sample.source_guid[..],
            ],
        )?;

        Ok(())
    }

    fn load(&self, topic: &str) -> Result<Vec<Sample>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT topic, type_name, payload, timestamp_ns, sequence, source_guid
             FROM samples
             WHERE topic = ?1
             ORDER BY timestamp_ns ASC",
        )?;

        let samples = stmt
            .query_map([topic], Self::row_to_sample)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(samples)
    }

    fn query_range(&self, topic: &str, start_ns: u64, end_ns: u64) -> Result<Vec<Sample>> {
        let conn = self.conn.lock().unwrap();

        // Saturate to i64::MAX to avoid overflow (u64::MAX as i64 = -1)
        let start_i64 = start_ns.min(i64::MAX as u64) as i64;
        let end_i64 = end_ns.min(i64::MAX as u64) as i64;

        // Support wildcard matching: "State/*" matches "State/Temperature", etc.
        let prefix = topic.strip_suffix("/*");
        let query = if let Some(prefix) = prefix {
            format!(
                "SELECT topic, type_name, payload, timestamp_ns, sequence, source_guid
                 FROM samples
                 WHERE topic LIKE '{}/%' AND timestamp_ns BETWEEN ?1 AND ?2
                 ORDER BY timestamp_ns ASC",
                prefix
            )
        } else if topic == "*" {
            "SELECT topic, type_name, payload, timestamp_ns, sequence, source_guid
             FROM samples
             WHERE timestamp_ns BETWEEN ?1 AND ?2
             ORDER BY timestamp_ns ASC"
                .to_string()
        } else {
            "SELECT topic, type_name, payload, timestamp_ns, sequence, source_guid
             FROM samples
             WHERE topic = ?3 AND timestamp_ns BETWEEN ?1 AND ?2
             ORDER BY timestamp_ns ASC"
                .to_string()
        };

        let mut stmt = conn.prepare(&query)?;

        let rows = if prefix.is_some() || topic == "*" {
            stmt.query_map(params![start_i64, end_i64], Self::row_to_sample)?
        } else {
            stmt.query_map(params![start_i64, end_i64, topic], Self::row_to_sample)?
        };

        let samples = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(samples)
    }

    fn apply_retention(&self, topic: &str, keep_count: usize) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        // Delete old samples, keeping only the most recent `keep_count`
        conn.execute(
            "DELETE FROM samples
             WHERE topic = ?1
             AND id NOT IN (
                 SELECT id FROM samples
                 WHERE topic = ?1
                 ORDER BY timestamp_ns DESC
                 LIMIT ?2
             )",
            params![topic, keep_count],
        )?;

        Ok(())
    }

    fn apply_retention_policy(&self, topic: &str, policy: &RetentionPolicy) -> Result<()> {
        if policy.is_noop() {
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();

        if policy.keep_count > 0 {
            conn.execute(
                "DELETE FROM samples
                 WHERE topic = ?1
                 AND id NOT IN (
                     SELECT id FROM samples
                     WHERE topic = ?1
                     ORDER BY timestamp_ns DESC
                     LIMIT ?2
                 )",
                params![topic, policy.keep_count as i64],
            )?;
        }

        if let Some(max_age_ns) = policy.max_age_ns {
            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let cutoff = now_ns.saturating_sub(max_age_ns);
            let cutoff_i64 = cutoff.min(i64::MAX as u64) as i64;
            conn.execute(
                "DELETE FROM samples
                 WHERE topic = ?1 AND timestamp_ns < ?2",
                params![topic, cutoff_i64],
            )?;
        }

        if let Some(max_bytes) = policy.max_bytes {
            let ids_to_delete = {
                let mut stmt = conn.prepare(
                    "SELECT id, length(payload) FROM samples
                     WHERE topic = ?1
                     ORDER BY timestamp_ns DESC",
                )?;
                let rows = stmt.query_map([topic], |row| {
                    let id: i64 = row.get(0)?;
                    let len: i64 = row.get(1)?;
                    Ok((id, len))
                })?;

                let mut total = 0u64;
                let mut ids: Vec<i64> = Vec::new();
                for row in rows {
                    let (id, len) = row?;
                    let len_u64 = if len < 0 { 0 } else { len as u64 };
                    if total.saturating_add(len_u64) <= max_bytes {
                        total = total.saturating_add(len_u64);
                    } else {
                        ids.push(id);
                    }
                }
                ids
            };

            if !ids_to_delete.is_empty() {
                let tx = conn.transaction()?;
                {
                    let mut del = tx.prepare("DELETE FROM samples WHERE id = ?1")?;
                    for id in ids_to_delete {
                        del.execute([id])?;
                    }
                }
                tx.commit()?;
            }
        }

        Ok(())
    }

    fn count(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM samples", [], |row| row.get(0))?;

        Ok(count as usize)
    }

    fn clear(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM samples", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_store_save_and_load() {
        let store = SqliteStore::new_in_memory().unwrap();

        let sample = Sample {
            topic: "test/topic".to_string(),
            type_name: "TestType".to_string(),
            payload: vec![0x01, 0x02, 0x03],
            timestamp_ns: 1000,
            sequence: 1,
            source_guid: [0xAA; 16],
        };

        store.save(&sample).unwrap();

        let loaded = store.load("test/topic").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].topic, "test/topic");
        assert_eq!(loaded[0].sequence, 1);
    }

    #[test]
    fn test_sqlite_store_query_range() {
        let store = SqliteStore::new_in_memory().unwrap();

        for i in 0..10 {
            let sample = Sample {
                topic: "test/topic".to_string(),
                type_name: "TestType".to_string(),
                payload: vec![i as u8],
                timestamp_ns: i * 1000,
                sequence: i,
                source_guid: [0xBB; 16],
            };
            store.save(&sample).unwrap();
        }

        let range = store.query_range("test/topic", 2000, 5000).unwrap();
        assert_eq!(range.len(), 4); // timestamps 2000, 3000, 4000, 5000
        assert_eq!(range[0].sequence, 2);
        assert_eq!(range[3].sequence, 5);
    }

    #[test]
    fn test_sqlite_store_wildcard_query() {
        let store = SqliteStore::new_in_memory().unwrap();

        let topics = ["State/Temperature", "State/Pressure", "Command/Set"];

        for (i, topic) in topics.iter().enumerate() {
            let sample = Sample {
                topic: topic.to_string(),
                type_name: "TestType".to_string(),
                payload: vec![i as u8],
                timestamp_ns: 1000,
                sequence: i as u64,
                source_guid: [0xCC; 16],
            };
            store.save(&sample).unwrap();
        }

        let state_samples = store.query_range("State/*", 0, 10000).unwrap();
        assert_eq!(state_samples.len(), 2);

        let all_samples = store.query_range("*", 0, 10000).unwrap();
        assert_eq!(all_samples.len(), 3);
    }

    #[test]
    fn test_sqlite_store_retention() {
        let store = SqliteStore::new_in_memory().unwrap();

        for i in 0..10 {
            let sample = Sample {
                topic: "test/topic".to_string(),
                type_name: "TestType".to_string(),
                payload: vec![i as u8],
                timestamp_ns: i * 1000,
                sequence: i,
                source_guid: [0xDD; 16],
            };
            store.save(&sample).unwrap();
        }

        assert_eq!(store.count().unwrap(), 10);

        store.apply_retention("test/topic", 5).unwrap();
        assert_eq!(store.count().unwrap(), 5);

        let remaining = store.load("test/topic").unwrap();
        assert_eq!(remaining[0].sequence, 5); // oldest kept is sequence 5
    }

    #[test]
    fn test_sqlite_store_clear() {
        let store = SqliteStore::new_in_memory().unwrap();

        let sample = Sample {
            topic: "test/topic".to_string(),
            type_name: "TestType".to_string(),
            payload: vec![0x01],
            timestamp_ns: 1000,
            sequence: 1,
            source_guid: [0xEE; 16],
        };

        store.save(&sample).unwrap();
        assert_eq!(store.count().unwrap(), 1);

        store.clear().unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }
}
