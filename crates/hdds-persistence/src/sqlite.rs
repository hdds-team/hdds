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
///     source_guid BLOB NOT NULL,
///     representation INTEGER NOT NULL DEFAULT 2
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
                source_guid BLOB NOT NULL,
                representation INTEGER NOT NULL DEFAULT 2,
                instance_handle BLOB NOT NULL DEFAULT (X'00000000000000000000000000000000')
            )",
            [],
        )?;

        conn.execute("CREATE INDEX IF NOT EXISTS idx_topic ON samples(topic)", [])?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON samples(timestamp_ns)",
            [],
        )?;

        // Migration for a database created before `representation` existed
        // (the CREATE TABLE above is a no-op on it): add the column with
        // the same DEFAULT 2 (XCDR2) every pre-existing row then gets --
        // every such row was saved by a build before this column existed,
        // whose default writer (the 1.4.x line) resolved
        // and encoded XCDR2 at run time, NOT the DDS-XTypes spec's "empty
        // list" default a current build's default writer resolves to
        // instead (see Sample::representation). SQLite has no portable
        // "ADD COLUMN IF NOT EXISTS" across the versions this crate
        // supports, so check first and ignore nothing else.
        let has_representation_column = conn
            .prepare("SELECT representation FROM samples LIMIT 1")
            .is_ok();
        if !has_representation_column {
            conn.execute(
                "ALTER TABLE samples ADD COLUMN representation INTEGER NOT NULL DEFAULT 2",
                [],
            )
            .context("Failed to migrate samples table to add the representation column")?;
        }

        // Migration for a database created before `instance_handle`
        // existed: every pre-existing row gets the nil instance, the
        // single bucket it was already implicitly sharing with every
        // other sample of its topic (see Sample::instance_handle).
        let has_instance_handle_column = conn
            .prepare("SELECT instance_handle FROM samples LIMIT 1")
            .is_ok();
        if !has_instance_handle_column {
            conn.execute(
                "ALTER TABLE samples ADD COLUMN instance_handle BLOB NOT NULL \
                 DEFAULT (X'00000000000000000000000000000000')",
                [],
            )
            .context("Failed to migrate samples table to add the instance_handle column")?;
        }

        // Legacy rows have no known source timestamp or destination order.
        for (column, definition) in [
            ("source_timestamp_ns", "INTEGER"),
            ("destination_order_by_source", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            if conn
                .prepare(&format!("SELECT {column} FROM samples LIMIT 1"))
                .is_err()
            {
                conn.execute(
                    &format!("ALTER TABLE samples ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }

        // DDS v1.4 Sec.2.2.3.18/2.2.3.5: retention is scoped PER INSTANCE,
        // so every retention query groups by (topic, instance_handle).
        // Created last, after both migrations above: on a pre-existing
        // database the column does not exist until the migration just
        // ran, and an index on a column that is not there yet fails
        // outright rather than being a harmless no-op.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_topic_instance ON samples(topic, instance_handle)",
            [],
        )?;

        Ok(())
    }

    /// Helper function to map a row to a Sample
    fn row_to_sample(row: &rusqlite::Row) -> rusqlite::Result<Sample> {
        let source_guid_blob: Vec<u8> = row.get(5)?;
        let mut source_guid = [0u8; 16];
        source_guid.copy_from_slice(&source_guid_blob);

        let instance_handle_blob: Vec<u8> = row.get(7)?;
        let mut instance_handle = [0u8; 16];
        instance_handle.copy_from_slice(&instance_handle_blob);

        Ok(Sample {
            topic: row.get(0)?,
            type_name: row.get(1)?,
            payload: row.get(2)?,
            timestamp_ns: row.get::<_, i64>(3)? as u64,
            sequence: row.get::<_, i64>(4)? as u64,
            source_guid,
            source_timestamp_ns: row.get::<_, Option<i64>>(8)?.map(|value| value as u64),
            destination_order_by_source: row.get(9)?,
            representation: row.get::<_, i64>(6)? as u16,
            instance_handle,
        })
    }

    /// Keep the `keep_count` most recent samples of EACH DDS instance of
    /// `topic` (DDS v1.4 Sec.2.2.3.18/2.2.3.5), never a count shared
    /// across every instance: one DELETE per distinct instance already
    /// stored for this topic, each scoped to that instance's own rows.
    fn delete_keep_last_per_instance(
        conn: &Connection,
        topic: &str,
        keep_count: usize,
    ) -> Result<()> {
        if keep_count == 0 {
            return Ok(());
        }

        let instances: Vec<Vec<u8>> = {
            let mut stmt =
                conn.prepare("SELECT DISTINCT instance_handle FROM samples WHERE topic = ?1")?;
            let rows = stmt
                .query_map([topic], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };

        for instance in instances {
            conn.execute(
                "DELETE FROM samples
                 WHERE topic = ?1 AND instance_handle = ?2
                 AND id NOT IN (
                     SELECT id FROM samples
                     WHERE topic = ?1 AND instance_handle = ?2
                     ORDER BY timestamp_ns DESC, id DESC
                     LIMIT ?3
                 )",
                params![topic, instance, keep_count as i64],
            )?;
        }

        Ok(())
    }
}

impl PersistenceStore for SqliteStore {
    fn save(&self, sample: &Sample) -> Result<()> {
        self.save_with_instance_limit(sample, 0).map(|_| ())
    }

    fn save_with_instance_limit(&self, sample: &Sample, max_instances: usize) -> Result<bool> {
        self.save_with_policy(
            sample,
            &RetentionPolicy {
                keep_count_per_instance: 0,
                max_samples_total: 0,
                max_instances,
                max_age_ns: None,
                max_bytes: None,
            },
        )
    }

    fn save_with_policy(&self, sample: &Sample, policy: &RetentionPolicy) -> Result<bool> {
        let max_instances = policy.max_instances;
        let mut conn = self.conn.lock().unwrap();
        // The transaction also serializes separate connections to the same DB.
        // DDS v1.4 Sec.2.2.3.5/2.2.3.19: reject a new key at capacity,
        // preserving every already retained instance, including across restart.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if max_instances > 0 {
            let (known, count): (bool, i64) = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM samples WHERE topic = ?1 AND instance_handle = ?2),
                        (SELECT COUNT(DISTINCT instance_handle) FROM samples WHERE topic = ?1)",
                params![sample.topic, &sample.instance_handle[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if !known && count as usize >= max_instances {
                return Ok(false);
            }
        }
        if policy.max_samples_total > 0 {
            let (count, instance_count): (i64, i64) = tx.query_row(
                "SELECT COUNT(*), COALESCE(SUM(instance_handle = ?2), 0)
                 FROM samples WHERE topic = ?1",
                params![sample.topic, &sample.instance_handle[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let replaces = policy.keep_count_per_instance > 0
                && instance_count as usize >= policy.keep_count_per_instance;
            if count as usize >= policy.max_samples_total && !replaces {
                return Ok(false);
            }
        }
        tx.execute(
            "INSERT INTO samples (topic, type_name, payload, timestamp_ns, sequence, source_guid, representation, instance_handle, source_timestamp_ns, destination_order_by_source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                sample.topic,
                sample.type_name,
                sample.payload,
                sample.timestamp_ns as i64,
                sample.sequence as i64,
                &sample.source_guid[..],
                sample.representation as i64,
                &sample.instance_handle[..],
                sample.source_timestamp_ns.map(|value| value as i64),
                sample.destination_order_by_source,
            ],
        )?;

        // Replacement and insertion share one transaction, so another
        // connection never observes temporary growth above capacity.
        if policy.keep_count_per_instance > 0 {
            tx.execute(
                "DELETE FROM samples WHERE topic = ?1 AND instance_handle = ?2
                 AND id NOT IN (
                     SELECT id FROM samples WHERE topic = ?1 AND instance_handle = ?2
                     ORDER BY timestamp_ns DESC, id DESC LIMIT ?3
                 )",
                params![
                    sample.topic,
                    &sample.instance_handle[..],
                    policy.keep_count_per_instance as i64
                ],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    fn load(&self, topic: &str) -> Result<Vec<Sample>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT topic, type_name, payload, timestamp_ns, sequence, source_guid, representation, instance_handle, source_timestamp_ns, destination_order_by_source
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
                "SELECT topic, type_name, payload, timestamp_ns, sequence, source_guid, representation, instance_handle, source_timestamp_ns, destination_order_by_source
                 FROM samples
                 WHERE topic LIKE '{}/%' AND timestamp_ns BETWEEN ?1 AND ?2
                 ORDER BY timestamp_ns ASC",
                prefix
            )
        } else if topic == "*" {
            "SELECT topic, type_name, payload, timestamp_ns, sequence, source_guid, representation, instance_handle, source_timestamp_ns, destination_order_by_source
             FROM samples
             WHERE timestamp_ns BETWEEN ?1 AND ?2
             ORDER BY timestamp_ns ASC"
                .to_string()
        } else {
            "SELECT topic, type_name, payload, timestamp_ns, sequence, source_guid, representation, instance_handle, source_timestamp_ns, destination_order_by_source
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
        Self::delete_keep_last_per_instance(&conn, topic, keep_count)?;
        Ok(())
    }

    fn apply_retention_policy(&self, topic: &str, policy: &RetentionPolicy) -> Result<()> {
        if policy.is_noop() {
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();

        // Instance capacity is an admission limit, never a retention eviction.
        if policy.keep_count_per_instance > 0 {
            Self::delete_keep_last_per_instance(&conn, topic, policy.keep_count_per_instance)?;
        }

        // Total sample and instance capacity are admission limits. Lowering
        // them must not destroy previously retained durable data.

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
                     ORDER BY timestamp_ns DESC, id DESC",
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
            source_timestamp_ns: None,
            destination_order_by_source: false,
            representation: 0,
            instance_handle: [0u8; 16],
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
                source_timestamp_ns: None,
                destination_order_by_source: false,
                representation: 0,
                instance_handle: [0u8; 16],
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
                source_timestamp_ns: None,
                destination_order_by_source: false,
                representation: 0,
                instance_handle: [0u8; 16],
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
                source_timestamp_ns: None,
                destination_order_by_source: false,
                representation: 0,
                instance_handle: [0u8; 16],
            };
            store.save(&sample).unwrap();
        }

        assert_eq!(store.count().unwrap(), 10);

        store.apply_retention("test/topic", 5).unwrap();
        assert_eq!(store.count().unwrap(), 5);

        let remaining = store.load("test/topic").unwrap();
        assert_eq!(remaining[0].sequence, 5); // oldest kept is sequence 5
    }

    /// DDS v1.4 Sec.2.2.3.18 (HISTORY) / Sec.2.2.3.5 (DURABILITY_SERVICE):
    /// `history_depth` is kept PER INSTANCE. On a keyed topic with two
    /// instances, `apply_retention(topic, 3)` must keep the 3 most recent
    /// samples of EACH instance (6 rows total), never purge one instance's
    /// durable data to stay under a count shared with the other.
    ///
    /// Mutant: revert `apply_retention` to the pre-fix single
    /// `DELETE ... LIMIT keep_count` scoped only by topic (no
    /// `instance_handle` in the WHERE/subquery) and this test fails --
    /// instance A's history is purged down to make room for instance B's,
    /// which happened to receive the later timestamps.
    #[test]
    fn apply_retention_keeps_depth_per_instance_not_per_topic() {
        let store = SqliteStore::new_in_memory().unwrap();
        let instance_a = [0xA0u8; 16];
        let instance_b = [0xB0u8; 16];

        for i in 0..10u64 {
            for (instance, source_guid) in [(instance_a, [0x0A; 16]), (instance_b, [0x0B; 16])] {
                store
                    .save(&Sample {
                        topic: "keyed/topic".to_string(),
                        type_name: "Keyed".to_string(),
                        payload: vec![i as u8],
                        timestamp_ns: i * 1000,
                        sequence: i,
                        source_guid,
                        source_timestamp_ns: None,
                        destination_order_by_source: false,
                        representation: 0,
                        instance_handle: instance,
                    })
                    .unwrap();
            }
        }
        assert_eq!(store.count().unwrap(), 20);

        store.apply_retention("keyed/topic", 3).unwrap();

        let remaining = store.load("keyed/topic").unwrap();
        assert_eq!(
            remaining.len(),
            6,
            "3 samples per instance * 2 instances, never a single topic-wide 3"
        );

        let a_seqs: Vec<u64> = remaining
            .iter()
            .filter(|s| s.instance_handle == instance_a)
            .map(|s| s.sequence)
            .collect();
        let b_seqs: Vec<u64> = remaining
            .iter()
            .filter(|s| s.instance_handle == instance_b)
            .map(|s| s.sequence)
            .collect();
        assert_eq!(a_seqs.len(), 3, "instance A must keep its own 3 samples");
        assert_eq!(b_seqs.len(), 3, "instance B must keep its own 3 samples");
        assert_eq!(a_seqs.iter().min().copied().unwrap(), 7);
        assert_eq!(b_seqs.iter().min().copied().unwrap(), 7);
    }

    /// DDS v1.4 Sec.2.2.3.5/2.2.3.19: at full service capacity, retain A,
    /// refuse B, and allow an existing instance's KEEP_LAST replacement.
    #[test]
    fn total_capacity_refuses_growth_and_allows_keep_last_replacement() {
        let store = SqliteStore::new_in_memory().unwrap();
        let policy = RetentionPolicy {
            keep_count_per_instance: 1,
            max_samples_total: 1,
            max_instances: 0,
            max_age_ns: None,
            max_bytes: None,
        };
        assert!(store
            .save_with_policy(&keyed_sample("topic", 1, 1, 1), &policy)
            .unwrap());
        assert!(!store
            .save_with_policy(&keyed_sample("topic", 2, 2, 2), &policy)
            .unwrap());
        let kept = store.load("topic").unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].sequence, 1);
        assert!(store
            .save_with_policy(&keyed_sample("topic", 1, 3, 3), &policy)
            .unwrap());
        let kept = store.load("topic").unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].sequence, 3);
        // KEEP_ALL cannot replace even a known instance at capacity.
        let keep_all = RetentionPolicy {
            keep_count_per_instance: 0,
            ..policy
        };
        assert!(!store
            .save_with_policy(&keyed_sample("topic", 1, 4, 4), &keep_all)
            .unwrap());
        // Limits apply per topic, not per database.
        assert!(store
            .save_with_policy(&keyed_sample("other", 2, 1, 1), &policy)
            .unwrap());
    }

    /// Independent connections serialize total-capacity admission with insert.
    #[test]
    fn total_capacity_is_atomic_across_connections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capacity.db");
        let a = SqliteStore::new(path.to_str().unwrap()).unwrap();
        let b = SqliteStore::new(path.to_str().unwrap()).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [a, b]
            .into_iter()
            .enumerate()
            .map(|(i, store)| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .save_with_policy(
                            &keyed_sample("topic", i as u8, 1, 1),
                            &RetentionPolicy {
                                keep_count_per_instance: 1,
                                max_samples_total: 1,
                                max_instances: 0,
                                max_age_ns: None,
                                max_bytes: None,
                            },
                        )
                        .unwrap()
                })
            })
            .collect();
        let admitted = handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>();
        assert_eq!(admitted, 1);
        let reopened = SqliteStore::new(path.to_str().unwrap()).unwrap();
        assert_eq!(reopened.count().unwrap(), 1);
    }

    fn keyed_sample(topic: &str, instance: u8, sequence: u64, timestamp_ns: u64) -> Sample {
        Sample {
            topic: topic.to_string(),
            type_name: "Keyed".to_string(),
            payload: vec![sequence as u8],
            timestamp_ns,
            sequence,
            source_guid: [0xA0; 16],
            instance_handle: [instance; 16],
            source_timestamp_ns: None,
            destination_order_by_source: false,
            representation: 0,
        }
    }

    /// DDS v1.4 Sec.2.2.3.5/2.2.3.19: capacity refuses new instances,
    /// preserving retained data and accepting updates of known keys.
    #[test]
    fn instance_capacity_refuses_new_keys_without_destroying_retained_data() {
        let store = SqliteStore::new_in_memory().unwrap();
        let a = keyed_sample("keyed/topic", 1, 1, 9000);
        let b = keyed_sample("keyed/topic", 2, 2, 8000);
        assert!(store.save_with_instance_limit(&a, 1).unwrap());
        assert!(!store.save_with_instance_limit(&b, 1).unwrap());
        assert!(store
            .save_with_instance_limit(&keyed_sample("keyed/topic", 1, 3, 7000), 1)
            .unwrap());
        assert!(store
            .save_with_instance_limit(&keyed_sample("other/topic", 2, 4, 6000), 1)
            .unwrap());
        let policy = RetentionPolicy {
            keep_count_per_instance: 0,
            max_samples_total: 0,
            max_instances: 1,
            max_age_ns: None,
            max_bytes: None,
        };
        store
            .apply_retention_policy("keyed/topic", &policy)
            .unwrap();
        let remaining = store.load("keyed/topic").unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining
            .iter()
            .all(|sample| sample.instance_handle == a.instance_handle));
        assert_eq!(store.load("other/topic").unwrap().len(), 1);
    }

    /// A lower limit must not destroy data already retained in a database.
    #[test]
    fn instance_sweep_preserves_preexisting_instances_above_capacity() {
        let store = SqliteStore::new_in_memory().unwrap();
        store.save(&keyed_sample("keyed/topic", 1, 1, 1)).unwrap();
        store.save(&keyed_sample("keyed/topic", 2, 2, 2)).unwrap();
        store
            .apply_retention_policy(
                "keyed/topic",
                &RetentionPolicy {
                    keep_count_per_instance: 0,
                    max_samples_total: 0,
                    max_instances: 1,
                    max_age_ns: None,
                    max_bytes: None,
                },
            )
            .unwrap();
        assert_eq!(store.load("keyed/topic").unwrap().len(), 2);
        assert!(!store
            .save_with_instance_limit(&keyed_sample("keyed/topic", 3, 3, 3), 1)
            .unwrap());
    }

    /// KEEP_LAST retains the last received update when timestamps tie
    /// (DDS v1.4 Sec.2.2.3.18, reception order Sec.2.2.3.17). Sequence
    /// numbers are writer-local and cannot break ties across writers.
    #[test]
    fn equal_timestamps_keep_last_received_per_instance() {
        let store = SqliteStore::new_in_memory().unwrap();
        store
            .save(&keyed_sample("keyed/topic", 1, 9, 1000))
            .unwrap();
        let mut latest = keyed_sample("keyed/topic", 1, 1, 1000);
        latest.source_guid = [0xB0; 16];
        store.save(&latest).unwrap();
        store.apply_retention("keyed/topic", 1).unwrap();
        let remaining = store.load("keyed/topic").unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].source_guid, latest.source_guid);
        assert_eq!(remaining[0].sequence, 1);
    }

    /// A lowered total capacity must not evict previously retained data.
    #[test]
    fn total_sweep_preserves_preexisting_samples_above_capacity() {
        let store = SqliteStore::new_in_memory().unwrap();
        store
            .save(&keyed_sample("keyed/topic", 1, 9, 1000))
            .unwrap();
        store
            .save(&keyed_sample("keyed/topic", 2, 1, 1000))
            .unwrap();
        let policy = RetentionPolicy {
            keep_count_per_instance: 0,
            max_samples_total: 1,
            max_instances: 0,
            max_age_ns: None,
            max_bytes: None,
        };
        store
            .apply_retention_policy("keyed/topic", &policy)
            .unwrap();
        let remaining = store.load("keyed/topic").unwrap();
        assert_eq!(remaining.len(), 2);
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
            source_timestamp_ns: None,
            destination_order_by_source: false,
            representation: 0,
            instance_handle: [0u8; 16],
        };

        store.save(&sample).unwrap();
        assert_eq!(store.count().unwrap(), 1);

        store.clear().unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn representation_roundtrips_through_save_and_load() {
        let store = SqliteStore::new_in_memory().unwrap();

        let xcdr1 = Sample {
            topic: "test/topic".to_string(),
            type_name: "TestType".to_string(),
            payload: vec![0x01],
            timestamp_ns: 1000,
            sequence: 1,
            source_guid: [0x11; 16],
            source_timestamp_ns: None,
            destination_order_by_source: false,
            representation: 0x0000,
            instance_handle: [0u8; 16],
        };
        let xcdr2 = Sample {
            topic: "test/topic".to_string(),
            type_name: "TestType".to_string(),
            payload: vec![0x02],
            timestamp_ns: 2000,
            sequence: 2,
            source_guid: [0x22; 16],
            source_timestamp_ns: None,
            destination_order_by_source: false,
            representation: 0x0002,
            instance_handle: [0u8; 16],
        };
        store.save(&xcdr1).unwrap();
        store.save(&xcdr2).unwrap();

        let loaded = store.load("test/topic").unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].representation, 0x0000);
        assert_eq!(loaded[1].representation, 0x0002);
    }

    /// A database file created by a build before `representation` existed
    /// (no such column at all) must still open, migrate, and default
    /// every pre-existing row to XCDR2: what the 1.4.x default
    /// writer actually sent -- see `Sample::representation`.
    #[test]
    fn a_pre_existing_database_migrates_and_defaults_to_xcdr2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v0.sqlite");
        let path_str = path.to_str().unwrap();

        // Hand-build a pre-migration database: the ORIGINAL schema, no
        // representation column, one row already in it.
        {
            let conn = Connection::open(path_str).unwrap();
            conn.execute(
                "CREATE TABLE samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT NOT NULL,
                    type_name TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    timestamp_ns INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    source_guid BLOB NOT NULL
                )",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO samples (topic, type_name, payload, timestamp_ns, sequence, source_guid)
                 VALUES ('old/topic', 'OldType', X'010203', 500, 9, X'00000000000000000000000000000000')",
                [],
            )
            .unwrap();
        }

        // Opening through SqliteStore::new runs init_schema, which must
        // migrate this file in place rather than fail on it.
        let store = SqliteStore::new(path_str).expect("a pre-existing database must still open");
        let loaded = store.load("old/topic").expect("load after migration");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].sequence, 9);
        assert_eq!(
            loaded[0].representation, 0x0002,
            "a migrated row with no stored representation must default to XCDR2, \
             the representation the 1.4.x default writer actually sent"
        );
        assert_eq!(
            loaded[0].instance_handle, [0u8; 16],
            "a migrated row with no stored instance_handle must default to nil"
        );

        // A fresh save on the migrated database must also work.
        store
            .save(&Sample {
                topic: "old/topic".to_string(),
                type_name: "OldType".to_string(),
                payload: vec![0xFF],
                timestamp_ns: 600,
                sequence: 10,
                source_guid: [0u8; 16],
                source_timestamp_ns: None,
                destination_order_by_source: false,
                representation: 0x0002,
                instance_handle: [0u8; 16],
            })
            .unwrap();
        let loaded = store.load("old/topic").unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].representation, 0x0002);
    }
}
