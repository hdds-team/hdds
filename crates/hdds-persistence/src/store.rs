// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Persistence store abstraction
//!
//! Defines the trait for storage backends (SQLite, RocksDB, etc.).

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A persisted DDS sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    /// Topic name
    pub topic: String,

    /// Type name
    pub type_name: String,

    /// Serialized payload (CDR)
    pub payload: Vec<u8>,

    /// Timestamp (Unix nanoseconds)
    pub timestamp_ns: u64,

    /// Sequence number
    pub sequence: u64,

    /// Source GUID (participant ID)
    pub source_guid: [u8; 16],
}

/// Retention policy for persisted samples.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    /// Number of recent samples to keep per topic (0 = unlimited).
    pub keep_count: usize,
    /// Maximum sample age in nanoseconds (None = unlimited).
    pub max_age_ns: Option<u64>,
    /// Maximum total bytes per topic (None = unlimited).
    pub max_bytes: Option<u64>,
}

impl RetentionPolicy {
    /// Returns true if no retention limits are configured.
    pub fn is_noop(&self) -> bool {
        self.keep_count == 0 && self.max_age_ns.is_none() && self.max_bytes.is_none()
    }
}

/// Persistence store trait
///
/// Backend-agnostic interface for storing and retrieving DDS samples.
///
/// # Implementations
///
/// - `SqliteStore` -- Default, zero-dependency
/// - `RocksDbStore` -- High-performance (feature flag)
pub trait PersistenceStore {
    /// Save a sample to persistent storage
    fn save(&self, sample: &Sample) -> Result<()>;

    /// Load all samples for a topic
    fn load(&self, topic: &str) -> Result<Vec<Sample>>;

    /// Query samples within a time range
    ///
    /// # Arguments
    ///
    /// - `topic` -- Topic name (supports wildcards: "State/*")
    /// - `start_ns` -- Start timestamp (Unix nanoseconds)
    /// - `end_ns` -- End timestamp (Unix nanoseconds)
    fn query_range(&self, topic: &str, start_ns: u64, end_ns: u64) -> Result<Vec<Sample>>;

    /// Delete old samples to enforce retention policy
    ///
    /// # Arguments
    ///
    /// - `topic` -- Topic name
    /// - `keep_count` -- Number of recent samples to keep
    fn apply_retention(&self, topic: &str, keep_count: usize) -> Result<()>;

    /// Apply retention policy with optional age/size constraints.
    fn apply_retention_policy(&self, topic: &str, policy: &RetentionPolicy) -> Result<()> {
        self.apply_retention(topic, policy.keep_count)
    }

    /// Get total number of samples stored
    fn count(&self) -> Result<usize>;

    /// Clear all samples (for testing)
    fn clear(&self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_serialization() {
        let sample = Sample {
            topic: "test/topic".to_string(),
            type_name: "TestType".to_string(),
            payload: vec![0x01, 0x02, 0x03],
            timestamp_ns: 1234567890,
            sequence: 42,
            source_guid: [0xAA; 16],
        };

        let json = serde_json::to_string(&sample).unwrap();
        let deserialized: Sample = serde_json::from_str(&json).unwrap();

        assert_eq!(sample.topic, deserialized.topic);
        assert_eq!(sample.sequence, deserialized.sequence);
    }
}
