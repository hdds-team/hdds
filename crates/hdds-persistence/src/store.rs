// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Persistence store abstraction
//!
//! Defines the trait for storage backends (SQLite, RocksDB, etc.).

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// The default for [`Sample::representation`] on a record that never
/// carried one -- see that field's doc for why this is XCDR2, not the
/// DDS-XTypes spec's "empty list" default.
fn default_representation() -> u16 {
    hdds::CdrVersion::Xcdr2.representation_code()
}

/// The default for [`Sample::instance_handle`] on a record that never
/// carried one -- a pre-existing record, from before this field existed,
/// is a keyless or single-instance topic as far as retention is
/// concerned, so it shares the nil instance like every other untagged
/// sample.
fn default_instance_handle() -> [u8; 16] {
    [0u8; 16]
}

/// A persisted DDS sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    /// Topic name
    pub topic: String,

    /// Type name
    pub type_name: String,

    /// Serialized payload (CDR)
    pub payload: Vec<u8>,

    /// Reception timestamp (Unix nanoseconds)
    pub timestamp_ns: u64,

    /// Original source timestamp (Unix nanoseconds), absent in legacy records.
    #[serde(default)]
    pub source_timestamp_ns: Option<u64>,

    /// Whether the original writer offered BY_SOURCE_TIMESTAMP ordering.
    #[serde(default)]
    pub destination_order_by_source: bool,

    /// Sequence number
    pub sequence: u64,

    /// Source writer GUID
    pub source_guid: [u8; 16],

    /// DDS instance handle (key hash for keyed topics, nil for keyless
    /// ones). Lets retention (`PersistenceStore::apply_retention`,
    /// `apply_retention_policy`) scope a KEEP_LAST depth to one DDS
    /// instance, as DDS 1.4 Sec.2.2.3.18/2.2.3.5 require (HISTORY.depth
    /// and DURABILITY_SERVICE.history_depth are both "per instance"),
    /// instead of deleting another instance's durable data to make room.
    /// `#[serde(default = "default_instance_handle")]` defaults a
    /// pre-existing record (saved before this column/field existed) to
    /// nil: the same single bucket every sample was already implicitly
    /// sharing, so an old record's retention behaviour is unchanged by
    /// the upgrade.
    #[serde(default = "default_instance_handle")]
    pub instance_handle: [u8; 16],

    /// The DATA_REPRESENTATION wire code `payload` is actually encoded in
    /// (`hdds::CdrVersion::representation_code`: `0x0000` XCDR1, `0x0002`
    /// XCDR2). Replaying this sample to a late-joining reader must route
    /// through a writer that offers exactly this representation
    /// (`hdds::RawRelayWriter`), never a plain writer resolved to a
    /// different one. `#[serde(default = "default_representation")]`
    /// defaults a pre-existing record (a sqlite row from before this
    /// column existed -- migrated with the same default, see
    /// `crate::sqlite::SqliteStore` -- or any other deserialized payload
    /// that never carried it) to `0x0002` XCDR2: NOT the DDS-XTypes
    /// spec's "empty list" default (XCDR1), but what HDDS's own
    /// default-QoS writer actually encoded before this field existed
    /// (the 1.4.x line). A current build's default-QoS
    /// writer resolves to XCDR1 instead
    /// (`hdds::dds::cdr_negotiation::resolve_writer_data_representation`);
    /// this default must track what an un-tagged record actually carries,
    /// not whatever the current build's own default happens to be.
    #[serde(default = "default_representation")]
    pub representation: u16,
}

/// Retention policy for persisted samples.
///
/// DDS v1.4 Sec.2.2.3.5 (DURABILITY_SERVICE) configures the service's
/// independent history and resource limits. History depth is per instance;
/// total samples and instance count are separate topic-wide limits.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    /// Number of recent samples to keep per DDS instance (0 = unlimited).
    /// Source: DURABILITY_SERVICE.history_depth / max_samples_per_instance.
    pub keep_count_per_instance: usize,
    /// Maximum total samples across every instance (0 = unlimited).
    /// Enforced atomically on admission by `save_with_policy`.
    pub max_samples_total: usize,
    /// Maximum distinct instances per topic (0 = unlimited).
    ///
    /// Enforced on admission by `save_with_instance_limit`. A new instance
    /// is rejected at capacity; existing retained instances are never evicted
    /// to admit another key.
    pub max_instances: usize,
    /// Maximum sample age in nanoseconds (None = unlimited). Applied
    /// topic-wide, across every instance.
    pub max_age_ns: Option<u64>,
    /// Maximum total bytes per topic (None = unlimited). Applied
    /// topic-wide, across every instance.
    pub max_bytes: Option<u64>,
}

impl RetentionPolicy {
    /// Returns true if no retention limits are configured.
    pub fn is_noop(&self) -> bool {
        self.keep_count_per_instance == 0
            && self.max_samples_total == 0
            && self.max_instances == 0
            && self.max_age_ns.is_none()
            && self.max_bytes.is_none()
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

    /// Save without evicting retained instances to admit a new key.
    /// Returns false when a new instance would exceed the topic's limit
    /// (0 means unlimited). Backends must make admission and insertion atomic.
    /// The default refuses finite limits rather than silently ignoring them.
    fn save_with_instance_limit(&self, sample: &Sample, max_instances: usize) -> Result<bool> {
        anyhow::ensure!(
            max_instances == 0,
            "backend does not support instance admission limits"
        );
        self.save(sample)?;
        Ok(true)
    }

    /// Atomically admit a sample under the service's capacity limits.
    /// A full topic refuses growth while permitting KEEP_LAST replacement
    /// within an existing instance. Retained instances are never evicted.
    /// Returns false for a capacity refusal. Unsupported finite total limits
    /// return an error rather than silently losing durable data.
    fn save_with_policy(&self, sample: &Sample, policy: &RetentionPolicy) -> Result<bool> {
        anyhow::ensure!(
            policy.max_samples_total == 0,
            "backend does not support total sample admission limits"
        );
        self.save_with_instance_limit(sample, policy.max_instances)
    }

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

    /// Delete old samples to enforce retention policy.
    ///
    /// `keep_count` is PER DDS INSTANCE (DDS v1.4 Sec.2.2.3.18/2.2.3.5): a
    /// backend must keep the `keep_count` most recent samples of EACH
    /// instance of `topic` separately, never delete a sample of one
    /// instance to stay under a count shared across every instance of
    /// the topic. A backend with no instance column (keyless-only use,
    /// or a backend that has not added one yet) may treat every sample
    /// as the single nil instance, which keeps this correct for a
    /// keyless topic but under-retains a keyed one -- see
    /// [`Sample::instance_handle`].
    ///
    /// # Arguments
    ///
    /// - `topic` -- Topic name
    /// - `keep_count` -- Number of recent samples to keep per instance
    fn apply_retention(&self, topic: &str, keep_count: usize) -> Result<()>;

    /// Apply retention policy with optional age/size constraints.
    ///
    /// The default forwards only the per-instance count to
    /// [`apply_retention`](Self::apply_retention); it does not enforce
    /// [`RetentionPolicy::max_samples_total`], `max_instances`, `max_age_ns` or
    /// `max_bytes` -- a backend that needs those must override this
    /// method (as `SqliteStore` does).
    fn apply_retention_policy(&self, topic: &str, policy: &RetentionPolicy) -> Result<()> {
        self.apply_retention(topic, policy.keep_count_per_instance)
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
            instance_handle: [0x5A; 16],
            source_timestamp_ns: None,
            destination_order_by_source: false,
            representation: 0x0002,
        };

        let json = serde_json::to_string(&sample).unwrap();
        let deserialized: Sample = serde_json::from_str(&json).unwrap();

        assert_eq!(sample.topic, deserialized.topic);
        assert_eq!(sample.sequence, deserialized.sequence);
        assert_eq!(deserialized.representation, 0x0002);
        assert_eq!(deserialized.instance_handle, [0x5A; 16]);
    }

    /// A JSON record from before `representation` existed must still
    /// deserialize, defaulting to XCDR2 -- what the 1.4.x default
    /// writer actually sent (see `Sample::representation`).
    #[test]
    fn a_pre_existing_record_defaults_representation_to_xcdr2() {
        let json = r#"{
            "topic": "test/topic",
            "type_name": "TestType",
            "payload": [1, 2, 3],
            "timestamp_ns": 1234567890,
            "sequence": 42,
            "source_guid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        }"#;
        let sample: Sample = serde_json::from_str(json).unwrap();
        assert_eq!(sample.representation, 0x0002);
    }

    /// A JSON record from before `instance_handle` existed must still
    /// deserialize, defaulting to nil: the single bucket every untagged
    /// sample already implicitly shared (see `Sample::instance_handle`).
    #[test]
    fn a_pre_existing_record_defaults_instance_handle_to_nil() {
        let json = r#"{
            "topic": "test/topic",
            "type_name": "TestType",
            "payload": [1, 2, 3],
            "timestamp_ns": 1234567890,
            "sequence": 42,
            "source_guid": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        }"#;
        let sample: Sample = serde_json::from_str(json).unwrap();
        assert_eq!(sample.instance_handle, [0u8; 16]);
    }

    /// DDS v1.4 Sec.2.2.3.18/2.2.3.5: `keep_count_per_instance` and
    /// `max_samples_total` are two independent axes, not synonyms. A
    /// policy that only limits per-instance history is not a no-op
    /// merely because it never sets a topic-wide total.
    #[test]
    fn is_noop_requires_every_axis_unset() {
        let all_unset = RetentionPolicy {
            keep_count_per_instance: 0,
            max_samples_total: 0,
            max_instances: 0,
            max_age_ns: None,
            max_bytes: None,
        };
        assert!(all_unset.is_noop());

        let per_instance_only = RetentionPolicy {
            keep_count_per_instance: 5,
            ..all_unset
        };
        assert!(!per_instance_only.is_noop());

        let total_only = RetentionPolicy {
            max_samples_total: 50,
            ..all_unset
        };
        assert!(!total_only.is_noop());

        let instances_only = RetentionPolicy {
            max_instances: 1,
            ..all_unset
        };
        assert!(!instances_only.is_noop());
    }
}
