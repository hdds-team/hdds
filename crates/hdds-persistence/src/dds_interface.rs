// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Interface Abstraction
//!
//! Provides an abstract interface for DDS operations that the persistence
//! service uses. This allows the persistence service to work without direct
//! dependency on the core hdds Participant implementation.
//!
//! # Integration
//!
//! To integrate with HDDS core, implement the `DdsInterface` trait:
//!
//! ```ignore
//! impl DdsInterface for HddsParticipant {
//!     fn subscribe(&self, topic: &str) -> Result<Box<dyn DataReader>> {
//!         // Create real DataReader...
//!     }
//!     // ...
//! }
//! ```

use crate::store::{RetentionPolicy, Sample};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;

/// Received sample from DDS
#[derive(Debug, Clone)]
pub struct ReceivedSample {
    /// Topic name
    pub topic: String,
    /// Type name
    pub type_name: String,
    /// Serialized payload (CDR)
    pub payload: Vec<u8>,
    /// Source writer GUID
    pub writer_guid: [u8; 16],
    /// Sequence number
    pub sequence: u64,
    /// Reception timestamp (Unix nanoseconds)
    pub timestamp_ns: u64,
    /// Original source timestamp, absent when no INFO_TS was supplied.
    pub source_timestamp_ns: Option<u64>,
    /// Original writer's DESTINATION_ORDER offer.
    pub destination_order_by_source: bool,
    /// DDS instance handle (key hash for keyed topics, nil otherwise). See
    /// [`crate::store::Sample::instance_handle`] for how this is used to
    /// scope retention to one instance instead of the whole topic.
    pub instance_handle: [u8; 16],
    /// The DATA_REPRESENTATION wire code `payload` is actually encoded in
    /// (`hdds::CdrVersion::representation_code`: `0x0000` XCDR1, `0x0002`
    /// XCDR2). See [`crate::store::Sample::representation`] for how this
    /// is used on replay.
    pub representation: u16,
}

impl From<ReceivedSample> for Sample {
    fn from(rs: ReceivedSample) -> Self {
        Sample {
            topic: rs.topic,
            type_name: rs.type_name,
            payload: rs.payload,
            timestamp_ns: rs.timestamp_ns,
            sequence: rs.sequence,
            source_guid: rs.writer_guid,
            instance_handle: rs.instance_handle,
            source_timestamp_ns: rs.source_timestamp_ns,
            destination_order_by_source: rs.destination_order_by_source,
            representation: rs.representation,
        }
    }
}

/// Durability policy exposed by discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityKind {
    Volatile,
    TransientLocal,
    Transient,
    Persistent,
}

impl DurabilityKind {
    /// Returns true for every non-volatile durability kind.
    pub fn is_durable(self) -> bool {
        matches!(
            self,
            Self::TransientLocal | Self::Transient | Self::Persistent
        )
    }

    /// Durability ordering for QoS compatibility.
    pub fn rank(self) -> u8 {
        match self {
            Self::Volatile => 0,
            Self::TransientLocal => 1,
            Self::Transient => 2,
            Self::Persistent => 3,
        }
    }
}

/// Discovered reader information
#[derive(Debug, Clone)]
pub struct DiscoveredReader {
    /// Reader GUID
    pub guid: [u8; 16],
    /// Topic name
    pub topic: String,
    /// Type name
    pub type_name: String,
    /// Durability requested by the reader.
    pub durability: DurabilityKind,
}

/// Discovered writer information
#[derive(Debug, Clone)]
pub struct DiscoveredWriter {
    /// Writer GUID
    pub guid: [u8; 16],
    /// Topic name
    pub topic: String,
    /// Type name
    pub type_name: String,
    /// Durability offered by the writer.
    pub durability: DurabilityKind,
    /// Optional retention hint derived from writer durability settings.
    pub retention_hint: Option<RetentionPolicy>,
}

/// Abstract data reader interface
pub trait DataReader: Send + Sync {
    /// Take all available samples (removes from reader cache)
    fn take(&self) -> Result<Vec<ReceivedSample>>;

    /// Read samples without removing from cache
    fn read(&self) -> Result<Vec<ReceivedSample>>;

    /// Get topic name
    fn topic(&self) -> &str;

    /// Get type name
    fn type_name(&self) -> &str;
}

/// Abstract data writer interface
pub trait DataWriter: Send + Sync {
    /// Write a sample
    fn write(&self, payload: &[u8]) -> Result<()>;

    /// Write a sample with timestamp
    fn write_with_timestamp(&self, payload: &[u8], timestamp_ns: u64) -> Result<()>;

    /// Write a sample with timestamp and its DATA_REPRESENTATION wire
    /// code (`hdds::CdrVersion::representation_code`): `0x0000` XCDR1,
    /// `0x0002` XCDR2. A replay of a persisted [`crate::store::Sample`]
    /// must call this, not [`write_with_timestamp`](Self::write_with_timestamp),
    /// whenever the representation it was recorded under is known --
    /// which for `HddsDataWriter` means routing through a writer that
    /// actually OFFERS that representation
    /// (`hdds::RawRelayWriter::relay_write`), never a single writer that
    /// resolved a different one.
    ///
    /// Default implementation ignores `representation` and falls back to
    /// [`write_with_timestamp`](Self::write_with_timestamp), for any
    /// implementor (a mock, a future non-HDDS backend) that has no
    /// representation-aware write path of its own.
    fn write_sample(&self, payload: &[u8], timestamp_ns: u64, representation: u16) -> Result<()> {
        let _ = representation;
        self.write_with_timestamp(payload, timestamp_ns)
    }

    /// Replay a stored sample, including the original instance KeyHash.
    /// Backends with opaque keyed writes must override this method.
    fn write_sample_with_key(
        &self,
        payload: &[u8],
        timestamp_ns: u64,
        representation: u16,
        instance_handle: [u8; 16],
    ) -> Result<()> {
        let _ = instance_handle;
        self.write_sample(payload, timestamp_ns, representation)
    }

    /// Get topic name
    fn topic(&self) -> &str;

    /// Get type name
    fn type_name(&self) -> &str;
}

/// Abstract DDS interface for persistence service
///
/// This trait abstracts DDS operations so the persistence service
/// doesn't depend on concrete HDDS implementation.
pub trait DdsInterface: Send + Sync {
    /// Create a data reader for a topic
    ///
    /// The reader should be configured with appropriate QoS for durability:
    /// - RELIABLE reliability
    /// - Durability matching the requested policy
    fn create_reader(
        &self,
        topic: &str,
        type_name: &str,
        durability: DurabilityKind,
    ) -> Result<Box<dyn DataReader>>;

    /// Create a data writer for a topic
    ///
    /// The writer should be configured with appropriate QoS:
    /// - RELIABLE reliability
    /// - Durability matching the replay target
    fn create_writer(
        &self,
        topic: &str,
        type_name: &str,
        durability: DurabilityKind,
    ) -> Result<Box<dyn DataWriter>>;

    /// Create a replay writer offering the retained destination order.
    /// Backends supporting source ordering must override this method.
    fn create_writer_with_destination_order(
        &self,
        topic: &str,
        type_name: &str,
        durability: DurabilityKind,
        by_source: bool,
    ) -> Result<Box<dyn DataWriter>> {
        anyhow::ensure!(
            !by_source,
            "backend does not support source destination order"
        );
        self.create_writer(topic, type_name, durability)
    }

    /// Get list of discovered readers matching a topic pattern
    fn discovered_readers(&self, topic_pattern: &str) -> Result<Vec<DiscoveredReader>>;

    /// Get list of discovered writers matching a topic pattern
    fn discovered_writers(&self, topic_pattern: &str) -> Result<Vec<DiscoveredWriter>>;

    /// Wait for discovery events
    ///
    /// Returns when new readers/writers are discovered or timeout expires.
    fn wait_for_discovery(&self, timeout: Duration) -> Result<bool>;

    /// Register a discovery callback for endpoint events.
    fn register_discovery_callback(&self, callback: Arc<dyn DiscoveryCallback>) -> Result<()>;

    /// Get participant GUID
    fn guid(&self) -> [u8; 16];
}

/// Callback-based sample receiver
///
/// Alternative to polling - receive samples via callback.
pub trait SampleCallback: Send + Sync {
    /// Called when a new sample is received
    fn on_sample(&self, sample: ReceivedSample);
}

/// Callback-based discovery listener
pub trait DiscoveryCallback: Send + Sync {
    /// Called when a new reader is discovered
    fn on_reader_discovered(&self, reader: DiscoveredReader);

    /// Called when a reader is removed
    fn on_reader_removed(&self, guid: [u8; 16]);

    /// Called when a new writer is discovered
    fn on_writer_discovered(&self, writer: DiscoveredWriter);

    /// Called when a writer is removed
    fn on_writer_removed(&self, guid: [u8; 16]);
}

// ============================================================================
// Mock Implementation for Testing
// ============================================================================

/// Mock DDS interface for testing without real HDDS
pub struct MockDdsInterface {
    guid: [u8; 16],
    readers: std::sync::Mutex<Vec<DiscoveredReader>>,
    writers: std::sync::Mutex<Vec<DiscoveredWriter>>,
    samples: std::sync::Mutex<Vec<ReceivedSample>>,
    callbacks: std::sync::Mutex<Vec<Arc<dyn DiscoveryCallback>>>,
}

impl MockDdsInterface {
    /// Create a new mock interface
    pub fn new() -> Self {
        Self {
            guid: [0x42; 16],
            readers: std::sync::Mutex::new(Vec::new()),
            writers: std::sync::Mutex::new(Vec::new()),
            samples: std::sync::Mutex::new(Vec::new()),
            callbacks: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Add a mock discovered reader
    pub fn add_reader(&self, reader: DiscoveredReader) {
        let mut readers = match self.readers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        readers.push(reader.clone());
        drop(readers);

        let callbacks = match self.callbacks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for callback in callbacks.iter() {
            callback.on_reader_discovered(reader.clone());
        }
    }

    /// Add a mock discovered writer
    pub fn add_writer(&self, writer: DiscoveredWriter) {
        let mut writers = match self.writers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        writers.push(writer.clone());
        drop(writers);

        let callbacks = match self.callbacks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for callback in callbacks.iter() {
            callback.on_writer_discovered(writer.clone());
        }
    }

    /// Add a mock sample to be returned by readers
    pub fn add_sample(&self, sample: ReceivedSample) {
        self.samples.lock().unwrap().push(sample);
    }

    /// Clear all mock data
    pub fn clear(&self) {
        let mut readers = match self.readers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        readers.clear();
        drop(readers);

        let mut writers = match self.writers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        writers.clear();
        drop(writers);

        let mut samples = match self.samples.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        samples.clear();
    }
}

impl Default for MockDdsInterface {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock data reader
struct MockDataReader {
    topic: String,
    type_name: String,
    samples: std::sync::Arc<std::sync::Mutex<Vec<ReceivedSample>>>,
}

impl DataReader for MockDataReader {
    fn take(&self) -> Result<Vec<ReceivedSample>> {
        let mut samples = self.samples.lock().unwrap();
        let matching: Vec<_> = samples
            .iter()
            .filter(|s| s.topic == self.topic)
            .cloned()
            .collect();
        samples.retain(|s| s.topic != self.topic);
        Ok(matching)
    }

    fn read(&self) -> Result<Vec<ReceivedSample>> {
        let samples = self.samples.lock().unwrap();
        Ok(samples
            .iter()
            .filter(|s| s.topic == self.topic)
            .cloned()
            .collect())
    }

    fn topic(&self) -> &str {
        &self.topic
    }

    fn type_name(&self) -> &str {
        &self.type_name
    }
}

/// Mock data writer
struct MockDataWriter {
    topic: String,
    type_name: String,
}

impl DataWriter for MockDataWriter {
    fn write(&self, _payload: &[u8]) -> Result<()> {
        tracing::debug!("MockDataWriter: write to {}", self.topic);
        Ok(())
    }

    fn write_with_timestamp(&self, _payload: &[u8], _timestamp_ns: u64) -> Result<()> {
        tracing::debug!("MockDataWriter: write_with_timestamp to {}", self.topic);
        Ok(())
    }

    fn topic(&self) -> &str {
        &self.topic
    }

    fn type_name(&self) -> &str {
        &self.type_name
    }
}

impl DdsInterface for MockDdsInterface {
    fn create_reader(
        &self,
        topic: &str,
        type_name: &str,
        _durability: DurabilityKind,
    ) -> Result<Box<dyn DataReader>> {
        Ok(Box::new(MockDataReader {
            topic: topic.to_string(),
            type_name: type_name.to_string(),
            samples: std::sync::Arc::new(self.samples.lock().unwrap().clone().into()),
        }))
    }

    fn create_writer(
        &self,
        topic: &str,
        type_name: &str,
        _durability: DurabilityKind,
    ) -> Result<Box<dyn DataWriter>> {
        Ok(Box::new(MockDataWriter {
            topic: topic.to_string(),
            type_name: type_name.to_string(),
        }))
    }

    fn discovered_readers(&self, topic_pattern: &str) -> Result<Vec<DiscoveredReader>> {
        let readers = self.readers.lock().unwrap();
        Ok(readers
            .iter()
            .filter(|r| topic_matches(topic_pattern, &r.topic))
            .cloned()
            .collect())
    }

    fn discovered_writers(&self, topic_pattern: &str) -> Result<Vec<DiscoveredWriter>> {
        let writers = self.writers.lock().unwrap();
        Ok(writers
            .iter()
            .filter(|w| topic_matches(topic_pattern, &w.topic))
            .cloned()
            .collect())
    }

    fn wait_for_discovery(&self, _timeout: Duration) -> Result<bool> {
        // Mock: always return true immediately
        Ok(true)
    }

    fn register_discovery_callback(&self, callback: Arc<dyn DiscoveryCallback>) -> Result<()> {
        let mut callbacks = match self.callbacks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        callbacks.push(callback);
        Ok(())
    }

    fn guid(&self) -> [u8; 16] {
        self.guid
    }
}

/// Check if a topic matches a pattern (supports wildcards)
pub(crate) fn topic_matches(pattern: &str, topic: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return topic.starts_with(prefix) && topic.len() > prefix.len();
    }
    pattern == topic
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_matches() {
        assert!(topic_matches("*", "any/topic"));
        assert!(topic_matches("State/*", "State/Temperature"));
        assert!(topic_matches("State/*", "State/Pressure"));
        assert!(!topic_matches("State/*", "Command/Set"));
        assert!(!topic_matches("State/*", "State")); // Must have something after /
        assert!(topic_matches("exact/topic", "exact/topic"));
        assert!(!topic_matches("exact/topic", "other/topic"));
    }

    #[test]
    fn test_mock_dds_interface() {
        let mock = MockDdsInterface::new();

        mock.add_reader(DiscoveredReader {
            guid: [0x01; 16],
            topic: "State/Temperature".to_string(),
            type_name: "Temperature".to_string(),
            durability: DurabilityKind::TransientLocal,
        });

        mock.add_reader(DiscoveredReader {
            guid: [0x02; 16],
            topic: "Command/Set".to_string(),
            type_name: "Command".to_string(),
            durability: DurabilityKind::Volatile,
        });

        let state_readers = mock.discovered_readers("State/*").unwrap();
        assert_eq!(state_readers.len(), 1);
        assert_eq!(state_readers[0].topic, "State/Temperature");

        let all_readers = mock.discovered_readers("*").unwrap();
        assert_eq!(all_readers.len(), 2);
    }

    #[test]
    fn test_mock_data_reader() {
        let mock = MockDdsInterface::new();

        mock.add_sample(ReceivedSample {
            topic: "test/topic".to_string(),
            type_name: "TestType".to_string(),
            payload: vec![1, 2, 3],
            writer_guid: [0xAA; 16],
            sequence: 1,
            timestamp_ns: 1000,
            instance_handle: [0u8; 16],
            source_timestamp_ns: None,
            destination_order_by_source: false,
            representation: 0,
        });

        let reader = mock
            .create_reader("test/topic", "TestType", DurabilityKind::Volatile)
            .unwrap();
        let samples = reader.read().unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].sequence, 1);
    }

    #[test]
    fn test_received_sample_to_sample() {
        let rs = ReceivedSample {
            topic: "test".to_string(),
            type_name: "Type".to_string(),
            payload: vec![42],
            writer_guid: [0xFF; 16],
            sequence: 99,
            timestamp_ns: 123456,
            instance_handle: [0x7A; 16],
            source_timestamp_ns: None,
            destination_order_by_source: false,
            representation: 0x0002,
        };

        let sample: Sample = rs.into();
        assert_eq!(sample.topic, "test");
        assert_eq!(sample.sequence, 99);
        assert_eq!(sample.source_guid, [0xFF; 16]);
        assert_eq!(
            sample.representation, 0x0002,
            "From<ReceivedSample> for Sample must carry representation through"
        );
        assert_eq!(
            sample.instance_handle, [0x7A; 16],
            "From<ReceivedSample> for Sample must carry instance_handle through"
        );
    }
}
