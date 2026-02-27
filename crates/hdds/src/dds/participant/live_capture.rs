// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Live DDS capture API for type-agnostic traffic monitoring.
//!
//!
//! This module provides APIs for discovering topics and reading raw CDR payloads
//! without compile-time type knowledge, enabling tools like `hdds_viewer` to
//! capture and analyze live DDS traffic (similar to Wireshark for DDS).

use crate::core::discovery::GUID;
use crate::core::ser::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::core::types::TypeDescriptor;
use crate::dds::{Error, Result, DDS as DdsTrait};
use crate::xtypes::CompleteTypeObject;
use std::sync::Arc;
use std::time::SystemTime;

/// Raw CDR payload wrapper for type-agnostic reading.
///
/// This type bypasses CDR deserialization and stores raw bytes directly.
/// Used by `RawDataReader` to capture DDS traffic without compile-time type knowledge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBytes(pub Vec<u8>);

impl Cdr2Decode for RawBytes {
    fn decode_cdr2_le(src: &[u8]) -> std::result::Result<(Self, usize), CdrError> {
        // No deserialization - just copy raw bytes
        let len = src.len();
        Ok((RawBytes(src.to_vec()), len))
    }
}

impl Cdr2Encode for RawBytes {
    fn encode_cdr2_le(&self, buf: &mut [u8]) -> std::result::Result<usize, CdrError> {
        if buf.len() < self.0.len() {
            return Err(CdrError::BufferTooSmall);
        }
        buf[..self.0.len()].copy_from_slice(&self.0);
        Ok(self.0.len())
    }

    fn max_cdr2_size(&self) -> usize {
        self.0.len()
    }
}

impl DdsTrait for RawBytes {
    fn type_descriptor() -> &'static TypeDescriptor {
        static DESC: TypeDescriptor = TypeDescriptor {
            type_id: 0x00000000,
            type_name: "RawBytes",
            size_bytes: 0, // Variable size
            alignment: 1,
            is_variable_size: true,
            fields: &[], // No fields - opaque payload
        };
        &DESC
    }

    fn encode_cdr2(&self, buf: &mut [u8]) -> Result<usize> {
        use crate::core::ser::Cdr2Encode;
        self.encode_cdr2_le(buf).map_err(|e| match e {
            CdrError::BufferTooSmall => Error::BufferTooSmall,
            _ => Error::SerializationError,
        })
    }

    fn decode_cdr2(buf: &[u8]) -> Result<Self> {
        use crate::core::ser::Cdr2Decode;
        Self::decode_cdr2_le(buf)
            .map(|(val, _)| val)
            .map_err(|e| match e {
                CdrError::UnexpectedEof => Error::EndianMismatch,
                _ => Error::SerializationError,
            })
    }
}

/// Information about a discovered topic on the DDS bus.
///
/// Returned by [`Participant::discover_topics()`](super::Participant::discover_topics).
#[derive(Debug, Clone)]
pub struct DiscoveredTopicInfo {
    /// Topic name (e.g., "/chatter")
    pub name: String,

    /// Type name (e.g., "std_msgs::msg::String")
    pub type_name: String,

    /// XTypes TypeIdentifier (for type compatibility checking)
    pub type_id: Vec<u8>,

    /// Complete TypeObject (if discovered)
    pub type_object: Option<CompleteTypeObject>,

    /// Number of publishers for this topic
    pub publisher_count: usize,

    /// Number of subscribers for this topic
    pub subscriber_count: usize,

    /// QoS profile advertised by the first discovered endpoint
    pub qos: crate::dds::QoS,

    /// QoS hash (for matching)
    pub qos_hash: u32,
}

/// A raw sample with unparsed CDR payload.
///
/// Returned by [`RawDataReader::try_take_raw()`].
#[derive(Debug, Clone)]
pub struct RawSample {
    /// Raw CDR2 payload (unparsed bytes)
    pub payload: Vec<u8>,

    /// Source timestamp (from DataWriter)
    pub source_timestamp: SystemTime,

    /// Reception timestamp (local time)
    pub reception_timestamp: SystemTime,

    /// Sample sequence number (if available)
    pub sequence_number: Option<u64>,

    /// GUID of the source DataWriter
    pub writer_guid: GUID,
}

/// A DataReader that returns raw CDR payloads instead of typed data.
///
/// Created by [`Participant::create_raw_reader()`](super::Participant::create_raw_reader).
pub struct RawDataReader {
    /// Internal DataReader using RawBytes type
    inner: crate::dds::DataReader<RawBytes>,
}

/// A DataWriter that sends raw CDR payloads without compile-time type knowledge.
pub struct RawDataWriter {
    inner: crate::dds::DataWriter<RawBytes>,
}

impl RawDataReader {
    /// Create a new RawDataReader wrapping a DataReader<RawBytes>.
    ///
    /// # Arguments
    /// * `inner` - The underlying DataReader<RawBytes>
    pub(super) fn new(inner: crate::dds::DataReader<RawBytes>) -> Self {
        Self { inner }
    }

    /// Try to take available samples without blocking.
    ///
    /// Returns all available raw samples since the last call.
    ///
    /// # Returns
    /// Vector of raw samples with metadata
    ///
    /// # Errors
    /// Returns error if reading fails
    pub fn try_take_raw(&self) -> Result<Vec<RawSample>> {
        let mut samples = Vec::new();
        let reception_timestamp = SystemTime::now();

        // Drain all available samples from the inner reader
        while let Some(raw_bytes) = self.inner.take()? {
            // CDR encapsulation header is now stripped in the router (route_data_packet
            // and route_reassembled_data), so the payload is raw serialized data.
            let payload = raw_bytes.0;
            samples.push(RawSample {
                payload,
                // Phase 7c: RTPS metadata extraction tracked in #GITEA_ISSUE_TBD
                source_timestamp: reception_timestamp,
                reception_timestamp,
                sequence_number: None,
                writer_guid: GUID::zero(),
            });
        }

        Ok(samples)
    }
}

impl RawDataWriter {
    /// Create a new RawDataWriter wrapping a DataWriter<RawBytes>.
    pub(super) fn new(inner: crate::dds::DataWriter<RawBytes>) -> Self {
        Self { inner }
    }

    /// Write a raw CDR payload.
    ///
    /// # Errors
    /// Returns error if the write fails.
    pub fn write_raw(&self, payload: &[u8]) -> Result<()> {
        let msg = RawBytes(payload.to_vec());
        self.inner.write(&msg)
    }

    /// Access the configured QoS.
    #[must_use]
    pub fn qos(&self) -> &crate::dds::QoS {
        self.inner.qos()
    }

    /// Return the topic name for this writer.
    #[must_use]
    pub fn topic_name(&self) -> &str {
        self.inner.topic_name()
    }
}

impl super::Participant {
    /// Discover all active topics on the DDS bus.
    ///
    /// Uses RTPS built-in endpoints (DCPSPublication, DCPSSubscription) to
    /// enumerate all topics currently in use by remote participants.
    ///
    /// # Returns
    /// List of discovered topics with their metadata
    ///
    /// # Errors
    /// Returns error if discovery fails or if DDS discovery is not initialized
    ///
    /// # Example
    /// ```no_run
    /// use hdds::Participant;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let participant = Participant::builder("viewer").domain_id(0).build()?;
    /// let topics = participant.discover_topics()?;
    /// for topic in topics {
    ///     println!("Found topic: {} (type: {})", topic.name, topic.type_name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn discover_topics(&self) -> Result<Vec<DiscoveredTopicInfo>> {
        // Check if discovery is available
        let Some(ref discovery_fsm) = self.discovery_fsm else {
            return Err(Error::InvalidState(
                "Discovery not initialized (participant may be in IntraProcess mode)".to_string(),
            ));
        };

        // Query all discovered topics from DiscoveryFsm
        let all_topics = discovery_fsm.get_all_topics();

        let mut result = Vec::new();

        for (topic_name, (writers, readers)) in all_topics {
            // Filter out built-in DDS topics (start with "DCPS")
            if topic_name.starts_with("DCPS") {
                continue;
            }

            // Skip topics with no endpoints
            if writers.is_empty() && readers.is_empty() {
                continue;
            }

            // Extract metadata from first endpoint (all should have same type_name/type_id)
            let first_endpoint = writers.first().or_else(|| readers.first());

            if let Some(endpoint) = first_endpoint {
                // v61: Compute QoS hash from actual QoS object
                // Simple hash combining reliability+durability+history for telemetry
                use crate::dds::qos::{Durability, History, Reliability};
                let rel_val = match endpoint.qos.reliability {
                    Reliability::BestEffort => 1u32,
                    Reliability::Reliable => 2u32,
                };
                let dur_val = match endpoint.qos.durability {
                    Durability::Volatile => 0u32,
                    Durability::TransientLocal => 1u32,
                    Durability::Persistent => 3u32,
                };
                let hist_val = match endpoint.qos.history {
                    History::KeepLast(depth) => depth & 0xFF,
                    History::KeepAll => 0xFF,
                };
                let qos_hash = (rel_val << 16) | (dur_val << 8) | hist_val;

                // Extract type_id (XTypes TypeIdentifier bytes)
                // For now, use empty Vec (will be populated with real TypeObject in Phase 8b)
                let type_id = Vec::new();

                result.push(DiscoveredTopicInfo {
                    name: topic_name,
                    type_name: endpoint.type_name.clone(),
                    type_id,
                    type_object: endpoint.type_object.clone(),
                    publisher_count: writers.len(),
                    subscriber_count: readers.len(),
                    qos: endpoint.qos.clone(),
                    qos_hash,
                });
            }
        }

        Ok(result)
    }

    /// Create a raw DataReader for a topic (no type checking).
    ///
    /// Subscribes to a topic and returns raw CDR payloads without deserialization.
    /// This allows monitoring DDS traffic without knowing the data type at compile-time.
    ///
    /// # Arguments
    /// * `topic_name` - Name of the topic to subscribe to
    /// * `qos` - Optional QoS (uses default if None)
    ///
    /// # Returns
    /// RawDataReader that yields unparsed CDR payloads
    ///
    /// # Errors
    /// Returns error if subscription fails or if transport is not initialized
    ///
    /// # Example
    /// ```no_run
    /// use hdds::Participant;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let participant = Participant::builder("viewer").domain_id(0).build()?;
    /// let raw_reader = participant.create_raw_reader("/chatter", None)?;
    ///
    /// let samples = raw_reader.try_take_raw()?;
    /// println!("Received {} raw samples", samples.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_raw_reader(
        self: &Arc<Self>,
        topic_name: &str,
        qos: Option<crate::dds::QoS>,
    ) -> Result<RawDataReader> {
        let type_name = RawBytes::type_descriptor().type_name;
        self.create_raw_reader_with_type(topic_name, type_name, qos, None)
    }

    /// Create a raw DataReader for a topic with an explicit type name.
    ///
    /// # Arguments
    /// * `topic_name` - Name of the topic to subscribe to
    /// * `type_name` - DDS type name to announce for discovery
    /// * `qos` - Optional QoS (uses default if None)
    /// * `type_object` - Optional CompleteTypeObject (XTypes)
    pub fn create_raw_reader_with_type(
        self: &Arc<Self>,
        topic_name: &str,
        type_name: &str,
        qos: Option<crate::dds::QoS>,
        type_object: Option<CompleteTypeObject>,
    ) -> Result<RawDataReader> {
        // Check if transport is available
        if self.transport.is_none() {
            return Err(Error::InvalidState(
                "Transport not initialized (participant may be in IntraProcess mode)".to_string(),
            ));
        }

        // Use default QoS if not provided
        let qos = qos.unwrap_or_default();

        // Create DataReader<RawBytes> using the same pattern as create_reader()
        let mut builder = self
            .topic::<RawBytes>(topic_name)?
            .reader()
            .qos(qos.clone())
            .with_type_name_override(type_name);

        if let Some(type_object) = type_object {
            builder = builder.with_type_object_override(type_object);
        }

        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        builder = builder.with_participant_guard(self.graph_guard());

        let inner_reader = builder.build()?;

        Ok(RawDataReader::new(inner_reader))
    }

    /// Create a raw DataWriter for a topic with an explicit type name.
    ///
    /// # Arguments
    /// * `topic_name` - Name of the topic to publish to
    /// * `type_name` - DDS type name to announce for discovery
    /// * `qos` - Optional QoS (uses default if None)
    /// * `type_object` - Optional CompleteTypeObject (XTypes)
    pub fn create_raw_writer_with_type(
        self: &Arc<Self>,
        topic_name: &str,
        type_name: &str,
        qos: Option<crate::dds::QoS>,
        type_object: Option<CompleteTypeObject>,
    ) -> Result<RawDataWriter> {
        if self.transport.is_none() {
            return Err(Error::InvalidState(
                "Transport not initialized (participant may be in IntraProcess mode)".to_string(),
            ));
        }

        let qos = qos.unwrap_or_default();

        let mut builder = self
            .topic::<RawBytes>(topic_name)?
            .writer()
            .qos(qos.clone())
            .with_type_name_override(type_name);

        if let Some(type_object) = type_object {
            builder = builder.with_type_object_override(type_object);
        }

        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        if let Some(ref discovery_fsm) = self.discovery_fsm {
            builder = builder.with_endpoint_registry(discovery_fsm.endpoint_registry());
        }

        builder = builder.with_domain_state(self.domain_state.clone());

        let inner_writer = builder.build()?;

        Ok(RawDataWriter::new(inner_writer))
    }

    /// Create a raw DataWriter for a topic (no type checking).
    pub fn create_raw_writer(
        self: &Arc<Self>,
        topic_name: &str,
        qos: Option<crate::dds::QoS>,
    ) -> Result<RawDataWriter> {
        let type_name = RawBytes::type_descriptor().type_name;
        self.create_raw_writer_with_type(topic_name, type_name, qos, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovered_topic_info_construction() {
        let info = DiscoveredTopicInfo {
            name: "/chatter".to_string(),
            type_name: "std_msgs::msg::String".to_string(),
            type_id: vec![1, 2, 3, 4],
            type_object: None,
            publisher_count: 2,
            subscriber_count: 1,
            qos: crate::dds::QoS::best_effort(),
            qos_hash: 0x12345678,
        };

        assert_eq!(info.name, "/chatter");
        assert_eq!(info.type_name, "std_msgs::msg::String");
        assert_eq!(info.publisher_count, 2);
        assert_eq!(info.subscriber_count, 1);
    }

    #[test]
    fn test_raw_sample_construction() {
        let sample = RawSample {
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
            source_timestamp: SystemTime::now(),
            reception_timestamp: SystemTime::now(),
            sequence_number: Some(42),
            writer_guid: GUID::zero(),
        };

        assert_eq!(sample.payload.len(), 4);
        assert_eq!(sample.sequence_number, Some(42));
    }

    // Note: RawDataReader construction tests removed
    // These require a full Participant infrastructure and will be tested
    // via integration tests (Phase 7b)
}
