// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! MicroReader - DDS DataReader for embedded

use crate::error::{Error, Result};
use crate::rtps::submessages::Data;
use crate::rtps::{EntityId, GuidPrefix, RtpsHeader, GUID};
use crate::transport::Transport;
use crate::MAX_PACKET_SIZE;

/// Sample received from reader
#[derive(Debug)]
pub struct Sample<'a> {
    /// Source writer GUID
    pub writer_guid: GUID,

    /// Sequence number
    pub sequence_number: crate::rtps::SequenceNumber,

    /// Payload (CDR-encoded)
    pub payload: &'a [u8],
}

/// MicroReader - DDS DataReader
///
/// Receives data samples from a topic.
///
/// # Design
///
/// - BEST_EFFORT QoS (no acknowledgments)
/// - No history cache (process immediately)
/// - Fixed-size receive buffer
///
/// # Example
///
/// ```ignore
/// let reader = MicroReader::new(
///     participant.guid_prefix(),
///     reader_entity_id,
///     "Temperature",
/// );
///
/// // Read sample
/// if let Some(sample) = reader.read(participant.transport_mut())? {
///     let mut decoder = CdrDecoder::new(sample.payload);
///     let temp: f32 = decoder.decode_f32()?;
///     let timestamp: i64 = decoder.decode_i64()?;
/// }
/// ```
#[derive(Debug, PartialEq)]
pub struct MicroReader {
    /// Reader GUID
    guid: GUID,

    /// Topic name
    topic_name: [u8; 64],
    topic_len: usize,

    /// Receive buffer (reusable)
    rx_buffer: [u8; MAX_PACKET_SIZE],
}

impl MicroReader {
    /// Create a new reader
    ///
    /// # Arguments
    ///
    /// * `guid_prefix` - Participant's GUID prefix
    /// * `entity_id` - Reader's entity ID
    /// * `topic_name` - Topic name (max 63 chars)
    pub fn new(guid_prefix: GuidPrefix, entity_id: EntityId, topic_name: &str) -> Result<Self> {
        if topic_name.len() > 63 {
            return Err(Error::InvalidParameter);
        }

        let mut topic_name_buf = [0u8; 64];
        topic_name_buf[0..topic_name.len()].copy_from_slice(topic_name.as_bytes());

        Ok(Self {
            guid: GUID::new(guid_prefix, entity_id),
            topic_name: topic_name_buf,
            topic_len: topic_name.len(),
            rx_buffer: [0u8; MAX_PACKET_SIZE],
        })
    }

    /// Get reader GUID
    pub const fn guid(&self) -> GUID {
        self.guid
    }

    /// Get topic name
    pub fn topic_name(&self) -> &str {
        core::str::from_utf8(&self.topic_name[0..self.topic_len]).unwrap_or("")
    }

    /// Read a sample (non-blocking)
    ///
    /// Returns `None` if no sample available.
    pub fn read<T: Transport>(&mut self, transport: &mut T) -> Result<Option<Sample<'_>>> {
        // Try to receive packet
        let (bytes_received, _source_locator) = match transport.try_recv(&mut self.rx_buffer) {
            Ok(result) => result,
            Err(Error::ResourceExhausted) => return Ok(None), // No packet available
            Err(e) => return Err(e),
        };

        // Parse RTPS header
        let header = RtpsHeader::decode(&self.rx_buffer[0..bytes_received])?;

        // Parse DATA submessage
        let (data, payload_offset) = Data::decode(&self.rx_buffer[RtpsHeader::SIZE..])?;

        // Filter by entity ID (if specified)
        if data.reader_id != EntityId::UNKNOWN && data.reader_id != self.guid.entity_id {
            return Ok(None); // Not for us
        }

        // Extract payload
        let payload_start = RtpsHeader::SIZE + payload_offset;
        let payload_end = bytes_received;

        if payload_start >= payload_end {
            return Err(Error::DecodingError);
        }

        let payload = &self.rx_buffer[payload_start..payload_end];

        // Build writer GUID
        let writer_guid = GUID::new(header.guid_prefix, data.writer_id);

        Ok(Some(Sample {
            writer_guid,
            sequence_number: data.writer_sn,
            payload,
        }))
    }

    // Note: Blocking read is not provided due to borrow checker limitations.
    // In embedded environments, you should call `read()` in a loop with
    // appropriate sleep/yield between iterations.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::NullTransport;

    #[test]
    fn test_reader_creation() {
        let reader = MicroReader::new(
            GuidPrefix::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            EntityId::new([0, 0, 0, 0xc7]),
            "TestTopic",
        )
        .unwrap();

        assert_eq!(reader.topic_name(), "TestTopic");
    }

    #[test]
    fn test_reader_no_data() {
        let mut reader =
            MicroReader::new(GuidPrefix::default(), EntityId::default(), "TestTopic").unwrap();

        let mut transport = NullTransport::default();

        let result = reader.read(&mut transport).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_reader_topic_name_too_long() {
        let long_name = "a".repeat(100);
        let result = MicroReader::new(GuidPrefix::default(), EntityId::default(), &long_name);

        assert_eq!(result, Err(Error::InvalidParameter));
    }
}
