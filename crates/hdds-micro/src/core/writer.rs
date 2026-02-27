// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! MicroWriter - DDS DataWriter for embedded

use crate::error::{Error, Result};
use crate::rtps::submessages::Data;
use crate::rtps::{EntityId, GuidPrefix, Locator, RtpsHeader, SequenceNumber, GUID};
use crate::transport::Transport;
use crate::MAX_PACKET_SIZE;

/// MicroWriter - DDS DataWriter
///
/// Publishes data samples to a topic.
///
/// # Design
///
/// - BEST_EFFORT QoS (no retransmissions)
/// - No history cache (fire-and-forget)
/// - Fixed-size packets
///
/// # Example
///
/// ```ignore
/// let writer = MicroWriter::new(
///     participant.guid_prefix(),
///     writer_entity_id,
///     "Temperature",
///     dest_locator,
/// );
///
/// // Encode sample
/// let mut buf = [0u8; 256];
/// let mut encoder = CdrEncoder::new(&mut buf);
/// encoder.encode_f32(23.5)?;
/// encoder.encode_i64(123456)?;
/// let payload = encoder.finish();
///
/// // Write sample
/// writer.write(payload, participant.transport_mut())?;
/// ```
#[derive(Debug, PartialEq)]
pub struct MicroWriter {
    /// Writer GUID
    guid: GUID,

    /// Topic name
    topic_name: [u8; 64],
    topic_len: usize,

    /// Destination locator (where to send DATA)
    dest_locator: Locator,

    /// Current sequence number
    sequence_number: SequenceNumber,
}

impl MicroWriter {
    /// Create a new writer
    ///
    /// # Arguments
    ///
    /// * `guid_prefix` - Participant's GUID prefix
    /// * `entity_id` - Writer's entity ID
    /// * `topic_name` - Topic name (max 63 chars)
    /// * `dest_locator` - Destination locator (multicast or unicast)
    pub fn new(
        guid_prefix: GuidPrefix,
        entity_id: EntityId,
        topic_name: &str,
        dest_locator: Locator,
    ) -> Result<Self> {
        if topic_name.len() > 63 {
            return Err(Error::InvalidParameter);
        }

        let mut topic_name_buf = [0u8; 64];
        topic_name_buf[0..topic_name.len()].copy_from_slice(topic_name.as_bytes());

        Ok(Self {
            guid: GUID::new(guid_prefix, entity_id),
            topic_name: topic_name_buf,
            topic_len: topic_name.len(),
            dest_locator,
            sequence_number: SequenceNumber::MIN,
        })
    }

    /// Get writer GUID
    pub const fn guid(&self) -> GUID {
        self.guid
    }

    /// Get topic name
    pub fn topic_name(&self) -> &str {
        core::str::from_utf8(&self.topic_name[0..self.topic_len]).unwrap_or("")
    }

    /// Get current sequence number
    pub const fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }

    /// Write a sample
    ///
    /// # Arguments
    ///
    /// * `payload` - CDR-encoded payload
    /// * `transport` - Transport to send through
    pub fn write<T: Transport>(&mut self, payload: &[u8], transport: &mut T) -> Result<()> {
        // Build RTPS packet: Header + DATA submessage + payload
        let mut packet = [0u8; MAX_PACKET_SIZE];

        // 1. RTPS header (20 bytes)
        let header = RtpsHeader::new(
            crate::rtps::ProtocolVersion::RTPS_2_5,
            crate::rtps::VendorId::HDDS,
            self.guid.prefix,
        );
        let header_len = header.encode(&mut packet)?;

        // 2. DATA submessage header (24 bytes)
        let data = Data::new(
            EntityId::UNKNOWN, // reader_id = UNKNOWN for multicast
            self.guid.entity_id,
            self.sequence_number,
        );
        let data_len = data.encode_header(&mut packet[header_len..])?;

        // 3. Payload
        let payload_offset = header_len + data_len;
        if payload_offset + payload.len() > MAX_PACKET_SIZE {
            return Err(Error::BufferTooSmall);
        }
        packet[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

        let total_len = payload_offset + payload.len();

        // Update DATA submessage header with correct octets_to_next
        // (20 bytes fixed fields + payload length)
        let octets_to_next = (20 + payload.len()) as u16;
        packet[header_len + 2] = (octets_to_next & 0xff) as u8;
        packet[header_len + 3] = ((octets_to_next >> 8) & 0xff) as u8;

        // Send packet
        transport.send(&packet[0..total_len], &self.dest_locator)?;

        // Increment sequence number
        self.sequence_number.increment();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdr::CdrEncoder;
    use crate::transport::NullTransport;

    #[test]
    fn test_writer_creation() {
        let writer = MicroWriter::new(
            GuidPrefix::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            EntityId::new([0, 0, 0, 0xc2]),
            "TestTopic",
            Locator::udpv4([239, 255, 0, 1], 7400),
        )
        .unwrap();

        assert_eq!(writer.topic_name(), "TestTopic");
        assert_eq!(writer.sequence_number(), SequenceNumber::MIN);
    }

    #[test]
    fn test_writer_write() {
        let mut writer = MicroWriter::new(
            GuidPrefix::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            EntityId::new([0, 0, 0, 0xc2]),
            "TestTopic",
            Locator::udpv4([239, 255, 0, 1], 7400),
        )
        .unwrap();

        let mut transport = NullTransport::default();

        // Encode sample
        let mut buf = [0u8; 128];
        let mut encoder = CdrEncoder::new(&mut buf);
        encoder.encode_f32(23.5).unwrap();
        let payload = encoder.finish();

        // Write sample
        writer.write(payload, &mut transport).unwrap();

        // Sequence number should increment
        assert_eq!(writer.sequence_number(), SequenceNumber::new(2));
    }

    #[test]
    fn test_writer_topic_name_too_long() {
        let long_name = "a".repeat(100);
        let result = MicroWriter::new(
            GuidPrefix::default(),
            EntityId::default(),
            &long_name,
            Locator::default(),
        );

        assert_eq!(result, Err(Error::InvalidParameter));
    }
}
