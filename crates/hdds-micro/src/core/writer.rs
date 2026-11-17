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
    /// Send DATA to `dest_locator` from now on. The sequence number carries
    /// on, so the stream stays continuous for the reader that follows it.
    pub fn set_dest_locator(&mut self, dest_locator: Locator) {
        self.dest_locator = dest_locator;
    }

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

    /// Write a sample encoded by [`crate::cdr::CdrEncoder`]
    ///
    /// `payload` is the CDR body alone. The serialized payload on the wire is
    /// that body behind the SerializedPayloadHeader (RTPS 2.5 10.2), whose
    /// identifier is `CDR_LE`: the encoder writes classic CDR, XCDR1, little
    /// endian (see the `cdr` module). For a body in another encoding use
    /// [`MicroWriter::write_with_representation`].
    ///
    /// # Arguments
    ///
    /// * `payload` - CDR-encoded body, without encapsulation header
    /// * `transport` - Transport to send through
    pub fn write<T: Transport>(&mut self, payload: &[u8], transport: &mut T) -> Result<()> {
        self.write_with_representation(crate::cdr::CDR_LE, payload, transport)
    }

    /// Write a sample whose body is encoded as `representation` says
    ///
    /// `representation` is the identifier of DDS-XTypes 1.3 7.6.3.1.2,
    /// Table 60, for the encoding of `body`: `PL_CDR_LE` for the parameter
    /// list of a MUTABLE type under XCDR1, `CDR2_LE` / `D_CDR2_LE` /
    /// `PL_CDR2_LE` for a body an XCDR2 encoder produced. The writer copies
    /// `body` unchanged and does not check it against the identifier: the
    /// identifier is the caller's statement about the bytes. Only the
    /// little-endian XCDR identifiers are accepted
    /// ([`crate::cdr::representation_is_xcdr_le`]); any other is refused
    /// with `InvalidParameter`.
    pub fn write_with_representation<T: Transport>(
        &mut self,
        representation: u16,
        body: &[u8],
        transport: &mut T,
    ) -> Result<()> {
        if !crate::cdr::representation_is_xcdr_le(representation) {
            return Err(Error::InvalidParameter);
        }

        // Build RTPS packet: Header + DATA submessage + serialized payload
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

        // 3. Serialized payload: SerializedPayloadHeader, then the body.
        // The identifier is two octets in the order Table 60 lists them;
        // the options are zero.
        let payload_offset = header_len + data_len;
        let serialized_len = crate::cdr::ENCAPSULATION_HEADER_SIZE + body.len();
        if payload_offset + serialized_len > MAX_PACKET_SIZE {
            return Err(Error::BufferTooSmall);
        }
        let body_offset = payload_offset + crate::cdr::ENCAPSULATION_HEADER_SIZE;
        packet[payload_offset..payload_offset + 2].copy_from_slice(&representation.to_be_bytes());
        packet[payload_offset + 2..body_offset].copy_from_slice(&[0, 0]);
        packet[body_offset..body_offset + body.len()].copy_from_slice(body);

        let total_len = payload_offset + serialized_len;

        // Update DATA submessage header with correct octets_to_next
        // (20 bytes fixed fields + serialized payload length)
        let octets_to_next = (20 + serialized_len) as u16;
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

    /// Keeps the last datagram it was asked to send.
    struct LastDatagram {
        packet: [u8; MAX_PACKET_SIZE],
        len: usize,
    }

    impl Default for LastDatagram {
        fn default() -> Self {
            Self {
                packet: [0; MAX_PACKET_SIZE],
                len: 0,
            }
        }
    }

    impl Transport for LastDatagram {
        fn init(&mut self) -> Result<()> {
            Ok(())
        }
        fn send(&mut self, data: &[u8], _dest: &Locator) -> Result<usize> {
            self.packet[..data.len()].copy_from_slice(data);
            self.len = data.len();
            Ok(data.len())
        }
        fn recv(&mut self, _buf: &mut [u8]) -> Result<(usize, Locator)> {
            Err(Error::TransportError)
        }
        fn try_recv(&mut self, _buf: &mut [u8]) -> Result<(usize, Locator)> {
            Err(Error::ResourceExhausted)
        }
        fn local_locator(&self) -> Locator {
            Locator::udpv4([127, 0, 0, 1], 7400)
        }
        fn mtu(&self) -> usize {
            MAX_PACKET_SIZE
        }
        fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    fn writer() -> MicroWriter {
        MicroWriter::new(
            GuidPrefix::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            EntityId::new([0, 0, 1, 0x02]),
            "TestTopic",
            Locator::udpv4([239, 255, 0, 1], 7400),
        )
        .unwrap()
    }

    /// RTPS 2.5 10.2: "All SerializedPayload shall start with the
    /// SerializedPayloadHeader". The body the encoder wrote is XCDR1, so the
    /// identifier is `CDR_LE` `{0x00, 0x01}` (DDS-XTypes 1.3 Table 60), and
    /// the DATA submessage counts the four header octets.
    #[test]
    fn a_sample_goes_out_behind_a_cdr_le_encapsulation_header() {
        let mut buf = [0u8; 32];
        let mut encoder = CdrEncoder::new(&mut buf);
        encoder.encode_u8(0x11).unwrap();
        encoder.encode_i64(0x0102_0304_0506_0708).unwrap();
        let body = encoder.finish();

        let mut transport = LastDatagram::default();
        writer().write(body, &mut transport).unwrap();

        let p = &transport.packet[..transport.len];
        // 20 RTPS header + 4 submessage header + 20 fixed DATA octets.
        assert_eq!(&p[44..48], &[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(&p[48..], body);
        let octets_to_next = u16::from_le_bytes([p[22], p[23]]);
        assert_eq!(usize::from(octets_to_next), 20 + 4 + body.len());
        assert_eq!(p.len(), 20 + 4 + usize::from(octets_to_next));
    }

    #[test]
    fn a_caller_states_another_encoding_and_it_is_what_goes_out() {
        let body = [0xAA, 0xBB, 0xCC, 0xDD];
        for (id, wire) in [
            (crate::cdr::PL_CDR_LE, [0x00, 0x03]),
            (crate::cdr::CDR2_LE, [0x00, 0x07]),
            (crate::cdr::D_CDR2_LE, [0x00, 0x09]),
            (crate::cdr::PL_CDR2_LE, [0x00, 0x0b]),
        ] {
            let mut transport = LastDatagram::default();
            writer()
                .write_with_representation(id, &body, &mut transport)
                .unwrap();
            let p = &transport.packet[..transport.len];
            assert_eq!(&p[44..46], &wire);
            assert_eq!(&p[46..48], &[0, 0]);
            assert_eq!(&p[48..], &body);
        }
    }

    /// A big-endian or unknown identifier is refused, and refused before
    /// anything is sent or the sequence number moves.
    #[test]
    fn an_identifier_outside_the_little_endian_xcdr_set_is_refused() {
        for id in [0x0000u16, 0x0002, 0x0006, 0x0011, 0x0004] {
            let mut transport = LastDatagram::default();
            let mut w = writer();
            assert_eq!(
                w.write_with_representation(id, &[1, 2, 3, 4], &mut transport),
                Err(Error::InvalidParameter),
                "{id:#06x}"
            );
            assert_eq!(transport.len, 0);
            assert_eq!(w.sequence_number(), SequenceNumber::MIN);
        }
    }

    /// The header counts against the packet size: a body that fills the
    /// packet without it no longer fits with it.
    #[test]
    fn the_header_counts_against_the_packet_size() {
        let body = [0u8; MAX_PACKET_SIZE - 44 - 4];
        let mut transport = LastDatagram::default();
        writer().write(&body, &mut transport).unwrap();
        assert_eq!(transport.len, MAX_PACKET_SIZE);

        let body = [0u8; MAX_PACKET_SIZE - 44 - 3];
        assert_eq!(
            writer().write(&body, &mut transport),
            Err(Error::BufferTooSmall)
        );
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
