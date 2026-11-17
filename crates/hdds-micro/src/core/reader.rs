// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! MicroReader - DDS DataReader for embedded

use crate::cdr::CdrDecoder;
use crate::error::{Error, Result};
use crate::rtps::submessages::{Data, SubmessageHeader};
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

    /// Representation identifier of the serialized payload, the first two
    /// octets of its SerializedPayloadHeader read in the order DDS-XTypes
    /// 1.3 Table 60 lists them (`0x0001` is `CDR_LE`).
    pub representation: u16,

    /// Body of the serialized payload: what follows the 4-octet
    /// SerializedPayloadHeader (RTPS 2.5 10.2), in the encoding
    /// `representation` names.
    pub payload: &'a [u8],
}

impl<'a> Sample<'a> {
    /// A decoder over the body, when its encoding is the one
    /// [`CdrDecoder`] reads: XCDR1, little endian (`CDR_LE` or
    /// `PL_CDR_LE`).
    ///
    /// Any other identifier is refused with `DecodingError`: an XCDR2 body
    /// places an 8-byte member at a different offset (DDS-XTypes 1.3
    /// 7.4.3.2.2, `MAXALIGN(VERSION2) = 4`), and reading it with XCDR1
    /// alignment would deliver wrong values with no error. A full HDDS
    /// writer sends the representation it offers, resolved at its creation:
    /// XCDR1 by default for a type that encodes it natively, XCDR2 for a C
    /// ABI writer or a type that does not; set `data_representation` XCDR1
    /// on a writer that offers XCDR2 to talk to this crate.
    pub fn decoder(&self) -> Result<CdrDecoder<'a>> {
        if crate::cdr::representation_is_xcdr1_le(self.representation) {
            Ok(CdrDecoder::new(self.payload))
        } else {
            Err(Error::DecodingError)
        }
    }
}

/// Outcome of one non-blocking receive ([`MicroReader::read_next`]).
#[derive(Debug)]
pub enum Next<'a> {
    /// A DATA sample addressed to this reader.
    Sample(Sample<'a>),
    /// A frame was consumed and carries no sample for this reader: it is
    /// malformed, addressed to another reader, or larger than the receive
    /// buffer. Keep draining: more frames may be queued behind it.
    Skipped,
    /// The transport has nothing queued.
    Empty,
}

/// End of the submessage whose header starts at `offset` in `frame`.
///
/// RTPS 2.5 9.4.5.1.3, as the HDDS walker reads it
/// (`core::discovery::multicast::classifier::walk`): `octetsToNextHeader` 0
/// means the submessage extends to the end of the message, otherwise its body
/// ends `octetsToNextHeader` octets after its header. A body that ends past
/// the frame is refused: the HDDS walker recovers from such a length by a
/// scan, which this receiver does not do.
fn submessage_end(frame: &[u8], offset: usize) -> Result<usize> {
    let (_flags, octets_to_next) = SubmessageHeader::framing(&frame[offset..])?;
    let end = if octets_to_next == 0 {
        frame.len()
    } else {
        offset + SubmessageHeader::SIZE + octets_to_next as usize
    };
    if end > frame.len() {
        return Err(Error::InvalidSubmessage);
    }
    Ok(end)
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
///     let mut decoder = sample.decoder()?;
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

    /// Receive one frame into the receive buffer: its length, or `None`
    /// when the transport has nothing queued.
    fn receive<T: Transport>(&mut self, transport: &mut T) -> Result<Option<usize>> {
        match transport.try_recv(&mut self.rx_buffer) {
            Ok((bytes_received, _source_locator)) => Ok(Some(bytes_received)),
            Err(Error::ResourceExhausted) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Decode the `len`-octet frame held in the receive buffer. `Ok(None)`
    /// when its DATA names another reader.
    ///
    /// Rejected (an error, so the caller skips the frame and never delivers
    /// it as a sample):
    /// - a DATA whose `octetsToNextHeader` runs past the frame
    ///   ([`submessage_end`]);
    /// - a sequence number below 1, which covers a negative high word and
    ///   SEQUENCENUMBER_UNKNOWN (RTPS 2.5 9.3.2);
    /// - a payload that does not lie inside the DATA: `octetsToInlineQos`
    ///   pointing into the fixed fields, or a payload shorter than its
    ///   encapsulation header.
    fn decode_sample(&self, len: usize) -> Result<Option<Sample<'_>>> {
        let frame = &self.rx_buffer[0..len];

        // Parse RTPS header
        let header = RtpsHeader::decode(frame)?;

        // The DATA is the first submessage. Its body ends where its
        // octetsToNextHeader says, inside this frame: a body that runs past
        // the frame is not read from the octets behind it.
        let body_end = submessage_end(frame, RtpsHeader::SIZE)?;
        let (data, payload_offset) = Data::decode(&frame[RtpsHeader::SIZE..body_end])?;

        // RTPS 2.5 9.3.2: valid sequence numbers are at least 1. A negative
        // high word makes the value negative, so it is refused here too.
        if data.writer_sn.value() < 1 {
            return Err(Error::InvalidSubmessage);
        }

        // Filter by entity ID (if specified)
        if data.reader_id != EntityId::UNKNOWN && data.reader_id != self.guid.entity_id {
            return Ok(None); // Not for us
        }

        // Extract the serialized payload: a SerializedPayloadHeader, then
        // the body (RTPS 2.5 10.2). The payload lies inside this DATA:
        // after the fixed fields (octetsToInlineQos cannot point back into
        // them) and before the end of the submessage, not the end of the
        // frame. Fewer than four octets cannot carry the header.
        let payload_start = RtpsHeader::SIZE + payload_offset;
        let payload_end = body_end;

        if payload_offset < Data::MIN_SIZE
            || payload_start >= payload_end
            || payload_end - payload_start < crate::cdr::ENCAPSULATION_HEADER_SIZE
        {
            return Err(Error::DecodingError);
        }

        let representation = u16::from_be_bytes([
            self.rx_buffer[payload_start],
            self.rx_buffer[payload_start + 1],
        ]);
        let body_start = payload_start + crate::cdr::ENCAPSULATION_HEADER_SIZE;
        let payload = &self.rx_buffer[body_start..payload_end];

        // Build writer GUID
        let writer_guid = GUID::new(header.guid_prefix, data.writer_id);

        Ok(Some(Sample {
            writer_guid,
            sequence_number: data.writer_sn,
            representation,
            payload,
        }))
    }

    /// Read a sample (non-blocking)
    ///
    /// Returns `None` if no sample available.
    pub fn read<T: Transport>(&mut self, transport: &mut T) -> Result<Option<Sample<'_>>> {
        match self.receive(transport)? {
            None => Ok(None),
            Some(len) => self.decode_sample(len),
        }
    }

    /// Non-blocking receive that tells "queue empty" apart from "frame
    /// skipped".
    ///
    /// Only [`Next::Empty`] means nothing is queued. A caller that stops at
    /// [`Next::Skipped`] leaves the frames behind it in the queue, and a ring
    /// only re-arms its notification once it finds the queue empty. A frame
    /// larger than the receive buffer is consumed by the transport, which
    /// reports it as [`Error::BufferTooSmall`]; that becomes
    /// [`Next::Skipped`]. Any other transport error is returned.
    pub fn read_next<T: Transport>(&mut self, transport: &mut T) -> Result<Next<'_>> {
        let len = match self.receive(transport) {
            Ok(Some(len)) => len,
            Ok(None) => return Ok(Next::Empty),
            Err(Error::BufferTooSmall) => return Ok(Next::Skipped),
            Err(e) => return Err(e),
        };
        match self.decode_sample(len) {
            Ok(Some(sample)) => Ok(Next::Sample(sample)),
            Ok(None) | Err(_) => Ok(Next::Skipped),
        }
    }

    // Note: Blocking read is not provided due to borrow checker limitations.
    // In embedded environments, you should call `read()` in a loop with
    // appropriate sleep/yield between iterations.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtps::Locator;
    use crate::transport::{NullTransport, Transport};

    /// The RTPS header, the DATA submessage header and its 20 fixed octets,
    /// plus an 8-octet payload. Spelled out because this crate is `no_std`:
    /// the fixture allocates nothing, so it compiles in the lane the crate
    /// actually ships in and not only under `std`.
    const PAYLOAD_LEN: usize = 8;
    const DATAGRAM_LEN: usize = 20 + 4 + 20 + PAYLOAD_LEN;

    /// A transport that hands out one canned datagram, then nothing.
    struct OneDatagram {
        packet: [u8; DATAGRAM_LEN],
        given: bool,
    }

    impl Transport for OneDatagram {
        fn init(&mut self) -> Result<()> {
            Ok(())
        }
        fn send(&mut self, data: &[u8], _dest: &Locator) -> Result<usize> {
            Ok(data.len())
        }
        fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
            self.try_recv(buf)
        }
        fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
            if self.given {
                return Err(Error::ResourceExhausted);
            }
            self.given = true;
            buf[..DATAGRAM_LEN].copy_from_slice(&self.packet);
            Ok((DATAGRAM_LEN, Locator::udpv4([192, 0, 2, 7], 7410)))
        }
        fn local_locator(&self) -> Locator {
            Locator::udpv4([127, 0, 0, 1], 7400)
        }
        fn mtu(&self) -> usize {
            1500
        }
        fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// One DATA submessage carrying `payload`, framed in the endianness the
    /// E flag declares. `octetsToInlineQos` is the conforming 16
    /// (RTPS v2.5 Sec.8.3.8.2), which is the field the misread turns into
    /// 4096.
    fn one_data_datagram(little_endian: bool, payload: &[u8; PAYLOAD_LEN]) -> [u8; DATAGRAM_LEN] {
        let framed16 = |n: u16| {
            if little_endian {
                n.to_le_bytes()
            } else {
                n.to_be_bytes()
            }
        };
        let framed32 = |n: u32| {
            if little_endian {
                n.to_le_bytes()
            } else {
                n.to_be_bytes()
            }
        };

        let mut p = [0u8; DATAGRAM_LEN];
        p[0..4].copy_from_slice(b"RTPS");
        p[4..8].copy_from_slice(&[0x02, 0x04, 0x01, 0x03]); // a foreign vendor id
        p[8..20].copy_from_slice(&[0x77; 12]);

        p[20] = 0x15; // DATA
        p[21] = 0x04 | u8::from(little_endian); // D flag (data present) | E
        p[22..24].copy_from_slice(&framed16((20 + PAYLOAD_LEN) as u16));

        p[24..26].copy_from_slice(&framed16(0)); // extraFlags
        p[26..28].copy_from_slice(&framed16(16)); // octetsToInlineQos
        p[28..32].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerId UNKNOWN
        p[32..36].copy_from_slice(&[0x00, 0x00, 0x12, 0x02]); // a user writer
        p[36..40].copy_from_slice(&framed32(0)); // writerSN high
        p[40..44].copy_from_slice(&framed32(1)); // writerSN low
        p[44..].copy_from_slice(payload);

        assert_eq!(
            &p[44..],
            payload,
            "the sample must sit where Sec.8.3.8.2 puts it: 20 header + 4 \
             submessage header + 20 fixed DATA octets"
        );
        p
    }

    /// A conforming BIG-ENDIAN peer's sample is REFUSED, never delivered as
    /// noise.
    ///
    /// hdds-micro's declared perimeter is HDDS-to-HDDS (see the crate doc),
    /// and HDDS always emits little-endian, so reading submessage BODY fields
    /// little-endian only is SCOPE rather than a conformance defect. That is
    /// only defensible while the wrong answer is REFUSED: a `MicroReader` on
    /// the UDP transport can join a multicast group, and a DDS group carries
    /// every vendor's traffic whatever a crate documents for itself.
    ///
    /// The mechanism is worth stating because it is arithmetic and not a
    /// guard anyone wrote: a conforming `octetsToInlineQos` of 16 arrives as
    /// `00 10`, read the wrong way round it is 4096, so the payload offset
    /// lands far past the datagram and the length check refuses. A SMALL
    /// wrong offset would have been delivered.
    ///
    /// Whoever later makes the body decoders honour the E flag will see THIS
    /// TEST FAIL, and that is its second job: widening the perimeter has to
    /// come with a rewrite of the crate doc that declares it, not silently.
    #[test]
    fn a_big_endian_peers_sample_is_refused_not_read_as_noise() {
        let payload: [u8; PAYLOAD_LEN] = [0x00, 0x01, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

        let mut reader =
            MicroReader::new(GuidPrefix::default(), EntityId::default(), "TestTopic").unwrap();
        let mut little = OneDatagram {
            packet: one_data_datagram(true, &payload),
            given: false,
        };
        assert!(
            reader.read(&mut little).unwrap().is_some(),
            "the little-endian control must be read, or the big-endian half proves nothing"
        );

        let mut reader =
            MicroReader::new(GuidPrefix::default(), EntityId::default(), "TestTopic").unwrap();
        let mut big = OneDatagram {
            packet: one_data_datagram(false, &payload),
            given: false,
        };
        assert!(
            reader.read(&mut big).is_err(),
            "a big-endian sample must be REFUSED; delivering a wrong slice as a \
             valid sample would be a defect under any perimeter"
        );
    }

    /// The reader hands out the body behind the SerializedPayloadHeader and
    /// the identifier the header carries; a CDR_LE body gets a decoder.
    #[test]
    fn the_body_is_delivered_without_its_encapsulation_header() {
        // CDR_LE, options 0, then a u32.
        let payload: [u8; PAYLOAD_LEN] = [0x00, 0x01, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12];
        let mut reader =
            MicroReader::new(GuidPrefix::default(), EntityId::default(), "TestTopic").unwrap();
        let mut transport = OneDatagram {
            packet: one_data_datagram(true, &payload),
            given: false,
        };
        let sample = reader.read(&mut transport).unwrap().unwrap();
        assert_eq!(sample.representation, crate::cdr::CDR_LE);
        assert_eq!(sample.payload, &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(sample.decoder().unwrap().decode_u32().unwrap(), 0x1234_5678);
    }

    /// A body labelled XCDR2 (or big endian) is delivered with its
    /// identifier, and refused by `decoder()`: its 8-byte members are not
    /// where an XCDR1 cursor looks for them.
    #[test]
    fn a_body_in_another_encoding_gets_no_xcdr1_decoder() {
        for (wire, id) in [
            ([0x00, 0x03], Some(crate::cdr::PL_CDR_LE)),
            ([0x00, 0x07], None),
            ([0x00, 0x09], None),
            ([0x00, 0x0b], None),
            ([0x00, 0x00], None),
            ([0x00, 0x06], None),
        ] {
            let payload: [u8; PAYLOAD_LEN] = [wire[0], wire[1], 0x00, 0x00, 1, 2, 3, 4];
            let mut reader =
                MicroReader::new(GuidPrefix::default(), EntityId::default(), "TestTopic").unwrap();
            let mut transport = OneDatagram {
                packet: one_data_datagram(true, &payload),
                given: false,
            };
            let sample = reader.read(&mut transport).unwrap().unwrap();
            assert_eq!(sample.representation, u16::from_be_bytes(wire));
            assert_eq!(sample.payload, &[1, 2, 3, 4]);
            match id {
                Some(_) => assert!(sample.decoder().is_ok(), "{wire:02x?}"),
                None => assert_eq!(
                    sample.decoder().err(),
                    Some(Error::DecodingError),
                    "{wire:02x?}"
                ),
            }
        }
    }

    /// A serialized payload shorter than its own header is no sample.
    #[test]
    fn a_payload_shorter_than_the_header_is_refused() {
        let mut p = one_data_datagram(true, &[0x00, 0x01, 0x00, 0x00, 1, 2, 3, 4]);
        // Three octets of serialized payload: cut the datagram there.
        let cut = 44 + 3;
        p[22..24].copy_from_slice(&((20 + 3) as u16).to_le_bytes());
        struct Short {
            packet: [u8; DATAGRAM_LEN],
            len: usize,
            given: bool,
        }
        impl Transport for Short {
            fn init(&mut self) -> Result<()> {
                Ok(())
            }
            fn send(&mut self, data: &[u8], _dest: &Locator) -> Result<usize> {
                Ok(data.len())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
                self.try_recv(buf)
            }
            fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
                if self.given {
                    return Err(Error::ResourceExhausted);
                }
                self.given = true;
                buf[..self.len].copy_from_slice(&self.packet[..self.len]);
                Ok((self.len, Locator::udpv4([192, 0, 2, 7], 7410)))
            }
            fn local_locator(&self) -> Locator {
                Locator::udpv4([127, 0, 0, 1], 7400)
            }
            fn mtu(&self) -> usize {
                1500
            }
            fn shutdown(&mut self) -> Result<()> {
                Ok(())
            }
        }
        for len in [cut, 44 + 4] {
            // The header-only case is a 48-octet frame whose DATA ends there: 24 octets.
            let mut p = p;
            if len != cut {
                p[22..24].copy_from_slice(&24u16.to_le_bytes());
            }
            let mut reader =
                MicroReader::new(GuidPrefix::default(), EntityId::default(), "TestTopic").unwrap();
            let mut transport = Short {
                packet: p,
                len,
                given: false,
            };
            let got = reader.read(&mut transport);
            if len == cut {
                assert!(got.is_err(), "three octets cannot hold the header");
            } else {
                let sample = got.unwrap().unwrap();
                assert_eq!(sample.representation, crate::cdr::CDR_LE);
                assert!(sample.payload.is_empty());
            }
        }
    }

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

#[cfg(test)]
mod robustness_tests {
    //! Frames the stress generator sends (`hostile.py` in the seL4 stress
    //! evidence): truncation, wrong magic, a submessage length past the end,
    //! random bytes, a foreign reader, bit flips, an empty datagram. Each
    //! malformed one must be skipped: no sample is delivered for it.
    use super::*;
    use crate::rtps::Locator;
    use crate::transport::Transport;

    const READER: EntityId = EntityId::new([0, 0, 0x01, 0xc7]);

    /// A real DATA datagram captured from `hdds_pub` on the LAN: 64 octets,
    /// writer SN 1, readerId UNKNOWN, octetsToInlineQos 16, octetsToNextHeader 40.
    const BASE: [u8; 64] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x1a, 0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x01,
        0x5b, 0x00, 0x00, 0x83, 0x4c, 0x15, 0x05, 0x28, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x66, 0x66, 0xa0, 0x41, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    /// One frame, handed out once as a transport queue would.
    struct OneFrame<'a> {
        bytes: &'a [u8],
        given: bool,
    }

    impl Transport for OneFrame<'_> {
        fn init(&mut self) -> Result<()> {
            Ok(())
        }
        fn send(&mut self, data: &[u8], _dest: &Locator) -> Result<usize> {
            Ok(data.len())
        }
        fn recv(&mut self, _buf: &mut [u8]) -> Result<(usize, Locator)> {
            Err(Error::TransportError)
        }
        fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
            if self.given {
                return Err(Error::ResourceExhausted);
            }
            self.given = true;
            if self.bytes.len() > buf.len() {
                return Err(Error::BufferTooSmall);
            }
            buf[..self.bytes.len()].copy_from_slice(self.bytes);
            Ok((self.bytes.len(), Locator::udpv4([10, 0, 0, 2], 7401)))
        }
        fn local_locator(&self) -> Locator {
            Locator::udpv4([10, 0, 0, 2], 7401)
        }
        fn mtu(&self) -> usize {
            1472
        }
        fn shutdown(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// What the reader makes of one frame: `Some((sn, payload length))` when
    /// it yields a sample, `None` when the frame is skipped.
    fn deliver(frame: &[u8]) -> Option<(i64, usize)> {
        let mut reader =
            MicroReader::new(GuidPrefix::UNKNOWN, READER, "Temperature").expect("reader");
        let mut transport = OneFrame {
            bytes: frame,
            given: false,
        };
        match reader.read_next(&mut transport).expect("read_next") {
            Next::Sample(sample) => Some((sample.sequence_number.value(), sample.payload.len())),
            Next::Skipped => None,
            Next::Empty => panic!("a queued frame must not read as Empty"),
        }
    }

    fn with(octets: &[(usize, u8)]) -> [u8; 64] {
        let mut f = BASE;
        for &(at, v) in octets {
            f[at] = v;
        }
        f
    }

    #[test]
    fn the_captured_datagram_is_delivered() {
        assert_eq!(deliver(&BASE), Some((1, 16)));
    }

    #[test]
    fn truncated_frames_are_skipped() {
        for n in [
            0usize, 1, 3, 4, 8, 19, 20, 21, 24, 27, 28, 40, 43, 44, 47, 50, 63,
        ] {
            assert_eq!(deliver(&BASE[..n]), None, "truncated to {n} octets");
        }
    }

    #[test]
    fn wrong_magic_is_skipped() {
        let f = with(&[(0, b'R'), (1, b'T'), (2, b'P'), (3, b'X')]);
        assert_eq!(deliver(&f), None);
    }

    #[test]
    fn a_submessage_length_past_the_end_is_skipped() {
        // The four octetsToNextHeader values of the generator's `badlen`
        // category, little-endian in octets 22-23.
        for v in [0xffffu16, 0x0100, 0x0080, 0x0041] {
            let [lo, hi] = v.to_le_bytes();
            let f = with(&[(22, lo), (23, hi)]);
            assert_eq!(deliver(&f), None, "octetsToNextHeader {v}");
        }
    }

    #[test]
    fn zero_octets_to_next_header_runs_to_the_end_of_the_frame() {
        // RTPS 2.5 9.4.5.1.3: the last submessage, extending to the frame end.
        let f = with(&[(22, 0), (23, 0)]);
        assert_eq!(deliver(&f), Some((1, 16)));
    }

    #[test]
    fn octets_behind_the_submessage_are_not_payload() {
        // The DATA body ends 28 octets after its header; the 12 octets
        // behind it belong to a following submessage, not to the payload.
        let f = with(&[(22, 28), (23, 0)]);
        assert_eq!(deliver(&f), Some((1, 4)));
    }

    #[test]
    fn a_sequence_number_below_one_is_skipped() {
        // Negative high word (bit 31 of the high word, octet 39).
        assert_eq!(deliver(&with(&[(39, 0x80)])), None, "negative high word");
        // SN 0: high and low both zero.
        assert_eq!(deliver(&with(&[(40, 0)])), None, "SN 0");
        // SEQUENCENUMBER_UNKNOWN: high -1, low 0.
        let unknown = with(&[(36, 0xff), (37, 0xff), (38, 0xff), (39, 0xff), (40, 0)]);
        assert_eq!(deliver(&unknown), None, "SEQUENCENUMBER_UNKNOWN");
        // Control: SN 2 is delivered.
        assert_eq!(deliver(&with(&[(40, 2)])), Some((2, 16)));
    }

    #[test]
    fn an_inline_qos_offset_into_the_fixed_fields_is_skipped() {
        // octetsToInlineQos 0 would place the payload inside readerId/writerId/SN.
        assert_eq!(
            deliver(&with(&[(26, 0), (27, 0)])),
            None,
            "octetsToInlineQos 0"
        );
        // octetsToInlineQos 48 puts the payload beyond the DATA body.
        assert_eq!(
            deliver(&with(&[(26, 48), (27, 0)])),
            None,
            "octetsToInlineQos 48"
        );
    }

    #[test]
    fn a_payload_shorter_than_its_header_is_skipped() {
        // The DATA body ends 3 octets into the payload.
        assert_eq!(deliver(&with(&[(22, 23), (23, 0)])), None);
    }

    #[test]
    fn a_foreign_reader_is_skipped() {
        assert_eq!(deliver(&with(&[(28, 0), (29, 0), (30, 0), (31, 1)])), None);
    }

    #[test]
    fn random_frames_are_skipped() {
        // Deterministic generator: frames of 0..1400 octets with no RTPS magic.
        let mut state: u32 = 0x2545_f491;
        let mut buf = [0u8; 1400];
        for round in 0..64u32 {
            for octet in buf.iter_mut() {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                *octet = (state >> 16) as u8;
            }
            buf[0] = 0;
            let len = (round as usize * 23) % 1401;
            assert_eq!(deliver(&buf[..len]), None, "random frame of {len} octets");
        }
    }
}
