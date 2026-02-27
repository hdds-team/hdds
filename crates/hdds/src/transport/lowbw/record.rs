// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LBW Record encoding and decoding.
//!
//! Records are the unit of data within a frame. Multiple records can be
//! batched into a single frame for efficiency.
//!
//! # Wire Format
//!
//! ```text
//! +----------+--------+----------+--------+---------+
//! | stream_id| rflags | msg_seq  | len    | payload |
//! | (u8)     | (u8)   | (varint) |(varint)| (bytes) |
//! +----------+--------+----------+--------+---------+
//! ```
//!
//! # Stream ID
//!
//! - `0` = CONTROL stream (reserved for protocol messages)
//! - `1-255` = User data streams (mapped via CONTROL)
//!
//! # Record Flags (rflags)
//!
//! | Bit | Name | Description |
//! |-----|------|-------------|
//! | 0 | DELTA | Payload is a delta patch (vs FULL) |
//! | 1 | RELIABLE | Requires acknowledgment |
//! | 2 | COMPRESSED | Payload is LZ4 compressed |
//! | 3 | FRAG | Payload contains fragment header |
//! | 4-5 | PRIORITY | Priority level (0=P0, 1=P1, 2=P2) |

use super::varint::{decode_varint, decode_varint_u32, encode_varint, varint_len};

/// Stream ID for the CONTROL stream.
pub const STREAM_CONTROL: u8 = 0;

/// Maximum payload size per record.
pub const MAX_PAYLOAD_SIZE: usize = 1500;

/// Record flags.
pub mod rflags {
    /// Payload is a delta patch (vs FULL keyframe).
    pub const DELTA: u8 = 0x01;
    /// Record requires acknowledgment (reliable delivery).
    pub const RELIABLE: u8 = 0x02;
    /// Payload is LZ4 compressed.
    pub const COMPRESSED: u8 = 0x04;
    /// Payload contains fragment header (large message).
    pub const FRAG: u8 = 0x08;
    /// Priority mask (bits 4-5).
    pub const PRIORITY_MASK: u8 = 0x30;
    /// Priority shift.
    pub const PRIORITY_SHIFT: u8 = 4;
}

/// Priority level for records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[derive(Default)]
pub enum Priority {
    /// P0: Critical/reliable (commands, state sync).
    /// Immediate flush, retransmit on loss.
    P0 = 0,
    /// P1: Important (sensor data).
    /// Batched, no retransmit.
    #[default]
    P1 = 1,
    /// P2: Telemetry (droppable).
    /// Batched, dropped on congestion.
    P2 = 2,
}

impl Priority {
    /// Create from raw priority bits.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::P0,
            1 => Self::P1,
            _ => Self::P2, // 2 or 3 both map to P2
        }
    }

    /// Convert to raw bits for encoding.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        self as u8
    }
}

/// Set priority in flags byte.
#[inline]
#[must_use]
pub const fn set_priority(flags: u8, priority: Priority) -> u8 {
    (flags & !rflags::PRIORITY_MASK) | ((priority as u8) << rflags::PRIORITY_SHIFT)
}

/// Get priority from flags byte.
#[inline]
#[must_use]
pub const fn get_priority(flags: u8) -> Priority {
    Priority::from_bits((flags & rflags::PRIORITY_MASK) >> rflags::PRIORITY_SHIFT)
}

/// Error during record encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// Buffer too small for encoding.
    BufferTooSmall,
    /// Payload exceeds maximum size.
    PayloadTooLarge,
    /// Truncated record (incomplete data).
    Truncated,
    /// Varint decoding error.
    VarintError,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small for record"),
            Self::PayloadTooLarge => write!(f, "payload exceeds maximum size"),
            Self::Truncated => write!(f, "truncated record"),
            Self::VarintError => write!(f, "varint decode error"),
        }
    }
}

impl std::error::Error for RecordError {}

/// Record header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHeader {
    /// Stream ID (0 = CONTROL, 1-255 = user streams).
    pub stream_id: u8,
    /// Record flags.
    pub flags: u8,
    /// Message sequence number.
    pub msg_seq: u32,
}

impl RecordHeader {
    /// Create a new record header.
    #[must_use]
    pub fn new(stream_id: u8, msg_seq: u32) -> Self {
        Self {
            stream_id,
            flags: 0,
            msg_seq,
        }
    }

    /// Create a CONTROL stream record header.
    #[must_use]
    pub fn control(msg_seq: u32) -> Self {
        let mut header = Self::new(STREAM_CONTROL, msg_seq);
        header.flags |= rflags::RELIABLE; // CONTROL is always reliable
        header
    }

    /// Check if this is a CONTROL stream record.
    #[inline]
    #[must_use]
    pub fn is_control(&self) -> bool {
        self.stream_id == STREAM_CONTROL
    }

    /// Check if delta flag is set.
    #[inline]
    #[must_use]
    pub fn is_delta(&self) -> bool {
        self.flags & rflags::DELTA != 0
    }

    /// Check if reliable flag is set.
    #[inline]
    #[must_use]
    pub fn is_reliable(&self) -> bool {
        self.flags & rflags::RELIABLE != 0
    }

    /// Check if compressed flag is set.
    #[inline]
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.flags & rflags::COMPRESSED != 0
    }

    /// Check if fragment flag is set.
    #[inline]
    #[must_use]
    pub fn is_fragment(&self) -> bool {
        self.flags & rflags::FRAG != 0
    }

    /// Get priority level.
    #[inline]
    #[must_use]
    pub fn priority(&self) -> Priority {
        get_priority(self.flags)
    }

    /// Set delta flag.
    #[inline]
    pub fn set_delta(&mut self, delta: bool) {
        if delta {
            self.flags |= rflags::DELTA;
        } else {
            self.flags &= !rflags::DELTA;
        }
    }

    /// Set reliable flag.
    #[inline]
    pub fn set_reliable(&mut self, reliable: bool) {
        if reliable {
            self.flags |= rflags::RELIABLE;
        } else {
            self.flags &= !rflags::RELIABLE;
        }
    }

    /// Set compressed flag.
    #[inline]
    pub fn set_compressed(&mut self, compressed: bool) {
        if compressed {
            self.flags |= rflags::COMPRESSED;
        } else {
            self.flags &= !rflags::COMPRESSED;
        }
    }

    /// Set fragment flag.
    #[inline]
    pub fn set_fragment(&mut self, fragment: bool) {
        if fragment {
            self.flags |= rflags::FRAG;
        } else {
            self.flags &= !rflags::FRAG;
        }
    }

    /// Set priority level.
    #[inline]
    pub fn set_priority(&mut self, priority: Priority) {
        self.flags = set_priority(self.flags, priority);
    }
}

/// Encode a record into the buffer.
///
/// # Arguments
///
/// * `header` - Record header
/// * `payload` - Record payload
/// * `buf` - Output buffer
///
/// # Returns
///
/// Number of bytes written on success.
pub fn encode_record(
    header: &RecordHeader,
    payload: &[u8],
    buf: &mut [u8],
) -> Result<usize, RecordError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(RecordError::PayloadTooLarge);
    }

    let seq_len = varint_len(u64::from(header.msg_seq));
    let len_len = varint_len(payload.len() as u64);
    let total_size = 2 + seq_len + len_len + payload.len();

    if buf.len() < total_size {
        return Err(RecordError::BufferTooSmall);
    }

    let mut offset = 0;

    // stream_id
    buf[offset] = header.stream_id;
    offset += 1;

    // rflags
    buf[offset] = header.flags;
    offset += 1;

    // msg_seq (varint)
    offset += encode_varint(u64::from(header.msg_seq), &mut buf[offset..]);

    // len (varint)
    offset += encode_varint(payload.len() as u64, &mut buf[offset..]);

    // payload
    buf[offset..offset + payload.len()].copy_from_slice(payload);
    offset += payload.len();

    Ok(offset)
}

/// Decoded record result.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedRecord<'a> {
    /// Record header.
    pub header: RecordHeader,
    /// Record payload.
    pub payload: &'a [u8],
    /// Total bytes consumed from input.
    pub consumed: usize,
}

/// Decode a record from the buffer.
///
/// # Arguments
///
/// * `buf` - Input buffer containing record data
///
/// # Returns
///
/// Decoded record with header and payload slice.
pub fn decode_record(buf: &[u8]) -> Result<DecodedRecord<'_>, RecordError> {
    if buf.len() < 4 {
        // Minimum: stream_id + rflags + 1-byte seq + 1-byte len
        return Err(RecordError::Truncated);
    }

    let mut offset = 0;

    // stream_id
    let stream_id = buf[offset];
    offset += 1;

    // rflags
    let flags = buf[offset];
    offset += 1;

    // msg_seq (varint)
    let (msg_seq, seq_bytes) =
        decode_varint_u32(&buf[offset..]).map_err(|_| RecordError::VarintError)?;
    offset += seq_bytes;

    // len (varint)
    let (len, len_bytes) = decode_varint(&buf[offset..]).map_err(|_| RecordError::VarintError)?;
    offset += len_bytes;

    let len = len as usize;
    if len > MAX_PAYLOAD_SIZE {
        return Err(RecordError::PayloadTooLarge);
    }

    // payload
    if buf.len() < offset + len {
        return Err(RecordError::Truncated);
    }

    let payload = &buf[offset..offset + len];
    offset += len;

    Ok(DecodedRecord {
        header: RecordHeader {
            stream_id,
            flags,
            msg_seq,
        },
        payload,
        consumed: offset,
    })
}

/// Decode multiple records from a buffer.
///
/// # Arguments
///
/// * `buf` - Input buffer containing one or more records
/// * `records` - Output vector for decoded records
///
/// # Returns
///
/// Total bytes consumed.
pub fn decode_records<'a>(
    buf: &'a [u8],
    records: &mut Vec<DecodedRecord<'a>>,
) -> Result<usize, RecordError> {
    let mut offset = 0;

    while offset < buf.len() {
        match decode_record(&buf[offset..]) {
            Ok(record) => {
                offset += record.consumed;
                records.push(record);
            }
            Err(RecordError::Truncated) if offset > 0 => {
                // We decoded some records, treat remainder as incomplete
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(offset)
}

/// Calculate the encoded size of a record.
#[must_use]
pub fn record_size(header: &RecordHeader, payload_len: usize) -> usize {
    let seq_len = varint_len(u64::from(header.msg_seq));
    let len_len = varint_len(payload_len as u64);
    2 + seq_len + len_len + payload_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_from_bits() {
        assert_eq!(Priority::from_bits(0), Priority::P0);
        assert_eq!(Priority::from_bits(1), Priority::P1);
        assert_eq!(Priority::from_bits(2), Priority::P2);
        assert_eq!(Priority::from_bits(3), Priority::P2); // 3 maps to P2
    }

    #[test]
    fn test_set_get_priority() {
        let flags = set_priority(0, Priority::P0);
        assert_eq!(get_priority(flags), Priority::P0);

        let flags = set_priority(0, Priority::P1);
        assert_eq!(get_priority(flags), Priority::P1);

        let flags = set_priority(0, Priority::P2);
        assert_eq!(get_priority(flags), Priority::P2);

        // Preserve other flags
        let flags = set_priority(rflags::RELIABLE | rflags::DELTA, Priority::P2);
        assert_eq!(flags & rflags::RELIABLE, rflags::RELIABLE);
        assert_eq!(flags & rflags::DELTA, rflags::DELTA);
        assert_eq!(get_priority(flags), Priority::P2);
    }

    #[test]
    fn test_record_header_flags() {
        let mut header = RecordHeader::new(1, 0);

        assert!(!header.is_delta());
        header.set_delta(true);
        assert!(header.is_delta());

        assert!(!header.is_reliable());
        header.set_reliable(true);
        assert!(header.is_reliable());

        assert!(!header.is_compressed());
        header.set_compressed(true);
        assert!(header.is_compressed());

        assert!(!header.is_fragment());
        header.set_fragment(true);
        assert!(header.is_fragment());

        assert_eq!(header.priority(), Priority::P0); // Default
        header.set_priority(Priority::P2);
        assert_eq!(header.priority(), Priority::P2);
    }

    #[test]
    fn test_control_header() {
        let header = RecordHeader::control(42);
        assert!(header.is_control());
        assert!(header.is_reliable());
        assert_eq!(header.msg_seq, 42);
    }

    #[test]
    fn test_encode_decode_empty_payload() {
        let header = RecordHeader::new(1, 100);
        let payload: &[u8] = &[];
        let mut buf = [0u8; 64];

        let encoded_len = encode_record(&header, payload, &mut buf).expect("encode");

        let decoded = decode_record(&buf[..encoded_len]).expect("decode");
        assert_eq!(decoded.header.stream_id, 1);
        assert_eq!(decoded.header.msg_seq, 100);
        assert!(decoded.payload.is_empty());
        assert_eq!(decoded.consumed, encoded_len);
    }

    #[test]
    fn test_encode_decode_with_payload() {
        let mut header = RecordHeader::new(5, 12345);
        header.set_reliable(true);
        header.set_priority(Priority::P0);

        let payload = b"Hello, LBW Record!";
        let mut buf = [0u8; 64];

        let encoded_len = encode_record(&header, payload, &mut buf).expect("encode");

        let decoded = decode_record(&buf[..encoded_len]).expect("decode");
        assert_eq!(decoded.header.stream_id, 5);
        assert_eq!(decoded.header.msg_seq, 12345);
        assert!(decoded.header.is_reliable());
        assert_eq!(decoded.header.priority(), Priority::P0);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_decode_truncated() {
        let buf = [0x01, 0x00]; // Too short
        assert_eq!(decode_record(&buf), Err(RecordError::Truncated));
    }

    #[test]
    fn test_decode_payload_truncated() {
        // Header says 100 bytes but only provide 10
        let mut buf = [0u8; 20];
        buf[0] = 1; // stream_id
        buf[1] = 0; // flags
        buf[2] = 0; // msg_seq = 0
        buf[3] = 100; // len = 100 (but buffer is too small)

        assert_eq!(decode_record(&buf), Err(RecordError::Truncated));
    }

    #[test]
    fn test_payload_too_large() {
        let header = RecordHeader::new(1, 0);
        let payload = [0u8; MAX_PAYLOAD_SIZE + 1];
        let mut buf = [0u8; MAX_PAYLOAD_SIZE + 20];

        assert_eq!(
            encode_record(&header, &payload, &mut buf),
            Err(RecordError::PayloadTooLarge)
        );
    }

    #[test]
    fn test_buffer_too_small() {
        let header = RecordHeader::new(1, 0);
        let payload = b"Test";
        let mut buf = [0u8; 3]; // Too small

        assert_eq!(
            encode_record(&header, payload, &mut buf),
            Err(RecordError::BufferTooSmall)
        );
    }

    #[test]
    fn test_record_size_calculation() {
        let header = RecordHeader::new(1, 0);
        let payload_len = 10;

        let calculated = record_size(&header, payload_len);

        let mut buf = [0u8; 64];
        let actual = encode_record(&header, &[0u8; 10], &mut buf).expect("encode");

        assert_eq!(calculated, actual);
    }

    #[test]
    fn test_decode_multiple_records() {
        let mut buf = [0u8; 256];
        let mut offset = 0;

        // Encode 3 records
        for i in 0..3 {
            let header = RecordHeader::new(i + 1, i as u32 * 100);
            let payload = format!("Record {}", i);
            offset +=
                encode_record(&header, payload.as_bytes(), &mut buf[offset..]).expect("encode");
        }

        // Decode all
        let mut records = Vec::new();
        let consumed = decode_records(&buf[..offset], &mut records).expect("decode");

        assert_eq!(consumed, offset);
        assert_eq!(records.len(), 3);

        for (i, rec) in records.iter().enumerate() {
            assert_eq!(rec.header.stream_id, (i + 1) as u8);
            assert_eq!(rec.header.msg_seq, i as u32 * 100);
        }
    }

    #[test]
    fn test_roundtrip_various_sizes() {
        let mut buf = [0u8; MAX_PAYLOAD_SIZE + 20];

        for stream_id in [0u8, 1, 127, 255] {
            for msg_seq in [0u32, 1, 127, 128, 16384, 1_000_000] {
                for payload_len in [0, 1, 10, 100, 500] {
                    let mut header = RecordHeader::new(stream_id, msg_seq);
                    header.set_priority(Priority::P1);
                    let payload: Vec<u8> = (0..payload_len).map(|i| i as u8).collect();

                    let encoded_len =
                        encode_record(&header, &payload, &mut buf).expect("encode should succeed");

                    let decoded =
                        decode_record(&buf[..encoded_len]).expect("decode should succeed");

                    assert_eq!(decoded.header.stream_id, stream_id);
                    assert_eq!(decoded.header.msg_seq, msg_seq);
                    assert_eq!(decoded.payload, &payload[..]);
                }
            }
        }
    }
}
