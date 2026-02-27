// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LBW Frame encoding and decoding.
//!
//! # Wire Format
//!
//! ```text
//! +--------+--------+--------+------------+------------+----------+----------+-------+
//! | sync   | version| flags  | frame_len  | session_id | frame_seq| records  | crc16 |
//! | (0xA5) | (1)    | (u8)   | (varint)   | (varint)   | (varint) | (...)    | (opt) |
//! +--------+--------+--------+------------+------------+----------+----------+-------+
//! ```
//!
//! - `frame_len` = bytes from session_id to end (including CRC if present)
//! - CRC-16 is appended if `CRC_PRESENT` flag is set (default)

use super::crc::{crc16_ccitt, verify_crc16};
use super::varint::{
    decode_varint, decode_varint_u16, decode_varint_u32, encode_varint, varint_len,
};

/// Frame sync byte (magic number).
pub const FRAME_SYNC: u8 = 0xA5;

/// Protocol version.
pub const FRAME_VERSION: u8 = 1;

/// Maximum frame size (including header and CRC).
pub const MAX_FRAME_SIZE: usize = 2048;

/// Minimum valid frame size (sync + version + flags + 1-byte frame_len + 1 record byte).
pub const MIN_FRAME_SIZE: usize = 5;

/// Frame flags.
pub mod flags {
    /// CRC-16 is present at end of frame.
    pub const CRC_PRESENT: u8 = 0x01;
    /// Reserved for future use.
    pub const RESERVED_1: u8 = 0x02;
    pub const RESERVED_2: u8 = 0x04;
    pub const RESERVED_3: u8 = 0x08;
}

/// Error during frame encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Buffer too small for encoding.
    BufferTooSmall,
    /// Invalid sync byte.
    InvalidSync,
    /// Unsupported protocol version.
    UnsupportedVersion,
    /// Frame length exceeds maximum.
    FrameTooLarge,
    /// CRC validation failed.
    CrcMismatch,
    /// Truncated frame (incomplete data).
    Truncated,
    /// Varint decoding error.
    VarintError,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small for frame"),
            Self::InvalidSync => write!(f, "invalid frame sync byte"),
            Self::UnsupportedVersion => write!(f, "unsupported protocol version"),
            Self::FrameTooLarge => write!(f, "frame exceeds maximum size"),
            Self::CrcMismatch => write!(f, "CRC validation failed"),
            Self::Truncated => write!(f, "truncated frame"),
            Self::VarintError => write!(f, "varint decode error"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Decoded frame header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    /// Protocol version (should be 1).
    pub version: u8,
    /// Frame flags.
    pub flags: u8,
    /// Session ID.
    pub session_id: u16,
    /// Frame sequence number.
    pub frame_seq: u32,
}

impl Default for FrameHeader {
    fn default() -> Self {
        Self {
            version: FRAME_VERSION,
            flags: flags::CRC_PRESENT,
            session_id: 0,
            frame_seq: 0,
        }
    }
}

impl FrameHeader {
    /// Create a new frame header with default flags (CRC enabled).
    #[must_use]
    pub fn new(session_id: u16, frame_seq: u32) -> Self {
        Self {
            version: FRAME_VERSION,
            flags: flags::CRC_PRESENT,
            session_id,
            frame_seq,
        }
    }

    /// Check if CRC is present.
    #[inline]
    #[must_use]
    pub fn has_crc(&self) -> bool {
        self.flags & flags::CRC_PRESENT != 0
    }

    /// Set CRC flag.
    #[inline]
    pub fn set_crc(&mut self, enabled: bool) {
        if enabled {
            self.flags |= flags::CRC_PRESENT;
        } else {
            self.flags &= !flags::CRC_PRESENT;
        }
    }
}

/// Encode a frame into the buffer.
///
/// # Arguments
///
/// * `header` - Frame header
/// * `records` - Serialized records payload
/// * `buf` - Output buffer (must be large enough)
///
/// # Returns
///
/// Number of bytes written on success.
pub fn encode_frame(
    header: &FrameHeader,
    records: &[u8],
    buf: &mut [u8],
) -> Result<usize, FrameError> {
    // Calculate sizes
    let session_len = varint_len(u64::from(header.session_id));
    let seq_len = varint_len(u64::from(header.frame_seq));
    let crc_len = if header.has_crc() { 2 } else { 0 };

    // frame_len = session_id + frame_seq + records + crc
    let frame_len = session_len + seq_len + records.len() + crc_len;
    let frame_len_bytes = varint_len(frame_len as u64);

    // Total frame size = sync + version + flags + frame_len + frame_len_data
    let total_size = 3 + frame_len_bytes + frame_len;

    if total_size > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge);
    }

    if buf.len() < total_size {
        return Err(FrameError::BufferTooSmall);
    }

    let mut offset = 0;

    // Fixed header
    buf[offset] = FRAME_SYNC;
    offset += 1;
    buf[offset] = header.version;
    offset += 1;
    buf[offset] = header.flags;
    offset += 1;

    // frame_len (varint)
    offset += encode_varint(frame_len as u64, &mut buf[offset..]);

    // Start of CRC-covered data
    let crc_start = offset;

    // session_id (varint)
    offset += encode_varint(u64::from(header.session_id), &mut buf[offset..]);

    // frame_seq (varint)
    offset += encode_varint(u64::from(header.frame_seq), &mut buf[offset..]);

    // records payload
    buf[offset..offset + records.len()].copy_from_slice(records);
    offset += records.len();

    // CRC if enabled
    if header.has_crc() {
        let crc = crc16_ccitt(&buf[crc_start..offset]);
        buf[offset] = (crc >> 8) as u8;
        buf[offset + 1] = crc as u8;
        offset += 2;
    }

    Ok(offset)
}

/// Decoded frame result.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedFrame<'a> {
    /// Frame header.
    pub header: FrameHeader,
    /// Records payload (excludes header and CRC).
    pub records: &'a [u8],
    /// Total bytes consumed from input.
    pub consumed: usize,
}

/// Decode a frame from the buffer.
///
/// # Arguments
///
/// * `buf` - Input buffer containing frame data
///
/// # Returns
///
/// Decoded frame with header and records slice.
///
/// # Errors
///
/// - `InvalidSync` if sync byte doesn't match
/// - `UnsupportedVersion` if version != 1
/// - `Truncated` if buffer doesn't contain full frame
/// - `CrcMismatch` if CRC validation fails
pub fn decode_frame(buf: &[u8]) -> Result<DecodedFrame<'_>, FrameError> {
    if buf.len() < MIN_FRAME_SIZE {
        return Err(FrameError::Truncated);
    }

    let mut offset = 0;

    // Sync byte
    if buf[offset] != FRAME_SYNC {
        return Err(FrameError::InvalidSync);
    }
    offset += 1;

    // Version
    let version = buf[offset];
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion);
    }
    offset += 1;

    // Flags
    let flags = buf[offset];
    offset += 1;

    // frame_len
    let (frame_len, len_bytes) =
        decode_varint(&buf[offset..]).map_err(|_| FrameError::VarintError)?;
    offset += len_bytes;

    let frame_len = frame_len as usize;
    if frame_len > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge);
    }

    // Check we have enough data
    let total_frame_size = offset + frame_len;
    if buf.len() < total_frame_size {
        return Err(FrameError::Truncated);
    }

    let crc_start = offset;
    let has_crc = flags & flags::CRC_PRESENT != 0;
    let crc_len = if has_crc { 2 } else { 0 };

    // Validate CRC before parsing content
    if has_crc {
        let crc_offset = offset + frame_len - 2;
        let stored_crc = u16::from_be_bytes([buf[crc_offset], buf[crc_offset + 1]]);
        let computed_crc = crc16_ccitt(&buf[crc_start..crc_offset]);
        if !verify_crc16(&buf[crc_start..crc_offset], stored_crc) {
            // Double-check by computing directly
            if computed_crc != stored_crc {
                return Err(FrameError::CrcMismatch);
            }
        }
    }

    // session_id
    let (session_id, session_bytes) =
        decode_varint_u16(&buf[offset..]).map_err(|_| FrameError::VarintError)?;
    offset += session_bytes;

    // frame_seq
    let (frame_seq, seq_bytes) =
        decode_varint_u32(&buf[offset..]).map_err(|_| FrameError::VarintError)?;
    offset += seq_bytes;

    // Records = remaining bytes minus CRC
    let records_end = crc_start + frame_len - crc_len;
    let records = &buf[offset..records_end];

    Ok(DecodedFrame {
        header: FrameHeader {
            version,
            flags,
            session_id,
            frame_seq,
        },
        records,
        consumed: total_frame_size,
    })
}

/// Find the next frame sync byte in a stream buffer.
///
/// Useful for resynchronizing after corruption.
///
/// # Returns
///
/// Offset of next sync byte, or `None` if not found.
#[must_use]
pub fn find_sync(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| b == FRAME_SYNC)
}

/// Calculate the minimum buffer size needed for a frame.
#[must_use]
pub fn frame_size(header: &FrameHeader, records_len: usize) -> usize {
    let session_len = varint_len(u64::from(header.session_id));
    let seq_len = varint_len(u64::from(header.frame_seq));
    let crc_len = if header.has_crc() { 2 } else { 0 };
    let frame_len = session_len + seq_len + records_len + crc_len;
    let frame_len_bytes = varint_len(frame_len as u64);

    3 + frame_len_bytes + frame_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_default() {
        let header = FrameHeader::default();
        assert_eq!(header.version, FRAME_VERSION);
        assert!(header.has_crc());
    }

    #[test]
    fn test_frame_header_crc_flag() {
        let mut header = FrameHeader::new(1, 0);
        assert!(header.has_crc());

        header.set_crc(false);
        assert!(!header.has_crc());

        header.set_crc(true);
        assert!(header.has_crc());
    }

    #[test]
    fn test_encode_decode_empty_frame() {
        let header = FrameHeader::new(42, 1);
        let records: &[u8] = &[];
        let mut buf = [0u8; 64];

        let encoded_len = encode_frame(&header, records, &mut buf).expect("encode");

        let decoded = decode_frame(&buf[..encoded_len]).expect("decode");
        assert_eq!(decoded.header.session_id, 42);
        assert_eq!(decoded.header.frame_seq, 1);
        assert!(decoded.records.is_empty());
        assert_eq!(decoded.consumed, encoded_len);
    }

    #[test]
    fn test_encode_decode_with_records() {
        let header = FrameHeader::new(1000, 12345);
        let records = b"Hello, LBW!";
        let mut buf = [0u8; 64];

        let encoded_len = encode_frame(&header, records, &mut buf).expect("encode");

        let decoded = decode_frame(&buf[..encoded_len]).expect("decode");
        assert_eq!(decoded.header.session_id, 1000);
        assert_eq!(decoded.header.frame_seq, 12345);
        assert_eq!(decoded.records, records);
    }

    #[test]
    fn test_encode_decode_no_crc() {
        let mut header = FrameHeader::new(1, 0);
        header.set_crc(false);

        let records = b"No CRC";
        let mut buf = [0u8; 64];

        let encoded_len = encode_frame(&header, records, &mut buf).expect("encode");

        let decoded = decode_frame(&buf[..encoded_len]).expect("decode");
        assert!(!decoded.header.has_crc());
        assert_eq!(decoded.records, records);
    }

    #[test]
    fn test_decode_invalid_sync() {
        let buf = [0x00, FRAME_VERSION, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode_frame(&buf), Err(FrameError::InvalidSync));
    }

    #[test]
    fn test_decode_unsupported_version() {
        let buf = [FRAME_SYNC, 99, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode_frame(&buf), Err(FrameError::UnsupportedVersion));
    }

    #[test]
    fn test_decode_truncated() {
        let buf = [FRAME_SYNC, FRAME_VERSION];
        assert_eq!(decode_frame(&buf), Err(FrameError::Truncated));
    }

    #[test]
    fn test_decode_crc_mismatch() {
        let header = FrameHeader::new(1, 0);
        let records = b"Test";
        let mut buf = [0u8; 64];

        let encoded_len = encode_frame(&header, records, &mut buf).expect("encode");

        // Corrupt the CRC
        buf[encoded_len - 1] ^= 0xFF;

        assert_eq!(
            decode_frame(&buf[..encoded_len]),
            Err(FrameError::CrcMismatch)
        );
    }

    #[test]
    fn test_decode_crc_data_corruption() {
        let header = FrameHeader::new(1, 0);
        let records = b"Test data";
        let mut buf = [0u8; 64];

        let encoded_len = encode_frame(&header, records, &mut buf).expect("encode");

        // Corrupt the data (not the CRC itself)
        buf[10] ^= 0x01;

        assert_eq!(
            decode_frame(&buf[..encoded_len]),
            Err(FrameError::CrcMismatch)
        );
    }

    #[test]
    fn test_find_sync() {
        let buf = [0x00, 0x01, FRAME_SYNC, 0x02];
        assert_eq!(find_sync(&buf), Some(2));

        let buf_no_sync = [0x00, 0x01, 0x02];
        assert_eq!(find_sync(&buf_no_sync), None);

        let buf_first = [FRAME_SYNC, 0x01, 0x02];
        assert_eq!(find_sync(&buf_first), Some(0));
    }

    #[test]
    fn test_frame_size_calculation() {
        let header = FrameHeader::new(1, 0);
        let records_len = 10;

        let calculated = frame_size(&header, records_len);

        let mut buf = [0u8; 64];
        let actual = encode_frame(&header, &[0u8; 10], &mut buf).expect("encode");

        assert_eq!(calculated, actual);
    }

    #[test]
    fn test_frame_too_large() {
        let header = FrameHeader::new(1, 0);
        let records = [0u8; MAX_FRAME_SIZE]; // Too large
        let mut buf = [0u8; MAX_FRAME_SIZE + 100];

        assert_eq!(
            encode_frame(&header, &records, &mut buf),
            Err(FrameError::FrameTooLarge)
        );
    }

    #[test]
    fn test_buffer_too_small() {
        let header = FrameHeader::new(1, 0);
        let records = b"Test";
        let mut buf = [0u8; 5]; // Too small

        assert_eq!(
            encode_frame(&header, records, &mut buf),
            Err(FrameError::BufferTooSmall)
        );
    }

    #[test]
    fn test_roundtrip_various_sizes() {
        let mut buf = [0u8; MAX_FRAME_SIZE];

        for session_id in [0u16, 1, 127, 128, 1000, u16::MAX] {
            for frame_seq in [0u32, 1, 127, 128, 16384, 1_000_000] {
                for records_len in [0, 1, 10, 100, 500] {
                    let header = FrameHeader::new(session_id, frame_seq);
                    let records: Vec<u8> = (0..records_len).map(|i| i as u8).collect();

                    let encoded_len =
                        encode_frame(&header, &records, &mut buf).expect("encode should succeed");

                    let decoded = decode_frame(&buf[..encoded_len]).expect("decode should succeed");

                    assert_eq!(decoded.header.session_id, session_id);
                    assert_eq!(decoded.header.frame_seq, frame_seq);
                    assert_eq!(decoded.records, &records[..]);
                }
            }
        }
    }
}
