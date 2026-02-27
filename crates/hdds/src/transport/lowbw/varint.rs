// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ULEB128 (Unsigned Little-Endian Base 128) variable-length integer encoding.
//!
//! This is the same encoding used by Protocol Buffers for unsigned integers.
//!
//! # Encoding Rules
//!
//! - Each byte uses 7 bits for data, bit 7 indicates continuation
//! - Values 0-127 encode in 1 byte
//! - Values 128-16383 encode in 2 bytes
//! - Maximum encoded length for u64 is 10 bytes
//!
//! # Examples
//!
//! ```
//! use hdds::transport::lowbw::varint::{encode_varint, decode_varint};
//!
//! let mut buf = [0u8; 10];
//! let len = encode_varint(300, &mut buf);
//! assert_eq!(len, 2);
//! assert_eq!(&buf[..2], &[0xAC, 0x02]);
//!
//! let (value, consumed) = decode_varint(&buf[..2]).unwrap();
//! assert_eq!(value, 300);
//! assert_eq!(consumed, 2);
//! ```

use std::io;

/// Maximum bytes needed to encode a u64 in ULEB128.
pub const MAX_VARINT_LEN: usize = 10;

/// Continuation bit mask (bit 7).
const CONTINUATION_BIT: u8 = 0x80;

/// Data bits mask (bits 0-6).
const DATA_MASK: u8 = 0x7F;

/// Error returned when varint decoding fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarintError {
    /// Buffer is empty or truncated mid-varint.
    UnexpectedEof,
    /// Varint is too long (overflow for u64).
    Overflow,
}

impl std::fmt::Display for VarintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of buffer while reading varint"),
            Self::Overflow => write!(f, "varint overflow (too many bytes for u64)"),
        }
    }
}

impl std::error::Error for VarintError {}

impl From<VarintError> for io::Error {
    fn from(e: VarintError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// Encode a u64 as ULEB128 into the buffer.
///
/// # Algorithm
///
/// ULEB128 encodes integers using 7 data bits per byte, with bit 7 (MSB) as a
/// continuation flag. Bytes are emitted LSB-first (little-endian):
///
/// ```text
/// Value 300 = 0b100101100 (9 bits)
///   Byte 0: 0b1_0101100 = 0xAC  (bits 0-6, continuation=1)
///   Byte 1: 0b0_0000010 = 0x02  (bits 7-8, continuation=0 → done)
/// ```
///
/// # Returns
///
/// Number of bytes written (1-10).
///
/// # Panics
///
/// Panics if buffer is smaller than needed (use `varint_len` to check).
#[inline]
pub fn encode_varint(mut value: u64, buf: &mut [u8]) -> usize {
    let mut i = 0;
    loop {
        // Extract lowest 7 bits as current byte's data payload
        let byte = (value & u64::from(DATA_MASK)) as u8;
        // Shift out the 7 bits we just consumed
        value >>= 7;
        if value == 0 {
            // No more bits to encode: write final byte without continuation bit
            buf[i] = byte;
            return i + 1;
        }
        // More bits remain: set MSB (continuation bit) to signal "keep reading"
        buf[i] = byte | CONTINUATION_BIT;
        i += 1;
    }
}

/// Encode a u64 as ULEB128, returning the bytes as a fixed array with length.
///
/// Useful when you need the encoded bytes without a pre-allocated buffer.
#[inline]
pub fn encode_varint_array(value: u64) -> ([u8; MAX_VARINT_LEN], usize) {
    let mut buf = [0u8; MAX_VARINT_LEN];
    let len = encode_varint(value, &mut buf);
    (buf, len)
}

/// Calculate the number of bytes needed to encode a value.
#[inline]
#[must_use]
pub const fn varint_len(value: u64) -> usize {
    // Each 7 bits needs 1 byte
    // 0 needs 1 byte (special case)
    if value == 0 {
        return 1;
    }
    // 64 - leading_zeros gives us the number of significant bits
    // Divide by 7 and round up
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(7) // Ceiling division by 7
}

/// Decode a ULEB128 varint from the buffer.
///
/// # Algorithm
///
/// Reverses the encoding process: reads bytes until one has MSB=0, accumulating
/// 7-bit chunks into the result with increasing bit shifts:
///
/// ```text
/// Input: [0xAC, 0x02]
///   Byte 0: 0xAC = 0b1_0101100 → data=0x2C, shift=0, continuation=1
///   Byte 1: 0x02 = 0b0_0000010 → data=0x02, shift=7, continuation=0
///   Result: (0x02 << 7) | 0x2C = 256 + 44 = 300
/// ```
///
/// # Returns
///
/// `Ok((value, bytes_consumed))` on success.
///
/// # Errors
///
/// - `UnexpectedEof` if buffer ends before varint terminates
/// - `Overflow` if varint exceeds 10 bytes (u64 max)
#[inline]
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), VarintError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;

    for (i, &byte) in buf.iter().enumerate() {
        // u64 max needs 10 bytes (ceil(64/7)). More bytes = malformed input.
        if i >= MAX_VARINT_LEN {
            return Err(VarintError::Overflow);
        }

        // Mask off continuation bit to get 7-bit data payload
        let data = u64::from(byte & DATA_MASK);

        // Overflow guard for 10th byte: at shift=63, only bit 0 is valid.
        // If data > 1, bits would shift beyond u64's 64-bit capacity.
        if shift == 63 && data > 1 {
            return Err(VarintError::Overflow);
        }

        // Accumulate this 7-bit chunk at current bit position
        result |= data << shift;

        // MSB=0 means this is the final byte (no continuation)
        if byte & CONTINUATION_BIT == 0 {
            return Ok((result, i + 1));
        }

        // Advance to next 7-bit chunk position
        shift += 7;
    }

    // Reached end of buffer with continuation bit still set
    Err(VarintError::UnexpectedEof)
}

/// Decode a varint, returning only the value (discarding byte count).
#[inline]
pub fn decode_varint_value(buf: &[u8]) -> Result<u64, VarintError> {
    decode_varint(buf).map(|(v, _)| v)
}

/// Decode a varint as u32, checking for overflow.
#[inline]
pub fn decode_varint_u32(buf: &[u8]) -> Result<(u32, usize), VarintError> {
    let (value, len) = decode_varint(buf)?;
    if value > u64::from(u32::MAX) {
        return Err(VarintError::Overflow);
    }
    Ok((value as u32, len))
}

/// Decode a varint as u16, checking for overflow.
#[inline]
pub fn decode_varint_u16(buf: &[u8]) -> Result<(u16, usize), VarintError> {
    let (value, len) = decode_varint(buf)?;
    if value > u64::from(u16::MAX) {
        return Err(VarintError::Overflow);
    }
    Ok((value as u16, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_single_byte() {
        let mut buf = [0u8; 10];

        // 0
        assert_eq!(encode_varint(0, &mut buf), 1);
        assert_eq!(buf[0], 0x00);

        // 1
        assert_eq!(encode_varint(1, &mut buf), 1);
        assert_eq!(buf[0], 0x01);

        // 127 (max single byte)
        assert_eq!(encode_varint(127, &mut buf), 1);
        assert_eq!(buf[0], 0x7F);
    }

    #[test]
    fn test_encode_two_bytes() {
        let mut buf = [0u8; 10];

        // 128 (first two-byte value)
        assert_eq!(encode_varint(128, &mut buf), 2);
        assert_eq!(&buf[..2], &[0x80, 0x01]);

        // 300
        assert_eq!(encode_varint(300, &mut buf), 2);
        assert_eq!(&buf[..2], &[0xAC, 0x02]);

        // 16383 (max two-byte value)
        assert_eq!(encode_varint(16383, &mut buf), 2);
        assert_eq!(&buf[..2], &[0xFF, 0x7F]);
    }

    #[test]
    fn test_encode_three_bytes() {
        let mut buf = [0u8; 10];

        // 16384 (first three-byte value)
        assert_eq!(encode_varint(16384, &mut buf), 3);
        assert_eq!(&buf[..3], &[0x80, 0x80, 0x01]);
    }

    #[test]
    fn test_encode_max_u64() {
        let mut buf = [0u8; 10];

        // u64::MAX requires 10 bytes
        let len = encode_varint(u64::MAX, &mut buf);
        assert_eq!(len, 10);

        // Verify it decodes back
        let (decoded, consumed) = decode_varint(&buf).expect("should decode");
        assert_eq!(decoded, u64::MAX);
        assert_eq!(consumed, 10);
    }

    #[test]
    fn test_decode_single_byte() {
        assert_eq!(decode_varint(&[0x00]).expect("decode 0"), (0, 1));
        assert_eq!(decode_varint(&[0x01]).expect("decode 1"), (1, 1));
        assert_eq!(decode_varint(&[0x7F]).expect("decode 127"), (127, 1));
    }

    #[test]
    fn test_decode_two_bytes() {
        assert_eq!(decode_varint(&[0x80, 0x01]).expect("decode 128"), (128, 2));
        assert_eq!(decode_varint(&[0xAC, 0x02]).expect("decode 300"), (300, 2));
        assert_eq!(
            decode_varint(&[0xFF, 0x7F]).expect("decode 16383"),
            (16383, 2)
        );
    }

    #[test]
    fn test_decode_with_trailing_data() {
        // Decoder should stop at the terminating byte
        let buf = [0x01, 0xFF, 0xFF, 0xFF];
        let (value, consumed) = decode_varint(&buf).expect("should decode");
        assert_eq!(value, 1);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_unexpected_eof() {
        // Continuation bit set but no more bytes
        assert_eq!(decode_varint(&[0x80]), Err(VarintError::UnexpectedEof));
        assert_eq!(
            decode_varint(&[0x80, 0x80]),
            Err(VarintError::UnexpectedEof)
        );

        // Empty buffer
        assert_eq!(decode_varint(&[]), Err(VarintError::UnexpectedEof));
    }

    #[test]
    fn test_decode_overflow() {
        // 11 bytes with continuation bits (too long)
        let buf = [0x80; 11];
        assert_eq!(decode_varint(&buf), Err(VarintError::Overflow));

        // 10th byte with value > 1 (would overflow u64)
        let mut buf = [0x80; 10];
        buf[9] = 0x02; // Would be bit 63+ with value > 1
        assert_eq!(decode_varint(&buf), Err(VarintError::Overflow));
    }

    #[test]
    fn test_varint_len() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(1), 1);
        assert_eq!(varint_len(127), 1);
        assert_eq!(varint_len(128), 2);
        assert_eq!(varint_len(16383), 2);
        assert_eq!(varint_len(16384), 3);
        assert_eq!(varint_len(u32::MAX as u64), 5);
        assert_eq!(varint_len(u64::MAX), 10);
    }

    #[test]
    fn test_roundtrip_various_values() {
        let test_values: &[u64] = &[
            0,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            65535,
            1_000_000,
            u32::MAX as u64,
            u64::MAX / 2,
            u64::MAX,
        ];

        for &value in test_values {
            let mut buf = [0u8; MAX_VARINT_LEN];
            let encoded_len = encode_varint(value, &mut buf);
            let (decoded, decoded_len) =
                decode_varint(&buf[..encoded_len]).expect("roundtrip decode");

            assert_eq!(decoded, value, "roundtrip failed for value {}", value);
            assert_eq!(
                decoded_len, encoded_len,
                "length mismatch for value {}",
                value
            );
            assert_eq!(
                varint_len(value),
                encoded_len,
                "varint_len mismatch for value {}",
                value
            );
        }
    }

    #[test]
    fn test_decode_u32_overflow() {
        let mut buf = [0u8; 10];
        encode_varint((u32::MAX as u64) + 1, &mut buf);
        assert_eq!(decode_varint_u32(&buf), Err(VarintError::Overflow));

        // Valid u32
        encode_varint(u32::MAX as u64, &mut buf);
        let (val, _) = decode_varint_u32(&buf).expect("valid u32");
        assert_eq!(val, u32::MAX);
    }

    #[test]
    fn test_decode_u16_overflow() {
        let mut buf = [0u8; 10];
        encode_varint((u16::MAX as u64) + 1, &mut buf);
        assert_eq!(decode_varint_u16(&buf), Err(VarintError::Overflow));

        // Valid u16
        encode_varint(u16::MAX as u64, &mut buf);
        let (val, _) = decode_varint_u16(&buf).expect("valid u16");
        assert_eq!(val, u16::MAX);
    }

    #[test]
    fn test_encode_varint_array() {
        let (buf, len) = encode_varint_array(300);
        assert_eq!(len, 2);
        assert_eq!(&buf[..len], &[0xAC, 0x02]);
    }
}
