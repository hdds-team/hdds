// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR Micro - Lightweight CDR encoder/decoder for embedded
//!
//! Implements a minimal subset of CDR2 (Common Data Representation v2.0)
//! with fixed buffers and no heap allocations.
//!
//! ## Supported Types
//!
//! - Primitives: u8, u16, u32, u64, i8, i16, i32, i64, f32, f64, bool
//! - Fixed-size arrays: [T; N]
//! - Strings: &str (with length prefix)
//!
//! ## Limitations
//!
//! - No sequences (unbounded arrays) - use fixed arrays instead
//! - No optional fields - all fields are required
//! - Little-endian only (for simplicity on embedded targets)

use crate::error::{Error, Result};

/// CDR Encoder with fixed buffer
///
/// # Example
///
/// ```ignore
/// let mut buf = [0u8; 256];
/// let mut encoder = CdrEncoder::new(&mut buf);
///
/// encoder.encode_u32(42)?;
/// encoder.encode_string("hello")?;
///
/// let bytes = encoder.finish();
/// ```
pub struct CdrEncoder<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> CdrEncoder<'a> {
    /// Create a new CDR encoder
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Get current position
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Finish encoding and return written bytes
    pub fn finish(self) -> &'a [u8] {
        &self.buf[0..self.pos]
    }

    /// Align to boundary (CDR alignment rules)
    fn align(&mut self, alignment: usize) -> Result<()> {
        let remainder = self.pos % alignment;
        if remainder != 0 {
            let padding = alignment - remainder;
            if self.pos + padding > self.buf.len() {
                return Err(Error::BufferTooSmall);
            }
            // Zero-fill padding
            for i in 0..padding {
                self.buf[self.pos + i] = 0;
            }
            self.pos += padding;
        }
        Ok(())
    }

    /// Write bytes
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if self.pos + bytes.len() > self.buf.len() {
            return Err(Error::BufferTooSmall);
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    /// Encode u8
    pub fn encode_u8(&mut self, value: u8) -> Result<()> {
        self.write_bytes(&[value])
    }

    /// Encode i8
    pub fn encode_i8(&mut self, value: i8) -> Result<()> {
        self.write_bytes(&[value as u8])
    }

    /// Encode bool
    pub fn encode_bool(&mut self, value: bool) -> Result<()> {
        self.encode_u8(if value { 1 } else { 0 })
    }

    /// Encode u16
    pub fn encode_u16(&mut self, value: u16) -> Result<()> {
        self.align(2)?;
        self.write_bytes(&value.to_le_bytes())
    }

    /// Encode i16
    pub fn encode_i16(&mut self, value: i16) -> Result<()> {
        self.align(2)?;
        self.write_bytes(&value.to_le_bytes())
    }

    /// Encode u32
    pub fn encode_u32(&mut self, value: u32) -> Result<()> {
        self.align(4)?;
        self.write_bytes(&value.to_le_bytes())
    }

    /// Encode i32
    pub fn encode_i32(&mut self, value: i32) -> Result<()> {
        self.align(4)?;
        self.write_bytes(&value.to_le_bytes())
    }

    /// Encode u64
    pub fn encode_u64(&mut self, value: u64) -> Result<()> {
        self.align(8)?;
        self.write_bytes(&value.to_le_bytes())
    }

    /// Encode i64
    pub fn encode_i64(&mut self, value: i64) -> Result<()> {
        self.align(8)?;
        self.write_bytes(&value.to_le_bytes())
    }

    /// Encode f32
    pub fn encode_f32(&mut self, value: f32) -> Result<()> {
        self.align(4)?;
        self.write_bytes(&value.to_le_bytes())
    }

    /// Encode f64
    pub fn encode_f64(&mut self, value: f64) -> Result<()> {
        self.align(8)?;
        self.write_bytes(&value.to_le_bytes())
    }

    /// Encode string (length-prefixed)
    pub fn encode_string(&mut self, value: &str) -> Result<()> {
        let bytes = value.as_bytes();
        let len = bytes.len() as u32;

        // Encode length (including null terminator)
        self.encode_u32(len + 1)?;

        // Encode string bytes
        self.write_bytes(bytes)?;

        // Null terminator
        self.encode_u8(0)?;

        Ok(())
    }

    /// Encode byte array
    pub fn encode_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_bytes(bytes)
    }

    /// Encode sequence length prefix (u32)
    ///
    /// Used for encoding bounded sequences/arrays with variable length.
    pub fn encode_seq_len(&mut self, len: usize) -> Result<()> {
        self.encode_u32(len as u32)
    }
}

/// CDR Decoder with fixed buffer
///
/// # Example
///
/// ```ignore
/// let mut decoder = CdrDecoder::new(&buf);
///
/// let value: u32 = decoder.decode_u32()?;
/// let text = decoder.decode_string_borrowed()?;
/// ```
pub struct CdrDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CdrDecoder<'a> {
    /// Create a new CDR decoder
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Get current position
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Get remaining bytes
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Align to boundary
    fn align(&mut self, alignment: usize) -> Result<()> {
        let remainder = self.pos % alignment;
        if remainder != 0 {
            let padding = alignment - remainder;
            if self.pos + padding > self.buf.len() {
                return Err(Error::BufferTooSmall);
            }
            self.pos += padding;
        }
        Ok(())
    }

    /// Read bytes
    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.pos + count > self.buf.len() {
            return Err(Error::BufferTooSmall);
        }
        let bytes = &self.buf[self.pos..self.pos + count];
        self.pos += count;
        Ok(bytes)
    }

    /// Decode u8
    pub fn decode_u8(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    /// Decode i8
    pub fn decode_i8(&mut self) -> Result<i8> {
        Ok(self.decode_u8()? as i8)
    }

    /// Decode bool
    pub fn decode_bool(&mut self) -> Result<bool> {
        Ok(self.decode_u8()? != 0)
    }

    /// Decode u16
    pub fn decode_u16(&mut self) -> Result<u16> {
        self.align(2)?;
        let bytes = self.read_bytes(2)?;
        let mut arr = [0u8; 2];
        arr.copy_from_slice(bytes);
        Ok(u16::from_le_bytes(arr))
    }

    /// Decode i16
    pub fn decode_i16(&mut self) -> Result<i16> {
        self.align(2)?;
        let bytes = self.read_bytes(2)?;
        let mut arr = [0u8; 2];
        arr.copy_from_slice(bytes);
        Ok(i16::from_le_bytes(arr))
    }

    /// Decode u32
    pub fn decode_u32(&mut self) -> Result<u32> {
        self.align(4)?;
        let bytes = self.read_bytes(4)?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(arr))
    }

    /// Decode i32
    pub fn decode_i32(&mut self) -> Result<i32> {
        self.align(4)?;
        let bytes = self.read_bytes(4)?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        Ok(i32::from_le_bytes(arr))
    }

    /// Decode u64
    pub fn decode_u64(&mut self) -> Result<u64> {
        self.align(8)?;
        let bytes = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(arr))
    }

    /// Decode i64
    pub fn decode_i64(&mut self) -> Result<i64> {
        self.align(8)?;
        let bytes = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(i64::from_le_bytes(arr))
    }

    /// Decode f32
    pub fn decode_f32(&mut self) -> Result<f32> {
        self.align(4)?;
        let bytes = self.read_bytes(4)?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        Ok(f32::from_le_bytes(arr))
    }

    /// Decode f64
    pub fn decode_f64(&mut self) -> Result<f64> {
        self.align(8)?;
        let bytes = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(f64::from_le_bytes(arr))
    }

    /// Decode string (borrowed, zero-copy)
    ///
    /// Returns &str pointing to buffer (without null terminator)
    pub fn decode_string_borrowed(&mut self) -> Result<&'a str> {
        // Decode length (includes null terminator)
        let len = self.decode_u32()? as usize;

        if len == 0 {
            return Err(Error::DecodingError);
        }

        // Read string bytes (without null terminator)
        let bytes = self.read_bytes(len - 1)?;

        // Skip null terminator
        self.decode_u8()?;

        // Convert to &str
        core::str::from_utf8(bytes).map_err(|_| Error::DecodingError)
    }

    /// Decode byte array (borrowed)
    pub fn decode_bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        self.read_bytes(count)
    }

    /// Decode sequence length prefix (u32)
    ///
    /// Used for decoding bounded sequences/arrays with variable length.
    pub fn decode_seq_len(&mut self) -> Result<usize> {
        Ok(self.decode_u32()? as usize)
    }

    /// Decode string into owned heapless::String
    ///
    /// Returns a heapless::String with capacity N. Fails if the decoded
    /// string is longer than N bytes.
    #[cfg(feature = "heapless")]
    pub fn decode_string<const N: usize>(&mut self) -> Result<heapless::String<N>> {
        let s = self.decode_string_borrowed()?;
        heapless::String::try_from(s).map_err(|_| Error::BufferTooSmall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_u32() {
        let mut buf = [0u8; 16];
        let mut encoder = CdrEncoder::new(&mut buf);
        encoder.encode_u32(0x1234_5678).unwrap();

        let bytes = encoder.finish();
        let mut decoder = CdrDecoder::new(bytes);
        let value = decoder.decode_u32().unwrap();

        assert_eq!(value, 0x1234_5678);
    }

    #[test]
    fn test_encode_decode_string() {
        let mut buf = [0u8; 64];
        let mut encoder = CdrEncoder::new(&mut buf);
        encoder.encode_string("hello").unwrap();

        let bytes = encoder.finish();
        let mut decoder = CdrDecoder::new(bytes);
        let value = decoder.decode_string_borrowed().unwrap();

        assert_eq!(value, "hello");
    }

    #[test]
    fn test_alignment() {
        let mut buf = [0u8; 64];
        let mut encoder = CdrEncoder::new(&mut buf);

        encoder.encode_u8(0x11).unwrap(); // pos = 1
        encoder.encode_u32(0x2222_2222).unwrap(); // should align to 4, then write

        assert_eq!(encoder.position(), 8); // 1 + 3 (padding) + 4
    }

    #[test]
    fn test_mixed_types() {
        let mut buf = [0u8; 128];
        let mut encoder = CdrEncoder::new(&mut buf);

        encoder.encode_bool(true).unwrap();
        encoder.encode_i16(-42).unwrap();
        encoder.encode_f32(2.72).unwrap();
        encoder.encode_string("test").unwrap();

        let bytes = encoder.finish();
        let mut decoder = CdrDecoder::new(bytes);

        assert!(decoder.decode_bool().unwrap());
        assert_eq!(decoder.decode_i16().unwrap(), -42);
        assert!((decoder.decode_f32().unwrap() - 2.72).abs() < 0.01);
        assert_eq!(decoder.decode_string_borrowed().unwrap(), "test");
    }

    #[test]
    fn test_buffer_too_small() {
        let mut buf = [0u8; 2];
        let mut encoder = CdrEncoder::new(&mut buf);

        let result = encoder.encode_u32(42);
        assert_eq!(result, Err(Error::BufferTooSmall));
    }
}
