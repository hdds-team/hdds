// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR Micro - Lightweight CDR encoder/decoder for embedded
//!
//! Implements a minimal subset of classic CDR, the XCDR version 1 encoding
//! (DDS-XTypes 1.3 7.4.1, `PLAIN_CDR`), little endian, with fixed buffers
//! and no heap allocations.
//!
//! ## Encoding version
//!
//! Every primitive is aligned to its own size, counted from the first byte
//! of the buffer, so an 8-byte value is aligned at 8: `MAXALIGN(VERSION1) =
//! 8` (DDS-XTypes 1.3 7.4.3.2.2, Table 37). That is XCDR1. XCDR2
//! (`PLAIN_CDR2`) caps the alignment at 4, `MAXALIGN(VERSION2) = 4`, so the
//! two differ on any 8-byte member that follows a member whose size is not a
//! multiple of 8. A body these cursors write must therefore travel under
//! [`CDR_LE`] (or [`PL_CDR_LE`] for a parameter list), never under an XCDR2
//! identifier, and a body labelled XCDR2 must not be read with them:
//! [`representation_is_xcdr1_le`] is the test.
//!
//! The alignment origin is the first byte of the buffer, which is the first
//! byte after the 4-byte encapsulation header (RTPS 2.5 10.2: "the CDR
//! stream is logically reset at the position that follows the
//! representation_options"). The header is written by `MicroWriter`, not by
//! the encoder.
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

/// Size of the SerializedPayloadHeader that starts every serialized
/// payload: a 2-octet representation identifier and 2 octets of options
/// (RTPS 2.5 10.2).
pub const ENCAPSULATION_HEADER_SIZE: usize = 4;

/// `CDR_LE` `{0x00, 0x01}`: classic CDR (XCDR1), little endian, for a FINAL
/// or APPENDABLE type (DDS-XTypes 1.3 7.6.3.1.2, Table 60). The identifier
/// of what [`CdrEncoder`] writes.
pub const CDR_LE: u16 = 0x0001;

/// `PL_CDR_LE` `{0x00, 0x03}`: XCDR1 parameter list, little endian, for a
/// MUTABLE type (DDS-XTypes 1.3 7.6.3.1.2, Table 60).
pub const PL_CDR_LE: u16 = 0x0003;

/// `CDR2_LE` `{0x00, 0x07}`: `PLAIN_CDR2`, little endian, for a FINAL type
/// (DDS-XTypes 1.3 7.6.3.1.2, Table 60).
///
/// RTPS 2.5 Table 10.3 lists `{0x00, 0x11}` for the same name; Table 60 of
/// DDS-XTypes is what the stacks put on the wire (Eclipse Cyclone DDS 0.11
/// answers `{0x00, 0x07}` for a FINAL type at encoding version 2), so it is
/// the value used here.
pub const CDR2_LE: u16 = 0x0007;

/// `D_CDR2_LE` `{0x00, 0x09}`: `DELIMITED_CDR`, little endian, for an
/// APPENDABLE type under XCDR2 (DDS-XTypes 1.3 7.6.3.1.2, Table 60).
pub const D_CDR2_LE: u16 = 0x0009;

/// `PL_CDR2_LE` `{0x00, 0x0b}`: `PL_CDR2`, little endian, for a MUTABLE
/// type under XCDR2 (DDS-XTypes 1.3 7.6.3.1.2, Table 60).
pub const PL_CDR2_LE: u16 = 0x000B;

/// Whether a body labelled `representation` is laid out as these cursors
/// read it: XCDR1, little endian ([`CDR_LE`] or [`PL_CDR_LE`]).
///
/// Every other identifier is either big endian or XCDR2, whose 8-byte
/// members sit at a different offset; decoding such a body with
/// [`CdrDecoder`] would deliver wrong values without an error.
pub const fn representation_is_xcdr1_le(representation: u16) -> bool {
    matches!(representation, CDR_LE | PL_CDR_LE)
}

/// Whether `representation` is one of the little-endian XCDR identifiers
/// (DDS-XTypes 1.3 7.6.3.1.2, Table 60), version 1 or 2.
pub const fn representation_is_xcdr_le(representation: u16) -> bool {
    matches!(
        representation,
        CDR_LE | PL_CDR_LE | CDR2_LE | D_CDR2_LE | PL_CDR2_LE
    )
}

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

    /// Bodies Eclipse Cyclone DDS 0.11.0 serializes for the same IDL types,
    /// declared `@final`, with `dds_stream_write_sample` on an output stream
    /// at encoding version 1 and at version 2, and the identifier
    /// `ddsi_sertype_get_native_enc_identifier` gives for each (captured
    /// with a probe program built against Cyclone DDS).
    /// Cyclone's output, verbatim (`encap` printed as a host-order u16 of
    /// the two wire octets, so `0100` is `{0x00, 0x01}`):
    ///
    /// ```text
    /// U8I64        xcdr2 encap=0700 body=110000000807060504030201
    /// U8I64        xcdr1 encap=0100 body=11000000000000000807060504030201
    /// U16F64U8     xcdr2 encap=0700 body=33220000000000000000f83f44
    /// U16F64U8     xcdr1 encap=0100 body=3322000000000000000000000000f83f44
    /// StrI64       xcdr2 encap=0700 body=060000006162636465000000feffffffffffffff
    /// StrI64       xcdr1 encap=0100 body=06000000616263646500000000000000feffffffffffffff
    /// U32F64       xcdr2 encap=0700 body=0d0c0b0a000000000000d0bf
    /// U32F64       xcdr1 encap=0100 body=0d0c0b0a00000000000000000000d0bf
    /// ```
    ///
    /// The encoder writes the version-1 bodies byte for byte and none of the
    /// version-2 ones, which is why its identifier is `CDR_LE`.
    const CYCLONE_U8I64_X1: [u8; 16] = [
        0x11, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    ];
    const CYCLONE_U8I64_X2: [u8; 12] = [
        0x11, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    ];
    const CYCLONE_U16F64U8_X1: [u8; 17] = [
        0x33, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf8, 0x3f, 0x44,
    ];
    const CYCLONE_STRI64_X1: [u8; 24] = [
        0x06, 0, 0, 0, b'a', b'b', b'c', b'd', b'e', 0, 0, 0, 0, 0, 0, 0, 0xfe, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
    ];
    const CYCLONE_U32F64_X1: [u8; 16] = [
        0x0d, 0x0c, 0x0b, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xd0, 0xbf,
    ];

    #[test]
    fn the_encoder_writes_cyclones_xcdr1_bodies() {
        let mut buf = [0u8; 32];
        let mut enc = CdrEncoder::new(&mut buf);
        enc.encode_u8(0x11).unwrap();
        enc.encode_i64(0x0102_0304_0506_0708).unwrap();
        let body = enc.finish();
        assert_eq!(body, &CYCLONE_U8I64_X1[..]);
        assert_ne!(body, &CYCLONE_U8I64_X2[..]);

        let mut buf = [0u8; 32];
        let mut enc = CdrEncoder::new(&mut buf);
        enc.encode_u16(0x2233).unwrap();
        enc.encode_f64(1.5).unwrap();
        enc.encode_u8(0x44).unwrap();
        assert_eq!(enc.finish(), &CYCLONE_U16F64U8_X1[..]);

        let mut buf = [0u8; 32];
        let mut enc = CdrEncoder::new(&mut buf);
        enc.encode_string("abcde").unwrap();
        enc.encode_i64(-2).unwrap();
        assert_eq!(enc.finish(), &CYCLONE_STRI64_X1[..]);

        let mut buf = [0u8; 32];
        let mut enc = CdrEncoder::new(&mut buf);
        enc.encode_u32(0x0a0b_0c0d).unwrap();
        enc.encode_f64(-0.25).unwrap();
        assert_eq!(enc.finish(), &CYCLONE_U32F64_X1[..]);
    }

    #[test]
    fn the_decoder_reads_cyclones_xcdr1_bodies() {
        let mut dec = CdrDecoder::new(&CYCLONE_U8I64_X1);
        assert_eq!(dec.decode_u8().unwrap(), 0x11);
        assert_eq!(dec.decode_i64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(dec.remaining(), 0);

        let mut dec = CdrDecoder::new(&CYCLONE_U16F64U8_X1);
        assert_eq!(dec.decode_u16().unwrap(), 0x2233);
        assert_eq!(dec.decode_f64().unwrap(), 1.5);
        assert_eq!(dec.decode_u8().unwrap(), 0x44);
        assert_eq!(dec.remaining(), 0);

        let mut dec = CdrDecoder::new(&CYCLONE_STRI64_X1);
        assert_eq!(dec.decode_string_borrowed().unwrap(), "abcde");
        assert_eq!(dec.decode_i64().unwrap(), -2);

        let mut dec = CdrDecoder::new(&CYCLONE_U32F64_X1);
        assert_eq!(dec.decode_u32().unwrap(), 0x0a0b_0c0d);
        assert_eq!(dec.decode_f64().unwrap(), -0.25);
    }

    #[test]
    fn only_the_little_endian_xcdr1_identifiers_are_read_by_these_cursors() {
        for id in [CDR_LE, PL_CDR_LE] {
            assert!(representation_is_xcdr1_le(id), "{id:#06x}");
            assert!(representation_is_xcdr_le(id), "{id:#06x}");
        }
        for id in [CDR2_LE, D_CDR2_LE, PL_CDR2_LE] {
            assert!(!representation_is_xcdr1_le(id), "{id:#06x}");
            assert!(representation_is_xcdr_le(id), "{id:#06x}");
        }
        // Big endian, version 1 and 2, and the RTPS 2.5 Table 10.3 values.
        for id in [0x0000, 0x0002, 0x0006, 0x0008, 0x000A, 0x0011, 0x0004] {
            assert!(!representation_is_xcdr1_le(id), "{id:#06x}");
            assert!(!representation_is_xcdr_le(id), "{id:#06x}");
        }
    }

    #[test]
    fn test_buffer_too_small() {
        let mut buf = [0u8; 2];
        let mut encoder = CdrEncoder::new(&mut buf);

        let result = encoder.encode_u32(42);
        assert_eq!(result, Err(Error::BufferTooSmall));
    }
}
