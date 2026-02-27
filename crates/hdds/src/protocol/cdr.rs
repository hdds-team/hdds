// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR2 v2 encoding/decoding for RTPS payloads.
//!
//! Provides `EncoderLE` and `DecoderLE` for little-endian canonical CDR2 format.

use crate::core::ser::cursor::{Cursor, CursorMut};
use crate::core::ser::{SerError, SerResult};
use crate::core::string_utils::format_string;

/// CDR2 v2 magic (0xCACE in little-endian)
const MAGIC: u16 = 0xCACE;
const VERSION_MAJOR: u8 = 0x02;
const VERSION_MINOR: u8 = 0x00;

/// Flags: LE (0), compact mode (0), inline type (0) = 0x00 canonical
const FLAGS_LE_CANONICAL: u8 = 0x00;
/// Flags: BE detected (bit 0 set) = 0x01 -> reject in T0
const FLAGS_BE_BIT: u8 = 0x01;

/// Encoder: writes CDR2 v2 LE canonical format
pub struct EncoderLE<'a> {
    cursor: CursorMut<'a>,
}

impl<'a> EncoderLE<'a> {
    /// Create new encoder, write header
    pub fn new(buffer: &'a mut [u8]) -> SerResult<Self> {
        let mut cursor = CursorMut::new(buffer);

        // Write CDR2 header (8 bytes total)
        cursor.write_u16_le(MAGIC)?; // offset 0-1: magic 0xCACE
        cursor.write_u8(VERSION_MAJOR)?; // offset 2: version 0x02
        cursor.write_u8(VERSION_MINOR)?; // offset 3: version 0x00
        cursor.write_u8(FLAGS_LE_CANONICAL)?; // offset 4: flags (LE, compact, inline)
        cursor.write_u8(0x00)?; // offset 5: reserved
        cursor.write_u16_le(0x0000)?; // offset 6-7: reserved

        Ok(EncoderLE { cursor })
    }

    // encode_struct/encode_sequence stubs removed in v0.3.0 cleanup.
    // v0.3.0 uses #[derive(hdds::DDS)] which generates field-by-field encoding.
    // If manual struct/sequence encoding needed, use primitive write methods above.

    pub fn offset(&self) -> usize {
        self.cursor.offset()
    }
}

/// Decoder: reads CDR2 v2 LE canonical format, strict BE rejection
pub struct DecoderLE<'a> {
    cursor: Cursor<'a>,
}

impl<'a> DecoderLE<'a> {
    /// Create new decoder, validate header
    pub fn new(buffer: &'a [u8]) -> SerResult<Self> {
        let mut cursor = Cursor::new(buffer);

        // Read CDR2 header
        let magic = cursor.read_u16_le()?;
        if magic != MAGIC {
            return Err(SerError::DecoderFailed {
                reason: format_string(format_args!("invalid magic {:#X}", magic)),
            });
        }

        let version_major = cursor.read_u8()?;
        if version_major != VERSION_MAJOR {
            return Err(SerError::DecoderFailed {
                reason: format_string(format_args!("unsupported version {}", version_major)),
            });
        }

        let _version_minor = cursor.read_u8()?;
        let flags = cursor.read_u8()?;
        cursor.read_u8()?; // reserved
        cursor.read_u16_le()?; // reserved

        // Check endianness: if flags & 0x01 != 0 (BE detected) -> reject in T0
        if (flags & FLAGS_BE_BIT) != 0 {
            return Err(SerError::DecoderFailed {
                reason: "big-endian flag set".into(),
            });
        }

        Ok(DecoderLE { cursor })
    }

    // decode_struct/decode_sequence stubs removed in v0.3.0 cleanup.
    // v0.3.0 uses #[derive(hdds::DDS)] which generates field-by-field decoding.
    // If manual struct/sequence decoding needed, use primitive read methods above.

    pub fn offset(&self) -> usize {
        self.cursor.offset()
    }
}

/// Helper: compute padding to alignment (v2 compact mode)
pub fn pad_to_align(offset: usize, alignment: u8) -> usize {
    if alignment <= 1 {
        return offset;
    }
    let mask = (alignment as usize) - 1;
    (offset + mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_header() {
        let mut buf = [0u8; 256];
        let encoder = EncoderLE::new(&mut buf).expect("buffer is large enough");
        assert_eq!(encoder.offset(), 8);

        // Verify header bytes
        assert_eq!(buf[0..2], [0xCE, 0xCA]); // magic LE
        assert_eq!(buf[2], 0x02); // version major
        assert_eq!(buf[3], 0x00); // version minor
        assert_eq!(buf[4], 0x00); // flags: LE, compact
    }

    #[test]
    fn test_encoder_buffer_too_small() {
        let mut buf = [0u8; 4];
        let result = EncoderLE::new(&mut buf);
        assert!(result.is_err(), "Should fail with buffer < 8 bytes");
    }

    #[test]
    fn test_encoder_buffer_exactly_8_bytes() {
        let mut buf = [0u8; 8];
        let encoder = EncoderLE::new(&mut buf).expect("exact buffer should succeed");
        assert_eq!(encoder.offset(), 8);
    }

    #[test]
    fn test_decoder_header_valid() {
        let buf = [0xCE, 0xCA, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        let decoder = DecoderLE::new(&buf).expect("valid header");
        assert_eq!(decoder.offset(), 8);
    }

    #[test]
    fn test_decoder_buffer_too_small() {
        let buf = [0xCE, 0xCA, 0x02, 0x00];
        let result = DecoderLE::new(&buf);
        assert!(result.is_err(), "Should fail with buffer < 8 bytes");
    }

    #[test]
    fn test_decoder_rejects_be() {
        let buf = [0xCA, 0xCE, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00]; // BE flags
        let result = DecoderLE::new(&buf);
        assert!(result.is_err(), "Should reject BE flag");
    }

    #[test]
    fn test_decoder_invalid_magic() {
        let buf = [0xFF, 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]; // bad magic
        let result = DecoderLE::new(&buf);
        assert!(result.is_err(), "Should reject invalid magic");
    }

    #[test]
    fn test_decoder_invalid_version() {
        let buf = [0xCE, 0xCA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]; // version 1
        let result = DecoderLE::new(&buf);
        assert!(result.is_err(), "Should reject invalid version");
    }

    #[test]
    fn test_pad_to_align() {
        assert_eq!(pad_to_align(8, 4), 8);
        assert_eq!(pad_to_align(9, 4), 12);
        assert_eq!(pad_to_align(10, 8), 16);
        assert_eq!(pad_to_align(8, 1), 8);
        assert_eq!(pad_to_align(0, 4), 0);
        assert_eq!(pad_to_align(1, 2), 2);
        assert_eq!(pad_to_align(3, 4), 4);
    }

    #[test]
    fn test_roundtrip_header() {
        let mut buf = [0u8; 256];

        // Encode
        let enc = EncoderLE::new(&mut buf).expect("encode header");
        assert_eq!(enc.offset(), 8);

        // Decode
        let dec = DecoderLE::new(&buf).expect("decode header");
        assert_eq!(dec.offset(), 8);
    }
}
