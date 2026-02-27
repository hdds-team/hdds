// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TypeObject compression and decompression utilities.
//!
//! This module handles XTypes TypeObject encoding/decoding with ZLIB compression
//! for efficient wire transmission. RTI Connext uses PID_TYPE_OBJECT_LB (0x8021)
//! for compressed TypeObject data.
//!
//! # References
//! - OMG DDS-XTypes v1.3 Sec.7.3 (TypeObject representation)
//! - OMG RTPS v2.5 Sec.9.6.3.1 (PID_TYPE_OBJECT_LB)
//! - RTI Connext v6.1.0 mig_rtps.h (vendor extensions)

use crate::protocol::discovery::ParseError;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Decompress ZLIB-compressed TypeObject data (RTI PID_TYPE_OBJECT_LB format).
///
/// RTI Connext sends TypeObject compressed with ZLIB via PID_TYPE_OBJECT_LB (0x8021)
/// to reduce wire size for large type definitions with nested structures.
///
/// # Arguments
/// * `buf` - Buffer containing the complete packet
/// * `offset` - Start position of compressed data
/// * `length` - Length of compressed data
///
/// # Returns
/// * `Ok(Vec<u8>)` - Decompressed TypeObject CDR2 bytes
/// * `Err(ParseError::InvalidFormat)` - Decompression failure
///
/// # Example Flow
/// ```text
/// RTPS Packet -> PID_TYPE_OBJECT_LB (0x8021) -> ZLIB compressed bytes
///   v decompress_type_object()
/// CompleteTypeObject CDR2 bytes -> decode_cdr2_le() -> CompleteTypeObject struct
/// ```
///
/// # References
/// - v59: Initial RTI TypeObject decompression support
/// - RTI Connext v6.1.0 mig_rtps.h
/// - OMG RTPS v2.5 Sec.9.6.3.1
pub fn decompress_type_object(
    buf: &[u8],
    offset: usize,
    length: usize,
) -> Result<Vec<u8>, ParseError> {
    let compressed_data = &buf[offset..offset + length];
    let mut decoder = DeflateDecoder::new(compressed_data);
    let mut decompressed = Vec::new();

    decoder
        .read_to_end(&mut decompressed)
        .map_err(|_| ParseError::InvalidFormat)?;

    log::debug!(
        "[TYPE-OBJECT] [OK] Decompressed ZLIB TypeObject: {} bytes -> {} bytes",
        length,
        decompressed.len()
    );
    Ok(decompressed)
}

/// Compress TypeObject CDR2 bytes with ZLIB for PID_TYPE_OBJECT_LB.
///
/// This function encodes a CompleteTypeObject to CDR2 format, then compresses
/// it with ZLIB deflate for efficient transmission. RTI Connext expects this
/// format in SEDP announcements.
///
/// # Arguments
/// * `type_obj_buf` - Pre-encoded TypeObject CDR2 bytes (from encode_cdr2_le)
/// * `type_obj_len` - Length of valid CDR2 data in buffer
///
/// # Returns
/// * `Ok(Vec<u8>)` - Compressed bytes ready for PID_TYPE_OBJECT_LB
/// * `Err(ParseError::EncodingError)` - Compression failure
///
/// # Example Flow
/// ```text
/// CompleteTypeObject -> encode_cdr2_le() -> CDR2 bytes
///   v compress_type_object()
/// ZLIB compressed bytes -> PID_TYPE_OBJECT_LB (0x8021) -> RTPS Packet
/// ```
///
/// # References
/// - v85: PID_TYPE_OBJECT_LB support for RTI compatibility
/// - RTI Connext uses default ZLIB compression level
pub fn compress_type_object(
    type_obj_buf: &[u8],
    type_obj_len: usize,
) -> Result<Vec<u8>, ParseError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&type_obj_buf[..type_obj_len])
        .map_err(|_| ParseError::EncodingError)?;
    let compressed = encoder.finish().map_err(|_| ParseError::EncodingError)?;

    log::debug!(
        "[TYPE-OBJECT] [OK] Compressed TypeObject: {} bytes -> {} bytes",
        type_obj_len,
        compressed.len()
    );
    Ok(compressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        // Use larger repetitive data where compression is guaranteed to work
        let pattern = b"TypeObject ";
        let original: Vec<u8> = pattern.iter().cycle().take(550).copied().collect();
        let compressed = compress_type_object(&original, original.len())
            .expect("Compression should succeed for test data");

        // Compressed should be smaller for highly repetitive data
        // Note: Small data may not compress well due to ZLIB header overhead,
        // but with 550 bytes of repetitive data, compression should work
        assert!(
            compressed.len() < original.len(),
            "Compressed size {} should be < original size {}",
            compressed.len(),
            original.len()
        );

        // Prepare buffer for decompression
        let mut buf = vec![0u8; compressed.len()];
        buf.copy_from_slice(&compressed);

        let decompressed = decompress_type_object(&buf, 0, compressed.len())
            .expect("Decompression should succeed for valid ZLIB data");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_decompress_invalid_data() {
        // Truly invalid ZLIB data should fail decompression
        // Use data that definitely can't be ZLIB (wrong magic bytes)
        let invalid_compressed = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
        let result = decompress_type_object(invalid_compressed, 0, 8);
        assert!(
            result.is_err(),
            "Invalid ZLIB data should fail decompression"
        );
    }
}
