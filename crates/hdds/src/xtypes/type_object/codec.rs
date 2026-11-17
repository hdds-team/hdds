// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TypeObject compression and decompression utilities.
//!
//! This module handles XTypes TypeObject encoding/decoding with ZLIB compression
//! for efficient wire transmission. The vendor-specific parameter
//! PID_TYPE_OBJECT_LB (0x8021, vendor id 0x0101) carries compressed TypeObject data.
//!
//! # References
//! - OMG DDS-XTypes v1.3 Sec.7.3 (TypeObject representation)
//! - PID_TYPE_OBJECT_LB (0x8021): a vendor-specific parameter (vendor
//!   0x0101), parsed by the RTI dialect; RTPS does not define it

use crate::protocol::discovery::ParseError;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Upper bound on the inflated size of a ZLIB TypeObject received from a peer.
///
/// A CompleteTypeObject for real IDL is tens of KB. A DEFLATE stream that
/// inflates past this bound is a bomb sized by the sender, so it is refused
/// (never truncated) and no allocation follows its declared content.
pub const MAX_DECOMPRESSED_TYPE_OBJECT: usize = 1 << 20;

/// Decompress ZLIB-compressed TypeObject data (PID_TYPE_OBJECT_LB format).
///
/// A peer may send a TypeObject compressed with ZLIB via PID_TYPE_OBJECT_LB (0x8021)
/// to reduce wire size for large type definitions with nested structures.
///
/// Uses `ZlibDecoder` (RFC 1950: 2-byte header + Adler-32 trailer around the
/// DEFLATE stream), not `DeflateDecoder` (RFC 1951, no wrapper): a real RTI
/// Connext 7.7.0 capture's `PID_TYPE_OBJECT_LB` payload begins with the
/// standard zlib magic (`0x78 0xda`) and fails to decode as raw DEFLATE.
///
/// # Arguments
/// * `buf` - Buffer containing the complete packet
/// * `offset` - Start position of compressed data
/// * `length` - Length of compressed data
///
/// # Returns
/// * `Ok(Vec<u8>)` - Decompressed TypeObject CDR2 bytes
/// * `Err(ParseError::InvalidFormat)` - Decompression failure, a slice outside
///   `buf`, or an inflated size past `MAX_DECOMPRESSED_TYPE_OBJECT`
///
/// # Example Flow
/// ```text
/// RTPS Packet -> PID_TYPE_OBJECT_LB (0x8021) -> ZLIB compressed bytes
///   v decompress_type_object()
/// CompleteTypeObject CDR2 bytes -> decode_cdr2_le() -> CompleteTypeObject struct
/// ```
///
/// # References
/// - Initial compressed TypeObject decompression support
/// - OMG RTPS v2.5 Sec.9.6.3.1
pub fn decompress_type_object(
    buf: &[u8],
    offset: usize,
    length: usize,
) -> Result<Vec<u8>, ParseError> {
    let end = offset
        .checked_add(length)
        .ok_or(ParseError::InvalidFormat)?;
    let compressed_data = buf.get(offset..end).ok_or(ParseError::InvalidFormat)?;
    let mut decompressed = Vec::new();

    if is_zlib_header(compressed_data) {
        // RFC 1950 (what RTI Connext sends). The stream must be whole: every
        // input octet consumed and the Adler-32 trailer equal to the checksum
        // of the output. flate2 reports a stream cut before its trailer as a
        // clean end of input, so a truncated stream is only caught here.
        let mut decoder = ZlibDecoder::new(compressed_data);
        read_bounded(&mut decoder, &mut decompressed)?;
        let consumed = usize::try_from(decoder.total_in()).ok();
        let trailer = compressed_data
            .len()
            .checked_sub(4)
            .and_then(|start| compressed_data.get(start..))
            .and_then(|t| <[u8; 4]>::try_from(t).ok())
            .map(u32::from_be_bytes);
        if consumed != Some(compressed_data.len()) || trailer != Some(adler32(&decompressed)) {
            return Err(ParseError::InvalidFormat);
        }
    } else {
        // Raw RFC 1951 DEFLATE, the form this decoder accepted before the
        // zlib wrapper was recognised; kept so such a peer keeps its type.
        let mut decoder = DeflateDecoder::new(compressed_data);
        read_bounded(&mut decoder, &mut decompressed)?;
    }

    log::debug!(
        "[TYPE-OBJECT] [OK] Decompressed ZLIB TypeObject: {} bytes -> {} bytes",
        length,
        decompressed.len()
    );
    Ok(decompressed)
}

/// `true` when `data` starts with a valid RFC 1950 header: compression
/// method 8 (DEFLATE), window at most 32 KiB, and the header check bits
/// making the 16-bit header a multiple of 31.
fn is_zlib_header(data: &[u8]) -> bool {
    match data {
        [cmf, flg, ..] => {
            cmf & 0x0f == 8 && cmf >> 4 <= 7 && (u16::from(*cmf) * 256 + u16::from(*flg)) % 31 == 0
        }
        _ => false,
    }
}

/// Inflate into `out`, refusing (never truncating) a stream past
/// `MAX_DECOMPRESSED_TYPE_OBJECT`: one octet past the bound tells a stream
/// that overflows it from one that ends exactly at it.
fn read_bounded(decoder: &mut impl Read, out: &mut Vec<u8>) -> Result<(), ParseError> {
    decoder
        .take(MAX_DECOMPRESSED_TYPE_OBJECT as u64 + 1)
        .read_to_end(out)
        .map_err(|_| ParseError::InvalidFormat)?;
    if out.len() > MAX_DECOMPRESSED_TYPE_OBJECT {
        return Err(ParseError::InvalidFormat);
    }
    Ok(())
}

/// Adler-32 (RFC 1950 section 8.2) of `data`.
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let (mut a, mut b) = (1u32, 0u32);
    // 5552 is the largest run before `b` can overflow a u32 (RFC 1950 / zlib NMAX).
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// Compress TypeObject CDR2 bytes with ZLIB for PID_TYPE_OBJECT_LB.
///
/// This function encodes a CompleteTypeObject to CDR2 format, then compresses
/// it with ZLIB deflate for efficient transmission. This is the format
/// carried by PID_TYPE_OBJECT_LB in SEDP announcements.
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
/// - PID_TYPE_OBJECT_LB support
/// - Uses the default ZLIB compression level
pub fn compress_type_object(
    type_obj_buf: &[u8],
    type_obj_len: usize,
) -> Result<Vec<u8>, ParseError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
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

    #[test]
    fn adler32_matches_the_rfc_1950_reference_value() {
        // Well-known check value: Adler-32("Wikipedia") = 0x11E60398.
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(b""), 1);
    }

    #[test]
    fn test_decompress_refuses_a_zlib_stream_cut_before_its_trailer() {
        let payload = b"a TypeObject long enough to compress into a real stream";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).expect("zlib into memory");
        let whole = encoder.finish().expect("zlib into memory");
        assert_eq!(
            decompress_type_object(&whole, 0, whole.len()).as_deref(),
            Ok(&payload[..])
        );
        for cut in 1..=4 {
            let short = &whole[..whole.len() - cut];
            assert_eq!(
                decompress_type_object(short, 0, short.len()),
                Err(ParseError::InvalidFormat),
                "a stream missing {cut} trailer octet(s) is refused"
            );
        }
        let mut trailing = whole.clone();
        trailing.push(0);
        assert_eq!(
            decompress_type_object(&trailing, 0, trailing.len()),
            Err(ParseError::InvalidFormat),
            "octets past the end of the stream are refused"
        );
    }

    #[test]
    fn test_decompress_still_accepts_raw_deflate() {
        let payload = b"raw DEFLATE without the zlib wrapper";
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).expect("deflate into memory");
        let raw = encoder.finish().expect("deflate into memory");
        assert!(!is_zlib_header(&raw));
        assert_eq!(
            decompress_type_object(&raw, 0, raw.len()).as_deref(),
            Ok(&payload[..])
        );
    }

    /// ZLIB (RFC 1950) of `len` zero octets, as an RTI peer sends it.
    fn deflate_zeros(len: usize) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&vec![0u8; len])
            .expect("zlib into memory");
        encoder.finish().expect("zlib into memory")
    }

    #[test]
    fn test_decompress_refuses_inflation_past_the_bound() {
        // A few KiB of compressed zeros inflating one octet past the bound.
        let bomb = deflate_zeros(MAX_DECOMPRESSED_TYPE_OBJECT + 1);
        assert_eq!(
            decompress_type_object(&bomb, 0, bomb.len()),
            Err(ParseError::InvalidFormat)
        );
    }

    #[test]
    fn test_decompress_accepts_inflation_exactly_at_the_bound() {
        let packed = deflate_zeros(MAX_DECOMPRESSED_TYPE_OBJECT);
        let out = decompress_type_object(&packed, 0, packed.len())
            .expect("a stream ending at the bound is accepted");
        assert_eq!(out.len(), MAX_DECOMPRESSED_TYPE_OBJECT);
    }

    #[test]
    fn test_decompress_out_of_range_slice_is_refused() {
        let buf = [0u8; 4];
        assert_eq!(
            decompress_type_object(&buf, 2, 10),
            Err(ParseError::InvalidFormat)
        );
        assert_eq!(
            decompress_type_object(&buf, usize::MAX, 2),
            Err(ParseError::InvalidFormat)
        );
    }
}
