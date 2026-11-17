// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DHEADER framing helpers for @APPENDABLE TypeObject records (XTypes v1.3).
//!
//! Per OMG DDS-XTypes v1.3 Sec.7.4.3.4 rule (30):
//!
//! ```text
//! XCDR[2] << {O : APPENDABLE_TYPE} =
//!     XCDR
//!         << { DHEADER(O) : UInt32 }   ; 4-byte aligned, value = payload size
//!         << { O : AsFinal(O.type) }   ; payload encoded as if FINAL
//! ```
//!
//! Per Sec.7.4.3.4.1: "The serialization of the DHEADER being a Uint32 type
//! forces a 4-byte alignment relative to XCDR.origin, this may insert into the
//! stream up to 3 padding bytes prior to the DHEADER."
//!
//! These helpers frame @APPENDABLE TypeObject sub-records with their DHEADER
//! (see `xtypes/cdr2/type_objects.rs`).

use crate::core::ser::traits::CdrError;

/// Wraps an `@APPENDABLE` payload encoder with the spec-mandated DHEADER prefix.
///
/// Pad-to-4 before the DHEADER (DHEADER itself is u32, requires 4-byte
/// alignment), reserve 4 bytes for the size prefix, invoke `body` to encode
/// the payload, then write the payload size back into the reserved DHEADER
/// slot.
///
/// # Arguments
/// * `dst` -- destination buffer (parent, full slice).
/// * `offset` -- global cursor, mutated in-place.
/// * `body` -- closure that encodes the payload starting at `*offset` and
///   advances `*offset` accordingly.
///
/// # Returns
/// `Ok(())` on success. The cursor advances by `pad + 4 + payload_size`.
///
/// # Errors
/// - `CdrError::BufferTooSmall` if `dst` lacks room for pad + DHEADER prefix.
/// - `CdrError::DataTooLarge` if the payload size overflows `u32`.
/// - Any error returned by `body` is propagated; the cursor state is undefined
///   on error.
#[inline]
pub(super) fn encode_dheader_at<F>(
    dst: &mut [u8],
    offset: &mut usize,
    body: F,
) -> Result<(), CdrError>
where
    F: FnOnce(&mut [u8], &mut usize) -> Result<(), CdrError>,
{
    let pad = (4 - (*offset % 4)) % 4;
    if *offset + pad + 4 > dst.len() {
        return Err(CdrError::BufferTooSmall);
    }
    dst[*offset..*offset + pad].fill(0);
    *offset += pad;

    let dheader_pos = *offset;
    *offset += 4;
    let payload_start = *offset;

    body(dst, offset)?;

    let payload_size =
        u32::try_from(*offset - payload_start).map_err(|_| CdrError::DataTooLarge)?;
    dst[dheader_pos..dheader_pos + 4].copy_from_slice(&payload_size.to_le_bytes());
    Ok(())
}

/// Decodes an `@APPENDABLE` payload by reading the DHEADER prefix first.
///
/// Pad-to-4 (DHEADER is u32, 4-aligned), read the 4-byte payload size, invoke
/// `body` to decode the payload with a buffer slice bounded to the DHEADER
/// region, then advance the cursor to `payload_end` (which may skip unknown
/// trailing bytes -- this is the forward-compatibility mechanism for adding
/// fields to @APPENDABLE records).
///
/// # Bounded body slice (defense against silent over-read)
/// The body closure receives `&src[..payload_end]`, not the full parent
/// buffer. This guarantees that a body which over-reads the declared DHEADER
/// size surfaces as `UnexpectedEof` instead of silently consuming bytes that
/// belong to the next record. Without this bound, a
/// malicious or buggy peer can write `DHEADER=N` with a body that reads >N
/// bytes; the unconditional `*offset = payload_end` rewind would mask the
/// over-read, returning a value composed of bytes from the next record and
/// causing cascading mis-parse downstream.
///
/// # Arguments
/// * `src` -- source buffer (parent, full slice).
/// * `offset` -- global cursor, mutated in-place.
/// * `body` -- closure that decodes the payload starting at `*offset` and
///   advances `*offset` by the bytes consumed. The closure receives a buffer
///   slice bounded to `payload_end`; reads past that bound return EOF.
///
/// # Returns
/// The value constructed by `body`. The cursor is advanced past any unknown
/// trailing bytes within the DHEADER payload (forward compatibility for
/// under-read; over-read is rejected by the bounded slice).
///
/// # Errors
/// - `CdrError::UnexpectedEof` if `src` lacks room for pad + DHEADER, the
///   DHEADER size exceeds the remaining buffer, or the body over-reads past
///   the declared DHEADER size.
/// - Any error returned by `body` is propagated; the cursor state is undefined
///   on error.
#[inline]
pub(super) fn decode_dheader_at<T, F>(
    src: &[u8],
    offset: &mut usize,
    body: F,
) -> Result<T, CdrError>
where
    F: FnOnce(&[u8], &mut usize) -> Result<T, CdrError>,
{
    let pad = (4 - (*offset % 4)) % 4;
    if *offset + pad + 4 > src.len() {
        return Err(CdrError::UnexpectedEof);
    }
    *offset += pad;

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&src[*offset..*offset + 4]);
    let payload_size = u32::from_le_bytes(len_bytes) as usize;
    *offset += 4;

    let payload_end = *offset + payload_size;
    if payload_end > src.len() {
        return Err(CdrError::UnexpectedEof);
    }

    // Bound the body's view of `src` to `payload_end`. The body still operates
    // on a `&[u8]` that starts at index 0 (matching the full-buffer contract
    // of every other Cdr2 decoder) but cannot see bytes beyond the declared
    // DHEADER region -- any read past `payload_end` returns EOF.
    let bounded = &src[..payload_end];
    let value = body(bounded, offset)?;

    // Forward-compat: skip any unknown trailing bytes within the DHEADER payload.
    *offset = payload_end;

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dheader_roundtrip_offset_zero() {
        let mut buf = [0u8; 32];
        let mut offset = 0;
        encode_dheader_at(&mut buf, &mut offset, |dst, off| {
            dst[*off..*off + 4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
            *off += 4;
            Ok(())
        })
        .unwrap();
        assert_eq!(offset, 8); // 4 (DHEADER) + 4 (payload)
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 4); // payload_size
        assert_eq!(
            u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            0xDEAD_BEEF
        );

        let mut read_off = 0;
        let value = decode_dheader_at(&buf, &mut read_off, |src, off| {
            let mut tmp = [0u8; 4];
            tmp.copy_from_slice(&src[*off..*off + 4]);
            *off += 4;
            Ok(u32::from_le_bytes(tmp))
        })
        .unwrap();
        assert_eq!(value, 0xDEAD_BEEF);
        assert_eq!(read_off, 8);
    }

    #[test]
    fn dheader_roundtrip_offset_3_pad_to_4() {
        let mut buf = [0u8; 32];
        let mut offset = 3;
        encode_dheader_at(&mut buf, &mut offset, |dst, off| {
            dst[*off..*off + 4].copy_from_slice(&0x1234_u32.to_le_bytes());
            *off += 4;
            Ok(())
        })
        .unwrap();
        // Expected layout: [..pre..][pad x 1 = 0x00][DHEADER 4 bytes][payload 4 bytes]
        // offset starts at 3, pad = (4 - 3%4)%4 = 1, so pad byte at index 3
        assert_eq!(buf[3], 0); // pad zero-filled
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 4); // payload_size
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 0x1234);
        assert_eq!(offset, 12);

        let mut read_off = 3;
        let value = decode_dheader_at(&buf, &mut read_off, |src, off| {
            let mut tmp = [0u8; 4];
            tmp.copy_from_slice(&src[*off..*off + 4]);
            *off += 4;
            Ok(u32::from_le_bytes(tmp))
        })
        .unwrap();
        assert_eq!(value, 0x1234);
        assert_eq!(read_off, 12);
    }

    #[test]
    fn dheader_decode_skips_unknown_trailing_bytes() {
        // Simulate a peer that wrote 4 bytes of payload + 4 bytes of "future
        // field" inside the DHEADER. Decoder reads only the first 4 bytes but
        // advances past payload_end (forward-compat).
        let mut buf = [0u8; 32];
        // DHEADER = 8 (4 bytes known + 4 bytes unknown future fields)
        buf[0..4].copy_from_slice(&8_u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0xCAFE_u32.to_le_bytes());
        buf[8..12].copy_from_slice(&0xDEAD_u32.to_le_bytes()); // unknown future field
        let mut read_off = 0;
        let value = decode_dheader_at(&buf, &mut read_off, |src, off| {
            let mut tmp = [0u8; 4];
            tmp.copy_from_slice(&src[*off..*off + 4]);
            *off += 4;
            Ok(u32::from_le_bytes(tmp))
        })
        .unwrap();
        assert_eq!(value, 0xCAFE);
        assert_eq!(read_off, 12); // 4 (DHEADER) + 8 (full DHEADER payload), not 4+4
    }

    #[test]
    fn dheader_encode_rejects_oversized_payload() {
        // Payload exceeds buffer -> encoder body returns BufferTooSmall
        let mut buf = [0u8; 6]; // 4 (DHEADER) + only 2 bytes for payload
        let mut offset = 0;
        let result = encode_dheader_at(&mut buf, &mut offset, |dst, off| {
            if *off + 4 > dst.len() {
                return Err(CdrError::BufferTooSmall);
            }
            dst[*off..*off + 4].copy_from_slice(&0_u32.to_le_bytes());
            *off += 4;
            Ok(())
        });
        assert!(matches!(result, Err(CdrError::BufferTooSmall)));
    }

    #[test]
    fn dheader_decode_rejects_bogus_size() {
        // DHEADER claims size > remaining buffer -> UnexpectedEof
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&999_u32.to_le_bytes()); // bogus size
        let mut read_off = 0;
        let result: Result<u32, _> = decode_dheader_at(&buf, &mut read_off, |_src, _off| Ok(0u32));
        assert!(matches!(result, Err(CdrError::UnexpectedEof)));
    }

    #[test]
    fn dheader_decode_rejects_eof_before_header() {
        // Source too short to hold the DHEADER itself
        let buf = [0u8; 2];
        let mut read_off = 0;
        let result: Result<u32, _> = decode_dheader_at(&buf, &mut read_off, |_src, _off| Ok(0u32));
        assert!(matches!(result, Err(CdrError::UnexpectedEof)));
    }

    /// Adversarial: DHEADER declares a 4-byte payload, but the body attempts
    /// to read 8 bytes. Without the bounded slice, the body
    /// would silently consume the next record's bytes and the helper would
    /// rewind to `payload_end`, returning a corrupted value composed of
    /// bytes from the wrong record. With the bounded slice, the over-read
    /// surfaces as `UnexpectedEof`.
    #[test]
    fn dheader_decode_rejects_body_over_read() {
        let mut buf = [0u8; 16];
        // DHEADER = 4 (payload is 4 bytes)
        buf[0..4].copy_from_slice(&4_u32.to_le_bytes());
        // 4 bytes of declared payload
        buf[4..8].copy_from_slice(&0xCAFE_u32.to_le_bytes());
        // 8 bytes belonging to the "next record" that the body must NOT see
        buf[8..16].copy_from_slice(&0xDEAD_BEEF_DEAD_BEEF_u64.to_le_bytes());

        let mut read_off = 0;
        let result: Result<u64, _> = decode_dheader_at(&buf, &mut read_off, |src, off| {
            // Body attempts to read 8 bytes even though DHEADER declared 4.
            // With bounded slice, src.len() == 8 (4 header + 4 payload), so
            // the 8-byte read at *off=4 needs src[4..12] which is out of
            // bounds -> UnexpectedEof.
            if *off + 8 > src.len() {
                return Err(CdrError::UnexpectedEof);
            }
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&src[*off..*off + 8]);
            *off += 8;
            Ok(u64::from_le_bytes(tmp))
        });
        assert!(
            matches!(result, Err(CdrError::UnexpectedEof)),
            "over-read past payload_end must be rejected, got {:?}",
            result
        );
    }
}
