// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR2 primitive encoding/decoding helpers
//!
//!
//! Low-level functions for encoding/decoding primitive types (u8, u16, u32, etc.)
//! and managing alignment/padding per CDR2 specification.
//!
//! # Note
//! These helpers are NOT auto-exported from `cdr2` module.
//! Use explicit imports: `use crate::xtypes::cdr2::primitives::encode_u32_le;`
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.1 (Primitive Types Encoding)

use crate::core::ser::traits::CdrError;
use std::convert::TryFrom;

// ============================================================================
// Helper: CDR2 Alignment and Padding
// ============================================================================

/// Align offset to required alignment (CDR2 spec section 10.2.2)
pub(super) const fn align_offset(offset: usize, alignment: usize) -> usize {
    (offset + alignment - 1) & !(alignment - 1)
}

/// Compute padding bytes needed for alignment
#[allow(dead_code)] // Used by type_objects tests for alignment verification
pub(super) const fn padding_for_alignment(offset: usize, alignment: usize) -> usize {
    align_offset(offset, alignment) - offset
}

// ============================================================================
// Primitive Encoding Helpers
// ============================================================================

/// Encode u8 (1-byte, no alignment)
pub(super) fn encode_u8(value: u8, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
    if *offset >= dst.len() {
        return Err(CdrError::BufferTooSmall);
    }
    dst[*offset] = value;
    *offset += 1;
    Ok(())
}

/// Encode u16 (2-byte alignment, zero-fills any padding gap per XCDR2 sec. 7.4.3.4.2).
pub(super) fn encode_u16(value: u16, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
    let aligned = align_offset(*offset, 2);
    if aligned + 2 > dst.len() {
        return Err(CdrError::BufferTooSmall);
    }
    dst[*offset..aligned].fill(0);
    *offset = aligned;
    dst[*offset..*offset + 2].copy_from_slice(&value.to_le_bytes());
    *offset += 2;
    Ok(())
}

/// Encode u32 (4-byte alignment, zero-fills any padding gap per XCDR2 sec. 7.4.3.4.2).
pub(super) fn encode_u32(value: u32, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
    let aligned = align_offset(*offset, 4);
    if aligned + 4 > dst.len() {
        return Err(CdrError::BufferTooSmall);
    }
    dst[*offset..aligned].fill(0);
    *offset = aligned;
    dst[*offset..*offset + 4].copy_from_slice(&value.to_le_bytes());
    *offset += 4;
    Ok(())
}

/// Encode i16 (2-byte alignment, zero-fills any padding gap per XCDR2 sec. 7.4.3.4.2).
pub(super) fn encode_i16(value: i16, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
    let aligned = align_offset(*offset, 2);
    if aligned + 2 > dst.len() {
        return Err(CdrError::BufferTooSmall);
    }
    dst[*offset..aligned].fill(0);
    *offset = aligned;
    dst[*offset..*offset + 2].copy_from_slice(&value.to_le_bytes());
    *offset += 2;
    Ok(())
}

/// Encode i32 (4-byte alignment, zero-fills any padding gap per XCDR2 sec. 7.4.3.4.2).
pub(super) fn encode_i32(value: i32, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
    let aligned = align_offset(*offset, 4);
    if aligned + 4 > dst.len() {
        return Err(CdrError::BufferTooSmall);
    }
    dst[*offset..aligned].fill(0);
    *offset = aligned;
    dst[*offset..*offset + 4].copy_from_slice(&value.to_le_bytes());
    *offset += 4;
    Ok(())
}

/// Encode `bytes` (a little-endian primitive) at `alignment`, zero-filling
/// the padding gap. XCDR2 aligns a primitive to its size up to 4 (DDS-XTypes
/// 1.3 7.4.3.4.2, MAXALIGN 4): 8- and 16-octet values take alignment 4.
pub(super) fn encode_aligned(
    bytes: &[u8],
    alignment: usize,
    dst: &mut [u8],
    offset: &mut usize,
) -> Result<(), CdrError> {
    let aligned = align_offset(*offset, alignment);
    if aligned + bytes.len() > dst.len() {
        return Err(CdrError::BufferTooSmall);
    }
    dst[*offset..aligned].fill(0);
    dst[aligned..aligned + bytes.len()].copy_from_slice(bytes);
    *offset = aligned + bytes.len();
    Ok(())
}

/// Encode bool (1-byte, stored using a u8 representation)
pub(super) fn encode_bool(value: bool, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
    encode_u8(u8::from(value), dst, offset)
}

/// Encode string (4-byte length + UTF-8 bytes + null terminator)
pub(super) fn encode_string(
    value: &str,
    dst: &mut [u8],
    offset: &mut usize,
) -> Result<(), CdrError> {
    let total_len_usize = value
        .len()
        .checked_add(1)
        .ok_or_else(|| CdrError::Other("String too long for CDR2 encoding".into()))?;
    let total_len = u32::try_from(total_len_usize)
        .map_err(|_| CdrError::Other("String too long for CDR2 encoding".into()))?;

    encode_u32(total_len, dst, offset)?;

    if *offset + total_len_usize > dst.len() {
        return Err(CdrError::BufferTooSmall);
    }

    dst[*offset..*offset + value.len()].copy_from_slice(value.as_bytes());
    *offset += value.len();
    dst[*offset] = 0; // Null terminator
    *offset += 1;

    Ok(())
}

/// Encode Option<T> (1-byte discriminator + value if Some)
pub(super) fn encode_option<T, F>(
    value: &Option<T>,
    dst: &mut [u8],
    offset: &mut usize,
    encode_fn: F,
) -> Result<(), CdrError>
where
    F: FnOnce(&T, &mut [u8], &mut usize) -> Result<(), CdrError>,
{
    match value {
        None => encode_bool(false, dst, offset),
        Some(v) => {
            encode_bool(true, dst, offset)?;
            encode_fn(v, dst, offset)
        }
    }
}

/// Encode Vec<T> (4-byte length + elements)
pub(super) fn encode_vec<T, F>(
    vec: &[T],
    dst: &mut [u8],
    offset: &mut usize,
    encode_fn: F,
) -> Result<(), CdrError>
where
    F: Fn(&T, &mut [u8], &mut usize) -> Result<(), CdrError>,
{
    let len = u32::try_from(vec.len())
        .map_err(|_| CdrError::Other("Vector too long for CDR2 encoding".into()))?;

    encode_u32(len, dst, offset)?;
    for item in vec {
        let aligned = align_offset(*offset, 4);
        if aligned > dst.len() {
            return Err(CdrError::BufferTooSmall);
        }
        dst[*offset..aligned].fill(0);
        *offset = aligned;
        encode_fn(item, dst, offset)?;
    }
    Ok(())
}

/// Encode Vec<T> with elements emitted in ascending key order.
///
/// Used by TypeObject sub-records that XTypes v1.3 sec. 7.3.4.5 requires to
/// serialize in a specific order (member_id, value, position, name_hash,
/// ...) for the resulting EquivalenceHash to be bitwise-identical across
/// vendors. Wire format is identical to [`encode_vec`]; only the element
/// order is normalized.
///
/// The source `vec` is not mutated -- sorting is done on an index buffer.
/// Uses [`slice::sort_by_cached_key`], which Rust guarantees is **stable**
/// AND evaluates `key_fn` exactly **once per element** (the keys are
/// cached, the sort runs on the cache). This matters for non-trivial
/// keys such as MD5-derived name hashes: `sort_by` would call `key_fn`
/// twice per comparison (`O(N log N)` evaluations); the cached variant
/// brings that down to `O(N)`.
///
/// Stability means duplicate keys preserve their source-Vec order in
/// the wire output. The spec forbids duplicate keys within an ordered
/// TypeObject sub-record, but stability still matters as a defence in
/// depth against malformed or adversarial inputs -- equal keys still
/// produce deterministic wire bytes.
pub(super) fn encode_vec_sorted<T, K, E, F>(
    vec: &[T],
    dst: &mut [u8],
    offset: &mut usize,
    key_fn: K,
    encode_fn: F,
) -> Result<(), CdrError>
where
    K: Fn(&T) -> E,
    E: Ord,
    F: Fn(&T, &mut [u8], &mut usize) -> Result<(), CdrError>,
{
    let len = u32::try_from(vec.len())
        .map_err(|_| CdrError::Other("Vector too long for CDR2 encoding".into()))?;

    encode_u32(len, dst, offset)?;

    let mut indices: Vec<usize> = (0..vec.len()).collect();
    indices.sort_by_cached_key(|&i| key_fn(&vec[i]));

    for i in indices {
        let aligned = align_offset(*offset, 4);
        if aligned > dst.len() {
            return Err(CdrError::BufferTooSmall);
        }
        dst[*offset..aligned].fill(0);
        *offset = aligned;
        encode_fn(&vec[i], dst, offset)?;
    }
    Ok(())
}

// ============================================================================
// Primitive Decoding Helpers
// ============================================================================

/// Decode u8 (1-byte, no alignment)
pub(super) fn decode_u8(src: &[u8], offset: &mut usize) -> Result<u8, CdrError> {
    if *offset >= src.len() {
        return Err(CdrError::UnexpectedEof);
    }
    let value = src[*offset];
    *offset += 1;
    Ok(value)
}

/// Decode u16 (2-byte alignment)
pub(super) fn decode_u16(src: &[u8], offset: &mut usize) -> Result<u16, CdrError> {
    *offset = align_offset(*offset, 2);
    if *offset + 2 > src.len() {
        return Err(CdrError::UnexpectedEof);
    }
    let bytes = src[*offset..*offset + 2]
        .try_into()
        .map_err(|_| CdrError::UnexpectedEof)?;
    *offset += 2;
    Ok(u16::from_le_bytes(bytes))
}

/// Decode u32 (4-byte alignment)
pub(super) fn decode_u32(src: &[u8], offset: &mut usize) -> Result<u32, CdrError> {
    *offset = align_offset(*offset, 4);
    if *offset + 4 > src.len() {
        return Err(CdrError::UnexpectedEof);
    }
    let bytes = src[*offset..*offset + 4]
        .try_into()
        .map_err(|_| CdrError::UnexpectedEof)?;
    *offset += 4;
    Ok(u32::from_le_bytes(bytes))
}

/// Decode i16 (2-byte alignment)
pub(super) fn decode_i16(src: &[u8], offset: &mut usize) -> Result<i16, CdrError> {
    *offset = align_offset(*offset, 2);
    if *offset + 2 > src.len() {
        return Err(CdrError::UnexpectedEof);
    }
    let bytes = src[*offset..*offset + 2]
        .try_into()
        .map_err(|_| CdrError::UnexpectedEof)?;
    *offset += 2;
    Ok(i16::from_le_bytes(bytes))
}

/// Decode i32 (4-byte alignment)
pub(super) fn decode_i32(src: &[u8], offset: &mut usize) -> Result<i32, CdrError> {
    *offset = align_offset(*offset, 4);
    if *offset + 4 > src.len() {
        return Err(CdrError::UnexpectedEof);
    }
    let bytes = src[*offset..*offset + 4]
        .try_into()
        .map_err(|_| CdrError::UnexpectedEof)?;
    *offset += 4;
    Ok(i32::from_le_bytes(bytes))
}

/// Decode `N` octets at `alignment` (see [`encode_aligned`]).
pub(super) fn decode_aligned<const N: usize>(
    src: &[u8],
    alignment: usize,
    offset: &mut usize,
) -> Result<[u8; N], CdrError> {
    let aligned = align_offset(*offset, alignment);
    let end = aligned.checked_add(N).ok_or(CdrError::UnexpectedEof)?;
    let bytes: [u8; N] = src
        .get(aligned..end)
        .ok_or(CdrError::UnexpectedEof)?
        .try_into()
        .map_err(|_| CdrError::UnexpectedEof)?;
    *offset = end;
    Ok(bytes)
}

/// Decode bool (1-byte, decoded from u8)
pub(super) fn decode_bool(src: &[u8], offset: &mut usize) -> Result<bool, CdrError> {
    Ok(decode_u8(src, offset)? != 0)
}

/// Decode string (4-byte length + UTF-8 bytes + null terminator)
pub(super) fn decode_string(src: &[u8], offset: &mut usize) -> Result<String, CdrError> {
    let len = usize::try_from(decode_u32(src, offset)?)
        .map_err(|_| CdrError::Other("String length exceeds platform capacity".into()))?;
    if len == 0 {
        return Ok(String::new());
    }

    if *offset + len > src.len() {
        return Err(CdrError::UnexpectedEof);
    }

    // Exclude null terminator
    let str_bytes = &src[*offset..*offset + len - 1];
    let s = String::from_utf8(str_bytes.to_vec()).map_err(|_| CdrError::InvalidEncoding)?;
    *offset += len;

    Ok(s)
}

/// Decode Option<T> (1-byte discriminator + value if Some)
pub(super) fn decode_option<T, F>(
    src: &[u8],
    offset: &mut usize,
    decode_fn: F,
) -> Result<Option<T>, CdrError>
where
    F: FnOnce(&[u8], &mut usize) -> Result<T, CdrError>,
{
    if decode_bool(src, offset)? {
        Ok(Some(decode_fn(src, offset)?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `encode_vec_sorted` must use a stable sort: when two elements
    /// compare equal under the key function, their wire emission order
    /// must follow their source-Vec order. The spec forbids duplicate
    /// keys in XTypes sec. 7.3.4.5 ordered sequences, but stability matters
    /// as a defence-in-depth -- duplicate keys must still produce
    /// deterministic wire bytes.
    #[test]
    fn encode_vec_sorted_is_stable_on_duplicate_keys() {
        // Three elements share key=2; the encoder should emit them in
        // source order (tag 'a', 'b', 'c'). Element with key=1 sorts
        // before; element with key=3 sorts after.
        let entries: Vec<(u8, u8)> = vec![(2, b'a'), (3, b'z'), (2, b'b'), (1, b'x'), (2, b'c')];

        let mut buf = vec![0u8; 64];
        let mut offset = 0;
        encode_vec_sorted(
            &entries,
            &mut buf,
            &mut offset,
            |(key, _)| *key,
            |(_, tag), dst, offset| encode_u8(*tag, dst, offset),
        )
        .expect("encode succeeds");

        // Wire layout: u32 length (5) + 5 aligned bytes (one per element)
        // Each element pads to 4-byte alignment per encode_vec(_sorted)
        // semantics, so tag bytes land at offsets 4, 8, 12, 16, 20.
        assert_eq!(buf[0..4], [5, 0, 0, 0], "length prefix is 5");
        assert_eq!(buf[4], b'x', "key=1 first");
        assert_eq!(buf[8], b'a', "key=2 source-first tag preserved");
        assert_eq!(buf[12], b'b', "key=2 source-second tag preserved");
        assert_eq!(buf[16], b'c', "key=2 source-third tag preserved");
        assert_eq!(buf[20], b'z', "key=3 last");
    }
}
