// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Byte-level primitives for the legacy TypeObject v1 (XCDR1) wire format:
//! bounds-checked reads, XCDR1 alignment, the short/RTI-extended parameter
//! header, CDR strings, and the v1 TypeId union (including the CoreDX
//! int8/uint8 vendor-extension kinds). See the module docs in `mod.rs` for
//! the format overview and references.

use crate::protocol::discovery::ParseError;
// ============================================================================
// Bounds-checked byte-level primitives
// ============================================================================

/// RTI's "extended parameter header" marker: a 16-bit parameter id whose
/// bits are a superset of this mask selects the 12-byte extended header
/// form (`u16 pid, u16 len_unused, u32 member_id, u32 member_length`)
/// instead of the plain 4-byte short form. Per packet-rtps.c `#define
/// PID_EXTENDED (0x3f01)`.
pub(super) const PID_EXTENDED_MASK: u16 = 0x3f01;

/// End-of-nested-list sentinel mask. A trailing `u32` whose bits are a
/// superset of this mask marks the end of a member's or a library
/// element's own field list. Per packet-rtps.c `#define PID_LIST_END
/// (0x3f02)`. Vendors differ in which superset bit pattern they actually
/// write (RTI: `0x7f02`, CoreDX: the literal `0x3f02`); both satisfy this
/// mask, matching `(long_number & PID_LIST_END) == PID_LIST_END` in the
/// reference dissector.
pub(super) const LIST_END_MASK: u32 = 0x0000_3f02;

/// Cap on MODULE nesting depth during library flattening.
pub(super) const MAX_MODULE_DEPTH: usize = 32;

/// Cap on named-type reference resolution depth (also bounds anonymous
/// collection-helper reference chains, since both paths share the
/// `building` cycle guard).
pub(super) const MAX_NAMED_RESOLUTION_DEPTH: usize = 64;

/// Cap on the dimensions of one array element. IDL arrays in practice have a
/// handful; the cap stops one wire element from declaring tens of thousands
/// of bounds that every reference then clones.
pub(super) const MAX_ARRAY_DIMENSIONS: usize = 32;

/// Aggregate budget of type-identifier resolutions for one decode. Anonymous
/// collection helpers are not memoized, so each member reference rebuilds
/// its helper chain; the budget keeps the total work and allocation linear
/// in a bound the payload cannot raise, whatever its sharing pattern.
pub(super) const MAX_RESOLUTION_STEPS: usize = 1 << 16;

pub(super) fn need(buf: &[u8], offset: usize, len: usize) -> Result<(), ParseError> {
    let end = offset.checked_add(len).ok_or(ParseError::InvalidFormat)?;
    if end > buf.len() {
        return Err(ParseError::TruncatedData);
    }
    Ok(())
}

pub(super) fn add(a: usize, b: usize) -> Result<usize, ParseError> {
    a.checked_add(b).ok_or(ParseError::InvalidFormat)
}

pub(super) fn u32_to_usize(x: u32) -> Result<usize, ParseError> {
    usize::try_from(x).map_err(|_| ParseError::InvalidFormat)
}

pub(super) fn round_up4(x: usize) -> Result<usize, ParseError> {
    let rem = x % 4;
    if rem == 0 {
        Ok(x)
    } else {
        add(x, 4 - rem)
    }
}

/// Align `offset` up to a `alignment`-byte boundary measured relative to
/// `zero` (NOT relative to the start of the buffer). Mirrors the
/// dissector's `ALIGN_ZERO(offset, alignment, zero)` macro.
pub(super) fn align_zero(
    offset: usize,
    alignment: usize,
    zero: usize,
) -> Result<usize, ParseError> {
    let rel = offset.checked_sub(zero).ok_or(ParseError::InvalidFormat)?;
    let rem = rel % alignment;
    let aligned_rel = if rem == 0 {
        rel
    } else {
        add(rel, alignment - rem)?
    };
    add(zero, aligned_rel)
}

pub(super) fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, ParseError> {
    need(buf, offset, 2)?;
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

pub(super) fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, ParseError> {
    need(buf, offset, 4)?;
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

pub(super) fn read_i32_le(buf: &[u8], offset: usize) -> Result<i32, ParseError> {
    need(buf, offset, 4)?;
    Ok(i32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

pub(super) fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64, ParseError> {
    need(buf, offset, 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&buf[offset..offset + 8]);
    Ok(u64::from_le_bytes(arr))
}

/// A parameter header, short (4-byte) or RTI-extended (12-byte) form.
pub(super) struct ParamHeader {
    pub(super) member_length: u32,
    /// Offset of the first byte of this parameter's content.
    pub(super) body_offset: usize,
}

pub(super) fn read_param_header(buf: &[u8], offset: usize) -> Result<ParamHeader, ParseError> {
    let pid16 = read_u16_le(buf, offset)?;
    let len16 = read_u16_le(buf, add(offset, 2)?)?;
    let after_short = add(offset, 4)?;
    if (pid16 & PID_EXTENDED_MASK) == PID_EXTENDED_MASK {
        let member_length = read_u32_le(buf, add(after_short, 4)?)?;
        let body_offset = add(after_short, 8)?;
        Ok(ParamHeader {
            member_length,
            body_offset,
        })
    } else {
        Ok(ParamHeader {
            member_length: u32::from(len16),
            body_offset: after_short,
        })
    }
}

/// Read a CDR string: `u32` length (including the NUL terminator) followed
/// by that many bytes, then padded so the next field starts on a 4-byte
/// boundary. Returns the decoded text (NUL and any trailing padding
/// stripped) and the offset right after the padded field.
pub(super) fn read_cdr_string(buf: &[u8], offset: usize) -> Result<(String, usize), ParseError> {
    let len = u32_to_usize(read_u32_le(buf, offset)?)?;
    let start = add(offset, 4)?;
    need(buf, start, len)?;
    let raw = &buf[start..start + len];
    let text = raw.split(|&b| b == 0).next().unwrap_or(&[]);
    let s = std::str::from_utf8(text)
        .map_err(|_| ParseError::InvalidFormat)?
        .to_string();
    let next = add(start, round_up4(len)?)?;
    Ok((s, next))
}

/// A v1 `TypeId` union value: either a primitive `TypeKind` discriminator
/// (`<= 13`) or a same-payload reference to another library element's own
/// type id (`> 13`, the wire hash).
#[derive(Clone, Copy)]
pub(super) enum RawTypeId {
    Primitive(u16),
    Complex(u64),
}

/// CoreDX vendor extension: v1 TypeId kind for IDL `int8`.
///
/// Unlike RTI (which collapses byte/uint8/int8 to BYTE = 2 on the v1 wire,
/// see `map_primitive_kind`), CoreDX 6.14.1 DISTINGUISHES the 8-bit integer
/// kinds by extending the kind table past RTI's enum: captured wire
/// (`Test::struct_primitive_int8`, raw 0x0072 payload) carries member
/// TypeId discriminator 24 in the primitive shape (u16 disc + redundant
/// u16, 4 bytes total, no hash).
pub(super) const V1_KIND_INT8: u16 = 24;

/// CoreDX vendor extension: v1 TypeId kind for IDL `uint8` (captured wire:
/// `Test::struct_primitive_uint8` carries discriminator 25). See
/// [`V1_KIND_INT8`].
pub(super) const V1_KIND_UINT8: u16 = 25;

/// Discriminator values that select the PRIMITIVE arm of the v1 TypeId
/// union (4-byte form: disc + redundant u16) rather than the complex arm
/// (pad-to-8 + u64 library reference).
///
/// Base range 0..=13 per the reference dissector (`rtps_util_add_type_id`:
/// `short_number <= 13`). The CoreDX int8/uint8 extensions (24/25) are
/// UNAMBIGUOUS additions here: in the TypeId-discriminator position RTI
/// only ever emits 0..=13 (primitives) or the referenced library element's
/// kind for complex refs, which is 14..=23 (ENUMERATION..ANNOTATION) --
/// RTI's 24 is MODULE, which owns no type id and can never be referenced
/// as a member type, so no RTI payload puts 24 (or anything above it) in
/// this position. No sending-vendor dispatch is therefore needed.
pub(super) fn is_primitive_type_id_disc(disc: u16) -> bool {
    disc <= 13 || disc == V1_KIND_INT8 || disc == V1_KIND_UINT8
}

/// Read a v1 `TypeId` union at `offset`. `zero` is the baseline the 8-byte
/// alignment for the complex-case hash is measured against (per
/// `rtps_util_add_type_id`'s `zero` parameter).
pub(super) fn read_type_id(
    buf: &[u8],
    offset: usize,
    zero: usize,
) -> Result<(RawTypeId, usize), ParseError> {
    let disc = read_u16_le(buf, offset)?;
    let after_disc = add(offset, 2)?;
    if is_primitive_type_id_disc(disc) {
        // Primitive: discriminator + one redundant/padding u16 (4 bytes total).
        need(buf, after_disc, 2)?;
        let next = add(after_disc, 2)?;
        Ok((RawTypeId::Primitive(disc), next))
    } else {
        let aligned = align_zero(after_disc, 8, zero)?;
        let hash = read_u64_le(buf, aligned)?;
        let next = add(aligned, 8)?;
        Ok((RawTypeId::Complex(hash), next))
    }
}

pub(super) fn qualify(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}::{name}")
    }
}
