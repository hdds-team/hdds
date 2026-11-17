// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Pass 1 of the legacy TypeObject v1 decode: flatten the wire TypeLibrary
//! (with transparent MODULE nesting) into a flat id -> RawElement map. See
//! the module docs in `mod.rs` for the format overview and robustness
//! strategy (declared-length resync per element).

use std::collections::HashMap;

use super::wire::{
    add, align_zero, need, qualify, read_cdr_string, read_i32_le, read_param_header, read_type_id,
    read_u16_le, read_u32_le, round_up4, u32_to_usize, RawTypeId, LIST_END_MASK,
    MAX_ARRAY_DIMENSIONS, MAX_MODULE_DEPTH,
};
use crate::protocol::discovery::ParseError;
// ============================================================================
// Pass 1: flatten the TypeLibrary into a flat id -> element map
// ============================================================================

/// A struct/union member, or (for a union) the discriminator entry (wire
/// index 0). `labels` is always empty for struct members.
pub(super) struct RawMember {
    pub(super) flags: u16,
    pub(super) member_id: u32,
    pub(super) type_id: RawTypeId,
    pub(super) name: String,
    pub(super) labels: Vec<i32>,
}

/// One `value = name` entry from an enum's `constant_seq`.
pub(super) struct RawEnumLiteral {
    pub(super) value: i32,
    pub(super) name: String,
}

/// A library element, pre-resolution. Names are already fully qualified
/// (module prefix baked in during flattening).
pub(super) enum RawElement {
    Struct {
        flags: u16,
        name: String,
        base_type: RawTypeId,
        members: Vec<RawMember>,
    },
    /// `members[0]` is the discriminator entry; `members[1..]` are the real
    /// case members, per the wire's own convention
    /// (`rtps_util_add_type_union_member(..., is_discriminator = i == 0)`).
    Union {
        flags: u16,
        name: String,
        members: Vec<RawMember>,
    },
    Enum {
        name: String,
        bit_bound: u32,
        literals: Vec<RawEnumLiteral>,
    },
    Alias {
        name: String,
        base_type: RawTypeId,
    },
    /// Anonymous collection helper: fixed-size (possibly multi-dimensional)
    /// array.
    Array {
        element_type: RawTypeId,
        bounds: Vec<u32>,
    },
    /// Anonymous collection helper: bounded (or unbounded, `bound == 0`)
    /// sequence.
    Sequence {
        element_type: RawTypeId,
        bound: u32,
    },
    /// Anonymous collection helper: bounded string or wstring
    /// (`char_kind` distinguishes CHAR_8 from CHAR_32/wide).
    StringColl {
        char_kind: RawTypeId,
        bound: u32,
    },
}

pub(super) fn flatten_type_library(
    buf: &[u8],
    offset: usize,
    prefix: &str,
    out: &mut HashMap<u64, RawElement>,
    depth: usize,
) -> Result<usize, ParseError> {
    let count = read_u32_le(buf, offset)?;
    let mut cur = add(offset, 4)?;
    for _ in 0..count {
        cur = flatten_type_library_element(buf, cur, prefix, out, depth)?;
    }
    Ok(cur)
}

// @audit-ok: kind dispatch (9 arms + fallthrough skip), mirrors packet-rtps.c
// rtps_util_add_type_library_element's switch(long_number) 1:1.
pub(super) fn flatten_type_library_element(
    buf: &[u8],
    offset: usize,
    prefix: &str,
    out: &mut HashMap<u64, RawElement>,
    depth: usize,
) -> Result<usize, ParseError> {
    // Header #1: the element's kind tag (a bare u32 wrapped in its own TLV).
    let hdr1 = read_param_header(buf, offset)?;
    let kind = read_u32_le(buf, hdr1.body_offset)?;
    let after_kind = round_up4(add(hdr1.body_offset, u32_to_usize(hdr1.member_length)?)?)?;

    // Header #2: the element's body.
    let hdr2 = read_param_header(buf, after_kind)?;
    let body_start = hdr2.body_offset;

    match kind {
        24 => {
            // MODULE: no type id of its own, just a name + nested TypeLibrary.
            if depth >= MAX_MODULE_DEPTH {
                return Err(ParseError::InvalidFormat);
            }
            let (mod_name, after_name) = read_cdr_string(buf, body_start)?;
            let child_prefix = qualify(prefix, &mod_name);
            let _ = flatten_type_library(buf, after_name, &child_prefix, out, depth + 1)?;
        }
        22 => {
            let (flags, own_id, name, base_type, members) = parse_struct_body(buf, body_start)?;
            out.insert(
                own_id,
                RawElement::Struct {
                    flags,
                    name: qualify(prefix, &name),
                    base_type,
                    members,
                },
            );
        }
        21 => {
            let (flags, own_id, name, members) = parse_union_body(buf, body_start)?;
            out.insert(
                own_id,
                RawElement::Union {
                    flags,
                    name: qualify(prefix, &name),
                    members,
                },
            );
        }
        14 => {
            let (own_id, name, bit_bound, literals) = parse_enum_body(buf, body_start)?;
            out.insert(
                own_id,
                RawElement::Enum {
                    name: qualify(prefix, &name),
                    bit_bound,
                    literals,
                },
            );
        }
        16 => {
            let (own_id, name, base_type) = parse_alias_body(buf, body_start)?;
            out.insert(
                own_id,
                RawElement::Alias {
                    name: qualify(prefix, &name),
                    base_type,
                },
            );
        }
        17 => {
            let (own_id, element_type, bounds) = parse_array_body(buf, body_start)?;
            out.insert(
                own_id,
                RawElement::Array {
                    element_type,
                    bounds,
                },
            );
        }
        18 => {
            let (own_id, element_type, bound) = parse_sequence_body(buf, body_start)?;
            out.insert(
                own_id,
                RawElement::Sequence {
                    element_type,
                    bound,
                },
            );
        }
        19 => {
            let (own_id, char_kind, bound) = parse_string_body(buf, body_start)?;
            out.insert(own_id, RawElement::StringColl { char_kind, bound });
        }
        _ => {
            // MAP (20), ANNOTATION (23), BITSET (15), or any future/unknown
            // kind: skip via the declared body length, exactly like the
            // reference dissector's `default:` case (`add_info = false`).
            // A member referencing this element's id will fail to resolve
            // (not found in the map), degrading that ONE type gracefully
            // rather than mis-typing the member.
        }
    }

    // Always resync via the declared body length, never trust wherever the
    // kind-specific parser above landed (see module docs: this mirrors
    // rtps_util_add_type_library_element discarding its per-kind parser's
    // internal, `void`-returning cursor).
    let after_body = round_up4(add(body_start, u32_to_usize(hdr2.member_length)?)?)?;
    need(buf, after_body, 4)?;
    add(after_body, 4)
}

/// Parse the common `type_library_type` prefix shared by every non-MODULE
/// library element: `flags(u16) + own_type_id + name(string)`, followed by
/// an (ignored) annotation_seq. Returns `(flags, own_id, name,
/// offset_after_annotations)`.
pub(super) fn parse_type_library_type_header(
    buf: &[u8],
    offset: usize,
) -> Result<(u16, u64, String, usize), ParseError> {
    let hdr = read_param_header(buf, offset)?;
    let body = hdr.body_offset;
    let flags = read_u16_le(buf, body)?;
    let after_flags = add(body, 2)?;
    // NOTE: unlike a member's property block, there is NO pad-to-4 here --
    // the type's own type id starts immediately after the 2-byte flags
    // (verified against the RTI golden vector byte trace).
    let (own_raw, after_id) = read_type_id(buf, after_flags, body)?;
    let own_id = match own_raw {
        RawTypeId::Complex(id) => id,
        // Never observed on the wire (a library element's own id is always
        // a hash); fall back to the bare discriminator so we still produce
        // a stable, if degenerate, key instead of failing outright.
        RawTypeId::Primitive(p) => u64::from(p),
    };
    let (name, _) = read_cdr_string(buf, after_id)?;
    let after_prop = round_up4(add(body, u32_to_usize(hdr.member_length)?)?)?;

    // annotation_seq: not modelled from the legacy wire (XTypes 1.3 members
    // still decode correctly without type-level builtin/custom
    // annotations); skip via declared length.
    let ann_hdr = read_param_header(buf, after_prop)?;
    let after_ann = round_up4(add(
        ann_hdr.body_offset,
        u32_to_usize(ann_hdr.member_length)?,
    )?)?;

    Ok((flags, own_id, name, after_ann))
}

pub(super) fn parse_struct_body(
    buf: &[u8],
    offset: usize,
) -> Result<(u16, u64, String, RawTypeId, Vec<RawMember>), ParseError> {
    let (flags, own_id, name, after_header) = parse_type_library_type_header(buf, offset)?;

    let base_hdr = read_param_header(buf, after_header)?;
    let (base_type, _) = read_type_id(buf, base_hdr.body_offset, base_hdr.body_offset)?;
    let after_base = round_up4(add(
        base_hdr.body_offset,
        u32_to_usize(base_hdr.member_length)?,
    )?)?;

    let seq_hdr = read_param_header(buf, after_base)?;
    let count = read_u32_le(buf, seq_hdr.body_offset)?;
    let mut members = Vec::new();
    let mut cur = add(seq_hdr.body_offset, 4)?;
    for _ in 0..count {
        let (m, next) = parse_struct_member(buf, cur)?;
        members.push(m);
        cur = next;
    }

    Ok((flags, own_id, name, base_type, members))
}

pub(super) fn parse_union_body(
    buf: &[u8],
    offset: usize,
) -> Result<(u16, u64, String, Vec<RawMember>), ParseError> {
    let (flags, own_id, name, after_header) = parse_type_library_type_header(buf, offset)?;

    let members_hdr = read_param_header(buf, after_header)?;
    let count = read_u32_le(buf, members_hdr.body_offset)?;
    let mut members = Vec::new();
    let mut cur = add(members_hdr.body_offset, 4)?;
    for _ in 0..count {
        let (m, next) = parse_union_member(buf, cur)?;
        members.push(m);
        cur = next;
    }
    if members.is_empty() {
        // Must have at least the discriminator entry (wire index 0).
        return Err(ParseError::InvalidFormat);
    }

    Ok((flags, own_id, name, members))
}

pub(super) fn parse_enum_body(
    buf: &[u8],
    offset: usize,
) -> Result<(u64, String, u32, Vec<RawEnumLiteral>), ParseError> {
    let (_flags, own_id, name, after_header) = parse_type_library_type_header(buf, offset)?;

    let bound_hdr = read_param_header(buf, after_header)?;
    let bit_bound = read_u32_le(buf, bound_hdr.body_offset)?;
    let after_bound = round_up4(add(
        bound_hdr.body_offset,
        u32_to_usize(bound_hdr.member_length)?,
    )?)?;

    let seq_hdr = read_param_header(buf, after_bound)?;
    let count = read_u32_le(buf, seq_hdr.body_offset)?;
    let mut cur = add(seq_hdr.body_offset, 4)?;
    let mut literals = Vec::new();
    for _ in 0..count {
        let value = read_i32_le(buf, cur)?;
        let after_value = add(cur, 4)?;
        let (lname, after_name) = read_cdr_string(buf, after_value)?;
        literals.push(RawEnumLiteral { value, name: lname });
        cur = after_name;
    }

    Ok((own_id, name, bit_bound, literals))
}

pub(super) fn parse_alias_body(
    buf: &[u8],
    offset: usize,
) -> Result<(u64, String, RawTypeId), ParseError> {
    let (_flags, own_id, name, after_header) = parse_type_library_type_header(buf, offset)?;
    let base_hdr = read_param_header(buf, after_header)?;
    let (base_type, _) = read_type_id(buf, base_hdr.body_offset, base_hdr.body_offset)?;
    Ok((own_id, name, base_type))
}

pub(super) fn parse_array_body(
    buf: &[u8],
    offset: usize,
) -> Result<(u64, RawTypeId, Vec<u32>), ParseError> {
    let (_flags, own_id, _name, after_header) = parse_type_library_type_header(buf, offset)?;

    let elem_hdr = read_param_header(buf, after_header)?;
    let (element_type, _) = read_type_id(buf, elem_hdr.body_offset, elem_hdr.body_offset)?;
    let after_elem = round_up4(add(
        elem_hdr.body_offset,
        u32_to_usize(elem_hdr.member_length)?,
    )?)?;

    let shared_hdr = read_param_header(buf, after_elem)?;
    let after_shared = round_up4(add(
        shared_hdr.body_offset,
        u32_to_usize(shared_hdr.member_length)?,
    )?)?;

    let bounds_hdr = read_param_header(buf, after_shared)?;
    let bounds = read_array_bounds(buf, bounds_hdr.body_offset)?;

    Ok((own_id, element_type, bounds))
}

/// An array element's dimension list at `offset`: a `u32` count, then that
/// many `u32` bounds. Refused when empty or past `MAX_ARRAY_DIMENSIONS`.
pub(super) fn read_array_bounds(buf: &[u8], offset: usize) -> Result<Vec<u32>, ParseError> {
    let count = u32_to_usize(read_u32_le(buf, offset)?)?;
    if count == 0 || count > MAX_ARRAY_DIMENSIONS {
        return Err(ParseError::InvalidFormat);
    }
    let mut cur = add(offset, 4)?;
    let mut bounds = Vec::with_capacity(count);
    for _ in 0..count {
        bounds.push(read_u32_le(buf, cur)?);
        cur = add(cur, 4)?;
    }
    Ok(bounds)
}

pub(super) fn parse_sequence_body(
    buf: &[u8],
    offset: usize,
) -> Result<(u64, RawTypeId, u32), ParseError> {
    let (_flags, own_id, _name, after_header) = parse_type_library_type_header(buf, offset)?;

    let elem_hdr = read_param_header(buf, after_header)?;
    let (element_type, _) = read_type_id(buf, elem_hdr.body_offset, elem_hdr.body_offset)?;
    let after_elem = round_up4(add(
        elem_hdr.body_offset,
        u32_to_usize(elem_hdr.member_length)?,
    )?)?;

    let shared_hdr = read_param_header(buf, after_elem)?;
    let after_shared = round_up4(add(
        shared_hdr.body_offset,
        u32_to_usize(shared_hdr.member_length)?,
    )?)?;

    let bound_hdr = read_param_header(buf, after_shared)?;
    let bound = read_u32_le(buf, bound_hdr.body_offset)?;

    Ok((own_id, element_type, bound))
}

pub(super) fn parse_string_body(
    buf: &[u8],
    offset: usize,
) -> Result<(u64, RawTypeId, u32), ParseError> {
    let (_flags, own_id, _name, after_header) = parse_type_library_type_header(buf, offset)?;

    let char_hdr = read_param_header(buf, after_header)?;
    let (char_kind, _) = read_type_id(buf, char_hdr.body_offset, char_hdr.body_offset)?;
    let after_char = round_up4(add(
        char_hdr.body_offset,
        u32_to_usize(char_hdr.member_length)?,
    )?)?;

    let shared_hdr = read_param_header(buf, after_char)?;
    let after_shared = round_up4(add(
        shared_hdr.body_offset,
        u32_to_usize(shared_hdr.member_length)?,
    )?)?;

    let bound_hdr = read_param_header(buf, after_shared)?;
    let bound = read_u32_le(buf, bound_hdr.body_offset)?;

    Ok((own_id, char_kind, bound))
}

/// Property block (`flags + pad-to-4 + member_id + type_id + name`) plus
/// its trailing (ignored) annotation_seq, shared by struct members and
/// union members/discriminator. Unlike `parse_type_library_type_header`,
/// there IS a pad-to-4 between flags and member_id here (per
/// `rtps_util_add_type_member`'s `ALIGN_ZERO(offset_tmp, 4, offset)`).
pub(super) fn parse_member_property_and_annotations(
    buf: &[u8],
    offset: usize,
) -> Result<(u16, u32, RawTypeId, String, usize), ParseError> {
    let hdr = read_param_header(buf, offset)?;
    let body = hdr.body_offset;
    let flags = read_u16_le(buf, body)?;
    let after_flags = add(body, 2)?;
    let after_align = align_zero(after_flags, 4, body)?;
    let member_id = read_u32_le(buf, after_align)?;
    let after_mid = add(after_align, 4)?;
    let (type_id, after_id) = read_type_id(buf, after_mid, body)?;
    let (name, _) = read_cdr_string(buf, after_id)?;
    let after_prop = round_up4(add(body, u32_to_usize(hdr.member_length)?)?)?;

    let ann_hdr = read_param_header(buf, after_prop)?;
    let after_ann = round_up4(add(
        ann_hdr.body_offset,
        u32_to_usize(ann_hdr.member_length)?,
    )?)?;

    // Trailing list-end sentinel is CONDITIONAL at member granularity (per
    // rtps_util_add_type_member: consumed only if present) and tolerated
    // when truncated (soft-fail to "no sentinel"), unlike the unconditional
    // library-element-level sentinel in `flatten_type_library_element`.
    let next = match read_u32_le(buf, after_ann) {
        Ok(probe) if (probe & LIST_END_MASK) == LIST_END_MASK => add(after_ann, 4)?,
        _ => after_ann,
    };

    Ok((flags, member_id, type_id, name, next))
}

pub(super) fn parse_struct_member(
    buf: &[u8],
    offset: usize,
) -> Result<(RawMember, usize), ParseError> {
    let (flags, member_id, type_id, name, next) =
        parse_member_property_and_annotations(buf, offset)?;
    Ok((
        RawMember {
            flags,
            member_id,
            type_id,
            name,
            labels: Vec::new(),
        },
        next,
    ))
}

pub(super) fn parse_union_member(
    buf: &[u8],
    offset: usize,
) -> Result<(RawMember, usize), ParseError> {
    let (flags, member_id, type_id, name, after_props) =
        parse_member_property_and_annotations(buf, offset)?;

    let labels_hdr = read_param_header(buf, after_props)?;
    let count = read_u32_le(buf, labels_hdr.body_offset)?;
    let mut cur = add(labels_hdr.body_offset, 4)?;
    let mut labels = Vec::new();
    for _ in 0..count {
        labels.push(read_i32_le(buf, cur)?);
        cur = add(cur, 4)?;
    }
    let after_labels = round_up4(add(
        labels_hdr.body_offset,
        u32_to_usize(labels_hdr.member_length)?,
    )?)?;

    let next = match read_u32_le(buf, after_labels) {
        Ok(probe) if (probe & LIST_END_MASK) == LIST_END_MASK => add(after_labels, 4)?,
        _ => after_labels,
    };

    Ok((
        RawMember {
            flags,
            member_id,
            type_id,
            name,
            labels,
        },
        next,
    ))
}
