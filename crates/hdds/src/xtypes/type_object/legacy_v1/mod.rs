// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Legacy TypeObject v1 (XCDR1) decoder.
//!
//!
//! RTI Connext (`--type-object-version 1`) and CoreDX both, in some
//! configurations, announce their type description using a pre-XTypes-1.2
//! "TypeObject v1" wire format instead of the OMG DDS-XTypes v1.3
//! `CompleteTypeObject` CDR2 encoding that [`super::codec`] and
//! [`Cdr2Decode`](crate::Cdr2Decode) target. This module decodes that
//! legacy format into our [`CompleteTypeObject`] model so the matcher can
//! use it exactly like a spec-current TypeObject.
//!
//! # Wire format
//!
//! The format is a "parameterized" XCDR1 little-endian serialization: every
//! field is wrapped in a small TLV envelope (a 4-byte short header, or a
//! 12-byte "RTI extended" header when the 16-bit parameter id has the
//! `PID_EXTENDED` (`0x3f01`) bit pattern set). The top-level layout is:
//!
//! ```text
//! TypeObject := TypeLibrary(member 0) _TypeId(member 1) PID_LIST_END
//! TypeLibrary := u32 count, TypeLibraryElement*
//! TypeLibraryElement := u32 kind, <kind-specific body>, PID_LIST_END
//! ```
//!
//! `_TypeId` and every "type reference" field on the wire is a small union:
//! a `u16` discriminator, either a primitive `TypeKind` (`<= 13`, followed
//! by 2 padding/redundant bytes) or a reference to another library element
//! (`> 13`, padded to an 8-byte boundary *relative to the enclosing field's
//! own start*, followed by a `u64` hash-like type id used purely as a
//! same-payload lookup key -- it has no relation to our own
//! [`EquivalenceHash`]).
//!
//! MODULE elements are transparent: they carry no type id of their own and
//! simply nest another `TypeLibrary`, contributing a `::`-qualified name
//! prefix to everything inside. Some vendors (CoreDX observed) instead emit
//! a single flat library element whose name is already fully qualified
//! (e.g. `"Test::struct_x1"`); both shapes are handled by the same
//! `prefix + "::" + own_name` rule (empty prefix at the top level -> the
//! flat name is used verbatim).
//!
//! ANONYMOUS collection kinds (ARRAY / SEQUENCE / STRING) are helper
//! library elements: a member that references one is inlined as a
//! `TypeIdentifier::PlainArray*` / `PlainSequence*` / `String*` /
//! `WString*`, never registered as a standalone dependent. References to
//! NAMED kinds (STRUCTURE / UNION / ENUMERATION / ALIAS) are resolved
//! recursively, hashed with our own [`EquivalenceHash`] machinery via
//! `crate::dynamic::complete_to_minimal_type_object`, and returned as
//! `TypeIdentifier::Minimal(hash)` plus a `(hash, CompleteTypeObject)` pair
//! in [`DecodedTypeObjectV1::dependents`].
//!
//! Kinds this decoder does not understand (MAP, ANNOTATION, BITSET, and any
//! future/unknown kind value) are skipped using their declared body length,
//! exactly like the reference dissector -- a member that references one of
//! these surfaces as a decode error for the enclosing type rather than a
//! silently wrong structural shape.
//!
//! Robustness follows the reference dissector's own strategy: every
//! sub-field is wrapped in a length-prefixed envelope, and advancing past
//! it ALWAYS uses the envelope's declared length (rounded up to 4 bytes),
//! never the offset our own recursive field-parsing happened to land on.
//! This makes the decoder tolerant of padding / reserved bytes we don't
//! otherwise interpret, and is what packet-rtps.c's
//! `rtps_util_add_type_library_element` does too (it discards the
//! `void`-returning per-kind parser's internal cursor).
//!
//! # References
//! - Wireshark `packet-rtps.c`: `rtps_util_add_typeobject`,
//!   `rtps_util_dissect_parameter_header`, `rtps_util_add_type_id`,
//!   `rtps_util_add_type_library[_element]`, `rtps_util_add_type_member`,
//!   `rtps_util_add_type_element_{struct,union,enumeration,alias,array,sequence,string}`.
//! - RTI Connext legacy TypeObject v1 (XTypes-1.1 era), XCDR1 little-endian.

use std::collections::{HashMap, HashSet};

use super::CompleteTypeObject;
use crate::protocol::discovery::ParseError;
use crate::xtypes::EquivalenceHash;

/// Result of decoding a legacy TypeObject v1 payload.
pub struct DecodedTypeObjectV1 {
    /// The root type (the one referenced by the payload's top-level
    /// `_TypeId`), ready to use exactly like a CDR2-decoded
    /// `CompleteTypeObject`.
    pub root: CompleteTypeObject,

    /// Named types (struct/union/enum/alias) transitively reachable from
    /// `root`'s members, keyed by the Minimal `EquivalenceHash` embedded in
    /// the corresponding `TypeIdentifier::Minimal(_)` member reference.
    /// Deduplicated by hash. Anonymous collection helpers (array/sequence/
    /// string library elements) are inlined into member `TypeIdentifier`s
    /// and never appear here.
    pub dependents: Vec<(EquivalenceHash, CompleteTypeObject)>,
}

/// Decode a legacy (XCDR1) TypeObject v1 payload into our XTypes 1.3 model.
///
/// `bytes` is the fully decompressed / raw parameter payload (the same
/// bytes that would otherwise be handed to
/// `CompleteTypeObject::decode_cdr2_le`): for `PID_TYPE_OBJECT_LB`
/// (`0x8021`) this is the zlib-decompressed body; for `PID_TYPE_OBJECT`
/// (`0x0072`) carrying a v1 payload (CoreDX observed) it is the raw
/// parameter value, uncompressed.
pub fn decode_type_object_v1(bytes: &[u8]) -> Result<DecodedTypeObjectV1, ParseError> {
    // TypeLibrary member (member id 0).
    let lib_hdr = read_param_header(bytes, 0)?;
    let mut library: HashMap<u64, RawElement> = HashMap::new();
    let _ = flatten_type_library(bytes, lib_hdr.body_offset, "", &mut library, 0)?;
    let after_lib = round_up4(add(
        lib_hdr.body_offset,
        u32_to_usize(lib_hdr.member_length)?,
    )?)?;

    // _TypeId member (member id 1): the root type reference.
    let tid_hdr = read_param_header(bytes, after_lib)?;
    let (root_raw, _) = read_type_id(bytes, tid_hdr.body_offset, tid_hdr.body_offset)?;
    let root_id = match root_raw {
        RawTypeId::Complex(id) => id,
        // A bare primitive cannot be a topic-level root type.
        RawTypeId::Primitive(_) => return Err(ParseError::InvalidFormat),
    };

    // Require the buffer to actually contain _TypeId's full declared extent
    // plus the trailing PID_LIST_END sentinel, even though `read_type_id`
    // above only needed to read a prefix of it: a payload truncated right
    // after the bytes we happen to consume is still a malformed/incomplete
    // payload relative to its own self-description and must not silently
    // decode successfully.
    let after_tid = round_up4(add(
        tid_hdr.body_offset,
        u32_to_usize(tid_hdr.member_length)?,
    )?)?;
    need(bytes, after_tid, 4)?;

    let mut ctx = BuildCtx {
        library: &library,
        dependents: HashMap::new(),
        building: HashSet::new(),
        resolved_named: HashMap::new(),
        steps: 0,
    };

    let root_elem = ctx.library.get(&root_id).ok_or(ParseError::InvalidFormat)?;
    if !matches!(
        root_elem,
        RawElement::Struct { .. }
            | RawElement::Union { .. }
            | RawElement::Enum { .. }
            | RawElement::Alias { .. }
    ) {
        // Root resolved to an anonymous collection helper or an unsupported
        // kind -- not a valid topic-level type.
        return Err(ParseError::InvalidFormat);
    }
    ctx.building.insert(root_id);
    let root = build_complete_type_object(root_elem, &mut ctx)?;
    ctx.building.remove(&root_id);

    Ok(DecodedTypeObjectV1 {
        root,
        dependents: ctx.dependents.into_iter().collect(),
    })
}

mod build;
mod flatten;
mod projection;
mod wire;

#[cfg(any(test, feature = "xtypes-structural-assignability"))]
pub(crate) use projection::v1_projection_equivalent;

#[cfg(test)]
pub(crate) mod test_vectors;

#[cfg(test)]
mod tests;

use build::{build_complete_type_object, BuildCtx};
use flatten::{flatten_type_library, RawElement};
use wire::{add, need, read_param_header, read_type_id, round_up4, u32_to_usize, RawTypeId};
