// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Pass 2 of the legacy TypeObject v1 decode: resolve wire type-id
//! references against the flattened library and build XTypes 1.3
//! `CompleteTypeObject`s (inlining anonymous collection helpers, hashing
//! named dependents with our own Minimal equivalence machinery). See the
//! module docs in `mod.rs` for the mapping rules.

use std::collections::{HashMap, HashSet};

use super::flatten::{RawElement, RawEnumLiteral, RawMember};
use super::wire::{
    RawTypeId, MAX_NAMED_RESOLUTION_DEPTH, MAX_RESOLUTION_STEPS, V1_KIND_INT8, V1_KIND_UINT8,
};
use crate::protocol::discovery::ParseError;
use crate::xtypes::type_object::{
    CommonAliasBody, CommonEnumeratedLiteral, CommonStructMember, CommonUnionMember,
    CompleteAliasBody, CompleteAliasHeader, CompleteAliasType, CompleteEnumeratedHeader,
    CompleteEnumeratedLiteral, CompleteEnumeratedType, CompleteMemberDetail, CompleteStructHeader,
    CompleteStructMember, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
    CompleteUnionHeader, CompleteUnionMember, CompleteUnionType, TypeIdentifier,
};
use crate::xtypes::{
    CollectionElementFlag, EnumeratedLiteralFlag, EquivalenceHash, EquivalenceKind, MemberFlag,
    PlainArrayLElemDefn, PlainArraySElemDefn, PlainCollectionHeader, PlainSequenceLElemDefn,
    PlainSequenceSElemDefn, StructTypeFlag, TypeKind, UnionTypeFlag,
};
// ============================================================================
// Pass 2: resolve references and build CompleteTypeObject
// ============================================================================

pub(super) struct BuildCtx<'a> {
    pub(super) library: &'a HashMap<u64, RawElement>,
    pub(super) dependents: HashMap<EquivalenceHash, CompleteTypeObject>,
    /// Wire type ids currently being resolved (both named types and
    /// anonymous collection helpers), for reference-cycle detection.
    pub(super) building: HashSet<u64>,
    /// Wire type id -> already-computed Minimal hash, so a named type
    /// referenced by multiple members is only built/hashed once.
    pub(super) resolved_named: HashMap<u64, EquivalenceHash>,
    /// Type-identifier resolutions performed so far, against
    /// `MAX_RESOLUTION_STEPS`.
    pub(super) steps: usize,
}

pub(super) fn map_primitive_kind(v1_kind: u16) -> Result<TypeKind, ParseError> {
    match v1_kind {
        0 => Ok(TypeKind::TK_NONE),
        1 => Ok(TypeKind::TK_BOOLEAN),
        2 => Ok(TypeKind::TK_BYTE),
        3 => Ok(TypeKind::TK_INT16),
        4 => Ok(TypeKind::TK_UINT16),
        5 => Ok(TypeKind::TK_INT32),
        6 => Ok(TypeKind::TK_UINT32),
        7 => Ok(TypeKind::TK_INT64),
        8 => Ok(TypeKind::TK_UINT64),
        9 => Ok(TypeKind::TK_FLOAT32),
        10 => Ok(TypeKind::TK_FLOAT64),
        11 => Ok(TypeKind::TK_FLOAT128),
        12 => Ok(TypeKind::TK_CHAR8),
        // v1 CHAR_32 (wide char) -> our TK_CHAR16 (the "16-bit / UTF-16
        // wide character" kind used by wstring element types).
        13 => Ok(TypeKind::TK_CHAR16),
        // CoreDX vendor extensions (captured wire, see V1_KIND_INT8 /
        // V1_KIND_UINT8): unlike RTI's BYTE-collapse, CoreDX keeps the
        // 8-bit integer kinds distinct on the v1 wire, so these map
        // faithfully and need no same-name substitution to match.
        V1_KIND_INT8 => Ok(TypeKind::TK_INT8),
        V1_KIND_UINT8 => Ok(TypeKind::TK_UINT8),
        _ => Err(ParseError::InvalidFormat),
    }
}

/// Map v1 `MemberFlag` bits (bit0=key, bit1=optional, bit2=shareable,
/// bit3=union_default) to our `MemberFlag`. The legacy wire carries no
/// try-construct information at all, so every member is given
/// `TRY_CONSTRUCT1` (DISCARD, the XTypes default and this codebase's own
/// fresh-encode convention) unconditionally.
pub(super) fn map_member_flags(v1_flags: u16) -> MemberFlag {
    let mut bits = MemberFlag::TRY_CONSTRUCT1.0;
    if v1_flags & 0x0001 != 0 {
        bits |= MemberFlag::IS_KEY.0;
    }
    if v1_flags & 0x0002 != 0 {
        bits |= MemberFlag::IS_OPTIONAL.0;
    }
    if v1_flags & 0x0004 != 0 {
        // "shareable" (external/shared-pointer member) is the closest
        // analog to our IS_EXTERNAL.
        bits |= MemberFlag::IS_EXTERNAL.0;
    }
    if v1_flags & 0x0008 != 0 {
        bits |= MemberFlag::IS_DEFAULT.0;
    }
    MemberFlag(bits)
}

/// Map v1 `TypeFlag` bits (bit0=FINAL, bit1=MUTABLE, bit2=NESTED) to our
/// `StructTypeFlag`. v1 has no explicit APPENDABLE bit: "neither FINAL nor
/// MUTABLE" is v1's APPENDABLE, matching packet-rtps.c's own
/// `EXTENSIBILITY_EXTENSIBLE` fallback in `rtps_util_add_type_library_type`.
pub(super) fn map_struct_flags(v1_flags: u16) -> StructTypeFlag {
    let mut bits = if v1_flags & 0x0002 != 0 {
        StructTypeFlag::IS_MUTABLE.0
    } else if v1_flags & 0x0001 != 0 {
        StructTypeFlag::IS_FINAL.0
    } else {
        StructTypeFlag::IS_APPENDABLE.0
    };
    if v1_flags & 0x0004 != 0 {
        bits |= StructTypeFlag::IS_NESTED.0;
    }
    StructTypeFlag(bits)
}

/// Union counterpart of [`map_struct_flags`]; same v1 bit layout.
pub(super) fn map_union_flags(v1_flags: u16) -> UnionTypeFlag {
    let mut bits = if v1_flags & 0x0002 != 0 {
        UnionTypeFlag::IS_MUTABLE.0
    } else if v1_flags & 0x0001 != 0 {
        UnionTypeFlag::IS_FINAL.0
    } else {
        UnionTypeFlag::IS_APPENDABLE.0
    };
    if v1_flags & 0x0004 != 0 {
        bits |= UnionTypeFlag::IS_NESTED.0;
    }
    UnionTypeFlag(bits)
}

pub(super) fn resolve_type_id(
    raw: &RawTypeId,
    ctx: &mut BuildCtx,
) -> Result<TypeIdentifier, ParseError> {
    ctx.steps += 1;
    if ctx.steps > MAX_RESOLUTION_STEPS {
        return Err(ParseError::InvalidFormat);
    }
    match raw {
        RawTypeId::Primitive(v1_kind) => {
            Ok(TypeIdentifier::Primitive(map_primitive_kind(*v1_kind)?))
        }
        RawTypeId::Complex(id) => resolve_named_or_helper(*id, ctx),
    }
}

/// Resolve a struct/bitset "base_type" (or any other optional type
/// reference) field: v1's `NO_TYPE` (primitive discriminator `0`) is a
/// sentinel meaning "absent", not a real reference to `TypeKind::TK_NONE`.
pub(super) fn resolve_optional_base(
    raw: &RawTypeId,
    ctx: &mut BuildCtx,
) -> Result<Option<TypeIdentifier>, ParseError> {
    match raw {
        RawTypeId::Primitive(0) => Ok(None),
        other => Ok(Some(resolve_type_id(other, ctx)?)),
    }
}

pub(super) fn resolve_named_or_helper(
    id: u64,
    ctx: &mut BuildCtx,
) -> Result<TypeIdentifier, ParseError> {
    if let Some(h) = ctx.resolved_named.get(&id) {
        return Ok(TypeIdentifier::Minimal(*h));
    }
    if ctx.building.len() >= MAX_NAMED_RESOLUTION_DEPTH {
        return Err(ParseError::InvalidFormat);
    }
    if !ctx.building.insert(id) {
        // Reference cycle (covers both named-type chains and anonymous
        // collection-helper chains, since both go through this guard).
        return Err(ParseError::InvalidFormat);
    }
    let result = resolve_named_or_helper_inner(id, ctx);
    ctx.building.remove(&id);
    result
}

// @audit-ok: kind dispatch (3 helper arms + 4 named-type arms sharing one
// body), mirrors the RawElement variant set 1:1.
pub(super) fn resolve_named_or_helper_inner(
    id: u64,
    ctx: &mut BuildCtx,
) -> Result<TypeIdentifier, ParseError> {
    let elem = ctx.library.get(&id).ok_or(ParseError::InvalidFormat)?;
    match elem {
        RawElement::Array {
            element_type,
            bounds,
        } => {
            let element_type = *element_type;
            let bounds = bounds.clone();
            let element_id = resolve_type_id(&element_type, ctx)?;
            Ok(build_plain_array(&bounds, element_id))
        }
        RawElement::Sequence {
            element_type,
            bound,
        } => {
            let element_type = *element_type;
            let bound = *bound;
            let element_id = resolve_type_id(&element_type, ctx)?;
            Ok(build_plain_sequence(bound, element_id))
        }
        RawElement::StringColl { char_kind, bound } => {
            let is_wide = matches!(char_kind, RawTypeId::Primitive(13));
            let bound = *bound;
            Ok(if is_wide {
                TypeIdentifier::wstring(bound)
            } else {
                TypeIdentifier::string(bound)
            })
        }
        RawElement::Struct { .. }
        | RawElement::Union { .. }
        | RawElement::Enum { .. }
        | RawElement::Alias { .. } => {
            let complete = build_complete_type_object(elem, ctx)?;
            let hash = minimal_hash_of(&complete)?;
            ctx.resolved_named.insert(id, hash);
            ctx.dependents.entry(hash).or_insert(complete);
            Ok(TypeIdentifier::Minimal(hash))
        }
    }
}

/// Compute the Minimal `EquivalenceHash` of a `CompleteTypeObject`, via the
/// same Complete-to-Minimal conversion + hash pipeline used elsewhere in
/// this codebase for local (self) types
/// (`crate::dynamic::complete_to_minimal_type_object` +
/// `MinimalTypeObject::compute_equivalence_hash`) so a v1-decoded
/// dependent's hash is computed exactly the same way as any other type's,
/// and resolves through the same `SnapshotResolver` store.
///
/// `complete_to_minimal_type_object` lives behind the
/// `xtypes-structural-assignability` feature (the same feature that gates
/// the matcher's type store this decoder's dependents feed into). With the
/// feature off, a member referencing a named type cannot be represented;
/// this degrades to a decode error for that ONE type (the caller falls
/// back to permissive name matching) rather than failing to compile or
/// silently producing a wrong structural shape.
#[cfg(feature = "xtypes-structural-assignability")]
pub(super) fn minimal_hash_of(obj: &CompleteTypeObject) -> Result<EquivalenceHash, ParseError> {
    let minimal =
        crate::dynamic::complete_to_minimal_type_object(obj).ok_or(ParseError::InvalidFormat)?;
    minimal
        .compute_equivalence_hash()
        .map_err(|_| ParseError::InvalidFormat)
}

#[cfg(not(feature = "xtypes-structural-assignability"))]
pub(super) fn minimal_hash_of(_obj: &CompleteTypeObject) -> Result<EquivalenceHash, ParseError> {
    Err(ParseError::InvalidFormat)
}

pub(super) fn build_plain_array(
    bounds: &[u32],
    element_identifier: TypeIdentifier,
) -> TypeIdentifier {
    let header = PlainCollectionHeader {
        equiv_kind: EquivalenceKind::Complete,
        element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
    };
    let small: Option<Vec<u8>> = bounds.iter().map(|&b| u8::try_from(b).ok()).collect();
    match small {
        Some(array_bound_seq) => TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
            header,
            array_bound_seq,
            element_identifier: Box::new(element_identifier),
        }),
        None => TypeIdentifier::PlainArrayLarge(PlainArrayLElemDefn {
            header,
            array_bound_seq: bounds.to_vec(),
            element_identifier: Box::new(element_identifier),
        }),
    }
}

/// The bound RTI Connext writes in a legacy v1 TypeObject for an unbounded
/// IDL `sequence<T>`: the largest signed 32-bit value, where the XTypes
/// TypeObject writes 0. It is read as 0, so the decoded identifier is the
/// one a local type declares for the same IDL.
const V1_UNBOUNDED_SEQUENCE_BOUND: u32 = 0x7FFF_FFFF;

pub(super) fn build_plain_sequence(
    bound: u32,
    element_identifier: TypeIdentifier,
) -> TypeIdentifier {
    let header = PlainCollectionHeader {
        equiv_kind: EquivalenceKind::Complete,
        element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
    };
    let bound = if bound == V1_UNBOUNDED_SEQUENCE_BOUND {
        0
    } else {
        bound
    };
    match u8::try_from(bound) {
        Ok(b) => TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header,
            bound: b,
            element_identifier: Box::new(element_identifier),
        }),
        Err(_) => TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
            header,
            bound,
            element_identifier: Box::new(element_identifier),
        }),
    }
}

pub(super) fn build_complete_type_object(
    elem: &RawElement,
    ctx: &mut BuildCtx,
) -> Result<CompleteTypeObject, ParseError> {
    match elem {
        RawElement::Struct {
            flags,
            name,
            base_type,
            members,
        } => Ok(CompleteTypeObject::Struct(build_struct(
            name.clone(),
            *flags,
            base_type,
            members,
            ctx,
        )?)),
        RawElement::Union {
            flags,
            name,
            members,
        } => Ok(CompleteTypeObject::Union(build_union(
            name.clone(),
            *flags,
            members,
            ctx,
        )?)),
        RawElement::Enum {
            name,
            bit_bound,
            literals,
        } => Ok(CompleteTypeObject::Enumerated(build_enum(
            name.clone(),
            *bit_bound,
            literals,
        ))),
        RawElement::Alias { name, base_type } => Ok(CompleteTypeObject::Alias(build_alias(
            name.clone(),
            base_type,
            ctx,
        )?)),
        // Anonymous collection helpers are never routed here (they're
        // handled directly in `resolve_named_or_helper_inner`); kept for
        // exhaustiveness.
        RawElement::Array { .. } | RawElement::Sequence { .. } | RawElement::StringColl { .. } => {
            Err(ParseError::InvalidFormat)
        }
    }
}

pub(super) fn build_struct(
    name: String,
    flags: u16,
    base_type: &RawTypeId,
    members: &[RawMember],
    ctx: &mut BuildCtx,
) -> Result<CompleteStructType, ParseError> {
    let base = resolve_optional_base(base_type, ctx)?;
    let mut member_seq = Vec::with_capacity(members.len());
    for m in members {
        let member_type_id = resolve_type_id(&m.type_id, ctx)?;
        member_seq.push(CompleteStructMember {
            common: CommonStructMember {
                member_id: m.member_id,
                member_flags: map_member_flags(m.flags),
                member_type_id,
            },
            detail: CompleteMemberDetail::new(m.name.clone()),
        });
    }
    Ok(CompleteStructType {
        struct_flags: map_struct_flags(flags),
        header: CompleteStructHeader {
            base_type: base,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq,
    })
}

pub(super) fn build_union(
    name: String,
    flags: u16,
    members: &[RawMember],
    ctx: &mut BuildCtx,
) -> Result<CompleteUnionType, ParseError> {
    let (disc_member, case_members) = members.split_first().ok_or(ParseError::InvalidFormat)?;
    let discriminator = resolve_type_id(&disc_member.type_id, ctx)?;
    let discriminator_flags = map_member_flags(disc_member.flags);

    let mut member_seq = Vec::with_capacity(case_members.len());
    for m in case_members {
        let member_type_id = resolve_type_id(&m.type_id, ctx)?;
        member_seq.push(CompleteUnionMember {
            common: CommonUnionMember {
                member_id: m.member_id,
                member_flags: map_member_flags(m.flags),
                member_type_id,
                label_seq: m.labels.clone(),
            },
            detail: CompleteMemberDetail::new(m.name.clone()),
        });
    }

    // Wire convention (coredx-conformant, verified on the wire, same as
    // the CDR2 union TypeObject decoder in `xtypes::cdr2::unions`): a @key
    // discriminator is flagged on the discriminator's OWN member entry only;
    // branch/case members are never key-flagged on the wire. Re-establish
    // the HDDS-internal convention (IS_KEY mirrored onto every member) that
    // `is_union_assignable`'s key-agreement rule (matcher/types.rs) inspects
    // via `member_seq`, not `discriminator_flags` -- without this, a v1
    // decoded key-discriminated union is indistinguishable from a non-keyed
    // one to that check, and a genuinely INCONSISTENT_TOPIC pairing (e.g.
    // OMG union_uint32_one_key) is wrongly accepted as compatible.
    if discriminator_flags.contains(MemberFlag::IS_KEY) {
        for m in &mut member_seq {
            m.common.member_flags = MemberFlag(m.common.member_flags.0 | MemberFlag::IS_KEY.0);
        }
    }

    Ok(CompleteUnionType {
        union_flags: map_union_flags(flags),
        header: CompleteUnionHeader {
            discriminator,
            discriminator_flags,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq,
    })
}

/// The wire's enum literal list carries no per-literal "is default" flag;
/// per OMG IDL enum default semantics (also documented on
/// `EnumeratedLiteralFlag::IS_DEFAULT`) the default is the first literal in
/// declaration order.
pub(super) fn build_enum(
    name: String,
    bit_bound_raw: u32,
    literals: &[RawEnumLiteral],
) -> CompleteEnumeratedType {
    let bit_bound = i16::try_from(bit_bound_raw).unwrap_or(32);
    let literal_seq = literals
        .iter()
        .enumerate()
        .map(|(i, lit)| CompleteEnumeratedLiteral {
            common: CommonEnumeratedLiteral {
                value: lit.value,
                flags: if i == 0 {
                    EnumeratedLiteralFlag::IS_DEFAULT
                } else {
                    EnumeratedLiteralFlag::empty()
                },
            },
            detail: CompleteMemberDetail::new(lit.name.clone()),
        })
        .collect();
    CompleteEnumeratedType {
        // v1 carries no enum extensibility; APPENDABLE is the default every
        // other enum builder in the crate declares (DYNAMIC_ENUM_FLAGS).
        enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
        header: CompleteEnumeratedHeader {
            bit_bound,
            detail: CompleteTypeDetail::new(name),
        },
        literal_seq,
    }
}

pub(super) fn build_alias(
    name: String,
    base_type: &RawTypeId,
    ctx: &mut BuildCtx,
) -> Result<CompleteAliasType, ParseError> {
    let related_type = resolve_type_id(base_type, ctx)?;
    Ok(CompleteAliasType {
        alias_flags: crate::xtypes::AliasTypeFlag::empty(),
        header: CompleteAliasHeader {
            detail: CompleteTypeDetail::new(name),
        },
        body: CompleteAliasBody {
            common: CommonAliasBody {
                related_flags: crate::xtypes::TypeRelationFlag::empty(),
                related_type,
            },
            ann_builtin: None,
            ann_custom: None,
        },
    })
}
