// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! V1-projection equivalence: the soundness gate for substituting a
//! locally-registered `CompleteTypeObject` in place of one reconstructed
//! from a lossy legacy TypeObject v1 payload.
//!
//! A same-QUALIFIED-name match alone is NOT sufficient to substitute: two
//! participants can legitimately (or maliciously) register different types
//! under the same name, and substituting the local type for a structurally
//! different remote one silently mis-deserializes that remote's data
//! (proven live: remote `{ float64 a }` published as `Test::adv_foo`,
//! local `{ int32 a }` subscribed under the same name -- name-triggered
//! substitution matched the pair and decoded float64 bytes as int32).
//! Substitution is therefore allowed ONLY when the local object is
//! structurally EQUAL to the decoded object under the v1 lossiness
//! relation defined here: exact equality everywhere, relaxed exclusively
//! on the axes the v1 wire format PROVABLY cannot represent.

use std::collections::HashMap;

use crate::xtypes::type_object::{
    AppliedBuiltinMemberAnnotations, CompleteAliasType, CompleteEnumeratedType,
    CompleteMemberDetail, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
    CompleteUnionType, TypeIdentifier,
};
use crate::xtypes::{EquivalenceHash, MemberFlag, TypeKind};

/// Resolver for hash-referenced dependents on BOTH sides of the
/// comparison: the local side's nested named types and the decoded side's
/// v1-computed dependents are both registered in the participant type
/// store, keyed by Minimal `EquivalenceHash`.
pub(crate) type DependentResolver<'a> = dyn Fn(&EquivalenceHash) -> Option<CompleteTypeObject> + 'a;

/// Recursion cap for the dependent graph walk. Deep enough for any real
/// type tree; cycles (impossible on the decoded side, which rejects them
/// at decode time, but constructible on the local side) terminate here
/// with `false` -- the fail-safe direction.
const MAX_EQ_DEPTH: usize = 32;

/// Member-flag bits the v1 wire CAN represent (per the member property
/// parse in `flatten.rs`: bit0 = key, bit1 = optional, bit2 = shareable /
/// external, bit3 = union default). These MUST be equal.
const MEMBER_FLAG_STRICT_MASK: u16 = MemberFlag::IS_KEY.0
    | MemberFlag::IS_OPTIONAL.0
    | MemberFlag::IS_EXTERNAL.0
    | MemberFlag::IS_DEFAULT.0;

/// Type-flag bits the v1 wire CAN represent (per `map_struct_flags` /
/// `map_union_flags`: bit0 = FINAL, bit1 = MUTABLE, bit2 = NESTED, and
/// APPENDABLE = neither extensibility bit, an injective 3-state encoding,
/// not a collapse -- both vendors' captures carry bit0 for FINAL types).
/// These MUST be equal. `IS_AUTOID_HASH` (0x10) is intentionally outside
/// the mask: v1 has no such bit, and the RESULTING member ids are compared
/// strictly anyway, which catches any real divergence the flag stands for.
const TYPE_FLAG_STRICT_MASK: u16 = 0x0001 | 0x0002 | 0x0004 | 0x0008;

/// Structural equality between a locally-registered `CompleteTypeObject`
/// and one decoded from a legacy TypeObject v1 payload, under the v1
/// lossiness relation. `true` means the local object is a faithful
/// stand-in for what the peer actually declared, so substituting it is
/// sound; `false` means keep the decoded object authoritative.
///
/// # The 8-bit ambiguity policy (field evidence)
///
/// RTI Connext 7.7.0 collapses IDL `byte`, `uint8` AND `int8` to the
/// single v1 kind BYTE (2) on the wire. This is capture-proven
/// (`Test::int32x10` / suite vectors) and corroborated by the official
/// interop matrix: Connext MATCHES across that ambiguity itself -- it
/// fails the `struct_byte_int8` / `struct_byte_uint8` NEGATIVES as
/// false-accepts even in its own connext-vs-connext cell, because the v1
/// format simply cannot distinguish the three. CoreDX 6.14.1, by
/// contrast, PRESERVES the distinction through vendor-extension TypeId
/// kinds 24 (int8) and 25 (uint8), which this decoder maps faithfully to
/// `TK_INT8` / `TK_UINT8`.
///
/// The tolerance is therefore ASYMMETRIC and direction-aware: a DECODED
/// `TK_BYTE` (the ambiguous collapse) is accepted against a local `byte`,
/// `int8` or `uint8` -- the local type's own v1 projection is exactly the
/// byte kind that was received. A decoded `TK_INT8` / `TK_UINT8` (a
/// vendor that CAN distinguish, and did) must match the local kind
/// exactly; `int8`-vs-`uint8` under a distinguishing vendor is a real
/// type mismatch and is rejected.
///
/// # Lossy-axis table (tolerate vs require), derived from the v1 grammar
/// implemented in `wire.rs` / `flatten.rs`:
///
/// | Axis                          | v1 representable?           | Policy    |
/// |-------------------------------|-----------------------------|-----------|
/// | 8-bit integer kinds           | RTI: no (BYTE collapse);    | tolerate  |
/// |                               | CoreDX: yes (24/25)         | (asym.)   |
/// | boolean vs byte               | yes (1 vs 2)                | require   |
/// | char8 / wide char             | yes (12 / 13)               | require   |
/// | other primitive kinds         | yes (3..=11)                | require   |
/// | member NAMES                  | yes (CDR string)            | require   |
/// | type NAMES (qualified)        | yes (module nesting / flat) | require   |
/// | member IDS (struct AND union) | yes (u32 on the wire)       | require   |
/// | member ORDER                  | yes (declaration order)     | require   |
/// | member COUNT                  | yes                         | require   |
/// | extensibility (F/A/M)         | yes (injective 3-state)     | require   |
/// | NESTED type flag              | yes (bit2)                  | require   |
/// | AUTOID_HASH type flag         | no (ids strict instead)     | tolerate  |
/// | @key / @optional / @external  | yes (member bits 0-2)       | require   |
/// | union default-case flag       | yes (member bit 3)          | require   |
/// | union case labels             | yes (i32 list)              | require   |
/// | union discriminator type      | yes (TypeId)                | require   |
/// | try-construct kind            | NO (no bits; decoder        | tolerate  |
/// |                               | defaults TRY_CONSTRUCT1)    |           |
/// | must-understand               | NO (no bit)                 | tolerate  |
/// | string/seq bounds, array dims | yes (u32)                   | require   |
/// | enum bit bound                | yes (u32 bound)             | require   |
/// | enum literal values/names     | yes                         | require   |
/// | enum default-literal flag     | NO (synthesized: first      | tolerate  |
/// |                               | literal, both conventions)  |           |
/// | collection header equiv_kind  | NO (encoding detail of the  | tolerate  |
/// |  / element flags / shared     | reference, decoder-chosen;  |           |
/// |                               | no data-layout effect)      |           |
/// | struct base type              | yes (NO_TYPE or ref)        | require   |
/// | annotations (any, each side)  | NOT modeled by this decoder | REFUSE    |
/// | maps, bitmask/bitset tops,    | NOT produced by decoder     | REFUSE    |
/// |  Complete/SCC hash refs       |                             |           |
///
/// FAIL-SAFE PRINCIPLE: anything this function does not explicitly model
/// compares as NOT equivalent (no substitution; the matcher then judges
/// the decoded object as-is). Under-modeling may cost interop score,
/// never soundness.
#[cfg(any(test, feature = "xtypes-structural-assignability"))]
pub(crate) fn v1_projection_equivalent(
    local: &CompleteTypeObject,
    decoded: &CompleteTypeObject,
    resolve: &DependentResolver<'_>,
) -> bool {
    cto_equivalent(local, decoded, resolve, 0)
}

#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn cto_equivalent(
    local: &CompleteTypeObject,
    decoded: &CompleteTypeObject,
    resolve: &DependentResolver<'_>,
    depth: usize,
) -> bool {
    if depth > MAX_EQ_DEPTH {
        return false;
    }
    match (local, decoded) {
        (CompleteTypeObject::Struct(l), CompleteTypeObject::Struct(d)) => {
            struct_equivalent(l, d, resolve, depth)
        }
        (CompleteTypeObject::Union(l), CompleteTypeObject::Union(d)) => {
            union_equivalent(l, d, resolve, depth)
        }
        (CompleteTypeObject::Enumerated(l), CompleteTypeObject::Enumerated(d)) => {
            enum_equivalent(l, d)
        }
        (CompleteTypeObject::Alias(l), CompleteTypeObject::Alias(d)) => {
            alias_equivalent(l, d, resolve, depth)
        }
        // Fail-safe: the v1 decoder only produces the four kinds above;
        // any other pairing (including matching non-decoder kinds on both
        // sides) is unmodeled and must not enable substitution.
        _ => false,
    }
}

/// Type detail: qualified name strict; any annotation payload on EITHER
/// side refuses (the decoder never surfaces v1 annotation usage, so it
/// cannot be compared -- fail-safe).
#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn type_detail_equivalent(l: &CompleteTypeDetail, d: &CompleteTypeDetail) -> bool {
    l.type_name == d.type_name
        && l.ann_builtin.is_none()
        && d.ann_builtin.is_none()
        && l.ann_custom.is_none()
        && d.ann_custom.is_none()
}

/// Member detail: name strict; annotations refuse (same rationale as
/// [`type_detail_equivalent`]).
#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn member_detail_equivalent(l: &CompleteMemberDetail, d: &CompleteMemberDetail) -> bool {
    l.name == d.name
        && only_hash_id(l.ann_builtin.as_ref())
        && d.ann_builtin.is_none()
        && l.ann_custom.is_none()
        && d.ann_custom.is_none()
}

/// A local member's builtin annotations are tolerated when `@hashid` is the
/// only one: v1 has no annotation field, but the one effect of `@hashid` is
/// the member id, which v1 carries and `struct_equivalent` compares
/// strictly. `@unit`, `@min` and `@max` still refuse.
#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn only_hash_id(ann: Option<&AppliedBuiltinMemberAnnotations>) -> bool {
    ann.is_none_or(|a| a.unit.is_none() && a.min.is_none() && a.max.is_none())
}

#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn member_flags_equivalent(l: MemberFlag, d: MemberFlag) -> bool {
    (l.0 & MEMBER_FLAG_STRICT_MASK) == (d.0 & MEMBER_FLAG_STRICT_MASK)
}

#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn type_flags_equivalent(l: u16, d: u16) -> bool {
    (l & TYPE_FLAG_STRICT_MASK) == (d & TYPE_FLAG_STRICT_MASK)
}

/// The asymmetric 8-bit rule (see the module-level policy paragraph):
/// a decoded BYTE tolerates any local 8-bit integer kind; a decoded
/// INT8/UINT8 (CoreDX faithful kinds) requires exact equality.
#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn primitive_equivalent(local: TypeKind, decoded: TypeKind) -> bool {
    local == decoded
        || (decoded == TypeKind::TK_BYTE
            && matches!(
                local,
                TypeKind::TK_BYTE | TypeKind::TK_INT8 | TypeKind::TK_UINT8
            ))
}

#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn tid_equivalent(
    local: &TypeIdentifier,
    decoded: &TypeIdentifier,
    resolve: &DependentResolver<'_>,
    depth: usize,
) -> bool {
    if depth > MAX_EQ_DEPTH {
        return false;
    }
    match (local, decoded) {
        (TypeIdentifier::Primitive(l), TypeIdentifier::Primitive(d)) => {
            primitive_equivalent(*l, *d)
        }
        // Bounds are faithfully represented in v1 (u32 on the wire):
        // strict, including the Small/Large split (both sides derive it
        // from the same <=255 rule).
        (TypeIdentifier::StringSmall { bound: l }, TypeIdentifier::StringSmall { bound: d }) => {
            l == d
        }
        (TypeIdentifier::StringLarge { bound: l }, TypeIdentifier::StringLarge { bound: d }) => {
            l == d
        }
        (TypeIdentifier::WStringSmall { bound: l }, TypeIdentifier::WStringSmall { bound: d }) => {
            l == d
        }
        (TypeIdentifier::WStringLarge { bound: l }, TypeIdentifier::WStringLarge { bound: d }) => {
            l == d
        }
        // Plain collections: bound/dimensions strict, element recursive.
        // The PlainCollectionHeader (equiv_kind + element flags) is a
        // decoder-chosen encoding detail with no data-layout effect and no
        // v1 wire representation beyond the unmodeled `element_shared`
        // byte: tolerated (see the axis table).
        (TypeIdentifier::PlainSequenceSmall(l), TypeIdentifier::PlainSequenceSmall(d)) => {
            l.bound == d.bound
                && tid_equivalent(
                    &l.element_identifier,
                    &d.element_identifier,
                    resolve,
                    depth + 1,
                )
        }
        (TypeIdentifier::PlainSequenceLarge(l), TypeIdentifier::PlainSequenceLarge(d)) => {
            l.bound == d.bound
                && tid_equivalent(
                    &l.element_identifier,
                    &d.element_identifier,
                    resolve,
                    depth + 1,
                )
        }
        (TypeIdentifier::PlainArraySmall(l), TypeIdentifier::PlainArraySmall(d)) => {
            l.array_bound_seq == d.array_bound_seq
                && tid_equivalent(
                    &l.element_identifier,
                    &d.element_identifier,
                    resolve,
                    depth + 1,
                )
        }
        (TypeIdentifier::PlainArrayLarge(l), TypeIdentifier::PlainArrayLarge(d)) => {
            l.array_bound_seq == d.array_bound_seq
                && tid_equivalent(
                    &l.element_identifier,
                    &d.element_identifier,
                    resolve,
                    depth + 1,
                )
        }
        // Named dependents: equal hashes are trivially equivalent; unequal
        // hashes may still be the SAME declared type whose 8-bit members
        // collapsed on the decoded side, so resolve BOTH and recurse to
        // full depth. Either side unresolvable -> fail-safe false.
        (TypeIdentifier::Minimal(lh), TypeIdentifier::Minimal(dh)) => {
            if lh == dh {
                return true;
            }
            match (resolve(lh), resolve(dh)) {
                (Some(lo), Some(dobj)) => cto_equivalent(&lo, &dobj, resolve, depth + 1),
                _ => false,
            }
        }
        // Fail-safe: maps, Complete/StronglyConnected references, and any
        // cross-variant pairing are unmodeled -> not equivalent.
        _ => false,
    }
}

#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn struct_equivalent(
    l: &CompleteStructType,
    d: &CompleteStructType,
    resolve: &DependentResolver<'_>,
    depth: usize,
) -> bool {
    if !type_flags_equivalent(l.struct_flags.0, d.struct_flags.0) {
        return false;
    }
    if !type_detail_equivalent(&l.header.detail, &d.header.detail) {
        return false;
    }
    let base_ok = match (&l.header.base_type, &d.header.base_type) {
        (None, None) => true,
        (Some(lb), Some(db)) => tid_equivalent(lb, db, resolve, depth + 1),
        _ => false,
    };
    if !base_ok {
        return false;
    }
    if l.member_seq.len() != d.member_seq.len() {
        return false;
    }
    l.member_seq
        .iter()
        .zip(d.member_seq.iter())
        .all(|(lm, dm)| {
            lm.common.member_id == dm.common.member_id
                && member_flags_equivalent(lm.common.member_flags, dm.common.member_flags)
                && member_detail_equivalent(&lm.detail, &dm.detail)
                && tid_equivalent(
                    &lm.common.member_type_id,
                    &dm.common.member_type_id,
                    resolve,
                    depth + 1,
                )
        })
}

#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn union_equivalent(
    l: &CompleteUnionType,
    d: &CompleteUnionType,
    resolve: &DependentResolver<'_>,
    depth: usize,
) -> bool {
    if !type_flags_equivalent(l.union_flags.0, d.union_flags.0) {
        return false;
    }
    if !type_detail_equivalent(&l.header.detail, &d.header.detail) {
        return false;
    }
    if !tid_equivalent(
        &l.header.discriminator,
        &d.header.discriminator,
        resolve,
        depth + 1,
    ) {
        return false;
    }
    // Discriminator flags: strict on the v1-representable bits (the key
    // bit matters for key-discriminator unions); the local convention of
    // `MemberFlag::empty()` meaning "derive the TRY_CONSTRUCT1 |
    // IS_MUST_UNDERSTAND default" compares equal under the mask, as both
    // tolerated bits are outside it.
    if !member_flags_equivalent(l.header.discriminator_flags, d.header.discriminator_flags) {
        return false;
    }
    if l.member_seq.len() != d.member_seq.len() {
        return false;
    }
    l.member_seq
        .iter()
        .zip(d.member_seq.iter())
        .all(|(lm, dm)| {
            lm.common.member_id == dm.common.member_id
                && lm.common.label_seq == dm.common.label_seq
                && member_flags_equivalent(lm.common.member_flags, dm.common.member_flags)
                && member_detail_equivalent(&lm.detail, &dm.detail)
                && tid_equivalent(
                    &lm.common.member_type_id,
                    &dm.common.member_type_id,
                    resolve,
                    depth + 1,
                )
        })
}

#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn enum_equivalent(l: &CompleteEnumeratedType, d: &CompleteEnumeratedType) -> bool {
    if l.header.bit_bound != d.header.bit_bound {
        return false;
    }
    if !type_detail_equivalent(&l.header.detail, &d.header.detail) {
        return false;
    }
    if l.literal_seq.len() != d.literal_seq.len() {
        return false;
    }
    // Literal flags are tolerated: v1 carries none, and the decoder
    // synthesizes IS_DEFAULT on the first literal exactly like the local
    // registration convention (declaration-order default).
    l.literal_seq
        .iter()
        .zip(d.literal_seq.iter())
        .all(|(ll, dl)| {
            ll.common.value == dl.common.value && member_detail_equivalent(&ll.detail, &dl.detail)
        })
}

#[cfg(any(test, feature = "xtypes-structural-assignability"))]
fn alias_equivalent(
    l: &CompleteAliasType,
    d: &CompleteAliasType,
    resolve: &DependentResolver<'_>,
    depth: usize,
) -> bool {
    // Alias/relation flag words: both sides are empty by convention (the
    // decoder emits empty; v1 carries no alias flags). Strict comparison
    // keeps the fail-safe direction if a local ever carries one.
    l.alias_flags == d.alias_flags
        && l.body.common.related_flags == d.body.common.related_flags
        && type_detail_equivalent(&l.header.detail, &d.header.detail)
        && tid_equivalent(
            &l.body.common.related_type,
            &d.body.common.related_type,
            resolve,
            depth + 1,
        )
}

/// Convenience resolver over a plain map (tests and callers that hold a
/// snapshot rather than a live registry).
#[cfg(any(test, feature = "xtypes-structural-assignability"))]
#[allow(dead_code)]
pub(crate) fn map_resolver(
    map: &HashMap<EquivalenceHash, CompleteTypeObject>,
) -> impl Fn(&EquivalenceHash) -> Option<CompleteTypeObject> + '_ {
    move |h| map.get(h).cloned()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::xtypes::type_object::legacy_v1::decode_type_object_v1;
    use crate::xtypes::type_object::legacy_v1::test_vectors::{
        COREDX_STRUCT_INT8_V1, COREDX_STRUCT_UINT8_V1,
    };
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, StructTypeFlag,
    };

    fn no_deps() -> impl Fn(&EquivalenceHash) -> Option<CompleteTypeObject> {
        |_h| None
    }

    fn one_member_struct(type_name: &str, member: &str, kind: TypeKind) -> CompleteTypeObject {
        one_member_struct_tid(type_name, member, TypeIdentifier::Primitive(kind))
    }

    fn one_member_struct_tid(
        type_name: &str,
        member: &str,
        tid: TypeIdentifier,
    ) -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(type_name),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::TRY_CONSTRUCT1,
                    member_type_id: tid,
                },
                detail: CompleteMemberDetail::new(member),
            }],
        })
    }

    /// The live adversarial case: same qualified name, different member
    /// type (local int32 vs remote float64). MUST NOT be equivalent -- a
    /// substitution here silently decodes remote float64 data as int32.
    #[test]
    fn adversarial_same_name_different_member_type_not_equivalent() {
        let local = one_member_struct("Test::adv_foo", "a", TypeKind::TK_INT32);
        let decoded = one_member_struct("Test::adv_foo", "a", TypeKind::TK_FLOAT64);
        assert!(!v1_projection_equivalent(&local, &decoded, &no_deps()));
    }

    /// The legitimate RTI collapse: a decoded BYTE member is equivalent to
    /// a local byte, uint8 OR int8 member (the local type's v1 projection
    /// is exactly the BYTE that was received).
    #[test]
    fn rti_byte_collapse_tolerated_for_all_three_locals() {
        let decoded = one_member_struct("Test::struct_primitive_uint8", "x1", TypeKind::TK_BYTE);
        for local_kind in [TypeKind::TK_BYTE, TypeKind::TK_UINT8, TypeKind::TK_INT8] {
            let local = one_member_struct("Test::struct_primitive_uint8", "x1", local_kind);
            assert!(
                v1_projection_equivalent(&local, &decoded, &no_deps()),
                "decoded BYTE must tolerate local {local_kind:?}"
            );
        }
    }

    /// The asymmetry, pinned against the REAL CoreDX captures: a vendor
    /// that CAN distinguish int8/uint8 (kinds 24/25) and did must match
    /// the local kind exactly. int8-received vs uint8-local is a real
    /// mismatch and must refuse.
    #[test]
    fn coredx_faithful_kinds_require_exact_match() {
        let decoded_int8 = decode_type_object_v1(&COREDX_STRUCT_INT8_V1)
            .expect("captured coredx int8 vector must decode")
            .root;
        let local_int8 = one_member_struct("Test::struct_primitive_int8", "x1", TypeKind::TK_INT8);
        let local_uint8_same_name =
            one_member_struct("Test::struct_primitive_int8", "x1", TypeKind::TK_UINT8);
        assert!(v1_projection_equivalent(
            &local_int8,
            &decoded_int8,
            &no_deps()
        ));
        assert!(
            !v1_projection_equivalent(&local_uint8_same_name, &decoded_int8, &no_deps()),
            "decoded TK_INT8 (CoreDX kind 24) must NOT tolerate a local uint8"
        );

        let decoded_uint8 = decode_type_object_v1(&COREDX_STRUCT_UINT8_V1)
            .expect("captured coredx uint8 vector must decode")
            .root;
        let local_uint8 =
            one_member_struct("Test::struct_primitive_uint8", "x1", TypeKind::TK_UINT8);
        assert!(v1_projection_equivalent(
            &local_uint8,
            &decoded_uint8,
            &no_deps()
        ));
    }

    /// Nested named dependents recurse through the resolver: an 8-bit
    /// difference at depth 1 is tolerated under the class; a genuine
    /// int16-vs-int32 difference at depth 1 vetoes substitution.
    #[test]
    fn nested_dependents_recurse_with_class_tolerance() {
        let dep_local = one_member_struct("Test::Inner", "v", TypeKind::TK_UINT8);
        let dep_decoded = one_member_struct("Test::Inner", "v", TypeKind::TK_BYTE);
        let lh = EquivalenceHash::from_bytes([1u8; 14]);
        let dh = EquivalenceHash::from_bytes([2u8; 14]);
        let mut store: HashMap<EquivalenceHash, CompleteTypeObject> = HashMap::new();
        store.insert(lh, dep_local);
        store.insert(dh, dep_decoded);

        let local = one_member_struct_tid("Test::Outer", "b", TypeIdentifier::Minimal(lh));
        let decoded = one_member_struct_tid("Test::Outer", "b", TypeIdentifier::Minimal(dh));
        assert!(v1_projection_equivalent(
            &local,
            &decoded,
            &map_resolver(&store)
        ));

        // Same shape but the nested member genuinely differs: int16 vs int32.
        let mut store2 = store.clone();
        store2.insert(
            lh,
            one_member_struct("Test::Inner", "v", TypeKind::TK_INT16),
        );
        store2.insert(
            dh,
            one_member_struct("Test::Inner", "v", TypeKind::TK_INT32),
        );
        assert!(!v1_projection_equivalent(
            &local,
            &decoded,
            &map_resolver(&store2)
        ));

        // Unresolvable dependent (either side): fail-safe refuse.
        assert!(!v1_projection_equivalent(&local, &decoded, &no_deps()));
    }

    /// A local `@hashid` member (its Complete detail carries `hash_id`) stays a faithful stand-in for the v1 object a peer
    /// sent: v1 has no annotations, the id `@hashid` produced is compared.
    /// Any other builtin member annotation still refuses.
    #[test]
    fn a_local_hashid_annotation_alone_is_tolerated() {
        let decoded = one_member_struct("Test::T", "x2", TypeKind::TK_BYTE);
        let mut hashid = one_member_struct("Test::T", "x2", TypeKind::TK_BYTE);
        if let CompleteTypeObject::Struct(s) = &mut hashid {
            s.member_seq[0].detail.ann_builtin = Some(AppliedBuiltinMemberAnnotations {
                hash_id: Some("x1".to_string()),
                ..Default::default()
            });
        }
        assert!(v1_projection_equivalent(&hashid, &decoded, &no_deps()));

        let mut unit = hashid.clone();
        if let CompleteTypeObject::Struct(s) = &mut unit {
            if let Some(a) = s.member_seq[0].detail.ann_builtin.as_mut() {
                a.unit = Some("m".to_string());
            }
        }
        assert!(!v1_projection_equivalent(&unit, &decoded, &no_deps()));

        // The decoded side never carries annotations; one that did refuses.
        assert!(!v1_projection_equivalent(&decoded, &hashid, &no_deps()));
    }

    /// Axis spot checks: every v1-representable difference must refuse.
    #[test]
    fn representable_axes_refuse_on_difference() {
        let base = one_member_struct("Test::T", "x1", TypeKind::TK_BYTE);

        // Extensibility differs (FINAL vs APPENDABLE).
        let mut appendable = one_member_struct("Test::T", "x1", TypeKind::TK_BYTE);
        if let CompleteTypeObject::Struct(s) = &mut appendable {
            s.struct_flags = StructTypeFlag::IS_APPENDABLE;
        }
        assert!(!v1_projection_equivalent(&appendable, &base, &no_deps()));

        // Member name differs.
        let renamed = one_member_struct("Test::T", "x2", TypeKind::TK_BYTE);
        assert!(!v1_projection_equivalent(&renamed, &base, &no_deps()));

        // Qualified type name differs.
        let other_name = one_member_struct("Other::T", "x1", TypeKind::TK_BYTE);
        assert!(!v1_projection_equivalent(&other_name, &base, &no_deps()));

        // Member id differs.
        let mut other_id = one_member_struct("Test::T", "x1", TypeKind::TK_BYTE);
        if let CompleteTypeObject::Struct(s) = &mut other_id {
            s.member_seq[0].common.member_id = 1;
        }
        assert!(!v1_projection_equivalent(&other_id, &base, &no_deps()));

        // Key flag differs (v1 represents @key).
        let mut keyed = one_member_struct("Test::T", "x1", TypeKind::TK_BYTE);
        if let CompleteTypeObject::Struct(s) = &mut keyed {
            s.member_seq[0].common.member_flags =
                MemberFlag(MemberFlag::TRY_CONSTRUCT1.0 | MemberFlag::IS_KEY.0);
        }
        assert!(!v1_projection_equivalent(&keyed, &base, &no_deps()));

        // String bound differs.
        let s10 = one_member_struct_tid("Test::T", "x1", TypeIdentifier::StringSmall { bound: 10 });
        let s20 = one_member_struct_tid("Test::T", "x1", TypeIdentifier::StringSmall { bound: 20 });
        assert!(!v1_projection_equivalent(&s10, &s20, &no_deps()));

        // Annotations present on the local side: fail-safe refuse. A lone
        // @hashid is the exception (a_local_hashid_annotation_alone_is_tolerated):
        // its one effect, the member id, is compared above.
        let mut annotated = one_member_struct("Test::T", "x1", TypeKind::TK_BYTE);
        if let CompleteTypeObject::Struct(s) = &mut annotated {
            s.member_seq[0].detail.ann_builtin = Some(AppliedBuiltinMemberAnnotations {
                unit: Some("m".to_string()),
                ..Default::default()
            });
        }
        assert!(!v1_projection_equivalent(&annotated, &base, &no_deps()));

        // Tolerated axes stay tolerated: try-construct and must-understand
        // bits differ but everything else matches.
        let mut tc2_mu = one_member_struct("Test::T", "x1", TypeKind::TK_BYTE);
        if let CompleteTypeObject::Struct(s) = &mut tc2_mu {
            s.member_seq[0].common.member_flags =
                MemberFlag(MemberFlag::TRY_CONSTRUCT2.0 | MemberFlag::IS_MUST_UNDERSTAND.0);
        }
        assert!(v1_projection_equivalent(&tc2_mu, &base, &no_deps()));
    }
}
