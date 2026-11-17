// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Must-reject fence for the matcher's structural-assignability change.
//!
//! Guards against false positives when a planned change adds structural-
//! assignability fallback for nested complex-type references (dereference +
//! coerce instead of exact hash-equality).  Every test here asserts that the
//! pair is NOT assignable per XTypes v1.3.  The comment on each test cites
//! the spec clause and explains why the pair must stay rejected even after
//! the fix that adds structural deref.
//!
//! Entry points under test:
//!   - `Matcher::is_assignable_to`           (types.rs: is_assignable_to_with_policy)
//!   - `Matcher::is_type_compatible`         (types.rs: is_type_compatible, top-level)
//!   - `Matcher::is_type_compatible_with_policy`  (with custom TypeConsistencyEnforcement)
//!
//! The nested-type cases (2b, 4, 7) embed complex types as
//! `TypeIdentifier::Minimal(hash)` inside sequences/arrays, which is the
//! exact position where the upcoming fix adds structural-coerce fallback.
//! The hashes here are computed from *real* MinimalTypeObjects so the fence
//! remains valid if the fix gains a registry to dereference them.

use super::*;
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::xtypes::{
    CollectionElementFlag, CommonEnumeratedLiteral, CommonStructMember, CommonUnionMember,
    CompleteEnumeratedHeader, CompleteEnumeratedLiteral, CompleteEnumeratedType,
    CompleteMemberDetail, CompleteStructHeader, CompleteStructMember, CompleteStructType,
    CompleteTypeDetail, CompleteTypeObject, CompleteUnionHeader, CompleteUnionMember,
    CompleteUnionType, EnumeratedLiteralFlag, EquivalenceKind, MemberFlag, MinimalEnumeratedHeader,
    MinimalEnumeratedLiteral, MinimalEnumeratedType, MinimalMemberDetail, MinimalStructHeader,
    MinimalStructMember, MinimalStructType, MinimalTypeDetail, MinimalTypeObject,
    PlainArraySElemDefn, PlainCollectionHeader, PlainSequenceSElemDefn, StructTypeFlag,
    TypeIdentifier, UnionTypeFlag,
};

// =============================================================================
// Internal helpers
// =============================================================================

/// Policy that blocks widening but still allows ALLOW_TYPE_COERCION + ignore
/// bounds.  Used for case 1: sequence-element widening must be rejected when
/// prevent_type_widening=true per XTypes v1.3 sec. 7.6.3.4.
fn prevent_widening_policy() -> TypeConsistencyEnforcement {
    TypeConsistencyEnforcement {
        kind: 1, // ALLOW_TYPE_COERCION
        ignore_sequence_bounds: true,
        ignore_string_bounds: true,
        ignore_member_names: true,
        prevent_type_widening: true,
        force_type_validation: false,
    }
}

/// Unbounded PlainSequenceSmall wrapping `elem`.
fn seq_of(elem: TypeIdentifier) -> TypeIdentifier {
    TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        bound: 0,
        element_identifier: Box::new(elem),
    })
}

/// PlainArraySmall with given element and dimension bounds.
fn arr_of(elem: TypeIdentifier, bounds: Vec<u8>) -> TypeIdentifier {
    TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        array_bound_seq: bounds,
        element_identifier: Box::new(elem),
    })
}

/// APPENDABLE struct with a single member (id=0, name="data") of `member_type`.
fn appendable_one_member(type_name: &str, member_type: TypeIdentifier) -> CompleteTypeObject {
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(type_name),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: member_type,
            },
            detail: CompleteMemberDetail::new("data"),
        }],
    })
}

/// FINAL struct with the given `(member_id, TypeIdentifier, name)` members.
fn final_struct(type_name: &str, members: &[(u32, TypeIdentifier, &str)]) -> CompleteTypeObject {
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(type_name),
        },
        member_seq: members
            .iter()
            .map(|(id, ty, name)| CompleteStructMember {
                common: CommonStructMember {
                    member_id: *id,
                    member_flags: MemberFlag::empty(),
                    member_type_id: ty.clone(),
                },
                detail: CompleteMemberDetail::new(*name),
            })
            .collect(),
    })
}

/// CompleteTypeObject::Enumerated with `(value, name)` literals.
fn enum_complete(type_name: &str, bit_bound: i16, values: &[(i32, &str)]) -> CompleteTypeObject {
    CompleteTypeObject::Enumerated(CompleteEnumeratedType {
        enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
        header: CompleteEnumeratedHeader {
            bit_bound,
            detail: CompleteTypeDetail::new(type_name),
        },
        literal_seq: values
            .iter()
            .map(|(v, n)| CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: *v,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new(*n),
            })
            .collect(),
    })
}

/// Compute the `TypeIdentifier::Minimal(hash)` of an enum type with the given
/// `bit_bound` and `(value, literal_name)` pairs.
///
/// This is the TypeIdentifier that would appear in a struct member or
/// collection-element position for a reference to this enum (XTypes v1.3
/// sec. 7.3.4.3).  The hash is computed from the real MinimalEnumeratedType so
/// any registry-aware deref in the upcoming fix will resolve to the correct
/// underlying type.
fn minimal_enum_tid(bit_bound: i16, values: &[(i32, &str)]) -> TypeIdentifier {
    let minimal = MinimalTypeObject::Enumerated(MinimalEnumeratedType {
        enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
        header: MinimalEnumeratedHeader {
            bit_bound,
            detail: MinimalTypeDetail::new(),
        },
        literal_seq: values
            .iter()
            .map(|(val, name)| MinimalEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: *val,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: MinimalMemberDetail::from_name(name),
            })
            .collect(),
    });
    let hash = minimal
        .compute_equivalence_hash()
        .expect("must_reject_fence helper: enum hash must not fail");
    TypeIdentifier::Minimal(hash)
}

/// Compute the `TypeIdentifier::Minimal(hash)` of a FINAL struct type with
/// the given `(member_id, member_type, member_name)` members.
///
/// Used to embed a FINAL struct reference in a sequence- or array-element
/// position.  Hash is derived from the real MinimalStructType.
fn minimal_final_struct_tid(members: &[(u32, TypeIdentifier, &str)]) -> TypeIdentifier {
    let minimal = MinimalTypeObject::Struct(MinimalStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: MinimalStructHeader {
            base_type: None,
            detail: MinimalTypeDetail::new(),
        },
        member_seq: members
            .iter()
            .map(|(id, ty, name)| MinimalStructMember {
                common: CommonStructMember {
                    member_id: *id,
                    member_flags: MemberFlag::empty(),
                    member_type_id: ty.clone(),
                },
                detail: MinimalMemberDetail::from_name(name),
            })
            .collect(),
    });
    let hash = minimal
        .compute_equivalence_hash()
        .expect("must_reject_fence helper: struct hash must not fail");
    TypeIdentifier::Minimal(hash)
}

/// Compute the `TypeIdentifier::Minimal(hash)` of an APPENDABLE struct type
/// with a single member (id=0) of `member_type`.
fn minimal_appendable_one_member_tid(
    member_type: TypeIdentifier,
    member_name: &str,
) -> TypeIdentifier {
    let minimal = MinimalTypeObject::Struct(MinimalStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: MinimalStructHeader {
            base_type: None,
            detail: MinimalTypeDetail::new(),
        },
        member_seq: vec![MinimalStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: member_type,
            },
            detail: MinimalMemberDetail::from_name(member_name),
        }],
    });
    let hash = minimal
        .compute_equivalence_hash()
        .expect("must_reject_fence helper: appendable struct hash must not fail");
    TypeIdentifier::Minimal(hash)
}

/// Union (FINAL or APPENDABLE) with explicit `(discriminant_label, case_type)` cases.
fn build_union(
    ext: UnionTypeFlag,
    name: &str,
    cases: &[(i32, TypeIdentifier)],
) -> CompleteTypeObject {
    CompleteTypeObject::Union(CompleteUnionType {
        union_flags: ext,
        header: CompleteUnionHeader {
            discriminator: TypeIdentifier::TK_INT32,
            discriminator_flags: MemberFlag::empty(),
            detail: CompleteTypeDetail::new(name),
        },
        member_seq: cases
            .iter()
            .enumerate()
            .map(|(idx, (label, ty))| CompleteUnionMember {
                common: CommonUnionMember {
                    // 1-based auto ids: the discriminator consumes id 0
                    // (XTypes v1.3 Sec 7.2.2.4.4.3).
                    member_id: idx as u32 + 1,
                    member_flags: MemberFlag::empty(),
                    member_type_id: ty.clone(),
                    label_seq: vec![*label],
                },
                detail: CompleteMemberDetail::new(format!("case_{}", label)),
            })
            .collect(),
    })
}

// =============================================================================
// CASE 1 -- sequence<int16> vs sequence<int32> with prevent_type_widening=true
// =============================================================================

/// FENCE CASE 1: sequence element widening must be rejected when the policy
/// has prevent_type_widening=true.
///
/// XTypes v1.3 sec. 7.5.1.3 Table 3 defines allowed primitive widening chains.
/// sec. 7.6.3.4 allow the reader to restrict widening via prevent_type_widening.
/// The policy flows into `type_id_assignable` at the sequence-element level
/// (PlainSequenceSmall.element_identifier = Primitive(TK_INT16/TK_INT32)).
///
/// After the structural-deref fix: the policy must still flow down through
/// the sequence-element path; a correct fix will NOT relax this rejection.
/// A buggy fix that strips the policy before recursing into element types
/// would incorrectly accept this pair.
#[test]
fn fence_seq_elem_widening_blocked_with_prevent_widening() {
    let writer = appendable_one_member("SeqInt16Writer", seq_of(TypeIdentifier::TK_INT16));
    let reader = appendable_one_member("SeqInt32Reader", seq_of(TypeIdentifier::TK_INT32));
    let policy = prevent_widening_policy();
    assert!(
        !Matcher::is_type_compatible_with_policy(
            Some(&writer),
            Some(&reader),
            "SeqInt16Writer",
            "SeqInt32Reader",
            Some(&policy),
        ),
        "CASE 1: sequence<int16> -> sequence<int32> must be rejected when \
         prevent_type_widening=true (XTypes sec. 7.5.1.3 Table 3 + sec. 7.6.3.4)"
    );
}

// Reverse direction is also a violation (narrowing, always disallowed).
#[test]
fn fence_seq_elem_narrowing_always_blocked() {
    let writer = appendable_one_member("SeqInt32Writer", seq_of(TypeIdentifier::TK_INT32));
    let reader = appendable_one_member("SeqInt16Reader", seq_of(TypeIdentifier::TK_INT16));
    // Even with prevent_type_widening=false, narrowing is never allowed.
    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "CASE 1 (reverse): sequence<int32> -> sequence<int16> must be rejected \
         (narrowing is never allowed per XTypes sec. 7.5.1.3)"
    );
}

// =============================================================================
// CASE 2a -- enum with DISJOINT literal values (top-level, exercises is_enum_assignable)
// =============================================================================

/// FENCE CASE 2a: two enums with disjoint literal values -- incompatible.
///
/// XTypes v1.3 sec. 7.5.2.8: when ALLOW_TYPE_COERCION is in effect and the hashes
/// differ, is_enum_assignable is called; it requires (a) the same bit_bound and
/// (b) a non-empty intersection of literal *values*.  EnumA has values {10,20,30}
/// and EnumB has values {100,200,300}; the intersection is empty -> not assignable.
///
/// After the fix: the top-level enum path through is_type_compatible ALREADY
/// calls is_enum_assignable on hash-mismatch; the fix must not bypass this check
/// for enum types or widen the criteria (e.g. accept zero-intersection enums).
#[test]
fn fence_enum_disjoint_values_top_level_rejected() {
    let enum_a = enum_complete(
        "EnumA",
        32,
        &[(10, "A_TEN"), (20, "A_TWENTY"), (30, "A_THIRTY")],
    );
    let enum_b = enum_complete(
        "EnumB",
        32,
        &[
            (100, "B_HUNDRED"),
            (200, "B_TWO_HUNDRED"),
            (300, "B_THREE_HUNDRED"),
        ],
    );
    assert!(
        !Matcher::is_type_compatible(Some(&enum_a), Some(&enum_b), "EnumA", "EnumB"),
        "CASE 2a: CompleteEnumerated with disjoint literal values must be rejected \
         (XTypes sec. 7.5.2.8: non-empty literal-value intersection required)"
    );
}

/// FENCE CASE 2a companion: different bit_bound enums with otherwise matching values.
///
/// XTypes v1.3 sec. 7.5.2.8 requires identical bit_bound (on-wire integer width).
/// bit_bound=8 vs bit_bound=32 -- even if literal values overlap, incompatible.
#[test]
fn fence_enum_different_bit_bound_rejected() {
    let enum_8 = enum_complete("Enum8", 8, &[(0, "ZERO"), (1, "ONE")]);
    let enum_32 = enum_complete("Enum32", 32, &[(0, "ZERO"), (1, "ONE")]);
    assert!(
        !Matcher::is_type_compatible(Some(&enum_8), Some(&enum_32), "Enum8", "Enum32"),
        "CASE 2a (bit_bound): EnumA(bit=8) vs EnumB(bit=32) must be rejected \
         even when literal values match (XTypes sec. 7.5.2.8 requires same bit_bound)"
    );
}

// =============================================================================
// CASE 2b -- array[10] of enumA vs array[10] of enumB, NESTED via Minimal hash
// =============================================================================

/// FENCE CASE 2b: array elements typed as two different enums (nested Minimal
/// hash position) -- incompatible.
///
/// Struct members reference enum types via TypeIdentifier::Minimal(hash).
/// `type_id_assignable(Minimal(h_a), Minimal(h_b))` currently returns
/// `h_a == h_b`; since the enums have different literal sets, their Minimal
/// hashes differ -> false.
///
/// After the fix (structural deref): if the fix can resolve h_a and h_b to
/// their underlying enum TypeObjects and calls is_enum_assignable, the result
/// must still be false: EnumA values {10,20,30} intersect EnumB values {100,200} = {}.
/// A buggy fix that accepts any two hash-differing Minimal references in element
/// position would incorrectly return true here.
///
/// XTypes v1.3 sec. 7.5.2.8 + sec. 7.5.1.5 (array element must be assignable).
#[test]
fn fence_array_of_enum_nested_hash_disjoint_rejected() {
    // Compute actual Minimal hashes so a registry-aware deref in the fix can
    // resolve the correct underlying enum type and verify value disjointness.
    let tid_enum_a = minimal_enum_tid(32, &[(10, "A_TEN"), (20, "A_TWENTY"), (30, "A_THIRTY")]);
    let tid_enum_b = minimal_enum_tid(32, &[(100, "B_HUNDRED"), (200, "B_TWO_HUNDRED")]);

    let writer = appendable_one_member("ArrEnumAWriter", arr_of(tid_enum_a, vec![10]));
    let reader = appendable_one_member("ArrEnumBReader", arr_of(tid_enum_b, vec![10]));

    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "CASE 2b: array[10] of EnumA (values 10/20/30) vs array[10] of EnumB \
         (values 100/200) must be rejected: different Minimal hashes + disjoint \
         literal values (XTypes sec. 7.5.2.8 + sec. 7.5.1.5)"
    );
}

// =============================================================================
// CASE 3 -- array[10] vs array[20] of the same element type
// =============================================================================

/// FENCE CASE 3: arrays with the same element type but different dimension
/// bounds -- incompatible.
///
/// XTypes v1.3 sec. 7.5.1.5: arrays are NOT covariant in size; all dimension bounds
/// must match exactly.  This is invariant over any coerce/widen policy.
///
/// After the fix: array bound comparison is in `type_id_assignable` before any
/// structural-coerce fallback; the fix must not short-circuit this check.  A
/// buggy fix that checks element-type structural compatibility first and skips
/// the bounds check would incorrectly accept array[10] as assignable to array[20].
#[test]
fn fence_array_size_mismatch_rejected() {
    let writer = appendable_one_member("Arr10Writer", arr_of(TypeIdentifier::TK_INT32, vec![10]));
    let reader = appendable_one_member("Arr20Reader", arr_of(TypeIdentifier::TK_INT32, vec![20]));
    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "CASE 3: array[10]<int32> -> array[20]<int32> must be rejected \
         (XTypes sec. 7.5.1.5: array dimensions are invariant)"
    );
}

// Reverse direction still fails.
#[test]
fn fence_array_size_mismatch_reverse_rejected() {
    let writer = appendable_one_member("Arr20Writer", arr_of(TypeIdentifier::TK_INT32, vec![20]));
    let reader = appendable_one_member("Arr10Reader", arr_of(TypeIdentifier::TK_INT32, vec![10]));
    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "CASE 3 (reverse): array[20]<int32> -> array[10]<int32> must be rejected \
         (XTypes sec. 7.5.1.5: array dimensions are invariant)"
    );
}

// =============================================================================
// CASE 4 -- sequence of FINAL S1{int32 a} vs FINAL S2{int32 a; int32 b}
// =============================================================================

/// FENCE CASE 4 (direct): FINAL S1{int32 a} is NOT assignable to FINAL
/// S2{int32 a; int32 b}.
///
/// XTypes v1.3 sec. 7.5.1.2: FINAL struct assignability is based on Minimal
/// EquivalenceHash equality.  S1 and S2 have different Minimal hashes because
/// their member lists differ -> not assignable, regardless of extensibility of
/// the outer context.
///
/// After the fix: FINAL struct comparison still goes through hash equality
/// first; a correct fix must not bypass the FINAL hash check and fall through
/// to structural APPENDABLE-style comparison.
#[test]
fn fence_final_struct_extra_member_rejected() {
    let s1 = final_struct("S1", &[(0, TypeIdentifier::TK_INT32, "a")]);
    let s2 = final_struct(
        "S2",
        &[
            (0, TypeIdentifier::TK_INT32, "a"),
            (1, TypeIdentifier::TK_INT32, "b"),
        ],
    );
    assert!(
        !Matcher::is_assignable_to(&s1, &s2),
        "CASE 4 (direct): FINAL S1{{int32 a}} -> FINAL S2{{int32 a, int32 b}} \
         must be rejected (XTypes sec. 7.5.1.2: FINAL requires identical Minimal hash)"
    );
}

/// FENCE CASE 4 (nested): sequence<FINAL S1> vs sequence<FINAL S2> inside an
/// APPENDABLE outer struct.
///
/// The sequence-element TypeIdentifiers are `Minimal(hash_s1)` and
/// `Minimal(hash_s2)`.  Since S1 and S2 are structurally different FINAL
/// types, their Minimal hashes differ -> `type_id_assignable(Minimal(h1),
/// Minimal(h2))` = false.
///
/// After the fix (structural deref): the fix must resolve h1->S1 and h2->S2,
/// then call is_assignable_to(S1, S2), which correctly rejects because FINAL
/// requires exact Minimal hash match (sec. 7.5.1.2).  A buggy fix that treats the
/// nested FINAL structs as APPENDABLE (checking only common members) would
/// incorrectly accept this pair.
#[test]
fn fence_seq_of_final_struct_extra_member_nested_rejected() {
    // Compute real Minimal hashes so a registry-aware deref can resolve them.
    let tid_s1 = minimal_final_struct_tid(&[(0, TypeIdentifier::TK_INT32, "a")]);
    let tid_s2 = minimal_final_struct_tid(&[
        (0, TypeIdentifier::TK_INT32, "a"),
        (1, TypeIdentifier::TK_INT32, "b"),
    ]);

    let writer = appendable_one_member("SeqS1Writer", seq_of(tid_s1));
    let reader = appendable_one_member("SeqS2Reader", seq_of(tid_s2));

    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "CASE 4 (nested): seq<FINAL S1{{int32 a}}> -> seq<FINAL S2{{int32 a, int32 b}}> \
         must be rejected: hashes differ + FINAL requires exact hash \
         (XTypes sec. 7.5.1.2 + sec. 7.5.1.5)"
    );
}

// =============================================================================
// CASE 5 -- struct member typed int32 vs same member typed string
// =============================================================================

/// FENCE CASE 5: struct member type int32 vs string (StringSmall{bound:0}).
///
/// XTypes v1.3 sec. 7.5.1.1.2: for each common member_id, the writer member type
/// must be assignable to the reader member type.  Primitive int32 is never
/// assignable to StringSmall; `type_id_assignable(Primitive(TK_INT32),
/// StringSmall{0})` returns false (different TypeIdentifier variants).
///
/// After the fix: cross-variant TypeIdentifier pairs still hit the `_ => false`
/// arm of type_id_assignable; a fix that incorrectly adds a "structural fallback
/// for all cross-variant Minimal/Complete pairs" must not relax this case.
#[test]
fn fence_struct_member_int32_vs_string_rejected() {
    // Build two APPENDABLE structs that share member_id=0 but differ in type.
    let writer = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("WriterInt32"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: CompleteMemberDetail::new("value"),
        }],
    });
    let reader = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("ReaderString"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::StringSmall { bound: 0 },
            },
            detail: CompleteMemberDetail::new("value"),
        }],
    });
    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "CASE 5: struct member int32 vs string must be rejected \
         (XTypes sec. 7.5.1.1.2: member types must be assignable; int32 is not assignable \
         to StringSmall)"
    );
}

// =============================================================================
// CASE 6 -- union with label sets {1,2} vs {3,4} -- FINAL and APPENDABLE
// =============================================================================

/// FENCE CASE 6a: FINAL unions with fully disjoint explicit label sets.
///
/// XTypes v1.3 sec. 7.5.1.4 rule 4: for FINAL unions the explicit discriminant
/// label sets must be equal.  {1,2} != {3,4} -> not assignable.
///
/// After the fix: union assignability is in is_union_assignable, not in the
/// structural-deref path.  A fix that adds structural fallback for the union
/// case must not relax the FINAL label-set equality requirement.
#[test]
fn fence_final_union_disjoint_labels_rejected() {
    let writer = build_union(
        UnionTypeFlag::IS_FINAL,
        "UnionFinalW",
        &[(1, TypeIdentifier::TK_INT32), (2, TypeIdentifier::TK_INT32)],
    );
    let reader = build_union(
        UnionTypeFlag::IS_FINAL,
        "UnionFinalR",
        &[(3, TypeIdentifier::TK_INT32), (4, TypeIdentifier::TK_INT32)],
    );
    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "CASE 6a: FINAL union labels {{1,2}} vs {{3,4}} must be rejected \
         (XTypes sec. 7.5.1.4 rule 4: FINAL requires identical explicit label sets)"
    );
    // Both directions must fail.
    assert!(
        !Matcher::is_assignable_to(&reader, &writer),
        "CASE 6a (reverse): FINAL union labels {{3,4}} vs {{1,2}} must be rejected"
    );
}

/// FENCE CASE 6b: APPENDABLE unions with fully disjoint explicit label sets.
///
/// XTypes v1.3 sec. 7.5.1.4 rule 5: for APPENDABLE/MUTABLE unions, the INTERSECTION
/// of explicit discriminant labels must be non-empty.  {1,2} intersect {3,4} = {} ->
/// not assignable.
///
/// After the fix: same reasoning as 6a.  A buggy fix that replaces
/// "no-common-label" with some structural heuristic must not accept this pair.
#[test]
fn fence_appendable_union_disjoint_labels_rejected() {
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        "UnionAppW",
        &[(1, TypeIdentifier::TK_INT32), (2, TypeIdentifier::TK_INT32)],
    );
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        "UnionAppR",
        &[(3, TypeIdentifier::TK_INT32), (4, TypeIdentifier::TK_INT32)],
    );
    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "CASE 6b: APPENDABLE union labels {{1,2}} vs {{3,4}} must be rejected \
         (XTypes sec. 7.5.1.4 rule 5: non-empty label intersection required)"
    );
    assert!(
        !Matcher::is_assignable_to(&reader, &writer),
        "CASE 6b (reverse): APPENDABLE union labels {{3,4}} vs {{1,2}} must be rejected"
    );
}

// =============================================================================
// CASE 7 -- nested struct with member type genuinely incompatible
// =============================================================================

/// FENCE CASE 7 (direct): outer struct whose member's type is a nested APPENDABLE
/// struct -- writer inner type has int32 field, reader inner type has BYTE field.
///
/// `type_id_assignable(Minimal(hash_int32_inner), Minimal(hash_byte_inner))` is
/// false because the hashes differ (different member type -> different Minimal
/// encoding).
///
/// After the fix (structural deref): fix resolves inner_W = {member_0: int32}
/// and inner_R = {member_0: byte}.  is_assignable_to(inner_W, inner_R) calls
/// type_id_assignable(TK_INT32, TK_BYTE).  TK_BYTE is NOT in the signed-int
/// widening chain and not in the uint chain (per XTypes sec. 7.5.1.3 Table 3 +
/// types.rs:primitive_widening_allowed); result is false.
/// A buggy fix that accepts any APPENDABLE-vs-APPENDABLE nested pair without
/// checking member types would incorrectly return true.
#[test]
fn fence_nested_member_type_int32_vs_byte_rejected() {
    let tid_inner_w = minimal_appendable_one_member_tid(TypeIdentifier::TK_INT32, "field");
    let tid_inner_r = minimal_appendable_one_member_tid(TypeIdentifier::TK_BYTE, "field");

    // Outer struct: member_0 is a Minimal-hash reference to the inner type.
    let outer_writer = appendable_one_member("OuterW", tid_inner_w);
    let outer_reader = appendable_one_member("OuterR", tid_inner_r);

    assert!(
        !Matcher::is_assignable_to(&outer_writer, &outer_reader),
        "CASE 7: nested struct member type int32 vs byte must be rejected \
         (XTypes sec. 7.5.1.1.2 recursively; TK_BYTE not in signed-int widening chain \
         sec. 7.5.1.3 Table 3)"
    );
}

/// FENCE CASE 7 (seq-nested): sequence whose elements are two different nested
/// APPENDABLE structs -- writer element has int32 field, reader element has
/// float64 field.  int32 and float64 are in different widening chains (signed-
/// int vs float), so even with prevent_type_widening=false they are not assignable.
///
/// Guards against a buggy fix that accepts any Minimal-hash sequence element pair
/// whose underlying types are "similar" (both are single-member APPENDABLE structs).
#[test]
fn fence_seq_nested_struct_incompatible_member_type_rejected() {
    let tid_inner_w = minimal_appendable_one_member_tid(TypeIdentifier::TK_INT32, "val");
    let tid_inner_r = minimal_appendable_one_member_tid(TypeIdentifier::TK_FLOAT64, "val");

    let writer = appendable_one_member("OuterSeqW", seq_of(tid_inner_w));
    let reader = appendable_one_member("OuterSeqR", seq_of(tid_inner_r));

    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "CASE 7 (seq): seq<struct{{int32 val}}> vs seq<struct{{float64 val}}> \
         must be rejected: int32 and float64 are in different primitive widening chains \
         (XTypes sec. 7.5.1.3 Table 3 + sec. 7.5.1.1.2 recursively)"
    );
}

// =============================================================================
// CASE 8 -- sanity ACCEPT: identical TypeObjects must be assignable
// =============================================================================

/// FENCE CASE 8a: identical APPENDABLE struct -- fast-path must still accept.
///
/// Guards against the fence itself or any refactoring accidentally blocking
/// the happy path.  A correct fix must not change the result for identical types.
#[test]
fn fence_identical_appendable_struct_accepted() {
    let s = appendable_one_member("Point", TypeIdentifier::TK_INT32);
    assert!(
        Matcher::is_assignable_to(&s, &s.clone()),
        "CASE 8a: identical APPENDABLE struct must be assignable (sanity fast-path)"
    );
}

/// FENCE CASE 8b: identical FINAL struct -- fast-path Minimal hash equality must
/// accept.
#[test]
fn fence_identical_final_struct_accepted() {
    let s = final_struct(
        "S",
        &[
            (0, TypeIdentifier::TK_INT64, "x"),
            (1, TypeIdentifier::TK_INT64, "y"),
        ],
    );
    assert!(
        Matcher::is_assignable_to(&s, &s.clone()),
        "CASE 8b: identical FINAL struct must be assignable (sanity: Minimal hash equality)"
    );
}

/// FENCE CASE 8c: identical CompleteTypeObject::Enumerated -- is_type_compatible
/// must accept via hash equality fast-path.
#[test]
fn fence_identical_enum_accepted() {
    let e = enum_complete("Color", 32, &[(0, "RED"), (1, "GREEN"), (2, "BLUE")]);
    assert!(
        Matcher::is_type_compatible(Some(&e), Some(&e.clone()), "Color", "Color"),
        "CASE 8c: identical enum TypeObject must be compatible (sanity: hash equality)"
    );
}

/// FENCE CASE 8d: APPENDABLE enum with overlapping literal values -- compatible.
///
/// Guards against over-rejection.  EnumA {0,1,2} vs EnumB {1,2,3} share values
/// {1,2} -> is_enum_assignable returns true (XTypes sec. 7.5.2.8 requires non-empty
/// intersection, not full equality).
#[test]
fn fence_enum_overlapping_values_accepted() {
    let enum_a = enum_complete("EnumA", 32, &[(0, "A_ZERO"), (1, "A_ONE"), (2, "A_TWO")]);
    let enum_b = enum_complete("EnumB", 32, &[(1, "B_ONE"), (2, "B_TWO"), (3, "B_THREE")]);
    assert!(
        Matcher::is_type_compatible(Some(&enum_a), Some(&enum_b), "EnumA", "EnumB"),
        "CASE 8d: enums with overlapping values {{0,1,2}} / {{1,2,3}} must be accepted \
         (XTypes sec. 7.5.2.8: non-empty intersection {{1,2}} is sufficient)"
    );
}

/// FENCE CASE 8e: sequence of the same nested APPENDABLE struct -- accepted.
///
/// Guards against the nested hash comparison being inadvertently broken by
/// the fix: seq<inner_type> vs seq<inner_type> (same hash) must remain true.
#[test]
fn fence_seq_identical_nested_struct_accepted() {
    let tid_inner = minimal_appendable_one_member_tid(TypeIdentifier::TK_INT32, "val");
    let writer = appendable_one_member("OuterSeqW", seq_of(tid_inner.clone()));
    let reader = appendable_one_member("OuterSeqR", seq_of(tid_inner));
    assert!(
        Matcher::is_assignable_to(&writer, &reader),
        "CASE 8e: seq<struct{{int32 val}}> vs seq<same struct{{int32 val}}> \
         must be accepted (same Minimal hash -> hash equality holds)"
    );
}
