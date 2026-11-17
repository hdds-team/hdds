// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::xtypes::{
    CollectionElementFlag, CommonStructMember, CompleteMemberDetail, CompleteStructHeader,
    CompleteStructMember, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
    EquivalenceHash, EquivalenceKind, MemberFlag, PlainArrayLElemDefn, PlainArraySElemDefn,
    PlainCollectionHeader, PlainSequenceLElemDefn, PlainSequenceSElemDefn, StructTypeFlag,
    TypeIdentifier,
};

// ============================================================================
// Helpers
// ============================================================================

fn plain_array_small(elem: TypeIdentifier, bounds: Vec<u8>) -> TypeIdentifier {
    TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        array_bound_seq: bounds,
        element_identifier: Box::new(elem),
    })
}

fn plain_sequence_small(elem: TypeIdentifier, bound: u8) -> TypeIdentifier {
    TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        bound,
        element_identifier: Box::new(elem),
    })
}

fn plain_sequence_large(elem: TypeIdentifier, bound: u32) -> TypeIdentifier {
    TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        bound,
        element_identifier: Box::new(elem),
    })
}

fn plain_array_large(elem: TypeIdentifier, bounds: Vec<u32>) -> TypeIdentifier {
    TypeIdentifier::PlainArrayLarge(PlainArrayLElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        array_bound_seq: bounds,
        element_identifier: Box::new(elem),
    })
}

fn struct_with_one_member(
    flag: StructTypeFlag,
    type_name: &str,
    member_type_id: TypeIdentifier,
) -> CompleteTypeObject {
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: flag,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(type_name),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id,
            },
            detail: CompleteMemberDetail::new("data"),
        }],
    })
}

// ============================================================================
// Array size mismatch
// ============================================================================

/// int32[10] writer vs int32[20] reader: different bounds, same element type.
/// Per XTypes v1.3 sec. 7.5.1.5 array dimensions are invariant.
#[test]
fn test_array_size_mismatch_fails() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Arr10",
        plain_array_small(TypeIdentifier::TK_INT32, vec![10]),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Arr20",
        plain_array_small(TypeIdentifier::TK_INT32, vec![20]),
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

/// int32[20] writer vs int32[10] reader: reversed direction, still incompatible.
#[test]
fn test_array_size_mismatch_reversed_fails() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Arr20",
        plain_array_small(TypeIdentifier::TK_INT32, vec![20]),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Arr10",
        plain_array_small(TypeIdentifier::TK_INT32, vec![10]),
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Array element type mismatch
// ============================================================================

/// int32[10] writer vs uint32[10] reader: same size, different element types.
/// TypeKind TK_INT32 != TK_UINT32, so element assignability fails.
#[test]
fn test_array_elem_type_mismatch_fails() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Int32Arr",
        plain_array_small(TypeIdentifier::TK_INT32, vec![10]),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Uint32Arr",
        plain_array_small(TypeIdentifier::TK_UINT32, vec![10]),
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Array exact match passes
// ============================================================================

/// int32[10] writer vs int32[10] reader: same bounds, same element type.
/// Must be assignable per XTypes v1.3 sec. 7.5.1.5.
#[test]
fn test_array_same_size_same_type_passes() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Arr10",
        plain_array_small(TypeIdentifier::TK_INT32, vec![10]),
    );
    let reader = writer.clone();
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

/// float64[3][4] writer vs float64[3][4] reader: multi-dimensional exact match.
#[test]
fn test_array_multidim_same_passes() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Matrix",
        plain_array_small(TypeIdentifier::TK_FLOAT64, vec![3, 4]),
    );
    let reader = writer.clone();
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

/// float64[3][4] writer vs float64[4][3] reader: swapped dimensions fails.
#[test]
fn test_array_multidim_swapped_dims_fails() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Matrix34",
        plain_array_small(TypeIdentifier::TK_FLOAT64, vec![3, 4]),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Matrix43",
        plain_array_small(TypeIdentifier::TK_FLOAT64, vec![4, 3]),
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Sequence bound tolerance
// ============================================================================

/// sequence<int32, 10> writer vs sequence<int32, 20> reader: element types
/// match; bounds differ but sequences are bound-tolerant by default.
/// Per XTypes v1.3 sec. 7.5.1.5 `ignore_sequence_bounds` defaults to true.
#[test]
fn test_sequence_different_bounds_passes() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Seq10",
        plain_sequence_small(TypeIdentifier::TK_INT32, 10),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Seq20",
        plain_sequence_small(TypeIdentifier::TK_INT32, 20),
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

/// sequence<int32, 10> writer vs sequence<uint32, 10> reader: same bound but
/// different element types; must fail.
#[test]
fn test_sequence_elem_type_mismatch_fails() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Int32Seq",
        plain_sequence_small(TypeIdentifier::TK_INT32, 10),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Uint32Seq",
        plain_sequence_small(TypeIdentifier::TK_UINT32, 10),
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

/// sequence<int32, 10> (Small) writer vs sequence<int32, 300> (Large) reader:
/// cross-size-class sequence assignability ignores bounds.
#[test]
fn test_sequence_small_to_large_passes() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "SeqSmall",
        plain_sequence_small(TypeIdentifier::TK_INT32, 10),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "SeqLarge",
        plain_sequence_large(TypeIdentifier::TK_INT32, 300),
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Large-bound arrays
// ============================================================================

/// int32[300] (PlainArrayLarge) writer vs int32[300] reader: large arrays
/// with identical bounds must pass.
#[test]
fn test_large_array_same_passes() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "LargeArr",
        plain_array_large(TypeIdentifier::TK_INT32, vec![300]),
    );
    let reader = writer.clone();
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

/// int32[300] writer vs int32[400] reader: large arrays, different bounds fails.
#[test]
fn test_large_array_size_mismatch_fails() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "LargeArr300",
        plain_array_large(TypeIdentifier::TK_INT32, vec![300]),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "LargeArr400",
        plain_array_large(TypeIdentifier::TK_INT32, vec![400]),
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Hash-based member types (enum, union via Minimal/Complete hash)
// ============================================================================

/// Two members with identical Minimal hashes: assignable.
#[test]
fn test_hash_based_same_hash_passes() {
    let hash = EquivalenceHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "TypeA",
        TypeIdentifier::Minimal(hash),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "TypeB",
        TypeIdentifier::Minimal(hash),
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

/// Two members with different Minimal hashes (enum1 vs enum2): not assignable.
#[test]
fn test_hash_based_different_hash_fails() {
    let hash1 = EquivalenceHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    let hash2 = EquivalenceHash::from_bytes([9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 12, 13, 14]);
    let writer = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Enum1",
        TypeIdentifier::Minimal(hash1),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_APPENDABLE,
        "Enum2",
        TypeIdentifier::Minimal(hash2),
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Array inside MUTABLE struct
// ============================================================================

/// MUTABLE struct: int32[10] member vs int32[20] member, matched by member_id.
/// Different array sizes must still fail after member-id resolution.
#[test]
fn test_mutable_array_size_mismatch_fails() {
    let writer = struct_with_one_member(
        StructTypeFlag::IS_MUTABLE,
        "Sensor10",
        plain_array_small(TypeIdentifier::TK_INT32, vec![10]),
    );
    let reader = struct_with_one_member(
        StructTypeFlag::IS_MUTABLE,
        "Sensor20",
        plain_array_small(TypeIdentifier::TK_INT32, vec![20]),
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Struct element assignability -- FINAL vs APPENDABLE extensibility
//
// Corresponds to OMG XTypes test array_test_suite (test_suite.py):
//   SFinal[10]_S[20]_SFinalAlt[10]_S[20]           -> OK
//   SAppendable[10]_S[20]_SAppendableAlt[10]_S[20] -> OK
// ============================================================================

/// Two FINAL structs with different member names ARE assignable when used as
/// direct topic types under the default permissive policy.
///
/// XTypes v1.3 sec. 7.5.1.2 bases FINAL equivalence on the Minimal hash (which
/// includes name_hash). However, sec. 7.6.3.4 ALLOW_TYPE_COERCION with the default
/// `ignore_member_names=true` permits structural assignability when the hashes
/// differ solely because of member name differences. This matches the OMG test
/// `struct_different_names_ok` expectation (ReturnCode.OK).
///
/// NOTE: this test exercises the TOP-LEVEL struct comparison only (these two
/// structs used directly as the pub/sub topic type). The OMG test
/// `SFinal[10]_S[20]_SFinalAlt[10]_S[20]` instead uses these same two struct
/// shapes NESTED as an array element inside an outer FINAL struct (so the
/// comparison is reached via `type_id_assignable`'s hash-referenced-type arm,
/// through a `TypeObjectResolver`, not via this direct top-level path). That
/// scenario is covered by
/// `structural_assignability_fix::nested_final_struct_alt_name_array_element_assignable`
/// and its `sequence_element` / `strict_policy_still_rejects` companions,
/// which pin the fix for `type_id_assignable`'s Minimal/Complete hash arms
/// (previously those arms forced `ignore_member_names=false` for any
/// FINAL-vs-FINAL nested pair regardless of the caller's actual policy,
/// which wrongly rejected this exact renamed-member case under the suite's
/// permissive default -- see the comment on those arms in
/// `matcher::types::type_id_assignable`).
///
/// Models: F_S__array20_uint32 (member x1) vs F_S__array20_uint32_alt (member altx1)
#[test]
fn test_array_of_final_struct_alt_name_assignable() {
    // Build writer FINAL struct: member "x1" (id=0, uint32[20])
    let writer = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("F_S__array20_uint32"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: plain_array_small(TypeIdentifier::TK_UINT32, vec![20]),
            },
            detail: CompleteMemberDetail::new("x1"),
        }],
    });
    // Build reader FINAL struct: member "altx1" (id=0, uint32[20]) -- different name
    let reader = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("F_S__array20_uint32_alt"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: plain_array_small(TypeIdentifier::TK_UINT32, vec![20]),
            },
            detail: CompleteMemberDetail::new("altx1"),
        }],
    });
    // Top-level FINAL struct comparison with default policy (ignore_member_names=true):
    // Minimal hashes differ (names differ), structural fallback ignores names,
    // member IDs match (both 0), types match (uint32[20]) -> assignable.
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

/// Two APPENDABLE structs with the same member_id and type but different member
/// names ARE assignable under the default permissive policy. The default policy
/// has ignore_member_names=true so name differences are not checked.
/// Strict name enforcement requires ignore_member_names=false in an explicit QoS.
///
/// Models: A_S__array20_uint32 (member x1) vs A_S__array20_uint32_alt (member altx1)
#[test]
fn test_array_of_appendable_struct_alt_name_assignable() {
    // Build writer APPENDABLE struct: member "x1" (id=0, uint32[20])
    let writer = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("A_S__array20_uint32"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: plain_array_small(TypeIdentifier::TK_UINT32, vec![20]),
            },
            detail: CompleteMemberDetail::new("x1"),
        }],
    });
    // Build reader APPENDABLE struct: member "altx1" (id=0, uint32[20]) -- different name
    let reader = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("A_S__array20_uint32_alt"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: plain_array_small(TypeIdentifier::TK_UINT32, vec![20]),
            },
            detail: CompleteMemberDetail::new("altx1"),
        }],
    });
    // Default policy has ignore_member_names=true; names are not enforced.
    assert!(Matcher::is_assignable_to(&writer, &reader));
}
