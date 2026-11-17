// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::xtypes::{
    CommonUnionMember, CompleteMemberDetail, CompleteTypeDetail, CompleteTypeObject,
    CompleteUnionHeader, CompleteUnionMember, CompleteUnionType, MemberFlag, TypeIdentifier,
    UnionTypeFlag,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a union case (non-default) with explicit discriminant labels.
fn union_case(labels: Vec<i32>, name: &str, type_id: TypeIdentifier) -> CompleteUnionMember {
    union_case_with_id(0, labels, name, type_id)
}

/// Build a union case with an explicit `member_id`.
fn union_case_with_id(
    member_id: u32,
    labels: Vec<i32>,
    name: &str,
    type_id: TypeIdentifier,
) -> CompleteUnionMember {
    CompleteUnionMember {
        common: CommonUnionMember {
            member_id,
            member_flags: MemberFlag::empty(),
            member_type_id: type_id,
            label_seq: labels,
        },
        detail: CompleteMemberDetail::new(name),
    }
}

/// Build a default union case (IS_DEFAULT flag, empty label_seq).
fn union_default_case(name: &str, type_id: TypeIdentifier) -> CompleteUnionMember {
    CompleteUnionMember {
        common: CommonUnionMember {
            member_id: 0,
            member_flags: MemberFlag::IS_DEFAULT,
            member_type_id: type_id,
            label_seq: vec![],
        },
        detail: CompleteMemberDetail::new(name),
    }
}

/// Build a union case whose discriminator is annotated @key (IS_KEY on member_flags).
fn union_case_key(labels: Vec<i32>, name: &str, type_id: TypeIdentifier) -> CompleteUnionMember {
    CompleteUnionMember {
        common: CommonUnionMember {
            member_id: 0,
            member_flags: MemberFlag::IS_KEY,
            member_type_id: type_id,
            label_seq: labels,
        },
        detail: CompleteMemberDetail::new(name),
    }
}

/// Build a `CompleteTypeObject::Union` from the supplied spec.
///
/// Fixtures built via `union_case` / `union_default_case` leave member_id=0.
/// Real unions never carry duplicate member ids (XTypes v1.3 Sec 7.3.1.2
/// requires uniqueness; the IDL/XML bridge assigns 1-based declaration-order
/// sequential ids, the discriminator being the first member and consuming id
/// 0 per XTypes v1.3 Sec 7.2.2.4.4.3), so when EVERY supplied member has id 0
/// and there is more than one member, ids are re-assigned sequentially
/// (1-based) in declaration order to keep the fixtures representative of
/// bridge-produced TypeObjects. Fixtures that pass explicit ids via
/// `union_case_with_id` are left untouched.
fn build_union(
    ext: UnionTypeFlag,
    disc: TypeIdentifier,
    name: &str,
    mut members: Vec<CompleteUnionMember>,
) -> CompleteTypeObject {
    if members.len() > 1 && members.iter().all(|m| m.common.member_id == 0) {
        for (idx, m) in members.iter_mut().enumerate() {
            m.common.member_id = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        }
    }
    CompleteTypeObject::Union(CompleteUnionType {
        union_flags: ext,
        header: CompleteUnionHeader {
            discriminator: disc,
            discriminator_flags: MemberFlag::empty(),
            detail: CompleteTypeDetail::new(name),
        },
        member_seq: members,
    })
}

// ---------------------------------------------------------------------------
// Extensibility mismatch tests (rules 1 + 2 of is_union_assignable)
// ---------------------------------------------------------------------------

/// FINAL writer vs APPENDABLE reader: extensibility mismatch -> INCONSISTENT_TOPIC.
/// Corresponds to OMG test union_final_appendable.
#[test]
fn test_union_final_vs_appendable_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT8,
        "union_primitives_final",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_BYTE),
            union_case(vec![2], "x2", TypeIdentifier::TK_UINT16),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT8,
        "union_primitives_appendable",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_BYTE),
            union_case(vec![2], "x2", TypeIdentifier::TK_UINT16),
        ],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

/// FINAL writer vs MUTABLE reader: extensibility mismatch -> incompatible.
/// Corresponds to OMG test union_final_mutable.
#[test]
fn test_union_final_vs_mutable_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT8,
        "union_primitives_final",
        vec![union_case(vec![1], "x1", TypeIdentifier::TK_BYTE)],
    );
    let reader = build_union(
        UnionTypeFlag::IS_MUTABLE,
        TypeIdentifier::TK_UINT8,
        "union_primitives_mutable",
        vec![union_case(vec![1], "x1", TypeIdentifier::TK_BYTE)],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

/// APPENDABLE writer vs MUTABLE reader: extensibility mismatch -> incompatible.
/// Corresponds to OMG test union_appendable_mutable.
#[test]
fn test_union_appendable_vs_mutable_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT8,
        "union_primitives_appendable",
        vec![union_case(vec![1], "x1", TypeIdentifier::TK_BYTE)],
    );
    let reader = build_union(
        UnionTypeFlag::IS_MUTABLE,
        TypeIdentifier::TK_UINT8,
        "union_primitives_mutable",
        vec![union_case(vec![1], "x1", TypeIdentifier::TK_BYTE)],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ---------------------------------------------------------------------------
// Same-type FINAL tests (should pass -- hash would also pass)
// ---------------------------------------------------------------------------

/// Same FINAL union on both sides: identical label set and member types -> OK.
/// Corresponds to OMG test union_primitives_final.
#[test]
fn test_union_final_identical_assignable() {
    let u = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT8,
        "union_primitives_final",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_BYTE),
            union_case(vec![2], "x2", TypeIdentifier::TK_UINT16),
            union_case(vec![3], "x3", TypeIdentifier::TK_UINT32),
        ],
    );
    assert!(Matcher::is_assignable_to(&u, &u.clone()));
}

// ---------------------------------------------------------------------------
// FINAL label-set exact-match tests
// ---------------------------------------------------------------------------

/// FINAL writer has 5 labels, FINAL reader has 6 labels (extra label 0) -> incompatible.
/// Corresponds to OMG test union_final_5_vs_6.
#[test]
fn test_union_final_label_sets_differ_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_final_5",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT64),
            union_case(vec![4], "x4", TypeIdentifier::TK_UINT16),
            union_case(vec![5], "x5", TypeIdentifier::TK_UINT32),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_final_6",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT64),
            union_case(vec![4], "x4", TypeIdentifier::TK_UINT16),
            union_case(vec![5], "x5", TypeIdentifier::TK_UINT32),
            union_case(vec![0], "x0", TypeIdentifier::TK_UINT64),
        ],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
    // Reverse direction also incompatible (label sets still differ).
    assert!(!Matcher::is_assignable_to(&reader, &writer));
}

/// FINAL union: same labels, writer has no default but reader has default -> incompatible.
/// Corresponds to OMG test union_final_one_default_1.
#[test]
fn test_union_final_default_presence_mismatch_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_final_5",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![5], "x5", TypeIdentifier::TK_UINT32),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_final_5_default",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![5], "x5", TypeIdentifier::TK_UINT32),
            union_default_case("DeFault", TypeIdentifier::TK_UINT32),
        ],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
    // Reverse direction: writer has default, reader does not -> also incompatible.
    assert!(!Matcher::is_assignable_to(&reader, &writer));
}

// ---------------------------------------------------------------------------
// Discriminator key annotation mismatch tests
// ---------------------------------------------------------------------------

/// Writer union has no @key on discriminator, reader union has @key -> incompatible.
/// Corresponds to OMG test union_uint32_one_key.
#[test]
fn test_union_discriminator_key_mismatch_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_uint32",
        vec![union_case(vec![1], "x1", TypeIdentifier::TK_INT32)],
    );
    // Reader discriminator is @key -- encoded as IS_KEY on every member's flags.
    let reader = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_uint32_key",
        vec![union_case_key(vec![1], "x1", TypeIdentifier::TK_INT32)],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ---------------------------------------------------------------------------
// Member type mismatch tests (label present in both, types differ)
// ---------------------------------------------------------------------------

/// APPENDABLE writer and reader share label 2 but writer has int16, reader has int32
/// -> member type mismatch -> incompatible.
/// Corresponds to OMG test union_int16_int32.
#[test]
fn test_union_appendable_common_label_type_mismatch_incompatible() {
    // union_int16: cases 1(int16), 2(int16), 3(int32)
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_int16",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![2], "x2", TypeIdentifier::TK_INT16),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // union_int32: cases 1(int16), 2(int32), 3(int32)
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_int32",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // Common labels = {1, 2, 3}. Label 2: int16 vs int32 -> incompatible.
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

/// APPENDABLE unions with identical types on all common labels -> compatible.
/// Corresponds to OMG test union_int32_int32_default (writer=union_int32, reader=union_int32_default).
/// Reader has a default case covering label 2 instead of explicit label 2; the
/// common explicit labels are {1,3} -- both have matching int16/int32 types -> OK.
#[test]
fn test_union_appendable_reader_default_covers_writer_label_compatible() {
    // union_int32: cases 1(int16), 2(int32), 3(int32) -- explicit label 2
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_int32",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // union_int32_default: cases 1(int16), default(int32), 3(int32) -- label 2 is default
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_int32_default",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_default_case("x2", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // Common explicit labels = {1, 3}. Both are compatible. -> OK.
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

// ---------------------------------------------------------------------------
// APPENDABLE: non-empty intersection tests
// ---------------------------------------------------------------------------

/// APPENDABLE writer labels {1,2,3,4,5}, reader labels {11,12,3,14,15,10} ->
/// intersection = {3} -> non-empty -> compatible.
/// Corresponds to OMG test union_appendable_one_common_1.
#[test]
fn test_union_appendable_one_common_label_compatible() {
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_appendable_a",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT64),
            union_case(vec![4], "x4", TypeIdentifier::TK_UINT16),
            union_case(vec![5], "x5", TypeIdentifier::TK_UINT32),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_appendable_b",
        vec![
            union_case(vec![11], "x11", TypeIdentifier::TK_INT16),
            union_case(vec![12], "x12", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT64),
            union_case(vec![14], "x14", TypeIdentifier::TK_UINT16),
            union_case(vec![15], "x15", TypeIdentifier::TK_UINT32),
            union_case(vec![10], "x10", TypeIdentifier::TK_UINT64),
        ],
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
    // Reverse direction: same common label 3 -> also OK.
    assert!(Matcher::is_assignable_to(&reader, &writer));
}

/// APPENDABLE writer labels {1,2,3,4,5}, reader labels {11,12,13,14,15,10} ->
/// intersection = {} -> incompatible.
/// Corresponds to OMG test union_appendable_no_common_1.
#[test]
fn test_union_appendable_no_common_label_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_appendable_a",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT64),
            union_case(vec![4], "x4", TypeIdentifier::TK_UINT16),
            union_case(vec![5], "x5", TypeIdentifier::TK_UINT32),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_appendable_c",
        vec![
            union_case(vec![11], "x11", TypeIdentifier::TK_INT16),
            union_case(vec![12], "x12", TypeIdentifier::TK_INT32),
            union_case(vec![13], "x13", TypeIdentifier::TK_INT64),
            union_case(vec![14], "x14", TypeIdentifier::TK_UINT16),
            union_case(vec![15], "x15", TypeIdentifier::TK_UINT32),
            union_case(vec![10], "x10", TypeIdentifier::TK_UINT64),
        ],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
    assert!(!Matcher::is_assignable_to(&reader, &writer));
}

/// APPENDABLE writer {5, default} vs reader {15, default} ->
/// intersection of explicit = {} -> incompatible (default does not count).
/// Corresponds to OMG test union_appendable_no_common_w_default.
#[test]
fn test_union_appendable_only_default_in_common_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_appendable_a_default",
        vec![
            union_case(vec![5], "x5", TypeIdentifier::TK_UINT32),
            union_default_case("xd", TypeIdentifier::TK_UINT32),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_appendable_b_default",
        vec![
            union_case(vec![15], "x15", TypeIdentifier::TK_UINT32),
            union_default_case("xd", TypeIdentifier::TK_UINT32),
        ],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ---------------------------------------------------------------------------
// MUTABLE: non-empty intersection tests (mirror of APPENDABLE above)
// ---------------------------------------------------------------------------

/// MUTABLE writer labels {1,2,3,4,5}, reader labels {11,12,3,14,15,10} ->
/// intersection = {3} -> compatible.
/// Corresponds to OMG test union_mutable_one_common.
#[test]
fn test_union_mutable_one_common_label_compatible() {
    let writer = build_union(
        UnionTypeFlag::IS_MUTABLE,
        TypeIdentifier::TK_UINT32,
        "union_mutable_a",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT64),
            union_case(vec![4], "x4", TypeIdentifier::TK_UINT16),
            union_case(vec![5], "x5", TypeIdentifier::TK_UINT32),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_MUTABLE,
        TypeIdentifier::TK_UINT32,
        "union_mutable_b",
        vec![
            union_case(vec![11], "x11", TypeIdentifier::TK_INT16),
            union_case(vec![12], "x12", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT64),
            union_case(vec![14], "x14", TypeIdentifier::TK_UINT16),
            union_case(vec![15], "x15", TypeIdentifier::TK_UINT32),
            union_case(vec![10], "x10", TypeIdentifier::TK_UINT64),
        ],
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
    assert!(Matcher::is_assignable_to(&reader, &writer));
}

/// MUTABLE writer {1,2,3,4,5}, reader {11,12,13,14,15,10} -> no common -> incompatible.
/// Corresponds to OMG test union_mutable_no_common.
#[test]
fn test_union_mutable_no_common_label_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_MUTABLE,
        TypeIdentifier::TK_UINT32,
        "union_mutable_a",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT64),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_MUTABLE,
        TypeIdentifier::TK_UINT32,
        "union_mutable_c",
        vec![
            union_case(vec![11], "x11", TypeIdentifier::TK_INT16),
            union_case(vec![12], "x12", TypeIdentifier::TK_INT32),
            union_case(vec![13], "x13", TypeIdentifier::TK_INT64),
        ],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

/// MUTABLE {5, default} vs {15, default} -> no common explicit label -> incompatible.
/// Corresponds to OMG test union_mutable_no_common_w_default.
#[test]
fn test_union_mutable_only_default_in_common_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_MUTABLE,
        TypeIdentifier::TK_UINT32,
        "union_mutable_a_default",
        vec![
            union_case(vec![5], "x5", TypeIdentifier::TK_UINT32),
            union_default_case("xd", TypeIdentifier::TK_UINT32),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_MUTABLE,
        TypeIdentifier::TK_UINT32,
        "union_mutable_b_default",
        vec![
            union_case(vec![15], "x15", TypeIdentifier::TK_UINT32),
            union_default_case("xd", TypeIdentifier::TK_UINT32),
        ],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ---------------------------------------------------------------------------
// FINAL member_id mismatch tests (defense-in-depth analog of
// union_different_ids_1 / _2 for genuinely FINAL unions)
// ---------------------------------------------------------------------------

/// FINAL union_1 vs union_2 (hypothetical FINAL variant): same label sets,
/// same member types, but label assignments to member_ids differ
/// (declaration order differs). Exercises the FINAL branch's own,
/// unconditional member_id equality check (is_union_assignable's FINAL arm),
/// which is intentionally left unchanged by the union_different_ids_1 fix
/// (see the comment on that check in is_union_assignable).
///
/// NOTE: this is NOT the same code path as the real OMG union_different_ids_1
/// / _2 tests. In unions.xml, union_1 and union_2 carry no `extensibility`
/// attribute, and the driver's XML loader defaults absent extensibility to
/// APPENDABLE (extensibility_defaults_to_appendable_when_absent), so the
/// real OMG pair is exercised by
/// `test_union_appendable_different_ids_policy_gated`, not by this FINAL
/// fixture. Kept as a targeted regression test for the FINAL branch's
/// independent, still-unconditional id check.
#[test]
fn test_union_final_different_member_ids_incompatible() {
    // union_1 (1-based auto ids, discriminator consumes id 0):
    // label=1->id=1(int16), label=2->id=2(int32), label=3->id=3(int32)
    let writer = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_1",
        vec![
            union_case_with_id(1, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(2, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(3, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // union_2: label=2->id=1(int32), label=1->id=2(int16), label=3->id=3(int32)
    let reader = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_2",
        vec![
            union_case_with_id(1, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(2, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(3, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // Label=1 maps to id=1 in writer but id=2 in reader -> incompatible.
    assert!(!Matcher::is_assignable_to(&writer, &reader));
    assert!(!Matcher::is_assignable_to(&reader, &writer));
}

/// Same FINAL fixture as above but with ignore_member_names=false. The
/// member_id mismatch still makes the pair incompatible regardless of the
/// name policy (the FINAL branch's id check is unconditional; see the note
/// on the previous test for why this is a defense-in-depth analog, not the
/// literal union_different_ids_2 code path).
#[test]
fn test_union_final_different_member_ids_ignore_names_false_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_1",
        vec![
            union_case_with_id(1, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(2, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(3, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_2",
        vec![
            union_case_with_id(1, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(2, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(3, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    let policy = TypeConsistencyEnforcement {
        ignore_member_names: false,
        ..TypeConsistencyEnforcement::default()
    };
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "",
        "",
        Some(&policy),
    ));
}

// ---------------------------------------------------------------------------
// FINAL member name mismatch tests (OMG union_different_names_2)
// ---------------------------------------------------------------------------

/// FINAL union_3 vs union_4 with ignore_member_names=false: same labels and
/// member_ids but different names at labels 1 and 2 -> incompatible.
/// Corresponds to OMG test union_different_names_2.
/// With ignore_member_names=true (default policy) the same pair is compatible.
#[test]
fn test_union_final_different_names_ignore_false_incompatible() {
    // union_3 (1-based auto ids): label=1(id=1,"x1"), label=2(id=2,"x2"),
    // label=3(id=3,"x3")
    let writer = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_3",
        vec![
            union_case_with_id(1, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(2, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(3, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // union_4: label=1(id=1,"x2"), label=2(id=2,"x1"), label=3(id=3,"x3")
    let reader = build_union(
        UnionTypeFlag::IS_FINAL,
        TypeIdentifier::TK_UINT32,
        "union_4",
        vec![
            union_case_with_id(1, vec![1], "x2", TypeIdentifier::TK_INT16),
            union_case_with_id(2, vec![2], "x1", TypeIdentifier::TK_INT32),
            union_case_with_id(3, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // ignore_member_names=false: name mismatch at labels 1 and 2.
    let strict_policy = TypeConsistencyEnforcement {
        ignore_member_names: false,
        ..TypeConsistencyEnforcement::default()
    };
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "",
        "",
        Some(&strict_policy),
    ));
    // ignore_member_names=true: name differences ignored, types match -> compatible.
    let permissive_policy = TypeConsistencyEnforcement {
        ignore_member_names: true,
        ..TypeConsistencyEnforcement::default()
    };
    assert!(Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "",
        "",
        Some(&permissive_policy),
    ));
}

// ---------------------------------------------------------------------------
// APPENDABLE both-default type mismatch tests (OMG union_int32_default_int16_default)
// ---------------------------------------------------------------------------

/// APPENDABLE union_int32_default vs union_int16_default:
/// same explicit labels {1,3}, types match at explicit labels, but default
/// member types differ (int32 vs int16) -> incompatible.
/// Any runtime discriminant value outside {1,3} routes to the default case;
/// the reader expects int16 while the writer sends int32.
/// Corresponds to OMG test union_int32_default_int16_default.
#[test]
fn test_union_appendable_both_default_type_mismatch_incompatible() {
    // union_int32_default: labels {1, 3}, default=int32
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_int32_default",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT32),
            union_default_case("x2", TypeIdentifier::TK_INT32),
        ],
    );
    // union_int16_default: labels {1, 3}, default=int16
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_int16_default",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT32),
            union_default_case("x2", TypeIdentifier::TK_INT16),
        ],
    );
    // Common labels {1,3} match. Defaults differ (int32 vs int16) -> incompatible.
    assert!(!Matcher::is_assignable_to(&writer, &reader));
    assert!(!Matcher::is_assignable_to(&reader, &writer));
}

/// APPENDABLE union_int32_default vs itself -> compatible (same default type).
/// Corresponds to OMG test union_int32_default_int32_default (identity case).
#[test]
fn test_union_appendable_both_same_default_compatible() {
    let u = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_int32_default",
        vec![
            union_case(vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case(vec![3], "x3", TypeIdentifier::TK_INT32),
            union_default_case("x2", TypeIdentifier::TK_INT32),
        ],
    );
    assert!(Matcher::is_assignable_to(&u, &u.clone()));
}

// ---------------------------------------------------------------------------
// APPENDABLE member-id coherence tests (rule 3b of is_union_assignable).
// The OMG driver defaults unions to APPENDABLE (spec-correct), so
// union_different_ids_1/_2, union_different_names_1/_2 and
// union_different_order_1/_2 exercise the APPENDABLE path.
// ---------------------------------------------------------------------------

/// union_1 vs union_2 as APPENDABLE: identical label->type mapping but the
/// declaration order differs, so sequential auto-assigned member ids
/// coincidentally pair x1(int16) with x2(int32) at id 0. Per DDS-XTypes v1.3
/// Table 19 (UNION_TYPE), member VALUE compatibility is established by
/// DISCRIMINATOR LABEL (rule 6), not by member id; the id/name coherence
/// bullet ("same id implies same name") only applies when
/// ignore_member_names=false (Sec 7.6.3.4.2 Step 1). Under the permissive
/// default (ignore_member_names=true, the OMG harness's no-flag behaviour)
/// the coincidental id collision must NOT reject: label 1 -> int16/int16,
/// label 2 -> int32/int32, label 3 -> int32/int32 are all consistent, so the
/// pair is compatible. Under an explicit ignore_member_names=false the
/// coherence bullet fires ("x1" and "x2" share id 0 but not a name) and the
/// pair is rejected.
/// Corresponds to OMG tests union_different_ids_1 (OK) and
/// union_different_ids_2 (INCONSISTENT_TOPIC, --ignore-member-names f).
#[test]
fn test_union_appendable_different_ids_policy_gated() {
    // union_1: x1(id0,label1,int16), x2(id1,label2,int32), x3(id2,label3,int32)
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_1",
        vec![
            union_case_with_id(0, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(1, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(2, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // union_2: x2(id0,label2,int32), x1(id1,label1,int16), x3(id2,label3,int32)
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_2",
        vec![
            union_case_with_id(0, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(1, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(2, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // Permissive default policy (ignore_member_names=true): the id-0 collision
    // is coincidental (declaration-order auto-ids); label-based value
    // compatibility holds for every label -> compatible.
    assert!(Matcher::is_assignable_to(&writer, &reader));
    assert!(Matcher::is_assignable_to(&reader, &writer));
    // Explicit ignore_member_names=false: the id/name coherence bullet now
    // applies and "x1" (id 0 in union_1) vs "x2" (id 0 in union_2) conflict.
    let strict_policy = TypeConsistencyEnforcement {
        ignore_member_names: false,
        ..TypeConsistencyEnforcement::default()
    };
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "",
        "",
        Some(&strict_policy),
    ));
}

/// union_3 vs union_4 as APPENDABLE: same ids, same labels, same types, but
/// the names at ids 0 and 1 are swapped. Name enforcement is policy-gated:
/// ignore_member_names=true (driver default when no flag is given) -> OK;
/// ignore_member_names=false (--ignore-member-names f) -> incompatible.
/// Corresponds to OMG tests union_different_names_1 (OK) and
/// union_different_names_2 (INCONSISTENT).
#[test]
fn test_union_appendable_same_id_name_mismatch_policy_gated() {
    // union_3: x1(id0,label1,int16), x2(id1,label2,int32), x3(id2,label3,int32)
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_3",
        vec![
            union_case_with_id(0, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(1, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(2, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // union_4: x2(id0,label1,int16), x1(id1,label2,int32), x3(id2,label3,int32)
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_4",
        vec![
            union_case_with_id(0, vec![1], "x2", TypeIdentifier::TK_INT16),
            union_case_with_id(1, vec![2], "x1", TypeIdentifier::TK_INT32),
            union_case_with_id(2, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // ignore_member_names=true: name differences ignored -> compatible.
    let permissive_policy = TypeConsistencyEnforcement {
        ignore_member_names: true,
        ..TypeConsistencyEnforcement::default()
    };
    assert!(Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "",
        "",
        Some(&permissive_policy),
    ));
    // ignore_member_names=false: id 0 pairs "x1" with "x2" -> incompatible.
    let strict_policy = TypeConsistencyEnforcement {
        ignore_member_names: false,
        ..TypeConsistencyEnforcement::default()
    };
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "",
        "",
        Some(&strict_policy),
    ));
}

/// union_5 vs union_6 as APPENDABLE: explicit @id annotations keep name, id,
/// label and type aligned; only the declaration ORDER differs. Must stay
/// assignable under BOTH the permissive and the name-enforcing policy
/// (matching is by id, never by declaration position).
/// Corresponds to OMG tests union_different_order_1 and union_different_order_2.
#[test]
fn test_union_appendable_id_order_permutation_compatible() {
    // union_5: x1(@id1,label1,int16), x2(@id2,label2,int32), x3(@id3,label3,int32)
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_5",
        vec![
            union_case_with_id(1, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(2, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(3, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    // union_6: same members declared in a different order.
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_6",
        vec![
            union_case_with_id(2, vec![2], "x2", TypeIdentifier::TK_INT32),
            union_case_with_id(1, vec![1], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(3, vec![3], "x3", TypeIdentifier::TK_INT32),
        ],
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
    assert!(Matcher::is_assignable_to(&reader, &writer));
    let strict_policy = TypeConsistencyEnforcement {
        ignore_member_names: false,
        ..TypeConsistencyEnforcement::default()
    };
    assert!(Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "",
        "",
        Some(&strict_policy),
    ));
}

/// Two non-empty APPENDABLE unions with fully disjoint member id sets carry
/// no common member and are not assignable, even when a common label with a
/// matching type exists (mirrors the struct no-common-member rule).
#[test]
fn test_union_appendable_disjoint_member_ids_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_w",
        vec![union_case_with_id(
            1,
            vec![1],
            "x1",
            TypeIdentifier::TK_INT32,
        )],
    );
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_r",
        vec![union_case_with_id(
            2,
            vec![1],
            "x1",
            TypeIdentifier::TK_INT32,
        )],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
    assert!(!Matcher::is_assignable_to(&reader, &writer));
}

// ---------------------------------------------------------------------------
// Discriminator strong-assignability tests
// ---------------------------------------------------------------------------

/// Discriminator int16 vs int32: primitive discriminators must be the SAME
/// kind (strongly assignable, no integer promotion) -> incompatible in both
/// directions even though the member sets are identical.
#[test]
fn test_union_discriminator_int16_vs_int32_incompatible() {
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_INT16,
        "union_disc16",
        vec![union_case(vec![1], "x1", TypeIdentifier::TK_INT32)],
    );
    let reader = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_INT32,
        "union_disc32",
        vec![union_case(vec![1], "x1", TypeIdentifier::TK_INT32)],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
    assert!(!Matcher::is_assignable_to(&reader, &writer));
}

/// uint32 discriminator vs hash-referenced bitmask discriminator, resolved
/// through a TypeObjectResolver stub: bitmask<32> holder is uint32 -> OK
/// (union_uint32_bitmask32); bitmask<16> holder is uint16 -> incompatible
/// (union_uint32_bitmask16). Without a resolver both pairs stay incompatible.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn test_union_discriminator_uint32_vs_bitmask_resolver() {
    use crate::core::discovery::matcher::types::TypeObjectResolver;
    use crate::xtypes::{
        CompleteBitflag, CompleteBitmaskHeader, CompleteBitmaskType, CompleteMemberDetail,
        EquivalenceHash,
    };
    use std::collections::HashMap;

    fn make_bitmask(name: &str, bit_bound: i16) -> CompleteTypeObject {
        CompleteTypeObject::Bitmask(CompleteBitmaskType {
            bitmask_flags: crate::xtypes::StructTypeFlag::empty(),
            header: CompleteBitmaskHeader {
                bit_bound,
                detail: CompleteTypeDetail::new(name),
            },
            flag_seq: vec![CompleteBitflag {
                common: crate::xtypes::CommonBitflag {
                    position: 0,
                    flags: crate::xtypes::BitflagFlag::empty(),
                },
                detail: CompleteMemberDetail::new("B_FLAG_1"),
            }],
        })
    }

    struct StubResolver {
        minimal: HashMap<EquivalenceHash, CompleteTypeObject>,
    }
    impl TypeObjectResolver for StubResolver {
        fn resolve_minimal(&self, h: &EquivalenceHash) -> Option<&CompleteTypeObject> {
            self.minimal.get(h)
        }
        fn resolve_complete(&self, _h: &EquivalenceHash) -> Option<&CompleteTypeObject> {
            None
        }
    }

    let h16 = EquivalenceHash::from_bytes([1u8; 14]);
    let h32 = EquivalenceHash::from_bytes([2u8; 14]);
    let mut minimal = HashMap::new();
    minimal.insert(h16, make_bitmask("B_16", 16));
    minimal.insert(h32, make_bitmask("B_32", 32));
    let resolver = StubResolver { minimal };

    // union_uint32: x1(id0,label2,int16), x2(id1,label1,int32)
    let members = || {
        vec![
            union_case_with_id(0, vec![2], "x1", TypeIdentifier::TK_INT16),
            union_case_with_id(1, vec![1], "x2", TypeIdentifier::TK_INT32),
        ]
    };
    let writer = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::TK_UINT32,
        "union_uint32",
        members(),
    );
    let reader_bm32 = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::Minimal(h32),
        "union_bitmask32",
        members(),
    );
    let reader_bm16 = build_union(
        UnionTypeFlag::IS_APPENDABLE,
        TypeIdentifier::Minimal(h16),
        "union_bitmask16",
        members(),
    );

    // bitmask<32> holder == uint32 -> strongly assignable, both directions.
    assert!(Matcher::is_type_compatible_with_resolver(
        Some(&writer),
        Some(&reader_bm32),
        "",
        "",
        None,
        Some(&resolver),
    ));
    assert!(Matcher::is_type_compatible_with_resolver(
        Some(&reader_bm32),
        Some(&writer),
        "",
        "",
        None,
        Some(&resolver),
    ));
    // bitmask<16> holder == uint16 != uint32 -> incompatible.
    assert!(!Matcher::is_type_compatible_with_resolver(
        Some(&writer),
        Some(&reader_bm16),
        "",
        "",
        None,
        Some(&resolver),
    ));
    // No resolver -> conservative reject (cross-variant discriminators).
    assert!(!Matcher::is_type_compatible_with_resolver(
        Some(&writer),
        Some(&reader_bm32),
        "",
        "",
        None,
        None,
    ));
}
