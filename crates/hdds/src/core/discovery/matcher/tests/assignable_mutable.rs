// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::xtypes::{
    CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
    CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    TypeIdentifier,
};

fn must_understand_member(id: u32, name: &'static str, type_id: TypeIdentifier) -> MemberSpec {
    MemberSpec {
        id,
        flags: MemberFlag::IS_MUST_UNDERSTAND,
        type_id,
        name,
    }
}

#[derive(Clone)]
struct MemberSpec {
    id: u32,
    flags: MemberFlag,
    type_id: TypeIdentifier,
    name: &'static str,
}

fn member(id: u32, name: &'static str, type_id: TypeIdentifier) -> MemberSpec {
    MemberSpec {
        id,
        flags: MemberFlag::empty(),
        type_id,
        name,
    }
}

fn optional_member(id: u32, name: &'static str, type_id: TypeIdentifier) -> MemberSpec {
    MemberSpec {
        id,
        flags: MemberFlag::IS_OPTIONAL,
        type_id,
        name,
    }
}

fn build_struct(flag: StructTypeFlag, name: &str, members: &[MemberSpec]) -> CompleteTypeObject {
    let member_seq = members
        .iter()
        .map(|spec| CompleteStructMember {
            common: CommonStructMember {
                member_id: spec.id,
                member_flags: spec.flags,
                member_type_id: spec.type_id.clone(),
            },
            detail: CompleteMemberDetail::new(spec.name),
        })
        .collect();

    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: flag,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq,
    })
}

#[test]
fn test_assignable_mutable_reordered_fields() {
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            member(1, "y", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(1, "y", TypeIdentifier::TK_INT32),
            member(0, "x", TypeIdentifier::TK_INT32),
        ],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_mutable_writer_has_extra_field() {
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            member(1, "y", TypeIdentifier::TK_INT32),
            optional_member(2, "z", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            member(1, "y", TypeIdentifier::TK_INT32),
        ],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_mutable_writer_extra_member_assignable() {
    // Writer has member id=1 that the reader does not have.
    // Per XTypes v1.3 sec. 7.2.2.4.4.4: extra writer members are silently ignored
    // by the reader; the pair is compatible.
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            member(1, "y", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[member(0, "x", TypeIdentifier::TK_INT32)],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_incompatible_extensibility() {
    let writer = build_struct(
        StructTypeFlag::IS_FINAL,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            member(1, "y", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            member(1, "y", TypeIdentifier::TK_INT32),
        ],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_mutable_optional_field_missing() {
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            member(1, "y", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            optional_member(1, "y", TypeIdentifier::TK_INT32),
            optional_member(2, "z", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_mutable_multiple_optional_fields() {
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[member(0, "x", TypeIdentifier::TK_INT32)],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            optional_member(1, "y", TypeIdentifier::TK_INT32),
            optional_member(2, "z", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_mutable_reader_extra_non_must_understand_assignable() {
    // Reader has members id=1 (@optional) and id=2 (non-optional, non-must_understand)
    // that the writer does not have. Per XTypes v1.3 sec. 7.2.2.4.4.4, a reader member
    // absent from the writer is only incompatible when IS_MUST_UNDERSTAND is set.
    // id=2 here has neither flag, so the pair is compatible.
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[member(0, "x", TypeIdentifier::TK_INT32)],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            optional_member(1, "y", TypeIdentifier::TK_INT32),
            member(2, "z", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_mutable_reader_must_understand_missing_incompatible() {
    // Reader has a member id=2 marked IS_MUST_UNDERSTAND that the writer does
    // not provide. Per XTypes v1.3 sec. 7.2.2.4.4.4, this makes the pair incompatible.
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[member(0, "x", TypeIdentifier::TK_INT32)],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "Point",
        &[
            member(0, "x", TypeIdentifier::TK_INT32),
            must_understand_member(2, "z", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// OMG XTypes v2 extensibility test suite equivalents (struct_m1..struct_m3 shapes).
// struct_m1: id=1 (x1/int32)
// struct_m2: id=1 (x1/int32), id=2 (x2/int32)
// struct_m3: id=1 (x1/int32), id=3 (x3/int32), id=2 (x2/int32)

#[test]
fn test_mutable_same_members_assignable() {
    // pub struct_m1, sub struct_m1: identical types, must match.
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m1",
        &[member(1, "x1", TypeIdentifier::TK_INT32)],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m1",
        &[member(1, "x1", TypeIdentifier::TK_INT32)],
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_mutable_writer_extra_member_assignable() {
    // pub struct_m2 (id=1, id=2), sub struct_m1 (id=1).
    // Writer has an extra member the reader does not know; reader ignores it.
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m2",
        &[
            member(1, "x1", TypeIdentifier::TK_INT32),
            member(2, "x2", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m1",
        &[member(1, "x1", TypeIdentifier::TK_INT32)],
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_mutable_reader_extra_member_assignable() {
    // pub struct_m1 (id=1), sub struct_m2 (id=1, id=2).
    // Reader has an extra member id=2 not in the writer; it is not IS_MUST_UNDERSTAND,
    // so the pair is compatible per XTypes v1.3 sec. 7.2.2.4.4.4.
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m1",
        &[member(1, "x1", TypeIdentifier::TK_INT32)],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m2",
        &[
            member(1, "x1", TypeIdentifier::TK_INT32),
            member(2, "x2", TypeIdentifier::TK_INT32),
        ],
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_mutable_reordered_members_assignable() {
    // pub struct_m3 (id=1, id=3, id=2), sub struct_m2 (id=1, id=2).
    // Writer and reader share id=1 and id=2; writer has extra id=3.
    // Member order differs; matching is by ID only.
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m3",
        &[
            member(1, "x1", TypeIdentifier::TK_INT32),
            member(3, "x3", TypeIdentifier::TK_INT32),
            member(2, "x2", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m2",
        &[
            member(1, "x1", TypeIdentifier::TK_INT32),
            member(2, "x2", TypeIdentifier::TK_INT32),
        ],
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

/// OMG XTypes v2 ext_mutable_struct_6 regression:
/// struct_m2 (id=1:x1, id=2:x2) vs struct_m4 (id=0:x1, id=1:x3, id=2:x2).
/// struct_m4 uses sequential IDs (no explicit @id); the name "x3" at id=1
/// conflicts with "x1" at id=1 from the writer side.
/// With ignore_member_names=false (spec default), reader x1(id=0) not found
/// in writer but writer has "x1" at id=1 -> name/ID incoherence -> incompatible.
#[test]
fn test_mutable_name_id_incoherence_incompatible() {
    use crate::protocol::discovery::types::TypeConsistencyEnforcement;
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m2",
        &[
            member(1, "x1", TypeIdentifier::TK_INT32),
            member(2, "x2", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m4",
        &[
            member(0, "x1", TypeIdentifier::TK_INT32),
            member(1, "x3", TypeIdentifier::TK_INT32),
            member(2, "x2", TypeIdentifier::TK_INT32),
        ],
    );
    let p = TypeConsistencyEnforcement {
        kind: 1,
        ignore_sequence_bounds: true,
        ignore_string_bounds: true,
        ignore_member_names: false,
        prevent_type_widening: false,
        force_type_validation: false,
    };
    assert!(
        !crate::core::discovery::Matcher::is_type_compatible_with_policy(
            Some(&writer),
            Some(&reader),
            "",
            "",
            Some(&p),
        ),
        "struct_m2 vs struct_m4: reader x1 absent by ID but writer has x1 at different ID -> incompatible"
    );
}

/// OMG XTypes v2 struct_different_ids regression:
/// struct_1 (id=1:x1, id=5:x5) vs struct_2 (id=2:x1, id=5:x5).
/// With ignore_member_names=false: reader x1(id=2) not found by ID in writer;
/// writer has "x1" at id=1 which differs from reader's id=2 -> incompatible.
#[test]
fn test_mutable_same_name_different_id_incompatible() {
    use crate::protocol::discovery::types::TypeConsistencyEnforcement;
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_1",
        &[
            member(1, "x1", TypeIdentifier::TK_INT32),
            member(5, "x5", TypeIdentifier::TK_INT32),
        ],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_2",
        &[
            member(2, "x1", TypeIdentifier::TK_INT32),
            member(5, "x5", TypeIdentifier::TK_INT32),
        ],
    );
    let p = TypeConsistencyEnforcement {
        kind: 1,
        ignore_sequence_bounds: true,
        ignore_string_bounds: true,
        ignore_member_names: false,
        prevent_type_widening: false,
        force_type_validation: false,
    };
    assert!(
        !crate::core::discovery::Matcher::is_type_compatible_with_policy(
            Some(&writer),
            Some(&reader),
            "",
            "",
            Some(&p),
        ),
        "struct_1 vs struct_2: both have x1 but at different IDs with ignore_member_names=false -> incompatible"
    );
}

/// Verify that a matched writer/reader ID pair with mismatched names is
/// incompatible when ignore_member_names=false.
#[test]
fn test_mutable_matched_id_different_name_incompatible() {
    use crate::protocol::discovery::types::TypeConsistencyEnforcement;
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "W",
        &[member(1, "foo", TypeIdentifier::TK_INT32)],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "R",
        &[member(1, "bar", TypeIdentifier::TK_INT32)],
    );
    let p = TypeConsistencyEnforcement {
        kind: 1,
        ignore_sequence_bounds: true,
        ignore_string_bounds: true,
        ignore_member_names: false,
        prevent_type_widening: false,
        force_type_validation: false,
    };
    assert!(
        !crate::core::discovery::Matcher::is_type_compatible_with_policy(
            Some(&writer),
            Some(&reader),
            "",
            "",
            Some(&p),
        ),
        "same ID=1 but different names (foo vs bar) with ignore_member_names=false -> incompatible"
    );
}

/// Verify that a matched writer/reader ID pair with mismatched names IS
/// compatible when ignore_member_names=true.
#[test]
fn test_mutable_matched_id_different_name_ignore_names_compatible() {
    use crate::protocol::discovery::types::TypeConsistencyEnforcement;
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "W",
        &[member(1, "foo", TypeIdentifier::TK_INT32)],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "R",
        &[member(1, "bar", TypeIdentifier::TK_INT32)],
    );
    let p = TypeConsistencyEnforcement {
        kind: 1,
        ignore_sequence_bounds: true,
        ignore_string_bounds: true,
        ignore_member_names: true,
        prevent_type_widening: false,
        force_type_validation: false,
    };
    assert!(
        crate::core::discovery::Matcher::is_type_compatible_with_policy(
            Some(&writer),
            Some(&reader),
            "",
            "",
            Some(&p),
        ),
        "same ID=1, different names, ignore_member_names=true -> compatible"
    );
}

#[test]
fn test_mutable_autoid_hash_mismatch_incompatible() {
    // Mixing explicit IDs (no IS_AUTOID_HASH) with hash-derived IDs (IS_AUTOID_HASH)
    // produces disjoint ID spaces that cannot be matched. Per XTypes v1.3 sec. 7.3.1.2
    // the autoid scheme must agree for assignability.
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_m2",
        &[
            member(1, "x1", TypeIdentifier::TK_INT32),
            member(2, "x2", TypeIdentifier::TK_INT32),
        ],
    );
    // IS_MUTABLE | IS_AUTOID_HASH
    let autoid_flag =
        StructTypeFlag(StructTypeFlag::IS_MUTABLE.0 | StructTypeFlag::IS_AUTOID_HASH.0);
    let reader = build_struct(
        autoid_flag,
        "struct_m4",
        &[
            member(0, "x1", TypeIdentifier::TK_INT32),
            member(1, "x3", TypeIdentifier::TK_INT32),
            member(2, "x2", TypeIdentifier::TK_INT32),
        ],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

/// OMG XTypes v2 struct_no_common_ids:
/// struct_5 (mutable, x1 id=1) vs struct_6 (mutable, x2 id=2).
/// The two types share no common member_id: the intersection of
/// {id=1} and {id=2} is empty. Per XTypes v1.3 sec. 7.5.2.1.1.4 mutable
/// types with completely disjoint member ID sets are not assignable.
#[test]
fn test_mutable_no_common_member_ids_incompatible() {
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_5",
        &[member(1, "x1", TypeIdentifier::TK_INT32)],
    );
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_6",
        &[member(2, "x2", TypeIdentifier::TK_INT32)],
    );
    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "mutable structs with no common member IDs must be incompatible"
    );
    // Incompatibility is symmetric.
    assert!(
        !Matcher::is_assignable_to(&reader, &writer),
        "mutable structs with no common member IDs must be incompatible (reverse direction)"
    );
}

/// Positive case: mutable structs with at least one shared member_id remain
/// assignable even when they also carry disjoint members. This guards against
/// over-eager rejection by the no-common-IDs guard.
///
/// Models the OMG struct_1 (id=1:x1, id=5:x5) vs struct_2 (id=2:x1, id=5:x5)
/// scenario: id=5 is shared, so the guard passes; incompatibility comes from
/// the name/ID coherence check when ignore_member_names=false.
#[test]
fn test_mutable_partial_common_ids_passes_guard() {
    // struct with id=1 and id=5 (writer)
    let writer = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_partial_w",
        &[
            member(1, "x1", TypeIdentifier::TK_INT32),
            member(5, "x5", TypeIdentifier::TK_INT32),
        ],
    );
    // reader that shares id=5 but not id=1
    let reader = build_struct(
        StructTypeFlag::IS_MUTABLE,
        "struct_partial_r",
        &[
            member(5, "x5", TypeIdentifier::TK_INT32),
            member(7, "x7", TypeIdentifier::TK_INT32),
        ],
    );
    // id=5 is shared -> no-common-IDs guard does not fire.
    // reader id=7 has no writer match and is not IS_MUST_UNDERSTAND -> skip.
    assert!(
        Matcher::is_assignable_to(&writer, &reader),
        "partial ID overlap: guard must not reject when at least one ID is shared"
    );
}
