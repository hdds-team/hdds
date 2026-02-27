// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::xtypes::{
    CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
    CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    TypeIdentifier,
};

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
fn test_assignable_mutable_reader_missing_field() {
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

    assert!(!Matcher::is_assignable_to(&writer, &reader));
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
fn test_assignable_mutable_mixed_optional_required() {
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

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}
