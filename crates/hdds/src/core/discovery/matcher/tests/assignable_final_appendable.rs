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
    type_id: TypeIdentifier,
    flags: MemberFlag,
    name: &'static str,
}

fn member(id: u32, name: &'static str) -> MemberSpec {
    MemberSpec {
        id,
        type_id: TypeIdentifier::TK_INT32,
        flags: MemberFlag::empty(),
        name,
    }
}

fn optional_member(id: u32, name: &'static str) -> MemberSpec {
    MemberSpec {
        id,
        type_id: TypeIdentifier::TK_INT32,
        flags: MemberFlag::IS_OPTIONAL,
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

// ========== Phase 11: Type Assignability Tests ==========

#[test]
fn test_assignable_final_exact_match() {
    let point_writer = build_struct(
        StructTypeFlag::IS_FINAL,
        "Point",
        &[member(0, "x"), member(1, "y")],
    );
    let point_reader = point_writer.clone();

    assert!(Matcher::is_assignable_to(&point_writer, &point_reader));
}

#[test]
fn test_assignable_final_different_structure() {
    let writer = build_struct(
        StructTypeFlag::IS_FINAL,
        "Point3D",
        &[member(0, "x"), member(1, "y"), member(2, "z")],
    );
    let reader = build_struct(
        StructTypeFlag::IS_FINAL,
        "Point",
        &[member(0, "x"), member(1, "y")],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_appendable_writer_has_extra_field() {
    let writer = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "Point",
        &[member(0, "x"), member(1, "y"), member(2, "z")],
    );
    let reader = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "Point",
        &[member(0, "x"), member(1, "y")],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_appendable_reader_has_extra_field() {
    let writer = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "Point",
        &[member(0, "x"), member(1, "y")],
    );
    let reader = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "Point",
        &[member(0, "x"), member(1, "y"), member(2, "z")],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_appendable_optional_field_missing() {
    let writer = build_struct(StructTypeFlag::IS_APPENDABLE, "Point", &[member(0, "x")]);
    let reader = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "Point",
        &[member(0, "x"), optional_member(1, "y")],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}
