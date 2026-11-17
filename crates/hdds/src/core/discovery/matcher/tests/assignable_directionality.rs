// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Directionality tests for is_type_compatible.
//!
//! is_type_compatible(writer, reader, ...) must follow XTypes v1.3 sec. 7.5.1 semantics where the
//! first argument is the writer type and the second is the reader type. These tests lock the
//! asymmetry by covering FINAL, APPENDABLE, and MUTABLE extensibility in both directions.
//!
//! Regression guard for the SEDP handle_sedp Writer branch fix (line 841 in discovery.rs):
//! the remote writer must be passed as arg 1 and the local reader as arg 2.

use super::*;
use crate::xtypes::{
    CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
    CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    TypeIdentifier,
};

fn member(id: u32, name: &'static str, flags: MemberFlag) -> CompleteStructMember {
    CompleteStructMember {
        common: CommonStructMember {
            member_id: id,
            member_flags: flags,
            member_type_id: TypeIdentifier::TK_INT32,
        },
        detail: CompleteMemberDetail::new(name),
    }
}

fn build(
    flag: StructTypeFlag,
    name: &str,
    members: Vec<CompleteStructMember>,
) -> CompleteTypeObject {
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: flag,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq: members,
    })
}

// ========== FINAL ==========

#[test]
fn test_directionality_final_symmetric_ok() {
    // FINAL types are symmetric: exact match required in both directions.
    let writer = build(
        StructTypeFlag::IS_FINAL,
        "Point",
        vec![
            member(0, "x", MemberFlag::empty()),
            member(1, "y", MemberFlag::empty()),
        ],
    );
    let reader = writer.clone();

    assert!(Matcher::is_type_compatible(
        Some(&writer),
        Some(&reader),
        "Point",
        "Point"
    ));
    assert!(Matcher::is_type_compatible(
        Some(&reader),
        Some(&writer),
        "Point",
        "Point"
    ));
}

#[test]
fn test_directionality_final_writer_extra_field_not_assignable() {
    // FINAL: writer with extra field is NOT assignable to a reader missing it, and vice versa.
    let writer = build(
        StructTypeFlag::IS_FINAL,
        "Point3D",
        vec![
            member(0, "x", MemberFlag::empty()),
            member(1, "y", MemberFlag::empty()),
            member(2, "z", MemberFlag::empty()),
        ],
    );
    let reader = build(
        StructTypeFlag::IS_FINAL,
        "Point",
        vec![
            member(0, "x", MemberFlag::empty()),
            member(1, "y", MemberFlag::empty()),
        ],
    );

    // Both directions fail for FINAL: extra field breaks exact equivalence.
    assert!(!Matcher::is_type_compatible(
        Some(&writer),
        Some(&reader),
        "Point3D",
        "Point"
    ));
    assert!(!Matcher::is_type_compatible(
        Some(&reader),
        Some(&writer),
        "Point",
        "Point3D"
    ));
}

// ========== APPENDABLE ==========

#[test]
fn test_directionality_appendable_writer_extra_field_ok() {
    // APPENDABLE: writer has extra trailing field; reader only checks its own prefix.
    // is_type_compatible(writer, reader) -> true.
    let writer = build(
        StructTypeFlag::IS_APPENDABLE,
        "ShapeTypeExtended",
        vec![
            member(0, "x", MemberFlag::empty()),
            member(1, "y", MemberFlag::empty()),
            member(2, "shapesize", MemberFlag::empty()),
            member(3, "color", MemberFlag::empty()),
        ],
    );
    let reader = build(
        StructTypeFlag::IS_APPENDABLE,
        "ShapeType",
        vec![
            member(0, "x", MemberFlag::empty()),
            member(1, "y", MemberFlag::empty()),
            member(2, "shapesize", MemberFlag::empty()),
        ],
    );

    // Writer with extra field -> reader that ignores it: OK per XTypes sec. 7.5.1.1.2.
    assert!(Matcher::is_type_compatible(
        Some(&writer),
        Some(&reader),
        "ShapeTypeExtended",
        "ShapeType"
    ));
}

#[test]
fn test_directionality_appendable_reader_extra_field_compatible() {
    // APPENDABLE: reader has extra non-must-understand field not present in writer.
    // Per XTypes v1.3 sec. 7.5.1.1.2, APPENDABLE allows the reader to have extra
    // trailing members; the reader fills them from the type default. Compatible
    // unless prevent_type_widening=true or the member is IS_MUST_UNDERSTAND.
    let writer = build(
        StructTypeFlag::IS_APPENDABLE,
        "ShapeType",
        vec![
            member(0, "x", MemberFlag::empty()),
            member(1, "y", MemberFlag::empty()),
            member(2, "shapesize", MemberFlag::empty()),
        ],
    );
    let reader = build(
        StructTypeFlag::IS_APPENDABLE,
        "ShapeTypeExtended",
        vec![
            member(0, "x", MemberFlag::empty()),
            member(1, "y", MemberFlag::empty()),
            member(2, "shapesize", MemberFlag::empty()),
            member(3, "color", MemberFlag::empty()),
        ],
    );

    // Reader has extra non-must-understand member; default policy allows this.
    assert!(Matcher::is_type_compatible(
        Some(&writer),
        Some(&reader),
        "ShapeType",
        "ShapeTypeExtended"
    ));

    // Swapped: writer has extra member reader doesn't know about; also compatible
    // (writer just sends more than reader needs; reader ignores extra fields).
    assert!(Matcher::is_type_compatible(
        Some(&reader),
        Some(&writer),
        "ShapeTypeExtended",
        "ShapeType"
    ));
}

// ========== MUTABLE ==========

#[test]
fn test_directionality_mutable_writer_extra_field_ok() {
    // MUTABLE: writer has extra non-optional member not required by reader; allowed per
    // XTypes sec. 7.5.1.1.3 because reader does not declare it.
    let writer = build(
        StructTypeFlag::IS_MUTABLE,
        "Telemetry",
        vec![
            member(0, "timestamp", MemberFlag::empty()),
            member(1, "value", MemberFlag::empty()),
            member(2, "source_id", MemberFlag::empty()),
        ],
    );
    let reader = build(
        StructTypeFlag::IS_MUTABLE,
        "Telemetry",
        vec![
            member(0, "timestamp", MemberFlag::empty()),
            member(1, "value", MemberFlag::empty()),
        ],
    );

    // Writer sends source_id; reader does not declare it -> compatible.
    assert!(Matcher::is_type_compatible(
        Some(&writer),
        Some(&reader),
        "Telemetry",
        "Telemetry"
    ));
}

#[test]
fn test_directionality_mutable_reader_must_understand_field_fails() {
    // MUTABLE: reader has a IS_MUST_UNDERSTAND field (source_id) that the writer never sends.
    // Per XTypes v1.3 sec. 7.2.2.4.4.4, only IS_MUST_UNDERSTAND members cause incompatibility
    // when absent from the writer. Non-optional-but-not-must_understand missing members are OK.
    // Regression guard: swapping writer/reader args must not hide the incompatibility.
    let writer = build(
        StructTypeFlag::IS_MUTABLE,
        "Telemetry",
        vec![
            member(0, "timestamp", MemberFlag::empty()),
            member(1, "value", MemberFlag::empty()),
        ],
    );
    let reader = build(
        StructTypeFlag::IS_MUTABLE,
        "Telemetry",
        vec![
            member(0, "timestamp", MemberFlag::empty()),
            member(1, "value", MemberFlag::empty()),
            member(2, "source_id", MemberFlag::IS_MUST_UNDERSTAND),
        ],
    );

    // Writer does not send source_id; reader marks it IS_MUST_UNDERSTAND: NOT assignable.
    assert!(!Matcher::is_type_compatible(
        Some(&writer),
        Some(&reader),
        "Telemetry",
        "Telemetry"
    ));

    // Swapped args: source_id is now in writer position; reader (original writer) has
    // id=0 and id=1 which are both present in writer (original reader) -> assignable.
    assert!(Matcher::is_type_compatible(
        Some(&reader),
        Some(&writer),
        "Telemetry",
        "Telemetry"
    ));
}

#[test]
fn test_directionality_mutable_optional_missing_ok() {
    // MUTABLE: reader has optional field not in writer; must be accepted per sec. 7.5.1.1.3.
    let writer = build(
        StructTypeFlag::IS_MUTABLE,
        "Telemetry",
        vec![
            member(0, "timestamp", MemberFlag::empty()),
            member(1, "value", MemberFlag::empty()),
        ],
    );
    let reader = build(
        StructTypeFlag::IS_MUTABLE,
        "Telemetry",
        vec![
            member(0, "timestamp", MemberFlag::empty()),
            member(1, "value", MemberFlag::empty()),
            member(2, "source_id", MemberFlag::IS_OPTIONAL),
        ],
    );

    // source_id is optional in reader; missing from writer is allowed.
    assert!(Matcher::is_type_compatible(
        Some(&writer),
        Some(&reader),
        "Telemetry",
        "Telemetry"
    ));
}
