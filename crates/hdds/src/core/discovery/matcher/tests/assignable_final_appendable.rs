// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
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
fn test_assignable_appendable_reader_has_extra_non_must_understand_field() {
    // Per XTypes v1.3 sec. 7.5.1.1.2, a reader with extra trailing members that
    // are NOT IS_MUST_UNDERSTAND is still assignable from a shorter writer:
    // the absent trailing members are filled with type defaults at the reader.
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

    assert!(Matcher::is_assignable_to(&writer, &reader));
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

// ========== ShapeTypeExtended vs ShapeType (OMG interop scenario) ==========
//
// ShapeTypeExtended is APPENDABLE and adds a color string field beyond the
// base ShapeType fields. A writer of ShapeTypeExtended must be assignable to
// a reader of ShapeType (reader ignores the extra field). The reverse is not
// true when the extra field in ShapeTypeExtended is mandatory.
//
// This pair is the primary XTypes v1.3 sec. 7.5.1 scenario exercised by the OMG
// interoperability harness ShapeTypeExtended tests.

fn shape_type() -> CompleteTypeObject {
    build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "ShapeType",
        &[member(0, "x"), member(1, "y"), member(2, "shapesize")],
    )
}

fn shape_type_extended() -> CompleteTypeObject {
    build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "ShapeTypeExtended",
        &[
            member(0, "x"),
            member(1, "y"),
            member(2, "shapesize"),
            member(3, "color"),
        ],
    )
}

#[test]
fn test_assignable_shape_type_extended_writer_to_shape_type_reader() {
    // Writer has extra mandatory field -- APPENDABLE reader stops at its own
    // field count, so the extra writer field is simply ignored (XTypes sec. 7.5.1.1.2).
    let writer = shape_type_extended();
    let reader = shape_type();
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_shape_type_writer_to_shape_type_extended_reader() {
    // Writer (ShapeType, 3 fields) -> reader (ShapeTypeExtended, 4 fields).
    // The extra "color" field in the reader is a non-IS_MUST_UNDERSTAND
    // trailing member; per sec. 7.5.1.1.2 the reader fills it with the type
    // default. The types ARE assignable.
    let writer = shape_type();
    let reader = shape_type_extended();
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_is_type_compatible_appendable_writer_has_extra_fields() {
    // When both TypeObjects are APPENDABLE Structs, is_type_compatible routes
    // through is_assignable_to instead of name equality. A writer with extra
    // trailing fields is structurally assignable to a reader with fewer fields.
    let writer = shape_type_extended();
    let reader = shape_type();
    assert!(Matcher::is_type_compatible(
        Some(&writer),
        Some(&reader),
        "ShapeTypeExtended",
        "ShapeType",
    ));
}

#[test]
fn test_is_type_compatible_appendable_reverse_direction() {
    // Writer (ShapeType, 3 fields) -> reader (ShapeTypeExtended, 4 fields).
    // The reader's extra trailing "color" field is not IS_MUST_UNDERSTAND, so
    // the writer IS assignable to the reader per sec. 7.5.1.1.2. Reader fills
    // absent trailing members with type defaults.
    let writer = shape_type();
    let reader = shape_type_extended();
    assert!(Matcher::is_type_compatible(
        Some(&writer),
        Some(&reader),
        "ShapeType",
        "ShapeTypeExtended",
    ));
}

// ========== FINAL primitive widening regression tests ==========
//
// XTypes v1.3 sec. 7.5.1.2: FINAL struct assignability is based on Minimal
// EquivalenceHash equality. If hashes differ, only bound-only relaxations
// (ignore_sequence_bounds / ignore_string_bounds) are permitted. Primitive
// type changes (e.g. uint8 vs uint16) alter structural identity and must
// never be accepted for FINAL types regardless of the prevent_type_widening
// policy setting.
//
// Regression guard: a prior code path passed the caller policy
// (prevent_type_widening=false) into the FINAL hash-mismatch fallback,
// allowing primitive widening for FINAL types. These tests lock the fix.

fn primitive_member_spec(type_id: TypeIdentifier) -> MemberSpec {
    MemberSpec {
        id: 0,
        type_id,
        flags: MemberFlag::empty(),
        name: "value",
    }
}

fn final_primitive_struct(type_id: TypeIdentifier) -> CompleteTypeObject {
    build_struct(
        StructTypeFlag::IS_FINAL,
        "S",
        &[primitive_member_spec(type_id)],
    )
}

fn appendable_primitive_struct(type_id: TypeIdentifier) -> CompleteTypeObject {
    build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "S",
        &[primitive_member_spec(type_id)],
    )
}

fn allow_widening_policy() -> TypeConsistencyEnforcement {
    TypeConsistencyEnforcement {
        kind: 1,
        ignore_sequence_bounds: true,
        ignore_string_bounds: true,
        ignore_member_names: false,
        prevent_type_widening: false,
        force_type_validation: false,
    }
}

/// FINAL uint8 writer vs uint16 reader: hashes differ, must be rejected.
/// Widening is never permitted for FINAL types even with prevent_type_widening=false.
#[test]
fn test_final_uint8_writer_to_uint16_reader_rejected() {
    let writer = final_primitive_struct(TypeIdentifier::TK_UINT8);
    let reader = final_primitive_struct(TypeIdentifier::TK_UINT16);
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

/// FINAL uint16 writer vs uint8 reader: narrowing, must be rejected.
#[test]
fn test_final_uint16_writer_to_uint8_reader_rejected() {
    let writer = final_primitive_struct(TypeIdentifier::TK_UINT16);
    let reader = final_primitive_struct(TypeIdentifier::TK_UINT8);
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

/// FINAL byte writer vs uint8 reader: TK_BYTE is not in the uint widening chain.
/// Per XTypes sec. 7.5.1.3 Table 3, byte and uint8 are distinct types.
#[test]
fn test_final_byte_writer_to_uint8_reader_rejected() {
    let writer = final_primitive_struct(TypeIdentifier::TK_BYTE);
    let reader = final_primitive_struct(TypeIdentifier::TK_UINT8);
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

/// FINAL uint8 writer vs byte reader: same argument -- byte is not uint8.
#[test]
fn test_final_uint8_writer_to_byte_reader_rejected() {
    let writer = final_primitive_struct(TypeIdentifier::TK_UINT8);
    let reader = final_primitive_struct(TypeIdentifier::TK_BYTE);
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

/// FINAL int8 writer vs int16 reader: widening not allowed for FINAL.
#[test]
fn test_final_int8_writer_to_int16_reader_rejected() {
    let writer = final_primitive_struct(TypeIdentifier::TK_INT8);
    let reader = final_primitive_struct(TypeIdentifier::TK_INT16);
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

/// FINAL float32 writer vs float64 reader: widening not allowed for FINAL.
#[test]
fn test_final_float32_writer_to_float64_reader_rejected() {
    let writer = final_primitive_struct(TypeIdentifier::TK_FLOAT32);
    let reader = final_primitive_struct(TypeIdentifier::TK_FLOAT64);
    assert!(!Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

/// FINAL uint8 writer vs uint8 reader: same type, must match regardless of policy.
#[test]
fn test_final_uint8_to_uint8_matches() {
    let writer = final_primitive_struct(TypeIdentifier::TK_UINT8);
    let reader = final_primitive_struct(TypeIdentifier::TK_UINT8);
    assert!(Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

/// FINAL byte writer vs byte reader: same type, must match.
#[test]
fn test_final_byte_to_byte_matches() {
    let writer = final_primitive_struct(TypeIdentifier::TK_BYTE);
    let reader = final_primitive_struct(TypeIdentifier::TK_BYTE);
    assert!(Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

/// Regression guard: APPENDABLE uint8 writer vs uint16 reader with allow-widening
/// policy must still be compatible. The FINAL fix must not break APPENDABLE widening.
#[test]
fn test_appendable_uint8_writer_to_uint16_reader_allowed() {
    let writer = appendable_primitive_struct(TypeIdentifier::TK_UINT8);
    let reader = appendable_primitive_struct(TypeIdentifier::TK_UINT16);
    assert!(Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

/// Regression guard: APPENDABLE int8 writer vs int32 reader with allow-widening
/// policy must still be compatible (multi-step widening).
#[test]
fn test_appendable_int8_writer_to_int32_reader_allowed() {
    let writer = appendable_primitive_struct(TypeIdentifier::TK_INT8);
    let reader = appendable_primitive_struct(TypeIdentifier::TK_INT32);
    assert!(Matcher::is_type_compatible_with_policy(
        Some(&writer),
        Some(&reader),
        "S",
        "S",
        Some(&allow_widening_policy()),
    ));
}

// ========== ext_appendable_struct_2 regression guard ========================
//
// OMG xtypes test: pub struct_a1 (1 field x1) -> sub struct_a2 (2 fields x1,x2).
// Expected: both OK. Per sec. 7.5.1.1.2, reader extra trailing members that are NOT
// IS_MUST_UNDERSTAND are acceptable; they receive type defaults on the read side.
// This locked the fix that removed the erroneous IS_OPTIONAL requirement.

fn must_understand_member(id: u32, name: &'static str) -> MemberSpec {
    MemberSpec {
        id,
        type_id: TypeIdentifier::TK_INT32,
        flags: MemberFlag::IS_MUST_UNDERSTAND,
        name,
    }
}

#[test]
fn test_appendable_reader_extra_trailing_non_must_understand_is_assignable() {
    // Writer struct_a1: 1 field. Reader struct_a2: 2 fields.
    // Reader's trailing x2 is not IS_MUST_UNDERSTAND -> assignable per sec. 7.5.1.1.2.
    let writer = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "struct_a1",
        &[member(0, "x1")],
    );
    let reader = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "struct_a2",
        &[member(0, "x1"), member(1, "x2")],
    );
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_appendable_reader_extra_must_understand_field_not_assignable() {
    // Reader has an IS_MUST_UNDERSTAND trailing field absent from the writer.
    // This makes the types incompatible even under APPENDABLE evolution rules.
    // Models the OMG struct_mustUnderstand_2 scenario (pub=struct_int32 1 field,
    // sub=struct_mustUnderstand 2 fields, x2 flagged IS_MUST_UNDERSTAND).
    let writer = build_struct(StructTypeFlag::IS_APPENDABLE, "W", &[member(0, "x1")]);
    let reader = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "R",
        &[member(0, "x1"), must_understand_member(1, "x2")],
    );
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

/// OMG XTypes v2 struct_mustUnderstand_1:
/// Writer struct_mustUnderstand (x1 plain, x2 IS_MUST_UNDERSTAND, APPENDABLE),
/// reader struct_int32 (x1 plain only, APPENDABLE).
/// The reader is shorter than the writer; writer position 1 carries IS_MUST_UNDERSTAND.
/// Per XTypes v1.3 sec. 7.6.3.3 the reader must understand all IS_MUST_UNDERSTAND
/// members it receives; since the reader type does not have a member at index 1,
/// it cannot understand the field -> types are incompatible.
#[test]
fn test_appendable_writer_must_understand_trailing_reader_shorter_incompatible() {
    let writer = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "struct_mustUnderstand",
        &[member(0, "x1"), must_understand_member(1, "x2")],
    );
    let reader = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "struct_int32",
        &[member(0, "x1")],
    );
    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "writer IS_MUST_UNDERSTAND trailing member must make shorter reader incompatible"
    );
}

/// Positive companion: writer with IS_MUST_UNDERSTAND at position 1 IS assignable
/// to a reader that also has a member at position 1 with the same member_id.
/// Guards against over-rejection from the writer IS_MUST_UNDERSTAND backward pass.
#[test]
fn test_appendable_writer_must_understand_reader_has_matching_member_compatible() {
    let writer = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "W_with_mu",
        &[member(0, "x1"), must_understand_member(1, "x2")],
    );
    let reader = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "R_with_x2",
        &[member(0, "x1"), member(1, "x2")],
    );
    assert!(
        Matcher::is_assignable_to(&writer, &reader),
        "reader has a matching member at the IS_MUST_UNDERSTAND position -> compatible"
    );
}

// ========== ID-based intersection guards (sec. 7.5.1.1.2) =======================
//
// APPENDABLE assignability uses member_id-based matching, not declaration order.
// Two non-empty types with fully disjoint member ID sets share no common data
// and are not assignable. Types whose members are declared in different order
// but share the same member IDs are assignable when individual types agree.

/// Writer has [id=0, id=1], reader has [id=10, id=11]. No member_id is shared.
/// Per sec. 7.5.1.1.2, zero common members -> INCONSISTENT_TOPIC (not assignable).
#[test]
fn appendable_zero_common_members_rejected_per_spec() {
    let writer = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "W",
        &[member(0, "a"), member(1, "b")],
    );
    let reader = build_struct(
        StructTypeFlag::IS_APPENDABLE,
        "R",
        &[member(10, "c"), member(11, "d")],
    );
    assert!(
        !Matcher::is_assignable_to(&writer, &reader),
        "APPENDABLE types with fully disjoint member IDs must be incompatible"
    );
}

/// Writer has [id=0:int32, id=1:int64], reader has [id=1:int64, id=0:int32].
/// Members are declared in different order but share the same IDs and types.
/// ID-based matching must accept this pair (sec. 7.5.1.1.2).
#[test]
fn appendable_reordered_members_accepted_when_ids_match() {
    // writer: id=0 -> int32, id=1 -> int64
    let writer_members = vec![
        MemberSpec {
            id: 0,
            type_id: TypeIdentifier::TK_INT32,
            flags: MemberFlag::empty(),
            name: "x",
        },
        MemberSpec {
            id: 1,
            type_id: TypeIdentifier::TK_INT64,
            flags: MemberFlag::empty(),
            name: "y",
        },
    ];
    // reader: id=1 -> int64, id=0 -> int32  (reversed declaration order)
    let reader_members = vec![
        MemberSpec {
            id: 1,
            type_id: TypeIdentifier::TK_INT64,
            flags: MemberFlag::empty(),
            name: "y",
        },
        MemberSpec {
            id: 0,
            type_id: TypeIdentifier::TK_INT32,
            flags: MemberFlag::empty(),
            name: "x",
        },
    ];
    let writer = build_struct(StructTypeFlag::IS_APPENDABLE, "W", &writer_members);
    let reader = build_struct(StructTypeFlag::IS_APPENDABLE, "R", &reader_members);
    assert!(
        Matcher::is_assignable_to(&writer, &reader),
        "APPENDABLE types with same member IDs in different declaration order must be compatible"
    );
}
