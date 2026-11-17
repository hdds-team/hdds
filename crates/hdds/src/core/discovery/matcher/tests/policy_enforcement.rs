// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Tests for TypeConsistencyEnforcement policy application.
//!
//! Validates that ignore_sequence_bounds, ignore_string_bounds, and
//! prevent_type_widening flags are correctly applied by the matcher.

use super::*;
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::xtypes::{
    CollectionElementFlag, EquivalenceKind, PlainCollectionHeader, PlainSequenceLElemDefn,
    PlainSequenceSElemDefn, TypeIdentifier, TypeKind,
};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn allow_coercion() -> TypeConsistencyEnforcement {
    TypeConsistencyEnforcement::default() // ignore_seq=true, ignore_str=true, no widening block
}

fn strict_bounds() -> TypeConsistencyEnforcement {
    TypeConsistencyEnforcement {
        kind: 1, // ALLOW_TYPE_COERCION
        ignore_sequence_bounds: false,
        ignore_string_bounds: false,
        ignore_member_names: false,
        prevent_type_widening: false,
        force_type_validation: false,
    }
}

fn prevent_widening() -> TypeConsistencyEnforcement {
    TypeConsistencyEnforcement {
        kind: 1,
        ignore_sequence_bounds: true,
        ignore_string_bounds: true,
        ignore_member_names: false,
        prevent_type_widening: true,
        force_type_validation: false,
    }
}

fn allow_widening() -> TypeConsistencyEnforcement {
    TypeConsistencyEnforcement {
        kind: 1,
        ignore_sequence_bounds: true,
        ignore_string_bounds: true,
        ignore_member_names: false,
        prevent_type_widening: false,
        force_type_validation: false,
    }
}

fn disallow_coercion() -> TypeConsistencyEnforcement {
    TypeConsistencyEnforcement {
        kind: 0, // DISALLOW_TYPE_COERCION
        ignore_sequence_bounds: false,
        ignore_string_bounds: false,
        ignore_member_names: false,
        prevent_type_widening: true,
        force_type_validation: false,
    }
}

fn plain_seq_small(bound: u8) -> TypeIdentifier {
    TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Complete,
            element_flags: CollectionElementFlag::empty(),
        },
        bound,
        element_identifier: Box::new(TypeIdentifier::TK_INT32),
    })
}

fn plain_seq_large(bound: u32) -> TypeIdentifier {
    TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Complete,
            element_flags: CollectionElementFlag::empty(),
        },
        bound,
        element_identifier: Box::new(TypeIdentifier::TK_INT32),
    })
}

// --------------------------------------------------------------------------
// ignore_sequence_bounds tests
// --------------------------------------------------------------------------

/// Default policy (ignore_sequence_bounds=true): bound mismatch must not block.
/// Writer has smaller bound (10) than reader (100) -- with ignore_sequence_bounds=true
/// (default), this must be compatible.
#[test]
fn test_ignore_sequence_bounds_true_allows_bound_mismatch() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };

    let make_struct_with_seq_member = |seq: TypeIdentifier| {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("S"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: seq,
                },
                detail: CompleteMemberDetail::new("data"),
            }],
        })
    };

    let w_obj = make_struct_with_seq_member(plain_seq_small(10));
    let r_obj = make_struct_with_seq_member(plain_seq_small(100));

    // With default policy (ignore_sequence_bounds=true): compatible.
    assert!(
        Matcher::is_type_compatible_with_policy(Some(&w_obj), Some(&r_obj), "", "", None),
        "ignore_sequence_bounds=true must allow bound mismatch (writer=10 reader=100)"
    );
}

/// ignore_sequence_bounds=false: writer bound > reader bound must be rejected.
#[test]
fn test_ignore_sequence_bounds_false_rejects_bound_mismatch() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };

    let make_struct_with_seq_member = |seq: TypeIdentifier| {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("S"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: seq,
                },
                detail: CompleteMemberDetail::new("data"),
            }],
        })
    };

    // Writer has bound=200 (Large), reader has bound=100 (Large): writer > reader.
    let w_obj = make_struct_with_seq_member(plain_seq_large(200));
    let r_obj = make_struct_with_seq_member(plain_seq_large(100));

    let policy = strict_bounds(); // ignore_sequence_bounds=false
    assert!(
        !Matcher::is_type_compatible_with_policy(Some(&w_obj), Some(&r_obj), "", "", Some(&policy)),
        "ignore_sequence_bounds=false must reject writer.bound(200) > reader.bound(100)"
    );
}

/// ignore_sequence_bounds=false: writer bound <= reader bound must be allowed.
#[test]
fn test_ignore_sequence_bounds_false_allows_writer_le_reader() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };

    let make_struct_with_seq_member = |seq: TypeIdentifier| {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("S"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: seq,
                },
                detail: CompleteMemberDetail::new("data"),
            }],
        })
    };

    let w_obj = make_struct_with_seq_member(plain_seq_large(50));
    let r_obj = make_struct_with_seq_member(plain_seq_large(100));

    let policy = strict_bounds();
    assert!(
        Matcher::is_type_compatible_with_policy(Some(&w_obj), Some(&r_obj), "", "", Some(&policy)),
        "ignore_sequence_bounds=false must allow writer.bound(50) <= reader.bound(100)"
    );
}

// --------------------------------------------------------------------------
// prevent_type_widening tests
// --------------------------------------------------------------------------

/// prevent_type_widening=false (default): uint8 is assignable to uint16 (widening).
#[test]
fn test_prevent_type_widening_false_allows_uint8_to_uint16() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };

    let make_struct_with_prim = |kind: TypeKind| {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("P"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::Primitive(kind),
                },
                detail: CompleteMemberDetail::new("val"),
            }],
        })
    };

    let w_obj = make_struct_with_prim(TypeKind::TK_UINT8);
    let r_obj = make_struct_with_prim(TypeKind::TK_UINT16);

    let policy = allow_widening();
    assert!(
        Matcher::is_type_compatible_with_policy(Some(&w_obj), Some(&r_obj), "", "", Some(&policy)),
        "prevent_type_widening=false: uint8 writer must be assignable to uint16 reader"
    );
}

/// prevent_type_widening=true: uint8 to uint16 must be rejected.
#[test]
fn test_prevent_type_widening_true_rejects_uint8_to_uint16() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };

    let make_struct_with_prim = |kind: TypeKind| {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("P"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::Primitive(kind),
                },
                detail: CompleteMemberDetail::new("val"),
            }],
        })
    };

    let w_obj = make_struct_with_prim(TypeKind::TK_UINT8);
    let r_obj = make_struct_with_prim(TypeKind::TK_UINT16);

    let policy = prevent_widening();
    assert!(
        !Matcher::is_type_compatible_with_policy(Some(&w_obj), Some(&r_obj), "", "", Some(&policy)),
        "prevent_type_widening=true: uint8 writer must NOT be assignable to uint16 reader"
    );
}

/// prevent_type_widening=false: narrowing (uint16 -> uint8) must still be rejected.
#[test]
fn test_prevent_type_widening_false_rejects_narrowing() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };

    let make_struct_with_prim = |kind: TypeKind| {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("P"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::Primitive(kind),
                },
                detail: CompleteMemberDetail::new("val"),
            }],
        })
    };

    let w_obj = make_struct_with_prim(TypeKind::TK_UINT16);
    let r_obj = make_struct_with_prim(TypeKind::TK_UINT8);

    // Narrowing is never allowed regardless of prevent_type_widening flag.
    let policy = allow_widening();
    assert!(
        !Matcher::is_type_compatible_with_policy(Some(&w_obj), Some(&r_obj), "", "", Some(&policy)),
        "uint16 writer must NOT be assignable to uint8 reader (narrowing not allowed)"
    );
}

/// prevent_type_widening=false: int32 writer assignable to int64 reader.
#[test]
fn test_prevent_type_widening_false_allows_int32_to_int64() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };

    let make_struct_with_prim = |kind: TypeKind| {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("P"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::Primitive(kind),
                },
                detail: CompleteMemberDetail::new("val"),
            }],
        })
    };

    let w_obj = make_struct_with_prim(TypeKind::TK_INT32);
    let r_obj = make_struct_with_prim(TypeKind::TK_INT64);

    let policy = allow_widening();
    assert!(
        Matcher::is_type_compatible_with_policy(Some(&w_obj), Some(&r_obj), "", "", Some(&policy)),
        "prevent_type_widening=false: int32 writer must be assignable to int64 reader"
    );
}

// --------------------------------------------------------------------------
// DISALLOW_TYPE_COERCION tests
// --------------------------------------------------------------------------

/// kind=DISALLOW_TYPE_COERCION: identical structs must still match.
#[test]
fn test_disallow_coercion_accepts_identical_types() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };

    let make_struct = || {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Exact"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_INT32,
                },
                detail: CompleteMemberDetail::new("x"),
            }],
        })
    };

    let obj = make_struct();
    let policy = disallow_coercion();
    assert!(
        Matcher::is_type_compatible_with_policy(
            Some(&obj),
            Some(&obj.clone()),
            "",
            "",
            Some(&policy)
        ),
        "DISALLOW_TYPE_COERCION: identical types must still be compatible"
    );
}

// --------------------------------------------------------------------------
// None policy fallback test (must behave identically to default)
// --------------------------------------------------------------------------

/// Passing None policy must behave identically to passing the spec default.
#[test]
fn test_none_policy_matches_default_policy() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };

    let make_struct_with_seq = |bound: u8| {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("S"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: plain_seq_small(bound),
                },
                detail: CompleteMemberDetail::new("data"),
            }],
        })
    };

    let w_obj = make_struct_with_seq(10);
    let r_obj = make_struct_with_seq(100);

    let with_none =
        Matcher::is_type_compatible_with_policy(Some(&w_obj), Some(&r_obj), "", "", None);
    let with_default = Matcher::is_type_compatible_with_policy(
        Some(&w_obj),
        Some(&r_obj),
        "",
        "",
        Some(&allow_coercion()),
    );
    assert_eq!(
        with_none, with_default,
        "None policy must produce the same result as the explicit spec default"
    );
}
