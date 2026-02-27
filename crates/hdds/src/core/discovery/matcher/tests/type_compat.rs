// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

// Phase 9: XTypes v1.3 TypeObject compatibility tests

fn make_struct(name: &str, member_names: &[&str]) -> CompleteTypeObject {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
        TypeIdentifier,
    };
    let members = member_names
        .iter()
        .copied()
        .zip(0_u32..)
        .map(|(field, member_id)| CompleteStructMember {
            common: CommonStructMember {
                member_id,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: CompleteMemberDetail::new(field),
        })
        .collect();

    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq: members,
    })
}

#[test]
fn test_type_compatible_xtypes_same_structure() {
    let local_obj = make_struct("Point", &["x", "y"]);
    let remote_obj = local_obj.clone();

    assert!(Matcher::is_type_compatible(
        Some(&local_obj),
        Some(&remote_obj),
        "Point",
        "Point"
    ));
}

#[test]
fn test_type_compatible_xtypes_different_structure() {
    let local_obj = make_struct("Point", &["x", "y"]);
    let remote_obj = make_struct("Point3D", &["x", "y", "z"]);

    assert!(!Matcher::is_type_compatible(
        Some(&local_obj),
        Some(&remote_obj),
        "Point",
        "Point3D"
    ));
}

#[test]
fn test_type_compatible_legacy_same_name() {
    let local_type = "IDL:Point:1.0";
    let remote_type = "IDL:Point:1.0";

    assert!(Matcher::is_type_compatible(
        None,
        None,
        local_type,
        remote_type
    ));
}

#[test]
fn test_type_compatible_legacy_different_name() {
    let local_type = "IDL:Point:1.0";
    let remote_type = "IDL:Temperature:1.0";

    assert!(!Matcher::is_type_compatible(
        None,
        None,
        local_type,
        remote_type
    ));
}

#[test]
fn test_type_compatible_mixed_local_has_typeobject() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
        TypeIdentifier,
    };

    // Local uses TypeObject, remote uses legacy type name
    let local_obj = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Point"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: CompleteMemberDetail::new("x"),
        }],
    });

    assert!(Matcher::is_type_compatible(
        Some(&local_obj),
        None,
        "Point",
        "IDL:Point:1.0"
    ));
}

#[test]
fn test_type_compatible_mixed_remote_has_typeobject() {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
        TypeIdentifier,
    };

    let remote_obj = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Point"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: CompleteMemberDetail::new("x"),
        }],
    });

    assert!(Matcher::is_type_compatible(
        None,
        Some(&remote_obj),
        "IDL:Point:1.0",
        "Point"
    ));
}
