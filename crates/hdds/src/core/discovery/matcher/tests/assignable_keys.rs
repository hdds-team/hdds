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

fn key_member(id: u32, name: &'static str, type_id: TypeIdentifier) -> MemberSpec {
    MemberSpec {
        id,
        type_id,
        flags: MemberFlag::IS_KEY,
        name,
    }
}

fn value_member(id: u32, name: &'static str, type_id: TypeIdentifier) -> MemberSpec {
    MemberSpec {
        id,
        type_id,
        flags: MemberFlag::empty(),
        name,
    }
}

fn build_struct(name: &str, members: &[MemberSpec]) -> CompleteTypeObject {
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
        struct_flags: StructTypeFlag::IS_MUTABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq,
    })
}

#[test]
fn test_assignable_keys_identical() {
    let writer = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_different_member_id() {
    let writer = build_struct(
        "DataSample",
        &[
            key_member(0, "sensor_id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "DataSample",
        &[
            value_member(0, "sensor_id", TypeIdentifier::TK_INT32),
            key_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_different_type() {
    let writer = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_UINT64),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_count_mismatch() {
    let writer = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            key_member(1, "partition", TypeIdentifier::TK_UINT16),
            value_member(2, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_no_keys_compatible() {
    let writer = build_struct(
        "PlainType",
        &[value_member(0, "value", TypeIdentifier::TK_FLOAT32)],
    );
    let reader = writer.clone();

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_multiple_keys_compatible() {
    let writer = build_struct(
        "MultiKey",
        &[
            key_member(0, "partition", TypeIdentifier::TK_UINT16),
            key_member(1, "id", TypeIdentifier::TK_INT32),
            value_member(2, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "MultiKey",
        &[
            key_member(1, "id", TypeIdentifier::TK_INT32),
            key_member(0, "partition", TypeIdentifier::TK_UINT16),
            value_member(2, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}
