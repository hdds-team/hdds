// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[cfg(feature = "xtypes")]
#[test]
fn test_complete_type_object_equivalence_hash_deterministic() {
    let type_obj = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("TestStruct"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: CompleteMemberDetail::new("field1"),
        }],
    });

    let hash1 = type_obj
        .compute_equivalence_hash()
        .expect("hash computation should succeed");
    let hash2 = type_obj
        .compute_equivalence_hash()
        .expect("hash computation should succeed (second call)");

    assert_eq!(hash1, hash2);
    assert_ne!(hash1, EquivalenceHash::zero());
    assert_eq!(hash1.as_bytes().len(), 14);
}

#[cfg(feature = "xtypes")]
#[test]
fn test_complete_type_object_equivalence_hash_different_types() {
    let type_obj1 = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("TypeA"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: CompleteMemberDetail::new("field1"),
        }],
    });

    let type_obj2 = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("TypeB"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_FLOAT32,
            },
            detail: CompleteMemberDetail::new("field2"),
        }],
    });

    let hash1 = type_obj1
        .compute_equivalence_hash()
        .expect("TypeA hash computation should succeed");
    let hash2 = type_obj2
        .compute_equivalence_hash()
        .expect("TypeB hash computation should succeed");

    assert_ne!(hash1, hash2);
}
