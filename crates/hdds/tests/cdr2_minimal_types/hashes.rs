// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[cfg(feature = "xtypes")]
#[test]
fn test_minimal_type_object_equivalence_hash() {
    let type_obj = MinimalTypeObject::Struct(MinimalStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: MinimalStructHeader {
            base_type: None,
            detail: MinimalTypeDetail::new(),
        },
        member_seq: vec![MinimalStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::IS_KEY,
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: MinimalMemberDetail::from_name("id"),
        }],
    });

    let hash = type_obj
        .compute_equivalence_hash()
        .expect("CDR2 minimal TypeObject: hash computation should succeed");

    assert_ne!(hash, EquivalenceHash::zero());
    assert_eq!(hash.as_bytes().len(), 14);

    let hash2 = type_obj
        .compute_equivalence_hash()
        .expect("CDR2 minimal TypeObject: hash computation should succeed (second call)");
    assert_eq!(hash, hash2);
}
