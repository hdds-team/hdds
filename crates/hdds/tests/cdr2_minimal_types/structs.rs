// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_minimal_struct_type_roundtrip() {
    let struct_type = MinimalStructType {
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
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = struct_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal StructType: encode should succeed");
    let decoded = MinimalStructType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal StructType: decode should succeed");

    assert_eq!(decoded.member_seq.len(), 1);
    assert_eq!(decoded.member_seq[0].common.member_id, 0);
}

#[test]
fn test_minimal_type_object_struct_roundtrip() {
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

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal TypeObject::Struct: encode should succeed");
    let decoded = MinimalTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal TypeObject::Struct: decode should succeed");

    assert!(matches!(decoded, MinimalTypeObject::Struct(_)));

    if let MinimalTypeObject::Struct(s) = decoded {
        assert_eq!(s.member_seq.len(), 1);
        assert_eq!(s.member_seq[0].common.member_id, 0);
    }
}
