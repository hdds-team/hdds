// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_complete_struct_type_roundtrip() {
    let struct_type = CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Temperature"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_FLOAT32,
            },
            detail: CompleteMemberDetail::new("value"),
        }],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = struct_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete StructType: encode should succeed");
    let decoded = CompleteStructType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete StructType: decode should succeed");

    assert_eq!(decoded.header.detail.type_name, "Temperature");
    assert_eq!(decoded.member_seq.len(), 1);
    assert_eq!(decoded.member_seq[0].detail.name, "value");
}

#[test]
fn test_complete_type_object_struct_roundtrip() {
    let type_obj = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Position"),
        },
        member_seq: vec![
            CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_FLOAT32,
                },
                detail: CompleteMemberDetail::new("x"),
            },
            CompleteStructMember {
                common: CommonStructMember {
                    member_id: 1,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_FLOAT32,
                },
                detail: CompleteMemberDetail::new("y"),
            },
        ],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Struct: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Struct: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Struct(_)));

    if let CompleteTypeObject::Struct(s) = decoded {
        assert_eq!(s.header.detail.type_name, "Position");
        assert_eq!(s.member_seq.len(), 2);
        assert_eq!(s.member_seq[0].detail.name, "x");
        assert_eq!(s.member_seq[1].detail.name, "y");
    }
}
