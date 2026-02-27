// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_complete_union_type_roundtrip() {
    let union_type = CompleteUnionType {
        union_flags: UnionTypeFlag::IS_FINAL,
        header: CompleteUnionHeader {
            discriminator: TypeIdentifier::TK_INT32,
            detail: CompleteTypeDetail::new("MyUnion"),
        },
        member_seq: vec![
            CompleteUnionMember {
                common: CommonUnionMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_FLOAT32,
                    label_seq: vec![0, 1],
                },
                detail: CompleteMemberDetail::new("x"),
            },
            CompleteUnionMember {
                common: CommonUnionMember {
                    member_id: 1,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_INT64,
                    label_seq: vec![2],
                },
                detail: CompleteMemberDetail::new("y"),
            },
        ],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = union_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete UnionType: encode should succeed");
    let decoded = CompleteUnionType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete UnionType: decode should succeed");

    assert_eq!(decoded.header.detail.type_name, "MyUnion");
    assert_eq!(decoded.member_seq.len(), 2);
    assert_eq!(decoded.member_seq[0].detail.name, "x");
    assert_eq!(decoded.member_seq[0].common.label_seq, vec![0, 1]);
    assert_eq!(decoded.member_seq[1].detail.name, "y");
    assert_eq!(decoded.member_seq[1].common.label_seq, vec![2]);
}

#[test]
fn test_complete_type_object_union_roundtrip() {
    let type_obj = CompleteTypeObject::Union(CompleteUnionType {
        union_flags: UnionTypeFlag::IS_FINAL,
        header: CompleteUnionHeader {
            discriminator: TypeIdentifier::TK_INT32,
            detail: CompleteTypeDetail::new("Variant"),
        },
        member_seq: vec![
            CompleteUnionMember {
                common: CommonUnionMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_INT32,
                    label_seq: vec![0],
                },
                detail: CompleteMemberDetail::new("int_value"),
            },
            CompleteUnionMember {
                common: CommonUnionMember {
                    member_id: 1,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_FLOAT64,
                    label_seq: vec![1],
                },
                detail: CompleteMemberDetail::new("float_value"),
            },
        ],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Union: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Union: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Union(_)));

    if let CompleteTypeObject::Union(u) = decoded {
        assert_eq!(u.header.detail.type_name, "Variant");
        assert_eq!(u.member_seq.len(), 2);
        assert_eq!(u.member_seq[0].detail.name, "int_value");
        assert_eq!(u.member_seq[1].detail.name, "float_value");
    }
}
