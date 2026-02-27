// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_minimal_union_type_roundtrip() {
    let union_type = MinimalUnionType {
        union_flags: UnionTypeFlag::IS_APPENDABLE,
        header: MinimalUnionHeader {
            discriminator: TypeIdentifier::TK_INT16,
            detail: MinimalTypeDetail::new(),
        },
        member_seq: vec![
            MinimalUnionMember {
                common: CommonUnionMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_BOOLEAN,
                    label_seq: vec![0],
                },
                detail: MinimalMemberDetail::from_name("flag"),
            },
            MinimalUnionMember {
                common: CommonUnionMember {
                    member_id: 1,
                    member_flags: MemberFlag::IS_KEY,
                    member_type_id: TypeIdentifier::TK_UINT32,
                    label_seq: vec![1, 2, 3],
                },
                detail: MinimalMemberDetail::from_name("name"),
            },
        ],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = union_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal UnionType: encode should succeed");
    let decoded = MinimalUnionType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal UnionType: decode should succeed");

    assert_eq!(decoded.member_seq.len(), 2);
    assert_eq!(decoded.member_seq[0].common.member_id, 0);
    assert_eq!(decoded.member_seq[0].common.label_seq, vec![0]);
    assert_eq!(decoded.member_seq[1].common.member_id, 1);
    assert_eq!(decoded.member_seq[1].common.label_seq, vec![1, 2, 3]);
}

#[test]
fn test_minimal_type_object_union_roundtrip() {
    let type_obj = MinimalTypeObject::Union(MinimalUnionType {
        union_flags: UnionTypeFlag::IS_MUTABLE,
        header: MinimalUnionHeader {
            discriminator: TypeIdentifier::TK_UINT8,
            detail: MinimalTypeDetail::new(),
        },
        member_seq: vec![MinimalUnionMember {
            common: CommonUnionMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_FLOAT64,
                label_seq: vec![0, 1],
            },
            detail: MinimalMemberDetail::from_name("value"),
        }],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal TypeObject::Union: encode should succeed");
    let decoded = MinimalTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal TypeObject::Union: decode should succeed");

    assert!(matches!(decoded, MinimalTypeObject::Union(_)));

    if let MinimalTypeObject::Union(u) = decoded {
        assert_eq!(u.member_seq.len(), 1);
        assert_eq!(u.member_seq[0].common.member_id, 0);
        assert_eq!(u.member_seq[0].common.label_seq, vec![0, 1]);
    }
}
