// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_complete_alias_type_roundtrip() {
    let alias_type = CompleteAliasType {
        alias_flags: AliasTypeFlag(0),
        header: CompleteAliasHeader {
            detail: CompleteTypeDetail::new("MyInt32"),
        },
        body: CompleteAliasBody {
            common: CommonAliasBody {
                related_flags: TypeRelationFlag(0),
                related_type: TypeIdentifier::TK_INT32,
            },
            detail: CompleteTypeDetail::new(""),
        },
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = alias_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete AliasType: encode should succeed");
    let decoded = CompleteAliasType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete AliasType: decode should succeed");

    assert_eq!(decoded.header.detail.type_name, "MyInt32");
    assert_eq!(decoded.body.common.related_type, TypeIdentifier::TK_INT32);
}

#[test]
fn test_complete_type_object_alias_roundtrip() {
    let type_obj = CompleteTypeObject::Alias(CompleteAliasType {
        alias_flags: AliasTypeFlag(0),
        header: CompleteAliasHeader {
            detail: CompleteTypeDetail::new("MyDouble"),
        },
        body: CompleteAliasBody {
            common: CommonAliasBody {
                related_flags: TypeRelationFlag(0),
                related_type: TypeIdentifier::TK_FLOAT64,
            },
            detail: CompleteTypeDetail::new("Alias for double precision"),
        },
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Alias: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Alias: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Alias(_)));

    if let CompleteTypeObject::Alias(a) = decoded {
        assert_eq!(a.header.detail.type_name, "MyDouble");
        assert_eq!(a.body.common.related_type, TypeIdentifier::TK_FLOAT64);
    }
}
