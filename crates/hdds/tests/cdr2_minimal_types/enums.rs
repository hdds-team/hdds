// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_minimal_enumerated_type_roundtrip() {
    let enum_type = MinimalEnumeratedType {
        header: MinimalEnumeratedHeader {
            bit_bound: 16,
            detail: MinimalTypeDetail::new(),
        },
        literal_seq: vec![
            MinimalEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 0,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: MinimalMemberDetail::from_name("SUCCESS"),
            },
            MinimalEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 1,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: MinimalMemberDetail::from_name("FAILURE"),
            },
        ],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = enum_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal EnumeratedType: encode should succeed");
    let decoded = MinimalEnumeratedType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal EnumeratedType: decode should succeed");

    assert_eq!(decoded.header.bit_bound, 16);
    assert_eq!(decoded.literal_seq.len(), 2);
    assert_eq!(decoded.literal_seq[0].common.value, 0);
    assert_eq!(decoded.literal_seq[1].common.value, 1);
}

#[test]
fn test_minimal_type_object_enum_roundtrip() {
    let type_obj = MinimalTypeObject::Enumerated(MinimalEnumeratedType {
        header: MinimalEnumeratedHeader {
            bit_bound: 16,
            detail: MinimalTypeDetail::new(),
        },
        literal_seq: vec![
            MinimalEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 0,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: MinimalMemberDetail::from_name("IDLE"),
            },
            MinimalEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 1,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: MinimalMemberDetail::from_name("RUNNING"),
            },
        ],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal TypeObject::Enumerated: encode should succeed");
    let decoded = MinimalTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal TypeObject::Enumerated: decode should succeed");

    assert!(matches!(decoded, MinimalTypeObject::Enumerated(_)));

    if let MinimalTypeObject::Enumerated(e) = decoded {
        assert_eq!(e.literal_seq.len(), 2);
        assert_eq!(e.literal_seq[0].common.value, 0);
        assert_eq!(e.literal_seq[1].common.value, 1);
    }
}
