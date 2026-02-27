// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_complete_enumerated_type_roundtrip() {
    let enum_type = CompleteEnumeratedType {
        header: CompleteEnumeratedHeader {
            bit_bound: 32,
            detail: CompleteTypeDetail::new("Status"),
        },
        literal_seq: vec![
            CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 0,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new("OK"),
            },
            CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 1,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new("ERROR"),
            },
        ],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = enum_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete EnumeratedType: encode should succeed");
    let decoded = CompleteEnumeratedType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete EnumeratedType: decode should succeed");

    assert_eq!(decoded.header.bit_bound, 32);
    assert_eq!(decoded.header.detail.type_name, "Status");
    assert_eq!(decoded.literal_seq.len(), 2);
    assert_eq!(decoded.literal_seq[0].common.value, 0);
    assert_eq!(decoded.literal_seq[0].detail.name, "OK");
    assert_eq!(decoded.literal_seq[1].common.value, 1);
    assert_eq!(decoded.literal_seq[1].detail.name, "ERROR");
}

#[test]
fn test_complete_type_object_enum_roundtrip() {
    let type_obj = CompleteTypeObject::Enumerated(CompleteEnumeratedType {
        header: CompleteEnumeratedHeader {
            bit_bound: 32,
            detail: CompleteTypeDetail::new("Color"),
        },
        literal_seq: vec![
            CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 0,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new("RED"),
            },
            CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 1,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new("GREEN"),
            },
            CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 2,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new("BLUE"),
            },
        ],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Enumerated: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Enumerated: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Enumerated(_)));

    if let CompleteTypeObject::Enumerated(e) = decoded {
        assert_eq!(e.header.detail.type_name, "Color");
        assert_eq!(e.literal_seq.len(), 3);
        assert_eq!(e.literal_seq[0].detail.name, "RED");
        assert_eq!(e.literal_seq[1].detail.name, "GREEN");
        assert_eq!(e.literal_seq[2].detail.name, "BLUE");
    }
}
