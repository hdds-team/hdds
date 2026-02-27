// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_complete_annotation_type_roundtrip() {
    let annotation_type = CompleteAnnotationType {
        header: CompleteAnnotationHeader {
            detail: CompleteTypeDetail::new("MyAnnotation"),
        },
        member_seq: vec![
            CompleteAnnotationParameter {
                common: CommonAnnotationParameter {
                    member_flags: AnnotationParameterFlag::empty(),
                    member_type_id: TypeIdentifier::TK_INT32,
                },
                name: "value".to_string(),
                default_value: Some(AnnotationParameterValue::Int32(42)),
            },
            CompleteAnnotationParameter {
                common: CommonAnnotationParameter {
                    member_flags: AnnotationParameterFlag::empty(),
                    member_type_id: TypeIdentifier::TK_BOOLEAN,
                },
                name: "enabled".to_string(),
                default_value: Some(AnnotationParameterValue::Boolean(true)),
            },
        ],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = annotation_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete AnnotationType: encode should succeed");
    let decoded = CompleteAnnotationType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete AnnotationType: decode should succeed");

    assert_eq!(decoded.header.detail.type_name, "MyAnnotation");
    assert_eq!(decoded.member_seq.len(), 2);
    assert_eq!(decoded.member_seq[0].name, "value");
    assert_eq!(
        decoded.member_seq[0].default_value,
        Some(AnnotationParameterValue::Int32(42))
    );
    assert_eq!(decoded.member_seq[1].name, "enabled");
    assert_eq!(
        decoded.member_seq[1].default_value,
        Some(AnnotationParameterValue::Boolean(true))
    );
}

#[test]
fn test_complete_type_object_annotation_roundtrip() {
    let type_obj = CompleteTypeObject::Annotation(CompleteAnnotationType {
        header: CompleteAnnotationHeader {
            detail: CompleteTypeDetail::new("Range"),
        },
        member_seq: vec![
            CompleteAnnotationParameter {
                common: CommonAnnotationParameter {
                    member_flags: AnnotationParameterFlag::empty(),
                    member_type_id: TypeIdentifier::TK_INT32,
                },
                name: "min".to_string(),
                default_value: Some(AnnotationParameterValue::Int32(0)),
            },
            CompleteAnnotationParameter {
                common: CommonAnnotationParameter {
                    member_flags: AnnotationParameterFlag::empty(),
                    member_type_id: TypeIdentifier::TK_INT32,
                },
                name: "max".to_string(),
                default_value: Some(AnnotationParameterValue::Int32(100)),
            },
        ],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Annotation: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Annotation: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Annotation(_)));

    if let CompleteTypeObject::Annotation(a) = decoded {
        assert_eq!(a.header.detail.type_name, "Range");
        assert_eq!(a.member_seq.len(), 2);
        assert_eq!(a.member_seq[0].name, "min");
        assert_eq!(
            a.member_seq[0].default_value,
            Some(AnnotationParameterValue::Int32(0))
        );
        assert_eq!(a.member_seq[1].name, "max");
        assert_eq!(
            a.member_seq[1].default_value,
            Some(AnnotationParameterValue::Int32(100))
        );
    }
}
