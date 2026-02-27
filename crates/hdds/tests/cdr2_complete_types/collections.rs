// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_complete_sequence_type_roundtrip() {
    let seq_type = CompleteSequenceType {
        header: CompleteCollectionHeader {
            bound: 100,
            detail: CompleteTypeDetail::new("PointSequence"),
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_FLOAT32,
        },
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = seq_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete SequenceType: encode should succeed");
    let decoded = CompleteSequenceType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete SequenceType: decode should succeed");

    assert_eq!(decoded.header.bound, 100);
    assert_eq!(decoded.header.detail.type_name, "PointSequence");
    assert_eq!(decoded.element.type_id, TypeIdentifier::TK_FLOAT32);
}

#[test]
fn test_complete_type_object_sequence_roundtrip() {
    let type_obj = CompleteTypeObject::Sequence(CompleteSequenceType {
        header: CompleteCollectionHeader {
            bound: 256,
            detail: CompleteTypeDetail::new("ImageData"),
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_UINT8,
        },
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Sequence: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Sequence: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Sequence(_)));

    if let CompleteTypeObject::Sequence(s) = decoded {
        assert_eq!(s.header.bound, 256);
        assert_eq!(s.header.detail.type_name, "ImageData");
        assert_eq!(s.element.type_id, TypeIdentifier::TK_UINT8);
    }
}

#[test]
fn test_complete_array_type_roundtrip() {
    let array_type = CompleteArrayType {
        header: CompleteCollectionHeader {
            bound: 0,
            detail: CompleteTypeDetail::new("Matrix3x4"),
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_INT32,
        },
        bound_seq: vec![3, 4],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = array_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete ArrayType: encode should succeed");
    let decoded = CompleteArrayType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete ArrayType: decode should succeed");

    assert_eq!(decoded.header.detail.type_name, "Matrix3x4");
    assert_eq!(decoded.element.type_id, TypeIdentifier::TK_INT32);
    assert_eq!(decoded.bound_seq, vec![3, 4]);
}

#[test]
fn test_complete_type_object_array_roundtrip() {
    let type_obj = CompleteTypeObject::Array(CompleteArrayType {
        header: CompleteCollectionHeader {
            bound: 0,
            detail: CompleteTypeDetail::new("Matrix"),
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_FLOAT32,
        },
        bound_seq: vec![3, 3],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Array: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Array: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Array(_)));

    if let CompleteTypeObject::Array(a) = decoded {
        assert_eq!(a.header.detail.type_name, "Matrix");
        assert_eq!(a.element.type_id, TypeIdentifier::TK_FLOAT32);
        assert_eq!(a.bound_seq, vec![3, 3]);
    }
}

#[test]
fn test_complete_map_type_roundtrip() {
    let map_type = CompleteMapType {
        header: CompleteCollectionHeader {
            bound: 100,
            detail: CompleteTypeDetail::new("UserScores"),
        },
        key: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_UINT64,
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_INT32,
        },
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = map_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete MapType: encode should succeed");
    let decoded = CompleteMapType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete MapType: decode should succeed");

    assert_eq!(decoded.header.bound, 100);
    assert_eq!(decoded.header.detail.type_name, "UserScores");
    assert_eq!(decoded.key.type_id, TypeIdentifier::TK_UINT64);
    assert_eq!(decoded.element.type_id, TypeIdentifier::TK_INT32);
}

#[test]
fn test_complete_type_object_map_roundtrip() {
    let type_obj = CompleteTypeObject::Map(CompleteMapType {
        header: CompleteCollectionHeader {
            bound: 256,
            detail: CompleteTypeDetail::new("SensorReadings"),
        },
        key: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_UINT32,
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_FLOAT64,
        },
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Map: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Map: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Map(_)));

    if let CompleteTypeObject::Map(m) = decoded {
        assert_eq!(m.header.bound, 256);
        assert_eq!(m.header.detail.type_name, "SensorReadings");
        assert_eq!(m.key.type_id, TypeIdentifier::TK_UINT32);
        assert_eq!(m.element.type_id, TypeIdentifier::TK_FLOAT64);
    }
}
