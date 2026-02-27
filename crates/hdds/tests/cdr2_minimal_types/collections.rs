// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_minimal_sequence_type_roundtrip() {
    let seq_type = MinimalSequenceType {
        header: MinimalCollectionHeader { bound: 0 },
        element: MinimalCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_INT64,
        },
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = seq_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal SequenceType: encode should succeed");
    let decoded = MinimalSequenceType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal SequenceType: decode should succeed");

    assert_eq!(decoded.header.bound, 0);
    assert_eq!(decoded.element.type_id, TypeIdentifier::TK_INT64);
}

#[test]
fn test_minimal_type_object_sequence_roundtrip() {
    let type_obj = MinimalTypeObject::Sequence(MinimalSequenceType {
        header: MinimalCollectionHeader { bound: 1024 },
        element: MinimalCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_FLOAT64,
        },
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal TypeObject::Sequence: encode should succeed");
    let decoded = MinimalTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal TypeObject::Sequence: decode should succeed");

    assert!(matches!(decoded, MinimalTypeObject::Sequence(_)));

    if let MinimalTypeObject::Sequence(s) = decoded {
        assert_eq!(s.header.bound, 1024);
        assert_eq!(s.element.type_id, TypeIdentifier::TK_FLOAT64);
    }
}

#[test]
fn test_minimal_array_type_roundtrip() {
    let array_type = MinimalArrayType {
        header: MinimalCollectionHeader { bound: 0 },
        element: MinimalCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_FLOAT64,
        },
        bound_seq: vec![10],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = array_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal ArrayType: encode should succeed");
    let decoded = MinimalArrayType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal ArrayType: decode should succeed");

    assert_eq!(decoded.element.type_id, TypeIdentifier::TK_FLOAT64);
    assert_eq!(decoded.bound_seq, vec![10]);
}

#[test]
fn test_minimal_type_object_array_roundtrip() {
    let type_obj = MinimalTypeObject::Array(MinimalArrayType {
        header: MinimalCollectionHeader { bound: 0 },
        element: MinimalCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_FLOAT32,
        },
        bound_seq: vec![4, 4],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal TypeObject::Array: encode should succeed");
    let decoded = MinimalTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal TypeObject::Array: decode should succeed");

    assert!(matches!(decoded, MinimalTypeObject::Array(_)));

    if let MinimalTypeObject::Array(a) = decoded {
        assert_eq!(a.element.type_id, TypeIdentifier::TK_FLOAT32);
        assert_eq!(a.bound_seq, vec![4, 4]);
    }
}

#[test]
fn test_minimal_map_type_roundtrip() {
    let map_type = MinimalMapType {
        header: MinimalCollectionHeader { bound: 0 },
        key: MinimalCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_UINT64,
        },
        element: MinimalCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_FLOAT32,
        },
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = map_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal MapType: encode should succeed");
    let decoded = MinimalMapType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal MapType: decode should succeed");

    assert_eq!(decoded.header.bound, 0);
    assert_eq!(decoded.key.type_id, TypeIdentifier::TK_UINT64);
    assert_eq!(decoded.element.type_id, TypeIdentifier::TK_FLOAT32);
}

#[test]
fn test_minimal_type_object_map_roundtrip() {
    let type_obj = MinimalTypeObject::Map(MinimalMapType {
        header: MinimalCollectionHeader { bound: 64 },
        key: MinimalCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_INT32,
        },
        element: MinimalCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_BOOLEAN,
        },
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal TypeObject::Map: encode should succeed");
    let decoded = MinimalTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal TypeObject::Map: decode should succeed");

    assert!(matches!(decoded, MinimalTypeObject::Map(_)));

    if let MinimalTypeObject::Map(m) = decoded {
        assert_eq!(m.header.bound, 64);
        assert_eq!(m.key.type_id, TypeIdentifier::TK_INT32);
        assert_eq!(m.element.type_id, TypeIdentifier::TK_BOOLEAN);
    }
}
