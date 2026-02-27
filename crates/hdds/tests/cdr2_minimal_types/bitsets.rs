// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_minimal_bitmask_type_roundtrip() {
    let bitmask_type = MinimalBitmaskType {
        header: MinimalBitmaskHeader {
            bit_bound: 16,
            detail: MinimalTypeDetail::new(),
        },
        flag_seq: vec![
            MinimalBitflag {
                common: CommonBitflag {
                    position: 0,
                    flags: BitflagFlag::empty(),
                },
                detail: MinimalMemberDetail::from_name("FLAG_A"),
            },
            MinimalBitflag {
                common: CommonBitflag {
                    position: 5,
                    flags: BitflagFlag::empty(),
                },
                detail: MinimalMemberDetail::from_name("FLAG_B"),
            },
        ],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = bitmask_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal BitmaskType: encode should succeed");
    let decoded = MinimalBitmaskType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal BitmaskType: decode should succeed");

    assert_eq!(decoded.header.bit_bound, 16);
    assert_eq!(decoded.flag_seq.len(), 2);
    assert_eq!(decoded.flag_seq[0].common.position, 0);
    assert_eq!(decoded.flag_seq[1].common.position, 5);
}

#[test]
fn test_minimal_type_object_bitmask_roundtrip() {
    let type_obj = MinimalTypeObject::Bitmask(MinimalBitmaskType {
        header: MinimalBitmaskHeader {
            bit_bound: 8,
            detail: MinimalTypeDetail::new(),
        },
        flag_seq: vec![
            MinimalBitflag {
                common: CommonBitflag {
                    position: 0,
                    flags: BitflagFlag::empty(),
                },
                detail: MinimalMemberDetail::from_name("BIT0"),
            },
            MinimalBitflag {
                common: CommonBitflag {
                    position: 7,
                    flags: BitflagFlag::empty(),
                },
                detail: MinimalMemberDetail::from_name("BIT7"),
            },
        ],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal TypeObject::Bitmask: encode should succeed");
    let decoded = MinimalTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal TypeObject::Bitmask: decode should succeed");

    assert!(matches!(decoded, MinimalTypeObject::Bitmask(_)));

    if let MinimalTypeObject::Bitmask(b) = decoded {
        assert_eq!(b.header.bit_bound, 8);
        assert_eq!(b.flag_seq.len(), 2);
        assert_eq!(b.flag_seq[0].common.position, 0);
        assert_eq!(b.flag_seq[1].common.position, 7);
    }
}

#[test]
fn test_minimal_bitset_type_roundtrip() {
    let bitset_type = MinimalBitsetType {
        bitset_flags: BitsetTypeFlag::empty(),
        header: MinimalBitsetHeader {
            base_type: Some(TypeIdentifier::TK_UINT32),
            detail: MinimalTypeDetail::new(),
        },
        field_seq: vec![MinimalBitfield {
            common: CommonBitfield {
                position: 0,
                flags: BitfieldFlag::empty(),
                bit_count: 8,
                holder_type: TypeIdentifier::TK_BYTE,
            },
            detail: MinimalMemberDetail::from_name("byte_field"),
        }],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = bitset_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal BitsetType: encode should succeed");
    let decoded = MinimalBitsetType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal BitsetType: decode should succeed");

    assert!(decoded.header.base_type.is_some());
    assert_eq!(decoded.field_seq.len(), 1);
    assert_eq!(decoded.field_seq[0].common.bit_count, 8);
}

#[test]
fn test_minimal_type_object_bitset_roundtrip() {
    let type_obj = MinimalTypeObject::Bitset(MinimalBitsetType {
        bitset_flags: BitsetTypeFlag::empty(),
        header: MinimalBitsetHeader {
            base_type: None,
            detail: MinimalTypeDetail::new(),
        },
        field_seq: vec![MinimalBitfield {
            common: CommonBitfield {
                position: 0,
                flags: BitfieldFlag::empty(),
                bit_count: 4,
                holder_type: TypeIdentifier::TK_INT16,
            },
            detail: MinimalMemberDetail::from_name("nibble"),
        }],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal TypeObject::Bitset: encode should succeed");
    let decoded = MinimalTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal TypeObject::Bitset: decode should succeed");

    assert!(matches!(decoded, MinimalTypeObject::Bitset(_)));

    if let MinimalTypeObject::Bitset(b) = decoded {
        assert_eq!(b.field_seq.len(), 1);
        assert_eq!(b.field_seq[0].common.bit_count, 4);
    }
}
