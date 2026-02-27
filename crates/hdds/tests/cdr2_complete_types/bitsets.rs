// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_complete_bitmask_type_roundtrip() {
    let bitmask_type = CompleteBitmaskType {
        header: CompleteBitmaskHeader {
            bit_bound: 32,
            detail: CompleteTypeDetail::new("StatusFlags"),
        },
        flag_seq: vec![
            CompleteBitflag {
                common: CommonBitflag {
                    position: 0,
                    flags: BitflagFlag::empty(),
                },
                detail: CompleteMemberDetail::new("READY"),
            },
            CompleteBitflag {
                common: CommonBitflag {
                    position: 1,
                    flags: BitflagFlag::empty(),
                },
                detail: CompleteMemberDetail::new("RUNNING"),
            },
            CompleteBitflag {
                common: CommonBitflag {
                    position: 2,
                    flags: BitflagFlag::empty(),
                },
                detail: CompleteMemberDetail::new("ERROR"),
            },
        ],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = bitmask_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete BitmaskType: encode should succeed");
    let decoded = CompleteBitmaskType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete BitmaskType: decode should succeed");

    assert_eq!(decoded.header.bit_bound, 32);
    assert_eq!(decoded.header.detail.type_name, "StatusFlags");
    assert_eq!(decoded.flag_seq.len(), 3);
    assert_eq!(decoded.flag_seq[0].detail.name, "READY");
    assert_eq!(decoded.flag_seq[1].detail.name, "RUNNING");
    assert_eq!(decoded.flag_seq[2].detail.name, "ERROR");
}

#[test]
fn test_complete_type_object_bitmask_roundtrip() {
    let type_obj = CompleteTypeObject::Bitmask(CompleteBitmaskType {
        header: CompleteBitmaskHeader {
            bit_bound: 64,
            detail: CompleteTypeDetail::new("Permissions"),
        },
        flag_seq: vec![
            CompleteBitflag {
                common: CommonBitflag {
                    position: 0,
                    flags: BitflagFlag::empty(),
                },
                detail: CompleteMemberDetail::new("READ"),
            },
            CompleteBitflag {
                common: CommonBitflag {
                    position: 1,
                    flags: BitflagFlag::empty(),
                },
                detail: CompleteMemberDetail::new("WRITE"),
            },
            CompleteBitflag {
                common: CommonBitflag {
                    position: 2,
                    flags: BitflagFlag::empty(),
                },
                detail: CompleteMemberDetail::new("EXECUTE"),
            },
        ],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Bitmask: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Bitmask: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Bitmask(_)));

    if let CompleteTypeObject::Bitmask(b) = decoded {
        assert_eq!(b.header.bit_bound, 64);
        assert_eq!(b.header.detail.type_name, "Permissions");
        assert_eq!(b.flag_seq.len(), 3);
        assert_eq!(b.flag_seq[0].detail.name, "READ");
        assert_eq!(b.flag_seq[1].detail.name, "WRITE");
        assert_eq!(b.flag_seq[2].detail.name, "EXECUTE");
    }
}

#[test]
fn test_complete_bitset_type_roundtrip() {
    let bitset_type = CompleteBitsetType {
        bitset_flags: BitsetTypeFlag::empty(),
        header: CompleteBitsetHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Config"),
        },
        field_seq: vec![
            CompleteBitfield {
                common: CommonBitfield {
                    position: 0,
                    flags: BitfieldFlag::empty(),
                    bit_count: 1,
                    holder_type: TypeIdentifier::TK_BOOLEAN,
                },
                detail: CompleteMemberDetail::new("enabled"),
            },
            CompleteBitfield {
                common: CommonBitfield {
                    position: 1,
                    flags: BitfieldFlag::empty(),
                    bit_count: 3,
                    holder_type: TypeIdentifier::TK_BYTE,
                },
                detail: CompleteMemberDetail::new("priority"),
            },
        ],
    };

    let mut buf = vec![0u8; 2048];
    let encoded_len = bitset_type
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete BitsetType: encode should succeed");
    let decoded = CompleteBitsetType::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete BitsetType: decode should succeed");

    assert_eq!(decoded.header.detail.type_name, "Config");
    assert_eq!(decoded.field_seq.len(), 2);
    assert_eq!(decoded.field_seq[0].detail.name, "enabled");
    assert_eq!(decoded.field_seq[1].detail.name, "priority");
}

#[test]
fn test_complete_type_object_bitset_roundtrip() {
    let type_obj = CompleteTypeObject::Bitset(CompleteBitsetType {
        bitset_flags: BitsetTypeFlag::empty(),
        header: CompleteBitsetHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Settings"),
        },
        field_seq: vec![
            CompleteBitfield {
                common: CommonBitfield {
                    position: 0,
                    flags: BitfieldFlag::empty(),
                    bit_count: 2,
                    holder_type: TypeIdentifier::TK_UINT8,
                },
                detail: CompleteMemberDetail::new("level"),
            },
            CompleteBitfield {
                common: CommonBitfield {
                    position: 2,
                    flags: BitfieldFlag::empty(),
                    bit_count: 1,
                    holder_type: TypeIdentifier::TK_BOOLEAN,
                },
                detail: CompleteMemberDetail::new("active"),
            },
        ],
    });

    let mut buf = vec![0u8; 2048];
    let encoded_len = type_obj
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeObject::Bitset: encode should succeed");
    let decoded = CompleteTypeObject::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeObject::Bitset: decode should succeed");

    assert!(matches!(decoded, CompleteTypeObject::Bitset(_)));

    if let CompleteTypeObject::Bitset(b) = decoded {
        assert_eq!(b.header.detail.type_name, "Settings");
        assert_eq!(b.field_seq.len(), 2);
        assert_eq!(b.field_seq[0].detail.name, "level");
        assert_eq!(b.field_seq[1].detail.name, "active");
    }
}
