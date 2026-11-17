// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The member TypeIdentifiers of a `#[derive(hdds::DDS)]` TypeObject, decoded
//! from the bytes against DDS-XTypes 1.3 and against a foreign oracle.
//!
//! A `String` member is a string TypeIdentifier, which DDS-XTypes 1.3
//! 7.3.4.4 (Annex B `union TypeIdentifier`) encodes as `TI_STRING8_SMALL`
//! (0x70) followed by an octet bound, 0 for unbounded. `TK_STRING8` (0x20) is
//! a TypeKind, not a TypeIdentifier discriminator, and a decoder refuses it.
//! A `Vec<u8>` member is `TI_PLAIN_SEQUENCE_SMALL` (0x80) with a
//! PlainCollectionHeader, an octet bound and the element identifier.
//!
//! The oracle is Eclipse Cyclone DDS 0.11.0 `idlc` on
//!
//! ```text
//! @appendable struct DeriveStr { @key string name; long long x; };
//! @appendable struct DeriveBytes { boolean b; sequence<uint8> payload; };
//! ```
//!
//! extracted with `golden/typeobject/extract_typeobjects.py`, which aborts
//! unless each object's MD5 is its EquivalenceHash.
//!
//! Member flags: every member carries TRY_CONSTRUCT1, DISCARD, the default
//! try-construct behavior (7.2.2.7; Annex B `bitmask MemberFlag`: "T1 | 00 =
//! INVALID, 01 = DISCARD"), and a key member also IS_MUST_UNDERSTAND
//! (7.2.2.4.4.4.8: key members "shall always have their 'must understand'
//! attribute set to true"). Cyclone writes the key member without that bit
//! (0x0021), so the objects are compared byte for byte with it cleared.

#![cfg(feature = "xtypes")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use hdds::xtypes::{CompleteTypeObject, MemberFlag, TypeIdentifier};
use hdds::{Cdr2Decode, Cdr2Encode, DdsTrait};

/// Cyclone's Complete TypeObject of `DeriveStr`, from its DHEADER
/// (hash dae14a63f0eaa60e34bc5dd681fb).
const CYCLONE_DERIVE_STR: &str = "50000000f251020012000000000000000a00000044657269766553747200\
    00003000000002000000130000000000000021007000050000006e616d6500000000100000000100000001000500\
    0200000078000000";
/// Cyclone's Complete TypeObject of `DeriveBytes`, from its DHEADER
/// (hash 8c7baaa7aeb1a7c5320ea826d91c).
const CYCLONE_DERIVE_BYTES: &str = "56000000f251020014000000000000000c0000004465726976654279746573\
    00360000000200000010000000000000000100010002000000620000001a00000001000000010080f30100000d08\
    0000007061796c6f6164000000";

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct DeriveStr {
    #[key]
    name: String,
    x: i64,
}

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct DeriveBytes {
    b: bool,
    payload: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn encode(obj: &CompleteTypeObject) -> Vec<u8> {
    let mut buf = vec![0u8; obj.max_cdr2_size()];
    let mut off = 0usize;
    obj.encode_cdr2_le_at(&mut buf, &mut off).expect("encode");
    buf.truncate(off);
    buf
}

fn members(obj: &CompleteTypeObject) -> Vec<(String, TypeIdentifier)> {
    match obj {
        CompleteTypeObject::Struct(s) => s
            .member_seq
            .iter()
            .map(|m| (m.detail.name.clone(), m.common.member_type_id.clone()))
            .collect(),
        other => panic!("expected a structure, got {other:?}"),
    }
}

/// Cyclone's object, decoded by HDDS: the bytes after the DHEADER and the EK
/// octet are the CompleteTypeObject (Annex B `@appendable union TypeObject`).
fn cyclone(hex: &str) -> CompleteTypeObject {
    let bytes = unhex(hex);
    assert_eq!(bytes[4], 0xF2, "EK_COMPLETE");
    let mut off = 5usize;
    CompleteTypeObject::decode_cdr2_le_at(&bytes, &mut off).expect("decode the oracle")
}

/// The six bytes that follow member `member_id`'s CommonStructMember
/// (`member_id` u32, `member_flags` u16, then the TypeIdentifier), located
/// in the encoding by those two fields, not read back from the model.
fn member_type_id_bytes(obj: &CompleteTypeObject, encoded: &[u8], member_id: u32) -> Vec<u8> {
    let flags = match obj {
        CompleteTypeObject::Struct(s) => s.member_seq[member_id as usize].common.member_flags.0,
        other => panic!("expected a structure, got {other:?}"),
    };
    let mut pattern = member_id.to_le_bytes().to_vec();
    pattern.extend_from_slice(&flags.to_le_bytes());
    let at = encoded
        .windows(pattern.len())
        .position(|w| w == pattern.as_slice())
        .expect("the member's CommonStructMember in the encoding");
    encoded[at + 6..at + 12].to_vec()
}

#[test]
fn a_string_member_is_ti_string8_small_on_the_wire() {
    let obj = DeriveStr::get_type_object().expect("type object");
    let bytes = encode(&obj);
    let ti = member_type_id_bytes(&obj, &bytes, 0);
    assert_eq!(
        &ti[..2],
        &[0x70, 0x00],
        "the String member must be TI_STRING8_SMALL bound 0, got {ti:02x?}"
    );
    let (back, _) = CompleteTypeObject::decode_cdr2_le(&bytes)
        .expect("the derive's own TypeObject must decode with HDDS's own decoder");
    assert_eq!(back, obj);
}

#[test]
fn a_byte_vec_member_is_a_plain_sequence_of_uint8_on_the_wire() {
    let obj = DeriveBytes::get_type_object().expect("type object");
    let bytes = encode(&obj);
    let ti = member_type_id_bytes(&obj, &bytes, 1);
    // 0x80 TI_PLAIN_SEQUENCE_SMALL, 0xF3 EK_BOTH, element_flags 0x0001
    // (TRY_CONSTRUCT1, aligned to 2), bound 0, TK_UINT8 (0x0D).
    assert_eq!(
        ti,
        [0x80, 0xF3, 0x01, 0x00, 0x00, 0x0D],
        "the Vec<u8> member must be a plain sequence of uint8, got {ti:02x?}"
    );
    let (back, _) = CompleteTypeObject::decode_cdr2_le(&bytes)
        .expect("the derive's own TypeObject must decode with HDDS's own decoder");
    assert_eq!(back, obj);
}

#[test]
fn the_member_type_identifiers_are_cyclones() {
    for (ours, theirs) in [
        (
            DeriveStr::get_type_object().expect("type object"),
            cyclone(CYCLONE_DERIVE_STR),
        ),
        (
            DeriveBytes::get_type_object().expect("type object"),
            cyclone(CYCLONE_DERIVE_BYTES),
        ),
    ] {
        assert_eq!(members(&ours), members(&theirs));
    }
}

/// Our TypeObject behind the TypeObject DHEADER and the EK octet, as the
/// EquivalenceHash preimage is laid out (7.3.4.8), the inner object at
/// stream position 5.
fn wrapped(obj: &CompleteTypeObject) -> Vec<u8> {
    let mut buf = vec![0u8; 5 + obj.max_cdr2_size()];
    buf[4] = 0xF2;
    let mut off = 5usize;
    obj.encode_cdr2_le_at(&mut buf, &mut off).expect("encode");
    let size = u32::try_from(off - 4).expect("size");
    buf[..4].copy_from_slice(&size.to_le_bytes());
    buf.truncate(off);
    buf
}

/// Every member of a derived type carries TRY_CONSTRUCT1, a key member
/// also IS_KEY and IS_MUST_UNDERSTAND; with the must-understand bit
/// cleared, the whole Complete TypeObject and its hash are Cyclone's.
#[test]
fn the_member_flags_are_the_spec_ones_and_the_object_is_cyclones() {
    for (ours, oracle, hash) in [
        (
            DeriveStr::get_type_object().expect("type object"),
            CYCLONE_DERIVE_STR,
            "dae14a63f0eaa60e34bc5dd681fb",
        ),
        (
            DeriveBytes::get_type_object().expect("type object"),
            CYCLONE_DERIVE_BYTES,
            "8c7baaa7aeb1a7c5320ea826d91c",
        ),
    ] {
        let CompleteTypeObject::Struct(s) = &ours else {
            panic!("expected a structure");
        };
        for m in &s.member_seq {
            let key = m.common.member_flags.0 & MemberFlag::IS_KEY.0 != 0;
            let want = if key {
                MemberFlag::IS_KEY.0
                    | MemberFlag::IS_MUST_UNDERSTAND.0
                    | MemberFlag::TRY_CONSTRUCT1.0
            } else {
                MemberFlag::TRY_CONSTRUCT1.0
            };
            assert_eq!(m.common.member_flags.0, want, "{}", m.detail.name);
        }
        let mut cyclone_flags = ours.clone();
        if let CompleteTypeObject::Struct(s) = &mut cyclone_flags {
            for m in &mut s.member_seq {
                m.common.member_flags.0 &= !MemberFlag::IS_MUST_UNDERSTAND.0;
            }
        }
        let bytes = wrapped(&cyclone_flags);
        assert_eq!(bytes, unhex(oracle));
        let digest = <md5::Md5 as md5::Digest>::digest(&bytes);
        let hex: String = digest[..14].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, hash);
    }
}
