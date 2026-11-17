// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Guard for the derive's one-byte-field codegen: alignment and
//! `bool`.
//!
//! `#[derive(hdds::DDS)]` must not emit `while cursor.offset() % 1 != 0` for
//! `u8`/`i8`/`bool` fields (alignment 1), which trips clippy's `modulo_one`
//! lint (deny by default in this workspace). This struct mixes one-byte
//! fields with wider ones so the codegen path for both alignment == 1 (no
//! loop emitted) and alignment > 1 (loop kept) is exercised in one type.
//!
//! `bool` must not be treated as a generic `Primitive` calling
//! `self.field.to_le_bytes()` / `<bool>::from_le_bytes(...)`, neither of
//! which exists on `bool` (E0599). It gets its own encode/decode arms: 1 byte,
//! 0x00/0x01 on the wire, and an invalid byte is a decode error rather than silently becoming
//! `true` (mirrors `impl Cdr2Decode for bool` in
//! `hdds/src/core/ser/traits.rs`).
//!
//! No DDS participant, writer or reader: this is a pure encode/decode
//! roundtrip through the `DDS` trait.

use hdds::{CdrVersion, DdsTrait};

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct MixedByteWidths {
    enabled: bool,
    tag: i8,
    small: u8,
    count: u16,
    id: u32,
    big: i64,
    ratio: f64,
}

#[test]
fn roundtrip_preserves_one_byte_and_wider_fields() {
    let original = MixedByteWidths {
        enabled: true,
        tag: -5,
        small: 200,
        count: 4321,
        id: 0xDEAD_BEEF,
        big: -123_456_789_012,
        ratio: std::f64::consts::PI,
    };

    let mut buf = [0u8; 64];
    let written = original.encode(&mut buf, CdrVersion::Xcdr2).unwrap();
    let decoded = MixedByteWidths::decode(&buf[..written], CdrVersion::Xcdr2).unwrap();

    assert_eq!(decoded, original);
}

#[test]
fn roundtrip_boundary_values() {
    let original = MixedByteWidths {
        enabled: false,
        tag: i8::MIN,
        small: u8::MAX,
        count: u16::MAX,
        id: u32::MAX,
        big: i64::MIN,
        ratio: f64::NEG_INFINITY,
    };

    let mut buf = [0u8; 64];
    let written = original.encode(&mut buf, CdrVersion::Xcdr2).unwrap();
    let decoded = MixedByteWidths::decode(&buf[..written], CdrVersion::Xcdr2).unwrap();

    assert_eq!(decoded, original);
}

#[test]
fn roundtrip_xcdr1_version_is_also_stable() {
    // XCDR1 aligns `big` and `ratio` at 8 where XCDR2 aligns them at 4
    // (the wire layouts are pinned in `derive_xcdr_alignment.rs`); each
    // version must read back what it wrote.
    let original = MixedByteWidths {
        enabled: true,
        tag: 1,
        small: 2,
        count: 3,
        id: 4,
        big: 5,
        ratio: 6.5,
    };

    let mut buf = [0u8; 64];
    let written = original.encode(&mut buf, CdrVersion::Xcdr1).unwrap();
    let decoded = MixedByteWidths::decode(&buf[..written], CdrVersion::Xcdr1).unwrap();

    assert_eq!(decoded, original);
}

#[test]
fn bool_field_encodes_as_exact_wire_byte() {
    // `enabled` is the struct's first field, so it lands right after the
    // 4-byte DHEADER of the @appendable body under XCDR2, at offset 4.
    for (value, expected_byte) in [(true, 0x01u8), (false, 0x00u8)] {
        let original = MixedByteWidths {
            enabled: value,
            tag: 1,
            small: 2,
            count: 3,
            id: 4,
            big: 5,
            ratio: 6.5,
        };

        // Poison the buffer so a missed write would be visible instead of
        // accidentally matching the expected byte.
        let mut buf = [0xAAu8; 64];
        let written = original.encode(&mut buf, CdrVersion::Xcdr2).unwrap();
        assert_eq!(
            buf[4], expected_byte,
            "bool field at offset 4 must encode to exactly {expected_byte:#04x}"
        );

        let decoded = MixedByteWidths::decode(&buf[..written], CdrVersion::Xcdr2).unwrap();
        assert_eq!(decoded, original);
    }
}

#[test]
fn bool_field_rejects_an_invalid_wire_byte() {
    let original = MixedByteWidths {
        enabled: true,
        tag: 1,
        small: 2,
        count: 3,
        id: 4,
        big: 5,
        ratio: 6.5,
    };

    let mut buf = [0u8; 64];
    let written = original.encode(&mut buf, CdrVersion::Xcdr2).unwrap();

    // Corrupt the bool slot (offset 4, after the DHEADER) with a byte that
    // is neither 0 nor 1.
    assert_eq!(buf[4], 0x01);
    buf[4] = 0x02;

    let result = MixedByteWidths::decode(&buf[..written], CdrVersion::Xcdr2);
    assert!(
        result.is_err(),
        "an invalid boolean byte must be a decode error, not silently true"
    );
}
