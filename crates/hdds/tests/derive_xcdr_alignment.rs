// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Wire layout of `#[derive(hdds::DDS)]` types under XCDR2 and XCDR1.
//!
//! A derived type is @appendable, the extensibility of a type that does not
//! indicate one (DDS-XTypes 1.3 7.3.1.2.1.8), so its sample body is
//! DELIMITED_CDR under XCDR2, a DHEADER then the members laid out as
//! PLAIN_CDR2, and PLAIN_CDR under XCDR1 (7.4.3.1, Table 35). 7.4.3.2.2,
//! Table 37:
//!
//! ```text
//! MAXALIGN( VERSION2) = 4
//! MAXALIGN( VERSION1) = 8
//! ALIGN(N) ... the stream is aligned to neededalign:
//!              neededalign = MIN(N, XCDR.maxalign)
//! ```
//!
//! So an 8-byte member (`i64`, `u64`, `f64`) is aligned at 4 under XCDR2 and
//! at 8 under XCDR1. Up to 1.4.x the derive was @final and aligned it at 8
//! under both, so a `{u8, i64}` carried 7 padding bytes under XCDR2 where the
//! specification puts 3.
//!
//! Every expected vector below is the body (no encapsulation header) that
//! Eclipse Cyclone DDS 0.11.0 serializes for the same IDL type, declared
//! `@appendable`, and value: `dds_stream_write_sample` on an XCDR2 and an
//! XCDR1 output stream (probe kept outside the repository, Derive.idl and
//! probe.c). Cyclone's output, verbatim:
//!
//! ```text
//! U8I64            xcdr2 0c000000110000000807060504030201
//! U8I64            xcdr1 11000000000000000807060504030201
//! U16F64U8         xcdr2 0d00000033220000000000000000f83f44
//! U16F64U8         xcdr1 3322000000000000000000000000f83f44
//! StrI64           xcdr2 14000000060000006162636465000000feffffffffffffff
//! StrI64           xcdr1 06000000616263646500000000000000feffffffffffffff
//! BoolU64BytesF64  xcdr2 1c00000001000000112233445566778803000000aabbcc00000000000000d0bf
//! BoolU64BytesF64  xcdr1 0100000000000000112233445566778803000000aabbcc00000000000000d0bf
//! ```
//!
//! The XCDR2 DHEADER counts the members' bytes and nothing after the last
//! one; under XCDR2 it sits at offset 0, so a member's alignment is the same
//! counted from the buffer or from the body. Cyclone's earlier output for the
//! same types declared `@final` was these bodies without the DHEADER, which
//! is what DELIMITED_CDR adds to PLAIN_CDR2 (7.4.3.1, spec text lines
//! 6240-6242).

use hdds::{CdrVersion, DdsTrait};

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct U8I64 {
    a: u8,
    b: i64,
}

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct U16F64U8 {
    a: u16,
    b: f64,
    c: u8,
}

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct StrI64 {
    s: String,
    b: i64,
}

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct BoolU64BytesF64 {
    f: bool,
    u: u64,
    d: Vec<u8>,
    g: f64,
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn encode<T: DdsTrait>(v: &T, version: CdrVersion) -> Vec<u8> {
    let mut buf = [0xA5u8; 128];
    let n = v.encode(&mut buf, version).expect("encode");
    buf[..n].to_vec()
}

/// Encodes `v` at `version`, compares with `expected`, and reads it back.
fn pin<T: DdsTrait + PartialEq + std::fmt::Debug>(v: &T, version: CdrVersion, expected: &str) {
    let expected = hex(expected);
    let wire = encode(v, version);
    assert_eq!(
        wire, expected,
        "{version:?} body of {v:?}:\n  got      {wire:02x?}\n  expected {expected:02x?}"
    );
    let back = T::decode(&wire, version).expect("decode");
    assert_eq!(&back, v, "{version:?} round trip");
}

fn u8_i64() -> U8I64 {
    U8I64 {
        a: 0x11,
        b: 0x0102_0304_0506_0708,
    }
}

#[test]
fn u8_then_i64_is_aligned_at_4_under_xcdr2_and_at_8_under_xcdr1() {
    pin(
        &u8_i64(),
        CdrVersion::Xcdr2,
        "0c000000 11000000 0807060504030201",
    );
    pin(
        &u8_i64(),
        CdrVersion::Xcdr1,
        "11000000 00000000 0807060504030201",
    );
}

#[test]
fn u16_f64_u8_is_aligned_at_4_under_xcdr2_and_at_8_under_xcdr1() {
    let v = U16F64U8 {
        a: 0x2233,
        b: 1.5,
        c: 0x44,
    };
    pin(
        &v,
        CdrVersion::Xcdr2,
        "0d000000 33220000 000000000000f83f 44",
    );
    pin(
        &v,
        CdrVersion::Xcdr1,
        "33220000 00000000 000000000000f83f 44",
    );
}

/// The member after a string starts where the string ends, so its padding
/// depends on the string's length: 4 + 6 = 10 octets, then 2 bytes of
/// padding to 12 (16 behind the DHEADER) under XCDR2 and 6 to 16 under
/// XCDR1.
#[test]
fn i64_after_a_string_is_aligned_at_4_under_xcdr2_and_at_8_under_xcdr1() {
    let v = StrI64 {
        s: "abcde".to_string(),
        b: -2,
    };
    pin(
        &v,
        CdrVersion::Xcdr2,
        "14000000 06000000 6162636465 00 0000 feffffffffffffff",
    );
    pin(
        &v,
        CdrVersion::Xcdr1,
        "06000000 6162636465 00 000000000000 feffffffffffffff",
    );
}

#[test]
fn bool_u64_bytes_f64_is_aligned_at_4_under_xcdr2_and_at_8_under_xcdr1() {
    let v = BoolU64BytesF64 {
        f: true,
        u: 0x8877_6655_4433_2211,
        d: vec![0xaa, 0xbb, 0xcc],
        g: -0.25,
    };
    pin(
        &v,
        CdrVersion::Xcdr2,
        "1c000000 01000000 1122334455667788 03000000 aabbcc 00 000000000000d0bf",
    );
    pin(
        &v,
        CdrVersion::Xcdr1,
        "01000000 00000000 1122334455667788 03000000 aabbcc 00 000000000000d0bf",
    );
}

/// The bytes HDDS 1.4.x emitted for `U8I64` under XCDR2: the XCDR1 layout,
/// 7 padding bytes, behind a PLAIN_CDR2 header.
const HDDS_1_4_XCDR2_U8I64: &str = "11000000 00000000 0807060504030201";

#[test]
fn the_1_4_layout_is_not_what_xcdr2_emits_any_more() {
    assert_ne!(
        encode(&u8_i64(), CdrVersion::Xcdr2),
        hex(HDDS_1_4_XCDR2_U8I64)
    );
}

/// What the wire break looks like from each side, the values the changelog
/// states, should two such endpoints exchange samples at all (they do not
/// match: a @final and an @appendable type are not assignable). A 1.5.0
/// reader of a 1.4.x XCDR2 sample takes its first word, 0x11, for a DHEADER
/// longer than the 12 bytes that follow and refuses it; a 1.4.x reader of a
/// 1.5.0 sample takes the DHEADER, 12, for `a`, then reads `b` at offset 8
/// and delivers `{ a: 0x0c, b: 0x0102030405060708 }`.
#[test]
fn across_the_break_each_side_misreads_or_refuses_the_other() {
    assert!(U8I64::decode(&hex(HDDS_1_4_XCDR2_U8I64), CdrVersion::Xcdr2).is_err());

    let from_1_5 = encode(&u8_i64(), CdrVersion::Xcdr2);
    // The 1.4.x decoder was the XCDR1 one, whatever the version.
    let misread = U8I64::decode(&from_1_5, CdrVersion::Xcdr1).expect("misread, not refused");
    assert_eq!(misread.a, 0x0c);
    assert_eq!(misread.b, 0x0102_0304_0506_0708);
}

/// A reader skips what a newer writer appended after the members it knows,
/// inside the DHEADER (DDS-XTypes 1.3 7.3.1.2.1.8 and 7.4.3.4.1), and refuses
/// a DHEADER that runs past the sample.
#[test]
fn an_appended_member_is_skipped_and_a_dheader_is_bounded() {
    let longer = hex("10000000 11000000 0807060504030201 99999999");
    assert_eq!(
        U8I64::decode(&longer, CdrVersion::Xcdr2).expect("appended member skipped"),
        u8_i64()
    );
    let past = hex("0d000000 11000000 0807060504030201");
    assert!(U8I64::decode(&past, CdrVersion::Xcdr2).is_err());
}

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct KeyU8I64 {
    #[key]
    a: u8,
    #[key]
    b: i64,
    x: i32,
}

/// The key-only payload of a dispose or unregister (`encode_key`) follows
/// the same rule as the sample: the key members of an @appendable type,
/// behind a DHEADER under XCDR2, the i64 at 4 under XCDR2 and at 8 under
/// XCDR1. Cyclone DDS 0.11, `@appendable struct { @key octet a; @key long
/// long b; long x; }` = {0x11, 0x0102030405060708, 0x55},
/// `dds_stream_extract_key_from_data` of the XCDR2 and XCDR1 sample (same
/// probe as above):
///
/// ```text
/// xcdr2 0c000000110000000807060504030201
/// xcdr1 11000000000000000807060504030201
/// ```
#[test]
fn the_key_only_payload_aligns_its_i64_by_the_version_too() {
    let v = KeyU8I64 {
        a: 0x11,
        b: 0x0102_0304_0506_0708,
        x: 0x55,
    };
    assert_eq!(
        v.encode_key(CdrVersion::Xcdr2),
        hex("0c000000 11000000 0807060504030201")
    );
    assert_eq!(
        v.encode_key(CdrVersion::Xcdr1),
        hex("11000000 00000000 0807060504030201")
    );
}

/// `payload` behind the encapsulation header `kind`, as a K=1 DATA carries
/// it.
fn encapsulated(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    out
}

/// The instance a key-only payload names is the one its sample names
/// (`key_hash_of_key_payload` == `compute_key`), at both versions, and for
/// the XCDR2 key Cyclone DDS 0.11's `dds_stream_extract_key_from_data`
/// extracts from the same sample (quoted above). Those are the bytes
/// `encode_key` writes; they come from Cyclone's key extraction in a probe,
/// not from a dispose captured on the wire (the shapes demo's tests carry
/// Cyclone dispose payloads captured on the wire).
#[test]
fn a_key_only_payload_names_the_instance_its_sample_names() {
    let v = KeyU8I64 {
        a: 0x11,
        b: 0x0102_0304_0506_0708,
        x: 0x55,
    };
    let key = v.compute_key();
    for (kind, version) in [(0x0009u16, CdrVersion::Xcdr2), (0x0001, CdrVersion::Xcdr1)] {
        let payload = encapsulated(kind, &v.encode_key(version));
        assert_eq!(
            KeyU8I64::key_hash_of_key_payload(&payload),
            Some(key),
            "{version:?}"
        );
    }
    let cyclone_xcdr2 = encapsulated(0x0009, &hex("0c000000 11000000 0807060504030201"));
    assert_eq!(KeyU8I64::key_hash_of_key_payload(&cyclone_xcdr2), Some(key));
    // The same key big endian (D_CDR2_BE): the same instance.
    let big_endian = encapsulated(0x0008, &hex("0000000c 11000000 0102030405060708"));
    assert_eq!(KeyU8I64::key_hash_of_key_payload(&big_endian), Some(key));
    let other = KeyU8I64 { a: 0x12, ..v };
    assert_ne!(
        KeyU8I64::key_hash_of_key_payload(&encapsulated(
            0x0009,
            &other.encode_key(CdrVersion::Xcdr2)
        )),
        Some(key),
        "another key names another instance"
    );

    let f = FinalU8I64 {
        a: 0x11,
        b: 0x0102_0304_0506_0708,
    };
    let payload = encapsulated(0x0007, &f.encode_key(CdrVersion::Xcdr2));
    assert_eq!(
        FinalU8I64::key_hash_of_key_payload(&payload),
        Some(f.compute_key())
    );
}

/// What the reader cannot read with certainty names no instance, and the
/// dispose falls back to its PID_KEY_HASH: an encapsulation that is not
/// CDR (0x0004, XML), the empty key a 1.4.x writer of a generated type
/// sends, a truncated key, a DHEADER past the payload, bytes after the key.
#[test]
fn an_unreadable_key_only_payload_names_no_instance() {
    let v = KeyU8I64 {
        a: 0x11,
        b: 0x0102_0304_0506_0708,
        x: 0x55,
    };
    let body = v.encode_key(CdrVersion::Xcdr2);
    assert_eq!(
        KeyU8I64::key_hash_of_key_payload(&encapsulated(0x0004, &body)),
        None
    );
    assert_eq!(
        KeyU8I64::key_hash_of_key_payload(&encapsulated(0x0009, &[])),
        None
    );
    assert_eq!(
        KeyU8I64::key_hash_of_key_payload(&encapsulated(0x0009, &body[..body.len() - 1])),
        None
    );
    let mut past = body.clone();
    past[0] = 0x10;
    assert_eq!(
        KeyU8I64::key_hash_of_key_payload(&encapsulated(0x0009, &past)),
        None
    );
    let mut trailing = body;
    trailing.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(
        KeyU8I64::key_hash_of_key_payload(&encapsulated(0x0009, &trailing)),
        None
    );
}

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct KeyStringBytes {
    #[key]
    name: String,
    #[key]
    raw: Vec<u8>,
    #[key]
    flag: bool,
    x: i32,
}

/// A string, byte-vector and bool key read back: the MD5 form (unbounded
/// key), at both versions.
#[test]
fn a_string_and_byte_vector_key_only_payload_names_its_instance() {
    let v = KeyStringBytes {
        name: "BLUE".to_string(),
        raw: vec![1, 2, 3],
        flag: true,
        x: 9,
    };
    for (kind, version) in [(0x0009u16, CdrVersion::Xcdr2), (0x0001, CdrVersion::Xcdr1)] {
        let payload = encapsulated(kind, &v.encode_key(version));
        assert_eq!(
            KeyStringBytes::key_hash_of_key_payload(&payload),
            Some(v.compute_key()),
            "{version:?}"
        );
    }
}

/// The TypeObject of a derived type declares the extensibility its bytes
/// follow: `IS_APPENDABLE` (DDS-XTypes 1.3 7.3.1.2.1.8).
#[test]
fn the_type_object_declares_appendable() {
    match U8I64::get_type_object() {
        Some(hdds::xtypes::CompleteTypeObject::Struct(s)) => {
            assert_eq!(s.struct_flags, hdds::xtypes::StructTypeFlag::IS_APPENDABLE);
        }
        other => panic!("expected a structure TypeObject, got {other:?}"),
    }
}

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
#[dds(final)]
struct FinalU8I64 {
    #[key]
    a: u8,
    b: i64,
}

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
#[dds(appendable)]
struct AppendableU8I64 {
    a: u8,
    b: i64,
}

/// `#[dds(final)]`: PLAIN_CDR2 under XCDR2 (no DHEADER), PLAIN_CDR under
/// XCDR1, `IS_FINAL` in the TypeObject, and a key-only payload without a
/// DHEADER. Cyclone DDS 0.11, `@final struct { octet a; long long b; }`
/// = {0x11, 0x0102030405060708}: XCDR2 `110000000807060504030201`, XCDR1
/// `11000000000000000807060504030201`. `#[dds(appendable)]` is the default.
#[test]
fn dds_final_and_dds_appendable_choose_the_extensibility() {
    let v = FinalU8I64 {
        a: 0x11,
        b: 0x0102_0304_0506_0708,
    };
    pin(&v, CdrVersion::Xcdr2, "11000000 0807060504030201");
    pin(&v, CdrVersion::Xcdr1, "11000000 00000000 0807060504030201");
    assert_eq!(v.encode_key(CdrVersion::Xcdr2), hex("11"));
    match FinalU8I64::get_type_object() {
        Some(hdds::xtypes::CompleteTypeObject::Struct(s)) => {
            assert_eq!(s.struct_flags, hdds::xtypes::StructTypeFlag::IS_FINAL);
        }
        other => panic!("expected a structure TypeObject, got {other:?}"),
    }
    let w = AppendableU8I64 {
        a: 0x11,
        b: 0x0102_0304_0506_0708,
    };
    pin(&w, CdrVersion::Xcdr2, "0c000000 11000000 0807060504030201");
}

/// The members are read inside the DHEADER's bound: a DHEADER that ends
/// inside `b` refuses the sample even when the buffer holds `b` past it.
#[test]
fn a_member_past_the_dheader_is_not_read() {
    let short = hex("08000000 11000000 0807060504030201");
    assert!(U8I64::decode(&short, CdrVersion::Xcdr2).is_err());
}
