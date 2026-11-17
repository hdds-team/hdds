// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Golden KeyHash vectors.
//!
//! # MANIFEST
//!
//! Every expected value below comes from a source outside this module, named
//! on the test:
//!
//! - **SPEC**: DDSI-RTPS 2.5 9.6.4.8, Examples 1 to 3, which print both the
//!   serialized bytes and the KeyHash. DDS-XTypes 1.3 7.6.8 repeats them; its
//!   Example 3 declares `string<16> label` in the IDL and `string<12>` in the
//!   KeyHolder. The serialized bytes and the MD5 are the same either way,
//!   since both bounds put the maximum size above 16 (21 or 25 bytes).
//! - **REF**: an independent Python transcription of the 9.6.4.8 algorithm
//!   (`struct.pack('>...')` with alignment capped at 4, then pad or
//!   `hashlib.md5`), which reproduces the three SPEC examples byte for byte
//!   before producing anything else. It shares no code with this module.
//!   REF also gives the KeyHash of the shapes demo `ShapeType` with color
//!   "BLUE" (`@key string<128> color`): `cac217c318363f8ef1160eeedef9e886`,
//!   the MD5 of `00000005 'BLUE\0'`.
//!
//! The writer calls in each test are what generated code emits for the IDL
//! quoted on the test: the KeyHolder members, in member-id order.
//!
//! The rules each vector pins, so that breaking one rule fails a named test:
//! big endian (all); alignment capped at 4 (`align_*`, `spec_example_2`,
//! `big_key_*`); zero padding (`spec_example_2`, `align_*`); the 16/17-byte
//! boundary of the maximum size, from both sides (`string11_*`,
//! `key16_*`, `big_key_*`); the form chosen by the TYPE's maximum and not by
//! the value's length (`spec_example_3`, `unbounded_string_*`); the string
//! length counting its NUL (`string8_*`).

use super::{KeyHolderWriter, KeyMaxSize};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run `write` on a fresh writer; return the serialization and the KeyHash.
fn key_hash(max: KeyMaxSize, write: impl FnOnce(&mut KeyHolderWriter)) -> (String, String) {
    let mut w = KeyHolderWriter::new();
    write(&mut w);
    let ser = hex(w.as_bytes());
    (ser, hex(&w.finish(max)))
}

/// SPEC Example 1: `@final struct Foo { @key long id; long x; long y; }`,
/// id = 0x12345678. Maximum 4: padded.
#[test]
fn spec_example_1_long_key_is_padded() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(4), |w| w.write_i32(0x1234_5678));
    assert_eq!(ser, "12345678");
    assert_eq!(kh, "12345678000000000000000000000000");
}

/// SPEC Example 2: `struct Foo { @key string<12> label; @key long long id;
/// long x; long y; }`, "BLUE", 0x123456789abcdef0. The `long long` is
/// aligned at 4 behind three zero bytes. Maximum 28: MD5.
#[test]
fn spec_example_2_string_and_long_long_is_md5() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(28), |w| {
        w.write_string("BLUE");
        w.write_i64(0x1234_5678_9abc_def0);
    });
    assert_eq!(ser, "00000005424c554500000000123456789abcdef0");
    assert_eq!(kh, "f91a59e32e4535d9a69cd5d9f5b6e36e");
}

/// SPEC Example 3: `@mutable struct Nested { @key long m_long; long u; long
/// w; }` and `@mutable struct Foo { @id(40) @key string<12> label; @id(30)
/// @key Nested m_nested; @id(20) long x; @id(10) long y; }`. The KeyHolder
/// puts `m_nested` (id 30) before `label` (id 40). The serialization is 13
/// bytes, yet the maximum is 21, so the KeyHash is the MD5: the form follows
/// the type, not the value.
#[test]
fn spec_example_3_member_id_order_and_md5_under_16_bytes() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(21), |w| {
        w.write_i32(0x1234_5678);
        w.write_string("BLUE");
    });
    assert_eq!(ser, "1234567800000005424c554500");
    assert_eq!(kh, "374b96e2e727237f016cc4cebb6eb71e");
}

/// REF: `@final struct LongKey { @key long id; long x; }`, id = 7.
#[test]
fn long_key_seven() {
    let (_, kh) = key_hash(KeyMaxSize::Bounded(4), |w| w.write_i32(7));
    assert_eq!(kh, "00000007000000000000000000000000");
}

/// REF: `@final struct StrKey { @key string label; long x; }`,
/// "BLUE". Unbounded: MD5 although nine bytes would fit.
#[test]
fn unbounded_string_blue_is_md5() {
    let (ser, kh) = key_hash(KeyMaxSize::Unbounded, |w| w.write_string("BLUE"));
    assert_eq!(ser, "00000005424c554500");
    assert_eq!(kh, "cac217c318363f8ef1160eeedef9e886");
}

/// REF: `@appendable struct ShapeType { @key string<128> color; ... }`,
/// "BLUE". Maximum 4 + 128 + 1 = 133: MD5, the same value as unbounded.
#[test]
fn shape_type_blue_is_the_md5_of_its_key_holder() {
    let (_, kh) = key_hash(KeyMaxSize::Bounded(133), |w| w.write_string("BLUE"));
    assert_eq!(kh, "cac217c318363f8ef1160eeedef9e886");
}

/// REF: `@final struct StrKey8 { @key string<8> label; long x; }`, "BLUE".
/// Maximum 4 + 8 + 1 = 13: padded. The length word is 5, NUL counted.
#[test]
fn string8_blue_is_padded() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(13), |w| w.write_string("BLUE"));
    assert_eq!(ser, "00000005424c554500");
    assert_eq!(kh, "00000005424c55450000000000000000");
}

/// REF: `@final struct Str11 { @key string<11> label; long x; }`, "BLUE".
/// Maximum 4 + 11 + 1 = 16, exactly the boundary: padded.
#[test]
fn string11_at_the_16_byte_boundary_is_padded() {
    let (_, kh) = key_hash(KeyMaxSize::Bounded(16), |w| w.write_string("BLUE"));
    assert_eq!(kh, "00000005424c55450000000000000000");
}

/// The other side of the boundary: a `string<12>` (maximum 17) holding the
/// same "BLUE" is hashed.
#[test]
fn string12_one_past_the_boundary_is_md5() {
    let (_, kh) = key_hash(KeyMaxSize::Bounded(17), |w| w.write_string("BLUE"));
    assert_eq!(kh, "cac217c318363f8ef1160eeedef9e886");
}

/// REF: `@final struct TwoKey { @key long a; @key short b; long x; }`,
/// a = 1, b = 2. Maximum 6.
#[test]
fn two_keys_long_then_short() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(6), |w| {
        w.write_i32(1);
        w.write_i16(2);
    });
    assert_eq!(ser, "000000010002");
    assert_eq!(kh, "00000001000200000000000000000000");
}

/// REF: `@mutable struct TwoKeyId { @id(2) @key long a; @id(1) @key short
/// b; @id(3) long x; }`, a = 1, b = 2. Member-id order writes `b` first; the
/// `long` then needs two bytes of padding. Maximum 8.
#[test]
fn two_keys_reordered_by_member_id() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(8), |w| {
        w.write_i16(2);
        w.write_i32(1);
    });
    assert_eq!(ser, "0002000000000001");
    assert_eq!(kh, "00020000000000010000000000000000");
}

/// REF: `@final struct Inner { @key long k; long u; }` and `@final struct
/// Outer { @key Inner in_; @key octet tag; long x; }`, k = 0x11223344,
/// tag = 0x55. Inner's KeyHolder is `k` alone. Maximum 5.
#[test]
fn nested_struct_contributes_its_key_members() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(5), |w| {
        w.write_i32(0x1122_3344);
        w.write_u8(0x55);
    });
    assert_eq!(ser, "1122334455");
    assert_eq!(kh, "11223344550000000000000000000000");
}

/// REF: `@final struct Inner2 { long a; long b; }` and `@final struct
/// OuterNoKey { @key Inner2 p; long x; }`, a = 1, b = 2. Inner2 has no key
/// member, so its KeyHolder keeps both. Maximum 8.
#[test]
fn nested_struct_without_keys_contributes_all_members() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(8), |w| {
        w.write_i32(1);
        w.write_i32(2);
    });
    assert_eq!(ser, "0000000100000002");
    assert_eq!(kh, "00000001000000020000000000000000");
}

/// REF: `@final struct AlignKey { @key octet t; @key long long v; }`, t = 1,
/// v = 2. PLAIN_CDR2 aligns the `long long` at 4, behind three zero bytes;
/// aligning it at 8 would give 16 bytes. Maximum 12.
#[test]
fn align_long_long_at_four() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(12), |w| {
        w.write_u8(1);
        w.write_i64(2);
    });
    assert_eq!(ser, "010000000000000000000002");
    assert_eq!(kh, "01000000000000000000000200000000");
}

/// The same rule for a `double` behind a `short`: two bytes of padding.
#[test]
fn align_double_at_four() {
    let mut w = KeyHolderWriter::new();
    w.write_i16(-1);
    w.write_f64(1.0);
    assert_eq!(hex(w.as_bytes()), "ffff00003ff0000000000000");
}

/// REF: `@final struct Key16 { @key long long a; @key long long b; }`, 1, 2.
/// Maximum 16, the boundary: padded, here with no padding left to add.
#[test]
fn key16_two_long_longs_at_the_boundary_are_padded() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(16), |w| {
        w.write_i64(1);
        w.write_i64(2);
    });
    assert_eq!(ser, "00000000000000010000000000000002");
    assert_eq!(kh, ser);
}

/// REF: `@final struct BigKey { @key long long a; @key long long b; @key
/// long c; }`, 1, 2, 3. Maximum 20, one word past the boundary: MD5.
#[test]
fn big_key_twenty_bytes_is_md5() {
    let (ser, kh) = key_hash(KeyMaxSize::Bounded(20), |w| {
        w.write_i64(1);
        w.write_i64(2);
        w.write_i32(3);
    });
    assert_eq!(ser, "0000000000000001000000000000000200000003");
    assert_eq!(kh, "8898488e44b5e511051f83ce5e917bb8");
}

/// XTypes 1.3 7.4.3.5.3 rule 4: a `wstring` length counts bytes of UTF-16
/// payload, with no terminating NUL; each code unit is big endian.
#[test]
fn wstring_counts_bytes_and_has_no_nul() {
    let mut w = KeyHolderWriter::new();
    w.write_wstring("Hi\u{e9}");
    assert_eq!(hex(w.as_bytes()), "000000060048006900e9");
}

/// A `wstring` behind an octet: its length word is aligned at 4.
#[test]
fn wstring_length_is_aligned_at_four() {
    let mut w = KeyHolderWriter::new();
    w.write_u8(1);
    w.write_wstring("A");
    assert_eq!(hex(w.as_bytes()), "01000000000000020041");
}

/// Every primitive width, back to back, so each one's alignment and byte
/// order is pinned in one place.
#[test]
fn primitives_are_big_endian_and_aligned_at_most_four() {
    let mut w = KeyHolderWriter::new();
    w.write_bool(true);
    w.write_i8(-2);
    w.write_u16(0x0102);
    w.write_u32(0x0304_0506);
    w.write_u8(7);
    w.write_f32(1.0);
    w.write_u64(0x0809_0a0b_0c0d_0e0f);
    assert_eq!(
        hex(w.as_bytes()),
        concat!(
            "01",
            "fe",
            "0102",
            "03040506",
            "07",
            "000000",
            "3f800000",
            "08090a0b0c0d0e0f"
        )
    );
}

/// A value longer than a declared maximum of at most 16 bytes is a contract
/// violation: a debug build panics, a release build hashes the bytes, never
/// truncating them into a padded form that another value shares.
#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "exceeds its declared maximum of 13")
)]
fn a_value_beyond_its_declared_bound_is_caught_or_hashed_not_truncated() {
    let (_, kh) = key_hash(KeyMaxSize::Bounded(13), |w| {
        w.write_string("TOO LONG FOR 8")
    });
    let mut md5 = KeyHolderWriter::new();
    md5.write_string("TOO LONG FOR 8");
    assert_eq!(kh, hex(&md5.finish(KeyMaxSize::Unbounded)));
}

/// `write_octets` neither aligns nor adds a length.
#[test]
fn octets_are_written_unaligned() {
    let mut w = KeyHolderWriter::new();
    w.write_u8(1);
    w.write_octets(&[2, 3]);
    w.write_octets(&[]);
    w.write_u8(4);
    assert_eq!(hex(w.as_bytes()), "01020304");
}

/// A declared maximum above 16 never trips the bound check: the form is MD5
/// whatever the length.
#[test]
fn a_value_beyond_a_maximum_above_16_is_hashed() {
    let (_, kh) = key_hash(KeyMaxSize::Bounded(17), |w| {
        w.write_string("TOO LONG FOR 12")
    });
    let mut md5 = KeyHolderWriter::new();
    md5.write_string("TOO LONG FOR 12");
    assert_eq!(kh, hex(&md5.finish(KeyMaxSize::Unbounded)));
}

/// The trait default: a type whose one hook writes its KeyHolder and returns
/// its maximum size gets the specification's KeyHash from `compute_key`; a
/// type that declares no key, or declares one and writes no KeyHolder, keeps
/// the all-zero value it always had.
mod through_the_dds_trait {
    use super::super::{KeyHolderWriter, KeyMaxSize};
    use crate::core::types::TypeDescriptor;
    use crate::dds::{CdrVersion, Result, DDS};

    static DESC: TypeDescriptor = TypeDescriptor {
        type_id: 0,
        type_name: "KeyHashProbe",
        size_bytes: 0,
        alignment: 4,
        is_variable_size: true,
        fields: &[],
    };

    /// `struct Shape { @key string<128> color; long x; }`.
    struct Shape {
        color: String,
        x: i32,
    }

    impl DDS for Shape {
        fn type_descriptor() -> &'static TypeDescriptor {
            &DESC
        }
        fn encode(&self, _buf: &mut [u8], _version: CdrVersion) -> Result<usize> {
            Ok(0)
        }
        fn decode(_buf: &[u8], _version: CdrVersion) -> Result<Self> {
            Ok(Self {
                color: String::new(),
                x: 0,
            })
        }
        fn has_key() -> bool {
            true
        }
        fn write_key_holder(&self, w: &mut KeyHolderWriter) -> Option<KeyMaxSize> {
            w.write_string(&self.color);
            Some(KeyMaxSize::Bounded(4 + 128 + 1))
        }
    }

    /// `struct Small { @key long id; }`: maximum 4, so the padded form, which
    /// a type gets only by declaring its maximum with its members.
    struct Small {
        id: i32,
    }

    impl DDS for Small {
        fn type_descriptor() -> &'static TypeDescriptor {
            &DESC
        }
        fn encode(&self, _buf: &mut [u8], _version: CdrVersion) -> Result<usize> {
            Ok(0)
        }
        fn decode(_buf: &[u8], _version: CdrVersion) -> Result<Self> {
            Ok(Self { id: 0 })
        }
        fn has_key() -> bool {
            true
        }
        fn write_key_holder(&self, w: &mut KeyHolderWriter) -> Option<KeyMaxSize> {
            w.write_i32(self.id);
            Some(KeyMaxSize::Bounded(4))
        }
    }

    /// Declares a key and implements no KeyHolder.
    struct KeyedWithoutHolder;

    impl DDS for KeyedWithoutHolder {
        fn type_descriptor() -> &'static TypeDescriptor {
            &DESC
        }
        fn encode(&self, _buf: &mut [u8], _version: CdrVersion) -> Result<usize> {
            Ok(0)
        }
        fn decode(_buf: &[u8], _version: CdrVersion) -> Result<Self> {
            Ok(Self)
        }
        fn has_key() -> bool {
            true
        }
    }

    /// The same type without a key member.
    struct Unkeyed;

    impl DDS for Unkeyed {
        fn type_descriptor() -> &'static TypeDescriptor {
            &DESC
        }
        fn encode(&self, _buf: &mut [u8], _version: CdrVersion) -> Result<usize> {
            Ok(0)
        }
        fn decode(_buf: &[u8], _version: CdrVersion) -> Result<Self> {
            Ok(Self)
        }
    }

    #[test]
    fn default_compute_key_uses_the_hooks() {
        let blue = Shape {
            color: "BLUE".into(),
            x: 1,
        };
        assert_eq!(
            super::hex(&blue.compute_key()),
            "cac217c318363f8ef1160eeedef9e886"
        );
        let moved = Shape {
            color: "BLUE".into(),
            x: 99,
        };
        assert_eq!(moved.compute_key(), blue.compute_key());
        assert_eq!(moved.x, 99);
    }

    #[test]
    fn the_one_hook_carries_the_maximum_size() {
        assert_eq!(
            super::hex(&Small { id: 0x1234_5678 }.compute_key()),
            "12345678000000000000000000000000"
        );
    }

    /// Not the MD5 of an empty serialization (`d41d8cd9...`): a keyed type
    /// without a KeyHolder has no KeyHash, and gets the explicit zero value.
    #[test]
    fn a_keyed_type_without_a_key_holder_keeps_the_zero_hash() {
        assert_eq!(KeyedWithoutHolder.compute_key(), [0u8; 16]);
    }

    #[test]
    fn a_type_without_key_keeps_the_zero_hash() {
        assert!(!Unkeyed::has_key());
        assert_eq!(Unkeyed.compute_key(), [0u8; 16]);
    }
}

/// `#[derive(DDS)]` with `#[key]` fields: the derive emits the hook, and
/// its maximum size follows the same alignment rule. Member ids are the
/// declaration order. Expected values: REF (see the MANIFEST).
mod through_the_derive {
    use crate::dds::DDS;
    use crate::xtypes::{CompleteTypeObject, MemberFlag};

    #[derive(crate::DDS)]
    struct LongKey {
        #[key]
        id: i32,
        x: i32,
    }

    #[derive(crate::DDS)]
    struct TwoKey {
        #[key]
        a: i32,
        #[key]
        b: i16,
        x: i32,
    }

    #[derive(crate::DDS)]
    struct AlignKey {
        #[key]
        t: u8,
        #[key]
        v: i64,
    }

    /// Maximum 16 with the 4-byte cap, 20 if the `i64` were aligned at 8.
    #[derive(crate::DDS)]
    struct CapKey {
        #[key]
        t: u8,
        #[key]
        v: i64,
        #[key]
        c: i32,
    }

    #[derive(crate::DDS)]
    struct BigKey {
        #[key]
        a: i64,
        #[key]
        b: i64,
        #[key]
        c: i32,
    }

    #[derive(crate::DDS)]
    struct StrKey {
        #[key]
        label: String,
        x: i32,
    }

    #[derive(crate::DDS)]
    struct NoKey {
        x: i32,
    }

    #[test]
    fn derived_keys_give_the_reference_key_hash() {
        let hex = |k: [u8; 16]| super::hex(&k);
        assert_eq!(
            hex(LongKey {
                id: 0x1234_5678,
                x: 10
            }
            .compute_key()),
            "12345678000000000000000000000000"
        );
        assert_eq!(
            hex(TwoKey { a: 1, b: 2, x: 9 }.compute_key()),
            "00000001000200000000000000000000"
        );
        assert_eq!(
            hex(AlignKey { t: 1, v: 2 }.compute_key()),
            "01000000000000000000000200000000"
        );
        assert_eq!(
            hex(CapKey { t: 1, v: 2, c: 3 }.compute_key()),
            "01000000000000000000000200000003"
        );
        assert_eq!(
            hex(BigKey { a: 1, b: 2, c: 3 }.compute_key()),
            "8898488e44b5e511051f83ce5e917bb8"
        );
        assert_eq!(
            hex(StrKey {
                label: "BLUE".into(),
                x: 1
            }
            .compute_key()),
            "cac217c318363f8ef1160eeedef9e886"
        );
    }

    #[test]
    fn a_non_key_field_does_not_move_the_key_hash() {
        assert_eq!(
            TwoKey { a: 1, b: 2, x: 9 }.compute_key(),
            TwoKey { a: 1, b: 2, x: -9 }.compute_key()
        );
        assert!(TwoKey::has_key());
        assert!(!NoKey::has_key());
        assert_eq!(NoKey { x: 1 }.compute_key(), [0u8; 16]);
    }

    #[test]
    fn key_members_are_flagged_in_the_type_object() {
        let Some(CompleteTypeObject::Struct(st)) = TwoKey::get_type_object() else {
            panic!("struct type object");
        };
        let flags: Vec<u16> = st
            .member_seq
            .iter()
            .map(|m| m.common.member_flags.0)
            .collect();
        // Every member DISCARD (TRY_CONSTRUCT1, DDS-XTypes 1.3 7.2.2.7 and
        // Annex B MemberFlag), a key member also IS_KEY and
        // IS_MUST_UNDERSTAND (7.2.2.4.4.4.8).
        let discard = MemberFlag::TRY_CONSTRUCT1.0;
        let key = MemberFlag::IS_KEY.0 | MemberFlag::IS_MUST_UNDERSTAND.0 | discard;
        assert_eq!(flags, vec![key, key, discard]);
    }
}

/// `#[derive(DDS)]` with `#[key]`: the key-only payload of a dispose or
/// unregister, and boolean and byte-vector keys.
mod derived_key_payload_and_kinds {
    use crate::dds::{CdrVersion, DDS};

    /// Maximum 8 + 4 + 1 + 1 = 14 with a boolean at one byte: padded. A
    /// boolean counted at 4 would make it 20, hashed.
    #[derive(crate::DDS)]
    struct BoolKey {
        #[key]
        a: i64,
        #[key]
        b: i32,
        #[key]
        f: bool,
        #[key]
        g: bool,
        x: i32,
    }

    #[derive(crate::DDS)]
    struct BytesKey {
        #[key]
        data: Vec<u8>,
        x: i32,
    }

    #[derive(crate::DDS)]
    struct AlignKey {
        #[key]
        t: u8,
        #[key]
        v: i64,
        x: i32,
    }

    #[derive(crate::DDS)]
    struct NoKey {
        x: i32,
    }

    fn sample_bool() -> BoolKey {
        BoolKey {
            a: 1,
            b: 2,
            f: true,
            g: false,
            x: 9,
        }
    }

    #[test]
    fn a_boolean_key_counts_one_byte() {
        assert_eq!(
            super::hex(&sample_bool().compute_key()),
            "00000000000000010000000201000000"
        );
    }

    /// A `sequence<octet>` key: its length word, then its bytes; unbounded,
    /// so MD5 of `00000003 010203` (REF: hashlib.md5).
    #[test]
    fn a_byte_vector_key_carries_its_length() {
        let k = BytesKey {
            data: vec![1, 2, 3],
            x: 0,
        };
        assert_eq!(
            super::hex(&k.compute_key()),
            "285e10af0e0ab4c4e1939c3b0ab185c5"
        );
    }

    /// The dispose payload of a derived (@appendable) type: the key members
    /// little endian, behind a DHEADER under XCDR2 (DELIMITED_CDR) and with
    /// none under XCDR1 (PLAIN_CDR), as the D_CDR2_LE / CDR_LE encapsulation
    /// of its DATA announces (DDS-XTypes 1.3 7.4.3.1, Table 35); aligned at
    /// most at 4 under XCDR2, at their size under XCDR1; the non-key member
    /// absent.
    #[test]
    fn derived_encode_key_is_the_plain_key_members_at_the_writers_version() {
        assert_eq!(
            sample_bool().encode_key(CdrVersion::Xcdr2),
            vec![14, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0]
        );
        assert_eq!(
            BytesKey {
                data: vec![1, 2, 3],
                x: 7
            }
            .encode_key(CdrVersion::Xcdr2),
            vec![7, 0, 0, 0, 3, 0, 0, 0, 1, 2, 3]
        );
        assert_eq!(
            AlignKey { t: 1, v: 2, x: 7 }.encode_key(CdrVersion::Xcdr2),
            vec![12, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            AlignKey { t: 1, v: 2, x: 7 }.encode_key(CdrVersion::Xcdr1),
            vec![1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(NoKey { x: 1 }.encode_key(CdrVersion::Xcdr2).is_empty());
    }

    /// `{ #[key] u8; #[key] String }` and `{ #[key] u8; #[key] Vec<u8> }`:
    /// the length word of the string or byte vector is aligned at 4, in the
    /// KeyHash and in the dispose payload.
    #[derive(crate::DDS)]
    struct OctetThenString {
        #[key]
        t: u8,
        #[key]
        s: String,
    }

    #[derive(crate::DDS)]
    struct OctetThenBytes {
        #[key]
        t: u8,
        #[key]
        b: Vec<u8>,
    }

    #[test]
    fn a_length_word_after_an_octet_is_aligned_at_four() {
        let s = OctetThenString {
            t: 1,
            s: "A".into(),
        };
        let b = OctetThenBytes { t: 1, b: vec![9] };
        // 01 000000 00000002 41 00, MD5 (unbounded): REF hashlib.md5.
        assert_eq!(
            super::hex(&s.compute_key()),
            "29fa24cab53f3e8266b9cc6c68169a17"
        );
        // 01 000000 00000001 09.
        assert_eq!(
            super::hex(&b.compute_key()),
            "fb46d1b348bdd9f7d7e61da46f9733a6"
        );
        assert_eq!(
            s.encode_key(CdrVersion::Xcdr2),
            vec![10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, b'A', 0]
        );
        assert_eq!(
            b.encode_key(CdrVersion::Xcdr2),
            vec![9, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 9]
        );
    }
}

/// The writer's inline buffer and the per-thread MD5 cache change no value.
mod buffer_and_cache {
    use super::super::{md5_cache, KeyHolderWriter, KeyMaxSize};
    use super::hex;

    fn md5_form(write: impl FnOnce(&mut KeyHolderWriter)) -> [u8; 16] {
        let mut w = KeyHolderWriter::new();
        write(&mut w);
        w.finish(KeyMaxSize::Unbounded)
    }

    /// A serialization that crosses the 32 inline bytes keeps every byte,
    /// its alignment counted across the spill.
    #[test]
    fn a_serialization_spills_past_the_inline_bytes_intact() {
        for n in 25..=40 {
            let s: String = "x".repeat(n);
            let mut w = KeyHolderWriter::new();
            w.write_string(&s);
            w.write_i64(-2);
            let mut expected = Vec::new();
            expected.extend_from_slice(&u32::try_from(n + 1).expect("len").to_be_bytes());
            expected.extend_from_slice(s.as_bytes());
            expected.push(0);
            while expected.len() % 4 != 0 {
                expected.push(0);
            }
            expected.extend_from_slice(&(-2i64).to_be_bytes());
            assert_eq!(w.as_bytes(), &expected[..], "string of {n}");
            assert_eq!(
                w.finish(KeyMaxSize::Unbounded),
                md5_cache::uncached(&expected),
                "string of {n}"
            );
        }
    }

    /// Every cached answer is the uncached digest, on the first call (miss)
    /// and the second (hit), for keys below, at and above the 32 bytes an
    /// entry holds.
    #[test]
    fn cached_and_uncached_digests_agree() {
        for n in [0usize, 1, 9, 31, 32, 33, 64] {
            let bytes: Vec<u8> = (0..n)
                .map(|i| u8::try_from(i % 251).expect("byte"))
                .collect();
            let first = md5_form(|w| w.write_octets(&bytes));
            let second = md5_form(|w| w.write_octets(&bytes));
            assert_eq!(first, md5_cache::uncached(&bytes), "{n} bytes");
            assert_eq!(second, first, "{n} bytes");
        }
        // REF value, through the cache twice.
        assert_eq!(
            hex(&md5_form(|w| w.write_string("BLUE"))),
            "cac217c318363f8ef1160eeedef9e886"
        );
        assert_eq!(
            hex(&md5_form(|w| w.write_string("BLUE"))),
            "cac217c318363f8ef1160eeedef9e886"
        );
    }

    /// `{ @key long long a; @key long long b; @key octet c; }`: 17 bytes,
    /// MD5 form. A key that differs from a cached one only in its LAST byte
    /// misses and is recomputed; the cached one still hits afterwards.
    #[test]
    fn a_changed_key_misses_and_is_recomputed() {
        let key = |c: u8| {
            move |w: &mut KeyHolderWriter| {
                w.write_i64(1);
                w.write_i64(2);
                w.write_u8(c);
            }
        };
        let a = md5_form(key(3));
        let hits = md5_cache::hits();
        let b = md5_form(key(4));
        assert_eq!(md5_cache::hits(), hits, "a changed key is a miss");
        let mut expected = KeyHolderWriter::new();
        key(4)(&mut expected);
        assert_eq!(expected.as_bytes().len(), 17);
        assert_eq!(b, md5_cache::uncached(expected.as_bytes()));
        assert_ne!(a, b);
        assert_eq!(md5_form(key(3)), a);
        assert_eq!(md5_cache::hits(), hits + 1, "the first key still hits");
    }

    /// A key that is a prefix of a cached one, or extends one, is a miss:
    /// the cache compares whole serializations.
    #[test]
    fn a_prefix_or_an_extension_of_a_cached_key_misses() {
        let long = md5_form(|w| w.write_octets(&[7, 7, 7, 7, 7]));
        let short = md5_form(|w| w.write_octets(&[7, 7, 7, 7]));
        assert_eq!(short, md5_cache::uncached(&[7, 7, 7, 7]));
        assert_ne!(short, long);
        let longer = md5_form(|w| w.write_octets(&[7, 7, 7, 7, 7, 7]));
        assert_eq!(longer, md5_cache::uncached(&[7, 7, 7, 7, 7, 7]));
    }

    /// The cache is bounded: after more distinct keys than it holds, the
    /// oldest is recomputed (a miss) and still correct.
    #[test]
    fn the_cache_is_bounded_and_an_evicted_key_is_recomputed() {
        let keys: Vec<String> = (0..12).map(|i| format!("EVICT-{i:02}")).collect();
        for k in &keys {
            let _ = md5_form(|w| w.write_string(k));
        }
        let hits = md5_cache::hits();
        let again = md5_form(|w| w.write_string(&keys[0]));
        assert_eq!(md5_cache::hits(), hits, "the oldest key was evicted");
        let mut expected = KeyHolderWriter::new();
        expected.write_string(&keys[0]);
        assert_eq!(again, md5_cache::uncached(expected.as_bytes()));
        // The most recent ones are still held.
        let _ = md5_form(|w| w.write_string(&keys[11]));
        assert_eq!(md5_cache::hits(), hits + 1);
    }
}

/// The dispose payload of a derived string key under XCDR2: the DHEADER of
/// the @appendable KeyHolder, the string's length word (NUL counted), its
/// bytes and the NUL, little endian.
mod derived_string_key_payload {
    use crate::dds::{CdrVersion, DDS};

    #[derive(crate::DDS)]
    struct StrKey {
        #[key]
        label: String,
        x: i32,
    }

    #[test]
    fn derived_string_key_payload_carries_length_bytes_and_nul() {
        assert_eq!(
            StrKey {
                label: "BLUE".into(),
                x: 3
            }
            .encode_key(CdrVersion::Xcdr2),
            vec![9, 0, 0, 0, 5, 0, 0, 0, b'B', b'L', b'U', b'E', 0]
        );
    }
}
