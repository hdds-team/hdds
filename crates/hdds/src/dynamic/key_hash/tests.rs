// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! KeyHash of dynamic samples. The expected values are the golden vectors of
//! `crate::core::key_hash::golden_tests` (SPEC and REF sources named
//! there); here they are reached from a descriptor rather than from writer
//! calls, so these tests pin what the walker decides: which members, in what
//! order, and which maximum size.

use super::super::{
    DynamicData, DynamicValue, EnumDescriptor, EnumVariant, Extensibility, FieldDescriptor,
    PrimitiveKind, SequenceDescriptor, TypeDescriptor, TypeKind, UnionCase, UnionDescriptor,
};
use crate::core::key_hash::{KeyHolderWriter, KeyMaxSize};
use std::collections::HashMap;
use std::sync::Arc;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn prim(kind: PrimitiveKind) -> Arc<TypeDescriptor> {
    Arc::new(TypeDescriptor::primitive("p", kind))
}

fn string(max: Option<usize>) -> Arc<TypeDescriptor> {
    prim(PrimitiveKind::String { max_length: max })
}

fn field(name: &str, ty: &Arc<TypeDescriptor>) -> FieldDescriptor {
    FieldDescriptor::new(name, Arc::clone(ty))
}

fn key(name: &str, ty: &Arc<TypeDescriptor>) -> FieldDescriptor {
    field(name, ty).with_key()
}

fn st(name: &str, fields: Vec<FieldDescriptor>) -> Arc<TypeDescriptor> {
    Arc::new(TypeDescriptor::struct_type(name, fields))
}

fn val(members: Vec<(&str, DynamicValue)>) -> DynamicValue {
    DynamicValue::Struct(
        members
            .into_iter()
            .map(|(n, v)| (n.to_string(), v))
            .collect::<HashMap<_, _>>(),
    )
}

fn kh(desc: &Arc<TypeDescriptor>, value: DynamicValue) -> String {
    let data = DynamicData::from_value(desc, value).expect("value");
    hex(&data
        .compute_key_hash()
        .expect("key hash")
        .expect("keyed type"))
}

/// SPEC Example 1: `@final struct Foo { @key long id; long x; long y; }`.
#[test]
fn spec_example_1() {
    let i32_t = prim(PrimitiveKind::I32);
    let foo = st(
        "Foo",
        vec![key("id", &i32_t), field("x", &i32_t), field("y", &i32_t)],
    );
    let v = val(vec![
        ("id", DynamicValue::I32(0x1234_5678)),
        ("x", DynamicValue::I32(10)),
        ("y", DynamicValue::I32(20)),
    ]);
    assert_eq!(kh(&foo, v), "12345678000000000000000000000000");
}

/// SPEC Example 2: `struct Foo { @key string<12> label; @key long long id;
/// long x; long y; }`. The maximum, 28, comes from the descriptor.
#[test]
fn spec_example_2() {
    let i32_t = prim(PrimitiveKind::I32);
    let foo = st(
        "Foo",
        vec![
            key("label", &string(Some(12))),
            key("id", &prim(PrimitiveKind::I64)),
            field("x", &i32_t),
            field("y", &i32_t),
        ],
    );
    let v = val(vec![
        ("label", DynamicValue::String("BLUE".into())),
        ("id", DynamicValue::I64(0x1234_5678_9abc_def0)),
        ("x", DynamicValue::I32(10)),
        ("y", DynamicValue::I32(20)),
    ]);
    assert_eq!(kh(&foo, v), "f91a59e32e4535d9a69cd5d9f5b6e36e");
}

/// SPEC Example 3: two `@mutable` structs, `@id` reordering `m_nested` (30)
/// before `label` (40), the nested KeyHolder keeping `m_long` alone.
#[test]
fn spec_example_3() {
    let i32_t = prim(PrimitiveKind::I32);
    let nested = Arc::new(
        TypeDescriptor::struct_type(
            "Nested",
            vec![
                key("m_long", &i32_t),
                field("u", &i32_t),
                field("w", &i32_t),
            ],
        )
        .with_extensibility(Extensibility::Mutable),
    );
    let foo = Arc::new(
        TypeDescriptor::struct_type(
            "Foo",
            vec![
                key("label", &string(Some(12))).with_id(40),
                key("m_nested", &nested).with_id(30),
                field("x", &i32_t).with_id(20),
                field("y", &i32_t).with_id(10),
            ],
        )
        .with_extensibility(Extensibility::Mutable),
    );
    let v = val(vec![
        ("label", DynamicValue::String("BLUE".into())),
        (
            "m_nested",
            val(vec![
                ("m_long", DynamicValue::I32(0x1234_5678)),
                ("u", DynamicValue::I32(10)),
                ("w", DynamicValue::I32(20)),
            ]),
        ),
        ("x", DynamicValue::I32(100)),
        ("y", DynamicValue::I32(200)),
    ]);
    assert_eq!(kh(&foo, v), "374b96e2e727237f016cc4cebb6eb71e");
}

/// REF: `@mutable struct TwoKeyId { @id(2) @key long a; @id(1) @key short
/// b; @id(3) long x; }`: `b` first.
#[test]
fn keys_follow_member_id_not_declaration() {
    let t = Arc::new(
        TypeDescriptor::struct_type(
            "TwoKeyId",
            vec![
                key("a", &prim(PrimitiveKind::I32)).with_id(2),
                key("b", &prim(PrimitiveKind::I16)).with_id(1),
                field("x", &prim(PrimitiveKind::I32)).with_id(3),
            ],
        )
        .with_extensibility(Extensibility::Mutable),
    );
    let v = val(vec![
        ("a", DynamicValue::I32(1)),
        ("b", DynamicValue::I16(2)),
        ("x", DynamicValue::I32(3)),
    ]);
    assert_eq!(kh(&t, v), "00020000000000010000000000000000");
}

fn outer_with_inner_key() -> Arc<TypeDescriptor> {
    let inner = st(
        "Inner",
        vec![
            key("k", &prim(PrimitiveKind::I32)),
            field("u", &prim(PrimitiveKind::I32)),
        ],
    );
    st(
        "Outer",
        vec![
            key("in_", &inner),
            key("tag", &prim(PrimitiveKind::U8)),
            field("x", &prim(PrimitiveKind::I32)),
        ],
    )
}

fn outer_value(u: i32) -> DynamicValue {
    val(vec![
        (
            "in_",
            val(vec![
                ("k", DynamicValue::I32(0x1122_3344)),
                ("u", DynamicValue::I32(u)),
            ]),
        ),
        ("tag", DynamicValue::U8(0x55)),
        ("x", DynamicValue::I32(7)),
    ])
}

/// REF: a nested struct contributes its key members only, so changing its
/// non-key member leaves the KeyHash unchanged.
#[test]
fn nested_key_members_only() {
    let outer = outer_with_inner_key();
    assert_eq!(
        kh(&outer, outer_value(99)),
        "11223344550000000000000000000000"
    );
    assert_eq!(kh(&outer, outer_value(1)), kh(&outer, outer_value(99)));
}

/// REF: a nested struct with no key member contributes all of them.
#[test]
fn nested_without_keys_contributes_all_members() {
    let i32_t = prim(PrimitiveKind::I32);
    let inner = st("Inner2", vec![field("a", &i32_t), field("b", &i32_t)]);
    let outer = st("OuterNoKey", vec![key("p", &inner), field("x", &i32_t)]);
    let v = val(vec![
        (
            "p",
            val(vec![
                ("a", DynamicValue::I32(1)),
                ("b", DynamicValue::I32(2)),
            ]),
        ),
        ("x", DynamicValue::I32(9)),
    ]);
    assert_eq!(kh(&outer, v), "00000001000000020000000000000000");
}

fn long_longs(with_long: bool) -> (Arc<TypeDescriptor>, DynamicValue) {
    let i64_t = prim(PrimitiveKind::I64);
    let mut fields = vec![key("a", &i64_t), key("b", &i64_t)];
    let mut members = vec![("a", DynamicValue::I64(1)), ("b", DynamicValue::I64(2))];
    if with_long {
        fields.push(key("c", &prim(PrimitiveKind::I32)));
        members.push(("c", DynamicValue::I32(3)));
    }
    (st("K", fields), val(members))
}

/// REF: 16 bytes of maximum is padded, 20 is hashed: the boundary as the
/// descriptor's maximum size reaches it.
#[test]
fn maximum_size_boundary_from_the_descriptor() {
    let (key16, v16) = long_longs(false);
    assert_eq!(kh(&key16, v16), "00000000000000010000000000000002");
    let (big, v20) = long_longs(true);
    assert_eq!(kh(&big, v20), "8898488e44b5e511051f83ce5e917bb8");
}

/// REF: `string<11>` (maximum 16) is padded, `string<12>` (17) and an
/// unbounded string are hashed, for the same "BLUE".
#[test]
fn string_bound_decides_the_form() {
    let blue = || val(vec![("label", DynamicValue::String("BLUE".into()))]);
    let s11 = st("S11", vec![key("label", &string(Some(11)))]);
    let s12 = st("S12", vec![key("label", &string(Some(12)))]);
    let unb = st("S", vec![key("label", &string(None))]);
    assert_eq!(kh(&s11, blue()), "00000005424c55450000000000000000");
    assert_eq!(kh(&s12, blue()), "cac217c318363f8ef1160eeedef9e886");
    assert_eq!(kh(&unb, blue()), "cac217c318363f8ef1160eeedef9e886");
}

/// REF: the `long long` behind an octet is aligned at 4 in the
/// serialization and in the maximum size (12, padded).
#[test]
fn eight_byte_member_aligned_at_four() {
    let t = st(
        "AlignKey",
        vec![
            key("t", &prim(PrimitiveKind::U8)),
            key("v", &prim(PrimitiveKind::I64)),
        ],
    );
    let v = val(vec![
        ("t", DynamicValue::U8(1)),
        ("v", DynamicValue::I64(2)),
    ]);
    assert_eq!(kh(&t, v), "01000000000000000000000200000000");
}

/// A type with no key member has no KeyHash.
#[test]
fn keyless_struct_has_no_key_hash() {
    let t = st("NoKey", vec![field("x", &prim(PrimitiveKind::I32))]);
    let data = DynamicData::from_value(&t, val(vec![("x", DynamicValue::I32(1))])).expect("value");
    assert_eq!(data.compute_key_hash().expect("ok"), None);
}

fn command_union(disc_is_key: bool) -> Arc<TypeDescriptor> {
    let disc = Arc::new(TypeDescriptor::new(
        "CommandKind",
        TypeKind::Enum(EnumDescriptor::new(vec![
            EnumVariant::new("START", 0),
            EnumVariant::new("STOP", 1),
        ])),
    ));
    let mut u = UnionDescriptor::new(
        disc,
        vec![
            UnionCase::single("delay", 0, prim(PrimitiveKind::F32)),
            UnionCase::single("distance", 1, prim(PrimitiveKind::F64)),
        ],
    );
    if disc_is_key {
        u = u.with_discriminator_key();
    }
    Arc::new(TypeDescriptor::new("Command", TypeKind::Union(u)))
}

/// XTypes 1.3 7.2.2.4.7: a union member whose discriminator is not a key is
/// kept whole; one whose discriminator is a key keeps the discriminator
/// alone. The expected bytes are the writer calls the rule prescribes.
#[test]
fn union_member_kept_whole_or_reduced_to_its_key_discriminator() {
    let stop = DynamicValue::Union(1, "distance".into(), Box::new(DynamicValue::F64(2.5)));
    for disc_is_key in [false, true] {
        let t = st("Holder", vec![key("cmd", &command_union(disc_is_key))]);
        let data = DynamicData::from_value(&t, val(vec![("cmd", stop.clone())])).expect("value");
        let mut w = KeyHolderWriter::new();
        w.write_i32(1);
        let max = if disc_is_key {
            KeyMaxSize::Bounded(4)
        } else {
            w.write_f64(2.5);
            KeyMaxSize::Bounded(12)
        };
        assert_eq!(
            data.compute_key_hash().expect("ok"),
            Some(w.finish(max)),
            "discriminator is key: {disc_is_key}"
        );
    }
}

/// An enum key is written at its holder width.
#[test]
fn enum_key_at_its_holder_width() {
    let e = Arc::new(TypeDescriptor::new(
        "Small",
        TypeKind::Enum(
            EnumDescriptor::new(vec![EnumVariant::new("A", 0), EnumVariant::new("B", 3)])
                .with_underlying(PrimitiveKind::I8),
        ),
    ));
    let t = st("E", vec![key("e", &e), key("n", &prim(PrimitiveKind::I16))]);
    let v = val(vec![
        ("e", DynamicValue::Enum(3, "B".into())),
        ("n", DynamicValue::I16(-1)),
    ]);
    assert_eq!(kh(&t, v), "0300ffff000000000000000000000000");
}

/// A bounded sequence of a primitive: its length word, then its elements;
/// its maximum counts the bound.
#[test]
fn bounded_primitive_sequence_key() {
    let seq = Arc::new(TypeDescriptor::new(
        "Seq",
        TypeKind::Sequence(SequenceDescriptor::bounded(prim(PrimitiveKind::U16), 4)),
    ));
    let t = st("Q", vec![key("s", &seq)]);
    let v = val(vec![(
        "s",
        DynamicValue::Sequence(vec![DynamicValue::U16(0x0102), DynamicValue::U16(0x0304)]),
    )]);
    // Maximum 4 + 4 * 2 = 12: padded.
    assert_eq!(kh(&t, v), "00000002010203040000000000000000");
}

/// What the walker does not cover is refused, never hashed by a guess; a
/// value beyond its bound is refused too.
#[test]
fn uncovered_keys_and_out_of_bound_values_are_refused() {
    let seq_of_strings = Arc::new(TypeDescriptor::new(
        "Names",
        TypeKind::Sequence(SequenceDescriptor::unbounded(string(None))),
    ));
    let t = st("N", vec![key("names", &seq_of_strings)]);
    let data = DynamicData::from_value(
        &t,
        val(vec![(
            "names",
            DynamicValue::Sequence(vec![DynamicValue::String("a".into())]),
        )]),
    )
    .expect("value");
    assert!(data.compute_key_hash().is_err());

    let s8 = st("S8", vec![key("label", &string(Some(8)))]);
    let data = DynamicData::from_value(
        &s8,
        val(vec![("label", DynamicValue::String("NINE CHARS".into()))]),
    )
    .expect("value");
    assert!(data.compute_key_hash().is_err());
}

/// REF: `{@key octet t; @key long long v; @key long c}` 1, 2, 3. With the
/// 4-byte cap the maximum is 16 (padded); aligning the `long long` at 8
/// would make it 20 and hash it.
#[test]
fn maximum_size_caps_alignment_at_four() {
    let t = st(
        "Cap",
        vec![
            key("t", &prim(PrimitiveKind::U8)),
            key("v", &prim(PrimitiveKind::I64)),
            key("c", &prim(PrimitiveKind::I32)),
        ],
    );
    let v = val(vec![
        ("t", DynamicValue::U8(1)),
        ("v", DynamicValue::I64(2)),
        ("c", DynamicValue::I32(3)),
    ]);
    assert_eq!(kh(&t, v), "01000000000000000000000200000003");
}

/// REF: `{@key octet a; @key octet b; @key string<8> s}` 1, 2, "". The
/// string's length word is aligned at 4, so the maximum is 4 + 4 + 8 + 1 =
/// 17 and the 9-byte value is hashed; a maximum that forgot the padding (15)
/// would pad it.
#[test]
fn maximum_size_counts_alignment_padding() {
    let t = st(
        "Pad",
        vec![
            key("a", &prim(PrimitiveKind::U8)),
            key("b", &prim(PrimitiveKind::U8)),
            key("s", &string(Some(8))),
        ],
    );
    let v = val(vec![
        ("a", DynamicValue::U8(1)),
        ("b", DynamicValue::U8(2)),
        ("s", DynamicValue::String(String::new())),
    ]);
    assert_eq!(kh(&t, v), "fd13f5a663ac53fe474b8e2a4c47f0b3");
}

/// An enumerated type received as a TypeObject, `@bit_bound(bits)`, two
/// literals A = 0 and B = 3.
fn enum_from_type_object(bits: i16) -> Arc<TypeDescriptor> {
    use crate::xtypes::{
        CommonEnumeratedLiteral, CompleteEnumeratedHeader, CompleteEnumeratedLiteral,
        CompleteEnumeratedType, CompleteMemberDetail, CompleteTypeDetail, CompleteTypeObject,
        EnumeratedLiteralFlag,
    };
    let literal = |name: &str, value: i32| CompleteEnumeratedLiteral {
        common: CommonEnumeratedLiteral {
            value,
            flags: EnumeratedLiteralFlag::empty(),
        },
        detail: CompleteMemberDetail::new(name),
    };
    super::super::type_descriptor_from_xtypes(&CompleteTypeObject::Enumerated(
        CompleteEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: CompleteEnumeratedHeader {
                bit_bound: bits,
                detail: CompleteTypeDetail::new("E"),
            },
            literal_seq: vec![literal("A", 0), literal("B", 3)],
        },
    ))
}

/// A bitmask received as a TypeObject, `@bit_bound(bits)`, flags at
/// positions 0 and 1.
fn bitmask_from_type_object(bits: i16) -> Arc<TypeDescriptor> {
    use crate::xtypes::{
        BitflagFlag, CommonBitflag, CompleteBitflag, CompleteBitmaskHeader, CompleteBitmaskType,
        CompleteMemberDetail, CompleteTypeDetail, CompleteTypeObject,
    };
    let flag = |name: &str, position: u16| CompleteBitflag {
        common: CommonBitflag {
            position,
            flags: BitflagFlag(0),
        },
        detail: CompleteMemberDetail::new(name),
    };
    super::super::type_descriptor_from_xtypes(&CompleteTypeObject::Bitmask(CompleteBitmaskType {
        bitmask_flags: crate::xtypes::StructTypeFlag::empty(),
        header: CompleteBitmaskHeader {
            bit_bound: bits,
            detail: CompleteTypeDetail::new("M"),
        },
        flag_seq: vec![flag("F0", 0), flag("F1", 1)],
    }))
}

/// `{ @key E e; @key short n; }` with `e` received as a TypeObject: the enum
/// is written at the holder width its @bit_bound gives (DDS-XTypes 1.3
/// Table 40), and the maximum size follows.
#[test]
fn enum_key_from_a_type_object_uses_its_bit_bound() {
    for (bits, expected) in [
        // Int8: 03, pad, ffff: max 4, padded.
        (8, "0300ffff000000000000000000000000"),
        // Int16: 0003 ffff: max 4, padded.
        (16, "0003ffff000000000000000000000000"),
        // Int32: 00000003 ffff: max 6, padded.
        (32, "00000003ffff00000000000000000000"),
    ] {
        let t = st(
            "K",
            vec![
                key("e", &enum_from_type_object(bits)),
                key("n", &prim(PrimitiveKind::I16)),
            ],
        );
        let v = val(vec![
            ("e", DynamicValue::Enum(3, "B".into())),
            ("n", DynamicValue::I16(-1)),
        ]);
        assert_eq!(kh(&t, v), expected, "bit_bound {bits}");
    }
}

/// The same for a bitmask: UInt8 to UInt64 by @bit_bound. With 64 bits the
/// holder is 8 bytes, aligned at 4 behind the octet, and the maximum is
/// 1 + 3 + 8 = 12.
#[test]
fn bitmask_key_from_a_type_object_uses_its_bit_bound() {
    for (bits, expected) in [
        (8, "01030000000000000000000000000000"),
        (16, "01000003000000000000000000000000"),
        (32, "01000000000000030000000000000000"),
        (64, "01000000000000000000000300000000"),
    ] {
        let t = st(
            "K",
            vec![
                key("t", &prim(PrimitiveKind::U8)),
                key("m", &bitmask_from_type_object(bits)),
            ],
        );
        let v = val(vec![
            ("t", DynamicValue::U8(1)),
            ("m", DynamicValue::Enum(3, String::new())),
        ]);
        assert_eq!(kh(&t, v), expected, "bit_bound {bits}");
    }
}

/// A 64-bit bitmask key whose maximum crosses 16 only at its true width:
/// `{ @key M64 a; @key M64 b; @key octet c; }` is 8 + 8 + 1 = 17, hashed;
/// read at 4 bytes it would be 9, padded.
#[test]
fn a_64_bit_bitmask_counts_eight_bytes_in_the_maximum() {
    let m = bitmask_from_type_object(64);
    let t = st(
        "K",
        vec![
            key("a", &m),
            key("b", &m),
            key("c", &prim(PrimitiveKind::U8)),
        ],
    );
    let v = val(vec![
        ("a", DynamicValue::Enum(1, String::new())),
        ("b", DynamicValue::Enum(2, String::new())),
        ("c", DynamicValue::U8(3)),
    ]);
    let mut w = KeyHolderWriter::new();
    w.write_u64(1);
    w.write_u64(2);
    w.write_u8(3);
    assert_eq!(kh(&t, v), hex(&w.finish(KeyMaxSize::Unbounded)));
}

/// `{ @key long a; @id(10) @key long b; @key long c; }`: the ids are 0, 10,
/// 11 (previous + 1), so the KeyHolder is a, b, c. Numbering `c` by its
/// declaration index (2) would put it before `b`.
#[test]
fn an_implicit_id_after_an_explicit_one_is_previous_plus_one() {
    let i32_t = prim(PrimitiveKind::I32);
    let t = Arc::new(
        TypeDescriptor::struct_type(
            "Ids",
            vec![
                key("a", &i32_t),
                key("b", &i32_t).with_id(10),
                key("c", &i32_t),
            ],
        )
        .with_extensibility(Extensibility::Mutable),
    );
    let v = val(vec![
        ("a", DynamicValue::I32(1)),
        ("b", DynamicValue::I32(2)),
        ("c", DynamicValue::I32(3)),
    ]);
    assert_eq!(kh(&t, v), "00000001000000020000000300000000");
}

// ---------------------------------------------------------------------------
// Coverage of each rule the walker applies. Expected MD5 values: REF
// (`hashlib.md5` of the serialization written in the comment).
// ---------------------------------------------------------------------------

/// `Inner { @optional long a; long b; long c; octet d; }` under
/// `{ @key Inner p; }`: Inner has no key, so all its members, the optional
/// one behind its presence flag (XTypes 1.3 7.4.3.5.3 rule 20). Maximum
/// 1 + 3 + 4 + 4 + 4 + 1 = 17: hashed. Without the flag byte it would be 13.
fn optional_holder() -> Arc<TypeDescriptor> {
    let i32_t = prim(PrimitiveKind::I32);
    let inner = st(
        "Inner",
        vec![
            field("a", &i32_t).optional(),
            field("b", &i32_t),
            field("c", &i32_t),
            field("d", &prim(PrimitiveKind::U8)),
        ],
    );
    st("OptHolder", vec![key("p", &inner)])
}

fn optional_value(a: DynamicValue) -> DynamicValue {
    val(vec![(
        "p",
        val(vec![
            ("a", a),
            ("b", DynamicValue::I32(6)),
            ("c", DynamicValue::I32(7)),
            ("d", DynamicValue::U8(8)),
        ]),
    )])
}

#[test]
fn an_optional_member_is_written_behind_its_presence_flag() {
    let t = optional_holder();
    // 01 000000 00000005 00000006 00000007 08
    assert_eq!(
        kh(&t, optional_value(DynamicValue::I32(5))),
        "7b07f8e6f5fe12024a66b61c30fd1d91"
    );
    // 00 000000 00000006 00000007 08
    assert_eq!(
        kh(&t, optional_value(DynamicValue::Null)),
        "6c317f03f711e675f3273f1adab4c69c"
    );
}

/// `union U switch (long) { case 0: long long x; case 1: long long y; }`
/// under `{ @key U u; }`: the discriminator is not a key, so the whole
/// union. Its maximum is the discriminator plus the LARGEST case, 12, not
/// the sum of the cases (20).
#[test]
fn a_union_maximum_is_its_largest_case() {
    let i64_t = prim(PrimitiveKind::I64);
    let u = Arc::new(TypeDescriptor::new(
        "U",
        TypeKind::Union(UnionDescriptor::new(
            prim(PrimitiveKind::I32),
            vec![
                UnionCase::single("x", 0, Arc::clone(&i64_t)),
                UnionCase::single("y", 1, Arc::clone(&i64_t)),
            ],
        )),
    ));
    let t = st("UHolder", vec![key("u", &u)]);
    let v = val(vec![(
        "u",
        DynamicValue::Union(1, "y".into(), Box::new(DynamicValue::I64(2))),
    )]);
    assert_eq!(kh(&t, v), "00000001000000000000000200000000");
}

/// `{ @key sequence<long, 4> s; }`, one element: the maximum counts the
/// length word, 4 + 16 = 20, hashed (`00000001 00000007`); without it, 16.
#[test]
fn a_bounded_sequence_maximum_counts_its_length_word() {
    let seq = Arc::new(TypeDescriptor::new(
        "S4",
        TypeKind::Sequence(SequenceDescriptor::bounded(prim(PrimitiveKind::I32), 4)),
    ));
    let t = st("SHolder", vec![key("s", &seq)]);
    let v = val(vec![(
        "s",
        DynamicValue::Sequence(vec![DynamicValue::I32(7)]),
    )]);
    assert_eq!(kh(&t, v), "27decd0effc3095b674df7e4029feeba");
}

/// A sequence beyond its bound is refused.
#[test]
fn a_sequence_beyond_its_bound_is_refused() {
    let seq = Arc::new(TypeDescriptor::new(
        "S2",
        TypeKind::Sequence(SequenceDescriptor::bounded(prim(PrimitiveKind::I32), 2)),
    ));
    let t = st("SHolder", vec![key("s", &seq)]);
    let three = DynamicValue::Sequence(vec![DynamicValue::I32(1); 3]);
    let data = DynamicData::from_value(&t, val(vec![("s", three)])).expect("value");
    assert!(data.compute_key_hash().is_err());
}

/// `{ @key octet t; @key long a[3]; @key short s; }`: the array is aligned
/// at 4 in the serialization and in the maximum, 1 + 3 + 12 + 2 = 18, hashed
/// (`01 000000 00000002 00000003 00000004 0005`).
#[test]
fn an_array_is_aligned_in_the_maximum() {
    let arr = Arc::new(TypeDescriptor::new(
        "A3",
        TypeKind::Array(crate::dynamic::ArrayDescriptor::new(
            prim(PrimitiveKind::I32),
            3,
        )),
    ));
    let t = st(
        "AHolder",
        vec![
            key("t", &prim(PrimitiveKind::U8)),
            key("a", &arr),
            key("s", &prim(PrimitiveKind::I16)),
        ],
    );
    let v = val(vec![
        ("t", DynamicValue::U8(1)),
        (
            "a",
            DynamicValue::Array(vec![
                DynamicValue::I32(2),
                DynamicValue::I32(3),
                DynamicValue::I32(4),
            ]),
        ),
        ("s", DynamicValue::I16(5)),
    ]);
    assert_eq!(kh(&t, v), "6622907d7c0501f3883ae5edc623bdca");
}

/// A string exactly at its bound is accepted: `string<4>` "BLUE", maximum
/// 4 + 4 + 1 = 9, padded.
#[test]
fn a_string_at_its_bound_is_accepted() {
    let t = st("S4", vec![key("s", &string(Some(4)))]);
    let v = val(vec![("s", DynamicValue::String("BLUE".into()))]);
    assert_eq!(kh(&t, v), "00000005424c55450000000000000000");
}

/// A union topic type keyed by its discriminator has the discriminator
/// alone as KeyHolder; one whose discriminator is not a key has no KeyHash.
#[test]
fn a_top_level_union_is_keyed_by_its_key_discriminator() {
    let cases = || {
        vec![
            UnionCase::single("x", 0, prim(PrimitiveKind::F64)),
            UnionCase::single("y", 1, prim(PrimitiveKind::I32)),
        ]
    };
    let keyed = Arc::new(TypeDescriptor::new(
        "KU",
        TypeKind::Union(
            UnionDescriptor::new(prim(PrimitiveKind::I32), cases()).with_discriminator_key(),
        ),
    ));
    let value = DynamicValue::Union(1, "y".into(), Box::new(DynamicValue::I32(9)));
    assert_eq!(
        kh(&keyed, value.clone()),
        "00000001000000000000000000000000"
    );
    let unkeyed = Arc::new(TypeDescriptor::new(
        "U",
        TypeKind::Union(UnionDescriptor::new(prim(PrimitiveKind::I32), cases())),
    ));
    let data = DynamicData::from_value(&unkeyed, value).expect("value");
    assert_eq!(data.compute_key_hash().expect("ok"), None);
}

/// A boolean discriminator is written as one byte, 1 for TRUE.
#[test]
fn a_boolean_discriminator_is_written_as_its_value() {
    let u = Arc::new(TypeDescriptor::new(
        "BU",
        TypeKind::Union(UnionDescriptor::new(
            prim(PrimitiveKind::Bool),
            vec![
                UnionCase::single("on", 1, prim(PrimitiveKind::I32)),
                UnionCase::single("off", 0, prim(PrimitiveKind::U8)),
            ],
        )),
    ));
    let t = st("BHolder", vec![key("u", &u)]);
    let v = val(vec![(
        "u",
        DynamicValue::Union(1, "on".into(), Box::new(DynamicValue::I32(5))),
    )]);
    assert_eq!(kh(&t, v), "01000000000000050000000000000000");
}

/// Boolean, char and wstring key values.
#[test]
fn boolean_char_and_wstring_values() {
    let t = st(
        "V",
        vec![
            key("b", &prim(PrimitiveKind::Bool)),
            key("c", &prim(PrimitiveKind::Char)),
            key(
                "w",
                &prim(PrimitiveKind::WString {
                    max_length: Some(2),
                }),
            ),
        ],
    );
    let v = val(vec![
        ("b", DynamicValue::Bool(true)),
        ("c", DynamicValue::Char('A')),
        ("w", DynamicValue::WString("Hi".into())),
    ]);
    // 01 41 0000 00000004 0048 0069: maximum 2 + 2 + 4 + 4 = 12, padded.
    assert_eq!(kh(&t, v), "01410000000000040048006900000000");
}

/// A char beyond one byte is refused, never truncated into another key.
#[test]
fn a_char_beyond_one_byte_is_refused() {
    let t = st("C", vec![key("c", &prim(PrimitiveKind::Char))]);
    let data = DynamicData::from_value(&t, val(vec![("c", DynamicValue::Char('\u{100}'))]))
        .expect("value");
    assert!(data.compute_key_hash().is_err());
}

/// A wstring beyond its bound is refused; its maximum counts two bytes per
/// code unit: `wstring<7>` is 4 + 14 = 18, hashed (`00000002 0041`).
#[test]
fn a_wstring_bound_counts_code_units_of_two_bytes() {
    let w7 = st(
        "W7",
        vec![key(
            "w",
            &prim(PrimitiveKind::WString {
                max_length: Some(7),
            }),
        )],
    );
    let v = val(vec![("w", DynamicValue::WString("A".into()))]);
    assert_eq!(kh(&w7, v), "a0dabf750f36a5ea14e3e501070ea2a3");

    let w2 = st(
        "W2",
        vec![key(
            "w",
            &prim(PrimitiveKind::WString {
                max_length: Some(2),
            }),
        )],
    );
    let data = DynamicData::from_value(&w2, val(vec![("w", DynamicValue::WString("abc".into()))]))
        .expect("value");
    assert!(data.compute_key_hash().is_err());
}

/// A bitmask received as a TypeObject is a bitmask in the descriptor, so a
/// re-announcement carries a bitmask identity and its 8 and 16-bit holders
/// read unsigned.
#[test]
fn a_bitmask_from_a_type_object_is_marked_as_one() {
    for bits in [8, 16, 32, 64] {
        let TypeKind::Enum(e) = &bitmask_from_type_object(bits).kind else {
            panic!("bitmask descriptor");
        };
        assert!(e.is_bitmask, "bit_bound {bits}");
    }
    let TypeKind::Enum(e) = &enum_from_type_object(8).kind else {
        panic!("enum descriptor");
    };
    assert!(!e.is_bitmask);
}

/// A received enum or bitmask is announced again with the bit_bound it was
/// received with: TypeObject -> descriptor -> TypeObject keeps 8 and 16.
#[test]
fn a_received_bit_bound_survives_the_round_trip() {
    use crate::xtypes::CompleteTypeObject;
    for bits in [8i16, 16, 32] {
        let Some(CompleteTypeObject::Enumerated(e)) =
            super::super::type_descriptor_to_xtypes(&enum_from_type_object(bits))
        else {
            panic!("enumerated type object");
        };
        assert_eq!(e.header.bit_bound, bits, "enum");
    }
}

/// A bit_bound outside the specification's range (1..=32 for an enum,
/// 1..=64 for a bitmask, DDS-XTypes 1.3 7.2.2.4.1) is read as the default,
/// 32, for both: a malformed 0 is not a 64-bit holder.
#[test]
fn an_out_of_range_bit_bound_is_read_as_the_default() {
    for bits in [0i16, -1, 65] {
        let TypeKind::Enum(m) = &bitmask_from_type_object(bits).kind else {
            panic!("bitmask descriptor");
        };
        assert_eq!(m.underlying, PrimitiveKind::U32, "bitmask {bits}");
    }
    for bits in [0i16, -1, 33] {
        let TypeKind::Enum(e) = &enum_from_type_object(bits).kind else {
            panic!("enum descriptor");
        };
        assert_eq!(e.underlying, PrimitiveKind::U32, "enum {bits}");
    }
    let TypeKind::Enum(m) = &bitmask_from_type_object(64).kind else {
        panic!("bitmask descriptor");
    };
    assert_eq!(m.underlying, PrimitiveKind::U64);
}

/// The KeyHolder takes the key members in ascending member id
/// (DDS-XTypes 1.3 7.6.8), and a `@hashid` member's id is its hash whatever
/// the `@autoid` (7.3.1.2.1.1): in
/// `@final struct { @key long a; @key @hashid("x") long b; @key @id(5) long c; }`
/// the ids are 0, 0x01e4d49d, 5, so the holder is a, c, b.
#[test]
fn a_hashid_key_member_is_ordered_by_its_hash() {
    let i32_t = prim(PrimitiveKind::I32);
    let t = st(
        "HashidKeys",
        vec![
            key("a", &i32_t),
            key("b", &i32_t).with_hashid_name("x"),
            key("c", &i32_t).with_id(5),
        ],
    );
    let v = val(vec![
        ("a", DynamicValue::I32(1)),
        ("b", DynamicValue::I32(2)),
        ("c", DynamicValue::I32(3)),
    ]);
    assert_eq!(kh(&t, v), "00000001000000030000000200000000");
}
