// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Member headers of mutable types: XCDR1 PL_CDR parameter headers
//! (DDS-XTypes 1.3 section 7.4.1.2) and XCDR2 EMHEADER1 (7.4.3.4.2). The
//! flags HDDS writes, the flags it accepts, the unknown must-understand
//! member it refuses (7.2.2.4.4.4.6), the 28-bit member id bound, and the
//! bytes of a foreign toolchain (Cyclone DDS 0.11.0) both ways.
//!
//! The Cyclone fixture comes from a probe kept outside the repository
//! (PlProbe.idl, probe.c, build.sh, which calls `dds_stream_write_sample`
//! and `dds_stream_normalize` + `dds_stream_read_sample` under
//! DDSI_RTPS_CDR_ENC_VERSION_1). The other foreign-shaped inputs are built
//! here, header by header, from the specification text: the layout a
//! writer may choose (short or extended headers, padded or exact lengths,
//! a flag set or clear) and what a reader must do with it.

use super::*;
use crate::dds::CdrVersion;
use std::sync::Arc;

fn prim(kind: PrimitiveKind) -> Arc<TypeDescriptor> {
    Arc::new(TypeDescriptor::primitive("", kind))
}

/// `@mutable struct PlProbe { @key @id(1) long id; @id(2) short s;
/// @id(3) string name; @id(16144) long long big; @key @id(5) octet tag; }`
fn probe_desc() -> Arc<TypeDescriptor> {
    Arc::new(
        TypeDescriptor::struct_type(
            "PlProbe",
            vec![
                FieldDescriptor::new("id", prim(PrimitiveKind::I32))
                    .with_id(1)
                    .with_key(),
                FieldDescriptor::new("s", prim(PrimitiveKind::I16)).with_id(2),
                FieldDescriptor::new("name", prim(PrimitiveKind::String { max_length: None }))
                    .with_id(3),
                FieldDescriptor::new("big", prim(PrimitiveKind::I64)).with_id(16144),
                FieldDescriptor::new("tag", prim(PrimitiveKind::U8))
                    .with_id(5)
                    .with_key(),
            ],
        )
        .with_extensibility(Extensibility::Mutable),
    )
}

fn probe_sample() -> DynamicData {
    let mut data = DynamicData::new(&probe_desc());
    data.set("id", 0x1122_3344i32).expect("id");
    data.set("s", -2i16).expect("s");
    data.set("name", "hdds").expect("name");
    data.set("big", 0x0102_0304_0506_0708i64).expect("big");
    data.set("tag", 0xABu8).expect("tag");
    data
}

fn assert_probe_values(d: &DynamicData) {
    assert_eq!(d.get::<i32>("id").expect("id"), 0x1122_3344);
    assert_eq!(d.get::<i16>("s").expect("s"), -2);
    assert_eq!(d.get::<String>("name").expect("name"), "hdds");
    assert_eq!(d.get::<i64>("big").expect("big"), 0x0102_0304_0506_0708);
    assert_eq!(d.get::<u8>("tag").expect("tag"), 0xAB);
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Cyclone DDS 0.11.0 `dds_stream_write_sample` of `probe_sample()`, XCDR1
/// body without the encapsulation header. Cyclone
/// always writes the extended form, 0x7F01, and ends with 0x7F02; it does
/// NOT set FLAG_2 on its key members (only an explicit @must_understand
/// sets it), and its llength is the padded length (4 for the short, 4 for
/// the octet).
const CYCLONE_0_11_PLPROBE: &str = "017f0800010000000400000044332211\
                                    017f08000200000004000000feff0000\
                                    017f0800030000000c00000005000000\
                                    6864647300000000\
                                    017f0800103f00000800000008070605\
                                    04030201\
                                    017f08000500000004000000ab000000\
                                    027f0000";

/// What HDDS writes for `probe_sample()`: the short form where the id and
/// the length fit, FLAG_MUST_UNDERSTAND (0x4000) on the two keys, the
/// exact length, the extended form 0x7F01 for member 16144 > 0x3F00, and
/// PID_LIST_END 0x7F02. Cyclone DDS 0.11.0 decodes these bytes
/// (`dds_stream_normalize` accepts all 64, `dds_stream_read_sample` gives
/// back every value).
const HDDS_PLPROBE: &str = "0140040044332211\
                            02000200feff0000\
                            03000900050000006864647300000000\
                            017f0800103f00000800000008070605\
                            04030201\
                            05400100ab000000\
                            027f0000";

#[test]
fn decodes_the_cyclone_0_11_bytes() {
    let wire = hex(CYCLONE_0_11_PLPROBE);
    let d = decode_dynamic_with_version(&wire, &probe_desc(), CdrVersion::Xcdr1).expect("decode");
    assert_probe_values(&d);
}

#[test]
fn encodes_keys_must_understand_and_the_flagged_reserved_ids() {
    let bytes = encode_dynamic_with_version(&probe_sample(), CdrVersion::Xcdr1).expect("encode");
    assert_eq!(bytes, hex(HDDS_PLPROBE));
    let back = decode_dynamic_with_version(&bytes, &probe_desc(), CdrVersion::Xcdr1).expect("rt");
    assert_probe_values(&back);
}

/// What HDDS 1.4.x wrote for the same sample: no flag on the keys, 0x3F01
/// and 0x3F02. Still decoded (readers are robust to any setting of the
/// flag, section 7.4.1.2.1).
#[test]
fn decodes_the_1_4_x_shape() {
    let mut old = hex(HDDS_PLPROBE);
    // id 1: 0x4001 -> 0x0001; tag 5: 0x4005 -> 0x0005.
    old[1] = 0x00;
    old[53] = 0x00;
    // PID_EXTENDED 0x7F01 -> 0x3F01; PID_LIST_END 0x7F02 -> 0x3F02.
    old[33] = 0x3F;
    old[61] = 0x3F;
    assert_eq!(
        old,
        hex("0100040044332211\
             02000200feff0000\
             03000900050000006864647300000000\
             013f0800103f00000800000008070605\
             04030201\
             05000100ab000000\
             023f0000")
    );
    let d = decode_dynamic_with_version(&old, &probe_desc(), CdrVersion::Xcdr1).expect("decode");
    assert_probe_values(&d);
}

/// FLAG_2 (must-understand) and the two unspecified flags of the extended
/// member header are not part of the member id (section 7.4.1.2.2). This
/// is what Cyclone writes for an `@must_understand` member; HDDS 1.4.x's
/// struct reader compared the whole word and dropped the member.
#[test]
fn the_extended_header_flags_are_not_part_of_the_member_id() {
    let mut wire = hex(CYCLONE_0_11_PLPROBE);
    // id (member 1): FLAG_2; big (member 16144): FLAG_2 | FLAG_3 | FLAG_4.
    wire[7] = 0x40;
    let big_header = 16 + 16 + 24 + 4;
    assert_eq!(&wire[big_header..big_header + 4], &[0x10, 0x3F, 0, 0]);
    wire[big_header + 3] = 0x70;
    let d = decode_dynamic_with_version(&wire, &probe_desc(), CdrVersion::Xcdr1).expect("decode");
    assert_probe_values(&d);
}

fn two_i32(ext_id: u32) -> Arc<TypeDescriptor> {
    Arc::new(
        TypeDescriptor::struct_type(
            "Two",
            vec![
                FieldDescriptor::new("a", prim(PrimitiveKind::I32)).with_id(1),
                FieldDescriptor::new("b", prim(PrimitiveKind::I32)).with_id(ext_id),
            ],
        )
        .with_extensibility(Extensibility::Mutable),
    )
}

fn param(pid: u16, value: &[u8]) -> Vec<u8> {
    let mut v = pid.to_le_bytes().to_vec();
    v.extend((value.len() as u16).to_le_bytes());
    v.extend(value);
    v
}

fn extended(header: u32, value: &[u8]) -> Vec<u8> {
    let mut v = 0x7F01u16.to_le_bytes().to_vec();
    v.extend(8u16.to_le_bytes());
    v.extend(header.to_le_bytes());
    v.extend((value.len() as u32).to_le_bytes());
    v.extend(value);
    v
}

/// A parameter with FLAG_IMPL_EXTENSION is not a Table 34 value and not a
/// member of a user type (sections 7.4.1.2.1, 7.4.1.2.2): 0xBF02 does not
/// end the list, 0xBF01 opens no extended header, 0x8001 is not member 1,
/// an extended header with FLAG_1 is not member 0x3F03. A short 0x3F03 is
/// PID_IGNORE, not member 0x3F03. All are skipped by their length. The
/// real members come first, the impostors after them, so an impostor taken
/// for a member would overwrite it; 0xBF02 comes before everything, so
/// taking it for the end would lose both members.
#[test]
fn implementation_extensions_and_reserved_ids_are_skipped() {
    let desc = two_i32(0x3F03);
    let mut wire = Vec::new();
    wire.extend(param(0xBF02, &[0xEE; 4]));
    wire.extend(param(0x0001, &7i32.to_le_bytes()));
    wire.extend(extended(0x3F03, &8i32.to_le_bytes()));
    wire.extend(param(0xBF01, &[0xEE; 8]));
    wire.extend(param(0x8001, &99i32.to_le_bytes()));
    wire.extend(param(0x3F03, &98i32.to_le_bytes()));
    wire.extend(extended(0x8000_3F03, &97i32.to_le_bytes()));
    wire.extend(param(0x7F02, &[]));
    let d = decode_dynamic_with_version(&wire, &desc, CdrVersion::Xcdr1).expect("decode");
    assert_eq!(d.get::<i32>("a").expect("a"), 7);
    assert_eq!(d.get::<i32>("b").expect("b"), 8);
}

/// Member ids 0 to 0x3F00 inclusive take the short form (section
/// 7.4.1.2.2); 0x3F01 and above the extended one, with no FLAG_2 for a
/// member that is not must-understand.
#[test]
fn the_short_form_ends_at_member_0x3f00() {
    let mut data = DynamicData::new(&two_i32(0x3F00));
    data.set("a", 1i32).expect("a");
    data.set("b", 2i32).expect("b");
    let bytes = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
    assert_eq!(
        bytes,
        hex("0100040001000000\
             003f040002000000\
             027f0000")
    );

    let mut data = DynamicData::new(&two_i32(0x3F01));
    data.set("a", 1i32).expect("a");
    data.set("b", 2i32).expect("b");
    let bytes = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
    assert_eq!(
        bytes,
        hex("0100040001000000\
             017f0800013f00000400000002000000\
             027f0000")
    );
}

/// An `@must_understand` member that is not a key carries the flag too,
/// in the short form (0x4000) and in the extended one (FLAG_2); a key in
/// the extended form carries FLAG_2.
#[test]
fn must_understand_members_carry_the_flag_in_both_forms() {
    let desc = Arc::new(
        TypeDescriptor::struct_type(
            "Mu",
            vec![
                FieldDescriptor::new("a", prim(PrimitiveKind::I32))
                    .with_id(1)
                    .with_must_understand(),
                FieldDescriptor::new("b", prim(PrimitiveKind::I32))
                    .with_id(0x0012_3456)
                    .with_must_understand(),
                FieldDescriptor::new("k", prim(PrimitiveKind::I32))
                    .with_id(0x0012_3457)
                    .with_key(),
            ],
        )
        .with_extensibility(Extensibility::Mutable),
    );
    let mut data = DynamicData::new(&desc);
    data.set("a", 1i32).expect("a");
    data.set("b", 2i32).expect("b");
    data.set("k", 3i32).expect("k");
    let bytes = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
    assert_eq!(
        bytes,
        hex("0140040001000000\
             017f08005634124004000000 02000000\
             017f08005734124004000000 03000000\
             027f0000"
            .replace(' ', "")
            .as_str())
    );
    let back = decode_dynamic_with_version(&bytes, &desc, CdrVersion::Xcdr1).expect("rt");
    assert_eq!(back.get::<i32>("a").expect("a"), 1);
    assert_eq!(back.get::<i32>("b").expect("b"), 2);
    assert_eq!(back.get::<i32>("k").expect("k"), 3);
}

/// A member id wider than the 28 bits of the member header has no PL_CDR1
/// representation: refused, never truncated into another member's id.
#[test]
fn a_member_id_wider_than_28_bits_is_refused() {
    let mut data = DynamicData::new(&two_i32(0x1000_0002));
    data.set("a", 1i32).expect("a");
    data.set("b", 2i32).expect("b");
    // Both encodings, the decoder and the TypeObject inherit the bound from
    // the one place member ids are assigned.
    assert!(encode_dynamic_with_version(&data, CdrVersion::Xcdr1).is_err());
    assert!(encode_dynamic_with_version(&data, CdrVersion::Xcdr2).is_err());
    assert!(
        decode_dynamic_with_version(&[0; 8], &two_i32(0x1000_0002), CdrVersion::Xcdr2).is_err()
    );
    assert!(type_descriptor_to_xtypes(&two_i32(0x1000_0002)).is_none());
    // An implied id (previous + 1) past the bound is refused the same way.
    let implied = Arc::new(
        TypeDescriptor::struct_type(
            "Implied",
            vec![
                FieldDescriptor::new("a", prim(PrimitiveKind::I32)).with_id(MAX_ID),
                FieldDescriptor::new("b", prim(PrimitiveKind::I32)),
            ],
        )
        .with_extensibility(Extensibility::Mutable),
    );
    let mut data = DynamicData::new(&implied);
    data.set("a", 1i32).expect("a");
    data.set("b", 2i32).expect("b");
    assert!(encode_dynamic_with_version(&data, CdrVersion::Xcdr2).is_err());
    // Under @autoid(HASH) an explicit id goes through the same bound.
    let hashed = Arc::new(
        TypeDescriptor::struct_type(
            "Hashed",
            vec![
                FieldDescriptor::new("a", prim(PrimitiveKind::I32)),
                FieldDescriptor::new("b", prim(PrimitiveKind::I32)).with_id(MAX_ID + 1),
            ],
        )
        .with_extensibility(Extensibility::Mutable)
        .with_autoid_hash(),
    );
    let mut data = DynamicData::new(&hashed);
    data.set("a", 1i32).expect("a");
    data.set("b", 2i32).expect("b");
    assert!(encode_dynamic_with_version(&data, CdrVersion::Xcdr1).is_err());
    // A union case id past the bound, both encodings.
    let disc = prim(PrimitiveKind::U32);
    let cases =
        vec![UnionCase::new("x", vec![1], prim(PrimitiveKind::I16)).with_member_id(MAX_ID + 1)];
    let td = Arc::new(
        TypeDescriptor::new("U", TypeKind::Union(UnionDescriptor::new(disc, cases)))
            .with_extensibility(Extensibility::Mutable),
    );
    let val = DynamicValue::Union(1, "x".into(), Box::new(DynamicValue::I16(-3)));
    let data = DynamicData::from_value(&td, val).expect("from_value");
    assert!(encode_dynamic_with_version(&data, CdrVersion::Xcdr1).is_err());
    assert!(encode_dynamic_with_version(&data, CdrVersion::Xcdr2).is_err());
}

/// Largest legal member id (28 bits).
const MAX_ID: u32 = 0x0FFF_FFFF;

/// Member id 0x0FFF_FFFF, the largest legal one, is written as is in both
/// encodings and read back.
#[test]
fn the_largest_member_id_is_written() {
    let desc = two_i32(MAX_ID);
    let mut data = DynamicData::new(&desc);
    data.set("a", 1i32).expect("a");
    data.set("b", 2i32).expect("b");
    let x1 = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("x1");
    assert_eq!(
        x1,
        hex("0100040001000000\
             017f0800ffffff0f0400000002000000\
             027f0000")
    );
    let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("x2");
    // DHEADER 16; EMHEADER1 LC=2 id 1; EMHEADER1 LC=2 id 0x0FFF_FFFF.
    assert_eq!(
        x2,
        hex("10000000\
             0100002001000000\
             ffffff2f02000000")
    );
    for (bytes, v) in [(x1, CdrVersion::Xcdr1), (x2, CdrVersion::Xcdr2)] {
        let back = decode_dynamic_with_version(&bytes, &desc, v).expect("rt");
        assert_eq!(back.get::<i32>("b").expect("b"), 2);
    }
}

/// A mutable union branch whose id is above 0x3F00 takes the extended
/// form: 0x7F01, member header without FLAG_2 (the branch is written
/// without the flag), exact llength; the list ends with 0x7F02.
#[test]
fn a_union_branch_in_the_extended_form() {
    let disc = prim(PrimitiveKind::U32);
    let cases = vec![UnionCase::new("x", vec![1], prim(PrimitiveKind::I16)).with_member_id(0x4000)];
    let td = Arc::new(
        TypeDescriptor::new("U", TypeKind::Union(UnionDescriptor::new(disc, cases)))
            .with_extensibility(Extensibility::Mutable),
    );
    let val = DynamicValue::Union(1, "x".into(), Box::new(DynamicValue::I16(-3)));
    let data = DynamicData::from_value(&td, val.clone()).expect("from_value");
    let bytes = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
    assert_eq!(
        bytes,
        hex("0040040001000000\
             017f08000040000002000000fdff0000\
             027f0000")
    );
    let back = decode_dynamic_with_version(&bytes, &td, CdrVersion::Xcdr1).expect("rt");
    assert_eq!(back.value(), &val);
}

fn assert_refused(r: Result<DynamicData, DynamicCdrError>) {
    match r {
        Err(DynamicCdrError::InvalidData(m)) => assert!(m.contains("must-understand"), "{m}"),
        other => panic!("expected the sample discarded, got {other:?}"),
    }
}

/// `probe_sample()` in an XCDR1 layout other than the one HDDS writes,
/// built from the specification: short parameter headers where the id and
/// the length fit (DDS-XTypes 1.3 7.4.1.2.2), each short length padded to
/// the next parameter id, a multiple of four (DDSI-RTPS 2.5 9.4.2.11, spec
/// text lines 8560-8561), no FLAG_MUST_UNDERSTAND on the keys (a reader
/// "shall be robust to any setting of the FLAG_MUST_UNDERSTAND bit",
/// DDS-XTypes 1.3 lines 6085-6087), the extended header for member 16144
/// above 0x3F00 with the exact llength (lines 6122-6124), then `extra`,
/// then PID_LIST_END 0x7F02 (Table 34).
fn x1_probe_padded(extra: &[u8]) -> Vec<u8> {
    let mut v = param(0x0001, &0x1122_3344i32.to_le_bytes());
    v.extend(param(0x0002, &[0xfe, 0xff, 0, 0]));
    v.extend(param(
        0x0003,
        &[5, 0, 0, 0, b'h', b'd', b'd', b's', 0, 0, 0, 0],
    ));
    v.extend(extended(0x3F10, &0x0102_0304_0506_0708i64.to_le_bytes()));
    v.extend(param(0x0005, &[0xab, 0, 0, 0]));
    v.extend(extra);
    v.extend(param(0x7F02, &[]));
    v
}

/// An XCDR2 EMHEADER1 (DDS-XTypes 1.3 7.4.3.4.2, line 6534):
/// `(M_FLAG << 31) + (LC << 28) + id`, little endian.
fn emheader(m: bool, lc: u32, id: u32) -> [u8; 4] {
    ((u32::from(m) << 31) | (lc << 28) | id).to_le_bytes()
}

/// `probe_sample()` in PL_CDR2 (DDS-XTypes 1.3 7.4.3.5.3 rule 28): a
/// DHEADER, then each member behind its EMHEADER1, every header aligned to
/// 4. `key_m` sets M on the two keys (line 2367, "Key members ... shall
/// always have their must understand attribute set to true"; a reader
/// accepts either setting for a member it knows). The string uses LC=5,
/// whose NEXTINT is also the string's length (lines 6556-6560), the other
/// members LC 0 to 3. `extra` members follow the last one.
fn x2_probe(key_m: bool, extra: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    let align4 = |b: &mut Vec<u8>| b.resize(b.len().next_multiple_of(4), 0);
    body.extend(emheader(key_m, 2, 1));
    body.extend(0x1122_3344i32.to_le_bytes());
    body.extend(emheader(false, 1, 2));
    body.extend((-2i16).to_le_bytes());
    align4(&mut body);
    body.extend(emheader(false, 5, 3));
    body.extend(5u32.to_le_bytes());
    body.extend(b"hdds\0");
    align4(&mut body);
    body.extend(emheader(false, 3, 0x3F10));
    body.extend(0x0102_0304_0506_0708i64.to_le_bytes());
    body.extend(emheader(key_m, 0, 5));
    body.push(0xab);
    if !extra.is_empty() {
        align4(&mut body);
        body.extend(extra);
    }
    let mut v = u32::try_from(body.len())
        .expect("len")
        .to_le_bytes()
        .to_vec();
    v.extend(body);
    v
}

/// Member 9, unknown to `probe_desc()`, as a 4-byte long: XCDR1 short
/// header without and with FLAG_MUST_UNDERSTAND (0x4000), XCDR1 extended
/// member 0x10 with FLAG_2, and XCDR2 EMHEADER1 without and with M.
fn unknown_x1(mu: bool) -> Vec<u8> {
    param(if mu { 0x4009 } else { 0x0009 }, &9i32.to_le_bytes())
}
fn unknown_x1_ext_mu() -> Vec<u8> {
    extended(0x4000_0010, &16i32.to_le_bytes())
}
fn unknown_x2(m: bool) -> Vec<u8> {
    let mut v = emheader(m, 2, 9).to_vec();
    v.extend(9i32.to_le_bytes());
    v
}

#[test]
fn the_spec_built_probe_layouts_are_the_expected_bytes() {
    // Pinned once, so that a helper drifting from the layout its comment
    // derives fails here rather than silently testing something else.
    assert_eq!(
        x1_probe_padded(&[]),
        hex(
            "010004004433221102000400feff000003000c00050000006864647300000000\
             017f0800103f000008000000080706050403020105000400ab000000027f0000"
        )
    );
    assert_eq!(
        x2_probe(false, &[]),
        hex(
            "31000000010000204433221102000010feff000003000050050000006864647300000000\
             103f0030080706050403020105000000ab"
        )
    );
}

/// DDS-XTypes 1.3 7.2.2.4.4.4.6: an unrecognized member with the
/// must-understand flag discards the sample; without it, it is skipped.
#[test]
fn an_unknown_must_understand_member_discards_the_sample() {
    let desc = probe_desc();
    for (wire, v) in [
        (x1_probe_padded(&[]), CdrVersion::Xcdr1),
        (x1_probe_padded(&unknown_x1(false)), CdrVersion::Xcdr1),
        (x2_probe(false, &[]), CdrVersion::Xcdr2),
        (x2_probe(false, &unknown_x2(false)), CdrVersion::Xcdr2),
    ] {
        let d = decode_dynamic_with_version(&wire, &desc, v).expect("accepted");
        assert_probe_values(&d);
    }
    assert_refused(decode_dynamic_with_version(
        &x1_probe_padded(&unknown_x1(true)),
        &desc,
        CdrVersion::Xcdr1,
    ));
    assert_refused(decode_dynamic_with_version(
        &x1_probe_padded(&unknown_x1_ext_mu()),
        &desc,
        CdrVersion::Xcdr1,
    ));
    assert_refused(decode_dynamic_with_version(
        &x2_probe(false, &unknown_x2(true)),
        &desc,
        CdrVersion::Xcdr2,
    ));
}

/// The must-understand flag on a Table 34 reserved id (PID_IGNORE 0x3F03,
/// reserved 0x3F04-0x3FFF) changes nothing: skipped. On a parameter that is
/// not a Table 34 value (FLAG_IMPL_EXTENSION, short or extended), it
/// discards the sample like any unrecognized must-understand parameter.
#[test]
fn reserved_ids_ignore_the_flag_implementation_extensions_do_not() {
    let desc = two_i32(2);
    let with = |extra: Vec<u8>| {
        let mut wire = param(0x0001, &7i32.to_le_bytes());
        wire.extend(extra);
        wire.extend(param(0x0002, &8i32.to_le_bytes()));
        wire.extend(param(0x7F02, &[]));
        wire
    };
    for reserved in [0x7F03u16, 0x7FFF] {
        let d = decode_dynamic_with_version(
            &with(param(reserved, &[0xEE; 4])),
            &desc,
            CdrVersion::Xcdr1,
        )
        .expect("a reserved id is skipped whatever its flag");
        assert_eq!(d.get::<i32>("a").expect("a"), 7);
        assert_eq!(d.get::<i32>("b").expect("b"), 8);
    }
    assert_refused(decode_dynamic_with_version(
        &with(param(0xC009, &[0xEE; 4])),
        &desc,
        CdrVersion::Xcdr1,
    ));
    assert_refused(decode_dynamic_with_version(
        &with(extended(0xC000_0009, &[0xEE; 4])),
        &desc,
        CdrVersion::Xcdr1,
    ));
}

/// A must-understand member the reader DOES know is accepted whatever the
/// flag says; the 16-bit short form maps member ids up to 0x3F00 inclusive
/// (section 7.4.1.2.2) on the reading side too.
#[test]
fn the_reader_maps_short_ids_up_to_0x3f00() {
    let desc = two_i32(0x3F00);
    let mut wire = param(0x4001, &7i32.to_le_bytes());
    wire.extend(param(0x7F00, &8i32.to_le_bytes()));
    wire.extend(param(0x7F02, &[]));
    let d = decode_dynamic_with_version(&wire, &desc, CdrVersion::Xcdr1).expect("decode");
    assert_eq!(d.get::<i32>("a").expect("a"), 7);
    assert_eq!(d.get::<i32>("b").expect("b"), 8);
}

/// `@mutable struct KeyAtZero { @key @id(0) octet k; @id(1) long v; }`: under
/// XCDR2 the key's EMHEADER1 with M set is 0x8000_0000 (M=1, LC=0, id 0), a
/// legal header, not a list end.
fn key_at_zero_desc() -> Arc<TypeDescriptor> {
    Arc::new(
        TypeDescriptor::struct_type(
            "KeyAtZero",
            vec![
                FieldDescriptor::new("k", prim(PrimitiveKind::U8))
                    .with_id(0)
                    .with_key(),
                FieldDescriptor::new("v", prim(PrimitiveKind::I32)).with_id(1),
            ],
        )
        .with_extensibility(Extensibility::Mutable),
    )
}

/// What HDDS writes for KeyAtZero { k: 0xAB, v: 0x11223344 }: M (XCDR2) and
/// 0x4000 (XCDR1) on the key.
const HDDS_KEY_AT_ZERO_X2: &str = "1000000000000080ab0000000100002044332211";
const HDDS_KEY_AT_ZERO_X1: &str = "00400100ab0000000100040044332211027f0000";

/// The same sample with no flag on the key, which a reader accepts for a
/// member it knows (DDS-XTypes 1.3 lines 6085-6087): under XCDR2 the key's
/// EMHEADER1 is then 0x0000_0000 (M=0, LC=0, id 0), still a header; under
/// XCDR1 the key's short length is padded to 4 (DDSI-RTPS 2.5 lines
/// 8560-8561).
fn key_at_zero_unflagged() -> [(Vec<u8>, CdrVersion); 2] {
    let mut x2 = vec![0x10, 0, 0, 0];
    x2.extend(emheader(false, 0, 0));
    x2.extend([0xab, 0, 0, 0]);
    x2.extend(emheader(false, 2, 1));
    x2.extend(0x1122_3344i32.to_le_bytes());
    let mut x1 = param(0x0000, &[0xab, 0, 0, 0]);
    x1.extend(param(0x0001, &0x1122_3344i32.to_le_bytes()));
    x1.extend(param(0x7F02, &[]));
    [(x2, CdrVersion::Xcdr2), (x1, CdrVersion::Xcdr1)]
}

#[test]
fn a_key_is_must_understand_in_xcdr2_and_a_one_byte_key_at_id_0_round_trips() {
    let desc = key_at_zero_desc();
    let mut data = DynamicData::new(&desc);
    data.set("k", 0xABu8).expect("k");
    data.set("v", 0x1122_3344i32).expect("v");
    let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("x2");
    assert_eq!(x2, hex(HDDS_KEY_AT_ZERO_X2));
    let x1 = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("x1");
    assert_eq!(x1, hex(HDDS_KEY_AT_ZERO_X1));
    let [unflagged_x2, unflagged_x1] = key_at_zero_unflagged();
    assert_eq!(
        unflagged_x2.0,
        hex("1000000000000000ab0000000100002044332211")
    );
    assert_eq!(
        unflagged_x1.0,
        hex("00000400ab0000000100040044332211027f0000")
    );
    for (bytes, v) in [
        (x2, CdrVersion::Xcdr2),
        (x1, CdrVersion::Xcdr1),
        unflagged_x2,
        unflagged_x1,
    ] {
        let d = decode_dynamic_with_version(&bytes, &desc, v).expect("decode");
        assert_eq!(d.get::<u8>("k").expect("k"), 0xAB);
        assert_eq!(d.get::<i32>("v").expect("v"), 0x1122_3344);
    }
}

/// XCDR2 PlProbe: HDDS sets M on both keys (DDS-XTypes 1.3 line 2367 with
/// 7.4.3.4.2) and gives the string LC=4, a NEXTINT of its exact length 9.
#[test]
fn xcdr2_keys_carry_m() {
    let bytes = encode_dynamic_with_version(&probe_sample(), CdrVersion::Xcdr2).expect("x2");
    assert_eq!(
        bytes,
        hex("35000000010000a04433221102000010feff00000300004009000000050000006864647300000000103f0030080706050403020105000080ab")
    );
}

/// An `@must_understand` member that is not a key carries M in XCDR2.
#[test]
fn xcdr2_must_understand_members_carry_m() {
    let desc = Arc::new(
        TypeDescriptor::struct_type(
            "Mu2",
            vec![FieldDescriptor::new("a", prim(PrimitiveKind::I32))
                .with_id(7)
                .with_must_understand()],
        )
        .with_extensibility(Extensibility::Mutable),
    );
    let mut data = DynamicData::new(&desc);
    data.set("a", 1i32).expect("a");
    let bytes = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("x2");
    assert_eq!(bytes, hex("08000000070000a001000000"));
}

/// In a mutable union too, a flagged parameter that names no member (an
/// implementation extension, short or extended) discards the sample, and
/// a flagged reserved id is skipped.
#[test]
fn a_union_refuses_a_flagged_implementation_extension() {
    let disc = prim(PrimitiveKind::U32);
    let cases = vec![UnionCase::new("x", vec![1], prim(PrimitiveKind::I16))];
    let td = Arc::new(
        TypeDescriptor::new("U", TypeKind::Union(UnionDescriptor::new(disc, cases)))
            .with_extensibility(Extensibility::Mutable),
    );
    let with = |extra: Vec<u8>| {
        let mut wire = param(0x4000, &1u32.to_le_bytes());
        wire.extend(extra);
        wire.extend(param(0x0001, &(-3i16).to_le_bytes()));
        wire.extend([0, 0]); // pad to 4
        wire.extend(param(0x7F02, &[]));
        wire
    };
    let ok = decode_dynamic_with_version(&with(param(0x7F03, &[0xEE; 4])), &td, CdrVersion::Xcdr1)
        .expect("a reserved id is skipped whatever its flag");
    assert_eq!(
        ok.value(),
        &DynamicValue::Union(1, "x".into(), Box::new(DynamicValue::I16(-3)))
    );
    assert_refused(decode_dynamic_with_version(
        &with(param(0xC009, &[0xEE; 4])),
        &td,
        CdrVersion::Xcdr1,
    ));
    assert_refused(decode_dynamic_with_version(
        &with(extended(0xC000_0009, &[0xEE; 4])),
        &td,
        CdrVersion::Xcdr1,
    ));
}

/// A union branch the reader knows is accepted when it carries the
/// must-understand flag (only an UNKNOWN flagged member discards the
/// sample), in both encodings.
#[test]
fn a_known_union_branch_with_the_flag_is_accepted() {
    let disc = prim(PrimitiveKind::U32);
    let cases = vec![UnionCase::new("x", vec![1], prim(PrimitiveKind::I16))];
    let td = Arc::new(
        TypeDescriptor::new("U", TypeKind::Union(UnionDescriptor::new(disc, cases)))
            .with_extensibility(Extensibility::Mutable),
    );
    let expected = DynamicValue::Union(1, "x".into(), Box::new(DynamicValue::I16(-3)));
    // XCDR1: discriminator 0x4000, branch 0x4001 (member 1 | flag), 0x7F02.
    let x1 = hex("0040040001000000\
                  01400200fdff0000\
                  027f0000");
    // XCDR2: DHEADER 12; EMHEADER1 M=1 LC=2 id 0; M=1 LC=1 id 1.
    let x2 = hex("0c000000\
                  000000a001000000\
                  01000090fdff");
    for (bytes, v) in [(x1, CdrVersion::Xcdr1), (x2, CdrVersion::Xcdr2)] {
        let d = decode_dynamic_with_version(&bytes, &td, v).expect("a known branch is accepted");
        assert_eq!(d.value(), &expected);
    }
}
