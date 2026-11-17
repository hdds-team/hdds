// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The TypeObject serializer against a foreign oracle.
//!
//! `golden/typeobject/cyclone-0.11-typeobjects.txt` holds every Complete and
//! Minimal TypeObject Cyclone DDS 0.11 idlc emits for
//! `golden/typeobject/typeobject_corpus.idl`, each one checked against its
//! MD5 EquivalenceHash when it was extracted (see the file header). For every
//! object this test decodes it with HDDS's decoder, re-encodes it with HDDS's
//! encoder at the same stream position (the inner object starts at byte 5,
//! behind the TypeObject DHEADER and the EK octet, DDS-XTypes 1.3 Annex B
//! `@appendable union TypeObject`), and requires the bytes and the
//! EquivalenceHash to come back identical.
//!
//! A byte-exact round trip means the HDDS model holds every field the
//! specification serializes for that object and the encoder lays each one
//! out where the specification puts it: it is the serializer half of hash
//! exactness. The builder half (that HDDS fills the model with the values a
//! given IDL declares) is pinned per builder elsewhere.
//!
//! `KNOWN_DIFF` lists the objects that do NOT round-trip, with the reason. An
//! entry that starts round-tripping fails the test until it is removed, so
//! the list can only shrink.

#![cfg(feature = "xtypes")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use hdds::xtypes::{CompleteTypeObject, MinimalTypeObject};
use hdds::{Cdr2Decode, Cdr2Encode, CdrError};

const ORACLE: &str = include_str!("golden/typeobject/cyclone-0.11-typeobjects.txt");
const FASTDDS_ORACLE: &str = include_str!("golden/typeobject/fastdds-3.4-typeobjects.txt");

/// Objects that do not round-trip byte-exact yet: (type, 'C' or 'M', reason).
const KNOWN_DIFF: &[(&str, char, &str)] = &[];

struct Row {
    name: String,
    kind: char,
    hash: String,
    bytes: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rows() -> Vec<Row> {
    rows_of(ORACLE)
}

fn rows_of(oracle: &str) -> Vec<Row> {
    oracle
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            assert_eq!(f.len(), 4, "malformed oracle line: {l}");
            Row {
                name: f[0].to_string(),
                kind: f[1].chars().next().expect("kind"),
                hash: f[2].to_string(),
                bytes: unhex(f[3]),
            }
        })
        .collect()
}

/// Re-encode `inner` behind the TypeObject DHEADER and EK octet, exactly as
/// the EquivalenceHash preimage is laid out (DDS-XTypes 1.3 7.3.4.8).
fn wrap<T: Cdr2Encode>(ek: u8, inner: &T) -> Result<Vec<u8>, CdrError> {
    let mut buf = vec![0u8; 5 + inner.max_cdr2_size()];
    buf[4] = ek;
    let mut off = 5usize;
    inner.encode_cdr2_le_at(&mut buf, &mut off)?;
    let size = u32::try_from(off - 4).expect("size");
    buf[..4].copy_from_slice(&size.to_le_bytes());
    buf.truncate(off);
    Ok(buf)
}

/// Decode the oracle object and re-encode it. `Ok((bytes, hash))` on a
/// successful round trip (whatever the bytes), `Err` with the step that
/// failed otherwise.
fn round_trip(row: &Row) -> Result<(Vec<u8>, String), String> {
    let b = &row.bytes;
    let mut off = 5usize;
    let (out, hash) = match row.kind {
        'C' => {
            assert_eq!(b[4], 0xF2, "{}: EK_COMPLETE", row.name);
            let obj = CompleteTypeObject::decode_cdr2_le_at(b, &mut off)
                .map_err(|e| format!("decode: {e:?}"))?;
            let out = wrap(0xF2, &obj).map_err(|e| format!("encode: {e:?}"))?;
            let h = obj
                .compute_equivalence_hash()
                .map_err(|e| format!("hash: {e:?}"))?;
            (out, hex(h.as_bytes()))
        }
        'M' => {
            assert_eq!(b[4], 0xF1, "{}: EK_MINIMAL", row.name);
            let obj = MinimalTypeObject::decode_cdr2_le_at(b, &mut off)
                .map_err(|e| format!("decode: {e:?}"))?;
            let out = wrap(0xF1, &obj).map_err(|e| format!("encode: {e:?}"))?;
            let h = obj
                .compute_equivalence_hash()
                .map_err(|e| format!("hash: {e:?}"))?;
            (out, hex(h.as_bytes()))
        }
        k => panic!("{}: unknown kind {k}", row.name),
    };
    if off != b.len() {
        return Err(format!("decode consumed {off} of {} bytes", b.len()));
    }
    Ok((out, hash))
}

fn first_difference(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()))
}

#[test]
fn every_oracle_type_object_round_trips_byte_exact() {
    let rows = rows();
    assert!(rows.len() >= 130, "oracle shrank: {} objects", rows.len());
    let mut report = String::new();
    let mut failures = Vec::new();
    let mut exact = 0usize;
    for row in &rows {
        let known = KNOWN_DIFF
            .iter()
            .find(|(n, k, _)| *n == row.name && *k == row.kind);
        let verdict = match round_trip(row) {
            Ok((out, hash)) if out == row.bytes && hash == row.hash => Ok(()),
            Ok((out, hash)) => Err(format!(
                "differs at byte {} (hash {hash}, oracle {})\n    ours   {}\n    oracle {}",
                first_difference(&out, &row.bytes),
                row.hash,
                hex(&out),
                hex(&row.bytes)
            )),
            Err(e) => Err(e),
        };
        match (&verdict, known) {
            (Ok(()), None) => {
                exact += 1;
                report.push_str(&format!("EXACT   {} {}\n", row.name, row.kind));
            }
            (Ok(()), Some((_, _, why))) => failures.push(format!(
                "{} {} now round-trips: remove it from KNOWN_DIFF ({why})",
                row.name, row.kind
            )),
            (Err(e), Some((_, _, why))) => {
                report.push_str(&format!("DIFFERS {} {} ({why}): {e}\n", row.name, row.kind));
            }
            (Err(e), None) => failures.push(format!("{} {}: {e}", row.name, row.kind)),
        }
    }
    for (n, k, _) in KNOWN_DIFF {
        assert!(
            rows.iter().any(|r| r.name == *n && r.kind == *k),
            "KNOWN_DIFF names {n} {k}, absent from the oracle"
        );
    }
    println!("{report}{exact} of {} objects exact", rows.len());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Fast DDS 3.4 objects HDDS does not yet re-encode byte for byte, each
/// with the Annex B layout it misses; the list may only shrink.
const FASTDDS_KNOWN_DIFF: &[(&str, char, &str)] = &[
    (
        "Array",
        'M',
        "held: the ROS 2 builder hashes this layout into what it announces",
    ),
    // DDS-XTypes 1.3 Annex B CompleteDiscriminatorMember { common;
    // @optional ann_builtin; @optional ann_custom; }: the model has no field
    // for the two annotations, so the decoder skips them (inside the member's
    // DHEADER) and the encoder writes both absent. Every union Cyclone idlc
    // emits round-trips; this one re-encodes without its annotation.
    (
        "UnionDiscAnn",
        'C',
        "discriminator annotations not modelled: dropped on decode",
    ),
];

#[test]
fn every_fast_dds_type_object_round_trips_byte_exact() {
    let rows = rows_of(FASTDDS_ORACLE);
    assert_eq!(rows.len(), 11, "Fast DDS oracle size");
    let mut report = String::new();
    let mut failures = Vec::new();
    for row in &rows {
        let known = FASTDDS_KNOWN_DIFF
            .iter()
            .find(|(n, k, _)| *n == row.name && *k == row.kind);
        let exact =
            matches!(round_trip(row), Ok((out, hash)) if out == row.bytes && hash == row.hash);
        match (exact, known) {
            (true, None) => report.push_str(&format!("EXACT   {} {}\n", row.name, row.kind)),
            (true, Some((_, _, why))) => failures.push(format!(
                "{} {} now round-trips: remove it from FASTDDS_KNOWN_DIFF ({why})",
                row.name, row.kind
            )),
            (false, Some((_, _, why))) => {
                report.push_str(&format!("DIFFERS {} {} ({why})\n", row.name, row.kind));
            }
            (false, None) => failures.push(format!(
                "{} {}: {:?}",
                row.name,
                row.kind,
                round_trip(row).map(|(out, _)| hex(&out))
            )),
        }
    }
    println!("{report}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The TypeObject `shape_main` announces, included from the one file the
/// example and the library's type-verdict tests both use.
mod shape {
    use hdds::xtypes::*;
    include!("../examples/shape_common/shape_type_object.rs");
}

/// What `shape_main` puts on the wire must not move by accident: its
/// TypeObject goes out in PID_TYPE_OBJECT (toward HDDS peers), in
/// PID_TYPE_INFORMATION (by its hashes, toward every peer) and in TypeLookup
/// replies, and a peer that compares hashes judges it by those bytes. These
/// are the bytes of the specification's form it announces: `color` as
/// TI_STRING8_SMALL bound 128 (0x70 0x80), the key member IS_KEY |
/// IS_MUST_UNDERSTAND | TRY_CONSTRUCT1 (0x0031), every other member
/// TRY_CONSTRUCT1. Changing them is a wire decision, validated on the
/// interop rig first, never a side effect of a serializer fix.
const SHAPE_MAIN_COMPLETE: &str = "ae000000f251020012000000000000000a00000053686170655479706500\
    00008e0000000500000014000000000000003100708006000000636f6c6f7200000010000000010000000100\
    0400020000007800000010000000020000000100040002000000790000001800000003000000010004000a00\
    0000736861706573697a650000002a00000004000000010080f30100000d180000006164646974696f6e616c\
    5f7061796c6f61645f73697a65000000";
const SHAPE_MAIN_COMPLETE_HASH: &str = "4d9a6d25f1eb434dbb3a601fb18a";
/// The Minimal hash its PID_TYPE_INFORMATION carries.
const SHAPE_MAIN_MINIMAL_HASH: &str = "6b428aede6719842160c1ffcce9f";

#[test]
fn shape_main_type_object_bytes_are_pinned() {
    let obj = shape::shape_type_object();
    let bytes = wrap(0xF2, &obj).expect("encode");
    let expected: String = SHAPE_MAIN_COMPLETE.split_whitespace().collect();
    assert_eq!(hex(&bytes), expected);
    assert_eq!(
        hex(obj.compute_equivalence_hash().expect("hash").as_bytes()),
        SHAPE_MAIN_COMPLETE_HASH
    );
    let minimal = hdds::dynamic::complete_type_object_minimal_hash(&obj).expect("minimal");
    assert_eq!(hex(minimal.as_bytes()), SHAPE_MAIN_MINIMAL_HASH);
}

fn oracle(name: &str, kind: char) -> Row {
    rows()
        .into_iter()
        .find(|r| r.name == name && r.kind == kind)
        .unwrap_or_else(|| panic!("{name} {kind} not in the oracle"))
}

/// `@final enum EFin { EF_0, EF_1 };` built from the model, not decoded:
/// the declared extensibility goes into `enum_flags` (IS_FINAL) and the
/// object is Cyclone's, byte for byte.
#[test]
fn a_final_enum_built_from_the_model_is_the_oracle_object() {
    use hdds::xtypes::*;
    let literal = |value: i32, name: &str, flags| MinimalEnumeratedLiteral {
        common: CommonEnumeratedLiteral { value, flags },
        detail: MinimalMemberDetail::from_name(name),
    };
    let efin = MinimalTypeObject::Enumerated(MinimalEnumeratedType {
        enum_flags: StructTypeFlag::IS_FINAL,
        header: MinimalEnumeratedHeader {
            bit_bound: 32,
            detail: MinimalTypeDetail::new(),
        },
        literal_seq: vec![
            literal(0, "EF_0", EnumeratedLiteralFlag::IS_DEFAULT),
            literal(1, "EF_1", EnumeratedLiteralFlag::empty()),
        ],
    });
    let want = oracle("EFin", 'M');
    assert_eq!(hex(&wrap(0xF1, &efin).expect("encode")), hex(&want.bytes));
    assert_eq!(
        hex(efin.compute_equivalence_hash().expect("hash").as_bytes()),
        want.hash
    );
}

/// `@appendable bitmask BMApp { BA_0, BA_1 };` built from the model: the
/// bitmask body is APPENDABLE (a DHEADER in front of `bitmask_flags`) and the
/// declared extensibility is the flag.
#[test]
fn an_appendable_bitmask_built_from_the_model_is_the_oracle_object() {
    use hdds::xtypes::*;
    let flag = |position: u16, name: &str| CompleteBitflag {
        common: CommonBitflag {
            position,
            flags: BitflagFlag::empty(),
        },
        detail: CompleteMemberDetail::new(name),
    };
    let bmapp = CompleteTypeObject::Bitmask(CompleteBitmaskType {
        bitmask_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteBitmaskHeader {
            bit_bound: 32,
            detail: CompleteTypeDetail::new("BMApp"),
        },
        flag_seq: vec![flag(0, "BA_0"), flag(1, "BA_1")],
    });
    let want = oracle("BMApp", 'C');
    assert_eq!(hex(&wrap(0xF2, &bmapp).expect("encode")), hex(&want.bytes));
    assert_eq!(
        hex(bmapp.compute_equivalence_hash().expect("hash").as_bytes()),
        want.hash
    );
}

fn shape_hashes(obj: &CompleteTypeObject) -> (String, String) {
    let complete = obj.compute_equivalence_hash().expect("hash");
    let minimal = hdds::dynamic::complete_type_object_minimal_hash(obj).expect("minimal");
    (hex(complete.as_bytes()), hex(minimal.as_bytes()))
}

/// The TypeObject `shape_main` announces round-trips through HDDS's own
/// encoder and decoder, consumes every byte it writes, and re-encodes to the
/// same bytes. The form it announced earlier does not decode: its
/// `color` member carries the bare TK_STRING8 (0x20), a TypeKind and not a
/// TypeIdentifier discriminator (DDS-XTypes 1.3 7.3.4.4), which is why those
/// announcements went out without PID_TYPE_OBJECT and PID_TYPE_INFORMATION.
/// The emitter is gone; the refusal is pinned here on the one member that
/// made it.
#[test]
fn shape_main_announces_an_object_that_round_trips() {
    let obj = shape::shape_type_object();
    let bytes = wrap(0xF2, &obj).expect("encode");
    let mut off = 5usize;
    let back = CompleteTypeObject::decode_cdr2_le_at(&bytes, &mut off).expect("decode");
    assert_eq!(back, obj);
    assert_eq!(off, bytes.len(), "the decoder consumes the whole object");
    // Re-encoded at the stream position the object occupied on the wire: a
    // CDR2 object's alignment depends on where it starts (7.4.3), so encoding
    // it from offset 0 lays its DHEADER out at a different position.
    let mut again = vec![0u8; bytes.len()];
    let mut out = 5usize;
    back.encode_cdr2_le_at(&mut again, &mut out)
        .expect("re-encode the decoded object");
    assert_eq!(
        &again[5..out],
        &bytes[5..],
        "re-encoding reproduces the bytes"
    );

    let mut old = obj;
    if let CompleteTypeObject::Struct(s) = &mut old {
        assert_eq!(s.member_seq[0].detail.name, "color");
        s.member_seq[0].common.member_type_id = hdds::xtypes::TypeIdentifier::TK_STRING8;
    }
    let old = wrap(0xF2, &old).expect("encode");
    let mut off = 5usize;
    let err = CompleteTypeObject::decode_cdr2_le_at(&old, &mut off).expect_err("0x20");
    assert!(format!("{err}").contains("0x20"), "{err}");
}

/// A little-endian XCDR2 stream (DDS-XTypes 1.3 7.4.3): each primitive is
/// aligned to its size, capped at 4, from the start of the buffer.
#[derive(Default)]
struct Xcdr2Le(Vec<u8>);

impl Xcdr2Le {
    fn align(&mut self, n: usize) {
        while !self.0.len().is_multiple_of(n) {
            self.0.push(0);
        }
    }

    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.align(2);
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.align(4);
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    /// A string: u32 length counting the terminating NUL, the octets, NUL.
    fn string(&mut self, s: &str) {
        self.u32(u32::try_from(s.len() + 1).expect("short"));
        self.0.extend_from_slice(s.as_bytes());
        self.u8(0);
    }

    /// A DHEADER (7.4.3.5.2): the u32 byte count of what `body` writes, then
    /// that body.
    fn delimited(&mut self, body: impl FnOnce(&mut Self)) {
        self.align(4);
        let at = self.0.len();
        self.u32(0);
        body(self);
        let len = u32::try_from(self.0.len() - at - 4).expect("short");
        self.0[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }
}

fn md5(bytes: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    Md5::digest(bytes).into()
}

/// The EquivalenceHash of a serialized TypeObject, in hex: the first 14
/// bytes of its MD5 (7.3.4.8).
fn md5_hash_hex(type_object: &[u8]) -> String {
    hex(&md5(type_object)[..14])
}

/// The members of
///
/// ```text
/// @appendable struct ShapeType {
///   @key string<128> color; long x; long y; long shapesize;
///   sequence<octet> additional_payload_size;
/// };
/// ```
///
/// in declaration order (member ids 0..4), with the flags the specification
/// gives them: the key member IS_KEY | IS_MUST_UNDERSTAND | TRY_CONSTRUCT1
/// (0x0031: 7.2.2.4.4.4.8, "key members ... shall always have their 'must
/// understand' attribute set to true"; TRY_CONSTRUCT1 is DISCARD, the default
/// of 7.2.2.7), the others TRY_CONSTRUCT1 (0x0001).
const SHAPE_MEMBERS: [(&str, u16); 5] = [
    ("color", 0x0031),
    ("x", 0x0001),
    ("y", 0x0001),
    ("shapesize", 0x0001),
    ("additional_payload_size", 0x0001),
];

/// The TypeIdentifier of member `index` (Annex B); `color_bound` is the
/// SBound of `color`'s TI_STRING8_SMALL. Every one is fully descriptive, so
/// the minimal and complete objects carry the same bytes.
fn write_member_type(w: &mut Xcdr2Le, index: usize, color_bound: u8) {
    match index {
        // TI_STRING8_SMALL, StringSTypeDefn { SBound bound }.
        0 => {
            w.u8(0x70);
            w.u8(color_bound);
        }
        // long: TK_INT32.
        1..=3 => w.u8(0x04),
        // sequence<octet>: TI_PLAIN_SEQUENCE_SMALL, PlainSequenceSElemDefn {
        // PlainCollectionHeader { equiv_kind EK_BOTH (a primitive element),
        // element_flags TRY_CONSTRUCT1 }, bound 0 (unbounded), TK_UINT8 }.
        _ => {
            w.u8(0x80);
            w.u8(0xF3);
            w.u16(0x0001);
            w.u8(0);
            w.u8(0x0D);
        }
    }
}

/// The serialized Complete TypeObject of ShapeType, from its DHEADER: the
/// preimage of its COMPLETE EquivalenceHash, written from Annex B.
fn shape_complete_bytes(color_bound: u8) -> Vec<u8> {
    let mut w = Xcdr2Le::default();
    // TypeObject: @appendable union, so a DHEADER, then the discriminator.
    w.delimited(|w| {
        w.u8(0xF2); // EK_COMPLETE
        w.u8(0x51); // CompleteTypeObject (@final union): TK_STRUCTURE
        w.u16(0x0002); // CompleteStructType.struct_flags: IS_APPENDABLE
                       // CompleteStructHeader (@appendable): base_type TK_NONE, then
                       // CompleteTypeDetail (@final): ann_builtin and ann_custom absent (an
                       // @optional member of a final struct is a presence flag), type_name.
        w.delimited(|w| {
            w.u8(0x00);
            w.u8(0);
            w.u8(0);
            w.string("ShapeType");
        });
        // CompleteStructMemberSeq: DHEADER (non-primitive element), length.
        w.delimited(|w| {
            w.u32(5);
            for (index, (name, flags)) in SHAPE_MEMBERS.iter().enumerate() {
                // CompleteStructMember (@appendable): CommonStructMember
                // (@final) { member_id, member_flags, member_type_id }, then
                // CompleteMemberDetail (@final) { name, ann_builtin and
                // ann_custom absent }.
                w.delimited(|w| {
                    w.u32(u32::try_from(index).expect("small"));
                    w.u16(*flags);
                    write_member_type(w, index, color_bound);
                    w.string(name);
                    w.u8(0);
                    w.u8(0);
                });
            }
        });
    });
    w.0
}

/// The serialized Minimal TypeObject of the same ShapeType: the preimage of
/// its MINIMAL EquivalenceHash.
fn shape_minimal_bytes(color_bound: u8) -> Vec<u8> {
    let mut w = Xcdr2Le::default();
    w.delimited(|w| {
        w.u8(0xF1); // EK_MINIMAL
        w.u8(0x51); // MinimalTypeObject (@final union): TK_STRUCTURE
        w.u16(0x0002); // MinimalStructType.struct_flags: IS_APPENDABLE
                       // MinimalStructHeader (@appendable): base_type TK_NONE, then the
                       // empty MinimalTypeDetail.
        w.delimited(|w| w.u8(0x00));
        w.delimited(|w| {
            w.u32(5);
            for (index, (name, flags)) in SHAPE_MEMBERS.iter().enumerate() {
                // MinimalStructMember (@appendable): CommonStructMember, then
                // MinimalMemberDetail { NameHash: the first four octets of
                // the MD5 of the member name }.
                w.delimited(|w| {
                    w.u32(u32::try_from(index).expect("small"));
                    w.u16(*flags);
                    write_member_type(w, index, color_bound);
                    w.0.extend_from_slice(&md5(name.as_bytes())[..4]);
                });
            }
        });
    });
    w.0
}

/// The specification's ShapeType is, byte for byte, the
/// Complete object written by hand above from Annex B, and both its hashes
/// are the MD5 of the hand-written Complete and Minimal objects. With
/// `color` given no bound (an SBound of 0) the same holds against the
/// hand-written objects of that variant. Against the Cyclone oracle, whose
/// ShapeType key member carries IS_KEY | TRY_CONSTRUCT1 (0x21) without the
/// IS_MUST_UNDERSTAND bit 7.2.2.4.4.4.8 requires, the specification's object
/// is the oracle's byte for byte once that one bit is cleared.
#[test]
fn the_spec_shape_type_object_is_its_hand_written_annex_b_form() {
    use hdds::xtypes::{MemberFlag, MinimalTypeObject};
    let spec = shape::shape_type_object();
    assert_eq!(
        hex(&wrap(0xF2, &spec).expect("encode")),
        hex(&shape_complete_bytes(128)),
        "the serializer writes the hand-written Complete object"
    );
    assert_eq!(
        shape_hashes(&spec),
        (
            md5_hash_hex(&shape_complete_bytes(128)),
            md5_hash_hex(&shape_minimal_bytes(128))
        )
    );

    // `color` without its bound.
    let mut unbounded = spec.clone();
    if let CompleteTypeObject::Struct(s) = &mut unbounded {
        assert_eq!(s.member_seq[0].detail.name, "color");
        s.member_seq[0].common.member_type_id = hdds::xtypes::TypeIdentifier::string(0);
    }
    assert_eq!(
        hex(&wrap(0xF2, &unbounded).expect("encode")),
        hex(&shape_complete_bytes(0))
    );
    assert_eq!(
        shape_hashes(&unbounded),
        (
            md5_hash_hex(&shape_complete_bytes(0)),
            md5_hash_hex(&shape_minimal_bytes(0))
        )
    );

    let mut cyclone_flags = spec.clone();
    if let CompleteTypeObject::Struct(s) = &mut cyclone_flags {
        assert_eq!(s.member_seq[0].detail.name, "color");
        s.member_seq[0].common.member_flags =
            MemberFlag(MemberFlag::IS_KEY.0 | MemberFlag::TRY_CONSTRUCT1.0);
    }
    let want = oracle("ShapeType", 'C');
    assert_eq!(
        hex(&wrap(0xF2, &cyclone_flags).expect("encode")),
        hex(&want.bytes)
    );
    let want_minimal = oracle("ShapeType", 'M');
    let mut off = 5usize;
    let theirs =
        MinimalTypeObject::decode_cdr2_le_at(&want_minimal.bytes, &mut off).expect("decode");
    let (complete, minimal) = shape_hashes(&cyclone_flags);
    assert_eq!(complete, want.hash);
    assert_eq!(minimal, want_minimal.hash);
    assert_eq!(
        hex(theirs.compute_equivalence_hash().expect("hash").as_bytes()),
        minimal
    );
}

/// The dynamic bridge (`type_descriptor_to_xtypes*`), the builder HDDS uses
/// for every type it announces from a `TypeDescriptor`, against the oracle:
/// the corpus types it can express, Complete object byte for byte, Minimal
/// object by its hash.
mod bridge {
    use super::{hex, oracle, wrap};
    use hdds::dynamic::{
        complete_type_object_minimal_hash, type_descriptor_to_xtypes,
        type_descriptor_to_xtypes_complete, ArrayDescriptor, EnumDescriptor, EnumVariant,
        Extensibility, FieldDescriptor, PrimitiveKind, SequenceDescriptor, TypeDescriptor,
        TypeKind, UnionCase, UnionDescriptor,
    };
    use std::sync::Arc;

    type D = Arc<TypeDescriptor>;

    fn prim(k: PrimitiveKind) -> D {
        Arc::new(TypeDescriptor::primitive("p", k))
    }
    fn long() -> D {
        prim(PrimitiveKind::I32)
    }
    /// IDL `octet` is TK_BYTE (0x02).
    fn octet() -> D {
        prim(PrimitiveKind::Byte)
    }
    fn string(bound: Option<usize>) -> D {
        prim(PrimitiveKind::String { max_length: bound })
    }
    fn field(name: &str, t: D) -> FieldDescriptor {
        FieldDescriptor::new(name, t)
    }
    fn key(name: &str, t: D) -> FieldDescriptor {
        let mut f = FieldDescriptor::new(name, t);
        f.is_key = true;
        f
    }
    fn st(name: &str, ext: Extensibility, fields: Vec<FieldDescriptor>) -> D {
        Arc::new(TypeDescriptor::new(name, TypeKind::Struct(fields)).with_extensibility(ext))
    }
    fn nested(t: &D) -> D {
        Arc::new(TypeDescriptor::new(
            t.name.clone(),
            TypeKind::Nested(t.clone()),
        ))
    }
    fn seq(t: D, bound: Option<usize>) -> D {
        let s = match bound {
            Some(b) => SequenceDescriptor::bounded(t, b),
            None => SequenceDescriptor::unbounded(t),
        };
        Arc::new(TypeDescriptor::new("seq", TypeKind::Sequence(s)))
    }
    fn arr(t: D, n: usize) -> D {
        Arc::new(TypeDescriptor::new(
            "arr",
            TypeKind::Array(ArrayDescriptor::new(t, n)),
        ))
    }
    fn en(name: &str, under: PrimitiveKind, lits: &[&str]) -> D {
        let variants = lits
            .iter()
            .enumerate()
            .map(|(i, n)| EnumVariant::new(*n, i64::try_from(i).expect("small")))
            .collect();
        Arc::new(TypeDescriptor::new(
            name,
            TypeKind::Enum(EnumDescriptor::new(variants).with_underlying(under)),
        ))
    }

    fn e8() -> D {
        en("E8", PrimitiveKind::U8, &["E8_A", "E8_B", "E8_C"])
    }
    fn e16() -> D {
        en("E16", PrimitiveKind::U16, &["E16_A", "E16_B"])
    }
    fn e32() -> D {
        en("E32", PrimitiveKind::U32, &["E32_A", "E32_B", "E32_C"])
    }
    fn inner8() -> D {
        st(
            "Inner8",
            Extensibility::Final,
            vec![field("x", prim(PrimitiveKind::I64)), field("y", long())],
        )
    }
    fn app_struct() -> D {
        st(
            "AppStruct",
            Extensibility::Appendable,
            vec![
                field("a", long()),
                field("s", string(None)),
                field("b", octet()),
            ],
        )
    }
    fn mut_prims() -> D {
        st(
            "MutPrims",
            Extensibility::Mutable,
            vec![field("x", long()), field("y", long()), field("z", long())],
        )
    }
    fn ul() -> D {
        let u = UnionDescriptor::new(
            long(),
            vec![
                UnionCase::single("a", 1, long()),
                UnionCase::single("s", 2, string(Some(8))),
                UnionCase::single("d", 3, prim(PrimitiveKind::F64)),
            ],
        )
        .with_default(UnionCase::new("o", vec![], octet()));
        Arc::new(TypeDescriptor::new("UL", TypeKind::Union(u)))
    }

    /// (type, descriptor) of every corpus type built here.
    fn corpus() -> Vec<(&'static str, D)> {
        let i8_ = inner8();
        vec![
            (
                "FinalPrims",
                st(
                    "FinalPrims",
                    Extensibility::Final,
                    vec![
                        field("a", octet()),
                        field("b", prim(PrimitiveKind::I64)),
                        field("c", prim(PrimitiveKind::I16)),
                        field("d", prim(PrimitiveKind::F64)),
                        field("e", prim(PrimitiveKind::Bool)),
                        field("f", prim(PrimitiveKind::U32)),
                    ],
                ),
            ),
            ("Inner8", i8_.clone()),
            (
                "NestFinal",
                st(
                    "NestFinal",
                    Extensibility::Final,
                    vec![
                        field("a", octet()),
                        field("in8", nested(&i8_)),
                        field("z", octet()),
                    ],
                ),
            ),
            ("AppStruct", app_struct()),
            (
                "MutDefault",
                st(
                    "MutDefault",
                    Extensibility::Mutable,
                    vec![
                        field("a", long()),
                        field("s", string(None)),
                        field("d", prim(PrimitiveKind::F64)),
                        field("o", octet()),
                    ],
                ),
            ),
            (
                "MutIds",
                st(
                    "MutIds",
                    Extensibility::Mutable,
                    vec![
                        field("a", long()).with_id(10),
                        field("b", long()),
                        field("c", prim(PrimitiveKind::I16)).with_id(5),
                        field("d", octet()),
                    ],
                ),
            ),
            ("MutPrims", mut_prims()),
            (
                "MutOpt",
                st(
                    "MutOpt",
                    Extensibility::Mutable,
                    vec![
                        field("a", long()).optional(),
                        field("b", string(None)).optional(),
                        field("c", long()),
                    ],
                ),
            ),
            (
                "MutHashid",
                st(
                    "MutHashid",
                    Extensibility::Mutable,
                    vec![
                        // `@hashid` without a parameter: the empty value.
                        field("x", long()).with_hashid_name(""),
                        field("y", long()).with_hashid_name("foo"),
                        field("z", long()),
                    ],
                ),
            ),
            // The OMG XTypes conformance suite's struct_hashid_2: member id
            // hash("x1"), Complete detail "x2" with hash_id "x1", Minimal
            // name hash of "x2".
            (
                "HashidAlias",
                Arc::new(
                    TypeDescriptor::new(
                        "HashidAlias",
                        TypeKind::Struct(vec![field("x2", long()).with_hashid_name("x1")]),
                    )
                    .with_extensibility(Extensibility::Final)
                    .with_autoid_hash(),
                ),
            ),
            ("E8", e8()),
            ("E16", e16()),
            ("E32", e32()),
            (
                "Enums",
                st(
                    "Enums",
                    Extensibility::Final,
                    vec![
                        field("a", e8()),
                        field("b", e16()),
                        field("c", e32()),
                        field("x", octet()),
                        field("d", e16()),
                        field("e", e8()),
                    ],
                ),
            ),
            (
                "Seqs",
                st(
                    "Seqs",
                    Extensibility::Final,
                    vec![
                        field("p", octet()),
                        field("u", seq(prim(PrimitiveKind::I64), None)),
                        field("bd", seq(prim(PrimitiveKind::F64), Some(5))),
                        field("q", octet()),
                        field("s", seq(prim(PrimitiveKind::I16), None)),
                        field("bl", seq(prim(PrimitiveKind::I64), Some(3))),
                    ],
                ),
            ),
            (
                "SeqStruct",
                st(
                    "SeqStruct",
                    Extensibility::Final,
                    vec![field("p", octet()), field("v", seq(nested(&i8_), None))],
                ),
            ),
            (
                "ArrStruct",
                st(
                    "ArrStruct",
                    Extensibility::Final,
                    vec![field("p", octet()), field("a", arr(nested(&i8_), 2))],
                ),
            ),
            (
                "BStr",
                st(
                    "BStr",
                    Extensibility::Final,
                    vec![
                        field("p", octet()),
                        field("s", string(Some(8))),
                        field("z", long()),
                    ],
                ),
            ),
            (
                "Keyed",
                st(
                    "Keyed",
                    Extensibility::Mutable,
                    vec![
                        key("id", long()),
                        key("name", string(Some(8))),
                        field("v", long()),
                    ],
                ),
            ),
            (
                "KeyedApp",
                st(
                    "KeyedApp",
                    Extensibility::Appendable,
                    vec![key("id", long()), field("v", long())],
                ),
            ),
            ("UL", ul()),
            (
                "ShapeType",
                st(
                    "ShapeType",
                    Extensibility::Appendable,
                    vec![
                        key("color", string(Some(128))),
                        field("x", long()),
                        field("y", long()),
                        field("shapesize", long()),
                        field(
                            "additional_payload_size",
                            seq(prim(PrimitiveKind::U8), None),
                        ),
                    ],
                ),
            ),
        ]
    }

    /// Bridge objects that differ from Cyclone 0.11's, each for a builder
    /// choice, not a serializer fault: (type, 'C' or 'M', reason).
    const BUILDER_DIFF: &[(&str, char, &str)] = &[
        // Cyclone gives an enum without annotation its own default, @final
        // (enum_flags 0x0001); the dynamic model cannot declare an enum's
        // extensibility and takes the specification's default, appendable.
        ("E8", 'C', "enum default extensibility"),
        ("E8", 'M', "enum default extensibility"),
        ("E16", 'C', "enum default extensibility"),
        ("E16", 'M', "enum default extensibility"),
        ("E32", 'C', "enum default extensibility"),
        ("E32", 'M', "enum default extensibility"),
        ("Enums", 'C', "enum default extensibility (member types)"),
        ("Enums", 'M', "enum default extensibility (member types)"),
        // DDS-XTypes 1.3 7.2.2.4.4.4.8: key members are always
        // must-understand; the bridge sets IS_MUST_UNDERSTAND on a key
        // member (0x31), Cyclone does not (0x21).
        (
            "Keyed",
            'C',
            "key members must-understand (Cyclone omits it)",
        ),
        (
            "Keyed",
            'M',
            "key members must-understand (Cyclone omits it)",
        ),
        (
            "KeyedApp",
            'C',
            "key members must-understand (Cyclone omits it)",
        ),
        (
            "KeyedApp",
            'M',
            "key members must-understand (Cyclone omits it)",
        ),
        (
            "ShapeType",
            'C',
            "key members must-understand (Cyclone omits it)",
        ),
        (
            "ShapeType",
            'M',
            "key members must-understand (Cyclone omits it)",
        ),
        // The bridge numbers union cases from 1 (the discriminator is member
        // 0: 7.2.2.4.4.3 with 7.3.1.2.1.1); Cyclone numbers them from 0.
        ("UL", 'C', "union case member ids from 1 (Cyclone: from 0)"),
        ("UL", 'M', "union case member ids from 1 (Cyclone: from 0)"),
    ];

    #[test]
    fn the_dynamic_bridge_against_the_oracle() {
        let mut report = String::new();
        let mut failures = Vec::new();
        for (name, desc) in corpus() {
            let complete = type_descriptor_to_xtypes_complete(&desc).expect("lowers");
            let minimal_source = type_descriptor_to_xtypes(&desc).expect("lowers");
            let ours_c = hex(&wrap(0xF2, &complete).expect("encode"));
            let ours_m = hex(complete_type_object_minimal_hash(&minimal_source)
                .expect("minimal")
                .as_bytes());
            for (kind, equal) in [
                ('C', ours_c == hex(&oracle(name, 'C').bytes)),
                ('M', ours_m == oracle(name, 'M').hash),
            ] {
                let known = BUILDER_DIFF
                    .iter()
                    .find(|(n, k, _)| *n == name && *k == kind);
                match (equal, known) {
                    (true, None) => report.push_str(&format!("EQUAL   {name} {kind}\n")),
                    (false, Some((_, _, why))) => {
                        report.push_str(&format!("DIFFERS {name} {kind} ({why})\n"));
                    }
                    (true, Some(_)) => failures.push(format!(
                        "{name} {kind} now equals the oracle: remove it from BUILDER_DIFF"
                    )),
                    (false, None) => failures.push(format!("{name} {kind} differs")),
                }
            }
        }
        println!("{report}");
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// A received `@hashid` object keeps its annotation through the dynamic
    /// model: the descriptor read from Cyclone's Complete object carries the
    /// `hash_id` values (Annex B, AppliedBuiltinMemberAnnotations) and lowers
    /// back to the same bytes, so the hash a reader recomputes for a peer's
    /// type is the hash the peer announced.
    #[test]
    fn a_received_hashid_object_lowers_back_to_its_own_bytes() {
        use hdds::xtypes::CompleteTypeObject;
        use hdds::Cdr2Decode;
        for name in ["MutHashid", "HashidAlias"] {
            let want = oracle(name, 'C');
            let mut off = 5usize;
            let received =
                CompleteTypeObject::decode_cdr2_le_at(&want.bytes, &mut off).expect("decode");
            let desc = hdds::dynamic::type_descriptor_from_xtypes(&received);
            let again = type_descriptor_to_xtypes_complete(&desc).expect("lowers");
            assert_eq!(
                hex(&wrap(0xF2, &again).expect("encode")),
                hex(&want.bytes),
                "{name}"
            );
        }
    }
}
