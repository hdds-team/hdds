// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Union TypeObject EquivalenceHash regression guard (test-only module; no
// production code path touches this).
//
// The rules HDDS follows for a union's Minimal TypeObject (DDS-XTypes 1.3):
//  - 7.2.2.4.4.3: "The discriminator member is always considered to be the
//    first member of a union", combined with 7.3.1.2.1.1 SEQUENTIAL member-id
//    assignment (first member = 0, then previous + 1): the discriminator
//    takes id 0 and the branches are numbered 1..N in declaration order.
//  - 7.2.2.4.4.4.6: "In a union type, the discriminator member shall always
//    have the must understand attribute set to true": the discriminator
//    member_flags are TRY_CONSTRUCT1 | IS_MUST_UNDERSTAND (0x0011).
//  - every branch carries TRY_CONSTRUCT1 (DISCARD, the default of 7.2.2.7).
//
// `HDDS_CURRENT` holds the Minimal hashes HDDS computes for three unions
// under those rules. Two independent paths must reproduce them:
//  - `engine_minimal_hashes_are_pinned`: the engine's own path (descriptor ->
//    `type_descriptor_to_xtypes` -> `complete_type_object_minimal_hash`), the
//    one `--print-typeid` uses;
//  - `hand_encoder_reproduces_the_engine`: a hand-written CDR2-LE preimage of
//    each Minimal TypeObject, laid out field by field from Annex B and hashed
//    with MD5 here, so an accidental flag, id-scheme or framing change in the
//    engine is caught against a layout that does not share its code.
// `hand_encoder_tells_the_rules_apart` checks the hand encoder is sensitive to
// the two rules above, so that its agreement with the engine means something.
//
// Run: cargo test --features xtypes -p hdds union_hash_crack -- --nocapture

#![cfg(all(test, feature = "xtypes"))]

use crate::xtypes::{
    CommonUnionMember, MemberFlag, MinimalMemberDetail, MinimalTypeDetail, MinimalTypeObject,
    MinimalUnionHeader, MinimalUnionMember, MinimalUnionType, TypeIdentifier, TypeKind,
    UnionTypeFlag,
};

// ---------------------------------------------------------------------------
// Reference unions
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct CaseSpec {
    name: &'static str,
    label: i32,
    ty: TypeKind,
}

#[derive(Clone)]
struct UnionSpec {
    /// true => @final (flag 0x0001), false => @appendable (flag 0x0002)
    is_final: bool,
    disc: TypeKind,
    /// declaration order (as written in the IDL)
    cases: Vec<CaseSpec>,
}

fn case(name: &'static str, label: i32, ty: TypeKind) -> CaseSpec {
    CaseSpec { name, label, ty }
}

fn spec_union_int32() -> UnionSpec {
    // @appendable switch(uint32) {1:int16 x1; 2:int32 x2; 3:int32 x3;}
    UnionSpec {
        is_final: false,
        disc: TypeKind::TK_UINT32,
        cases: vec![
            case("x1", 1, TypeKind::TK_INT16),
            case("x2", 2, TypeKind::TK_INT32),
            case("x3", 3, TypeKind::TK_INT32),
        ],
    }
}

fn spec_union_uint32() -> UnionSpec {
    // @appendable switch(uint32) {2:int16 x1; 1:int32 x2;}  (labels OUT OF ORDER)
    UnionSpec {
        is_final: false,
        disc: TypeKind::TK_UINT32,
        cases: vec![
            case("x1", 2, TypeKind::TK_INT16),
            case("x2", 1, TypeKind::TK_INT32),
        ],
    }
}

fn spec_union_primitives_final() -> UnionSpec {
    // @final switch(uint8) {0x01:octet x1; ...; 0x0c:double x12;}
    UnionSpec {
        is_final: true,
        disc: TypeKind::TK_UINT8,
        cases: vec![
            case("x1", 0x01, TypeKind::TK_UINT8), // octet
            case("x2", 0x02, TypeKind::TK_UINT16),
            case("x3", 0x03, TypeKind::TK_UINT32),
            case("x4", 0x04, TypeKind::TK_UINT64),
            case("x5", 0x05, TypeKind::TK_CHAR8), // char
            case("x6", 0x06, TypeKind::TK_INT16),
            case("x7", 0x07, TypeKind::TK_INT32),
            case("x8", 0x08, TypeKind::TK_INT64),
            case("x9", 0x09, TypeKind::TK_BOOLEAN),
            case("x10", 0x0a, TypeKind::TK_FLOAT32),
            case("x11", 0x0b, TypeKind::TK_FLOAT64),
            case("x12", 0x0c, TypeKind::TK_FLOAT64),
        ],
    }
}

/// The Minimal hashes HDDS computes for the three unions above (hex of the
/// 14-byte EquivalenceHash). Our own engine's output, pinned.
struct Targets {
    int32: &'static str,
    uint32: &'static str,
    prim: &'static str,
}

const HDDS_CURRENT: Targets = Targets {
    int32: "45611d883b75ce57a37f3b53a6b5",
    uint32: "396f46dc56effbc37811fb6a874c",
    prim: "9837fe2abd503ab60c13a89cec23",
};

// ---------------------------------------------------------------------------
// The data model, hashed by the engine
// ---------------------------------------------------------------------------

fn name_hash(name: &str) -> u32 {
    MinimalMemberDetail::from_name(name).name_hash
}

/// Branch member id under 7.3.1.2.1.1 with the discriminator as member 0
/// (`one_based`), or with the branches numbered from 0 (the rule broken).
fn branch_id(one_based: bool, decl_idx: usize) -> u32 {
    let idx = u32::try_from(decl_idx).expect("a handful of test cases");
    if one_based {
        idx + 1
    } else {
        idx
    }
}

fn union_flags(spec: &UnionSpec) -> u16 {
    if spec.is_final {
        UnionTypeFlag::IS_FINAL.0
    } else {
        UnionTypeFlag::IS_APPENDABLE.0
    }
}

/// The MinimalUnionType of `spec` under the rules of the module header, as a
/// data model the engine encodes and hashes. `octet` is kept as TK_UINT8.
fn build_union(spec: &UnionSpec) -> MinimalUnionType {
    let members = spec
        .cases
        .iter()
        .enumerate()
        .map(|(i, c)| MinimalUnionMember {
            common: CommonUnionMember {
                member_id: branch_id(true, i),
                member_flags: MemberFlag::TRY_CONSTRUCT1,
                member_type_id: TypeIdentifier::primitive(c.ty),
                label_seq: vec![c.label],
            },
            detail: MinimalMemberDetail::from_name(c.name),
        })
        .collect();
    MinimalUnionType {
        union_flags: UnionTypeFlag(union_flags(spec)),
        header: MinimalUnionHeader {
            discriminator: TypeIdentifier::primitive(spec.disc),
            // The engine writes the discriminator member flags itself
            // (TRY_CONSTRUCT1 | IS_MUST_UNDERSTAND, + IS_KEY for a key).
            discriminator_flags: MemberFlag::empty(),
            detail: MinimalTypeDetail::new(),
        },
        member_seq: members,
    }
}

fn hash_of(spec: &UnionSpec) -> String {
    let to = MinimalTypeObject::Union(build_union(spec));
    format!("{}", to.compute_equivalence_hash().expect("hash"))
}

/// The data model above, encoded and hashed by the engine, gives the pinned
/// hash. `prim` is not compared here: the model keeps `octet` as TK_UINT8,
/// while the descriptor bridge maps it to TK_BYTE (covered by the two tests
/// below).
#[test]
fn baseline_reproduces_hdds_current() {
    assert_eq!(
        hash_of(&spec_union_int32()),
        HDDS_CURRENT.int32,
        "int32 baseline"
    );
    assert_eq!(
        hash_of(&spec_union_uint32()),
        HDDS_CURRENT.uint32,
        "uint32 baseline"
    );
}

// ---------------------------------------------------------------------------
// The engine's own path: descriptor -> CompleteTypeObject -> minimal hash
// ---------------------------------------------------------------------------

#[test]
fn engine_minimal_hashes_are_pinned() {
    use super::type_descriptor::{
        Extensibility, PrimitiveKind, TypeDescriptor, TypeKind, UnionCase, UnionDescriptor,
    };
    use super::xtypes_bridge::{complete_type_object_minimal_hash, type_descriptor_to_xtypes};
    use crate::xtypes::{MinimalTypeObject, TypeIdentifier};
    use std::sync::Arc;

    let prim = |n: &str, k: PrimitiveKind| Arc::new(TypeDescriptor::primitive(n, k));

    let build = |name: &str, ext: Extensibility, disc: PrimitiveKind, cases: Vec<UnionCase>| {
        TypeDescriptor::new(
            name,
            TypeKind::Union(UnionDescriptor::new(
                Arc::new(TypeDescriptor::primitive("disc", disc)),
                cases,
            )),
        )
        .with_extensibility(ext)
    };

    // union_int32 @appendable switch(uint32) {1:int16 x1; 2:int32 x2; 3:int32 x3;}
    let int32 = build(
        "union_int32",
        Extensibility::Appendable,
        PrimitiveKind::U32,
        vec![
            UnionCase::single("x1", 1, prim("int16", PrimitiveKind::I16)),
            UnionCase::single("x2", 2, prim("int32", PrimitiveKind::I32)),
            UnionCase::single("x3", 3, prim("int32", PrimitiveKind::I32)),
        ],
    );
    // union_uint32 @appendable switch(uint32) {2:int16 x1; 1:int32 x2;}  (OUT OF ORDER)
    let uint32 = build(
        "union_uint32",
        Extensibility::Appendable,
        PrimitiveKind::U32,
        vec![
            UnionCase::single("x1", 2, prim("int16", PrimitiveKind::I16)),
            UnionCase::single("x2", 1, prim("int32", PrimitiveKind::I32)),
        ],
    );
    // union_primitives_final @final switch(uint8) {0x01:octet x1; ... }
    let prim_final = build(
        "union_primitives_final",
        Extensibility::Final,
        PrimitiveKind::U8,
        vec![
            UnionCase::single("x1", 0x01, prim("octet", PrimitiveKind::Byte)),
            UnionCase::single("x2", 0x02, prim("uint16", PrimitiveKind::U16)),
            UnionCase::single("x3", 0x03, prim("uint32", PrimitiveKind::U32)),
            UnionCase::single("x4", 0x04, prim("uint64", PrimitiveKind::U64)),
            UnionCase::single("x5", 0x05, prim("char", PrimitiveKind::Char)),
            UnionCase::single("x6", 0x06, prim("int16", PrimitiveKind::I16)),
            UnionCase::single("x7", 0x07, prim("int32", PrimitiveKind::I32)),
            UnionCase::single("x8", 0x08, prim("int64", PrimitiveKind::I64)),
            UnionCase::single("x9", 0x09, prim("boolean", PrimitiveKind::Bool)),
            UnionCase::single("x10", 0x0a, prim("float32", PrimitiveKind::F32)),
            UnionCase::single("x11", 0x0b, prim("float64", PrimitiveKind::F64)),
            UnionCase::single("x12", 0x0c, prim("float64", PrimitiveKind::F64)),
        ],
    );

    for (label, d, want) in [
        ("union_int32", &int32, HDDS_CURRENT.int32),
        ("union_uint32", &uint32, HDDS_CURRENT.uint32),
        ("union_primitives_final", &prim_final, HDDS_CURRENT.prim),
    ] {
        let complete = type_descriptor_to_xtypes(d).expect("to xtypes");
        let h = complete_type_object_minimal_hash(&complete).expect("min hash");
        // Decode the actual minimal bytes, printed to show member ids,
        // flags, types and order when the hash moves.
        let (_c, minner) =
            super::xtypes_bridge::debug_type_object_inner_cdr2(&complete).expect("debug inner");
        use crate::core::ser::traits::Cdr2Decode;
        let (mto, _used) = MinimalTypeObject::decode_cdr2_le(&minner).expect("decode min");
        eprintln!("\n### {label}: minimal hash = {h}  (want {want})");
        if let MinimalTypeObject::Union(u) = mto {
            eprintln!("  union_flags = 0x{:04x}", u.union_flags.0);
            eprintln!("  discriminator = {:?}", u.header.discriminator);
            for m in &u.member_seq {
                let tystr = match &m.common.member_type_id {
                    TypeIdentifier::Primitive(k) => format!("Primitive(0x{:02x})", k.to_u8()),
                    other => format!("{other:?}"),
                };
                eprintln!(
                    "  member id={} flags=0x{:04x} type={} labels={:?} name_hash=0x{:08x}",
                    m.common.member_id,
                    m.common.member_flags.0,
                    tystr,
                    m.common.label_seq,
                    m.detail.name_hash
                );
            }
        }
        assert_eq!(format!("{h}"), want, "{label}: engine minimal hash");
    }
}

// ===========================================================================
// HAND-WRITTEN CDR2-LE PREIMAGE
//
// The Minimal TypeObject of a union, written byte by byte from DDS-XTypes 1.3
// Annex B and hashed with MD5 here (7.3.4.8: the first 14 bytes of the MD5 of
// the serialized TypeObject). It shares no code with the engine's encoder.
// ===========================================================================

fn cw_align(b: &mut Vec<u8>, n: usize) {
    while !b.len().is_multiple_of(n) {
        b.push(0);
    }
}
fn cw_u8(b: &mut Vec<u8>, v: u8) {
    b.push(v);
}
fn cw_u16(b: &mut Vec<u8>, v: u16) {
    cw_align(b, 2);
    b.extend_from_slice(&v.to_le_bytes());
}
fn cw_u32(b: &mut Vec<u8>, v: u32) {
    cw_align(b, 4);
    b.extend_from_slice(&v.to_le_bytes());
}
fn cw_i32(b: &mut Vec<u8>, v: i32) {
    cw_align(b, 4);
    b.extend_from_slice(&v.to_le_bytes());
}
/// DHEADER (7.4.3.5.2): pad to 4, reserve a u32, write the body, backpatch
/// the body's byte count.
fn cw_dheader<F: FnOnce(&mut Vec<u8>)>(b: &mut Vec<u8>, body: F) {
    cw_align(b, 4);
    let pos = b.len();
    b.extend_from_slice(&[0u8; 4]);
    let start = b.len();
    body(b);
    let size = u32::try_from(b.len() - start).expect("small test buffer");
    b[pos..pos + 4].copy_from_slice(&size.to_le_bytes());
}

/// The choices the hand encoder exposes: the two rules of the module header
/// and the TypeKind `octet` is written as.
#[derive(Clone, Copy, Debug)]
struct CKnobs {
    /// Discriminator member_flags.
    disc_flags: u16,
    /// Branch ids 1..N (discriminator = member 0) or 0..N-1.
    one_based_ids: bool,
    /// `octet` as TK_BYTE (0x02) rather than TK_UINT8 (0x0D).
    octet_as_byte: bool,
}

/// The knobs of the rules HDDS follows; `octet` as TK_BYTE, as the
/// descriptor bridge maps it.
const HDDS_RULES: CKnobs = CKnobs {
    disc_flags: MemberFlag::TRY_CONSTRUCT1.0 | MemberFlag::IS_MUST_UNDERSTAND.0,
    one_based_ids: true,
    octet_as_byte: true,
};

fn custom_hash(spec: &UnionSpec, k: CKnobs) -> String {
    use md5::{Digest, Md5};

    let type_byte = |ty: TypeKind| {
        if ty == TypeKind::TK_UINT8 && k.octet_as_byte {
            TypeKind::TK_BYTE.to_u8()
        } else {
            ty.to_u8()
        }
    };

    let mut b: Vec<u8> = Vec::new();
    // TypeObject (@appendable union): DHEADER, then EK_MINIMAL.
    cw_dheader(&mut b, |b| {
        cw_u8(b, 0xF1); // EK_MINIMAL
        cw_u8(b, TypeKind::TK_UNION.to_u8()); // MinimalTypeObject: TK_UNION
        cw_u16(b, union_flags(spec)); // MinimalUnionType.union_flags
                                      // MinimalUnionHeader (@appendable): DHEADER + empty MinimalTypeDetail.
        cw_dheader(b, |_b| {});
        // MinimalDiscriminatorMember (@appendable): DHEADER +
        // CommonDiscriminatorMember { member_flags, type_id }.
        cw_dheader(b, |b| {
            cw_u16(b, k.disc_flags);
            cw_u8(b, spec.disc.to_u8());
        });
        // MinimalUnionMemberSeq: DHEADER (non-primitive element) + length.
        cw_dheader(b, |b| {
            cw_u32(b, u32::try_from(spec.cases.len()).expect("small"));
            for (i, c) in spec.cases.iter().enumerate() {
                // MinimalUnionMember (@appendable).
                cw_dheader(b, |b| {
                    // CommonUnionMember (@final): member_id, member_flags,
                    // type_id, label_seq.
                    cw_u32(b, branch_id(k.one_based_ids, i));
                    cw_u16(b, MemberFlag::TRY_CONSTRUCT1.0);
                    cw_u8(b, type_byte(c.ty));
                    cw_u32(b, 1);
                    cw_i32(b, c.label);
                    // MinimalMemberDetail: NameHash.
                    cw_u32(b, name_hash(c.name));
                });
            }
        });
    });

    let digest = Md5::digest(&b);
    let mut s = String::new();
    for byte in &digest[..14] {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// The hand-written preimage under the rules HDDS follows hashes to the
/// engine's pinned value for all three unions.
#[test]
fn hand_encoder_reproduces_the_engine() {
    assert_eq!(
        custom_hash(&spec_union_int32(), HDDS_RULES),
        HDDS_CURRENT.int32,
        "int32"
    );
    assert_eq!(
        custom_hash(&spec_union_uint32(), HDDS_RULES),
        HDDS_CURRENT.uint32,
        "uint32"
    );
    assert_eq!(
        custom_hash(&spec_union_primitives_final(), HDDS_RULES),
        HDDS_CURRENT.prim,
        "prim"
    );
}

/// Breaking either rule moves every hash: the agreement above is not a
/// coincidence of an encoder blind to them.
#[test]
fn hand_encoder_tells_the_rules_apart() {
    let zero_based = CKnobs {
        one_based_ids: false,
        ..HDDS_RULES
    };
    let disc_not_must_understand = CKnobs {
        disc_flags: MemberFlag::TRY_CONSTRUCT1.0,
        ..HDDS_RULES
    };
    for spec in [
        spec_union_int32(),
        spec_union_uint32(),
        spec_union_primitives_final(),
    ] {
        let ours = custom_hash(&spec, HDDS_RULES);
        assert_ne!(custom_hash(&spec, zero_based), ours, "branch ids");
        assert_ne!(
            custom_hash(&spec, disc_not_must_understand),
            ours,
            "discriminator flags"
        );
    }
}
