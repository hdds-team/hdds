// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#[allow(clippy::wildcard_imports)]
use super::test_vectors::*;
use super::*;
use crate::xtypes::{
    decompress_type_object, CompleteTypeObject, MemberFlag, StructTypeFlag, TypeIdentifier,
    TypeKind, UnionTypeFlag,
};

fn expect_int32_array10(type_id: &TypeIdentifier) {
    match type_id {
        TypeIdentifier::PlainArraySmall(d) => {
            assert_eq!(d.array_bound_seq, vec![10u8]);
            assert_eq!(
                *d.element_identifier,
                TypeIdentifier::Primitive(TypeKind::TK_INT32)
            );
        }
        other => panic!("expected PlainArraySmall<10>[TK_INT32], got {other:?}"),
    }
}

#[test]
fn decodes_rti_golden_vector_struct_shape() {
    let decoded = decode_type_object_v1(&RTI_INT32X10_V1).expect("golden vector must decode");
    match &decoded.root {
        CompleteTypeObject::Struct(s) => {
            assert_eq!(s.header.detail.type_name, "Test::int32x10");
            assert_eq!(s.struct_flags, StructTypeFlag::IS_FINAL);
            assert!(s.header.base_type.is_none());
            assert_eq!(s.member_seq.len(), 1);
            let m = &s.member_seq[0];
            assert_eq!(m.detail.name, "x1");
            assert_eq!(m.common.member_id, 0);
            expect_int32_array10(&m.common.member_type_id);
        }
        other => panic!("expected Struct root, got {other:?}"),
    }
    // The array_10_Int32 helper is inlined, never a standalone dependent.
    assert!(
        decoded.dependents.is_empty(),
        "anonymous collection helper must not be registered as a dependent"
    );
}

/// CoreDX emits DISTINCT v1 kinds for the 8-bit integers (24 = int8,
/// 25 = uint8), unlike RTI's BYTE-collapse. The decode must map them
/// to TK_INT8 / TK_UINT8 faithfully; before the kind-table extension
/// these payloads failed to decode entirely (the discriminator fell
/// into the complex arm and derailed the member parse), degrading the
/// OMG negatives struct_*_int8 / struct_*_uint8 to silent no-match.
#[test]
fn decodes_coredx_int8_uint8_vendor_extension_kinds() {
    for (vector, expected_name, expected_kind) in [
        (
            &COREDX_STRUCT_INT8_V1[..],
            "Test::struct_primitive_int8",
            TypeKind::TK_INT8,
        ),
        (
            &COREDX_STRUCT_UINT8_V1[..],
            "Test::struct_primitive_uint8",
            TypeKind::TK_UINT8,
        ),
    ] {
        let decoded = decode_type_object_v1(vector).expect("captured coredx vector must decode");
        match &decoded.root {
            CompleteTypeObject::Struct(s) => {
                assert_eq!(s.header.detail.type_name, expected_name);
                assert_eq!(s.struct_flags, StructTypeFlag::IS_FINAL);
                assert_eq!(s.member_seq.len(), 1);
                let m = &s.member_seq[0];
                assert_eq!(m.detail.name, "x1");
                assert_eq!(m.common.member_id, 0);
                assert_eq!(
                    m.common.member_type_id,
                    TypeIdentifier::Primitive(expected_kind),
                    "{expected_name} member kind"
                );
            }
            other => panic!("expected Struct root, got {other:?}"),
        }
        assert!(decoded.dependents.is_empty());
    }
}

#[test]
fn decodes_coredx_golden_vector_flat_qualified_name() {
    let decoded =
        decode_type_object_v1(&COREDX_STRUCT_X1_V1).expect("coredx golden vector must decode");
    match &decoded.root {
        CompleteTypeObject::Struct(s) => {
            assert_eq!(s.header.detail.type_name, "Test::struct_x1");
            assert_eq!(s.member_seq.len(), 1);
            let m = &s.member_seq[0];
            assert_eq!(m.detail.name, "x1");
            assert_eq!(m.common.member_id, 0);
            assert_eq!(
                m.common.member_type_id,
                TypeIdentifier::Primitive(TypeKind::TK_INT32)
            );
        }
        other => panic!("expected Struct root, got {other:?}"),
    }
    assert!(decoded.dependents.is_empty());
}

#[test]
fn decodes_rti_full_envelope_via_decompress_type_object() {
    // Mirrors parse.rs's PID_TYPE_OBJECT_LB handling: decompress the
    // zlib envelope first, then run the v1 decoder on the result.
    let decompressed = decompress_type_object(&RTI_INT32X10_PARAM, 12, 184)
        .expect("zlib envelope must decompress");
    assert_eq!(decompressed.len(), 408);
    assert_eq!(decompressed.as_slice(), &RTI_INT32X10_V1[..]);

    let decoded = decode_type_object_v1(&decompressed).expect("decompressed payload must decode");
    match &decoded.root {
        CompleteTypeObject::Struct(s) => {
            assert_eq!(s.header.detail.type_name, "Test::int32x10");
        }
        other => panic!("expected Struct root, got {other:?}"),
    }
}

#[test]
fn truncated_golden_vector_errors_never_panics() {
    for len in [
        0usize, 1, 2, 4, 8, 12, 16, 32, 64, 100, 150, 200, 250, 300, 350, 400, 407,
    ] {
        let result = std::panic::catch_unwind(|| decode_type_object_v1(&RTI_INT32X10_V1[..len]));
        match result {
            Ok(decoded) => assert!(
                decoded.is_err(),
                "truncated buffer (len={len}) must not decode successfully"
            ),
            Err(_) => panic!("decode_type_object_v1 panicked on truncated input (len={len})"),
        }
    }
}

#[test]
fn truncated_coredx_vector_errors_never_panics() {
    for len in [0usize, 1, 4, 12, 40, 80, 120, 160, 200, 223] {
        let result =
            std::panic::catch_unwind(|| decode_type_object_v1(&COREDX_STRUCT_X1_V1[..len]));
        match result {
            Ok(decoded) => assert!(
                decoded.is_err(),
                "truncated coredx buffer (len={len}) must not decode successfully"
            ),
            Err(_) => {
                panic!("decode_type_object_v1 panicked on truncated coredx input (len={len})")
            }
        }
    }
}

#[test]
fn garbage_bytes_error_never_panics() {
    let patterns: [&[u8]; 5] = [&[], &[0u8; 1], &[0xFFu8; 8], &[0xFFu8; 64], &[0x00u8; 256]];
    for (i, pattern) in patterns.iter().enumerate() {
        let result = std::panic::catch_unwind(|| decode_type_object_v1(pattern));
        match result {
            Ok(decoded) => assert!(decoded.is_err(), "garbage pattern #{i} must not decode"),
            Err(_) => panic!("decode_type_object_v1 panicked on garbage pattern #{i}"),
        }
    }
    // A pattern that happens to start with the v1 sniff bytes but is
    // otherwise nonsense must still error, not panic.
    let mut sniff_then_garbage = vec![0x01u8, 0x7f, 0x08, 0x00];
    sniff_then_garbage.extend(std::iter::repeat_n(0xAAu8, 60));
    let result = std::panic::catch_unwind(|| decode_type_object_v1(&sniff_then_garbage));
    match result {
        Ok(decoded) => assert!(decoded.is_err(), "sniff-prefixed garbage must not decode"),
        Err(_) => panic!("decode_type_object_v1 panicked on sniff-prefixed garbage"),
    }
}

// Named-type member resolution (the Minimal-hash + dependents pipeline)
// requires `xtypes-structural-assignability`; see `minimal_hash_of`.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn hand_built_named_member_reference_produces_dependent() {
    let decoded =
        decode_type_object_v1(&STRUCT_WITH_ENUM_V1).expect("hand-built payload must decode");

    let member_type_id = match &decoded.root {
        CompleteTypeObject::Struct(s) => {
            assert_eq!(s.header.detail.type_name, "Test::StructWithEnum");
            assert_eq!(s.member_seq.len(), 1);
            assert_eq!(s.member_seq[0].detail.name, "color");
            s.member_seq[0].common.member_type_id.clone()
        }
        other => panic!("expected Struct root, got {other:?}"),
    };

    let hash = match member_type_id {
        TypeIdentifier::Minimal(h) => h,
        other => panic!("expected Minimal(hash) member reference, got {other:?}"),
    };

    assert_eq!(
        decoded.dependents.len(),
        1,
        "exactly one dependent (the enum)"
    );
    let (dep_hash, dep_obj) = &decoded.dependents[0];
    assert_eq!(
        *dep_hash, hash,
        "dependent must be keyed by the member's referenced hash"
    );
    match dep_obj {
        CompleteTypeObject::Enumerated(e) => {
            assert_eq!(e.header.detail.type_name, "Test::Color");
            assert_eq!(e.literal_seq.len(), 3);
            assert_eq!(e.literal_seq[0].detail.name, "RED");
            assert_eq!(e.literal_seq[0].common.value, 0);
            assert_eq!(e.literal_seq[1].detail.name, "GREEN");
            assert_eq!(e.literal_seq[1].common.value, 1);
            assert_eq!(e.literal_seq[2].detail.name, "BLUE");
            assert_eq!(e.literal_seq[2].common.value, 2);
        }
        other => panic!("expected Enumerated dependent, got {other:?}"),
    }

    // The hash embedded in the member reference must be independently
    // reproducible from the dependent object alone (self-consistency
    // of the Minimal-hash machinery this decoder relies on).
    let recomputed_minimal = crate::dynamic::complete_to_minimal_type_object(dep_obj)
        .expect("enum must convert to MinimalTypeObject");
    let recomputed_hash = recomputed_minimal
        .compute_equivalence_hash()
        .expect("hash computation must succeed");
    assert_eq!(recomputed_hash, hash);
}

/// Decode the hand-built `Test::union_primitives_final` v1 payload (the
/// OMG suite union, encoded with the measured RTI 8-bit collapse; see
/// the vector's doc comment) and pin the union parser's structural
/// output: extensibility, discriminator, member count/order, per-member
/// ids, names, single-label lists, and the collapsed primitive kinds.
#[test]
fn decodes_union_primitives_final_v1_structure() {
    let decoded = decode_type_object_v1(&UNION_PRIMITIVES_FINAL_V1)
        .expect("hand-built union_primitives_final v1 payload must decode");

    let u = match &decoded.root {
        CompleteTypeObject::Union(u) => u,
        other => panic!("expected Union root, got {other:?}"),
    };
    assert_eq!(u.header.detail.type_name, "Test::union_primitives_final");
    assert_eq!(u.union_flags, UnionTypeFlag::IS_FINAL);
    // uint8 discriminator arrives as v1 kind BYTE (the 8-bit collapse).
    assert_eq!(
        u.header.discriminator,
        TypeIdentifier::Primitive(TypeKind::TK_BYTE)
    );
    assert_eq!(u.member_seq.len(), 14, "14 case members (disc excluded)");

    // (name, wire member id [1-based, disc owns 0], label, decoded member kind)
    let expected: [(&str, u32, i32, TypeKind); 14] = [
        ("x1", 1, 1, TypeKind::TK_BYTE), // IDL uint8 -> v1 BYTE
        ("x2", 2, 2, TypeKind::TK_UINT16),
        ("x3", 3, 3, TypeKind::TK_UINT32),
        ("x4", 4, 4, TypeKind::TK_UINT64),
        ("x5", 5, 5, TypeKind::TK_BYTE), // IDL int8 -> v1 BYTE
        ("x6", 6, 6, TypeKind::TK_INT16),
        ("x7", 7, 7, TypeKind::TK_INT32),
        ("x8", 8, 8, TypeKind::TK_INT64),
        ("x9", 9, 9, TypeKind::TK_BOOLEAN),
        ("x10", 10, 10, TypeKind::TK_FLOAT32),
        ("x11", 11, 11, TypeKind::TK_FLOAT64),
        ("x12", 12, 12, TypeKind::TK_FLOAT128),
        ("x13", 13, 13, TypeKind::TK_BYTE), // IDL byte -> v1 BYTE
        ("x14", 14, 14, TypeKind::TK_CHAR8),
    ];
    for (i, (name, id, label, kind)) in expected.iter().enumerate() {
        let m = &u.member_seq[i];
        assert_eq!(m.detail.name, *name, "member {i} name");
        assert_eq!(m.common.member_id, *id, "member {i} id");
        assert_eq!(m.common.label_seq, vec![*label], "member {i} labels");
        assert_eq!(
            m.common.member_type_id,
            TypeIdentifier::Primitive(*kind),
            "member {i} type kind"
        );
        assert!(
            !m.common.member_flags.contains(MemberFlag::IS_DEFAULT),
            "no default case in union_primitives_final"
        );
    }
    assert!(
        decoded.dependents.is_empty(),
        "all-primitive union has no dependents"
    );
}

/// Wire convention (coredx-conformant, verified on the wire, matching
/// `xtypes::cdr2::unions`'s `CompleteUnionType` decoder): a @key
/// discriminator is flagged on the discriminator's OWN wire member entry
/// only; branch/case members are never key-flagged on the wire. The v1
/// decoder must re-establish the HDDS-internal convention (IS_KEY mirrored
/// onto every case member) that `is_union_assignable`'s key-agreement rule
/// (matcher/types.rs) inspects via `member_seq`, not `discriminator_flags`.
///
/// Regression coverage for OMG `union_uint32_one_key`
/// (`Test::union_uint32` vs `Test::union_uint32_key`, expected
/// INCONSISTENT_TOPIC both sides): without this propagation, a v1-decoded
/// key-discriminated union is indistinguishable from a non-keyed one to
/// that check, and HDDS wrongly reports the pairing as compatible.
#[test]
fn build_union_propagates_key_discriminator_onto_case_members() {
    use super::build::{build_union, BuildCtx};
    use super::flatten::RawMember;
    use super::wire::RawTypeId;
    use std::collections::{HashMap, HashSet};

    let library = HashMap::new();
    let mut ctx = BuildCtx {
        library: &library,
        dependents: HashMap::new(),
        building: HashSet::new(),
        resolved_named: HashMap::new(),
        steps: 0,
    };

    // Mirrors Test::union_uint32_key (unions_key_discriminator.xml):
    // <discriminator type="uint32" key="true"/>, case x1 (label 2, int16),
    // case x2 (label 1, int32) -- neither case member is @key in the IDL.
    let members = vec![
        RawMember {
            flags: 0x0001, // bit0 = IS_KEY, per the wire's discriminator-only convention
            member_id: 0,
            type_id: RawTypeId::Primitive(6), // UINT_32_TYPE
            name: String::new(),
            labels: vec![],
        },
        RawMember {
            flags: 0x0000,
            member_id: 0,
            type_id: RawTypeId::Primitive(3), // INT_16_TYPE
            name: "x1".to_string(),
            labels: vec![2],
        },
        RawMember {
            flags: 0x0000,
            member_id: 1,
            type_id: RawTypeId::Primitive(5), // INT_32_TYPE
            name: "x2".to_string(),
            labels: vec![1],
        },
    ];

    let built = build_union("Test::union_uint32_key".to_string(), 0, &members, &mut ctx)
        .expect("build_union must succeed for a simple primitive-case union");

    assert!(
        built
            .header
            .discriminator_flags
            .contains(MemberFlag::IS_KEY),
        "discriminator_flags must retain IS_KEY as decoded from the wire"
    );
    assert_eq!(built.member_seq.len(), 2);
    for m in &built.member_seq {
        assert!(
            m.common.member_flags.contains(MemberFlag::IS_KEY),
            "case member '{}' must have IS_KEY re-injected when the discriminator is @key",
            m.detail.name
        );
    }
}

/// Companion negative case: a NON-key discriminator must NOT cause the
/// propagation to fire (no false-positive IS_KEY on case members).
#[test]
fn build_union_no_key_propagation_when_discriminator_not_keyed() {
    use super::build::{build_union, BuildCtx};
    use super::flatten::RawMember;
    use super::wire::RawTypeId;
    use std::collections::{HashMap, HashSet};

    let library = HashMap::new();
    let mut ctx = BuildCtx {
        library: &library,
        dependents: HashMap::new(),
        building: HashSet::new(),
        resolved_named: HashMap::new(),
        steps: 0,
    };

    // Mirrors Test::union_uint32 (unions.xml): plain uint32 discriminator,
    // no @key anywhere.
    let members = vec![
        RawMember {
            flags: 0x0000,
            member_id: 0,
            type_id: RawTypeId::Primitive(6),
            name: String::new(),
            labels: vec![],
        },
        RawMember {
            flags: 0x0000,
            member_id: 0,
            type_id: RawTypeId::Primitive(3),
            name: "x1".to_string(),
            labels: vec![2],
        },
        RawMember {
            flags: 0x0000,
            member_id: 1,
            type_id: RawTypeId::Primitive(5),
            name: "x2".to_string(),
            labels: vec![1],
        },
    ];

    let built = build_union("Test::union_uint32".to_string(), 0, &members, &mut ctx)
        .expect("build_union must succeed for a simple primitive-case union");

    assert!(!built
        .header
        .discriminator_flags
        .contains(MemberFlag::IS_KEY));
    for m in &built.member_seq {
        assert!(
            !m.common.member_flags.contains(MemberFlag::IS_KEY),
            "case member '{}' must NOT gain IS_KEY when the discriminator is not @key",
            m.detail.name
        );
    }
}

#[test]
fn array_dimensions_past_the_cap_are_refused() {
    use super::flatten::read_array_bounds;
    use super::wire::MAX_ARRAY_DIMENSIONS;
    let encode = |n: usize| {
        let mut buf = u32::try_from(n).expect("small").to_le_bytes().to_vec();
        for _ in 0..n {
            buf.extend_from_slice(&7u32.to_le_bytes());
        }
        buf
    };
    assert_eq!(
        read_array_bounds(&encode(MAX_ARRAY_DIMENSIONS), 0).map(|b| b.len()),
        Ok(MAX_ARRAY_DIMENSIONS)
    );
    assert_eq!(
        read_array_bounds(&encode(MAX_ARRAY_DIMENSIONS + 1), 0),
        Err(ParseError::InvalidFormat)
    );
    assert_eq!(
        read_array_bounds(&encode(0), 0),
        Err(ParseError::InvalidFormat)
    );
}

#[test]
fn resolutions_past_the_budget_are_refused() {
    use super::build::resolve_type_id;
    use super::wire::{RawTypeId, MAX_RESOLUTION_STEPS};
    let library = HashMap::new();
    let mut ctx = BuildCtx {
        library: &library,
        dependents: HashMap::new(),
        building: HashSet::new(),
        resolved_named: HashMap::new(),
        steps: MAX_RESOLUTION_STEPS - 1,
    };
    // The last step inside the budget resolves; the next one is refused.
    assert!(resolve_type_id(&RawTypeId::Primitive(5), &mut ctx).is_ok());
    assert_eq!(
        resolve_type_id(&RawTypeId::Primitive(5), &mut ctx),
        Err(ParseError::InvalidFormat)
    );
}

/// Connext announces its unbounded `sequence<uint8>` with bound 0x7FFFFFFF;
/// the decoded identifier is the unbounded sequence (bound 0), as a local
/// type declares it, with the v1 element kind BYTE.
#[test]
fn connext_unbounded_sequence_bound_decodes_as_unbounded() {
    let decoded =
        decode_type_object_v1(&CONNEXT_SHAPETYPE_V1).expect("captured ShapeType must decode");
    let CompleteTypeObject::Struct(s) = &decoded.root else {
        panic!("expected Struct root, got {:?}", decoded.root);
    };
    assert_eq!(s.header.detail.type_name, "ShapeType");
    assert_eq!(s.struct_flags, StructTypeFlag::IS_APPENDABLE);
    let payload = &s.member_seq[4];
    assert_eq!(payload.detail.name, "additional_payload_size");
    match &payload.common.member_type_id {
        TypeIdentifier::PlainSequenceSmall(d) => {
            assert_eq!(d.bound, 0, "unbounded");
            assert_eq!(
                *d.element_identifier,
                TypeIdentifier::Primitive(TypeKind::TK_BYTE)
            );
        }
        other => panic!("expected an unbounded PlainSequenceSmall, got {other:?}"),
    }
}

/// A declared sequence bound that is not the unbounded sentinel is kept.
#[test]
fn a_declared_sequence_bound_is_kept() {
    use super::build::build_plain_sequence;
    let elem = TypeIdentifier::Primitive(TypeKind::TK_INT32);
    match build_plain_sequence(0x7FFF_FFFE, elem.clone()) {
        TypeIdentifier::PlainSequenceLarge(d) => assert_eq!(d.bound, 0x7FFF_FFFE),
        other => panic!("expected PlainSequenceLarge, got {other:?}"),
    }
    match build_plain_sequence(100, elem) {
        TypeIdentifier::PlainSequenceSmall(d) => assert_eq!(d.bound, 100),
        other => panic!("expected PlainSequenceSmall, got {other:?}"),
    }
}

/// The Connext 6 Temperature announcement is APPENDABLE: a FINAL local
/// Temperature is neither a v1 stand-in for it nor assignable either way;
/// an APPENDABLE local Temperature is both.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn rti_temperature_extensibility_is_judged_as_announced() {
    use crate::core::discovery::Matcher;
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail,
    };
    let decoded = decode_type_object_v1(&RTI_TEMPERATURE_V1)
        .expect("captured Temperature must decode")
        .root;
    let local = |flags: StructTypeFlag| {
        let member = |id: u32, kind: TypeKind, name: &str| CompleteStructMember {
            common: CommonStructMember {
                member_id: id,
                member_flags: MemberFlag::TRY_CONSTRUCT1,
                member_type_id: TypeIdentifier::Primitive(kind),
            },
            detail: CompleteMemberDetail::new(name),
        };
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: flags,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Temperature"),
            },
            member_seq: vec![
                member(0, TypeKind::TK_INT32, "id"),
                member(1, TypeKind::TK_FLOAT32, "value"),
                member(2, TypeKind::TK_UINT64, "timestamp"),
            ],
        })
    };
    let no_deps = |_: &crate::xtypes::EquivalenceHash| None;
    let compatible = |w: &CompleteTypeObject, r: &CompleteTypeObject| {
        Matcher::is_type_compatible_with_policy(
            Some(w),
            Some(r),
            "Temperature",
            "Temperature",
            None,
        )
    };

    let final_local = local(StructTypeFlag::IS_FINAL);
    assert!(!v1_projection_equivalent(&final_local, &decoded, &no_deps));
    assert!(!compatible(&decoded, &final_local));
    assert!(!compatible(&final_local, &decoded));

    let appendable_local = local(StructTypeFlag::IS_APPENDABLE);
    assert!(v1_projection_equivalent(
        &appendable_local,
        &decoded,
        &no_deps
    ));
    assert!(compatible(&decoded, &appendable_local));
    assert!(compatible(&appendable_local, &decoded));
}
