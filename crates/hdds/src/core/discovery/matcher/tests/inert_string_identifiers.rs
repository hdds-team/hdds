// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The inert string identifiers (`TypeIdentifier::TK_STRING8` /
//! `TK_STRING16`, held as `Primitive(..)` by the guardrail on those
//! constants) are read by the matcher as the unbounded strings they denote,
//! so a member a peer announces as `TI_STRING8_SMALL` is judged by
//! DDS-XTypes v1.3 Sec.7.2.4.4.5 Table 16, not as a string against a
//! primitive.

use super::*;
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::xtypes::{
    CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
    CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    TypeIdentifier,
};

/// `@appendable struct Keyed { @key <key_type> name; int32 value; }`
fn keyed(key_type: TypeIdentifier) -> CompleteTypeObject {
    let member = |member_id, member_flags, member_type_id, name: &str| CompleteStructMember {
        common: CommonStructMember {
            member_id,
            member_flags,
            member_type_id,
        },
        detail: CompleteMemberDetail::new(name),
    };
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Keyed"),
        },
        member_seq: vec![
            member(0, MemberFlag::IS_KEY, key_type, "name"),
            member(1, MemberFlag::empty(), TypeIdentifier::TK_INT32, "value"),
        ],
    })
}

fn assignable(
    writer: &CompleteTypeObject,
    reader: &CompleteTypeObject,
    policy: Option<&TypeConsistencyEnforcement>,
) -> bool {
    Matcher::is_type_compatible_with_policy(Some(writer), Some(reader), "Keyed", "Keyed", policy)
}

#[test]
fn an_inert_string8_member_is_the_unbounded_string_a_peer_announces() {
    let ours = keyed(TypeIdentifier::TK_STRING8);
    let spec_default = TypeConsistencyEnforcement::default();
    for peer_key in [
        TypeIdentifier::StringSmall { bound: 0 },
        TypeIdentifier::StringSmall { bound: 128 },
        TypeIdentifier::StringLarge { bound: 300 },
    ] {
        let peer = keyed(peer_key.clone());
        for policy in [None, Some(&spec_default)] {
            assert!(
                assignable(&peer, &ours, policy),
                "a peer writer announcing {peer_key:?} is assignable to our reader \
                 (policy {policy:?})"
            );
            assert!(
                assignable(&ours, &peer, policy),
                "our writer is assignable to a peer reader announcing {peer_key:?} \
                 (policy {policy:?})"
            );
        }
    }
}

/// When the reader enforces string bounds, the inert identifier is held to
/// the bound it denotes: unbounded. A bounded writer fits an unbounded
/// reader; an unbounded writer does not fit a bounded reader.
#[test]
fn an_inert_string8_member_keeps_its_unbounded_bound_when_bounds_are_enforced() {
    let ours = keyed(TypeIdentifier::TK_STRING8);
    let peer = keyed(TypeIdentifier::StringSmall { bound: 128 });
    let strict = TypeConsistencyEnforcement {
        ignore_string_bounds: false,
        ..TypeConsistencyEnforcement::default()
    };
    assert!(
        assignable(&peer, &ours, Some(&strict)),
        "string<128> is assignable to an unbounded string"
    );
    assert!(
        assignable(
            &keyed(TypeIdentifier::StringLarge { bound: 300 }),
            &ours,
            Some(&strict)
        ),
        "string<300> is assignable to an unbounded string: no small bound is assumed"
    );
    assert!(
        !assignable(&ours, &peer, Some(&strict)),
        "an unbounded string is not assignable to string<128> when bounds are enforced"
    );
}

/// The reading is width-preserving: the inert wide string is a wide string,
/// assignable from a wide string and never from a narrow one (Table 16).
#[test]
fn an_inert_string16_member_is_a_wide_string_not_a_narrow_one() {
    let ours = keyed(TypeIdentifier::TK_STRING16);
    let wide = keyed(TypeIdentifier::WStringSmall { bound: 0 });
    let narrow = keyed(TypeIdentifier::StringSmall { bound: 0 });
    assert!(assignable(&wide, &ours, None), "wstring -> inert wstring");
    assert!(assignable(&ours, &wide, None), "inert wstring -> wstring");
    assert!(
        !assignable(&narrow, &ours, None),
        "a narrow string is not assignable to a wide one"
    );
    assert!(
        !assignable(&ours, &narrow, None),
        "a wide string is not assignable to a narrow one"
    );
    assert!(
        !assignable(&keyed(TypeIdentifier::TK_STRING8), &ours, None),
        "the two inert forms keep their widths apart"
    );
}

/// A string is still not a primitive: the reading changes what the inert
/// identifier denotes, not what a string is assignable from.
#[test]
fn an_inert_string8_member_is_still_not_an_integer() {
    let ours = keyed(TypeIdentifier::TK_STRING8);
    let integer = keyed(TypeIdentifier::TK_INT32);
    assert!(!assignable(&integer, &ours, None));
    assert!(!assignable(&ours, &integer, None));
}

/// `@appendable struct Labelled { @key int32 id; <label_type> label; }`: the
/// string is a plain member (a key string follows the same bound flag,
/// `assignable_keys`).
fn labelled(label_type: TypeIdentifier) -> CompleteTypeObject {
    let CompleteTypeObject::Struct(mut s) = keyed(TypeIdentifier::TK_INT32) else {
        unreachable!("keyed builds a struct");
    };
    s.member_seq[1].common.member_type_id = label_type;
    CompleteTypeObject::Struct(s)
}

/// A bound is a bound whichever size class it is written in (DDS-XTypes v1.3
/// Sec.7.6.3.4.1, ignore_string_bounds=false: T1 is assignable from T2 when
/// L1 >= L2, an unbounded L1 holding every L2). The Small/Large split is an
/// encoding detail of `TypeIdentifier`, so it decides nothing here.
#[test]
fn a_string_bound_is_compared_across_size_classes_when_bounds_are_enforced() {
    let strict = TypeConsistencyEnforcement {
        ignore_string_bounds: false,
        ..TypeConsistencyEnforcement::default()
    };
    let large_300 = labelled(TypeIdentifier::StringLarge { bound: 300 });
    let small_200 = labelled(TypeIdentifier::StringSmall { bound: 200 });
    let small_unbounded = labelled(TypeIdentifier::StringSmall { bound: 0 });
    let wide_large_300 = labelled(TypeIdentifier::WStringLarge { bound: 300 });
    let wide_small_200 = labelled(TypeIdentifier::WStringSmall { bound: 200 });
    let wide_small_unbounded = labelled(TypeIdentifier::WStringSmall { bound: 0 });
    for (writer, reader, fits, what) in [
        (&large_300, &small_unbounded, true, "string<300> -> string"),
        (&large_300, &small_200, false, "string<300> -> string<200>"),
        (&small_200, &large_300, true, "string<200> -> string<300>"),
        (&small_unbounded, &large_300, false, "string -> string<300>"),
        (
            &wide_large_300,
            &wide_small_unbounded,
            true,
            "wstring<300> -> wstring",
        ),
        (
            &wide_large_300,
            &wide_small_200,
            false,
            "wstring<300> -> wstring<200>",
        ),
        (
            &wide_small_200,
            &wide_large_300,
            true,
            "wstring<200> -> wstring<300>",
        ),
        (
            &wide_small_unbounded,
            &wide_large_300,
            false,
            "wstring -> wstring<300>",
        ),
    ] {
        assert_eq!(assignable(writer, reader, Some(&strict)), fits, "{what}");
        assert!(
            assignable(writer, reader, None),
            "{what}: bounds are ignored by default"
        );
    }
}
