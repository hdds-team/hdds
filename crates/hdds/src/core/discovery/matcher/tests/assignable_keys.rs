// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::xtypes::{
    CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
    CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    TypeIdentifier,
};

#[derive(Clone)]
struct MemberSpec {
    id: u32,
    type_id: TypeIdentifier,
    flags: MemberFlag,
    name: &'static str,
}

fn key_member(id: u32, name: &'static str, type_id: TypeIdentifier) -> MemberSpec {
    MemberSpec {
        id,
        type_id,
        flags: MemberFlag::IS_KEY,
        name,
    }
}

fn value_member(id: u32, name: &'static str, type_id: TypeIdentifier) -> MemberSpec {
    MemberSpec {
        id,
        type_id,
        flags: MemberFlag::empty(),
        name,
    }
}

fn build_struct(name: &str, members: &[MemberSpec]) -> CompleteTypeObject {
    let member_seq = members
        .iter()
        .map(|spec| CompleteStructMember {
            common: CommonStructMember {
                member_id: spec.id,
                member_flags: spec.flags,
                member_type_id: spec.type_id.clone(),
            },
            detail: CompleteMemberDetail::new(spec.name),
        })
        .collect();

    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_MUTABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq,
    })
}

#[test]
fn test_assignable_keys_identical() {
    let writer = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_different_member_id() {
    let writer = build_struct(
        "DataSample",
        &[
            key_member(0, "sensor_id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "DataSample",
        &[
            value_member(0, "sensor_id", TypeIdentifier::TK_INT32),
            key_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_different_type() {
    let writer = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_UINT64),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_count_mismatch() {
    let writer = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            value_member(1, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "DataSample",
        &[
            key_member(0, "id", TypeIdentifier::TK_INT32),
            key_member(1, "partition", TypeIdentifier::TK_UINT16),
            value_member(2, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_no_keys_compatible() {
    let writer = build_struct(
        "PlainType",
        &[value_member(0, "value", TypeIdentifier::TK_FLOAT32)],
    );
    let reader = writer.clone();

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

#[test]
fn test_assignable_keys_multiple_keys_compatible() {
    let writer = build_struct(
        "MultiKey",
        &[
            key_member(0, "partition", TypeIdentifier::TK_UINT16),
            key_member(1, "id", TypeIdentifier::TK_INT32),
            value_member(2, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );
    let reader = build_struct(
        "MultiKey",
        &[
            key_member(1, "id", TypeIdentifier::TK_INT32),
            key_member(0, "partition", TypeIdentifier::TK_UINT16),
            value_member(2, "value", TypeIdentifier::TK_FLOAT32),
        ],
    );

    assert!(Matcher::is_assignable_to(&writer, &reader));
}

/// `@key <key> name; int32 value;`, the writer's or the reader's.
fn keyed_by(key: TypeIdentifier) -> CompleteTypeObject {
    build_struct(
        "Keyed",
        &[
            key_member(0, "name", key),
            value_member(1, "value", TypeIdentifier::TK_INT32),
        ],
    )
}

/// The spec default policy with both bound flags set to `ignore`.
fn bounds_policy(ignore: bool) -> crate::protocol::discovery::types::TypeConsistencyEnforcement {
    crate::protocol::discovery::types::TypeConsistencyEnforcement {
        ignore_string_bounds: ignore,
        ignore_sequence_bounds: ignore,
        ..Default::default()
    }
}

/// Writer -> reader assignability of `keyed_by(writer_key)` to
/// `keyed_by(reader_key)` under: no local policy (the fallback), the spec
/// default (flags TRUE), and both bound flags FALSE.
fn key_assignable(writer_key: TypeIdentifier, reader_key: TypeIdentifier) -> [bool; 3] {
    let (writer, reader) = (keyed_by(writer_key), keyed_by(reader_key));
    let (ignored, enforced) = (bounds_policy(true), bounds_policy(false));
    [None, Some(&ignored), Some(&enforced)].map(|policy| {
        Matcher::is_type_compatible_with_policy(
            Some(&writer),
            Some(&reader),
            "Keyed",
            "Keyed",
            policy,
        )
    })
}

/// DDS-XTypes v1.3 Sec.7.6.3.4.1: with `ignore_string_bounds` TRUE (the
/// default) string bounds "are not considered as part of the type
/// assignability", keys included; with FALSE, Table 19's key rule
/// (m1.type.length >= m2.type.length) holds. The OMG struct_key_string_3
/// pair is the first row: writer key string<20>, reader key string<10>.
#[test]
fn a_string_key_bound_counts_only_when_string_bounds_are_enforced() {
    for (writer, reader, fits_when_enforced, what) in [
        (
            TypeIdentifier::string(20),
            TypeIdentifier::string(10),
            false,
            "string<20> -> string<10>",
        ),
        (
            TypeIdentifier::string(0),
            TypeIdentifier::string(128),
            false,
            "string -> string<128>",
        ),
        (
            TypeIdentifier::string(300),
            TypeIdentifier::string(255),
            false,
            "string<300> -> string<255>",
        ),
        (
            TypeIdentifier::wstring(64),
            TypeIdentifier::wstring(32),
            false,
            "wstring<64> -> wstring<32>",
        ),
        (
            TypeIdentifier::string(128),
            TypeIdentifier::string(200),
            true,
            "string<128> -> string<200>",
        ),
        (
            TypeIdentifier::string(128),
            TypeIdentifier::string(0),
            true,
            "string<128> -> string",
        ),
        (
            TypeIdentifier::string(128),
            TypeIdentifier::string(128),
            true,
            "string<128> -> string<128>",
        ),
    ] {
        assert_eq!(
            key_assignable(writer, reader),
            [true, true, fits_when_enforced],
            "{what}"
        );
    }
}

/// The same for a sequence key member under `ignore_sequence_bounds`
/// (the OMG struct_key_seq_2 pair: writer sequence<int32,20>, reader
/// sequence<int32,10>).
#[test]
fn a_sequence_key_bound_counts_only_when_sequence_bounds_are_enforced() {
    use crate::xtypes::{EquivalenceKind, PlainCollectionHeader, PlainSequenceSElemDefn};
    let int32s = |bound: u8| {
        TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header: PlainCollectionHeader {
                equiv_kind: EquivalenceKind::Both,
                element_flags: crate::xtypes::CollectionElementFlag::TRY_CONSTRUCT1,
            },
            bound,
            element_identifier: Box::new(TypeIdentifier::TK_INT32),
        })
    };
    assert_eq!(
        key_assignable(int32s(20), int32s(10)),
        [true, true, false],
        "seq<20> -> seq<10>"
    );
    assert_eq!(
        key_assignable(int32s(0), int32s(10)),
        [true, true, false],
        "seq -> seq<10>"
    );
    assert_eq!(
        key_assignable(int32s(10), int32s(20)),
        [true; 3],
        "seq<10> -> seq<20>"
    );
}

/// Each flag governs its own kind: enforcing sequence bounds alone does not
/// hold a string key to its bound, and enforcing string bounds alone does
/// not hold a sequence key to its bound.
#[test]
fn each_bound_flag_governs_its_own_key_kind() {
    use crate::xtypes::{EquivalenceKind, PlainCollectionHeader, PlainSequenceSElemDefn};
    let int32s = |bound: u8| {
        TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header: PlainCollectionHeader {
                equiv_kind: EquivalenceKind::Both,
                element_flags: crate::xtypes::CollectionElementFlag::TRY_CONSTRUCT1,
            },
            bound,
            element_identifier: Box::new(TypeIdentifier::TK_INT32),
        })
    };
    let only_strings = crate::protocol::discovery::types::TypeConsistencyEnforcement {
        ignore_string_bounds: false,
        ..Default::default()
    };
    let only_sequences = crate::protocol::discovery::types::TypeConsistencyEnforcement {
        ignore_sequence_bounds: false,
        ..Default::default()
    };
    let fits = |w: TypeIdentifier, r: TypeIdentifier, p| {
        Matcher::is_type_compatible_with_policy(
            Some(&keyed_by(w)),
            Some(&keyed_by(r)),
            "Keyed",
            "Keyed",
            Some(p),
        )
    };
    let (s20, s10) = (TypeIdentifier::string(20), TypeIdentifier::string(10));
    assert!(!fits(s20.clone(), s10.clone(), &only_strings));
    assert!(fits(s20, s10, &only_sequences));
    assert!(!fits(int32s(20), int32s(10), &only_sequences));
    assert!(fits(int32s(20), int32s(10), &only_strings));
}

/// A non-key string member follows the same flag.
#[test]
fn a_non_key_string_bound_follows_ignore_string_bounds() {
    let labelled = |label| {
        build_struct(
            "Keyed",
            &[
                key_member(0, "id", TypeIdentifier::TK_INT32),
                value_member(1, "label", label),
            ],
        )
    };
    let (writer, reader) = (
        labelled(TypeIdentifier::string(200)),
        labelled(TypeIdentifier::string(128)),
    );
    let (ignored, enforced) = (bounds_policy(true), bounds_policy(false));
    for (policy, fits) in [
        (None, true),
        (Some(&ignored), true),
        (Some(&enforced), false),
    ] {
        assert_eq!(
            Matcher::is_type_compatible_with_policy(
                Some(&writer),
                Some(&reader),
                "Keyed",
                "Keyed",
                policy
            ),
            fits
        );
    }
}

/// The inert string identifier carries no bound (the guardrail on
/// `TypeIdentifier::TK_STRING8`): as a key it is compared like any other
/// string, as unbounded. Under the default flag no bound is compared, so a
/// shape_main writer (`@key color` in the inert form) matches a reader
/// declaring the OMG shape's `@key string<128> color`; a reader enforcing
/// string bounds refuses it, an unbounded L2 fitting no bounded L1.
#[test]
fn an_inert_string_key_is_an_unbounded_string() {
    assert_eq!(
        key_assignable(TypeIdentifier::TK_STRING8, TypeIdentifier::string(128)),
        [true, true, false],
        "inert -> string<128>"
    );
    assert_eq!(
        key_assignable(TypeIdentifier::string(300), TypeIdentifier::TK_STRING8),
        [true; 3],
        "string<300> -> inert"
    );
}

#[cfg(feature = "xtypes-structural-assignability")]
mod nested_keys {
    //! Keys whose type is reached by hash: a nested structure key (the OMG
    //! struct_key_struct pairs) and an enumerated key (struct_key_enum).

    use super::*;
    use crate::core::discovery::matcher::types::TypeObjectResolver;
    use crate::protocol::discovery::types::TypeConsistencyEnforcement;
    use crate::xtypes::{
        CommonEnumeratedLiteral, CompleteEnumeratedHeader, CompleteEnumeratedLiteral,
        CompleteEnumeratedType, EnumeratedLiteralFlag, EquivalenceHash,
    };
    use std::collections::HashMap;

    struct Resolver(HashMap<EquivalenceHash, CompleteTypeObject>);

    impl TypeObjectResolver for Resolver {
        fn resolve_minimal(&self, _: &EquivalenceHash) -> Option<&CompleteTypeObject> {
            None
        }
        fn resolve_complete(&self, h: &EquivalenceHash) -> Option<&CompleteTypeObject> {
            self.0.get(h)
        }
    }

    fn by_hash(obj: &CompleteTypeObject) -> (EquivalenceHash, TypeIdentifier) {
        let h = obj.compute_equivalence_hash().expect("equivalence hash");
        (h, TypeIdentifier::Complete(h))
    }

    /// `@appendable struct key_N { @key string<k1> k1; string<x2> x2; }`.
    fn key_struct(name: &str, k1: u32, x2: u32) -> CompleteTypeObject {
        let CompleteTypeObject::Struct(mut s) = build_struct(
            name,
            &[
                key_member(0, "k1", TypeIdentifier::string(k1)),
                value_member(1, "x2", TypeIdentifier::string(x2)),
            ],
        ) else {
            unreachable!("build_struct builds a struct");
        };
        s.struct_flags = StructTypeFlag::IS_APPENDABLE;
        CompleteTypeObject::Struct(s)
    }

    fn appendable_keyed_by(key: TypeIdentifier) -> CompleteTypeObject {
        let CompleteTypeObject::Struct(mut s) = build_struct("Outer", &[key_member(0, "x1", key)])
        else {
            unreachable!("build_struct builds a struct");
        };
        s.struct_flags = StructTypeFlag::IS_APPENDABLE;
        CompleteTypeObject::Struct(s)
    }

    fn assignable(
        writer_key: CompleteTypeObject,
        reader_key: CompleteTypeObject,
        policy: &TypeConsistencyEnforcement,
    ) -> bool {
        let (wh, wid) = by_hash(&writer_key);
        let (rh, rid) = by_hash(&reader_key);
        assert_ne!(wh, rh, "fixture: the two key types must differ");
        let resolver = Resolver(HashMap::from([(wh, writer_key), (rh, reader_key)]));
        Matcher::is_type_compatible_with_resolver(
            Some(&appendable_keyed_by(wid)),
            Some(&appendable_keyed_by(rid)),
            "Outer",
            "Outer",
            Some(policy),
            Some(&resolver),
        )
    }

    /// The OMG struct_key_struct_2 pair: the writer's nested key holds
    /// `@key string<20> k1`, the reader's `@key string<10> k1`. The bound
    /// flags reach the nested type's keys.
    #[test]
    fn a_nested_struct_key_bound_counts_only_when_string_bounds_are_enforced() {
        let writer = || key_struct("key_2", 20, 10);
        let reader = || key_struct("key_1", 10, 20);
        assert!(assignable(writer(), reader(), &bounds_policy(true)));
        assert!(!assignable(writer(), reader(), &bounds_policy(false)));
        // The key alone decides: a longer reader key fits when enforced.
        let wider = key_struct("key_3", 20, 20);
        assert!(assignable(reader(), wider, &bounds_policy(false)));
    }

    fn enumeration(name: &str, literals: i32) -> CompleteTypeObject {
        CompleteTypeObject::Enumerated(CompleteEnumeratedType {
            enum_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteEnumeratedHeader {
                bit_bound: 32,
                detail: CompleteTypeDetail::new(name),
            },
            literal_seq: (0..literals)
                .map(|value| CompleteEnumeratedLiteral {
                    common: CommonEnumeratedLiteral {
                        value,
                        flags: EnumeratedLiteralFlag::empty(),
                    },
                    detail: CompleteMemberDetail::new(format!("VAL{value}")),
                })
                .collect(),
        })
    }

    /// Table 19: "For any enumerated key member m2 in T2, the m1 member of
    /// T1 with the same member ID verifies that all literals in m2.type
    /// appear as literals in m1.type", whatever the bound flags. The OMG
    /// struct_key_enum_2 pair: writer key E2 (4 literals), reader key E1 (3).
    #[test]
    fn an_enum_key_with_fewer_reader_literals_is_refused() {
        for ignore in [true, false] {
            let p = bounds_policy(ignore);
            assert!(!assignable(enumeration("E2", 4), enumeration("E1", 3), &p));
            assert!(assignable(enumeration("E1", 3), enumeration("E2", 4), &p));
        }
    }

    /// The rule is the key's: a plain enumerated member keeps the literal
    /// intersection rule of `is_enum_assignable`.
    #[test]
    fn a_non_key_enum_with_fewer_reader_literals_is_assignable() {
        let plain = |id| {
            let CompleteTypeObject::Struct(mut s) = build_struct(
                "Outer",
                &[
                    key_member(0, "id", TypeIdentifier::TK_INT32),
                    value_member(1, "x1", id),
                ],
            ) else {
                unreachable!("build_struct builds a struct");
            };
            s.struct_flags = StructTypeFlag::IS_APPENDABLE;
            CompleteTypeObject::Struct(s)
        };
        let (writer, reader) = (enumeration("E2", 4), enumeration("E1", 3));
        let (wh, wid) = by_hash(&writer);
        let (rh, rid) = by_hash(&reader);
        let resolver = Resolver(HashMap::from([(wh, writer), (rh, reader)]));
        assert!(Matcher::is_type_compatible_with_resolver(
            Some(&plain(wid)),
            Some(&plain(rid)),
            "Outer",
            "Outer",
            Some(&bounds_policy(true)),
            Some(&resolver),
        ));
    }
}
