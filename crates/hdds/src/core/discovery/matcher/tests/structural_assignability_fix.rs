// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Tests for the xtypes-structural-assignability feature.
//!
//! Validates that `type_id_assignable` can resolve nested complex type references
//! (enum-in-struct-member, struct-in-struct-member) structurally when a resolver
//! is provided, while preserving exact-hash behavior when the feature is OFF or
//! the resolver is None.
//!
//! Test matrix:
//!   1. Feature OFF (or no resolver): different-hash nested enums INCOMPATIBLE
//!   2. Feature ON + resolver: assignable enum members COMPATIBLE
//!   3. Feature ON + resolver: incompatible bit_bound stays REJECTED
//!   4. Feature ON + resolver: disjoint enum values (no intersection) REJECTED
//!   5. Feature ON + resolver=None: falls back to exact hash (INCOMPATIBLE)
//!   6. Feature ON + resolver: appendable struct-in-struct-member ASSIGNABLE
//!   7. Feature ON, DISALLOW_TYPE_COERCION: resolver NOT consulted
//!   8. Feature ON: Minimal-hash path resolved structurally

use super::*;
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::xtypes::{
    CollectionElementFlag, CommonEnumeratedLiteral, CommonStructMember, CompleteEnumeratedHeader,
    CompleteEnumeratedLiteral, CompleteEnumeratedType, CompleteMemberDetail, CompleteStructHeader,
    CompleteStructMember, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
    EnumeratedLiteralFlag, EquivalenceHash, EquivalenceKind, MemberFlag, MinimalEnumeratedHeader,
    MinimalEnumeratedLiteral, MinimalEnumeratedType, MinimalMemberDetail, MinimalStructHeader,
    MinimalStructMember, MinimalStructType, MinimalTypeDetail, MinimalTypeObject,
    PlainArraySElemDefn, PlainCollectionHeader, PlainSequenceSElemDefn, StructTypeFlag,
    TypeIdentifier,
};

// =============================================================================
// Helpers
// =============================================================================

fn make_enum(name: &str, bit_bound: i16, values: &[(&str, i32)]) -> CompleteTypeObject {
    CompleteTypeObject::Enumerated(CompleteEnumeratedType {
        enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
        header: CompleteEnumeratedHeader {
            bit_bound,
            detail: CompleteTypeDetail::new(name),
        },
        literal_seq: values
            .iter()
            .map(|(lit_name, val)| CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: *val,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new(*lit_name),
            })
            .collect(),
    })
}

fn complete_hash(obj: &CompleteTypeObject) -> EquivalenceHash {
    obj.compute_equivalence_hash()
        .expect("compute_equivalence_hash must succeed with xtypes feature")
}

fn minimal_hash_of_enum(obj: &CompleteTypeObject) -> EquivalenceHash {
    if let CompleteTypeObject::Enumerated(e) = obj {
        let minimal = MinimalTypeObject::Enumerated(MinimalEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: MinimalEnumeratedHeader {
                bit_bound: e.header.bit_bound,
                detail: MinimalTypeDetail::new(),
            },
            literal_seq: e
                .literal_seq
                .iter()
                .map(|l| MinimalEnumeratedLiteral {
                    common: l.common.clone(),
                    detail: MinimalMemberDetail::from_name(&l.detail.name),
                })
                .collect(),
        });
        minimal.compute_equivalence_hash().expect("minimal hash OK")
    } else {
        panic!("expected Enumerated CompleteTypeObject");
    }
}

/// Wrap a single TypeIdentifier inside an APPENDABLE struct member.
fn wrapper_struct(member_type_id: TypeIdentifier) -> CompleteTypeObject {
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Wrapper"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id,
            },
            detail: CompleteMemberDetail::new("field"),
        }],
    })
}

/// Build an APPENDABLE struct with optional extra optional member.
fn appendable_struct(name: &str, extra: Option<(&str, u32)>) -> CompleteTypeObject {
    let mut members = vec![CompleteStructMember {
        common: CommonStructMember {
            member_id: 0,
            member_flags: MemberFlag::empty(),
            member_type_id: TypeIdentifier::TK_INT32,
        },
        detail: CompleteMemberDetail::new("x"),
    }];
    if let Some((mname, mid)) = extra {
        members.push(CompleteStructMember {
            common: CommonStructMember {
                member_id: mid,
                member_flags: MemberFlag::IS_OPTIONAL,
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: CompleteMemberDetail::new(mname),
        });
    }
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq: members,
    })
}

// =============================================================================
// Stub resolver (feature-gated)
// =============================================================================

#[cfg(feature = "xtypes-structural-assignability")]
use crate::core::discovery::matcher::types::TypeObjectResolver;

#[cfg(feature = "xtypes-structural-assignability")]
struct HashStubResolver {
    complete: std::collections::HashMap<EquivalenceHash, CompleteTypeObject>,
    minimal: std::collections::HashMap<EquivalenceHash, CompleteTypeObject>,
}

#[cfg(feature = "xtypes-structural-assignability")]
impl HashStubResolver {
    fn new() -> Self {
        Self {
            complete: Default::default(),
            minimal: Default::default(),
        }
    }
    fn register_complete(&mut self, obj: CompleteTypeObject) {
        let h = complete_hash(&obj);
        self.complete.insert(h, obj);
    }
    fn register_minimal(&mut self, obj: CompleteTypeObject) {
        let h = minimal_hash_of_enum(&obj);
        self.minimal.insert(h, obj);
    }
}

#[cfg(feature = "xtypes-structural-assignability")]
impl TypeObjectResolver for HashStubResolver {
    fn resolve_minimal(&self, h: &EquivalenceHash) -> Option<&CompleteTypeObject> {
        self.minimal.get(h)
    }
    fn resolve_complete(&self, h: &EquivalenceHash) -> Option<&CompleteTypeObject> {
        self.complete.get(h)
    }
}

// =============================================================================
// Test 1: baseline preserved -- public API without resolver rejects different hashes
// =============================================================================

/// When called through the standard public API (which passes resolver=None),
/// two wrapper-structs with different-hash enum members must be INCOMPATIBLE.
/// This guards the baseline behaviour of the public API.
#[test]
fn baseline_different_hash_nested_enum_incompatible() {
    let enum1 = make_enum("Color1", 32, &[("RED", 0), ("GREEN", 1), ("BLUE", 2)]);
    let enum2 = make_enum("Color2", 32, &[("RED", 0), ("YELLOW", 1)]);

    let hash1 = complete_hash(&enum1);
    let hash2 = complete_hash(&enum2);
    assert_ne!(hash1, hash2, "test setup: enums must differ");

    let writer = wrapper_struct(TypeIdentifier::Complete(hash1));
    let reader = wrapper_struct(TypeIdentifier::Complete(hash2));

    let result = Matcher::is_type_compatible(Some(&writer), Some(&reader), "Wrapper", "Wrapper");
    assert!(
        !result,
        "public API without resolver: different-hash nested enum must be INCOMPATIBLE"
    );
}

// =============================================================================
// Tests 2-8 (feature ON only)
// =============================================================================

/// Feature ON + resolver: enum-member structural assignability (non-empty value intersection).
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn feature_on_assignable_enum_member_compatible() {
    let enum1 = make_enum("Color1", 32, &[("RED", 0), ("GREEN", 1), ("BLUE", 2)]);
    // enum2 is a subset; intersection {RED=0, GREEN=1} is non-empty -> assignable per sec. 7.5.2.8
    let enum2 = make_enum("Color2", 32, &[("RED", 0), ("GREEN", 1)]);

    let hash1 = complete_hash(&enum1);
    let hash2 = complete_hash(&enum2);
    assert_ne!(hash1, hash2);

    let writer = wrapper_struct(TypeIdentifier::Complete(hash1));
    let reader = wrapper_struct(TypeIdentifier::Complete(hash2));

    let mut res = HashStubResolver::new();
    res.register_complete(enum1);
    res.register_complete(enum2);

    assert!(
        Matcher::is_type_compatible_with_resolver(
            Some(&writer),
            Some(&reader),
            "Wrapper",
            "Wrapper",
            None,
            Some(&res),
        ),
        "feature ON + resolver: assignable enum members must be COMPATIBLE"
    );
}

/// Feature ON + resolver: different bit_bound stays REJECTED.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn feature_on_different_bit_bound_stays_rejected() {
    let enum_32 = make_enum("Color32", 32, &[("RED", 0)]);
    let enum_16 = make_enum("Color16", 16, &[("RED", 0)]); // 16-bit != 32-bit -> incompatible

    let h32 = complete_hash(&enum_32);
    let h16 = complete_hash(&enum_16);
    assert_ne!(h32, h16);

    let writer = wrapper_struct(TypeIdentifier::Complete(h32));
    let reader = wrapper_struct(TypeIdentifier::Complete(h16));

    let mut res = HashStubResolver::new();
    res.register_complete(enum_32);
    res.register_complete(enum_16);

    assert!(
        !Matcher::is_type_compatible_with_resolver(
            Some(&writer),
            Some(&reader),
            "Wrapper",
            "Wrapper",
            None,
            Some(&res),
        ),
        "feature ON: different bit_bound enums must stay INCOMPATIBLE"
    );
}

/// Feature ON + resolver: disjoint enum value sets (empty intersection) REJECTED.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn feature_on_disjoint_enum_values_rejected() {
    let enum_a = make_enum("EnumA", 32, &[("RED", 0), ("GREEN", 1)]);
    let enum_b = make_enum("EnumB", 32, &[("BLUE", 2), ("YELLOW", 3)]); // no overlap

    let ha = complete_hash(&enum_a);
    let hb = complete_hash(&enum_b);

    let writer = wrapper_struct(TypeIdentifier::Complete(ha));
    let reader = wrapper_struct(TypeIdentifier::Complete(hb));

    let mut res = HashStubResolver::new();
    res.register_complete(enum_a);
    res.register_complete(enum_b);

    assert!(
        !Matcher::is_type_compatible_with_resolver(
            Some(&writer),
            Some(&reader),
            "Wrapper",
            "Wrapper",
            None,
            Some(&res),
        ),
        "feature ON: disjoint enum value sets must stay INCOMPATIBLE (empty intersection)"
    );
}

/// Feature ON but resolver=None: falls back to exact hash comparison (INCOMPATIBLE).
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn feature_on_resolver_none_falls_back_to_exact_hash() {
    let enum1 = make_enum("Color1", 32, &[("RED", 0), ("GREEN", 1)]);
    let enum2 = make_enum("Color2", 32, &[("RED", 0), ("GREEN", 1), ("BLUE", 2)]);

    let hash1 = complete_hash(&enum1);
    let hash2 = complete_hash(&enum2);
    assert_ne!(hash1, hash2);

    let writer = wrapper_struct(TypeIdentifier::Complete(hash1));
    let reader = wrapper_struct(TypeIdentifier::Complete(hash2));

    // No resolver -> must fall back to exact hash -> INCOMPATIBLE
    assert!(
        !Matcher::is_type_compatible_with_resolver(
            Some(&writer),
            Some(&reader),
            "Wrapper",
            "Wrapper",
            None,
            None::<&dyn TypeObjectResolver>,
        ),
        "resolver=None must fall back to exact-hash comparison (INCOMPATIBLE)"
    );
}

/// Feature ON + resolver: APPENDABLE struct extension is COMPATIBLE as nested type.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn feature_on_appendable_nested_struct_assignable() {
    // s_base: appendable, 1 member x: int32
    let s_base = appendable_struct("SBase", None);
    // s_wider: appendable, same x plus optional y -- writer SBase assignable to reader SWider
    let s_wider = appendable_struct("SWider", Some(("y", 1)));

    let hash_base = complete_hash(&s_base);
    let hash_wider = complete_hash(&s_wider);
    assert_ne!(hash_base, hash_wider);

    // Outer wrapper: member typed by inner struct hash
    let writer_outer = wrapper_struct(TypeIdentifier::Complete(hash_base));
    let reader_outer = wrapper_struct(TypeIdentifier::Complete(hash_wider));

    let mut res = HashStubResolver::new();
    res.register_complete(s_base);
    res.register_complete(s_wider);

    assert!(
        Matcher::is_type_compatible_with_resolver(
            Some(&writer_outer),
            Some(&reader_outer),
            "Wrapper",
            "Wrapper",
            None,
            Some(&res),
        ),
        "feature ON: appendable struct extension must be COMPATIBLE via resolver"
    );
}

/// DISALLOW_TYPE_COERCION (kind=0): resolver must NOT be consulted -- exact hash only.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn feature_on_disallow_coercion_ignores_resolver() {
    let enum1 = make_enum("Color1", 32, &[("RED", 0), ("GREEN", 1)]);
    // Different name but same values (if the resolver WERE consulted it would pass)
    let enum2 = make_enum("Color2_diff", 32, &[("ROUGE", 0), ("VERT", 1)]);

    let hash1 = complete_hash(&enum1);
    let hash2 = complete_hash(&enum2);
    assert_ne!(hash1, hash2);

    let writer = wrapper_struct(TypeIdentifier::Complete(hash1));
    let reader = wrapper_struct(TypeIdentifier::Complete(hash2));

    let mut res = HashStubResolver::new();
    res.register_complete(enum1);
    res.register_complete(enum2);

    let strict = TypeConsistencyEnforcement {
        kind: 0, // DISALLOW_TYPE_COERCION
        ..Default::default()
    };
    assert!(
        !Matcher::is_type_compatible_with_resolver(
            Some(&writer),
            Some(&reader),
            "Wrapper",
            "Wrapper",
            Some(&strict),
            Some(&res),
        ),
        "DISALLOW_TYPE_COERCION: resolver must NOT be consulted; exact hash match required"
    );
}

/// Feature ON + resolver: Minimal-hash TypeIdentifiers resolved structurally.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn feature_on_minimal_hash_path_assignable() {
    let enum1 = make_enum("Color1", 32, &[("RED", 0), ("GREEN", 1), ("BLUE", 2)]);
    let enum2 = make_enum("Color2", 32, &[("RED", 0), ("GREEN", 1)]);

    let mhash1 = minimal_hash_of_enum(&enum1);
    let mhash2 = minimal_hash_of_enum(&enum2);
    assert_ne!(mhash1, mhash2);

    let writer = wrapper_struct(TypeIdentifier::Minimal(mhash1));
    let reader = wrapper_struct(TypeIdentifier::Minimal(mhash2));

    let mut res = HashStubResolver::new();
    res.register_minimal(enum1);
    res.register_minimal(enum2);

    assert!(
        Matcher::is_type_compatible_with_resolver(
            Some(&writer),
            Some(&reader),
            "Wrapper",
            "Wrapper",
            None,
            Some(&res),
        ),
        "feature ON: Minimal-hash path must also resolve structurally via resolver"
    );
}

// =============================================================================
// Nested FINAL struct renamed-member regression (OMG xtypes_v2_array_test_suite
// SFinal[10]_S[20]_SFinalAlt[10]_S[20] and the xtypes_v2_sequence_test_suite
// seq(SFinal,10)_seq(SFinalAlt,10) analog)
// =============================================================================
//
// Both OMG tests wrap two structurally-identical FINAL structs -- differing
// ONLY in the (single) member's name -- as an array/sequence element inside
// an outer FINAL struct, and expect ReturnCode.OK under the suite's default
// (no --ignore-member-names flag => permissive) policy. Previously,
// `type_id_assignable`'s `(Minimal(wh), Minimal(rh))` and
// `(Complete(wh), Complete(rh))` arms forced `ignore_member_names=false` for
// any FINAL-vs-FINAL resolved pair regardless of the caller's actual policy,
// which made both tests wrongly report INCONSISTENT_TOPIC. See the updated
// comment on those arms in `matcher::types::type_id_assignable`.

/// Build a FINAL struct with a single `uint32` member of the given name,
/// mirroring `F_S__array20_uint32` / `_alt` (arrays.xml) and
/// `F_S__seq20_uint32` / `_alt` (sequences.xml): identical shape, renamed
/// member.
fn final_struct_one_member(type_name: &str, member_name: &str) -> CompleteTypeObject {
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(type_name),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_UINT32,
            },
            detail: CompleteMemberDetail::new(member_name),
        }],
    })
}

/// Minimal-representation EquivalenceHash of a Struct `CompleteTypeObject`.
/// Mirrors `matcher::types::complete_to_minimal_struct` (private to that
/// module, so re-derived here): the Minimal form drops the type name and
/// replaces every member name with its 32-bit name_hash. Two
/// otherwise-identical FINAL structs whose sole member is renamed therefore
/// produce DIFFERENT Minimal hashes -- exactly what the OMG "Alt" struct
/// variants do, and exactly why the fast-hash-equality path alone cannot
/// resolve these pairs; the resolver-based structural fallback must run.
fn minimal_hash_of_struct(obj: &CompleteTypeObject) -> EquivalenceHash {
    if let CompleteTypeObject::Struct(s) = obj {
        let minimal = MinimalTypeObject::Struct(MinimalStructType {
            struct_flags: s.struct_flags,
            header: MinimalStructHeader {
                base_type: s.header.base_type.clone(),
                detail: MinimalTypeDetail::new(),
            },
            member_seq: s
                .member_seq
                .iter()
                .map(|m| MinimalStructMember {
                    common: m.common.clone(),
                    detail: MinimalMemberDetail::from_name(&m.detail.name),
                })
                .collect(),
        });
        minimal.compute_equivalence_hash().expect("minimal hash OK")
    } else {
        panic!("expected Struct CompleteTypeObject");
    }
}

/// Wrap a `TypeIdentifier` as a 10-bound `PlainArraySmall` element, mirroring
/// `arrayDimensions="10"` on `F_S__array10_F_S__array20_uint32`'s member.
fn plain_array10_of(elem: TypeIdentifier) -> TypeIdentifier {
    TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        array_bound_seq: vec![10],
        element_identifier: Box::new(elem),
    })
}

/// Wrap a `TypeIdentifier` as a 10-bound `PlainSequenceSmall` element,
/// mirroring `sequenceMaxLength="10"` on `F_S__seq10_F_S__seq20_uint32`'s
/// member.
fn plain_sequence10_of(elem: TypeIdentifier) -> TypeIdentifier {
    TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        bound: 10,
        element_identifier: Box::new(elem),
    })
}

/// Outer FINAL struct with a single member typed by `wrapped` (an array or
/// sequence TypeIdentifier wrapping a Minimal-hash reference to the inner
/// struct), mirroring `F_S__array10_F_S__array20_uint32` /
/// `F_S__seq10_F_S__seq20_uint32` and their `_alt` counterparts.
fn outer_final_wrapping(
    type_name: &str,
    member_name: &str,
    wrapped: TypeIdentifier,
) -> CompleteTypeObject {
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(type_name),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: wrapped,
            },
            detail: CompleteMemberDetail::new(member_name),
        }],
    })
}

/// OMG `xtypes_v2_array_test_suite_SFinal[10]_S[20]_SFinalAlt[10]_S[20]`
/// expects OK. Models `F_S__array10_F_S__array20_uint32` (member "x1" ->
/// array<F_S__array20_uint32, 10>, itself member "x1" -> uint32[20]) against
/// `F_S__array10_F_S__array20_uint32_alt` (member "altx1" ->
/// array<F_S__array20_uint32_alt, 10>, itself member "altx1" -> uint32[20]).
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn nested_final_struct_alt_name_array_element_assignable() {
    let inner_w = final_struct_one_member("F_S__array20_uint32", "x1");
    let inner_r = final_struct_one_member("F_S__array20_uint32_alt", "altx1");

    let mhash_w = minimal_hash_of_struct(&inner_w);
    let mhash_r = minimal_hash_of_struct(&inner_r);
    assert_ne!(
        mhash_w, mhash_r,
        "test setup: a renamed sole member must change the Minimal hash"
    );

    let outer_w = outer_final_wrapping(
        "F_S__array10_F_S__array20_uint32",
        "x1",
        plain_array10_of(TypeIdentifier::Minimal(mhash_w)),
    );
    let outer_r = outer_final_wrapping(
        "F_S__array10_F_S__array20_uint32_alt",
        "altx1",
        plain_array10_of(TypeIdentifier::Minimal(mhash_r)),
    );

    let mut res = HashStubResolver::new();
    res.minimal.insert(mhash_w, inner_w);
    res.minimal.insert(mhash_r, inner_r);

    assert!(
        Matcher::is_type_compatible_with_resolver(
            Some(&outer_w),
            Some(&outer_r),
            "F_S__array10_F_S__array20_uint32",
            "F_S__array10_F_S__array20_uint32_alt",
            None,
            Some(&res),
        ),
        "OMG SFinal[10]_S[20]_SFinalAlt[10]_S[20] must be OK under the \
         default permissive policy (nested FINAL struct, renamed member)"
    );
}

/// OMG `xtypes_v2_sequence_test_suite_seq(SFinal,10)_seq(SFinalAlt,10)`
/// expects OK. Same shapes as the array test above, wrapped in a
/// `PlainSequenceSmall` element instead of `PlainArraySmall` (models
/// `F_S__seq10_F_S__seq20_uint32` vs `F_S__seq10_F_S__seq20_uint32_alt`).
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn nested_final_struct_alt_name_sequence_element_assignable() {
    let inner_w = final_struct_one_member("F_S__seq20_uint32", "x1");
    let inner_r = final_struct_one_member("F_S__seq20_uint32_alt", "altx1");

    let mhash_w = minimal_hash_of_struct(&inner_w);
    let mhash_r = minimal_hash_of_struct(&inner_r);
    assert_ne!(mhash_w, mhash_r);

    let outer_w = outer_final_wrapping(
        "F_S__seq10_F_S__seq20_uint32",
        "x1",
        plain_sequence10_of(TypeIdentifier::Minimal(mhash_w)),
    );
    let outer_r = outer_final_wrapping(
        "F_S__seq10_F_S__seq20_uint32_alt",
        "altx1",
        plain_sequence10_of(TypeIdentifier::Minimal(mhash_r)),
    );

    let mut res = HashStubResolver::new();
    res.minimal.insert(mhash_w, inner_w);
    res.minimal.insert(mhash_r, inner_r);

    assert!(
        Matcher::is_type_compatible_with_resolver(
            Some(&outer_w),
            Some(&outer_r),
            "F_S__seq10_F_S__seq20_uint32",
            "F_S__seq10_F_S__seq20_uint32_alt",
            None,
            Some(&res),
        ),
        "OMG seq(SFinal,10)_seq(SFinalAlt,10) must be OK under the default \
         permissive policy (nested FINAL struct, renamed member)"
    );
}

/// Must-stay-negative pin: the SAME nested FINAL structs as above, but under
/// an EXPLICIT `ignore_member_names=false` policy, must still be rejected.
/// This is the crux of the fix: the recursive nested comparison now
/// propagates the CALLER's policy unchanged (instead of always forcing
/// permissive, and instead of the old bug's always forcing strict) --
/// permissive stays permissive (tests above), and strict stays strict here.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn nested_final_struct_alt_name_array_element_strict_policy_still_rejects() {
    let inner_w = final_struct_one_member("F_S__array20_uint32", "x1");
    let inner_r = final_struct_one_member("F_S__array20_uint32_alt", "altx1");

    let mhash_w = minimal_hash_of_struct(&inner_w);
    let mhash_r = minimal_hash_of_struct(&inner_r);

    let outer_w = outer_final_wrapping(
        "F_S__array10_F_S__array20_uint32",
        "x1",
        plain_array10_of(TypeIdentifier::Minimal(mhash_w)),
    );
    let outer_r = outer_final_wrapping(
        "F_S__array10_F_S__array20_uint32_alt",
        "altx1",
        plain_array10_of(TypeIdentifier::Minimal(mhash_r)),
    );

    let mut res = HashStubResolver::new();
    res.minimal.insert(mhash_w, inner_w);
    res.minimal.insert(mhash_r, inner_r);

    let strict = TypeConsistencyEnforcement {
        ignore_member_names: false,
        ..Default::default()
    };
    assert!(
        !Matcher::is_type_compatible_with_resolver(
            Some(&outer_w),
            Some(&outer_r),
            "F_S__array10_F_S__array20_uint32",
            "F_S__array10_F_S__array20_uint32_alt",
            Some(&strict),
            Some(&res),
        ),
        "explicit ignore_member_names=false must still reject the renamed \
         nested member -- the fix propagates the caller's policy, it does \
         not force permissive unconditionally"
    );
}

// =============================================================================
// DIAGNOSTIC: production hash-keying alignment for nested enum in array
// =============================================================================
//
// Confirms/refutes: is the store KEY produced by the production keying path
// (`collect_nested_type_objects` -> `complete_type_object_minimal_hash`) equal
// to the inner enum hash embedded by the emitter in a top-level array's
// `element.type_id`? If they differ, `resolve_minimal` misses at match time and
// the structural flip never fires even with a fully populated store.
//
// This test drives BOTH sides through the real production functions (no
// hand-picked hashes, unlike the tests above), then calls the matcher end to
// end via a real `SnapshotResolver`.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn production_keying_enum_in_array_hash_alignment() {
    use crate::dynamic::{
        collect_nested_type_objects, complete_type_object_minimal_hash, type_descriptor_to_xtypes,
        ArrayDescriptor, EnumDescriptor, EnumVariant, FieldDescriptor, TypeDescriptor, TypeKind,
    };
    use crate::xtypes::{
        CollectionElementFlag, CollectionTypeFlag, CompleteArrayHeader, CompleteArrayType,
        CompleteCollectionElement, CompleteElementDetail,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    fn hex(h: &EquivalenceHash) -> String {
        h.as_bytes().iter().map(|b| format!("{:02x}", b)).collect()
    }

    // 1. Two distinct enums as dynamic descriptors. E1 declared in NON-ascending
    //    value order to also stress the literal-sort path; E2 is a subset.
    let e1_desc = TypeDescriptor::new(
        "E1",
        TypeKind::Enum(EnumDescriptor::new(vec![
            EnumVariant::new("B", 1),
            EnumVariant::new("C", 2),
            EnumVariant::new("A", 0),
        ])),
    );
    let e2_desc = TypeDescriptor::new(
        "E2",
        TypeKind::Enum(EnumDescriptor::new(vec![
            EnumVariant::new("A", 0),
            EnumVariant::new("B", 1),
        ])),
    );

    // 2. Production CompleteTypeObject for each enum. `type_descriptor_to_xtypes`
    //    on a top-level enum dispatches to the SAME `descriptor_enum_to_xtypes`
    //    that `collect_nested_type_objects` uses internally.
    let e1_complete = type_descriptor_to_xtypes(&e1_desc).expect("E1 -> CompleteTypeObject");
    let e2_complete = type_descriptor_to_xtypes(&e2_desc).expect("E2 -> CompleteTypeObject");
    assert!(matches!(e1_complete, CompleteTypeObject::Enumerated(_)));

    // 3. STORE KEY (production keying): the exact hash used as the resolver map key.
    let key1 = complete_type_object_minimal_hash(&e1_complete).expect("min hash E1");
    let key2 = complete_type_object_minimal_hash(&e2_complete).expect("min hash E2");

    // 4. EMISSION: wrap each enum in array<E,10> inside a struct, then pull the
    //    `element.type_id` the emitter actually produces
    //    (descriptor_to_type_identifier -> enum_descriptor_to_minimal_type_identifier).
    let outer1 = TypeDescriptor::struct_type(
        "Outer1",
        vec![FieldDescriptor::new(
            "arr",
            Arc::new(TypeDescriptor::new(
                "E1x10",
                TypeKind::Array(ArrayDescriptor::new(Arc::new(e1_desc.clone()), 10)),
            )),
        )],
    );
    let outer2 = TypeDescriptor::struct_type(
        "Outer2",
        vec![FieldDescriptor::new(
            "arr",
            Arc::new(TypeDescriptor::new(
                "E2x10",
                TypeKind::Array(ArrayDescriptor::new(Arc::new(e2_desc.clone()), 10)),
            )),
        )],
    );

    fn extract_array_element_id(outer: &TypeDescriptor) -> TypeIdentifier {
        let c = type_descriptor_to_xtypes(outer).expect("outer -> complete");
        let member_tid = match c {
            CompleteTypeObject::Struct(s) => s.member_seq[0].common.member_type_id.clone(),
            _ => panic!("expected struct top-level"),
        };
        println!("emitted array member TypeIdentifier = {:?}", member_tid);
        match &member_tid {
            TypeIdentifier::PlainArraySmall(d) => (*d.element_identifier).clone(),
            TypeIdentifier::PlainArrayLarge(d) => (*d.element_identifier).clone(),
            other => panic!("member is not a PlainArray: {:?}", other),
        }
    }

    let elem1 = extract_array_element_id(&outer1);
    let elem2 = extract_array_element_id(&outer2);

    // 5. (step b) element ids must be hash-based; note Minimal vs Complete.
    let (eh1, is_min1) = match &elem1 {
        TypeIdentifier::Minimal(h) => (*h, true),
        TypeIdentifier::Complete(h) => (*h, false),
        other => panic!("E1 element id not hash-based: {:?}", other),
    };
    let (eh2, is_min2) = match &elem2 {
        TypeIdentifier::Minimal(h) => (*h, true),
        TypeIdentifier::Complete(h) => (*h, false),
        other => panic!("E2 element id not hash-based: {:?}", other),
    };

    println!(
        "E1 array-element hash = {} (minimal={})",
        hex(&eh1),
        is_min1
    );
    println!("E1 store       key    = {}", hex(&key1));
    println!(
        "E2 array-element hash = {} (minimal={})",
        hex(&eh2),
        is_min2
    );
    println!("E2 store       key    = {}", hex(&key2));
    println!("E1 element==key ? {}", eh1 == key1);
    println!("E2 element==key ? {}", eh2 == key2);

    // 6. Build the resolver via the PRODUCTION keying path.
    let mut store: HashMap<EquivalenceHash, CompleteTypeObject> = HashMap::new();
    collect_nested_type_objects(&outer1, &mut store);
    collect_nested_type_objects(&outer2, &mut store);
    println!(
        "resolver store keys = {:?}",
        store.keys().map(hex).collect::<Vec<_>>()
    );
    println!(
        "store contains E1 element hash? {}",
        store.contains_key(&eh1)
    );
    println!(
        "store contains E2 element hash? {}",
        store.contains_key(&eh2)
    );
    let resolver = crate::core::discovery::matcher::SnapshotResolver::new(store);

    // 7. Compare the two top-level array TypeObjects the matcher sees, reusing the
    //    emitter's element TypeIdentifier verbatim on both sides.
    let arr_e1 = CompleteTypeObject::Array(CompleteArrayType {
        collection_flag: CollectionTypeFlag::default(),
        header: CompleteArrayHeader {
            bound_seq: vec![10],
            detail: CompleteTypeDetail::new("E1x10"),
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: elem1.clone(),
            detail: CompleteElementDetail::default(),
        },
    });
    let arr_e2 = CompleteTypeObject::Array(CompleteArrayType {
        collection_flag: CollectionTypeFlag::default(),
        header: CompleteArrayHeader {
            bound_seq: vec![10],
            detail: CompleteTypeDetail::new("E2x10"),
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: elem2.clone(),
            detail: CompleteElementDetail::default(),
        },
    });

    let compatible = Matcher::is_type_compatible_with_resolver(
        Some(&arr_e1),
        Some(&arr_e2),
        "E1x10",
        "E2x10",
        None,
        Some(&resolver as &dyn TypeObjectResolver),
    );
    println!("matcher is_type_compatible_with_resolver = {}", compatible);

    // THE CRUX (step d): the emitted array element hash MUST equal the production
    // store key, otherwise resolve_minimal misses and the flip never fires.
    assert_eq!(
        eh1, key1,
        "E1: array element hash must equal production store key"
    );
    assert_eq!(
        eh2, key2,
        "E2: array element hash must equal production store key"
    );
}
