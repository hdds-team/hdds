// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::xtypes::{
    CollectionElementFlag, EquivalenceHash, EquivalenceKind, PlainCollectionHeader,
    PlainMapLTypeDefn, PlainMapSTypeDefn, StronglyConnectedComponentId, TypeIdentifier,
};

// ============================================================================
// Helpers
// ============================================================================

fn plain_map_small(key: TypeIdentifier, val: TypeIdentifier, bound: u8) -> TypeIdentifier {
    TypeIdentifier::PlainMapSmall(PlainMapSTypeDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        bound,
        element_identifier: Box::new(val),
        key_flags: CollectionElementFlag::empty(),
        key_identifier: Box::new(key),
    })
}

fn plain_map_large(key: TypeIdentifier, val: TypeIdentifier, bound: u32) -> TypeIdentifier {
    TypeIdentifier::PlainMapLarge(PlainMapLTypeDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag::empty(),
        },
        bound,
        element_identifier: Box::new(val),
        key_flags: CollectionElementFlag::empty(),
        key_identifier: Box::new(key),
    })
}

fn scc_id(hash: EquivalenceHash, index: i32, length: i32) -> TypeIdentifier {
    TypeIdentifier::StronglyConnected(StronglyConnectedComponentId {
        kind: EquivalenceKind::Minimal,
        sc_component_id: hash,
        scc_length: length,
        scc_index: index,
    })
}

fn struct_with_member(name: &str, member_tid: TypeIdentifier) -> crate::xtypes::CompleteTypeObject {
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    };
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: member_tid,
            },
            detail: CompleteMemberDetail::new("data"),
        }],
    })
}

// ============================================================================
// Map same key+value passes
// ============================================================================

/// map<int32, int32, 10> writer vs map<int32, int32, 10> reader: same key and
/// element types, same bound. Must be assignable.
#[test]
fn test_assignable_map_same_key_value_passes() {
    let map_tid = plain_map_small(TypeIdentifier::TK_INT32, TypeIdentifier::TK_INT32, 10);
    let writer = struct_with_member("MapA", map_tid.clone());
    let reader = struct_with_member("MapA", map_tid);
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Map different value type fails
// ============================================================================

/// map<int32, int32, 10> writer vs map<int32, uint32, 10> reader: key types
/// match but element (value) type differs. Must fail per sec. 7.5.1.5.
#[test]
fn test_assignable_map_different_value_type_fails() {
    let writer_map = plain_map_small(TypeIdentifier::TK_INT32, TypeIdentifier::TK_INT32, 10);
    let reader_map = plain_map_small(TypeIdentifier::TK_INT32, TypeIdentifier::TK_UINT32, 10);
    let writer = struct_with_member("MapInt32", writer_map);
    let reader = struct_with_member("MapUint32", reader_map);
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// StronglyConnected same hash passes
// ============================================================================

/// Two member TypeIdentifiers with the same StronglyConnected component hash
/// and the same SCC index: must be assignable per XTypes v1.3 sec. 7.3.4.5.
#[test]
fn test_assignable_stronglyconnected_same_hash_passes() {
    let hash = EquivalenceHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    let scc_a = scc_id(hash, 0, 2);
    let scc_b = scc_id(hash, 0, 2);
    let writer = struct_with_member("NodeA", scc_a);
    let reader = struct_with_member("NodeB", scc_b);
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

/// Two SCC TypeIdentifiers with the same hash but different index within the SCC:
/// different positions in the cycle must NOT be assignable.
#[test]
fn test_assignable_stronglyconnected_different_index_fails() {
    let hash = EquivalenceHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    let scc_0 = scc_id(hash, 0, 2);
    let scc_1 = scc_id(hash, 1, 2);
    let writer = struct_with_member("NodeA", scc_0);
    let reader = struct_with_member("NodeB", scc_1);
    assert!(!Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Map small vs large cross-size passes
// ============================================================================

/// map<int32, int32, 10> (Small) writer vs map<int32, int32, 300> (Large)
/// reader: cross-size-class with same key+value types. Bounds and size class
/// differ only in encoding; structural types match, so assignable.
#[test]
fn test_assignable_map_small_to_large_same_types_passes() {
    let writer_map = plain_map_small(TypeIdentifier::TK_INT32, TypeIdentifier::TK_INT32, 10);
    let reader_map = plain_map_large(TypeIdentifier::TK_INT32, TypeIdentifier::TK_INT32, 300);
    let writer = struct_with_member("SmallMap", writer_map);
    let reader = struct_with_member("LargeMap", reader_map);
    assert!(Matcher::is_assignable_to(&writer, &reader));
}

// ============================================================================
// Map bound semantics under strict policy (ignore_sequence_bounds = false)
// ============================================================================

/// map<int32, int32, 0> (unbounded) writer vs map<int32, int32, 10> reader
/// under strict bounds: writer can produce more entries than reader accepts,
/// so NOT assignable per XTypes v1.3 sec. 7.5.1.5.
#[test]
fn test_map_unbounded_writer_rejected_for_bounded_reader_strict() {
    use crate::protocol::discovery::types::TypeConsistencyEnforcement;
    let writer_map = plain_map_large(TypeIdentifier::TK_INT32, TypeIdentifier::TK_INT32, 0);
    let reader_map = plain_map_large(TypeIdentifier::TK_INT32, TypeIdentifier::TK_INT32, 10);
    let writer = struct_with_member("UnboundedMap", writer_map);
    let reader = struct_with_member("BoundedMap", reader_map);
    let strict = TypeConsistencyEnforcement {
        kind: 1,
        ignore_sequence_bounds: false,
        ignore_string_bounds: true,
        ignore_member_names: true,
        prevent_type_widening: false,
        force_type_validation: false,
    };
    assert!(
        !crate::core::discovery::Matcher::is_type_compatible_with_policy(
            Some(&writer),
            Some(&reader),
            "",
            "",
            Some(&strict),
        ),
        "unbounded writer must not fit bounded reader under strict bounds"
    );
}

/// map<int32, int32, 5> writer vs map<int32, int32, 0> (unbounded) reader
/// under strict bounds: bounded writer always fits unbounded reader.
#[test]
fn test_map_bounded_writer_fits_unbounded_reader_strict() {
    use crate::protocol::discovery::types::TypeConsistencyEnforcement;
    let writer_map = plain_map_large(TypeIdentifier::TK_INT32, TypeIdentifier::TK_INT32, 5);
    let reader_map = plain_map_large(TypeIdentifier::TK_INT32, TypeIdentifier::TK_INT32, 0);
    let writer = struct_with_member("BoundedMap", writer_map);
    let reader = struct_with_member("UnboundedMap", reader_map);
    let strict = TypeConsistencyEnforcement {
        kind: 1,
        ignore_sequence_bounds: false,
        ignore_string_bounds: true,
        ignore_member_names: true,
        prevent_type_widening: false,
        force_type_validation: false,
    };
    assert!(
        crate::core::discovery::Matcher::is_type_compatible_with_policy(
            Some(&writer),
            Some(&reader),
            "",
            "",
            Some(&strict),
        ),
        "bounded writer must fit unbounded reader under strict bounds"
    );
}
