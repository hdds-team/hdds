// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::core::discovery::matcher::types::TypeObjectResolver;
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::xtypes::*;
use std::collections::HashMap;

struct Objects(HashMap<EquivalenceHash, CompleteTypeObject>);
impl TypeObjectResolver for Objects {
    fn resolve_minimal(&self, hash: &EquivalenceHash) -> Option<&CompleteTypeObject> {
        self.0.get(hash)
    }
    fn resolve_complete(&self, hash: &EquivalenceHash) -> Option<&CompleteTypeObject> {
        self.0.get(hash)
    }
}

fn bitmask(name: &str, bound: i16) -> CompleteTypeObject {
    CompleteTypeObject::Bitmask(CompleteBitmaskType {
        bitmask_flags: StructTypeFlag::empty(),
        header: CompleteBitmaskHeader {
            bit_bound: bound,
            detail: CompleteTypeDetail::new(name),
        },
        flag_seq: vec![CompleteBitflag {
            common: CommonBitflag {
                position: 0,
                flags: BitflagFlag::empty(),
            },
            detail: CompleteMemberDetail::new(name),
        }],
    })
}

fn member(id: TypeIdentifier, shape: u8) -> CompleteTypeObject {
    let header = PlainCollectionHeader {
        equiv_kind: match id {
            TypeIdentifier::Complete(_) => EquivalenceKind::Complete,
            TypeIdentifier::Minimal(_) => EquivalenceKind::Minimal,
            _ => EquivalenceKind::Both,
        },
        element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
    };
    let member_type_id = match shape {
        0 => id,
        1 => TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header,
            bound: 3,
            element_identifier: Box::new(id),
        }),
        _ => TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
            header,
            array_bound_seq: vec![3],
            element_identifier: Box::new(id),
        }),
    };
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Container"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::TRY_CONSTRUCT1,
                member_type_id,
            },
            detail: CompleteMemberDetail::new("value"),
        }],
    })
}

fn compatible(
    w: &CompleteTypeObject,
    r: &CompleteTypeObject,
    resolver: Option<&Objects>,
    deny_coercion: bool,
) -> bool {
    let policy = TypeConsistencyEnforcement {
        kind: u16::from(!deny_coercion),
        ..TypeConsistencyEnforcement::default()
    };
    Matcher::is_type_compatible_with_resolver(
        Some(w),
        Some(r),
        "",
        "",
        Some(&policy),
        resolver.map(|r| r as &dyn TypeObjectResolver),
    )
}

// XTypes 1.3 7.2.4.4.4 Table 15 and 7.2.4.4.7 Table 18. A bitmask
// and the unsigned integer holding its bound are mutually assignable.
// The same rule applies recursively to struct and collection members.
#[test]
fn bitmask_members_keep_unsigned_holder_assignability() {
    for (bound, holder) in [
        (1, TypeKind::TK_UINT8),
        (8, TypeKind::TK_UINT8),
        (9, TypeKind::TK_UINT16),
        (16, TypeKind::TK_UINT16),
        (17, TypeKind::TK_UINT32),
        (32, TypeKind::TK_UINT32),
        (33, TypeKind::TK_UINT64),
        (64, TypeKind::TK_UINT64),
    ] {
        let object = bitmask("Flags", bound);
        let complete = object.compute_equivalence_hash().unwrap();
        let minimal = crate::dynamic::complete_to_minimal_type_object(&object)
            .unwrap()
            .compute_equivalence_hash()
            .unwrap();
        let resolver = Objects(HashMap::from([
            (complete, object.clone()),
            (minimal, object),
        ]));
        for reference in [
            TypeIdentifier::Complete(complete),
            TypeIdentifier::Minimal(minimal),
        ] {
            for shape in 0..3 {
                let bitmask = member(reference.clone(), shape);
                for primitive in [
                    TypeKind::TK_UINT8,
                    TypeKind::TK_UINT16,
                    TypeKind::TK_UINT32,
                    TypeKind::TK_UINT64,
                    TypeKind::TK_INT32,
                ] {
                    let integer = member(TypeIdentifier::Primitive(primitive), shape);
                    assert_eq!(
                        compatible(&bitmask, &integer, Some(&resolver), false),
                        primitive == holder,
                        "bound={bound}, shape={shape}, primitive={primitive:?}"
                    );
                    assert_eq!(
                        compatible(&integer, &bitmask, Some(&resolver), false),
                        primitive == holder
                    );
                    assert!(!compatible(&bitmask, &integer, Some(&resolver), true));
                    assert!(!compatible(&bitmask, &integer, None, false));
                }
            }
        }
    }
}

// Table 18: bitmask-to-bitmask assignability uses the exact bound rather
// than holder width, flag names, or the set of named positions.
#[test]
fn bitmask_members_compare_bounds_after_resolution() {
    for (writer_bound, reader_bound, expected) in [
        (8, 8, true),
        (9, 9, true),
        (9, 16, false),
        (16, 17, false),
        (64, 64, true),
    ] {
        let writer = bitmask("WriterFlag", writer_bound);
        let reader = bitmask("ReaderFlag", reader_bound);
        let wh = writer.compute_equivalence_hash().unwrap();
        let rh = reader.compute_equivalence_hash().unwrap();
        let resolver = Objects(HashMap::from([(wh, writer), (rh, reader)]));
        for shape in 0..3 {
            assert_eq!(
                compatible(
                    &member(TypeIdentifier::Complete(wh), shape),
                    &member(TypeIdentifier::Complete(rh), shape),
                    Some(&resolver),
                    false
                ),
                expected
            );
        }
    }
}
