// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::core::TypeObjectBuilder;
use super::model::{FieldType, MessageDescriptor, MessageMember, PrimitiveType};
use crate::core::types::{Distro, ROS_HASH_SIZE};
use crate::xtypes::{CompleteTypeObject, MinimalTypeObject, TypeIdentifier, TypeKind};
use std::convert::TryFrom;

fn ros_hash(seed: u8) -> [u8; ROS_HASH_SIZE] {
    let mut bytes = [0u8; ROS_HASH_SIZE];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        let idx_u8 = u8::try_from(idx).expect("ROS hash length fits in u8");
        *byte = seed.wrapping_add(idx_u8);
    }
    bytes
}

#[cfg(feature = "xtypes")]
fn assert_deep_collection_hashes(
    field_type: FieldType<'_>,
    minimal_hash: [u8; 14],
    complete_hash: [u8; 14],
) {
    use crate::xtypes::EquivalenceHash;

    let members = [MessageMember {
        name: "x",
        field_type,
        is_key: false,
    }];
    let hash = ros_hash(0x50);
    let descriptor = MessageDescriptor {
        namespace: "test_msgs::msg",
        name: "DeepCollections",
        members: &members,
        ros_hash_version: 1,
        ros_hash: &hash,
    };
    let handle = TypeObjectBuilder::from_descriptor(Distro::Humble, &descriptor).expect("build");
    assert_eq!(
        handle.type_id_minimal,
        TypeIdentifier::minimal(EquivalenceHash::from_bytes(minimal_hash))
    );
    assert_eq!(
        handle.type_id_complete,
        TypeIdentifier::complete(EquivalenceHash::from_bytes(complete_hash))
    );
}

// XTypes 1.3 7.3.4.5, 7.3.4.6 and Annex B: plain identifiers recursively
// contain their element identifiers, without a fixed serialized size limit.
// Hash oracles were independently serialized from the normative IDL and
// computed with Python hashlib: MD5(outer XCDR2-LE TypeObject)[0..14].
#[cfg(feature = "xtypes")]
#[test]
fn deep_sequence_identifiers_hash_the_entire_type_object() {
    let mut field_type = FieldType::Primitive(PrimitiveType::Int32);
    for _ in 0..16 {
        field_type = FieldType::Sequence {
            element: Box::new(field_type),
            bound: None,
        };
    }
    // Minimal: 134 bytes; Complete: 176 bytes, including all DHEADERs.
    assert_deep_collection_hashes(
        field_type,
        [
            0xc4, 0x51, 0xd3, 0x0d, 0xb6, 0x36, 0x54, 0x8e, 0x38, 0x83, 0x67, 0x2d, 0xa9, 0x65,
        ],
        [
            0xe6, 0xd4, 0x15, 0x82, 0xc1, 0x7c, 0xd9, 0xec, 0xf9, 0xe0, 0x1c, 0x31, 0x4f, 0xe1,
        ],
    );
}

#[cfg(feature = "xtypes")]
#[test]
fn deep_array_identifiers_hash_every_large_dimension() {
    let mut field_type = FieldType::Primitive(PrimitiveType::Int32);
    for _ in 0..16 {
        field_type = FieldType::Array {
            element: Box::new(field_type),
            dimensions: vec![256; 80],
        };
    }
    // Annex B's LBoundSeq has no bound on the dimension count. Each level
    // alone exceeds 256 bytes; Minimal is 5289 bytes and Complete is 5332.
    assert_deep_collection_hashes(
        field_type,
        [
            0x12, 0x3b, 0x29, 0xaa, 0xba, 0xb6, 0x10, 0xce, 0x7f, 0xaa, 0xdf, 0xe0, 0xd1, 0x50,
        ],
        [
            0x9b, 0xf0, 0x1a, 0x44, 0x53, 0x29, 0xef, 0x9e, 0xb8, 0x45, 0xc8, 0xe1, 0xee, 0x29,
        ],
    );
}

#[test]
fn builds_struct_with_primitives() {
    let members = [
        MessageMember {
            name: "temperature",
            field_type: FieldType::Primitive(PrimitiveType::Float32),
            is_key: false,
        },
        MessageMember {
            name: "humidity",
            field_type: FieldType::Primitive(PrimitiveType::Float64),
            is_key: false,
        },
    ];
    let hash = ros_hash(0x10);
    let descriptor = MessageDescriptor {
        namespace: "sensor_msgs::msg",
        name: "Climate",
        members: &members,
        ros_hash_version: 1,
        ros_hash: &hash,
    };

    let handle = TypeObjectBuilder::from_descriptor(Distro::Humble, &descriptor).expect("build");

    let struct_complete = match &handle.complete {
        CompleteTypeObject::Struct(s) => Some(s),
        _ => None,
    }
    .expect("expected struct TypeObject");
    let struct_minimal = match &handle.minimal {
        MinimalTypeObject::Struct(s) => Some(s),
        _ => None,
    }
    .expect("expected struct TypeObject");

    assert_eq!(struct_complete.member_seq.len(), 2);
    assert_eq!(struct_minimal.member_seq.len(), 2);
    assert_eq!(struct_complete.member_seq[0].detail.name, "temperature");
    assert!(matches!(
        struct_complete.member_seq[0].common.member_type_id,
        TypeIdentifier::Primitive(TypeKind::TK_FLOAT32)
    ));
    assert_eq!(handle.ros_hash_version, 1);
    assert_eq!(handle.ros_hash.as_ref(), &hash);
}

#[test]
fn builds_sequence_of_strings() {
    let members = [MessageMember {
        name: "labels",
        field_type: FieldType::Sequence {
            element: Box::new(FieldType::String { bound: Some(16) }),
            bound: Some(32),
        },
        is_key: false,
    }];
    let hash = ros_hash(0x22);
    let descriptor = MessageDescriptor {
        namespace: "vision_msgs::msg",
        name: "Annotations",
        members: &members,
        ros_hash_version: 1,
        ros_hash: &hash,
    };

    let handle = TypeObjectBuilder::from_descriptor(Distro::Iron, &descriptor).expect("build");

    let struct_complete = match &handle.complete {
        CompleteTypeObject::Struct(s) => Some(s),
        _ => None,
    }
    .expect("expected struct TypeObject");
    assert_eq!(struct_complete.member_seq.len(), 1);
    let TypeIdentifier::PlainSequenceSmall(seq) =
        &struct_complete.member_seq[0].common.member_type_id
    else {
        panic!("anonymous sequence must use a plain identifier");
    };
    assert_eq!(seq.bound, 32);
    assert_eq!(*seq.element_identifier, TypeIdentifier::string(16));
}

#[test]
fn builds_nested_structs_and_keys() {
    let point_members = [
        MessageMember {
            name: "x",
            field_type: FieldType::Primitive(PrimitiveType::Float64),
            is_key: false,
        },
        MessageMember {
            name: "y",
            field_type: FieldType::Primitive(PrimitiveType::Float64),
            is_key: false,
        },
    ];
    let point_hash = ros_hash(0x33);
    let point_descriptor = MessageDescriptor {
        namespace: "geometry_msgs::msg",
        name: "Point",
        members: &point_members,
        ros_hash_version: 1,
        ros_hash: &point_hash,
    };

    let pose_members = [
        MessageMember {
            name: "position",
            field_type: FieldType::Nested(&point_descriptor),
            is_key: false,
        },
        MessageMember {
            name: "tag",
            field_type: FieldType::String { bound: None },
            is_key: true,
        },
    ];
    let pose_hash = ros_hash(0x44);
    let pose_descriptor = MessageDescriptor {
        namespace: "geometry_msgs::msg",
        name: "Pose",
        members: &pose_members,
        ros_hash_version: 1,
        ros_hash: &pose_hash,
    };

    let handle =
        TypeObjectBuilder::from_descriptor(Distro::Jazzy, &pose_descriptor).expect("build");

    let mut builder = TypeObjectBuilder::new(Distro::Jazzy);
    let first = builder.build_handle(&pose_descriptor).expect("first build");
    let rebuilt = builder
        .build_handle(&pose_descriptor)
        .expect("interned rebuild");
    assert_eq!(first.complete, rebuilt.complete);
    assert_eq!(first.minimal, rebuilt.minimal);
    assert_eq!(handle.complete, rebuilt.complete);
    let struct_complete = match &handle.complete {
        CompleteTypeObject::Struct(s) => Some(s),
        _ => None,
    }
    .expect("expected struct TypeObject");
    assert_eq!(struct_complete.member_seq.len(), 2);
    assert!(matches!(
        struct_complete.member_seq[0].common.member_type_id,
        TypeIdentifier::Complete(_)
    ));
    assert_eq!(struct_complete.member_seq[1].common.member_flags.0, 0x0031);
    assert_eq!(struct_complete.member_seq[0].common.member_flags.0, 0x0001);
    let MinimalTypeObject::Struct(minimal) = &handle.minimal else {
        panic!("expected struct");
    };
    assert!(matches!(
        minimal.member_seq[0].common.member_type_id,
        TypeIdentifier::Minimal(_)
    ));
    assert_eq!(minimal.member_seq[1].common.member_flags.0, 0x0031);
    assert_eq!(minimal.member_seq[0].common.member_flags.0, 0x0001);
}

/// XTypes 1.3 7.3.4.1 / 7.3.4.6: anonymous collections have only
/// plain TypeIdentifiers, fully descriptive when their elements are.
#[test]
fn anonymous_collections_use_plain_identifiers() {
    let members = [
        MessageMember {
            name: "samples",
            field_type: FieldType::Sequence {
                element: Box::new(FieldType::Primitive(PrimitiveType::Int32)),
                bound: None,
            },
            is_key: false,
        },
        MessageMember {
            name: "matrix",
            field_type: FieldType::Array {
                element: Box::new(FieldType::Primitive(PrimitiveType::Float64)),
                dimensions: vec![3, 3],
            },
            is_key: false,
        },
    ];
    let hash = ros_hash(0x40);
    let descriptor = MessageDescriptor {
        namespace: "test_msgs::msg",
        name: "Collections",
        members: &members,
        ros_hash_version: 1,
        ros_hash: &hash,
    };
    let handle = TypeObjectBuilder::from_descriptor(Distro::Humble, &descriptor).expect("build");
    let CompleteTypeObject::Struct(s) = &handle.complete else {
        panic!("struct");
    };
    let header = crate::xtypes::PlainCollectionHeader {
        equiv_kind: crate::xtypes::EquivalenceKind::Both,
        element_flags: crate::xtypes::CollectionElementFlag::TRY_CONSTRUCT1,
    };
    assert_eq!(
        s.member_seq[0].common.member_type_id,
        TypeIdentifier::PlainSequenceSmall(crate::xtypes::PlainSequenceSElemDefn {
            header,
            bound: 0,
            element_identifier: Box::new(TypeIdentifier::primitive(TypeKind::TK_INT32)),
        })
    );
    assert_eq!(
        s.member_seq[1].common.member_type_id,
        TypeIdentifier::PlainArraySmall(crate::xtypes::PlainArraySElemDefn {
            header,
            array_bound_seq: vec![3, 3],
            element_identifier: Box::new(TypeIdentifier::primitive(TypeKind::TK_FLOAT64)),
        })
    );
    let MinimalTypeObject::Struct(m) = &handle.minimal else {
        panic!("struct");
    };
    assert_eq!(s.member_seq[0].common, m.member_seq[0].common);
    assert_eq!(s.member_seq[1].common, m.member_seq[1].common);
}

/// Bounds must select SMALL up to 255 and LARGE thereafter, independently
/// of the element's equivalence kind (XTypes 1.3 Annex B).
#[test]
fn plain_collection_bounds_and_recursive_equivalence_kind() {
    use crate::xtypes::{EquivalenceHash, EquivalenceKind};
    for element in [
        TypeIdentifier::primitive(TypeKind::TK_INT32),
        TypeIdentifier::complete(EquivalenceHash::from_bytes([7; 14])),
        TypeIdentifier::minimal(EquivalenceHash::from_bytes([8; 14])),
    ] {
        let expected_kind = match element {
            TypeIdentifier::Complete(_) => EquivalenceKind::Complete,
            TypeIdentifier::Minimal(_) => EquivalenceKind::Minimal,
            _ => EquivalenceKind::Both,
        };
        for bound in [0, 1, 255, 256, u32::MAX] {
            let id = TypeObjectBuilder::sequence_type_identifier_from_element(
                element.clone(),
                Some(bound),
            )
            .expect("sequence");
            let (header, actual_bound, actual_element) = match &id {
                TypeIdentifier::PlainSequenceSmall(s) if bound <= 255 => {
                    (s.header, u32::from(s.bound), &s.element_identifier)
                }
                TypeIdentifier::PlainSequenceLarge(s) if bound > 255 => {
                    (s.header, s.bound, &s.element_identifier)
                }
                _ => panic!("incorrect bound representation"),
            };
            assert_eq!(actual_bound, bound);
            assert_eq!(**actual_element, element);
            assert_eq!(header.equiv_kind, expected_kind);
            assert_eq!(header.element_flags.0, 1);
            let array = TypeObjectBuilder::array_type_identifier_from_element(id, &[2, 256])
                .expect("array of sequences");
            let TypeIdentifier::PlainArrayLarge(a) = array else {
                panic!("large array");
            };
            assert_eq!(a.array_bound_seq, [2, 256]);
            assert_eq!(a.header.equiv_kind, expected_kind);
            assert_eq!(a.header.element_flags.0, 1);
        }
        for dimensions in [vec![1, 255], vec![256, 1], vec![1, u32::MAX]] {
            let id =
                TypeObjectBuilder::array_type_identifier_from_element(element.clone(), &dimensions)
                    .expect("array");
            let (header, actual, actual_element) = match id {
                TypeIdentifier::PlainArraySmall(a) if dimensions.iter().all(|d| *d <= 255) => (
                    a.header,
                    a.array_bound_seq
                        .into_iter()
                        .map(u32::from)
                        .collect::<Vec<_>>(),
                    a.element_identifier,
                ),
                TypeIdentifier::PlainArrayLarge(a) if dimensions.iter().any(|d| *d > 255) => {
                    (a.header, a.array_bound_seq, a.element_identifier)
                }
                _ => panic!("incorrect dimension representation"),
            };
            assert_eq!(actual, dimensions);
            assert_eq!(*actual_element, element);
            assert_eq!(header.equiv_kind, expected_kind);
        }
    }
    for dimensions in [vec![], vec![0], vec![1, 0]] {
        assert!(TypeObjectBuilder::array_type_identifier_from_element(
            TypeIdentifier::primitive(TypeKind::TK_INT32),
            &dimensions
        )
        .is_err());
    }
}
