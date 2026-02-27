// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::core::TypeObjectBuilder;
use super::model::{FieldType, MessageDescriptor, MessageMember, PrimitiveType};
use crate::core::types::{Distro, ROS_HASH_SIZE};
use crate::xtypes::{CompleteTypeObject, MemberFlag, MinimalTypeObject, TypeIdentifier, TypeKind};
use std::convert::TryFrom;

fn ros_hash(seed: u8) -> [u8; ROS_HASH_SIZE] {
    let mut bytes = [0u8; ROS_HASH_SIZE];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        let idx_u8 = u8::try_from(idx).expect("ROS hash length fits in u8");
        *byte = seed.wrapping_add(idx_u8);
    }
    bytes
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
    assert!(matches!(
        struct_complete.member_seq[0].common.member_type_id,
        TypeIdentifier::Minimal(_)
    ));
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

    let struct_complete = match &handle.complete {
        CompleteTypeObject::Struct(s) => Some(s),
        _ => None,
    }
    .expect("expected struct TypeObject");
    assert_eq!(struct_complete.member_seq.len(), 2);
    assert!(matches!(
        struct_complete.member_seq[0].common.member_type_id,
        TypeIdentifier::Minimal(_)
    ));
    assert!(struct_complete.member_seq[1]
        .common
        .member_flags
        .contains(MemberFlag::IS_KEY));
}
