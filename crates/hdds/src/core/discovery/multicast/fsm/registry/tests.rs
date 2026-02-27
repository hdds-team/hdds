// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::core::discovery::GUID;
use crate::xtypes::{
    CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
    CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    TypeIdentifier,
};
use std::convert::TryFrom;

fn build_test_struct(
    name: &str,
    flags: StructTypeFlag,
    members: Vec<(u32, &str, TypeIdentifier)>,
) -> CompleteTypeObject {
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: flags,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq: members
            .into_iter()
            .map(|(id, member_name, type_id)| CompleteStructMember {
                common: CommonStructMember {
                    member_id: id,
                    member_flags: MemberFlag::empty(),
                    member_type_id: type_id,
                },
                detail: CompleteMemberDetail::new(member_name),
            })
            .collect(),
    })
}

fn make_endpoint(
    kind: EndpointKind,
    topic: &str,
    type_name: &str,
    unique: u8,
    _qos_hash: u64, // v61: Deprecated - now using real QoS object
    type_obj: Option<CompleteTypeObject>,
) -> EndpointInfo {
    let mut guid_bytes = [0u8; 16];
    for (idx, byte) in guid_bytes.iter_mut().take(12).enumerate() {
        let offset = u8::try_from(idx).expect("index fits in u8");
        *byte = unique.saturating_add(offset);
    }
    guid_bytes[15] = match kind {
        EndpointKind::Writer => 0x02,
        EndpointKind::Reader => 0x04,
    };

    EndpointInfo {
        endpoint_guid: GUID::from_bytes(guid_bytes),
        participant_guid: GUID::zero(),
        topic_name: topic.to_string(),
        type_name: type_name.to_string(),
        qos: crate::dds::qos::QoS::rti_defaults(), // v61: Use actual QoS object
        kind,
        type_object: type_obj,
    }
}

#[test]
fn test_topic_registry_new() {
    let registry = TopicRegistry::new();
    assert_eq!(registry.find_writers("sensor/temp").len(), 0);
    assert_eq!(registry.find_readers("sensor/temp").len(), 0);
}

#[test]
fn test_topic_registry_insert_writer() {
    let mut registry = TopicRegistry::new();
    let endpoint = make_endpoint(
        EndpointKind::Writer,
        "sensor/temp",
        "Temperature",
        1,
        42_u64,
        None,
    );

    registry.insert(endpoint.clone());

    let writers = registry.find_writers("sensor/temp");
    assert_eq!(writers.len(), 1);
    assert_eq!(writers[0].endpoint_guid, endpoint.endpoint_guid);
}

#[test]
fn test_topic_registry_find_writers_filters_readers() {
    let mut registry = TopicRegistry::new();
    registry.insert(make_endpoint(
        EndpointKind::Writer,
        "sensor/temp",
        "Temperature",
        1,
        11_u64,
        None,
    ));
    registry.insert(make_endpoint(
        EndpointKind::Reader,
        "sensor/temp",
        "Temperature",
        2,
        22_u64,
        None,
    ));

    let writers = registry.find_writers("sensor/temp");
    assert_eq!(writers.len(), 1);
    assert!(writers.iter().all(|e| e.kind == EndpointKind::Writer));
}

#[test]
fn test_topic_registry_multiple_topics() {
    let mut registry = TopicRegistry::new();
    registry.insert(make_endpoint(
        EndpointKind::Writer,
        "sensor/temp",
        "Temperature",
        1,
        11_u64,
        None,
    ));
    registry.insert(make_endpoint(
        EndpointKind::Reader,
        "telemetry/pressure",
        "Pressure",
        2,
        22_u64,
        None,
    ));

    let writers = registry.find_writers("sensor/temp");
    let readers = registry.find_readers("telemetry/pressure");

    assert_eq!(writers.len(), 1);
    assert_eq!(readers.len(), 1);
    assert!(registry.find_writers("unknown").is_empty());
}

#[test]
fn test_topic_registry_update_existing_endpoint() {
    let mut registry = TopicRegistry::new();
    let mut endpoint = make_endpoint(
        EndpointKind::Writer,
        "sensor/temp",
        "Temperature",
        1,
        11_u64,
        None,
    );

    registry.insert(endpoint.clone());

    // v61: Update QoS instead of qos_hash
    endpoint.qos.history = crate::dds::qos::History::KeepLast(99);
    registry.insert(endpoint.clone());

    let writers = registry.find_writers("sensor/temp");
    assert_eq!(writers.len(), 1);
    assert!(matches!(
        writers[0].qos.history,
        crate::dds::qos::History::KeepLast(99)
    ));
}

#[test]
fn test_topic_registry_remove_participant() {
    let mut registry = TopicRegistry::new();
    let participant1 = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0x02]);
    let participant2 = GUID::from_bytes([9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 0, 0, 0, 0x02]);

    registry.insert(EndpointInfo {
        endpoint_guid: participant1,
        participant_guid: participant1,
        topic_name: "sensor/temp".to_string(),
        type_name: "Temperature".to_string(),
        qos: crate::dds::qos::QoS::rti_defaults(), // v61: Use actual QoS object
        kind: EndpointKind::Writer,
        type_object: None,
    });
    registry.insert(EndpointInfo {
        endpoint_guid: participant2,
        participant_guid: participant2,
        topic_name: "sensor/temp".to_string(),
        type_name: "Temperature".to_string(),
        qos: crate::dds::qos::QoS::rti_defaults(), // v61: Use actual QoS object
        kind: EndpointKind::Writer,
        type_object: None,
    });

    let removed = registry.remove_participant(&participant1);
    assert_eq!(removed, 1);
    assert_eq!(registry.find_writers("sensor/temp").len(), 1);
}

#[test]
fn test_find_compatible_writers_xtypes_matching() {
    let mut registry = TopicRegistry::new();
    let point_type_obj = build_test_struct("Point", StructTypeFlag::IS_FINAL, vec![]);

    registry.insert(make_endpoint(
        EndpointKind::Writer,
        "geometry/points",
        "Point",
        1,
        11_u64,
        Some(point_type_obj.clone()),
    ));

    let compatible =
        registry.find_compatible_writers("geometry/points", Some(&point_type_obj), "Point");

    assert_eq!(compatible.len(), 1);
    assert_eq!(compatible[0].kind, EndpointKind::Writer);
}

#[test]
fn test_find_compatible_writers_xtypes_mismatch() {
    use crate::xtypes::{CompleteStructHeader, CompleteStructType, CompleteTypeDetail};

    let mut registry = TopicRegistry::new();
    let point_type_obj = build_test_struct("Point", StructTypeFlag::IS_FINAL, vec![]);

    registry.insert(make_endpoint(
        EndpointKind::Writer,
        "geometry/points",
        "Point",
        1,
        11_u64,
        Some(point_type_obj.clone()),
    ));

    let line_type_obj = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Line"),
        },
        member_seq: vec![],
    });

    let compatible =
        registry.find_compatible_writers("geometry/points", Some(&line_type_obj), "Line");

    assert!(compatible.is_empty());
}

#[test]
fn test_find_compatible_writers_legacy_matching() {
    let mut registry = TopicRegistry::new();
    registry.insert(make_endpoint(
        EndpointKind::Writer,
        "sensor/temp",
        "Temperature",
        1,
        11_u64,
        None,
    ));

    let compatible = registry.find_compatible_writers("sensor/temp", None, "Temperature");
    assert_eq!(compatible.len(), 1);
    assert_eq!(compatible[0].type_name, "Temperature");
}

#[test]
fn test_find_compatible_writers_legacy_mismatch() {
    let mut registry = TopicRegistry::new();
    registry.insert(make_endpoint(
        EndpointKind::Writer,
        "sensor/temp",
        "Temperature",
        1,
        11_u64,
        None,
    ));

    let compatible = registry.find_compatible_writers("sensor/temp", None, "Humidity");
    assert!(compatible.is_empty());
}

#[test]
fn test_find_compatible_readers_xtypes_matching() {
    use crate::xtypes::{
        CompleteStructHeader, CompleteStructType, CompleteTypeDetail, StructTypeFlag,
    };

    let mut registry = TopicRegistry::new();
    let temp_type_obj = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Temperature"),
        },
        member_seq: vec![],
    });

    registry.insert(make_endpoint(
        EndpointKind::Reader,
        "sensor/temp",
        "Temperature",
        1,
        11_u64,
        Some(temp_type_obj.clone()),
    ));

    let compatible =
        registry.find_compatible_readers("sensor/temp", Some(&temp_type_obj), "Temperature");

    assert_eq!(compatible.len(), 1);
    assert_eq!(compatible[0].kind, EndpointKind::Reader);
}

#[test]
fn test_find_compatible_mixed_endpoints() {
    let mut registry = TopicRegistry::new();
    let type_obj = build_test_struct("Point", StructTypeFlag::IS_FINAL, vec![]);

    for (unique, qos) in [(1, 1_u64), (2, 2_u64)] {
        registry.insert(make_endpoint(
            EndpointKind::Writer,
            "geometry/points",
            "Point",
            unique,
            qos,
            Some(type_obj.clone()),
        ));
    }
    for (unique, qos) in [(3, 3_u64), (4, 4_u64)] {
        registry.insert(make_endpoint(
            EndpointKind::Reader,
            "geometry/points",
            "Point",
            unique,
            qos,
            Some(type_obj.clone()),
        ));
    }

    let writers = registry.find_compatible_writers("geometry/points", Some(&type_obj), "Point");
    assert_eq!(writers.len(), 2);
    assert!(writers.iter().all(|e| e.kind == EndpointKind::Writer));

    let readers = registry.find_compatible_readers("geometry/points", Some(&type_obj), "Point");
    assert_eq!(readers.len(), 2);
    assert!(readers.iter().all(|e| e.kind == EndpointKind::Reader));
}

#[test]
fn test_find_compatible_empty_topic() {
    let registry = TopicRegistry::new();

    assert!(registry
        .find_compatible_writers("nonexistent", None, "SomeType")
        .is_empty());
    assert!(registry
        .find_compatible_readers("nonexistent", None, "SomeType")
        .is_empty());
}
