// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Metadata QoS policies integration tests (USER_DATA, GROUP_DATA, TOPIC_DATA)
//!
//! Validates metadata policies exposed through public API.

use hdds::api::{GroupData, Participant, QoS, TopicData, UserData};
use hdds::test_support::domains::unique_domain;
use std::time::Duration;

// ============================================================================
// USER_DATA QoS policy tests
// ============================================================================

#[test]
fn test_user_data_qos_builder_custom() {
    // Create QoS with custom USER_DATA
    let qos = QoS::best_effort().user_data(UserData::new(b"version=1.0.0".to_vec()));

    assert_eq!(qos.user_data.value, b"version=1.0.0");
    assert!(!qos.user_data.is_empty());
    assert_eq!(qos.user_data.len(), 13);
}

#[test]
fn test_user_data_qos_builder_bytes() {
    // Create QoS with USER_DATA from byte slice
    let qos = QoS::best_effort().user_data_bytes(b"app_id=12345");

    assert_eq!(qos.user_data.value, b"app_id=12345");
    assert_eq!(qos.user_data.len(), 12);
}

#[test]
fn test_user_data_qos_default() {
    // Default QoS should have empty USER_DATA
    let qos = QoS::default();

    assert!(qos.user_data.is_empty());
    assert_eq!(qos.user_data.len(), 0);
}

#[test]
fn test_user_data_struct_creation() {
    let user_data = UserData::new(b"test_data".to_vec());
    assert_eq!(user_data.value, b"test_data");
    assert_eq!(user_data.len(), 9);
}

#[test]
fn test_user_data_struct_empty() {
    let user_data = UserData::empty();
    assert!(user_data.is_empty());
    assert_eq!(user_data.value, Vec::<u8>::new());
}

#[test]
fn test_participant_with_user_data_qos() {
    // Verify participant can be created with USER_DATA QoS (smoke test)
    // No `.with_transport(...)`: this participant takes the DEFAULT
    // UdpMulticast transport and therefore binds RTPS ports. The domain
    // is leased (declared first, so dropped last) instead of defaulting
    // to 0, which every other test binary also lands on.
    let domain = unique_domain();
    let participant = Participant::builder("user_data_test")
        .domain_id(domain.id())
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until metadata is fully integrated
    // In the future, this will test metadata propagation in discovery

    drop(participant);
}

// ============================================================================
// GROUP_DATA QoS policy tests
// ============================================================================

#[test]
fn test_group_data_qos_builder_custom() {
    // Create QoS with custom GROUP_DATA
    let qos = QoS::best_effort().group_data(GroupData::new(b"deployment=production".to_vec()));

    assert_eq!(qos.group_data.value, b"deployment=production");
    assert!(!qos.group_data.is_empty());
    assert_eq!(qos.group_data.len(), 21);
}

#[test]
fn test_group_data_qos_builder_bytes() {
    // Create QoS with GROUP_DATA from byte slice
    let qos = QoS::best_effort().group_data_bytes(b"org=robotics");

    assert_eq!(qos.group_data.value, b"org=robotics");
    assert_eq!(qos.group_data.len(), 12);
}

#[test]
fn test_group_data_qos_default() {
    // Default QoS should have empty GROUP_DATA
    let qos = QoS::default();

    assert!(qos.group_data.is_empty());
    assert_eq!(qos.group_data.len(), 0);
}

#[test]
fn test_group_data_struct_creation() {
    let group_data = GroupData::new(b"test_group".to_vec());
    assert_eq!(group_data.value, b"test_group");
    assert_eq!(group_data.len(), 10);
}

#[test]
fn test_group_data_struct_empty() {
    let group_data = GroupData::empty();
    assert!(group_data.is_empty());
    assert_eq!(group_data.value, Vec::<u8>::new());
}

// ============================================================================
// TOPIC_DATA QoS policy tests
// ============================================================================

#[test]
fn test_topic_data_qos_builder_custom() {
    // Create QoS with custom TOPIC_DATA
    let qos = QoS::best_effort().topic_data(TopicData::new(b"schema=v2".to_vec()));

    assert_eq!(qos.topic_data.value, b"schema=v2");
    assert!(!qos.topic_data.is_empty());
    assert_eq!(qos.topic_data.len(), 9);
}

#[test]
fn test_topic_data_qos_builder_bytes() {
    // Create QoS with TOPIC_DATA from byte slice
    let qos = QoS::best_effort().topic_data_bytes(b"units=meters");

    assert_eq!(qos.topic_data.value, b"units=meters");
    assert_eq!(qos.topic_data.len(), 12);
}

#[test]
fn test_topic_data_qos_default() {
    // Default QoS should have empty TOPIC_DATA
    let qos = QoS::default();

    assert!(qos.topic_data.is_empty());
    assert_eq!(qos.topic_data.len(), 0);
}

#[test]
fn test_topic_data_struct_creation() {
    let topic_data = TopicData::new(b"test_topic".to_vec());
    assert_eq!(topic_data.value, b"test_topic");
    assert_eq!(topic_data.len(), 10);
}

#[test]
fn test_topic_data_struct_empty() {
    let topic_data = TopicData::empty();
    assert!(topic_data.is_empty());
    assert_eq!(topic_data.value, Vec::<u8>::new());
}

// ============================================================================
// Combined metadata tests
// ============================================================================

#[test]
fn test_qos_all_metadata_policies() {
    // Create QoS with all three metadata policies
    let qos = QoS::reliable()
        .user_data_bytes(b"version=1.0.0")
        .group_data_bytes(b"deployment=production")
        .topic_data_bytes(b"schema=v2");

    assert_eq!(qos.user_data.value, b"version=1.0.0");
    assert_eq!(qos.group_data.value, b"deployment=production");
    assert_eq!(qos.topic_data.value, b"schema=v2");
}

#[test]
fn test_qos_metadata_builder_chaining() {
    // Test that metadata policies can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .user_data_bytes(b"app=sensor")
        .group_data_bytes(b"team=robotics")
        .topic_data_bytes(b"units=celsius");

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.user_data.value, b"app=sensor");
    assert_eq!(qos.group_data.value, b"team=robotics");
    assert_eq!(qos.topic_data.value, b"units=celsius");
}

#[test]
fn test_metadata_clone() {
    let qos1 = QoS::best_effort().user_data_bytes(b"test");
    let qos2 = qos1.clone();

    assert_eq!(qos2.user_data.value, b"test");
}

#[test]
fn test_metadata_binary_data() {
    // Test with arbitrary binary data
    let binary_data = vec![0x01, 0x02, 0x03, 0xFF, 0xFE];
    let qos = QoS::best_effort().user_data(UserData::new(binary_data.clone()));

    assert_eq!(qos.user_data.value, binary_data);
    assert_eq!(qos.user_data.len(), 5);
}

// ============================================================================
// Use case tests
// ============================================================================

#[test]
fn test_user_data_use_case_version_info() {
    // Store version information in USER_DATA
    let qos = QoS::best_effort().user_data_bytes(b"app_version=1.2.3");

    assert_eq!(qos.user_data.value, b"app_version=1.2.3");
}

#[test]
fn test_user_data_use_case_build_id() {
    // Store build ID in USER_DATA
    let qos = QoS::best_effort().user_data_bytes(b"build_id=abc123");

    assert!(!qos.user_data.is_empty());
    assert_eq!(qos.user_data.len(), 15);
}

#[test]
fn test_group_data_use_case_deployment_env() {
    // Store deployment environment in GROUP_DATA
    let qos = QoS::best_effort().group_data_bytes(b"env=production");

    assert_eq!(qos.group_data.value, b"env=production");
}

#[test]
fn test_group_data_use_case_organization() {
    // Store organization info in GROUP_DATA
    let qos = QoS::best_effort().group_data_bytes(b"org=robotics_team");

    assert!(!qos.group_data.is_empty());
}

#[test]
fn test_topic_data_use_case_schema_version() {
    // Store schema version in TOPIC_DATA
    let qos = QoS::best_effort().topic_data_bytes(b"schema_version=2.0");

    assert_eq!(qos.topic_data.value, b"schema_version=2.0");
}

#[test]
fn test_topic_data_use_case_units() {
    // Store units metadata in TOPIC_DATA
    let qos = QoS::best_effort().topic_data_bytes(b"units=meters/second");

    assert!(!qos.topic_data.is_empty());
    assert_eq!(qos.topic_data.len(), 19);
}

#[test]
fn test_metadata_json_serialized() {
    // Example: JSON-serialized metadata
    let json = b"{\"version\":\"1.0\",\"debug\":true}";
    let qos = QoS::best_effort().user_data_bytes(json);

    assert_eq!(qos.user_data.value, json);
}

#[test]
fn test_metadata_large_payload() {
    // Test with larger metadata payload (1KB)
    let large_data = vec![0x42; 1024];
    let qos = QoS::best_effort().topic_data(TopicData::new(large_data.clone()));

    assert_eq!(qos.topic_data.len(), 1024);
    assert_eq!(qos.topic_data.value, large_data);
}

#[test]
fn test_metadata_discovery_scenario() {
    // Realistic discovery scenario: participant with multiple metadata
    let qos = QoS::reliable()
        .user_data_bytes(b"participant_id=sensor_001")
        .group_data_bytes(b"location=factory_floor_1")
        .topic_data_bytes(b"topic=temperature_celsius");

    assert_eq!(qos.user_data.value, b"participant_id=sensor_001");
    assert_eq!(qos.group_data.value, b"location=factory_floor_1");
    assert_eq!(qos.topic_data.value, b"topic=temperature_celsius");
}

#[test]
fn test_user_data_equality() {
    let data1 = UserData::new(b"test".to_vec());
    let data2 = UserData::new(b"test".to_vec());
    let data3 = UserData::new(b"other".to_vec());

    assert_eq!(data1, data2);
    assert_ne!(data1, data3);
}

#[test]
fn test_group_data_equality() {
    let data1 = GroupData::new(b"test".to_vec());
    let data2 = GroupData::new(b"test".to_vec());
    let data3 = GroupData::new(b"other".to_vec());

    assert_eq!(data1, data2);
    assert_ne!(data1, data3);
}

#[test]
fn test_topic_data_equality() {
    let data1 = TopicData::new(b"test".to_vec());
    let data2 = TopicData::new(b"test".to_vec());
    let data3 = TopicData::new(b"other".to_vec());

    assert_eq!(data1, data2);
    assert_ne!(data1, data3);
}

#[test]
fn test_metadata_debug() {
    let user_data = UserData::new(b"test".to_vec());
    let debug_str = format!("{user_data:?}");
    assert!(debug_str.contains("UserData"));

    let group_data = GroupData::new(b"test".to_vec());
    let debug_str = format!("{group_data:?}");
    assert!(debug_str.contains("GroupData"));

    let topic_data = TopicData::new(b"test".to_vec());
    let debug_str = format!("{topic_data:?}");
    assert!(debug_str.contains("TopicData"));
}

// ============================================================================
// Behavior tests: Deferred
// ============================================================================
//
// TODO: Metadata (USER_DATA, GROUP_DATA, TOPIC_DATA) behavior tests are deferred.
// Metadata propagation via SPDP/SEDP discovery messages is not yet wired
// into the public API for reading remote participant/endpoint metadata.
// Once integrated, add tests for:
// 1. Participant A sets USER_DATA, Participant B discovers it
// 2. Writer sets TOPIC_DATA, matched reader can query it
// 3. GROUP_DATA propagation through publisher/subscriber discovery
//
// For now, these tests validate the QoS API surface only.
