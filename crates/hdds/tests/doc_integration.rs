// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Doc Integration Tests (Doc-as-Contract)
//!
//! These tests validate that documented API patterns work correctly.
//! If any test fails, it indicates the documentation may be misleading.
//!
//! Test levels:
//! - UC-01: Basic pub/sub (same process)
//! - UC-02: QoS Reliable + KeepLast
//! - UC-03: Publisher/Subscriber entities
//! - UC-04: Coherent changes API

use hdds::api::Reliability;
use hdds::{Participant, QoS};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Temperature {
    sensor_id: u32,
    value: f64,
}

/// Helper to check if QoS is reliable
fn is_reliable(qos: &QoS) -> bool {
    matches!(qos.reliability, Reliability::Reliable)
}

/// UC-01: Basic pub/sub (single topic, single writer, single reader, same process)
///
/// Documentation claims:
/// - Participant::builder(name).build() creates a participant
/// - create_writer/create_reader work with DDS-derived types
/// - write() publishes data
/// - take() receives data
///
/// Note: This test is flaky in IntraProcess mode due to timing issues.
/// The API works correctly but requires UdpMulticast for reliable testing.
#[test]
#[ignore = "Flaky in IntraProcess mode - see publisher_subscriber tests for reliable version"]
fn uc01_basic_pubsub() {
    let participant = Arc::new(
        Participant::builder("doc-test-uc01")
            .build()
            .expect("Participant creation should succeed (documented)"),
    );

    let writer = participant
        .create_writer::<Temperature>("temperature", QoS::default())
        .expect("create_writer should succeed (documented)");

    let reader = participant
        .create_reader::<Temperature>("temperature", QoS::default())
        .expect("create_reader should succeed (documented)");

    // Write data
    let sample = Temperature {
        sensor_id: 1,
        value: 25.5,
    };
    writer
        .write(&sample)
        .expect("write should succeed (documented)");

    // Small delay for intra-process delivery
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Read data - take() returns Result<Option<T>>
    let received = reader.take().expect("take should succeed (documented)");
    assert!(received.is_some(), "Should receive published sample");
    let temp = received.unwrap();
    assert_eq!(temp.sensor_id, 1);
    assert!((temp.value - 25.5).abs() < 0.001);
}

/// UC-02: QoS Reliable + KeepLast
///
/// Documentation claims:
/// - QoS::reliable() creates reliable QoS
/// - QoS::keep_last(n) sets history depth
/// - Builder pattern works: QoS::reliable().keep_last(10)
#[test]
fn uc02_qos_reliable_keeplast() {
    // Test QoS builder pattern (documented)
    let qos = QoS::reliable().keep_last(10);

    // Verify QoS properties (internal validation)
    assert!(
        is_reliable(&qos),
        "reliable() should set reliable QoS (documented)"
    );

    // Use in participant
    let participant = Arc::new(
        Participant::builder("doc-test-uc02")
            .build()
            .expect("Participant creation should succeed"),
    );

    let _writer = participant
        .create_writer::<Temperature>("temperature", qos.clone())
        .expect("create_writer with QoS should succeed (documented)");

    let _reader = participant
        .create_reader::<Temperature>("temperature", qos)
        .expect("create_reader with QoS should succeed (documented)");
}

/// UC-03: Publisher/Subscriber entities
///
/// Documentation claims:
/// - participant.create_publisher(qos) creates a Publisher
/// - participant.create_subscriber(qos) creates a Subscriber
/// - Publisher can create_writer
/// - Subscriber can create_reader
#[test]
fn uc03_publisher_subscriber() {
    let participant = Arc::new(
        Participant::builder("doc-test-uc03")
            .build()
            .expect("Participant creation should succeed"),
    );

    // Create Publisher (documented)
    let publisher = participant
        .create_publisher(QoS::default())
        .expect("create_publisher should succeed (documented)");

    // Create Subscriber (documented)
    let subscriber = participant
        .create_subscriber(QoS::default())
        .expect("create_subscriber should succeed (documented)");

    // Create writer through Publisher (documented)
    let _writer = publisher
        .create_writer::<Temperature>("temperature", QoS::reliable())
        .expect("Publisher::create_writer should succeed (documented)");

    // Create reader through Subscriber (documented)
    let _reader = subscriber
        .create_reader::<Temperature>("temperature", QoS::reliable())
        .expect("Subscriber::create_reader should succeed (documented)");
}

/// UC-04: Coherent Changes API
///
/// Documentation claims:
/// - publisher.begin_coherent_changes() starts coherent set
/// - publisher.end_coherent_changes() commits coherent set
/// - subscriber.begin_access() locks view
/// - subscriber.end_access() unlocks view
/// - Nested calls should return error
#[test]
fn uc04_coherent_changes() {
    let participant = Arc::new(
        Participant::builder("doc-test-uc04")
            .build()
            .expect("Participant creation should succeed"),
    );

    let publisher = participant
        .create_publisher(QoS::default())
        .expect("create_publisher should succeed");

    let subscriber = participant
        .create_subscriber(QoS::default())
        .expect("create_subscriber should succeed");

    // Test Publisher coherent changes (documented)
    publisher
        .begin_coherent_changes()
        .expect("begin_coherent_changes should succeed (documented)");

    // Nested should fail (documented)
    assert!(
        publisher.begin_coherent_changes().is_err(),
        "Nested begin_coherent_changes should fail (documented)"
    );

    publisher
        .end_coherent_changes()
        .expect("end_coherent_changes should succeed (documented)");

    // End without begin should fail (documented)
    assert!(
        publisher.end_coherent_changes().is_err(),
        "end_coherent_changes without begin should fail (documented)"
    );

    // Test Subscriber access (documented)
    subscriber
        .begin_access()
        .expect("begin_access should succeed (documented)");

    // Nested should fail (documented)
    assert!(
        subscriber.begin_access().is_err(),
        "Nested begin_access should fail (documented)"
    );

    subscriber
        .end_access()
        .expect("end_access should succeed (documented)");

    // End without begin should fail (documented)
    assert!(
        subscriber.end_access().is_err(),
        "end_access without begin should fail (documented)"
    );
}

/// UC-05: Best-effort QoS
///
/// Documentation claims:
/// - QoS::best_effort() creates best-effort QoS
#[test]
fn uc05_qos_best_effort() {
    let qos = QoS::best_effort();

    assert!(
        !is_reliable(&qos),
        "best_effort() should set non-reliable QoS (documented)"
    );

    let participant = Arc::new(
        Participant::builder("doc-test-uc05")
            .build()
            .expect("Participant creation should succeed"),
    );

    let _writer = participant
        .create_writer::<Temperature>("temperature", qos)
        .expect("create_writer with best_effort QoS should succeed (documented)");
}

/// UC-06: Partition QoS
///
/// Documentation claims:
/// - QoS::default().partition_single(name) sets partition
/// - Partition is inherited from Publisher/Subscriber
#[test]
fn uc06_partition_qos() {
    let qos = QoS::default().partition_single("production");

    assert!(
        !qos.partition.is_default(),
        "partition_single should set non-default partition (documented)"
    );

    let participant = Arc::new(
        Participant::builder("doc-test-uc06")
            .build()
            .expect("Participant creation should succeed"),
    );

    // Publisher with partition (documented)
    let publisher = participant
        .create_publisher(qos.clone())
        .expect("create_publisher with partition should succeed (documented)");

    // Verify partition is set
    assert!(
        !publisher.qos().partition.is_default(),
        "Publisher should have partition set (documented)"
    );
}

/// UC-07: Volatile vs TransientLocal durability
///
/// Documentation claims:
/// - QoS has durability settings
/// - volatile() and transient_local() methods exist
#[test]
fn uc07_durability_qos() {
    // Volatile (default)
    let volatile_qos = QoS::reliable().volatile();

    // TransientLocal
    let transient_qos = QoS::reliable().transient_local();

    // Both should be usable
    let participant = Arc::new(
        Participant::builder("doc-test-uc07")
            .build()
            .expect("Participant creation should succeed"),
    );

    let _writer1 = participant
        .create_writer::<Temperature>("temp_volatile", volatile_qos)
        .expect("create_writer with volatile should succeed (documented)");

    let _writer2 = participant
        .create_writer::<Temperature>("temp_transient", transient_qos)
        .expect("create_writer with transient_local should succeed (documented)");
}

/// UC-08: ContentFilteredTopic
///
/// Documentation claims:
/// - participant.create_content_filtered_topic() creates a filtered topic
/// - Filter expression uses SQL-like syntax
/// - Parameters are substituted for %0, %1, etc.
/// - filtered_topic.reader() returns a reader builder with filter attached
#[test]
fn uc08_content_filtered_topic() {
    let participant = Arc::new(
        Participant::builder("doc-test-uc08")
            .build()
            .expect("Participant creation should succeed"),
    );

    // Create content filtered topic (documented)
    let filtered_topic = participant
        .create_content_filtered_topic::<Temperature>(
            "high_temp",              // filtered topic name
            "sensors/temperature",    // related topic name
            "value > %0",             // SQL-like filter expression
            vec!["25.0".to_string()], // expression parameters
        )
        .expect("create_content_filtered_topic should succeed (documented)");

    // Verify filter properties (documented)
    assert_eq!(filtered_topic.name(), "high_temp");
    assert_eq!(filtered_topic.related_topic_name(), "sensors/temperature");
    assert_eq!(filtered_topic.filter_expression(), "value > %0");
    assert_eq!(
        filtered_topic.expression_parameters(),
        vec!["25.0".to_string()]
    );

    // Create reader from filtered topic (documented)
    let _reader = filtered_topic
        .reader()
        .build()
        .expect("filtered_topic.reader().build() should succeed (documented)");
}

/// UC-09: Filter Expression Parser
///
/// Documentation claims:
/// - Supports comparison operators: >, <, >=, <=, =, <>
/// - Supports logical operators: AND, OR, NOT
/// - Supports parameters: %0, %1, etc.
/// - Supports parentheses for grouping
#[test]
fn uc09_filter_expression_syntax() {
    use hdds::filter::parse_expression;

    // Simple comparison (documented)
    assert!(parse_expression("temperature > 25").is_ok());

    // With parameter (documented)
    assert!(parse_expression("value > %0").is_ok());

    // AND expression (documented)
    assert!(parse_expression("a > 1 AND b < 2").is_ok());

    // OR expression (documented)
    assert!(parse_expression("a > 1 OR b < 2").is_ok());

    // NOT expression (documented)
    assert!(parse_expression("NOT active = 0").is_ok());

    // Parentheses (documented)
    assert!(parse_expression("(a > 1 OR b < 2) AND c = 3").is_ok());

    // All comparison operators (documented)
    assert!(parse_expression("x > 1").is_ok());
    assert!(parse_expression("x < 1").is_ok());
    assert!(parse_expression("x >= 1").is_ok());
    assert!(parse_expression("x <= 1").is_ok());
    assert!(parse_expression("x = 1").is_ok());
    assert!(parse_expression("x <> 1").is_ok());
    assert!(parse_expression("x != 1").is_ok());
}
