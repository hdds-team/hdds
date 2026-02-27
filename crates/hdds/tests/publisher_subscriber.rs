// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Publisher/Subscriber integration tests
//!
//! Validates Publisher and Subscriber entities per DDS v1.4 specification.

use hdds::api::{Participant, QoS, TransportMode};

#[test]
fn test_create_publisher_default_qos() {
    let participant = Participant::builder("test_pub")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let publisher = participant
        .create_publisher(QoS::default())
        .expect("Failed to create publisher");

    assert!(publisher.qos().partition.is_default());
}

#[test]
fn test_create_subscriber_default_qos() {
    let participant = Participant::builder("test_sub")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let subscriber = participant
        .create_subscriber(QoS::default())
        .expect("Failed to create subscriber");

    assert!(subscriber.qos().partition.is_default());
}

#[test]
fn test_create_publisher_with_partition() {
    let participant = Participant::builder("test_pub_partition")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let qos = QoS::default().partition_single("production");
    let publisher = participant
        .create_publisher(qos)
        .expect("Failed to create publisher");

    assert!(!publisher.qos().partition.is_default());
    assert_eq!(publisher.qos().partition.names.len(), 1);
    assert_eq!(publisher.qos().partition.names[0], "production");
}

#[test]
fn test_create_subscriber_with_partition() {
    let participant = Participant::builder("test_sub_partition")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let qos = QoS::default().partition_single("production");
    let subscriber = participant
        .create_subscriber(qos)
        .expect("Failed to create subscriber");

    assert!(!subscriber.qos().partition.is_default());
    assert_eq!(subscriber.qos().partition.names.len(), 1);
    assert_eq!(subscriber.qos().partition.names[0], "production");
}

#[test]
fn test_publisher_create_writer() {
    use hdds::generated::temperature::Temperature;

    let participant = Participant::builder("test_pub_writer")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let publisher = participant
        .create_publisher(QoS::default())
        .expect("Failed to create publisher");

    let _writer = publisher
        .create_writer::<Temperature>("temperature", QoS::best_effort())
        .expect("Failed to create writer through publisher");
}

#[test]
fn test_subscriber_create_reader() {
    use hdds::generated::temperature::Temperature;

    let participant = Participant::builder("test_sub_reader")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let subscriber = participant
        .create_subscriber(QoS::default())
        .expect("Failed to create subscriber");

    let _reader = subscriber
        .create_reader::<Temperature>("temperature", QoS::best_effort())
        .expect("Failed to create reader through subscriber");
}

#[test]
fn test_publisher_partition_inheritance() {
    use hdds::generated::temperature::Temperature;

    let participant = Participant::builder("test_partition_inherit_pub")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    // Publisher with partition
    let pub_qos = QoS::default().partition_single("sensors");
    let publisher = participant
        .create_publisher(pub_qos)
        .expect("Failed to create publisher");

    // Writer with default QoS should inherit partition from publisher
    let writer = publisher
        .create_writer::<Temperature>("temperature", QoS::best_effort())
        .expect("Failed to create writer");

    // Writer should have inherited the partition
    assert!(!writer.qos().partition.is_default());
    assert_eq!(writer.qos().partition.names.len(), 1);
    assert_eq!(writer.qos().partition.names[0], "sensors");
}

#[test]
fn test_subscriber_partition_inheritance() {
    use hdds::generated::temperature::Temperature;

    let participant = Participant::builder("test_partition_inherit_sub")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    // Subscriber with partition
    let sub_qos = QoS::default().partition_single("sensors");
    let subscriber = participant
        .create_subscriber(sub_qos)
        .expect("Failed to create subscriber");

    // Reader with default QoS should inherit partition from subscriber
    let reader = subscriber
        .create_reader::<Temperature>("temperature", QoS::best_effort())
        .expect("Failed to create reader");

    // Reader should have inherited the partition
    assert!(!reader.qos().partition.is_default());
    assert_eq!(reader.qos().partition.names.len(), 1);
    assert_eq!(reader.qos().partition.names[0], "sensors");
}

#[test]
fn test_writer_explicit_partition_overrides_publisher() {
    use hdds::generated::temperature::Temperature;

    let participant = Participant::builder("test_partition_override_pub")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    // Publisher with partition
    let pub_qos = QoS::default().partition_single("sensors");
    let publisher = participant
        .create_publisher(pub_qos)
        .expect("Failed to create publisher");

    // Writer with explicit partition should override publisher's partition
    let writer_qos = QoS::best_effort().partition_single("actuators");
    let writer = publisher
        .create_writer::<Temperature>("temperature", writer_qos)
        .expect("Failed to create writer");

    // Writer should have its own partition, not the publisher's
    assert_eq!(writer.qos().partition.names.len(), 1);
    assert_eq!(writer.qos().partition.names[0], "actuators");
}

#[test]
fn test_reader_explicit_partition_overrides_subscriber() {
    use hdds::generated::temperature::Temperature;

    let participant = Participant::builder("test_partition_override_sub")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    // Subscriber with partition
    let sub_qos = QoS::default().partition_single("sensors");
    let subscriber = participant
        .create_subscriber(sub_qos)
        .expect("Failed to create subscriber");

    // Reader with explicit partition should override subscriber's partition
    let reader_qos = QoS::best_effort().partition_single("actuators");
    let reader = subscriber
        .create_reader::<Temperature>("temperature", reader_qos)
        .expect("Failed to create reader");

    // Reader should have its own partition, not the subscriber's
    assert_eq!(reader.qos().partition.names.len(), 1);
    assert_eq!(reader.qos().partition.names[0], "actuators");
}

#[test]
fn test_multiple_publishers_per_participant() {
    let participant = Participant::builder("test_multi_pub")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let _publisher1 = participant
        .create_publisher(QoS::default().partition_single("partition1"))
        .expect("Failed to create publisher 1");

    let _publisher2 = participant
        .create_publisher(QoS::default().partition_single("partition2"))
        .expect("Failed to create publisher 2");

    // Should be able to create multiple publishers
}

#[test]
fn test_multiple_subscribers_per_participant() {
    let participant = Participant::builder("test_multi_sub")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let _subscriber1 = participant
        .create_subscriber(QoS::default().partition_single("partition1"))
        .expect("Failed to create subscriber 1");

    let _subscriber2 = participant
        .create_subscriber(QoS::default().partition_single("partition2"))
        .expect("Failed to create subscriber 2");

    // Should be able to create multiple subscribers
}
