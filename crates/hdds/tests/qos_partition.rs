// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PARTITION QoS policy integration tests
//!
//! Validates PARTITION policy exposed through public API.

use hdds::api::{Participant, Partition, QoS};
use hdds::test_support::domains::unique_domain;
use std::time::Duration;

#[test]
fn test_partition_qos_builder_single() {
    // Create QoS with single partition using builder pattern
    let qos = QoS::best_effort().partition_single("sensor");

    assert_eq!(qos.partition.names.len(), 1);
    assert_eq!(qos.partition.names[0], "sensor");
}

#[test]
fn test_partition_qos_builder_multiple() {
    // Create QoS with multiple partitions
    let qos = QoS::best_effort().partition(Partition::new(vec![
        "sensor".to_string(),
        "actuator".to_string(),
    ]));

    assert_eq!(qos.partition.names.len(), 2);
    assert!(qos.partition.names.contains(&"sensor".to_string()));
    assert!(qos.partition.names.contains(&"actuator".to_string()));
}

#[test]
fn test_partition_qos_default() {
    // Default QoS should have default (empty) partition
    let qos = QoS::default();

    assert!(qos.partition.names.is_empty());
}

#[test]
fn test_partition_struct_creation_default() {
    let partition = Partition::default_partition();
    assert!(partition.names.is_empty());
}

#[test]
fn test_partition_struct_creation_single() {
    let partition = Partition::single("sensor");
    assert_eq!(partition.names.len(), 1);
    assert_eq!(partition.names[0], "sensor");
}

#[test]
fn test_partition_struct_creation_new() {
    let partition = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);
    assert_eq!(partition.names.len(), 2);
}

#[test]
fn test_partition_add() {
    let mut partition = Partition::default();
    partition.add("sensor");
    partition.add("actuator");
    assert_eq!(partition.names.len(), 2);
}

#[test]
fn test_participant_with_partition_qos() {
    // Verify participant can be created with partition QoS (smoke test)
    // No `.with_transport(...)`: this participant takes the DEFAULT
    // UdpMulticast transport and therefore binds RTPS ports. The domain
    // is leased (declared first, so dropped last) instead of defaulting
    // to 0, which every other test binary also lands on.
    let domain = unique_domain();
    let participant = Participant::builder("partition_test")
        .domain_id(domain.id())
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until Writer/Reader integration is complete
    // In the future, this will test:
    // 1. Writer creation with partition QoS
    // 2. Reader creation with partition QoS
    // 3. Cross-partition isolation
    // 4. Partition matching

    drop(participant);
}

#[test]
fn test_qos_partition_builder_chaining() {
    // Test that partition can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .partition_single("sensor");

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.partition.names.len(), 1);
    assert_eq!(qos.partition.names[0], "sensor");
}

#[test]
fn test_partition_with_best_effort() {
    // Partition works with best-effort reliability
    let qos = QoS::best_effort().partition_single("actuator");

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert_eq!(qos.partition.names[0], "actuator");
}

#[test]
fn test_partition_with_reliable() {
    // Partition works with reliable reliability
    let qos = QoS::reliable().partition_single("sensor");

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert_eq!(qos.partition.names[0], "sensor");
}

#[test]
fn test_partition_add_multiple() {
    // Test add_partition builder method
    let qos = QoS::best_effort()
        .add_partition("sensor")
        .add_partition("actuator")
        .add_partition("camera");

    assert_eq!(qos.partition.names.len(), 3);
    assert!(qos.partition.names.contains(&"sensor".to_string()));
    assert!(qos.partition.names.contains(&"actuator".to_string()));
    assert!(qos.partition.names.contains(&"camera".to_string()));
}

#[test]
fn test_partition_clone() {
    let qos1 = QoS::best_effort().partition_single("sensor");
    let qos2 = qos1.clone();

    assert_eq!(qos2.partition.names.len(), 1);
    assert_eq!(qos2.partition.names[0], "sensor");
}

// ============================================================================
// Behavior tests: Real pub/sub with PARTITION QoS
// ============================================================================

#[test]
fn test_partition_behavior_same_partition_receives_data() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Writer and reader in the same partition should communicate
    let participant = Participant::builder("partition_same_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let writer_qos = QoS::reliable().partition_single("sensors");
    let reader_qos = QoS::reliable().partition_single("sensors");

    let writer = participant
        .topic::<Temperature>("PartitionTestTopic")
        .expect("topic")
        .writer()
        .qos(writer_qos)
        .build()
        .expect("writer");
    let reader = participant
        .topic::<Temperature>("PartitionTestTopic")
        .expect("topic")
        .reader()
        .qos(reader_qos)
        .build()
        .expect("reader");

    thread::sleep(Duration::from_millis(50));

    writer
        .write(&Temperature {
            value: 42.0,
            timestamp: 1000,
        })
        .expect("write");

    thread::sleep(Duration::from_millis(100));

    if let Ok(Some(msg)) = reader.take() {
        assert_eq!(msg.value, 42.0);
    } else {
        panic!("Expected reader in same partition to receive data");
    }
}

#[test]
fn test_partition_behavior_different_partition_no_data() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Writer in partition "A", reader in partition "B" - no communication
    let participant = Participant::builder("partition_diff_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let writer_qos = QoS::reliable().partition_single("A");
    let reader_qos = QoS::reliable().partition_single("B");

    let writer = participant
        .topic::<Temperature>("PartitionIsoTopic")
        .expect("topic")
        .writer()
        .qos(writer_qos)
        .build()
        .expect("writer");
    let reader_b = participant
        .topic::<Temperature>("PartitionIsoTopic")
        .expect("topic")
        .reader()
        .qos(reader_qos)
        .build()
        .expect("reader_b");

    thread::sleep(Duration::from_millis(50));

    writer
        .write(&Temperature {
            value: 99.0,
            timestamp: 2000,
        })
        .expect("write");

    thread::sleep(Duration::from_millis(200));

    // Reader in partition "B" should NOT receive data from writer in partition "A"
    assert_eq!(writer.merger().reader_count(), 0);
    assert!(
        reader_b.take().expect("partition B take").is_none(),
        "reader in partition B received data from partition A"
    );
}

#[test]
fn test_partition_behavior_writer_and_two_readers() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Writer in partition "A", reader_a in "A" (receives), reader_b in "B" (may not)
    let participant = Participant::builder("partition_two_readers_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let writer_qos = QoS::reliable().partition_single("A");
    let reader_a_qos = QoS::reliable().partition_single("A");
    let reader_b_qos = QoS::reliable().partition_single("B");

    let writer = participant
        .topic::<Temperature>("PartitionTwoReadersTopic")
        .expect("topic")
        .writer()
        .qos(writer_qos)
        .build()
        .expect("writer");
    let reader_a = participant
        .topic::<Temperature>("PartitionTwoReadersTopic")
        .expect("topic")
        .reader()
        .qos(reader_a_qos)
        .build()
        .expect("reader_a");
    let reader_b = participant
        .topic::<Temperature>("PartitionTwoReadersTopic")
        .expect("topic")
        .reader()
        .qos(reader_b_qos)
        .build()
        .expect("reader_b");

    assert_eq!(writer.merger().reader_count(), 1);

    thread::sleep(Duration::from_millis(50));

    writer
        .write(&Temperature {
            value: 55.0,
            timestamp: 3000,
        })
        .expect("write");

    thread::sleep(Duration::from_millis(100));

    // Reader A (same partition as writer) should receive data
    if let Ok(Some(msg)) = reader_a.take() {
        assert_eq!(msg.value, 55.0);
    } else {
        panic!("Reader in partition A should receive data from writer in partition A");
    }

    assert!(
        reader_b.take().expect("partition B take").is_none(),
        "reader in partition B received data from partition A"
    );
}
