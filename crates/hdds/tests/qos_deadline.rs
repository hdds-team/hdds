// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DEADLINE QoS policy integration tests
//!
//! Validates DEADLINE policy exposed through public API.

use hdds::api::{Deadline, Participant, QoS};
use hdds::test_support::domains::unique_domain;
use std::time::Duration;

#[test]
fn test_deadline_qos_builder() {
    // Create QoS with deadline using builder pattern
    let qos = QoS::best_effort().deadline_millis(100);

    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert!(!qos.deadline.is_infinite());
}

#[test]
fn test_deadline_qos_from_secs() {
    let qos = QoS::reliable().deadline_secs(5);

    assert_eq!(qos.deadline.period, Duration::from_secs(5));
}

#[test]
fn test_deadline_qos_infinite_default() {
    // Default QoS should have infinite deadline
    let qos = QoS::default();

    assert!(qos.deadline.is_infinite());
    assert_eq!(qos.deadline.period, Duration::from_secs(u64::MAX));
}

#[test]
fn test_deadline_struct_creation() {
    let deadline = Deadline::from_millis(200);
    assert_eq!(deadline.period, Duration::from_millis(200));

    let deadline_secs = Deadline::from_secs(10);
    assert_eq!(deadline_secs.period, Duration::from_secs(10));

    let infinite = Deadline::infinite();
    assert_eq!(infinite.period, Duration::from_secs(u64::MAX));
    assert!(infinite.is_infinite());
}

#[test]
fn test_participant_with_deadline_qos() {
    // Verify participant can be created with deadline QoS (smoke test)
    // No `.with_transport(...)`: this participant takes the DEFAULT
    // UdpMulticast transport and therefore binds RTPS ports. The domain
    // is leased (declared first, so dropped last) instead of defaulting
    // to 0, which every other test binary also lands on.
    let domain = unique_domain();
    let participant = Participant::builder("deadline_test")
        .domain_id(domain.id())
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until Writer/Reader integration is complete
    // In the future, this will test:
    // 1. Writer creation with deadline QoS
    // 2. Reader creation with deadline QoS
    // 3. Deadline tracking and missed event detection

    drop(participant);
}

#[test]
fn test_qos_deadline_builder_chaining() {
    // Test that deadline can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
}

// ============================================================================
// Behavior tests: Real pub/sub with DEADLINE QoS
// ============================================================================

#[test]
fn test_deadline_behavior_write_and_read_with_deadline_qos() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Create participant with IntraProcess transport
    let participant = Participant::builder("deadline_behavior_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    // Writer and Reader both with 500ms deadline
    let qos = QoS::reliable().deadline_millis(500);
    let writer = participant
        .topic::<Temperature>("DeadlineTopic")
        .expect("topic")
        .writer()
        .qos(qos.clone())
        .build()
        .expect("writer");
    let reader = participant
        .topic::<Temperature>("DeadlineTopic")
        .expect("topic")
        .reader()
        .qos(qos)
        .build()
        .expect("reader");

    // Allow time for intra-process binding
    thread::sleep(Duration::from_millis(50));

    // Publish a sample within deadline
    let sample = Temperature {
        value: 25.0,
        timestamp: 1000,
    };
    writer.write(&sample).expect("write");

    // Wait for delivery
    thread::sleep(Duration::from_millis(100));

    // Reader should receive the sample
    if let Ok(Some(msg)) = reader.take() {
        assert_eq!(msg.value, 25.0);
        assert_eq!(msg.timestamp, 1000);
    } else {
        panic!("Expected to receive a sample within deadline period");
    }
}

#[test]
fn test_deadline_behavior_multiple_samples_within_deadline() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    let participant = Participant::builder("deadline_multi_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    // 200ms deadline - writer must publish at least every 200ms
    let qos = QoS::reliable().deadline_millis(200);
    let writer = participant
        .topic::<Temperature>("DeadlineMultiTopic")
        .expect("topic")
        .writer()
        .qos(qos.clone())
        .build()
        .expect("writer");
    let reader = participant
        .topic::<Temperature>("DeadlineMultiTopic")
        .expect("topic")
        .reader()
        .qos(qos)
        .build()
        .expect("reader");

    thread::sleep(Duration::from_millis(50));

    // Publish 5 samples at 50ms intervals (well within 200ms deadline)
    for i in 0..5 {
        let sample = Temperature {
            value: 20.0 + i as f32,
            timestamp: (i + 1) * 100,
        };
        writer.write(&sample).expect("write");
        thread::sleep(Duration::from_millis(50));
    }

    thread::sleep(Duration::from_millis(100));

    // Drain all samples
    let mut received = Vec::new();
    while let Ok(Some(msg)) = reader.take() {
        received.push(msg);
    }

    assert!(
        received.len() >= 3,
        "Expected at least 3 samples, got {}",
        received.len()
    );
}

// Note: Testing deadline *missed* status requires listener callbacks
// or status condition polling, which depends on the DeadlineTracker
// integration. The above tests verify data flows correctly when
// deadline QoS is configured.
