// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)] // Test/bench code readability over pedantic
#![allow(clippy::cast_precision_loss)] // Stats/metrics need this
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::cast_possible_truncation)] // Test parameters
#![allow(clippy::float_cmp)] // Test assertions with constants
#![allow(clippy::unreadable_literal)] // Large test constants
#![allow(clippy::doc_markdown)] // Test documentation
#![allow(clippy::missing_panics_doc)] // Tests/examples panic on failure
#![allow(clippy::missing_errors_doc)] // Test documentation
#![allow(clippy::items_after_statements)] // Test helpers
#![allow(clippy::module_name_repetitions)] // Test modules
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::wildcard_imports)] // Test utility imports
#![allow(clippy::redundant_closure_for_method_calls)] // Test code clarity
#![allow(clippy::similar_names)] // Test variable naming
#![allow(clippy::shadow_unrelated)] // Test scoping
#![allow(clippy::needless_pass_by_value)] // Test functions
#![allow(clippy::cast_possible_wrap)] // Test conversions
#![allow(clippy::single_match_else)] // Test clarity
#![allow(clippy::needless_continue)] // Test logic
#![allow(clippy::cast_lossless)] // Test simplicity
#![allow(clippy::match_wild_err_arm)] // Test error handling
#![allow(clippy::explicit_iter_loop)] // Test iteration
#![allow(clippy::must_use_candidate)] // Test functions
#![allow(clippy::if_not_else)] // Test conditionals
#![allow(clippy::map_unwrap_or)] // Test options
#![allow(clippy::match_wildcard_for_single_variants)] // Test patterns
#![allow(clippy::ignored_unit_patterns)] // Test closures

//! LIVELINESS QoS policy integration tests
//!
//! Validates LIVELINESS policy exposed through public API.

use hdds::api::{Liveliness, LivelinessKind, Participant, QoS};
use std::time::Duration;

#[test]
fn test_liveliness_qos_builder_automatic() {
    // Create QoS with automatic liveliness using builder pattern
    let qos = QoS::best_effort().liveliness_automatic_secs(5);

    assert_eq!(qos.liveliness.kind, LivelinessKind::Automatic);
    assert_eq!(qos.liveliness.lease_duration, Duration::from_secs(5));
    assert!(!qos.liveliness.is_infinite());
}

#[test]
fn test_liveliness_qos_builder_manual_participant() {
    let qos = QoS::reliable().liveliness_manual_participant_millis(100);

    assert_eq!(qos.liveliness.kind, LivelinessKind::ManualByParticipant);
    assert_eq!(qos.liveliness.lease_duration, Duration::from_millis(100));
}

#[test]
fn test_liveliness_qos_infinite_default() {
    // Default QoS should have infinite liveliness
    let qos = QoS::default();

    assert!(qos.liveliness.is_infinite());
    assert_eq!(qos.liveliness.lease_duration, Duration::from_secs(u64::MAX));
    assert_eq!(qos.liveliness.kind, LivelinessKind::Automatic);
}

#[test]
fn test_liveliness_struct_creation_automatic() {
    let liveliness = Liveliness::automatic_secs(10);
    assert_eq!(liveliness.kind, LivelinessKind::Automatic);
    assert_eq!(liveliness.lease_duration, Duration::from_secs(10));
}

#[test]
fn test_liveliness_struct_creation_manual_participant() {
    let liveliness = Liveliness::manual_participant_millis(200);
    assert_eq!(liveliness.kind, LivelinessKind::ManualByParticipant);
    assert_eq!(liveliness.lease_duration, Duration::from_millis(200));
}

#[test]
fn test_liveliness_struct_creation_manual_topic() {
    let liveliness = Liveliness::manual_topic_secs(15);
    assert_eq!(liveliness.kind, LivelinessKind::ManualByTopic);
    assert_eq!(liveliness.lease_duration, Duration::from_secs(15));
}

#[test]
fn test_liveliness_struct_infinite() {
    let infinite = Liveliness::infinite();
    assert_eq!(infinite.lease_duration, Duration::from_secs(u64::MAX));
    assert!(infinite.is_infinite());
    assert_eq!(infinite.kind, LivelinessKind::Automatic);
}

#[test]
fn test_participant_with_liveliness_qos() {
    // Verify participant can be created with liveliness QoS (smoke test)
    let participant = Participant::builder("liveliness_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until Writer/Reader integration is complete
    // In the future, this will test:
    // 1. Writer creation with liveliness QoS
    // 2. Reader creation with liveliness QoS
    // 3. Liveliness tracking and lost_liveliness event detection

    drop(participant);
}

#[test]
fn test_qos_liveliness_builder_chaining() {
    // Test that liveliness can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .liveliness_automatic_secs(5);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.liveliness.lease_duration, Duration::from_secs(5));
    assert_eq!(qos.liveliness.kind, LivelinessKind::Automatic);
}

#[test]
fn test_liveliness_kind_variants() {
    // Test all liveliness kind variants
    assert_eq!(LivelinessKind::default(), LivelinessKind::Automatic);

    let automatic = LivelinessKind::Automatic;
    let manual_participant = LivelinessKind::ManualByParticipant;
    let manual_topic = LivelinessKind::ManualByTopic;

    assert_ne!(automatic, manual_participant);
    assert_ne!(automatic, manual_topic);
    assert_ne!(manual_participant, manual_topic);
}

#[test]
fn test_liveliness_policy_with_struct() {
    // Test using Liveliness struct with QoS builder
    let liveliness = Liveliness::automatic_millis(500);
    let qos = QoS::best_effort().liveliness(liveliness);

    assert_eq!(qos.liveliness.lease_duration, Duration::from_millis(500));
    assert_eq!(qos.liveliness.kind, LivelinessKind::Automatic);
}

// ============================================================================
// Behavior tests: Real pub/sub with LIVELINESS QoS
// ============================================================================

#[test]
fn test_liveliness_behavior_automatic_data_flow() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Create participant with IntraProcess transport
    let participant = Participant::builder("liveliness_auto_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    // Writer with automatic liveliness (5s lease)
    let writer_qos = QoS::reliable().liveliness_automatic_secs(5);
    let reader_qos = QoS::reliable().liveliness_automatic_secs(5);

    let writer = participant
        .create_writer::<Temperature>("LivelinessAutoTopic", writer_qos)
        .expect("writer");
    let reader = participant
        .create_reader::<Temperature>("LivelinessAutoTopic", reader_qos)
        .expect("reader");

    thread::sleep(Duration::from_millis(50));

    // Writing data implicitly asserts liveliness
    let sample = Temperature {
        value: 36.6,
        timestamp: 1000,
    };
    writer.write(&sample).expect("write");

    thread::sleep(Duration::from_millis(100));

    // Reader should receive data (writer is alive)
    if let Ok(Some(msg)) = reader.take() {
        assert_eq!(msg.value, 36.6);
    } else {
        panic!("Expected to receive sample from live writer");
    }
}

#[test]
fn test_liveliness_behavior_manual_participant_data_flow() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    let participant = Participant::builder("liveliness_manual_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    // Manual-by-participant liveliness
    let writer_qos = QoS::reliable().liveliness_manual_participant_millis(500);
    let reader_qos = QoS::reliable().liveliness_manual_participant_millis(500);

    let writer = participant
        .create_writer::<Temperature>("LivelinessManualTopic", writer_qos)
        .expect("writer");
    let reader = participant
        .create_reader::<Temperature>("LivelinessManualTopic", reader_qos)
        .expect("reader");

    thread::sleep(Duration::from_millis(50));

    // Publish data (also acts as liveliness assertion)
    for i in 0..3 {
        let sample = Temperature {
            value: 20.0 + i as f32,
            timestamp: (i + 1) * 100,
        };
        writer.write(&sample).expect("write");
        thread::sleep(Duration::from_millis(100));
    }

    thread::sleep(Duration::from_millis(100));

    let mut received = Vec::new();
    while let Ok(Some(msg)) = reader.take() {
        received.push(msg);
    }

    assert!(
        !received.is_empty(),
        "Expected to receive samples with manual liveliness"
    );
}

// Note: Testing lost_liveliness detection requires listener callbacks
// or waiting for the lease to expire after dropping the writer.
// Full lost_liveliness behavior tests depend on LivelinessMonitor
// integration with DataReader status conditions.
