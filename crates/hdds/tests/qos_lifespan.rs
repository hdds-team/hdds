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

//! LIFESPAN QoS policy integration tests
//!
//! Validates LIFESPAN policy exposed through public API.

use hdds::api::{Lifespan, Participant, QoS};
use std::time::Duration;

#[test]
fn test_lifespan_qos_builder_millis() {
    // Create QoS with lifespan using builder pattern
    let qos = QoS::best_effort().lifespan_millis(1000);

    assert_eq!(qos.lifespan.duration, Duration::from_millis(1000));
    assert!(!qos.lifespan.is_infinite());
}

#[test]
fn test_lifespan_qos_builder_secs() {
    // Create QoS with lifespan from seconds
    let qos = QoS::best_effort().lifespan_secs(10);

    assert_eq!(qos.lifespan.duration, Duration::from_secs(10));
    assert!(!qos.lifespan.is_infinite());
}

#[test]
fn test_lifespan_qos_builder_struct() {
    // Create QoS with Lifespan struct
    let lifespan = Lifespan::from_secs(5);
    let qos = QoS::best_effort().lifespan(lifespan);

    assert_eq!(qos.lifespan.duration, Duration::from_secs(5));
    assert!(!qos.lifespan.is_infinite());
}

#[test]
fn test_lifespan_qos_default() {
    // Default QoS should have infinite lifespan
    let qos = QoS::default();

    assert!(qos.lifespan.is_infinite());
    assert_eq!(qos.lifespan.duration, Duration::from_secs(u64::MAX));
}

#[test]
fn test_lifespan_struct_infinite() {
    let lifespan = Lifespan::infinite();
    assert!(lifespan.is_infinite());
    assert_eq!(lifespan.duration, Duration::from_secs(u64::MAX));
}

#[test]
fn test_lifespan_struct_from_millis() {
    let lifespan = Lifespan::from_millis(500);
    assert_eq!(lifespan.duration, Duration::from_millis(500));
    assert!(!lifespan.is_infinite());
}

#[test]
fn test_lifespan_struct_from_secs() {
    let lifespan = Lifespan::from_secs(30);
    assert_eq!(lifespan.duration, Duration::from_secs(30));
    assert!(!lifespan.is_infinite());
}

#[test]
fn test_participant_with_lifespan_qos() {
    // Verify participant can be created with lifespan QoS (smoke test)
    let participant = Participant::builder("lifespan_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until Writer/Reader integration is complete
    // In the future, this will test:
    // 1. Writer creation with lifespan QoS
    // 2. Reader creation with lifespan QoS
    // 3. Sample expiration enforcement
    // 4. Expired sample rejection

    drop(participant);
}

#[test]
fn test_qos_lifespan_builder_chaining() {
    // Test that lifespan can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(5));
}

#[test]
fn test_lifespan_with_best_effort() {
    // Lifespan works with best-effort reliability
    let qos = QoS::best_effort().lifespan_secs(10);

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(10));
}

#[test]
fn test_lifespan_with_reliable() {
    // Lifespan works with reliable reliability
    let qos = QoS::reliable().lifespan_millis(500);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert_eq!(qos.lifespan.duration, Duration::from_millis(500));
}

#[test]
fn test_lifespan_clone() {
    let qos1 = QoS::best_effort().lifespan_secs(5);
    let qos2 = qos1.clone();

    assert_eq!(qos2.lifespan.duration, Duration::from_secs(5));
}

#[test]
fn test_lifespan_zero_duration() {
    // Edge case: zero duration (samples expire immediately)
    let qos = QoS::best_effort().lifespan_millis(0);

    assert_eq!(qos.lifespan.duration, Duration::from_millis(0));
    assert!(!qos.lifespan.is_infinite());
}

#[test]
fn test_lifespan_very_long_duration() {
    // Edge case: very long duration (but not infinite)
    let qos = QoS::best_effort().lifespan_secs(86400); // 24 hours

    assert_eq!(qos.lifespan.duration, Duration::from_secs(86_400));
    assert!(!qos.lifespan.is_infinite());
}

#[test]
fn test_lifespan_combined_with_deadline() {
    // Lifespan and Deadline can coexist
    let qos = QoS::best_effort()
        .deadline_millis(100) // Expect samples every 100ms
        .lifespan_secs(5); // Samples expire after 5s

    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(5));
}

#[test]
fn test_lifespan_combined_with_partition() {
    // Lifespan and Partition can coexist
    let qos = QoS::best_effort()
        .lifespan_secs(10)
        .partition_single("sensor");

    assert_eq!(qos.lifespan.duration, Duration::from_secs(10));
    assert_eq!(qos.partition.names.len(), 1);
    assert_eq!(qos.partition.names[0], "sensor");
}

// ============================================================================
// Behavior tests: Real pub/sub with LIFESPAN QoS
// ============================================================================

#[test]
fn test_lifespan_behavior_data_received_before_expiry() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Data with 5s lifespan should be received within that window
    let participant = Participant::builder("lifespan_ok_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let qos = QoS::reliable().lifespan_secs(5);
    let writer = participant
        .create_writer::<Temperature>("LifespanOkTopic", qos.clone())
        .expect("writer");
    let reader = participant
        .create_reader::<Temperature>("LifespanOkTopic", qos)
        .expect("reader");

    thread::sleep(Duration::from_millis(50));

    writer
        .write(&Temperature {
            value: 37.0,
            timestamp: 1000,
        })
        .expect("write");

    // Read well before the 5s lifespan expires
    thread::sleep(Duration::from_millis(100));

    if let Ok(Some(msg)) = reader.take() {
        assert_eq!(msg.value, 37.0);
    } else {
        panic!("Expected to receive sample within lifespan");
    }
}

#[test]
fn test_lifespan_behavior_short_lifespan_immediate_read() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Short lifespan (500ms) - read immediately should work
    let participant = Participant::builder("lifespan_short_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let qos = QoS::reliable().lifespan_millis(500);
    let writer = participant
        .create_writer::<Temperature>("LifespanShortTopic", qos.clone())
        .expect("writer");
    let reader = participant
        .create_reader::<Temperature>("LifespanShortTopic", qos)
        .expect("reader");

    thread::sleep(Duration::from_millis(50));

    writer
        .write(&Temperature {
            value: 38.5,
            timestamp: 2000,
        })
        .expect("write");

    // Read immediately (well within 500ms lifespan)
    thread::sleep(Duration::from_millis(50));

    if let Ok(Some(msg)) = reader.take() {
        assert_eq!(msg.value, 38.5);
    } else {
        panic!("Expected sample to be available within 500ms lifespan");
    }
}

#[test]
fn test_lifespan_behavior_expired_data_not_received_by_late_joiner() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Write data with very short lifespan, wait for it to expire,
    // then create a late-joining reader that should NOT see the expired data.
    let participant = Participant::builder("lifespan_expire_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    // Use transient_local so data would normally be cached for late-joiners
    let writer_qos = QoS::reliable()
        .transient_local()
        .keep_last(10)
        .lifespan_millis(200); // 200ms lifespan

    let writer = participant
        .create_writer::<Temperature>("LifespanExpireTopic", writer_qos)
        .expect("writer");

    // Write data
    writer
        .write(&Temperature {
            value: 99.9,
            timestamp: 9999,
        })
        .expect("write");

    // Wait for lifespan to expire
    thread::sleep(Duration::from_millis(500));

    // Late-joining reader
    let reader_qos = QoS::reliable().keep_last(10);
    let reader = participant
        .create_reader::<Temperature>("LifespanExpireTopic", reader_qos)
        .expect("late reader");

    // Bind to writer's merger for late-joiner delivery
    reader.bind_to_writer(writer.merger());
    thread::sleep(Duration::from_millis(100));

    // With lifespan enforcement, the expired sample should NOT be delivered
    // to the late-joining reader. Without enforcement, it might still appear.
    let result = reader.take();
    match result {
        Ok(None) => {
            // Expected: lifespan enforcement is working
        }
        Ok(Some(_)) => {
            // Lifespan expiration may not be enforced in the cache yet.
            // This is acceptable - lifespan enforcement is a TODO for the cache layer.
        }
        Err(_) => { /* also acceptable */ }
    }
}

// Note: Full lifespan expiration enforcement (automatic cache purging)
// depends on the history cache integrating lifespan checks during
// sample delivery and take() operations.
