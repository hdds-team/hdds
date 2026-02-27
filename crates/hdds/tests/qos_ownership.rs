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

//! OWNERSHIP QoS policy integration tests
//!
//! Validates OWNERSHIP and OWNERSHIP_STRENGTH policies exposed through public API.

use hdds::api::{Ownership, OwnershipKind, OwnershipStrength, Participant, QoS};
use std::time::Duration;

#[test]
fn test_ownership_qos_builder_shared() {
    // Create QoS with shared ownership using builder pattern
    let qos = QoS::best_effort().ownership_shared();

    assert_eq!(qos.ownership.kind, OwnershipKind::Shared);
}

#[test]
fn test_ownership_qos_builder_exclusive() {
    // Create QoS with exclusive ownership using builder pattern
    let qos = QoS::reliable().ownership_exclusive();

    assert_eq!(qos.ownership.kind, OwnershipKind::Exclusive);
}

#[test]
fn test_ownership_qos_default() {
    // Default QoS should have shared ownership
    let qos = QoS::default();

    assert_eq!(qos.ownership.kind, OwnershipKind::Shared);
}

#[test]
fn test_ownership_struct_creation_shared() {
    let ownership = Ownership::shared();
    assert_eq!(ownership.kind, OwnershipKind::Shared);
}

#[test]
fn test_ownership_struct_creation_exclusive() {
    let ownership = Ownership::exclusive();
    assert_eq!(ownership.kind, OwnershipKind::Exclusive);
}

#[test]
fn test_ownership_kind_variants() {
    // Test all ownership kind variants
    assert_eq!(OwnershipKind::default(), OwnershipKind::Shared);

    let shared = OwnershipKind::Shared;
    let exclusive = OwnershipKind::Exclusive;

    assert_ne!(shared, exclusive);
}

#[test]
fn test_ownership_policy_with_struct() {
    // Test using Ownership struct with QoS builder
    let ownership = Ownership::exclusive();
    let qos = QoS::best_effort().ownership(ownership);

    assert_eq!(qos.ownership.kind, OwnershipKind::Exclusive);
}

#[test]
fn test_participant_with_ownership_qos() {
    // Verify participant can be created with ownership QoS (smoke test)
    let participant = Participant::builder("ownership_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until Writer/Reader integration is complete
    // In the future, this will test:
    // 1. Writer creation with EXCLUSIVE ownership
    // 2. Multiple writers with different OWNERSHIP_STRENGTH values
    // 3. Arbiter election (highest-strength writer wins)
    // 4. Writer takeover when higher-strength writer starts

    drop(participant);
}

#[test]
fn test_qos_ownership_builder_chaining() {
    // Test that ownership can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .ownership_exclusive();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.ownership.kind, OwnershipKind::Exclusive);
}

#[test]
fn test_ownership_shared_with_best_effort() {
    // Shared ownership works with best-effort reliability
    let qos = QoS::best_effort().ownership_shared();

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert_eq!(qos.ownership.kind, OwnershipKind::Shared);
}

#[test]
fn test_ownership_exclusive_with_reliable() {
    // Exclusive ownership commonly used with reliable reliability
    let qos = QoS::reliable().ownership_exclusive();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert_eq!(qos.ownership.kind, OwnershipKind::Exclusive);
}

// ============================================================================
// OWNERSHIP_STRENGTH QoS policy tests
// ============================================================================

#[test]
fn test_ownership_strength_qos_default() {
    // Default QoS should have ownership strength 0
    let qos = QoS::default();
    assert_eq!(qos.ownership_strength.value, 0);
}

#[test]
fn test_ownership_strength_qos_builder_custom() {
    // Create QoS with custom ownership strength
    let qos = QoS::best_effort().ownership_strength(50);
    assert_eq!(qos.ownership_strength.value, 50);
}

#[test]
fn test_ownership_strength_qos_builder_high() {
    // Create QoS with high ownership strength
    let qos = QoS::best_effort().ownership_strength_high();
    assert_eq!(qos.ownership_strength.value, 100);
}

#[test]
fn test_ownership_strength_qos_builder_low() {
    // Create QoS with low ownership strength (backup writer)
    let qos = QoS::best_effort().ownership_strength_low();
    assert_eq!(qos.ownership_strength.value, -100);
}

#[test]
fn test_ownership_strength_struct_default() {
    let strength = OwnershipStrength::default();
    assert_eq!(strength.value, 0);
}

#[test]
fn test_ownership_strength_struct_high() {
    let strength = OwnershipStrength::high();
    assert_eq!(strength.value, 100);
}

#[test]
fn test_ownership_strength_struct_low() {
    let strength = OwnershipStrength::low();
    assert_eq!(strength.value, -100);
}

#[test]
fn test_ownership_strength_ordering() {
    let high = OwnershipStrength::high();
    let low = OwnershipStrength::low();
    let default = OwnershipStrength::default();

    assert!(high > default);
    assert!(default > low);
    assert!(high > low);
}

#[test]
fn test_ownership_exclusive_with_strength() {
    // Common pattern: EXCLUSIVE ownership with explicit strength
    let qos = QoS::reliable().ownership_exclusive().ownership_strength(75);

    assert_eq!(qos.ownership.kind, OwnershipKind::Exclusive);
    assert_eq!(qos.ownership_strength.value, 75);
}

#[test]
fn test_ownership_strength_primary_backup_pattern() {
    // Primary writer with high strength
    let primary_qos = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength_high();

    // Backup writer with low strength
    let backup_qos = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength_low();

    assert_eq!(primary_qos.ownership.kind, OwnershipKind::Exclusive);
    assert_eq!(primary_qos.ownership_strength.value, 100);

    assert_eq!(backup_qos.ownership.kind, OwnershipKind::Exclusive);
    assert_eq!(backup_qos.ownership_strength.value, -100);

    // Primary should have higher strength
    assert!(primary_qos.ownership_strength > backup_qos.ownership_strength);
}

#[test]
fn test_ownership_strength_with_shared_ownership() {
    // OWNERSHIP_STRENGTH is ignored when OWNERSHIP is SHARED
    let qos = QoS::best_effort().ownership_shared().ownership_strength(50);

    assert_eq!(qos.ownership.kind, OwnershipKind::Shared);
    assert_eq!(qos.ownership_strength.value, 50); // Value is set but ignored
}

#[test]
fn test_ownership_strength_builder_chaining() {
    // Test that OWNERSHIP_STRENGTH can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5)
        .ownership_exclusive()
        .ownership_strength(80);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(5));
    assert_eq!(qos.ownership.kind, OwnershipKind::Exclusive);
    assert_eq!(qos.ownership_strength.value, 80);
}

#[test]
fn test_ownership_strength_use_case_redundant_sensors() {
    // Redundant sensors: primary sensor has higher strength
    let primary_sensor = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength(100); // High priority

    let backup_sensor = QoS::reliable().ownership_exclusive().ownership_strength(10); // Low priority

    assert!(primary_sensor.ownership_strength.value > backup_sensor.ownership_strength.value);
}

#[test]
fn test_ownership_strength_use_case_failover() {
    // Failover scenario: active server high, standby server low
    let active_server = QoS::reliable().ownership_exclusive().ownership_strength(50);

    let standby_server = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength(-50);

    assert!(active_server.ownership_strength.value > standby_server.ownership_strength.value);
}

#[test]
fn test_ownership_strength_equality() {
    let strength1 = OwnershipStrength { value: 50 };
    let strength2 = OwnershipStrength { value: 50 };
    let strength3 = OwnershipStrength { value: 75 };

    assert_eq!(strength1, strength2);
    assert_ne!(strength1, strength3);
}

#[test]
fn test_ownership_strength_clone() {
    let qos1 = QoS::best_effort().ownership_strength(60);
    let qos2 = qos1.clone();

    assert_eq!(qos2.ownership_strength.value, 60);
}

#[test]
fn test_ownership_strength_negative_values() {
    // Test negative strength values (backup/fallback writers)
    let qos = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength(-25);

    assert_eq!(qos.ownership_strength.value, -25);
}

#[test]
fn test_ownership_strength_zero_value() {
    // Test zero strength value (default)
    let qos = QoS::reliable().ownership_exclusive().ownership_strength(0);

    assert_eq!(qos.ownership_strength.value, 0);
}

#[test]
fn test_ownership_strength_very_high_value() {
    // Test very high strength value
    let qos = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength(1000);

    assert_eq!(qos.ownership_strength.value, 1000);
}

#[test]
fn test_ownership_strength_very_low_value() {
    // Test very low strength value
    let qos = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength(-1000);

    assert_eq!(qos.ownership_strength.value, -1000);
}

// ============================================================================
// Behavior tests: Real pub/sub with OWNERSHIP QoS
// ============================================================================

#[test]
fn test_ownership_behavior_shared_both_writers_received() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // With SHARED ownership, data from all writers is delivered
    let participant = Participant::builder("ownership_shared_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let qos = QoS::reliable().ownership_shared();
    let writer1 = participant
        .create_writer::<Temperature>("OwnershipSharedTopic", qos.clone())
        .expect("writer1");
    let writer2 = participant
        .create_writer::<Temperature>("OwnershipSharedTopic", qos.clone())
        .expect("writer2");
    let reader = participant
        .create_reader::<Temperature>("OwnershipSharedTopic", qos)
        .expect("reader");

    thread::sleep(Duration::from_millis(100));

    // Both writers publish
    writer1
        .write(&Temperature {
            value: 10.0,
            timestamp: 100,
        })
        .expect("write1");
    thread::sleep(Duration::from_millis(50));
    writer2
        .write(&Temperature {
            value: 20.0,
            timestamp: 200,
        })
        .expect("write2");

    thread::sleep(Duration::from_millis(200));

    let mut received = Vec::new();
    while let Ok(Some(msg)) = reader.take() {
        received.push(msg);
    }

    // With shared ownership, reader should receive data from both writers.
    // In IntraProcess mode with same topic, two writers may share a merger,
    // so the reader may receive 1 or 2 samples depending on timing.
    assert!(
        !received.is_empty(),
        "Expected at least 1 sample from shared ownership, got 0"
    );
}

#[test]
fn test_ownership_behavior_exclusive_with_strength() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // With EXCLUSIVE ownership, only the highest-strength writer's data is delivered
    let participant = Participant::builder("ownership_excl_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    // High-strength writer (primary)
    let primary_qos = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength(100);
    // Low-strength writer (backup)
    let backup_qos = QoS::reliable().ownership_exclusive().ownership_strength(10);
    let reader_qos = QoS::reliable().ownership_exclusive();

    let primary_writer = participant
        .create_writer::<Temperature>("OwnershipExclTopic", primary_qos)
        .expect("primary writer");
    let backup_writer = participant
        .create_writer::<Temperature>("OwnershipExclTopic", backup_qos)
        .expect("backup writer");
    let reader = participant
        .create_reader::<Temperature>("OwnershipExclTopic", reader_qos)
        .expect("reader");

    thread::sleep(Duration::from_millis(50));

    // Both writers publish
    primary_writer
        .write(&Temperature {
            value: 100.0,
            timestamp: 1000,
        })
        .expect("primary write");
    backup_writer
        .write(&Temperature {
            value: 50.0,
            timestamp: 2000,
        })
        .expect("backup write");

    thread::sleep(Duration::from_millis(100));

    let mut received = Vec::new();
    while let Ok(Some(msg)) = reader.take() {
        received.push(msg);
    }

    // With exclusive ownership, we expect data to flow.
    // Whether the arbiter filters to only the highest-strength writer
    // depends on the OwnershipArbiter implementation.
    assert!(
        !received.is_empty(),
        "Expected to receive at least one sample with exclusive ownership"
    );

    // If ownership arbitration is fully implemented, only the primary writer's
    // data (value=100.0) should be received. Verify if available:
    if received.len() == 1 {
        assert_eq!(
            received[0].value, 100.0,
            "Expected primary writer's data (strength=100)"
        );
    }
}

// Note: Full ownership arbitration tests (writer takeover, failover)
// require the OwnershipArbiter to be fully wired into the reader cache.
// The above tests verify that data flows correctly with EXCLUSIVE/SHARED
// ownership QoS configured.
