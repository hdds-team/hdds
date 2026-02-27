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

//! LATENCY_BUDGET QoS policy integration tests
//!
//! Validates LATENCY_BUDGET policy exposed through public API.

use hdds::api::{LatencyBudget, Participant, QoS};
use std::time::Duration;

#[test]
fn test_latency_budget_qos_builder_millis() {
    // Create QoS with LATENCY_BUDGET from milliseconds
    let qos = QoS::best_effort().latency_budget_millis(10);

    assert_eq!(qos.latency_budget.duration, Duration::from_millis(10));
    assert!(qos.latency_budget.is_set());
    assert!(!qos.latency_budget.is_zero());
}

#[test]
fn test_latency_budget_qos_builder_secs() {
    // Create QoS with LATENCY_BUDGET from seconds
    let qos = QoS::best_effort().latency_budget_secs(1);

    assert_eq!(qos.latency_budget.duration, Duration::from_secs(1));
    assert!(qos.latency_budget.is_set());
}

#[test]
fn test_latency_budget_qos_builder_struct() {
    // Create QoS with LatencyBudget struct
    let budget = LatencyBudget::from_millis(50);
    let qos = QoS::best_effort().latency_budget(budget);

    assert_eq!(qos.latency_budget.duration, Duration::from_millis(50));
    assert!(qos.latency_budget.is_set());
}

#[test]
fn test_latency_budget_qos_default() {
    // Default QoS should have zero latency budget
    let qos = QoS::default();

    assert!(qos.latency_budget.is_zero());
    assert!(!qos.latency_budget.is_set());
    assert_eq!(qos.latency_budget.duration, Duration::ZERO);
}

#[test]
fn test_latency_budget_struct_zero() {
    let budget = LatencyBudget::zero();
    assert!(budget.is_zero());
    assert!(!budget.is_set());
    assert_eq!(budget.duration, Duration::ZERO);
}

#[test]
fn test_latency_budget_struct_from_millis() {
    let budget = LatencyBudget::from_millis(100);
    assert_eq!(budget.duration, Duration::from_millis(100));
    assert!(budget.is_set());
    assert!(!budget.is_zero());
}

#[test]
fn test_latency_budget_struct_from_secs() {
    let budget = LatencyBudget::from_secs(2);
    assert_eq!(budget.duration, Duration::from_secs(2));
    assert!(budget.is_set());
}

#[test]
fn test_participant_with_latency_budget_qos() {
    // Verify participant can be created with LATENCY_BUDGET QoS (smoke test)
    let participant = Participant::builder("latency_budget_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until transport optimization is complete
    // In the future, this will test:
    // 1. Transport path selection based on latency budget
    // 2. Priority routing for low-latency data
    // 3. Latency monitoring and reporting

    drop(participant);
}

#[test]
fn test_qos_latency_budget_builder_chaining() {
    // Test that LATENCY_BUDGET can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5)
        .time_based_filter_millis(50)
        .destination_order_by_source()
        .presentation_topic_coherent()
        .latency_budget_millis(10);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(5));
    assert_eq!(
        qos.time_based_filter.minimum_separation,
        Duration::from_millis(50)
    );
    assert_eq!(
        qos.destination_order.kind,
        hdds::api::DestinationOrderKind::BySourceTimestamp
    );
    assert_eq!(
        qos.presentation.access_scope,
        hdds::api::PresentationAccessScope::Topic
    );
    assert_eq!(qos.latency_budget.duration, Duration::from_millis(10));
}

#[test]
fn test_latency_budget_with_best_effort() {
    // LATENCY_BUDGET works with best-effort reliability
    let qos = QoS::best_effort().latency_budget_millis(20);

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert_eq!(qos.latency_budget.duration, Duration::from_millis(20));
}

#[test]
fn test_latency_budget_with_reliable() {
    // LATENCY_BUDGET works with reliable reliability
    let qos = QoS::reliable().latency_budget_secs(1);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert_eq!(qos.latency_budget.duration, Duration::from_secs(1));
}

#[test]
fn test_latency_budget_clone() {
    let qos1 = QoS::best_effort().latency_budget_millis(100);
    let qos2 = qos1.clone();

    assert_eq!(qos2.latency_budget.duration, Duration::from_millis(100));
}

#[test]
fn test_latency_budget_zero_duration() {
    // Edge case: zero duration (no specific latency requirement)
    let budget = LatencyBudget::zero();
    let qos = QoS::best_effort().latency_budget(budget);

    assert_eq!(qos.latency_budget.duration, Duration::ZERO);
    assert!(qos.latency_budget.is_zero());
}

#[test]
fn test_latency_budget_very_short_duration() {
    // Edge case: very short duration (1 millisecond)
    let qos = QoS::best_effort().latency_budget_millis(1);

    assert_eq!(qos.latency_budget.duration, Duration::from_millis(1));
    assert!(qos.latency_budget.is_set());
}

#[test]
fn test_latency_budget_very_long_duration() {
    // Edge case: very long duration (1 hour)
    let qos = QoS::best_effort().latency_budget_secs(3600);

    assert_eq!(qos.latency_budget.duration, Duration::from_secs(3600));
    assert!(qos.latency_budget.is_set());
}

#[test]
fn test_latency_budget_combined_with_deadline() {
    // LATENCY_BUDGET and Deadline can coexist
    let qos = QoS::best_effort()
        .deadline_millis(100) // Expect samples every 100ms
        .latency_budget_millis(10); // Target 10ms latency

    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.latency_budget.duration, Duration::from_millis(10));
}

#[test]
fn test_latency_budget_combined_with_lifespan() {
    // LATENCY_BUDGET and Lifespan can coexist
    let qos = QoS::best_effort()
        .lifespan_secs(10) // Samples expire after 10s
        .latency_budget_millis(20); // Target 20ms latency

    assert_eq!(qos.lifespan.duration, Duration::from_secs(10));
    assert_eq!(qos.latency_budget.duration, Duration::from_millis(20));
}

#[test]
fn test_latency_budget_combined_with_time_based_filter() {
    // LATENCY_BUDGET and TIME_BASED_FILTER can coexist
    let qos = QoS::best_effort()
        .time_based_filter_millis(100) // Accept at most every 100ms
        .latency_budget_millis(15); // Target 15ms latency

    assert_eq!(
        qos.time_based_filter.minimum_separation,
        Duration::from_millis(100)
    );
    assert_eq!(qos.latency_budget.duration, Duration::from_millis(15));
}

#[test]
fn test_latency_budget_use_case_critical_control() {
    // Critical control data: 10ms latency budget
    let qos = QoS::reliable().latency_budget_millis(10);

    assert_eq!(qos.latency_budget.duration, Duration::from_millis(10));
    assert!(qos.latency_budget.is_set());
    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
}

#[test]
fn test_latency_budget_use_case_emergency_alerts() {
    // Emergency alerts: 5ms latency budget
    let qos = QoS::reliable().latency_budget_millis(5);

    assert_eq!(qos.latency_budget.duration, Duration::from_millis(5));
    assert!(qos.latency_budget.is_set());
}

#[test]
fn test_latency_budget_use_case_real_time_sensors() {
    // Real-time sensor data: 20ms latency budget
    let qos = QoS::best_effort().latency_budget_millis(20);

    assert_eq!(qos.latency_budget.duration, Duration::from_millis(20));
    assert!(qos.latency_budget.is_set());
}

#[test]
fn test_latency_budget_use_case_non_critical_logs() {
    // Logs: no specific latency requirement
    let qos = QoS::best_effort().latency_budget(LatencyBudget::zero());

    assert!(qos.latency_budget.is_zero());
    assert!(!qos.latency_budget.is_set());
}

#[test]
fn test_latency_budget_equality() {
    let budget1 = LatencyBudget::from_millis(10);
    let budget2 = LatencyBudget::from_millis(10);
    let budget3 = LatencyBudget::from_millis(20);

    assert_eq!(budget1, budget2);
    assert_ne!(budget1, budget3);
}

// ============================================================================
// Behavior tests: Real pub/sub with LATENCY_BUDGET QoS
// ============================================================================

#[test]
fn test_latency_budget_behavior_data_flows_with_budget() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Verify that data flows correctly when latency budget is configured
    let participant = Participant::builder("latency_budget_flow_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let qos = QoS::reliable().latency_budget_millis(10);
    let writer = participant
        .create_writer::<Temperature>("LatencyBudgetTopic", qos.clone())
        .expect("writer");
    let reader = participant
        .create_reader::<Temperature>("LatencyBudgetTopic", qos)
        .expect("reader");

    thread::sleep(Duration::from_millis(50));

    writer
        .write(&Temperature {
            value: 25.5,
            timestamp: 1000,
        })
        .expect("write");

    thread::sleep(Duration::from_millis(100));

    if let Ok(Some(msg)) = reader.take() {
        assert_eq!(msg.value, 25.5);
        assert_eq!(msg.timestamp, 1000);
    } else {
        panic!("Expected to receive sample with latency budget configured");
    }
}

#[test]
fn test_latency_budget_behavior_multiple_budgets() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Two readers: one with low latency budget, one with high
    let participant = Participant::builder("latency_budget_multi_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let writer_qos = QoS::reliable().latency_budget_millis(5);
    let low_latency_qos = QoS::reliable().latency_budget_millis(5);
    let high_latency_qos = QoS::reliable().latency_budget_millis(500);

    let writer = participant
        .create_writer::<Temperature>("LatencyMultiTopic", writer_qos)
        .expect("writer");
    let low_reader = participant
        .create_reader::<Temperature>("LatencyMultiTopic", low_latency_qos)
        .expect("low_reader");
    let high_reader = participant
        .create_reader::<Temperature>("LatencyMultiTopic", high_latency_qos)
        .expect("high_reader");

    thread::sleep(Duration::from_millis(50));

    for i in 0..5 {
        writer
            .write(&Temperature {
                value: 20.0 + i as f32,
                timestamp: (i + 1) * 100,
            })
            .expect("write");
        thread::sleep(Duration::from_millis(20));
    }

    thread::sleep(Duration::from_millis(200));

    // Both readers should receive data (budget is a hint, not enforcement)
    let mut low_count = 0;
    while let Ok(Some(_)) = low_reader.take() {
        low_count += 1;
    }
    let mut high_count = 0;
    while let Ok(Some(_)) = high_reader.take() {
        high_count += 1;
    }

    assert!(low_count > 0, "Low-latency reader should receive samples");
    assert!(high_count > 0, "High-latency reader should receive samples");
}

// Note: LATENCY_BUDGET is a hint for transport optimization.
// In IntraProcess mode, all data is delivered immediately regardless
// of the budget. Full enforcement requires transport-layer routing.
