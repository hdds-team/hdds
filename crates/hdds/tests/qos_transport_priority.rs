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

//! TRANSPORT_PRIORITY QoS policy integration tests
//!
//! Validates TRANSPORT_PRIORITY policy exposed through public API.

use hdds::api::{Participant, QoS, TransportPriority};
use std::time::Duration;

#[test]
fn test_transport_priority_qos_builder_custom() {
    // Create QoS with custom TRANSPORT_PRIORITY value
    let qos = QoS::best_effort().transport_priority(100);

    assert_eq!(qos.transport_priority.value, 100);
    assert!(qos.transport_priority.is_high());
    assert!(!qos.transport_priority.is_normal());
}

#[test]
fn test_transport_priority_qos_builder_high() {
    // Create QoS with high TRANSPORT_PRIORITY
    let qos = QoS::best_effort().transport_priority_high();

    assert_eq!(qos.transport_priority.value, 50);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_qos_builder_low() {
    // Create QoS with low TRANSPORT_PRIORITY
    let qos = QoS::best_effort().transport_priority_low();

    assert_eq!(qos.transport_priority.value, -50);
    assert!(qos.transport_priority.is_low());
}

#[test]
fn test_transport_priority_qos_builder_normal() {
    // Create QoS with normal TRANSPORT_PRIORITY
    let qos = QoS::best_effort().transport_priority_normal();

    assert_eq!(qos.transport_priority.value, 0);
    assert!(qos.transport_priority.is_normal());
}

#[test]
fn test_transport_priority_qos_default() {
    // Default QoS should have normal priority (0)
    let qos = QoS::default();

    assert_eq!(qos.transport_priority.value, 0);
    assert!(qos.transport_priority.is_normal());
}

#[test]
fn test_transport_priority_struct_normal() {
    let priority = TransportPriority::normal();
    assert_eq!(priority.value, 0);
    assert!(priority.is_normal());
    assert!(!priority.is_high());
    assert!(!priority.is_low());
}

#[test]
fn test_transport_priority_struct_high() {
    let priority = TransportPriority::high();
    assert_eq!(priority.value, 50);
    assert!(priority.is_high());
    assert!(!priority.is_normal());
}

#[test]
fn test_transport_priority_struct_low() {
    let priority = TransportPriority::low();
    assert_eq!(priority.value, -50);
    assert!(priority.is_low());
    assert!(!priority.is_normal());
}

#[test]
fn test_participant_with_transport_priority_qos() {
    // Verify participant can be created with TRANSPORT_PRIORITY QoS (smoke test)
    let participant = Participant::builder("transport_priority_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until transport optimization is complete
    // In the future, this will test:
    // 1. DSCP/ToS field marking in UDP packets
    // 2. Network priority routing
    // 3. Traffic shaping based on priority

    drop(participant);
}

#[test]
fn test_qos_transport_priority_builder_chaining() {
    // Test that TRANSPORT_PRIORITY can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5)
        .time_based_filter_millis(50)
        .destination_order_by_source()
        .presentation_topic_coherent()
        .latency_budget_millis(10)
        .transport_priority_high();

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
    assert_eq!(qos.transport_priority.value, 50);
}

#[test]
fn test_transport_priority_with_best_effort() {
    // TRANSPORT_PRIORITY works with best-effort reliability
    let qos = QoS::best_effort().transport_priority_high();

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert_eq!(qos.transport_priority.value, 50);
}

#[test]
fn test_transport_priority_with_reliable() {
    // TRANSPORT_PRIORITY works with reliable reliability
    let qos = QoS::reliable().transport_priority_low();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert_eq!(qos.transport_priority.value, -50);
}

#[test]
fn test_transport_priority_clone() {
    let qos1 = QoS::best_effort().transport_priority(100);
    let qos2 = qos1.clone();

    assert_eq!(qos2.transport_priority.value, 100);
}

#[test]
fn test_transport_priority_positive_value() {
    // Test positive priority values
    let qos = QoS::best_effort().transport_priority(25);

    assert_eq!(qos.transport_priority.value, 25);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_negative_value() {
    // Test negative priority values
    let qos = QoS::best_effort().transport_priority(-25);

    assert_eq!(qos.transport_priority.value, -25);
    assert!(qos.transport_priority.is_low());
}

#[test]
fn test_transport_priority_zero_value() {
    // Test zero priority value
    let qos = QoS::best_effort().transport_priority(0);

    assert_eq!(qos.transport_priority.value, 0);
    assert!(qos.transport_priority.is_normal());
}

#[test]
fn test_transport_priority_very_high_value() {
    // Test very high priority (critical systems)
    let qos = QoS::best_effort().transport_priority(1000);

    assert_eq!(qos.transport_priority.value, 1000);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_very_low_value() {
    // Test very low priority (background traffic)
    let qos = QoS::best_effort().transport_priority(-1000);

    assert_eq!(qos.transport_priority.value, -1000);
    assert!(qos.transport_priority.is_low());
}

#[test]
fn test_transport_priority_combined_with_latency_budget() {
    // TRANSPORT_PRIORITY and LATENCY_BUDGET can coexist
    let qos = QoS::best_effort()
        .latency_budget_millis(10) // Target 10ms latency
        .transport_priority_high(); // High network priority

    assert_eq!(qos.latency_budget.duration, Duration::from_millis(10));
    assert_eq!(qos.transport_priority.value, 50);
}

#[test]
fn test_transport_priority_combined_with_deadline() {
    // TRANSPORT_PRIORITY and Deadline can coexist
    let qos = QoS::best_effort()
        .deadline_millis(100) // Expect samples every 100ms
        .transport_priority_high(); // High network priority

    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.transport_priority.value, 50);
}

#[test]
fn test_transport_priority_combined_with_lifespan() {
    // TRANSPORT_PRIORITY and Lifespan can coexist
    let qos = QoS::best_effort()
        .lifespan_secs(10) // Samples expire after 10s
        .transport_priority_low(); // Low network priority

    assert_eq!(qos.lifespan.duration, Duration::from_secs(10));
    assert_eq!(qos.transport_priority.value, -50);
}

#[test]
fn test_transport_priority_use_case_emergency_alerts() {
    // Emergency alerts: highest priority
    let qos = QoS::reliable().transport_priority(100);

    assert_eq!(qos.transport_priority.value, 100);
    assert!(qos.transport_priority.is_high());
    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
}

#[test]
fn test_transport_priority_use_case_control_commands() {
    // Control commands: high priority
    let qos = QoS::reliable().transport_priority_high();

    assert_eq!(qos.transport_priority.value, 50);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_use_case_real_time_telemetry() {
    // Real-time telemetry: medium-high priority
    let qos = QoS::best_effort().transport_priority(30);

    assert_eq!(qos.transport_priority.value, 30);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_use_case_sensor_data() {
    // Sensor data: normal priority
    let qos = QoS::best_effort().transport_priority_normal();

    assert_eq!(qos.transport_priority.value, 0);
    assert!(qos.transport_priority.is_normal());
}

#[test]
fn test_transport_priority_use_case_logs() {
    // Logs: low priority
    let qos = QoS::best_effort().transport_priority_low();

    assert_eq!(qos.transport_priority.value, -50);
    assert!(qos.transport_priority.is_low());
}

#[test]
fn test_transport_priority_use_case_bulk_transfers() {
    // Bulk transfers: lowest priority
    let qos = QoS::best_effort().transport_priority(-100);

    assert_eq!(qos.transport_priority.value, -100);
    assert!(qos.transport_priority.is_low());
}

#[test]
fn test_transport_priority_dscp_expedited_forwarding() {
    // DSCP EF (Expedited Forwarding): value 46
    let qos = QoS::best_effort().transport_priority(46);

    assert_eq!(qos.transport_priority.value, 46);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_dscp_assured_forwarding_4() {
    // DSCP AF4 (Assured Forwarding 4): value 34
    let qos = QoS::best_effort().transport_priority(34);

    assert_eq!(qos.transport_priority.value, 34);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_dscp_assured_forwarding_3() {
    // DSCP AF3 (Assured Forwarding 3): value 26
    let qos = QoS::best_effort().transport_priority(26);

    assert_eq!(qos.transport_priority.value, 26);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_dscp_assured_forwarding_2() {
    // DSCP AF2 (Assured Forwarding 2): value 18
    let qos = QoS::best_effort().transport_priority(18);

    assert_eq!(qos.transport_priority.value, 18);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_dscp_assured_forwarding_1() {
    // DSCP AF1 (Assured Forwarding 1): value 10
    let qos = QoS::best_effort().transport_priority(10);

    assert_eq!(qos.transport_priority.value, 10);
    assert!(qos.transport_priority.is_high());
}

#[test]
fn test_transport_priority_dscp_best_effort() {
    // DSCP Best Effort: value 0
    let qos = QoS::best_effort().transport_priority(0);

    assert_eq!(qos.transport_priority.value, 0);
    assert!(qos.transport_priority.is_normal());
}

#[test]
fn test_transport_priority_equality() {
    let priority1 = TransportPriority { value: 10 };
    let priority2 = TransportPriority { value: 10 };
    let priority3 = TransportPriority { value: 20 };

    assert_eq!(priority1, priority2);
    assert_ne!(priority1, priority3);
}

#[test]
fn test_transport_priority_ordering() {
    let low = TransportPriority::low();
    let normal = TransportPriority::normal();
    let high = TransportPriority::high();

    assert!(low < normal);
    assert!(normal < high);
    assert!(low < high);
}

// ============================================================================
// Behavior tests: Real pub/sub with TRANSPORT_PRIORITY QoS
// ============================================================================

#[test]
fn test_transport_priority_behavior_data_flows_with_priority() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Verify data flows correctly when transport priority is set
    let participant = Participant::builder("tp_flow_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let qos = QoS::reliable().transport_priority(10);
    let writer = participant
        .create_writer::<Temperature>("TransportPriorityTopic", qos.clone())
        .expect("writer");
    let reader = participant
        .create_reader::<Temperature>("TransportPriorityTopic", qos)
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
        panic!("Expected to receive sample with transport priority set");
    }
}

#[test]
fn test_transport_priority_behavior_high_and_low_priority_topics() {
    use hdds::generated::temperature::Temperature;
    use std::thread;

    // Two topics with different priorities - both should deliver data
    let participant = Participant::builder("tp_two_topics_test")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("participant");

    let high_qos = QoS::reliable().transport_priority(100);
    let low_qos = QoS::reliable().transport_priority(0);

    let high_writer = participant
        .create_writer::<Temperature>("HighPriorityTopic", high_qos.clone())
        .expect("high writer");
    let low_writer = participant
        .create_writer::<Temperature>("LowPriorityTopic", low_qos.clone())
        .expect("low writer");
    let high_reader = participant
        .create_reader::<Temperature>("HighPriorityTopic", high_qos)
        .expect("high reader");
    let low_reader = participant
        .create_reader::<Temperature>("LowPriorityTopic", low_qos)
        .expect("low reader");

    thread::sleep(Duration::from_millis(50));

    // Send on both topics
    for i in 0..5 {
        high_writer
            .write(&Temperature {
                value: 100.0 + i as f32,
                timestamp: (i + 1) * 100,
            })
            .expect("high write");
        low_writer
            .write(&Temperature {
                value: i as f32,
                timestamp: (i + 1) * 100,
            })
            .expect("low write");
    }

    thread::sleep(Duration::from_millis(200));

    let mut high_count = 0;
    while let Ok(Some(_)) = high_reader.take() {
        high_count += 1;
    }
    let mut low_count = 0;
    while let Ok(Some(_)) = low_reader.take() {
        low_count += 1;
    }

    // Both should receive all their samples (priority affects transport, not delivery)
    assert_eq!(
        high_count, 5,
        "High-priority reader should receive 5 samples"
    );
    assert_eq!(low_count, 5, "Low-priority reader should receive 5 samples");
}

// Note: In IntraProcess mode, transport priority has no effect on ordering
// since there is no network layer. On real networks, priority maps to
// DSCP/ToS bits in IP packets for QoS-aware switches.
