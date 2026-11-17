// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DESTINATION_ORDER QoS policy integration tests
//!
//! Validates DESTINATION_ORDER policy exposed through public API.

use hdds::api::{DestinationOrder, DestinationOrderKind, Participant, QoS};
use hdds::test_support::domains::unique_domain;
use std::time::Duration;

#[test]
fn test_destination_order_qos_builder_reception() {
    // Create QoS with DESTINATION_ORDER BY_RECEPTION_TIMESTAMP
    let qos = QoS::best_effort().destination_order_by_reception();

    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::ByReceptionTimestamp
    );
    assert!(qos.destination_order.uses_reception_timestamp());
    assert!(!qos.destination_order.uses_source_timestamp());
}

#[test]
fn test_destination_order_qos_builder_source() {
    // Create QoS with DESTINATION_ORDER BY_SOURCE_TIMESTAMP
    let qos = QoS::best_effort().destination_order_by_source();

    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
    assert!(qos.destination_order.uses_source_timestamp());
    assert!(!qos.destination_order.uses_reception_timestamp());
}

#[test]
fn test_destination_order_qos_builder_struct() {
    // Create QoS with DestinationOrder struct
    let order = DestinationOrder::by_source_timestamp();
    let qos = QoS::best_effort().destination_order(order);

    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
    assert!(qos.destination_order.uses_source_timestamp());
}

#[test]
fn test_destination_order_qos_default() {
    // Default QoS should have BY_RECEPTION_TIMESTAMP
    let qos = QoS::default();

    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::ByReceptionTimestamp
    );
    assert!(qos.destination_order.uses_reception_timestamp());
}

#[test]
fn test_destination_order_struct_by_reception() {
    let order = DestinationOrder::by_reception_timestamp();
    assert_eq!(order.kind, DestinationOrderKind::ByReceptionTimestamp);
    assert!(order.uses_reception_timestamp());
}

#[test]
fn test_destination_order_struct_by_source() {
    let order = DestinationOrder::by_source_timestamp();
    assert_eq!(order.kind, DestinationOrderKind::BySourceTimestamp);
    assert!(order.uses_source_timestamp());
}

#[test]
fn test_destination_order_kind_default() {
    let kind = DestinationOrderKind::default();
    assert_eq!(kind, DestinationOrderKind::ByReceptionTimestamp);
}

#[test]
fn test_participant_with_destination_order_qos() {
    // Verify participant can be created with DESTINATION_ORDER QoS (smoke test)
    // No `.with_transport(...)`: this participant takes the DEFAULT
    // UdpMulticast transport and therefore binds RTPS ports. The domain
    // is leased (declared first, so dropped last) instead of defaulting
    // to 0, which every other test binary also lands on.
    let domain = unique_domain();
    let participant = Participant::builder("destination_order_test")
        .domain_id(domain.id())
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until Reader integration is complete
    // In the future, this will test:
    // 1. Reader creation with DESTINATION_ORDER QoS
    // 2. Sample ordering enforcement (reception vs source timestamp)
    // 3. Out-of-order sample handling

    drop(participant);
}

#[test]
fn test_qos_destination_order_builder_chaining() {
    // Test that DESTINATION_ORDER can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5)
        .time_based_filter_millis(50)
        .destination_order_by_source();

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
        DestinationOrderKind::BySourceTimestamp
    );
}

#[test]
fn test_destination_order_with_best_effort() {
    // DESTINATION_ORDER works with best-effort reliability
    let qos = QoS::best_effort().destination_order_by_source();

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
}

#[test]
fn test_destination_order_with_reliable() {
    // DESTINATION_ORDER works with reliable reliability
    let qos = QoS::reliable().destination_order_by_source();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
}

#[test]
fn test_destination_order_clone() {
    let qos1 = QoS::best_effort().destination_order_by_source();
    let qos2 = qos1.clone();

    assert_eq!(
        qos2.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
}

#[test]
fn test_destination_order_default_value() {
    // Edge case: default DESTINATION_ORDER
    let order = DestinationOrder::default();
    let qos = QoS::best_effort().destination_order(order);

    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::ByReceptionTimestamp
    );
}

#[test]
fn test_destination_order_combined_with_deadline() {
    // DESTINATION_ORDER and Deadline can coexist
    let qos = QoS::best_effort()
        .deadline_millis(100) // Expect samples every 100ms
        .destination_order_by_source(); // Order by source timestamp

    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
}

#[test]
fn test_destination_order_combined_with_lifespan() {
    // DESTINATION_ORDER and Lifespan can coexist
    let qos = QoS::best_effort()
        .lifespan_secs(10) // Samples expire after 10s
        .destination_order_by_source(); // Order by source timestamp

    assert_eq!(qos.lifespan.duration, Duration::from_secs(10));
    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
}

#[test]
fn test_destination_order_combined_with_time_based_filter() {
    // DESTINATION_ORDER and TIME_BASED_FILTER can coexist
    let qos = QoS::best_effort()
        .time_based_filter_millis(100) // Accept at most every 100ms
        .destination_order_by_source(); // Order by source timestamp

    assert_eq!(
        qos.time_based_filter.minimum_separation,
        Duration::from_millis(100)
    );
    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
}

#[test]
fn test_destination_order_real_time_sensor_scenario() {
    // Real-time sensor data: process in arrival order (minimize latency)
    let qos = QoS::best_effort().destination_order_by_reception();

    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::ByReceptionTimestamp
    );
    assert!(qos.destination_order.uses_reception_timestamp());
}

#[test]
fn test_destination_order_log_replay_scenario() {
    // Log replay: preserve original temporal order
    let qos = QoS::best_effort().destination_order_by_source();

    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
    assert!(qos.destination_order.uses_source_timestamp());
}

#[test]
fn test_destination_order_distributed_events_scenario() {
    // Distributed system event correlation: use source timestamps
    let qos = QoS::reliable()
        .transient_local()
        .destination_order_by_source();

    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::BySourceTimestamp
    );
    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
}

#[test]
fn test_destination_order_kind_equality() {
    let kind1 = DestinationOrderKind::BySourceTimestamp;
    let kind2 = DestinationOrderKind::BySourceTimestamp;
    let kind3 = DestinationOrderKind::ByReceptionTimestamp;

    assert_eq!(kind1, kind2);
    assert_ne!(kind1, kind3);
}

#[test]
fn test_destination_order_equality() {
    let order1 = DestinationOrder::by_source_timestamp();
    let order2 = DestinationOrder::by_source_timestamp();
    let order3 = DestinationOrder::by_reception_timestamp();

    assert_eq!(order1, order2);
    assert_ne!(order1, order3);
}

#[test]
fn test_destination_order_kind_ordering() {
    // BY_RECEPTION_TIMESTAMP (0) < BY_SOURCE_TIMESTAMP (1)
    assert!(DestinationOrderKind::ByReceptionTimestamp < DestinationOrderKind::BySourceTimestamp);
    assert!(DestinationOrderKind::BySourceTimestamp > DestinationOrderKind::ByReceptionTimestamp);
}

// ============================================================================
// Behavior tests: Deferred
// ============================================================================
//
// TODO: DESTINATION_ORDER behavior tests are deferred.
// DESTINATION_ORDER sample ordering (BY_RECEPTION vs BY_SOURCE timestamp)
// is not yet wired into the reader cache delivery path.
// Once integrated, add tests for:
// 1. Two writers publishing with different source timestamps
// 2. Reader with BY_SOURCE_TIMESTAMP receiving samples in source order
// 3. Reader with BY_RECEPTION_TIMESTAMP receiving in arrival order
//
// For now, these tests validate the QoS API surface only.
