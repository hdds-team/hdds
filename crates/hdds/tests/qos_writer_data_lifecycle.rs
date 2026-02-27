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

//! WRITER_DATA_LIFECYCLE QoS policy integration tests
//!
//! Validates WRITER_DATA_LIFECYCLE policy exposed through public API.

use hdds::api::{Participant, QoS, WriterDataLifecycle};
use std::time::Duration;

// ============================================================================
// WRITER_DATA_LIFECYCLE QoS builder tests
// ============================================================================

#[test]
fn test_writer_data_lifecycle_qos_builder_auto_dispose() {
    // Create QoS with auto-dispose (default)
    let qos = QoS::best_effort().writer_data_lifecycle_auto_dispose();

    assert!(qos.writer_data_lifecycle.autodispose_unregistered_instances);
    assert!(qos.writer_data_lifecycle.is_auto_dispose());
    assert!(!qos.writer_data_lifecycle.is_manual_dispose());
}

#[test]
fn test_writer_data_lifecycle_qos_builder_manual_dispose() {
    // Create QoS with manual dispose
    let qos = QoS::best_effort().writer_data_lifecycle_manual_dispose();

    assert!(!qos.writer_data_lifecycle.autodispose_unregistered_instances);
    assert!(!qos.writer_data_lifecycle.is_auto_dispose());
    assert!(qos.writer_data_lifecycle.is_manual_dispose());
}

#[test]
fn test_writer_data_lifecycle_qos_builder_with_struct() {
    // Create QoS using WriterDataLifecycle struct
    let qos = QoS::best_effort().writer_data_lifecycle(WriterDataLifecycle::manual_dispose());

    assert!(!qos.writer_data_lifecycle.autodispose_unregistered_instances);
    assert!(qos.writer_data_lifecycle.is_manual_dispose());
}

#[test]
fn test_writer_data_lifecycle_qos_default() {
    // Default QoS should have auto-dispose
    let qos = QoS::default();

    assert!(qos.writer_data_lifecycle.autodispose_unregistered_instances);
    assert!(qos.writer_data_lifecycle.is_auto_dispose());
}

#[test]
fn test_writer_data_lifecycle_struct_auto_dispose() {
    let lifecycle = WriterDataLifecycle::auto_dispose();
    assert!(lifecycle.autodispose_unregistered_instances);
    assert!(lifecycle.is_auto_dispose());
}

#[test]
fn test_writer_data_lifecycle_struct_manual_dispose() {
    let lifecycle = WriterDataLifecycle::manual_dispose();
    assert!(!lifecycle.autodispose_unregistered_instances);
    assert!(lifecycle.is_manual_dispose());
}

#[test]
fn test_writer_data_lifecycle_struct_default() {
    let lifecycle = WriterDataLifecycle::default();
    assert!(lifecycle.autodispose_unregistered_instances);
    assert!(lifecycle.is_auto_dispose());
}

// ============================================================================
// Builder chaining tests
// ============================================================================

#[test]
fn test_qos_writer_data_lifecycle_builder_chaining() {
    // Test that WRITER_DATA_LIFECYCLE can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5)
        .writer_data_lifecycle_manual_dispose();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(5));
    assert!(!qos.writer_data_lifecycle.autodispose_unregistered_instances);
}

#[test]
fn test_writer_data_lifecycle_with_best_effort() {
    // WRITER_DATA_LIFECYCLE works with best-effort reliability
    let qos = QoS::best_effort().writer_data_lifecycle_manual_dispose();

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert!(qos.writer_data_lifecycle.is_manual_dispose());
}

#[test]
fn test_writer_data_lifecycle_with_reliable() {
    // WRITER_DATA_LIFECYCLE works with reliable reliability
    let qos = QoS::reliable().writer_data_lifecycle_auto_dispose();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(qos.writer_data_lifecycle.is_auto_dispose());
}

// ============================================================================
// Use case tests
// ============================================================================

#[test]
fn test_use_case_simple_cleanup_auto_dispose() {
    // Simple applications: auto-dispose for automatic cleanup
    let qos = QoS::best_effort().writer_data_lifecycle_auto_dispose();

    assert!(qos.writer_data_lifecycle.is_auto_dispose());
    // When writer unregisters an instance, it's automatically disposed
}

#[test]
fn test_use_case_coordinated_disposal() {
    // Coordinated disposal across multiple writers
    let qos = QoS::reliable().writer_data_lifecycle_manual_dispose();

    assert!(qos.writer_data_lifecycle.is_manual_dispose());
    // Application would:
    // 1. Unregister instance from multiple writers
    // 2. Coordinate disposal logic
    // 3. Explicitly dispose when all writers ready
}

#[test]
fn test_use_case_conditional_cleanup() {
    // Conditional cleanup with custom logic
    let qos = QoS::best_effort().writer_data_lifecycle_manual_dispose();

    assert!(qos.writer_data_lifecycle.is_manual_dispose());
    // Application would:
    // 1. Unregister instance
    // 2. Check custom conditions (e.g., database cleanup)
    // 3. Dispose only if conditions met
}

#[test]
fn test_use_case_graceful_shutdown() {
    // Graceful shutdown with controlled cleanup order
    let qos = QoS::reliable()
        .transient_local()
        .writer_data_lifecycle_manual_dispose();

    assert!(qos.writer_data_lifecycle.is_manual_dispose());
    // Application would:
    // 1. Unregister instances during shutdown
    // 2. Perform cleanup operations
    // 3. Dispose instances in specific order
}

#[test]
fn test_use_case_instance_reuse() {
    // Instance reuse: keep instances alive after unregister
    let qos = QoS::best_effort().writer_data_lifecycle_manual_dispose();

    assert!(!qos.writer_data_lifecycle.autodispose_unregistered_instances);
    // Application would:
    // 1. Unregister instance temporarily
    // 2. Perform operations (e.g., update instance state)
    // 3. Re-register instance without disposal
}

// ============================================================================
// Participant smoke tests
// ============================================================================

#[test]
fn test_participant_with_writer_data_lifecycle_qos() {
    // Verify participant can be created with WRITER_DATA_LIFECYCLE QoS (smoke test)
    let participant = Participant::builder("writer_data_lifecycle_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until writer unregister/dispose is fully integrated
    // In the future, this will test:
    // 1. Creating writer with autodispose_unregistered_instances=false
    // 2. Unregistering an instance
    // 3. Verifying instance state (NOT_ALIVE_NO_WRITERS vs NOT_ALIVE_DISPOSED)
    // 4. Explicitly disposing instance

    drop(participant);
}

// ============================================================================
// Clone and equality tests
// ============================================================================

#[test]
fn test_writer_data_lifecycle_clone() {
    let qos1 = QoS::best_effort().writer_data_lifecycle_manual_dispose();
    let qos2 = qos1.clone();

    assert_eq!(
        qos2.writer_data_lifecycle
            .autodispose_unregistered_instances,
        qos1.writer_data_lifecycle
            .autodispose_unregistered_instances
    );
}

#[test]
fn test_writer_data_lifecycle_equality() {
    let lifecycle1 = WriterDataLifecycle::auto_dispose();
    let lifecycle2 = WriterDataLifecycle::auto_dispose();
    let lifecycle3 = WriterDataLifecycle::manual_dispose();

    assert_eq!(lifecycle1, lifecycle2);
    assert_ne!(lifecycle1, lifecycle3);
}

#[test]
fn test_writer_data_lifecycle_debug() {
    let lifecycle = WriterDataLifecycle::auto_dispose();
    let debug_str = format!("{:?}", lifecycle);
    assert!(debug_str.contains("WriterDataLifecycle"));
    assert!(debug_str.contains("autodispose_unregistered_instances"));
}

// ============================================================================
// Edge cases and combinations
// ============================================================================

#[test]
fn test_writer_data_lifecycle_toggle() {
    // Toggle between auto and manual
    let qos1 = QoS::best_effort().writer_data_lifecycle_auto_dispose();
    let qos2 = qos1.writer_data_lifecycle_manual_dispose();
    let qos3 = qos2.writer_data_lifecycle_auto_dispose();

    assert!(qos3.writer_data_lifecycle.is_auto_dispose());
}

#[test]
fn test_writer_data_lifecycle_with_ownership() {
    // Combine WRITER_DATA_LIFECYCLE with OWNERSHIP (common pattern)
    let qos = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength_high()
        .writer_data_lifecycle_manual_dispose();

    assert_eq!(qos.ownership.kind, hdds::api::OwnershipKind::Exclusive);
    assert_eq!(qos.ownership_strength.value, 100);
    assert!(qos.writer_data_lifecycle.is_manual_dispose());
}

#[test]
fn test_writer_data_lifecycle_with_all_qos_policies() {
    // Combine WRITER_DATA_LIFECYCLE with all other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(100)
        .deadline_millis(50)
        .lifespan_secs(10)
        .time_based_filter_millis(20)
        .destination_order_by_source()
        .presentation_topic_coherent()
        .latency_budget_millis(5)
        .transport_priority_high()
        .liveliness_automatic_millis(1000)
        .ownership_exclusive()
        .ownership_strength_high()
        .partition_single("test")
        .user_data_bytes(b"app")
        .group_data_bytes(b"team")
        .topic_data_bytes(b"schema")
        .entity_factory_manual_enable()
        .writer_data_lifecycle_manual_dispose();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(100)));
    assert_eq!(qos.deadline.period, Duration::from_millis(50));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(10));
    assert_eq!(
        qos.time_based_filter.minimum_separation,
        Duration::from_millis(20)
    );
    assert_eq!(
        qos.destination_order.kind,
        hdds::api::DestinationOrderKind::BySourceTimestamp
    );
    assert_eq!(
        qos.presentation.access_scope,
        hdds::api::PresentationAccessScope::Topic
    );
    assert_eq!(qos.latency_budget.duration, Duration::from_millis(5));
    assert_eq!(qos.transport_priority.value, 50);
    assert_eq!(qos.liveliness.lease_duration, Duration::from_millis(1000));
    assert_eq!(qos.ownership.kind, hdds::api::OwnershipKind::Exclusive);
    assert_eq!(qos.ownership_strength.value, 100);
    assert_eq!(qos.partition.names, vec!["test"]);
    assert_eq!(qos.user_data.value, b"app");
    assert_eq!(qos.group_data.value, b"team");
    assert_eq!(qos.topic_data.value, b"schema");
    assert!(qos.entity_factory.is_manual_enable());
    assert!(qos.writer_data_lifecycle.is_manual_dispose());
}

#[test]
fn test_writer_data_lifecycle_copy_semantics() {
    let lifecycle1 = WriterDataLifecycle::manual_dispose();
    let lifecycle2 = lifecycle1; // Copy, not move
    assert_eq!(lifecycle1, lifecycle2);
}

// ============================================================================
// Behavior tests: Deferred
// ============================================================================
//
// TODO: WRITER_DATA_LIFECYCLE behavior tests are deferred.
// WRITER_DATA_LIFECYCLE (autodispose_unregistered_instances) is not yet
// wired into the writer unregister/dispose path.
// Once integrated, add tests for:
// 1. auto_dispose: unregister instance -> reader sees DISPOSED state
// 2. manual_dispose: unregister instance -> reader sees NOT_ALIVE_NO_WRITERS
//    (not DISPOSED until explicit dispose call)
// 3. Instance reuse pattern with manual dispose
//
// For now, these tests validate the QoS API surface only.
