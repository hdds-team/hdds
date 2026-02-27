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

//! `DURABILITY_SERVICE` `QoS` policy integration tests
//!
//! Validates `DURABILITY_SERVICE` policy exposed through public API.

use hdds::api::{DurabilityService, Participant, QoS};
use std::time::Duration;

// ============================================================================
// DURABILITY_SERVICE QoS builder tests
// ============================================================================

#[test]
fn test_durability_service_qos_builder_default() {
    // Default QoS should have default DURABILITY_SERVICE
    let qos = QoS::default();

    assert_eq!(qos.durability_service.service_cleanup_delay_us, 0);
    assert_eq!(qos.durability_service.history_depth, 1);
    assert_eq!(qos.durability_service.max_samples, 1000);
    assert_eq!(qos.durability_service.max_instances, 1);
    assert_eq!(qos.durability_service.max_samples_per_instance, 1000);
    assert!(qos.durability_service.is_immediate_cleanup());
}

#[test]
fn test_durability_service_qos_builder_keep_last() {
    // Create QoS with keep_last configuration
    let qos = QoS::best_effort()
        .transient_local()
        .durability_service_keep_last(100, 5000, 10, 500);

    assert_eq!(qos.durability_service.history_depth, 100);
    assert_eq!(qos.durability_service.max_samples, 5000);
    assert_eq!(qos.durability_service.max_instances, 10);
    assert_eq!(qos.durability_service.max_samples_per_instance, 500);
}

#[test]
fn test_durability_service_qos_builder_cleanup_delay() {
    // Create QoS with cleanup delay
    let qos = QoS::reliable()
        .transient_local()
        .durability_service_cleanup_delay_secs(60);

    assert_eq!(qos.durability_service.service_cleanup_delay_us, 60_000_000);
    assert!(!qos.durability_service.is_immediate_cleanup());
}

#[test]
fn test_durability_service_qos_builder_with_struct() {
    // Create QoS using DurabilityService struct
    let service = DurabilityService::keep_last(200, 10000, 20, 500);
    let qos = QoS::reliable()
        .transient_local()
        .durability_service(service);

    assert_eq!(qos.durability_service.history_depth, 200);
    assert_eq!(qos.durability_service.max_samples, 10000);
}

#[test]
fn test_durability_service_struct_default() {
    let service = DurabilityService::default();
    assert_eq!(service.service_cleanup_delay_us, 0);
    assert_eq!(service.history_depth, 1);
    assert_eq!(service.max_samples, 1000);
    assert_eq!(service.max_instances, 1);
    assert_eq!(service.max_samples_per_instance, 1000);
    assert!(service.is_immediate_cleanup());
}

#[test]
fn test_durability_service_struct_keep_last() {
    let service = DurabilityService::keep_last(100, 5000, 10, 500);
    assert_eq!(service.history_depth, 100);
    assert_eq!(service.max_samples, 5000);
    assert_eq!(service.max_instances, 10);
    assert_eq!(service.max_samples_per_instance, 500);
}

#[test]
fn test_durability_service_struct_with_cleanup_delay() {
    let service = DurabilityService::with_cleanup_delay_secs(30);
    assert_eq!(service.service_cleanup_delay_us, 30_000_000);
    assert!(!service.is_immediate_cleanup());
}

// ============================================================================
// Validation tests
// ============================================================================

#[test]
fn test_durability_service_validate_default() {
    let service = DurabilityService::default();
    assert!(service.validate().is_ok());
}

#[test]
fn test_durability_service_validate_history_depth_zero() {
    let service = DurabilityService {
        history_depth: 0,
        ..Default::default()
    };
    assert!(service.validate().is_err());
    assert!(service
        .validate()
        .unwrap_err()
        .contains("history_depth must be > 0"));
}

#[test]
fn test_durability_service_validate_max_samples_too_small() {
    let service = DurabilityService {
        max_samples: 10,
        max_instances: 5,
        max_samples_per_instance: 10,
        ..Default::default()
    };
    assert!(service.validate().is_err());
    assert!(service.validate().unwrap_err().contains("max_samples"));
}

#[test]
fn test_durability_service_validate_max_samples_zero() {
    let service = DurabilityService {
        max_samples: 0,
        ..Default::default()
    };
    assert!(service.validate().is_err());
    assert!(service
        .validate()
        .unwrap_err()
        .contains("max_samples must be > 0"));
}

#[test]
fn test_durability_service_validate_max_instances_zero() {
    let service = DurabilityService {
        max_instances: 0,
        ..Default::default()
    };
    assert!(service.validate().is_err());
    assert!(service
        .validate()
        .unwrap_err()
        .contains("max_instances must be > 0"));
}

#[test]
fn test_durability_service_validate_max_samples_per_instance_zero() {
    let service = DurabilityService {
        max_samples_per_instance: 0,
        ..Default::default()
    };
    assert!(service.validate().is_err());
    assert!(service
        .validate()
        .unwrap_err()
        .contains("max_samples_per_instance must be > 0"));
}

// ============================================================================
// Builder chaining tests
// ============================================================================

#[test]
fn test_qos_durability_service_builder_chaining() {
    // Test that DURABILITY_SERVICE can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5)
        .durability_service_keep_last(100, 5000, 10, 500);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(5));
    assert_eq!(qos.durability_service.history_depth, 100);
    assert_eq!(qos.durability_service.max_samples, 5000);
}

#[test]
fn test_durability_service_with_transient_local() {
    // DURABILITY_SERVICE is typically used with TRANSIENT_LOCAL
    let qos = QoS::best_effort()
        .transient_local()
        .durability_service_keep_last(100, 1000, 10, 100);

    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert_eq!(qos.durability_service.history_depth, 100);
}

#[test]
fn test_durability_service_with_reliable() {
    // DURABILITY_SERVICE + RELIABLE + TRANSIENT_LOCAL = guaranteed historical delivery
    let qos = QoS::reliable()
        .transient_local()
        .durability_service_keep_last(1000, 10000, 10, 1000);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert_eq!(qos.durability_service.history_depth, 1000);
}

// ============================================================================
// Use case tests
// ============================================================================

#[test]
fn test_use_case_late_joiner_support() {
    // Late-joiner support: keep last 100 samples for new readers
    let qos = QoS::reliable()
        .transient_local()
        .durability_service_keep_last(100, 1000, 10, 100);

    assert_eq!(qos.durability_service.history_depth, 100);
    assert!(qos.durability_service.validate().is_ok());

    // Application would:
    // 1. Create writer with TRANSIENT_LOCAL durability
    // 2. Configure DURABILITY_SERVICE to keep 100 samples
    // 3. Late-joining readers receive historical samples
}

#[test]
fn test_use_case_memory_constrained() {
    // Memory-constrained: limit history cache size
    let qos = QoS::best_effort()
        .transient_local()
        .durability_service_keep_last(10, 100, 5, 20);

    assert_eq!(qos.durability_service.max_samples, 100);
    assert!(qos.durability_service.validate().is_ok());

    // Balances late-joiner support with memory constraints
}

#[test]
fn test_use_case_reliable_transient() {
    // Reliable + TransientLocal: guaranteed historical delivery
    let qos = QoS::reliable()
        .transient_local()
        .durability_service_keep_last(1000, 10000, 10, 1000);

    assert_eq!(qos.durability_service.history_depth, 1000);
    assert!(qos.durability_service.validate().is_ok());

    // Combine with RELIABLE QoS for guaranteed delivery
    // and TRANSIENT_LOCAL for late-joiner support
}

#[test]
fn test_use_case_cleanup_delay() {
    // Cleanup delay: allow very late readers to catch up
    let qos = QoS::reliable()
        .transient_local()
        .durability_service_cleanup_delay_secs(300);

    assert_eq!(qos.durability_service.service_cleanup_delay_us, 300_000_000);
    assert!(!qos.durability_service.is_immediate_cleanup());

    // Keep samples in cache for 5 minutes after all readers ack
}

#[test]
fn test_use_case_high_throughput() {
    // High-throughput: large history cache
    let qos = QoS::reliable()
        .transient_local()
        .durability_service_keep_last(10000, 100000, 100, 1000);

    assert_eq!(qos.durability_service.max_samples, 100000);
    assert!(qos.durability_service.validate().is_ok());

    // Support high-rate topics with many instances
}

// ============================================================================
// Participant smoke tests
// ============================================================================

#[test]
fn test_participant_with_durability_service_qos() {
    // Verify participant can be created with DURABILITY_SERVICE QoS (smoke test)
    let participant = Participant::builder("durability_service_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until history cache is fully integrated
    // In the future, this will test:
    // 1. Creating writer with TRANSIENT_LOCAL + DURABILITY_SERVICE
    // 2. Writing samples to populate history cache
    // 3. Late-joining reader connects
    // 4. Verifying reader receives historical samples

    drop(participant);
}

// ============================================================================
// Clone and equality tests
// ============================================================================

#[test]
fn test_durability_service_clone() {
    let qos1 = QoS::reliable()
        .transient_local()
        .durability_service_keep_last(100, 1000, 10, 100);
    let qos2 = qos1.clone();

    assert_eq!(
        qos2.durability_service.history_depth,
        qos1.durability_service.history_depth
    );
    assert_eq!(
        qos2.durability_service.max_samples,
        qos1.durability_service.max_samples
    );
}

#[test]
fn test_durability_service_equality() {
    let service1 = DurabilityService::keep_last(100, 1000, 10, 100);
    let service2 = DurabilityService::keep_last(100, 1000, 10, 100);
    let service3 = DurabilityService::keep_last(200, 1000, 10, 100);

    assert_eq!(service1, service2);
    assert_ne!(service1, service3);
}

#[test]
fn test_durability_service_debug() {
    let service = DurabilityService::default();
    let debug_str = format!("{service:?}");
    assert!(debug_str.contains("DurabilityService"));
    assert!(debug_str.contains("service_cleanup_delay_us"));
}

// ============================================================================
// Edge cases and combinations
// ============================================================================

#[test]
fn test_durability_service_with_all_qos_policies() {
    // Combine DURABILITY_SERVICE with all other QoS policies
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
        .writer_data_lifecycle_manual_dispose()
        .reader_data_lifecycle_secs(30, 60)
        .durability_service_keep_last(500, 50000, 50, 1000);

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
    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        30_000_000
    );
    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_disposed_samples_delay_us,
        60_000_000
    );
    assert_eq!(qos.durability_service.history_depth, 500);
    assert_eq!(qos.durability_service.max_samples, 50000);
    assert_eq!(qos.durability_service.max_instances, 50);
    assert_eq!(qos.durability_service.max_samples_per_instance, 1000);
}

#[test]
fn test_durability_service_copy_semantics() {
    let service1 = DurabilityService::keep_last(100, 1000, 10, 100);
    let service2 = service1; // Copy, not move
    assert_eq!(service1, service2);
}

#[test]
fn test_durability_service_validate_boundary_exact() {
    // max_samples = max_instances * max_samples_per_instance (exact)
    let service = DurabilityService {
        max_samples: 100,
        max_instances: 10,
        max_samples_per_instance: 10,
        ..Default::default()
    };
    assert!(service.validate().is_ok());
}

#[test]
fn test_durability_service_validate_boundary_greater() {
    // max_samples > max_instances * max_samples_per_instance
    let service = DurabilityService {
        max_samples: 101,
        max_instances: 10,
        max_samples_per_instance: 10,
        ..Default::default()
    };
    assert!(service.validate().is_ok());
}

// ============================================================================
// Behavior tests: Deferred
// ============================================================================
//
// TODO: DURABILITY_SERVICE behavior tests are deferred.
// DURABILITY_SERVICE controls how the built-in transient/persistent
// service manages historical data. It is not yet wired into the
// writer history cache for behavioral enforcement.
// Once integrated, add tests for:
// 1. Writer with TRANSIENT_LOCAL + DURABILITY_SERVICE publishing N samples
// 2. Late-joining reader receiving up to history_depth samples
// 3. Verifying max_samples and max_instances limits on the service cache
//
// For now, these tests validate the QoS API surface only.
