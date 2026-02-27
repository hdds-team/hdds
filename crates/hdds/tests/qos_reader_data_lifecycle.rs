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

//! READER_DATA_LIFECYCLE QoS policy integration tests
//!
//! Validates READER_DATA_LIFECYCLE policy exposed through public API.

use hdds::api::{Participant, QoS, ReaderDataLifecycle};
use std::time::Duration;

// ============================================================================
// READER_DATA_LIFECYCLE QoS builder tests
// ============================================================================

#[test]
fn test_reader_data_lifecycle_qos_builder_keep_all() {
    // Create QoS with keep all (default)
    let qos = QoS::best_effort().reader_data_lifecycle_keep_all();

    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        i64::MAX
    );
    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_disposed_samples_delay_us,
        i64::MAX
    );
    assert!(qos.reader_data_lifecycle.is_keep_all());
    assert!(!qos.reader_data_lifecycle.is_immediate_cleanup());
}

#[test]
fn test_reader_data_lifecycle_qos_builder_immediate_cleanup() {
    // Create QoS with immediate cleanup
    let qos = QoS::best_effort().reader_data_lifecycle_immediate_cleanup();

    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        0
    );
    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_disposed_samples_delay_us,
        0
    );
    assert!(!qos.reader_data_lifecycle.is_keep_all());
    assert!(qos.reader_data_lifecycle.is_immediate_cleanup());
}

#[test]
fn test_reader_data_lifecycle_qos_builder_secs() {
    // Create QoS with 30 second delays
    let qos = QoS::best_effort().reader_data_lifecycle_secs(30, 30);

    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        30_000_000
    );
    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_disposed_samples_delay_us,
        30_000_000
    );
}

#[test]
fn test_reader_data_lifecycle_qos_builder_with_struct() {
    // Create QoS using ReaderDataLifecycle struct
    let qos = QoS::best_effort().reader_data_lifecycle(ReaderDataLifecycle::immediate_cleanup());

    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        0
    );
    assert!(qos.reader_data_lifecycle.is_immediate_cleanup());
}

#[test]
fn test_reader_data_lifecycle_qos_default() {
    // Default QoS should have keep_all
    let qos = QoS::default();

    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        i64::MAX
    );
    assert!(qos.reader_data_lifecycle.is_keep_all());
}

#[test]
fn test_reader_data_lifecycle_struct_keep_all() {
    let lifecycle = ReaderDataLifecycle::keep_all();
    assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, i64::MAX);
    assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, i64::MAX);
    assert!(lifecycle.is_keep_all());
}

#[test]
fn test_reader_data_lifecycle_struct_immediate_cleanup() {
    let lifecycle = ReaderDataLifecycle::immediate_cleanup();
    assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 0);
    assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 0);
    assert!(lifecycle.is_immediate_cleanup());
}

#[test]
fn test_reader_data_lifecycle_struct_from_secs() {
    let lifecycle = ReaderDataLifecycle::from_secs(10, 20);
    assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 10_000_000);
    assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 20_000_000);
}

#[test]
fn test_reader_data_lifecycle_struct_default() {
    let lifecycle = ReaderDataLifecycle::default();
    assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, i64::MAX);
    assert!(lifecycle.is_keep_all());
}

// ============================================================================
// Builder chaining tests
// ============================================================================

#[test]
fn test_qos_reader_data_lifecycle_builder_chaining() {
    // Test that READER_DATA_LIFECYCLE can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5)
        .reader_data_lifecycle_secs(30, 60);

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(5));
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
}

#[test]
fn test_reader_data_lifecycle_with_best_effort() {
    // READER_DATA_LIFECYCLE works with best-effort reliability
    let qos = QoS::best_effort().reader_data_lifecycle_immediate_cleanup();

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert!(qos.reader_data_lifecycle.is_immediate_cleanup());
}

#[test]
fn test_reader_data_lifecycle_with_reliable() {
    // READER_DATA_LIFECYCLE works with reliable reliability
    let qos = QoS::reliable().reader_data_lifecycle_keep_all();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(qos.reader_data_lifecycle.is_keep_all());
}

// ============================================================================
// Use case tests
// ============================================================================

#[test]
fn test_use_case_historical_data() {
    // Keep historical data: INFINITE delays
    let qos = QoS::best_effort().reader_data_lifecycle_keep_all();

    assert!(qos.reader_data_lifecycle.is_keep_all());
    // Application can analyze all historical instances,
    // even after writers are gone or instances are disposed
}

#[test]
fn test_use_case_memory_management() {
    // Memory management: purge after 30 seconds
    let qos = QoS::reliable().reader_data_lifecycle_secs(30, 30);

    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        30_000_000
    );
    // Balances memory usage with data retention
}

#[test]
fn test_use_case_real_time_cleanup() {
    // Real-time systems: immediate cleanup
    let qos = QoS::best_effort().reader_data_lifecycle_immediate_cleanup();

    assert!(qos.reader_data_lifecycle.is_immediate_cleanup());
    // Minimizes memory footprint in resource-constrained environments
}

#[test]
fn test_use_case_graceful_processing() {
    // Graceful processing: allow time to handle final states
    let qos = QoS::best_effort().reader_data_lifecycle_secs(10, 5);

    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        10_000_000
    );
    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_disposed_samples_delay_us,
        5_000_000
    );
    // Application has time to process NOT_ALIVE states before purge
}

#[test]
fn test_use_case_asymmetric_delays() {
    // Asymmetric delays: different cleanup policies for different states
    let lifecycle = ReaderDataLifecycle::from_secs(60, 5);
    let qos = QoS::best_effort().reader_data_lifecycle(lifecycle);

    // Keep NO_WRITERS instances longer (60s) for late-joining apps
    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        60_000_000
    );

    // Purge DISPOSED instances quickly (5s) to free memory
    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_disposed_samples_delay_us,
        5_000_000
    );
}

// ============================================================================
// Participant smoke tests
// ============================================================================

#[test]
fn test_participant_with_reader_data_lifecycle_qos() {
    // Verify participant can be created with READER_DATA_LIFECYCLE QoS (smoke test)
    let participant = Participant::builder("reader_data_lifecycle_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until reader instance management is fully integrated
    // In the future, this will test:
    // 1. Creating reader with custom autopurge delays
    // 2. Receiving samples from writer
    // 3. Writer goes away (NOT_ALIVE_NO_WRITERS)
    // 4. Verifying instance is purged after delay
    // 5. Similar test for NOT_ALIVE_DISPOSED state

    drop(participant);
}

// ============================================================================
// Clone and equality tests
// ============================================================================

#[test]
fn test_reader_data_lifecycle_clone() {
    let qos1 = QoS::best_effort().reader_data_lifecycle_immediate_cleanup();
    let qos2 = qos1.clone();

    assert_eq!(
        qos2.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        qos1.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us
    );
    assert_eq!(
        qos2.reader_data_lifecycle
            .autopurge_disposed_samples_delay_us,
        qos1.reader_data_lifecycle
            .autopurge_disposed_samples_delay_us
    );
}

#[test]
fn test_reader_data_lifecycle_equality() {
    let lifecycle1 = ReaderDataLifecycle::keep_all();
    let lifecycle2 = ReaderDataLifecycle::keep_all();
    let lifecycle3 = ReaderDataLifecycle::immediate_cleanup();

    assert_eq!(lifecycle1, lifecycle2);
    assert_ne!(lifecycle1, lifecycle3);
}

#[test]
fn test_reader_data_lifecycle_debug() {
    let lifecycle = ReaderDataLifecycle::keep_all();
    let debug_str = format!("{:?}", lifecycle);
    assert!(debug_str.contains("ReaderDataLifecycle"));
    assert!(debug_str.contains("autopurge_nowriter_samples_delay_us"));
}

// ============================================================================
// Edge cases and combinations
// ============================================================================

#[test]
fn test_reader_data_lifecycle_toggle() {
    // Toggle between keep_all and immediate cleanup
    let qos1 = QoS::best_effort().reader_data_lifecycle_keep_all();
    let qos2 = qos1.reader_data_lifecycle_immediate_cleanup();
    let qos3 = qos2.reader_data_lifecycle_keep_all();

    assert!(qos3.reader_data_lifecycle.is_keep_all());
}

#[test]
fn test_reader_data_lifecycle_with_ownership() {
    // Combine READER_DATA_LIFECYCLE with OWNERSHIP (common pattern)
    let qos = QoS::reliable()
        .ownership_exclusive()
        .ownership_strength_high()
        .reader_data_lifecycle_immediate_cleanup();

    assert_eq!(qos.ownership.kind, hdds::api::OwnershipKind::Exclusive);
    assert_eq!(qos.ownership_strength.value, 100);
    assert!(qos.reader_data_lifecycle.is_immediate_cleanup());
}

#[test]
fn test_reader_data_lifecycle_with_all_qos_policies() {
    // Combine READER_DATA_LIFECYCLE with all other QoS policies
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
        .reader_data_lifecycle_secs(30, 60);

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
}

#[test]
fn test_reader_data_lifecycle_copy_semantics() {
    let lifecycle1 = ReaderDataLifecycle::from_secs(10, 20);
    let lifecycle2 = lifecycle1; // Copy, not move
    assert_eq!(lifecycle1, lifecycle2);
}

#[test]
fn test_reader_data_lifecycle_zero_delays() {
    let lifecycle = ReaderDataLifecycle::from_secs(0, 0);
    assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 0);
    assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 0);
    assert!(lifecycle.is_immediate_cleanup());
}

#[test]
fn test_reader_data_lifecycle_mixed_delays() {
    // One INFINITE, one immediate
    let qos = QoS::best_effort().reader_data_lifecycle(ReaderDataLifecycle {
        autopurge_nowriter_samples_delay_us: i64::MAX,
        autopurge_disposed_samples_delay_us: 0,
    });

    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_nowriter_samples_delay_us,
        i64::MAX
    );
    assert_eq!(
        qos.reader_data_lifecycle
            .autopurge_disposed_samples_delay_us,
        0
    );
    assert!(!qos.reader_data_lifecycle.is_keep_all());
    assert!(!qos.reader_data_lifecycle.is_immediate_cleanup());
}

// ============================================================================
// Behavior tests: Deferred
// ============================================================================
//
// TODO: READER_DATA_LIFECYCLE behavior tests are deferred.
// READER_DATA_LIFECYCLE (autopurge_nowriter_samples_delay,
// autopurge_disposed_samples_delay) is not yet wired into the
// reader instance management layer.
// Once integrated, add tests for:
// 1. Writer goes away -> reader purges NOT_ALIVE_NO_WRITERS instances
//    after the configured delay
// 2. Writer disposes instance -> reader purges NOT_ALIVE_DISPOSED
//    instances after the configured delay
// 3. immediate_cleanup vs keep_all behavior differences
//
// For now, these tests validate the QoS API surface only.
