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

//! ENTITY_FACTORY QoS policy integration tests
//!
//! Validates ENTITY_FACTORY policy exposed through public API.

use hdds::api::{EntityFactory, Participant, QoS};
use std::time::Duration;

// ============================================================================
// ENTITY_FACTORY QoS builder tests
// ============================================================================

#[test]
fn test_entity_factory_qos_builder_auto_enable() {
    // Create QoS with auto-enable (default)
    let qos = QoS::best_effort().entity_factory_auto_enable();

    assert!(qos.entity_factory.autoenable_created_entities);
    assert!(qos.entity_factory.is_auto_enable());
    assert!(!qos.entity_factory.is_manual_enable());
}

#[test]
fn test_entity_factory_qos_builder_manual_enable() {
    // Create QoS with manual enable
    let qos = QoS::best_effort().entity_factory_manual_enable();

    assert!(!qos.entity_factory.autoenable_created_entities);
    assert!(!qos.entity_factory.is_auto_enable());
    assert!(qos.entity_factory.is_manual_enable());
}

#[test]
fn test_entity_factory_qos_builder_with_struct() {
    // Create QoS using EntityFactory struct
    let qos = QoS::best_effort().entity_factory(EntityFactory::manual_enable());

    assert!(!qos.entity_factory.autoenable_created_entities);
    assert!(qos.entity_factory.is_manual_enable());
}

#[test]
fn test_entity_factory_qos_default() {
    // Default QoS should have auto-enable
    let qos = QoS::default();

    assert!(qos.entity_factory.autoenable_created_entities);
    assert!(qos.entity_factory.is_auto_enable());
}

#[test]
fn test_entity_factory_struct_auto_enable() {
    let factory = EntityFactory::auto_enable();
    assert!(factory.autoenable_created_entities);
    assert!(factory.is_auto_enable());
}

#[test]
fn test_entity_factory_struct_manual_enable() {
    let factory = EntityFactory::manual_enable();
    assert!(!factory.autoenable_created_entities);
    assert!(factory.is_manual_enable());
}

#[test]
fn test_entity_factory_struct_default() {
    let factory = EntityFactory::default();
    assert!(factory.autoenable_created_entities);
    assert!(factory.is_auto_enable());
}

// ============================================================================
// Builder chaining tests
// ============================================================================

#[test]
fn test_qos_entity_factory_builder_chaining() {
    // Test that ENTITY_FACTORY can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5)
        .entity_factory_manual_enable();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(matches!(
        qos.durability,
        hdds::api::Durability::TransientLocal
    ));
    assert!(matches!(qos.history, hdds::api::History::KeepLast(50)));
    assert_eq!(qos.deadline.period, Duration::from_millis(100));
    assert_eq!(qos.lifespan.duration, Duration::from_secs(5));
    assert!(!qos.entity_factory.autoenable_created_entities);
}

#[test]
fn test_entity_factory_with_best_effort() {
    // ENTITY_FACTORY works with best-effort reliability
    let qos = QoS::best_effort().entity_factory_manual_enable();

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert!(qos.entity_factory.is_manual_enable());
}

#[test]
fn test_entity_factory_with_reliable() {
    // ENTITY_FACTORY works with reliable reliability
    let qos = QoS::reliable().entity_factory_auto_enable();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert!(qos.entity_factory.is_auto_enable());
}

// ============================================================================
// Use case tests
// ============================================================================

#[test]
fn test_use_case_simple_app_auto_enable() {
    // Simple applications: auto-enable for ease of use
    let qos = QoS::best_effort().entity_factory_auto_enable();

    assert!(qos.entity_factory.is_auto_enable());
    // Entities would be immediately ready after creation
}

#[test]
fn test_use_case_batch_configuration() {
    // Batch configuration: create multiple entities disabled, enable together
    let qos = QoS::reliable().entity_factory_manual_enable();

    assert!(qos.entity_factory.is_manual_enable());
    // Application would:
    // 1. Create multiple entities (disabled)
    // 2. Configure each entity
    // 3. Enable all at once
}

#[test]
fn test_use_case_testing_controlled_activation() {
    // Testing scenario: manual enable for controlled activation
    let qos = QoS::best_effort().entity_factory_manual_enable();

    assert!(qos.entity_factory.is_manual_enable());
    // Test framework would:
    // 1. Create entities disabled
    // 2. Set up test conditions
    // 3. Enable entities to start test
}

#[test]
fn test_use_case_performance_optimization() {
    // Performance optimization: batch enable to reduce discovery overhead
    let qos = QoS::reliable()
        .transient_local()
        .entity_factory_manual_enable();

    assert!(qos.entity_factory.is_manual_enable());
    // Application creates N entities disabled (no discovery), then enables all
}

#[test]
fn test_use_case_atomic_system_startup() {
    // Atomic system startup: ensure all components start together
    let qos = QoS::reliable().entity_factory_manual_enable();

    assert!(qos.entity_factory.is_manual_enable());
    // Robot controller example:
    // 1. Create sensor readers (disabled)
    // 2. Create actuator writers (disabled)
    // 3. Enable all at once (atomic start)
}

// ============================================================================
// Participant smoke tests
// ============================================================================

#[test]
fn test_participant_with_entity_factory_qos() {
    // Verify participant can be created with ENTITY_FACTORY QoS (smoke test)
    let participant = Participant::builder("entity_factory_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until entity enable/disable is fully integrated
    // In the future, this will test:
    // 1. Creating entities with autoenable_created_entities=false
    // 2. Verifying entities are in disabled state
    // 3. Explicitly enabling entities
    // 4. Verifying entities transition to enabled state

    drop(participant);
}

// ============================================================================
// Clone and equality tests
// ============================================================================

#[test]
fn test_entity_factory_clone() {
    let qos1 = QoS::best_effort().entity_factory_manual_enable();
    let qos2 = qos1.clone();

    assert_eq!(
        qos2.entity_factory.autoenable_created_entities,
        qos1.entity_factory.autoenable_created_entities
    );
}

#[test]
fn test_entity_factory_equality() {
    let factory1 = EntityFactory::auto_enable();
    let factory2 = EntityFactory::auto_enable();
    let factory3 = EntityFactory::manual_enable();

    assert_eq!(factory1, factory2);
    assert_ne!(factory1, factory3);
}

#[test]
fn test_entity_factory_debug() {
    let factory = EntityFactory::auto_enable();
    let debug_str = format!("{:?}", factory);
    assert!(debug_str.contains("EntityFactory"));
    assert!(debug_str.contains("autoenable_created_entities"));
}

// ============================================================================
// Edge cases and combinations
// ============================================================================

#[test]
fn test_entity_factory_toggle() {
    // Toggle between auto and manual
    let qos1 = QoS::best_effort().entity_factory_auto_enable();
    let qos2 = qos1.entity_factory_manual_enable();
    let qos3 = qos2.entity_factory_auto_enable();

    assert!(qos3.entity_factory.is_auto_enable());
}

#[test]
fn test_entity_factory_with_all_qos_policies() {
    // Combine ENTITY_FACTORY with all other QoS policies
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
        .entity_factory_manual_enable();

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
}

#[test]
fn test_entity_factory_copy_semantics() {
    let factory1 = EntityFactory::manual_enable();
    let factory2 = factory1; // Copy, not move
    assert_eq!(factory1, factory2);
}

// ============================================================================
// Behavior tests: Deferred
// ============================================================================
//
// TODO: ENTITY_FACTORY behavior tests are deferred.
// ENTITY_FACTORY controls whether entities are auto-enabled at creation.
// The entity enable/disable API is not yet fully integrated.
// Once integrated, add tests for:
// 1. Creating writer with manual_enable, verifying it does not participate
//    in discovery or data exchange until explicitly enabled
// 2. Enabling the entity and verifying data flows
// 3. Batch creation pattern: create multiple entities disabled, enable all
//
// For now, these tests validate the QoS API surface only.
