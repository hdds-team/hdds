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

//! PRESENTATION QoS policy integration tests
//!
//! Validates PRESENTATION policy exposed through public API.

use hdds::api::{Participant, Presentation, PresentationAccessScope, QoS};
use std::time::Duration;

#[test]
fn test_presentation_qos_builder_instance() {
    // Create QoS with PRESENTATION INSTANCE scope
    let qos = QoS::best_effort().presentation_instance();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Instance
    );
    assert!(!qos.presentation.coherent_access);
    assert!(!qos.presentation.ordered_access);
    assert!(qos.presentation.is_instance_scope());
}

#[test]
fn test_presentation_qos_builder_topic_coherent() {
    // Create QoS with PRESENTATION TOPIC coherent
    let qos = QoS::best_effort().presentation_topic_coherent();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Topic
    );
    assert!(qos.presentation.coherent_access);
    assert!(!qos.presentation.ordered_access);
    assert!(qos.presentation.is_topic_scope());
}

#[test]
fn test_presentation_qos_builder_topic_ordered() {
    // Create QoS with PRESENTATION TOPIC ordered
    let qos = QoS::best_effort().presentation_topic_ordered();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Topic
    );
    assert!(!qos.presentation.coherent_access);
    assert!(qos.presentation.ordered_access);
    assert!(qos.presentation.is_topic_scope());
}

#[test]
fn test_presentation_qos_builder_group_coherent() {
    // Create QoS with PRESENTATION GROUP coherent
    let qos = QoS::best_effort().presentation_group_coherent();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Group
    );
    assert!(qos.presentation.coherent_access);
    assert!(!qos.presentation.ordered_access);
    assert!(qos.presentation.is_group_scope());
}

#[test]
fn test_presentation_qos_builder_group_coherent_ordered() {
    // Create QoS with PRESENTATION GROUP coherent and ordered
    let qos = QoS::best_effort().presentation_group_coherent_ordered();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Group
    );
    assert!(qos.presentation.coherent_access);
    assert!(qos.presentation.ordered_access);
    assert!(qos.presentation.is_group_scope());
}

#[test]
fn test_presentation_qos_builder_struct() {
    // Create QoS with Presentation struct
    let presentation = Presentation::topic_coherent();
    let qos = QoS::best_effort().presentation(presentation);

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Topic
    );
    assert!(qos.presentation.coherent_access);
}

#[test]
fn test_presentation_qos_default() {
    // Default QoS should have INSTANCE scope
    let qos = QoS::default();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Instance
    );
    assert!(!qos.presentation.coherent_access);
    assert!(!qos.presentation.ordered_access);
}

#[test]
fn test_presentation_struct_instance() {
    let presentation = Presentation::instance();
    assert_eq!(presentation.access_scope, PresentationAccessScope::Instance);
    assert!(!presentation.coherent_access);
    assert!(!presentation.ordered_access);
}

#[test]
fn test_presentation_struct_topic_coherent() {
    let presentation = Presentation::topic_coherent();
    assert_eq!(presentation.access_scope, PresentationAccessScope::Topic);
    assert!(presentation.coherent_access);
    assert!(!presentation.ordered_access);
}

#[test]
fn test_presentation_struct_group_coherent_ordered() {
    let presentation = Presentation::group_coherent_ordered();
    assert_eq!(presentation.access_scope, PresentationAccessScope::Group);
    assert!(presentation.coherent_access);
    assert!(presentation.ordered_access);
}

#[test]
fn test_presentation_access_scope_default() {
    let scope = PresentationAccessScope::default();
    assert_eq!(scope, PresentationAccessScope::Instance);
}

#[test]
fn test_participant_with_presentation_qos() {
    // Verify participant can be created with PRESENTATION QoS (smoke test)
    let participant = Participant::builder("presentation_test")
        .build()
        .expect("Failed to create participant");

    // This is a placeholder until Reader integration is complete
    // In the future, this will test:
    // 1. Reader creation with PRESENTATION QoS
    // 2. Coherent access enforcement
    // 3. Transactional updates across topics

    drop(participant);
}

#[test]
fn test_qos_presentation_builder_chaining() {
    // Test that PRESENTATION can be combined with other QoS policies
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(50)
        .deadline_millis(100)
        .lifespan_secs(5)
        .time_based_filter_millis(50)
        .destination_order_by_source()
        .presentation_group_coherent_ordered();

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
        PresentationAccessScope::Group
    );
    assert!(qos.presentation.coherent_access);
    assert!(qos.presentation.ordered_access);
}

#[test]
fn test_presentation_with_best_effort() {
    // PRESENTATION works with best-effort reliability
    let qos = QoS::best_effort().presentation_topic_coherent();

    assert!(matches!(
        qos.reliability,
        hdds::api::Reliability::BestEffort
    ));
    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Topic
    );
}

#[test]
fn test_presentation_with_reliable() {
    // PRESENTATION works with reliable reliability
    let qos = QoS::reliable().presentation_group_coherent();

    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Group
    );
}

#[test]
fn test_presentation_clone() {
    let qos1 = QoS::best_effort().presentation_group_coherent_ordered();
    let qos2 = qos1.clone();

    assert_eq!(
        qos2.presentation.access_scope,
        PresentationAccessScope::Group
    );
    assert!(qos2.presentation.coherent_access);
    assert!(qos2.presentation.ordered_access);
}

#[test]
fn test_presentation_default_value() {
    // Edge case: default PRESENTATION
    let presentation = Presentation::default();
    let qos = QoS::best_effort().presentation(presentation);

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Instance
    );
    assert!(!qos.presentation.coherent_access);
}

#[test]
fn test_presentation_use_case_independent_sensors() {
    // Real-time sensor data: INSTANCE scope (independent)
    let qos = QoS::best_effort().presentation_instance();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Instance
    );
    assert!(!qos.presentation.coherent_access);
}

#[test]
fn test_presentation_use_case_robot_joints() {
    // Robot joint states: TOPIC coherent (all joints updated together)
    let qos = QoS::best_effort().presentation_topic_coherent();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Topic
    );
    assert!(qos.presentation.coherent_access);
}

#[test]
fn test_presentation_use_case_pose_velocity() {
    // Pose + velocity: GROUP coherent ordered (transactional update)
    let qos = QoS::reliable().presentation_group_coherent_ordered();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Group
    );
    assert!(qos.presentation.coherent_access);
    assert!(qos.presentation.ordered_access);
    assert!(matches!(qos.reliability, hdds::api::Reliability::Reliable));
}

#[test]
fn test_presentation_use_case_financial_transaction() {
    // Financial transaction (debit + credit): GROUP coherent
    let qos = QoS::reliable().presentation_group_coherent();

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Group
    );
    assert!(qos.presentation.coherent_access);
}

#[test]
fn test_presentation_access_scope_equality() {
    let scope1 = PresentationAccessScope::Topic;
    let scope2 = PresentationAccessScope::Topic;
    let scope3 = PresentationAccessScope::Instance;

    assert_eq!(scope1, scope2);
    assert_ne!(scope1, scope3);
}

#[test]
fn test_presentation_equality() {
    let pres1 = Presentation::topic_coherent();
    let pres2 = Presentation::topic_coherent();
    let pres3 = Presentation::topic_ordered();

    assert_eq!(pres1, pres2);
    assert_ne!(pres1, pres3);
}

#[test]
fn test_presentation_access_scope_ordering() {
    // INSTANCE (0) < TOPIC (1) < GROUP (2)
    assert!(PresentationAccessScope::Instance < PresentationAccessScope::Topic);
    assert!(PresentationAccessScope::Topic < PresentationAccessScope::Group);
    assert!(PresentationAccessScope::Instance < PresentationAccessScope::Group);
}

#[test]
fn test_presentation_custom_new() {
    let presentation = Presentation::new(
        PresentationAccessScope::Topic,
        true, /* coherent */
        true, /* ordered */
    );
    let qos = QoS::best_effort().presentation(presentation);

    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Topic
    );
    assert!(qos.presentation.coherent_access);
    assert!(qos.presentation.ordered_access);
}

#[test]
fn test_presentation_scope_helpers() {
    let instance = Presentation::instance();
    let topic = Presentation::topic_coherent();
    let group = Presentation::group_coherent();

    assert!(instance.is_instance_scope());
    assert!(!instance.is_topic_scope());
    assert!(!instance.is_group_scope());

    assert!(!topic.is_instance_scope());
    assert!(topic.is_topic_scope());
    assert!(!topic.is_group_scope());

    assert!(!group.is_instance_scope());
    assert!(!group.is_topic_scope());
    assert!(group.is_group_scope());
}

#[test]
fn test_presentation_combined_with_destination_order() {
    // PRESENTATION and DESTINATION_ORDER can coexist
    let qos = QoS::best_effort()
        .destination_order_by_source()
        .presentation_topic_coherent();

    assert_eq!(
        qos.destination_order.kind,
        hdds::api::DestinationOrderKind::BySourceTimestamp
    );
    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Topic
    );
    assert!(qos.presentation.coherent_access);
}

#[test]
fn test_presentation_combined_with_lifespan() {
    // PRESENTATION and Lifespan can coexist
    let qos = QoS::best_effort()
        .lifespan_secs(10)
        .presentation_group_coherent();

    assert_eq!(qos.lifespan.duration, Duration::from_secs(10));
    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Group
    );
}

#[test]
fn test_presentation_combined_with_time_based_filter() {
    // PRESENTATION and TIME_BASED_FILTER can coexist
    let qos = QoS::best_effort()
        .time_based_filter_millis(100)
        .presentation_topic_ordered();

    assert_eq!(
        qos.time_based_filter.minimum_separation,
        Duration::from_millis(100)
    );
    assert_eq!(
        qos.presentation.access_scope,
        PresentationAccessScope::Topic
    );
    assert!(qos.presentation.ordered_access);
}

// ============================================================================
// Behavior tests: Deferred
// ============================================================================
//
// TODO: PRESENTATION behavior tests are deferred.
// PRESENTATION QoS (coherent_access, ordered_access, access_scope)
// is not yet wired into the DataReader/DataWriter delivery path.
// Once integrated, add tests for:
// 1. TOPIC coherent: writer publishes a coherent set, reader receives atomically
// 2. GROUP coherent: updates across multiple topics delivered as a set
// 3. ordered_access: samples within a scope delivered in order
//
// For now, these tests validate the QoS API surface only.
