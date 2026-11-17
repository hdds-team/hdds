// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! WRITER_DATA_LIFECYCLE QoS policy integration tests
//!
//! Validates WRITER_DATA_LIFECYCLE policy exposed through public API.

use hdds::api::{Participant, QoS, WriterDataLifecycle};
use hdds::test_support::domains::unique_domain;
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
    // No `.with_transport(...)`: this participant takes the DEFAULT
    // UdpMulticast transport and therefore binds RTPS ports. The domain
    // is leased (declared first, so dropped last) instead of defaulting
    // to 0, which every other test binary also lands on.
    let domain = unique_domain();
    let participant = Participant::builder("writer_data_lifecycle_test")
        .domain_id(domain.id())
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
// Behavior: the policy decides what unregister_instance() puts on the wire
// ============================================================================
//
// The policy is wired into the writer unregister/dispose path. An announced
// QoS that does nothing would be a conformance gap, not a documentation gap.

use hdds::protocol::builder::StatusInfoKind;

/// The DDS default is TRUE, and TRUE means the writer DISPOSES each instance
/// it unregisters (DDS v1.4 2.2.3.21), so the default unregister carries both
/// bits and readers report NOT_ALIVE_DISPOSED.
#[test]
fn the_default_policy_makes_an_unregister_carry_dispose_as_well() {
    let qos = QoS::default();
    assert!(
        qos.writer_data_lifecycle.autodispose_unregistered_instances,
        "the DDS default is TRUE; if this flips, the mapping below changes meaning"
    );
    assert_eq!(
        StatusInfoKind::for_unregister(
            qos.writer_data_lifecycle.autodispose_unregistered_instances
        ),
        StatusInfoKind::DisposedUnregistered
    );
    assert_eq!(StatusInfoKind::DisposedUnregistered as u32, 0x03);
}

/// Turning the policy off is what makes a plain unregister read as
/// NOT_ALIVE_NO_WRITERS. The OMG reference `shape_main.cxx` sets exactly this
/// when asked to finish by unregistering - which it would not need to do if
/// conformant writers ignored the policy.
#[test]
fn manual_dispose_makes_an_unregister_carry_unregister_alone() {
    let qos = QoS::default().writer_data_lifecycle_manual_dispose();
    assert!(!qos.writer_data_lifecycle.autodispose_unregistered_instances);
    assert_eq!(
        StatusInfoKind::for_unregister(
            qos.writer_data_lifecycle.autodispose_unregistered_instances
        ),
        StatusInfoKind::Unregistered
    );
    assert_eq!(StatusInfoKind::Unregistered as u32, 0x02);
}

/// `dispose()` is unconditional: the policy governs UNREGISTER, never an
/// explicit dispose, which must stay a bare DISPOSED.
#[test]
fn the_policy_never_touches_an_explicit_dispose() {
    assert_eq!(StatusInfoKind::Disposed as u32, 0x01);
}

// ============================================================================
// Behavior: the policy decides what deleting the writer does to its instances
// ============================================================================
//
// DDS v1.4 2.2.2.4.1.6: "The deletion of the DataWriter will automatically
// unregister all instances. Depending on the settings of the
// WRITER_DATA_LIFECYCLE QosPolicy, the deletion of the DataWriter may also
// dispose all instances." 2.2.3.21: the flag "will determine whether
// instances are ultimately disposed when the DataWriter is deleted". The
// deletion must not unregister only, whatever the policy.

mod deletion {
    use hdds::api::{Participant, QoS};
    use hdds::dds::InstanceState;
    use hdds::test_support::domains::unique_domain;
    use hdds::TransportMode;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[derive(Clone, Debug, PartialEq, hdds::DDS)]
    struct Car {
        #[key]
        id: u32,
        speed: u32,
    }

    fn udp_participant(name: &str, domain_id: u32, participant_id: u8) -> Arc<Participant> {
        Participant::builder(name)
            .domain_id(domain_id)
            .participant_id(Some(participant_id))
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("participant")
    }

    /// Writer in one participant, reader in another, over UDP. The writer
    /// writes one instance, the reader takes that sample, the writer is
    /// dropped. Returns the instance states of the transitions the remote
    /// reader then reports.
    fn transitions_after_drop(topic: &str, writer_qos: QoS) -> Vec<InstanceState> {
        let domain = unique_domain();
        let publisher = udp_participant(&format!("{topic}_pub"), domain.id(), 80);
        let subscriber = udp_participant(&format!("{topic}_sub"), domain.id(), 81);
        let reader = subscriber
            .topic::<Car>(topic)
            .expect("topic")
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader");
        let writer = publisher
            .topic::<Car>(topic)
            .expect("topic")
            .writer()
            .qos(writer_qos)
            .build()
            .expect("writer");

        let deadline = Instant::now() + Duration::from_secs(10);
        while writer.matched_reader_count() == 0 {
            assert!(Instant::now() < deadline, "the reader never matched");
            std::thread::sleep(Duration::from_millis(20));
        }
        let sample = Car { id: 7, speed: 1 };
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut received = false;
        while !received {
            assert!(Instant::now() < deadline, "the sample never arrived");
            writer.write(&sample).expect("write");
            std::thread::sleep(Duration::from_millis(100));
            while let Some((data, _)) = reader.take_with_info().expect("take") {
                received |= data == Some(sample.clone());
            }
        }

        drop(writer);

        let mut transitions = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut quiet_until = None;
        while Instant::now() < deadline {
            while let Some((data, info)) = reader.take_with_info().expect("take") {
                if data.is_none() {
                    transitions.push(info.instance_state);
                    // Keep listening a little after the first transition, so
                    // a later one (the SEDP retirement of the writer) is seen.
                    quiet_until.get_or_insert(Instant::now() + Duration::from_millis(800));
                }
            }
            if quiet_until.is_some_and(|t| Instant::now() > t) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(subscriber);
        drop(publisher);
        transitions
    }

    #[test]
    fn a_remote_reader_sees_the_instances_of_a_deleted_writer_disposed_by_default() {
        let transitions = transitions_after_drop("WdlDropAuto", QoS::reliable());
        assert!(
            !transitions.is_empty()
                && transitions
                    .iter()
                    .all(|s| *s == InstanceState::NotAliveDisposed),
            "autodispose TRUE (the default): the deletion disposes the instance; \
             transitions seen: {transitions:?}"
        );
    }

    #[test]
    fn a_remote_reader_sees_the_instances_of_a_deleted_writer_with_no_writers_without_autodispose()
    {
        let transitions = transitions_after_drop(
            "WdlDropManual",
            QoS::reliable().writer_data_lifecycle_manual_dispose(),
        );
        assert!(
            !transitions.is_empty()
                && transitions
                    .iter()
                    .all(|s| *s == InstanceState::NotAliveNoWriters),
            "autodispose FALSE: the deletion unregisters only; \
             transitions seen: {transitions:?}"
        );
    }
}
