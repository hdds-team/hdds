// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `DURABILITY_SERVICE` `QoS` policy integration tests
//!
//! Validates `DURABILITY_SERVICE` policy exposed through public API.

use hdds::api::{DurabilityService, Participant, QoS};
use hdds::qos::durability_service::LENGTH_UNLIMITED;
use hdds::test_support::domains::unique_domain;
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
    // DDS v1.4 defaults: the three limits are LENGTH_UNLIMITED (-1).
    assert_eq!(qos.durability_service.max_samples, LENGTH_UNLIMITED);
    assert_eq!(qos.durability_service.max_instances, LENGTH_UNLIMITED);
    assert_eq!(
        qos.durability_service.max_samples_per_instance,
        LENGTH_UNLIMITED
    );
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
    assert_eq!(service.max_samples, LENGTH_UNLIMITED);
    assert_eq!(service.max_instances, LENGTH_UNLIMITED);
    assert_eq!(service.max_samples_per_instance, LENGTH_UNLIMITED);
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
    // DDS v1.4 2.2.3.19: max_samples >= max_samples_per_instance.
    let service = DurabilityService {
        max_samples: 5,
        max_instances: 5,
        max_samples_per_instance: 10,
        ..Default::default()
    };
    assert!(service.validate().is_err());
    assert!(service.validate().unwrap_err().contains("max_samples"));

    // No rule on max_instances * max_samples_per_instance in the spec: this
    // setting is legal (it must not be refused).
    let service = DurabilityService {
        max_samples: 10,
        max_instances: 5,
        max_samples_per_instance: 10,
        ..Default::default()
    };
    assert!(service.validate().is_ok());
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
        .durability_service_keep_last(1000, 100000, 100, 1000);

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
    // No `.with_transport(...)`: this participant takes the DEFAULT
    // UdpMulticast transport and therefore binds RTPS ports. The domain
    // is leased (declared first, so dropped last) instead of defaulting
    // to 0, which every other test binary also lands on.
    let domain = unique_domain();
    let participant = Participant::builder("durability_service_test")
        .domain_id(domain.id())
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
// Behavior tests: service_cleanup_delay (DDS v1.4 Sec.2.2.3.5)
// ============================================================================
//
// 1 and 3 (a late joiner receiving the replay, and the resource limits) are
// covered where a real writer and reader already exist: see
// crates/hdds/tests/transient_local_late_joiner.rs and
// crates/hdds/src/dds/writer/durability_service_tests.rs's max_samples /
// max_instances / max_samples_per_instance tests. This covers the cleanup
// timer's own rule: an instance's information is removed only once it has
// been explicitly disposed, no live writer still claims it, AND the delay
// has elapsed since -- never merely "every reader has acknowledged it".

// A @key field, deliberately: an unkeyed write() journals with
// `metadata.key_hash = None` (`T::has_key()` gates it) while
// `dispose`/`unregister_instance` always journal
// `key_hash = Some(instance.compute_key())` -- for an unkeyed type that
// is `Some([0; 16])`, a DIFFERENT `InstanceId` from the plain write's
// `Legacy(0)`. That mismatch (found writing this test, left as is: a
// pre-existing inconsistency in write()/dispose()'s own instance
// identity for unkeyed topics, out of scope here) would make the
// cleanup rule's "latest entry per instance" never see the write and
// the dispose as the same instance. A keyed type sidesteps it.
#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct CleanupProbe {
    #[key]
    id: u32,
    value: f32,
}

/// Poll until a real SEDP match lands, so a following
/// `wait_for_acknowledgments` call waits for a real ACKNACK instead of
/// racing discovery -- `fully_acked` is vacuously true before any reader
/// has matched (nothing tracked yet), by its own doc contract.
fn wait_for_match<T: hdds::DdsTrait>(writer: &hdds::api::DataWriter<T>) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while writer.matched_reader_count() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "no reader matched within 5s"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// TRANSIENT (the persistence-service durability `service_cleanup_delay`
/// actually governs, DDS v1.4 Sec.2.2.3.5): a disposed-and-unregistered
/// instance -- the DDS default autodispose lifecycle, so one plain
/// `unregister_instance` call carries both bits -- that every matched
/// RELIABLE reader has acknowledged is swept once the delay elapses. A
/// real late-joining DataReader created afterward gets nothing for it.
#[test]
fn test_transient_cleanup_removes_a_disposed_instance_after_the_delay() {
    use hdds::api::{DurabilityService, Participant, QoS};
    use hdds::test_support::domains::unique_domain;
    use std::thread;
    use std::time::Duration;

    // Two SEPARATE participants on the same domain, not two endpoints of
    // one: a same-participant pair never exercises the real wire ACKNACK
    // path this test needs (found while writing it; see
    // `wait_for_match`'s doc).
    let domain = unique_domain();
    let writer_participant = Participant::builder("transient_cleanup_delay_writer")
        .domain_id(domain.id())
        .participant_id(Some(1))
        .build()
        .expect("Failed to create writer participant");
    let reader_participant = Participant::builder("transient_cleanup_delay_reader")
        .domain_id(domain.id())
        .participant_id(Some(2))
        .build()
        .expect("Failed to create reader participant");

    let delay_us: u64 = 50_000;
    let writer = writer_participant
        .topic::<CleanupProbe>("TransientCleanupDelayTopic")
        .expect("Failed to create topic")
        .writer()
        .qos(
            QoS::reliable()
                .transient()
                .keep_last(5)
                .durability_service(DurabilityService {
                    service_cleanup_delay_us: delay_us,
                    ..Default::default()
                }),
        )
        .build()
        .expect("Failed to create writer");

    let sample = CleanupProbe { id: 1, value: 1.0 };
    writer.write(&sample).expect("write");

    let reader = reader_participant
        .topic::<CleanupProbe>("TransientCleanupDelayTopic")
        .expect("Failed to create topic")
        .reader()
        .qos(QoS::reliable().keep_last(5))
        .build()
        .expect("Failed to create reader");

    // `wait_for_acknowledgments` is vacuously true before any reader has
    // MATCHED at all (nothing tracked to wait for yet, by its own
    // doc contract): wait for the real SEDP match first, so the calls
    // below wait for a real ACKNACK, not a race against discovery.
    wait_for_match(&writer);
    writer
        .wait_for_acknowledgments(Duration::from_secs(5))
        .expect("the reader acknowledges the write");

    writer.unregister_instance(&sample).expect("unregister");
    writer
        .wait_for_acknowledgments(Duration::from_secs(5))
        .expect("the reader acknowledges the unregister too");

    // The cleanup timer polls at delay/2; several multiples of the delay
    // past the acknowledged unregister is ample margin.
    thread::sleep(Duration::from_micros(delay_us) * 6);

    let late_joiner = reader_participant
        .topic::<CleanupProbe>("TransientCleanupDelayTopic")
        .expect("Failed to create topic")
        .reader()
        .qos(QoS::reliable().keep_last(5))
        .build()
        .expect("Failed to create late-joiner reader");
    late_joiner.bind_to_writer(writer.merger());
    thread::sleep(Duration::from_millis(100));

    let mut received = Vec::new();
    while let Ok(Some(s)) = late_joiner.take() {
        received.push(s);
    }
    assert!(
        received.is_empty(),
        "a disposed, unregistered, acknowledged instance past its \
         service_cleanup_delay must not reach a late joiner: got {received:?}"
    );
    let _ = &reader;
}

/// The negative case pinning the SAME rule from the other side: a plain
/// write (never disposed) past the very same delay, acknowledged the
/// same way, is NOT swept -- `service_cleanup_delay` alone is not
/// `remove_acknowledged`.
#[test]
fn test_transient_cleanup_leaves_an_undisposed_instance_alone() {
    use hdds::api::{DurabilityService, Participant, QoS};
    use hdds::test_support::domains::unique_domain;
    use std::thread;
    use std::time::Duration;

    let domain = unique_domain();
    let writer_participant = Participant::builder("transient_cleanup_no_dispose_writer")
        .domain_id(domain.id())
        .participant_id(Some(1))
        .build()
        .expect("Failed to create writer participant");
    let reader_participant = Participant::builder("transient_cleanup_no_dispose_reader")
        .domain_id(domain.id())
        .participant_id(Some(2))
        .build()
        .expect("Failed to create reader participant");

    let delay_us: u64 = 50_000;
    let writer = writer_participant
        .topic::<CleanupProbe>("TransientCleanupNoDisposeTopic")
        .expect("Failed to create topic")
        .writer()
        .qos(
            QoS::reliable()
                .transient()
                .keep_last(5)
                .durability_service(DurabilityService {
                    service_cleanup_delay_us: delay_us,
                    ..Default::default()
                }),
        )
        .build()
        .expect("Failed to create writer");

    let sample = CleanupProbe { id: 2, value: 2.0 };
    writer.write(&sample).expect("write");

    let reader = reader_participant
        .topic::<CleanupProbe>("TransientCleanupNoDisposeTopic")
        .expect("Failed to create topic")
        .reader()
        .qos(QoS::reliable().keep_last(5))
        .build()
        .expect("Failed to create reader");
    wait_for_match(&writer);
    writer
        .wait_for_acknowledgments(Duration::from_secs(5))
        .expect("the reader acknowledges the write");

    thread::sleep(Duration::from_micros(delay_us) * 6);

    let late_joiner = reader_participant
        .topic::<CleanupProbe>("TransientCleanupNoDisposeTopic")
        .expect("Failed to create topic")
        .reader()
        .qos(QoS::reliable().keep_last(5))
        .build()
        .expect("Failed to create late-joiner reader");
    late_joiner.bind_to_writer(writer.merger());
    thread::sleep(Duration::from_millis(100));

    let mut received = Vec::new();
    while let Ok(Some(s)) = late_joiner.take() {
        received.push(s);
    }
    assert_eq!(
        received.len(),
        1,
        "never disposed: service_cleanup_delay alone must not remove it"
    );
    let _ = reader;
}
