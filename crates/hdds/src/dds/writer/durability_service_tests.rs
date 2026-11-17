// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Integration tests for DurabilityService QoS wired into writer + SEDP.
//!
//! Tests cover:
//! - Writer respects max_samples
//! - Writer respects max_instances
//! - Writer respects max_samples_per_instance
//! - Cleanup timer removes old acknowledged samples
//! - Late-joiner gets correct history subset
//! - SEDP includes PID_DURABILITY_SERVICE
//! - DurabilityService only active when durability >= TRANSIENT_LOCAL
//! - LENGTH_UNLIMITED means no limit
//! - SEDP roundtrip (serialize + deserialize)

use crate::core::rt::slabpool::SlabPool;
use crate::qos::History;
use crate::reliability::{HistoryCache, LENGTH_UNLIMITED};
use std::sync::Arc;

// =============================================================================
// Test 1: Writer respects max_samples
// =============================================================================
#[test]
fn test_durability_service_max_samples() {
    let pool = Arc::new(SlabPool::new());
    let max_samples = 20;

    let cache = HistoryCache::new_with_durability_service_limits(
        pool,
        max_samples,
        10_000_000,
        History::KeepLast(u32::try_from(max_samples).expect("test constant fits u32")),
        LENGTH_UNLIMITED,
        LENGTH_UNLIMITED,
    );

    // Write 100 samples
    for i in 1..=100u64 {
        cache
            .insert(i, b"test payload data")
            .expect("insert should succeed");
    }

    // Only max_samples should be retained
    assert_eq!(
        cache.len(),
        max_samples,
        "cache should retain only max_samples"
    );
    assert_eq!(
        cache.oldest_seq(),
        Some(81),
        "oldest should be 81 (100 - 20 + 1)"
    );
    assert_eq!(cache.newest_seq(), Some(100), "newest should be 100");
}

// =============================================================================
// Test 2: Writer respects max_instances
// =============================================================================
#[test]
fn test_durability_service_max_instances() {
    let pool = Arc::new(SlabPool::new());
    let max_instances = 3;

    let cache = HistoryCache::new_with_durability_service_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
        max_instances,
        LENGTH_UNLIMITED,
    );

    // Write samples for 5 different instances. The first three fit; a new
    // instance beyond max_instances is refused (DDS 1.4 2.2.2.4.2.11:
    // OUT_OF_RESOURCES when waiting cannot free the resource). It must NOT
    // evict an instance already stored, or the late joiner would lose whole
    // instances.
    for instance in 1..=5u64 {
        for sample in 1..=3u64 {
            let seq = (instance - 1) * 3 + sample;
            let result = cache.insert_keyed(seq, b"test payload", instance);
            if instance <= 3 {
                result.expect("an instance within max_instances is stored");
            } else {
                assert!(
                    matches!(result, Err(crate::Error::ResourceLimitExceeded(_))),
                    "instance {instance} beyond max_instances must be refused, got {result:?}"
                );
            }
        }
    }

    assert_eq!(cache.instance_count(), max_instances);
    for instance in 1..=3u64 {
        assert_eq!(
            cache.samples_for_instance(instance),
            3,
            "instance {instance} keeps every sample"
        );
    }
}

// =============================================================================
// Test 3: Writer respects max_samples_per_instance
// =============================================================================
#[test]
fn test_durability_service_max_samples_per_instance() {
    let pool = Arc::new(SlabPool::new());
    let max_spi = 5;

    let cache = HistoryCache::new_with_durability_service_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
        LENGTH_UNLIMITED,
        max_spi,
    );

    // Write 20 samples for the same instance
    for i in 1..=20u64 {
        cache
            .insert_keyed(i, b"test payload", 42)
            .expect("insert should succeed");
    }

    // Should only retain max_samples_per_instance for that instance
    let instance_samples = cache.samples_for_instance(42);
    assert!(
        instance_samples <= max_spi,
        "samples for instance 42 ({}) should be <= max_samples_per_instance ({})",
        instance_samples,
        max_spi
    );
}

// =============================================================================
// Test 4: the cleanup timer's rule (DDS v1.4 Sec.2.2.3.5) -- disposed,
// no live writer, acknowledged, AND the delay elapsed; never merely
// "acknowledged"
// =============================================================================

/// `HistoryCache::remove_durability_expired` directly: the three spec
/// conditions, each checked from both sides. An instance whose latest
/// change is NOT `StatusInfoKind::DisposedUnregistered` (disposed AND no
/// live writer, both at once for a single-writer history) is never
/// touched, however acked or old; one that IS is removed only once it is
/// also acked through AND old enough.
#[test]
fn test_durability_service_cleanup_rule_needs_all_three_conditions() {
    use crate::protocol::builder::StatusInfoKind;
    use crate::reliability::ChangeMetadata;
    use crate::telemetry::metrics::current_time_ns;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
    ));
    cache.enable_durability_cleanup();

    // Instance 1: a sample, then disposed+unregistered (the DDS default
    // autodispose lifecycle: one unregister carries both bits at once).
    cache
        .insert_with_metadata(1, b"inst1-data", 1, ChangeMetadata::user_data())
        .expect("insert");
    cache
        .insert_with_metadata(
            2,
            b"",
            1,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::DisposedUnregistered),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert the disposing end");
    // Instance 2: a sample, never disposed.
    cache
        .insert_with_metadata(3, b"inst2-data", 2, ChangeMetadata::user_data())
        .expect("insert");

    let now = current_time_ns();

    // Not yet acknowledged: nothing is removed, however expired the delay.
    assert_eq!(
        cache.remove_durability_expired(0, 0, now),
        0,
        "unacknowledged changes are never swept"
    );

    // Acknowledged, but the delay has not elapsed: nothing is removed.
    assert_eq!(
        cache.remove_durability_expired(3, u64::MAX / 2, now),
        0,
        "the delay has not elapsed yet"
    );

    // Acknowledged AND the delay has elapsed (delay 0): instance 1's two
    // changes go; instance 2, never disposed, is untouched.
    let removed = cache.remove_durability_expired(3, 0, current_time_ns());
    assert_eq!(
        removed, 2,
        "instance 1's sample and its own disposing end, both removed"
    );
    assert!(cache.get_change(1).is_none(), "instance 1's sample is gone");
    assert!(
        cache.get_change(2).is_none(),
        "instance 1's disposing end is gone too"
    );
    assert!(
        cache.get_change(3).is_some(),
        "instance 2 was never disposed: left alone"
    );
}

/// A bare `Disposed` (no unregister) or a bare `Unregistered` (no
/// dispose) each satisfy only one of the spec's two instance conditions:
/// neither sweeps on its own, whatever the ack/delay state.
#[test]
fn test_durability_service_cleanup_rule_rejects_a_partial_lifecycle() {
    use crate::protocol::builder::StatusInfoKind;
    use crate::reliability::ChangeMetadata;
    use crate::telemetry::metrics::current_time_ns;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
    ));
    cache.enable_durability_cleanup();

    cache
        .insert_with_metadata(
            1,
            b"",
            1,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::Disposed),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert disposed-only");
    cache
        .insert_with_metadata(
            2,
            b"",
            2,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::Unregistered),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert unregistered-only");

    let now = current_time_ns();
    assert_eq!(
        cache.remove_durability_expired(2, 0, now),
        0,
        "disposed-but-still-written and unregistered-but-not-disposed \
         each satisfy only one of the two instance conditions"
    );
}

/// `manual_dispose` (`WriterDataLifecycle::autodispose_unregistered_instances
/// == false`): `dispose()` then a LATER, SEPARATE `unregister_instance()`
/// journal two entries of ONE instance -- `Disposed`, then `Unregistered`
/// -- never the combined `DisposedUnregistered` bit in one change. DDS
/// v1.4 Sec.2.2.3.5's conditions are per INSTANCE, not per change: both
/// together, however far apart, make it eligible once acked and the
/// delay has elapsed since the LATER of the two.
#[test]
fn test_durability_service_cleanup_rule_sees_a_separate_dispose_then_unregister() {
    use crate::protocol::builder::StatusInfoKind;
    use crate::reliability::ChangeMetadata;
    use crate::telemetry::metrics::current_time_ns;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
    ));
    cache.enable_durability_cleanup();

    cache
        .insert_with_metadata(1, b"data", 1, ChangeMetadata::user_data())
        .expect("insert");
    cache
        .insert_with_metadata(
            2,
            b"",
            1,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::Disposed),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert the dispose, alone");
    cache
        .insert_with_metadata(
            3,
            b"",
            1,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::Unregistered),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert the unregister, separately, later");

    let removed = cache.remove_durability_expired(3, 0, current_time_ns());
    assert_eq!(
        removed, 3,
        "all three of this instance's changes go: disposed AND \
         unregistered, just never in the same change"
    );
}

/// A plain write after a dispose revives the instance (DDS v1.4
/// Sec.2.2.3.5's "no live writer" condition is no longer true): the
/// rule starts over, so a later unregister alone, paired with a dispose
/// that no longer counts, does not make it eligible.
#[test]
fn test_durability_service_cleanup_rule_a_write_after_dispose_revives_the_instance() {
    use crate::protocol::builder::StatusInfoKind;
    use crate::reliability::ChangeMetadata;
    use crate::telemetry::metrics::current_time_ns;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
    ));
    cache.enable_durability_cleanup();

    cache
        .insert_with_metadata(1, b"data", 1, ChangeMetadata::user_data())
        .expect("insert");
    cache
        .insert_with_metadata(
            2,
            b"",
            1,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::Disposed),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert the dispose");
    // The application writes to the instance again: it is alive once
    // more, and the dispose above no longer counts.
    cache
        .insert_with_metadata(3, b"revived", 1, ChangeMetadata::user_data())
        .expect("insert the revival");
    cache
        .insert_with_metadata(
            4,
            b"",
            1,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::Unregistered),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert the unregister");

    let removed = cache.remove_durability_expired(4, 0, current_time_ns());
    assert_eq!(
        removed, 0,
        "unregistered, but not disposed since the revival: only one of \
         the two conditions holds"
    );
}

/// The delay is measured from the LATER of the two timestamps, not the
/// earlier (DDS v1.4 Sec.2.2.3.5: "a time interval longer than
/// service_cleanup_delay has elapsed since the moment the service
/// detected that the previous two conditions were met" -- both,
/// together). A real clock sleep between the dispose and the
/// unregister, long enough that the EARLIER one alone would already
/// look expired against `delay_nanos`, while the LATER one does not.
#[test]
fn test_durability_service_cleanup_rule_measures_the_delay_from_the_later_timestamp() {
    use crate::protocol::builder::StatusInfoKind;
    use crate::reliability::ChangeMetadata;
    use crate::telemetry::metrics::current_time_ns;
    use std::time::Duration;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
    ));
    cache.enable_durability_cleanup();

    cache
        .insert_with_metadata(
            1,
            b"",
            1,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::Disposed),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert the dispose");
    std::thread::sleep(Duration::from_millis(80));
    cache
        .insert_with_metadata(
            2,
            b"",
            1,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::Unregistered),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert the unregister, 80ms later");

    // A delay that the dispose alone cleared 80ms ago, but the
    // unregister has not: using the earlier timestamp would sweep this
    // (wrongly); using the later one must not.
    let delay_nanos = Duration::from_millis(60).as_nanos() as u64;
    let removed = cache.remove_durability_expired(2, delay_nanos, current_time_ns());
    assert_eq!(
        removed, 0,
        "60ms have not elapsed since the LATER event (the unregister, \
         ~80ms younger than the dispose)"
    );
}

/// The cleanup timer thread itself, wired through `spawn_cleanup_timer`:
/// a disposed+unregistered, acknowledged instance is removed once the
/// configured delay elapses; one still short of it is not.
#[test]
fn test_durability_service_cleanup_timer_thread_honors_the_delay() {
    use super::cleanup_timer::spawn_cleanup_timer;
    use crate::protocol::builder::StatusInfoKind;
    use crate::reliability::ChangeMetadata;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
    ));
    cache.enable_durability_cleanup();
    cache
        .insert_with_metadata(1, b"data", 1, ChangeMetadata::user_data())
        .expect("insert");
    cache
        .insert_with_metadata(
            2,
            b"",
            1,
            ChangeMetadata {
                status_info: Some(StatusInfoKind::DisposedUnregistered),
                ..ChangeMetadata::user_data()
            },
        )
        .expect("insert the disposing end");

    let acked = Arc::new(AtomicU64::new(2));
    let for_timer = acked.clone();
    let delay = Duration::from_millis(60);
    let _handle = spawn_cleanup_timer(
        cache.clone(),
        Arc::new(move || for_timer.load(Ordering::Relaxed)),
        delay / 2,
        u64::try_from(delay.as_nanos()).expect("test delay fits u64 nanos"),
    )
    .expect("spawn cleanup timer");

    // Short of the delay: still there.
    std::thread::sleep(Duration::from_millis(20));
    assert!(
        cache.get_change(1).is_some(),
        "the delay has not elapsed yet"
    );

    // Past the delay, with margin for the timer's own poll interval.
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        cache.get_change(1).is_none(),
        "disposed, unregistered, acknowledged, and past the delay"
    );
}

// =============================================================================
// Test 5: Late-joiner gets correct history subset
// =============================================================================
#[test]
fn test_durability_service_late_joiner_replay() {
    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
    ));

    // Insert 50 samples
    for i in 1..=50u64 {
        cache
            .insert(i, format!("sample_{}", i).as_bytes())
            .expect("insert should succeed");
    }

    // Late joiner with DurabilityService.history_depth = 10 should only get last 10
    let replay_depth = 10;
    let replay_samples = cache.snapshot_payloads_limited(replay_depth);

    assert_eq!(
        replay_samples.len(),
        replay_depth,
        "late-joiner should get exactly replay_depth samples"
    );

    // Verify we got the most recent samples (41-50)
    assert_eq!(replay_samples[0].0, 41, "first replayed seq should be 41");
    assert_eq!(replay_samples[9].0, 50, "last replayed seq should be 50");
}

// =============================================================================
// Test 6: SEDP includes PID_DURABILITY_SERVICE
// =============================================================================
#[test]
fn test_sedp_includes_pid_durability_service() {
    use crate::core::discovery::GUID;
    use crate::dds::QoS;
    use crate::protocol::discovery::{build_sedp, SedpData};

    let qos = QoS::reliable().transient_local().durability_service(
        crate::dds::qos::DurabilityService::keep_last(50, 1000, 10, 100),
    );

    let sedp_data = SedpData {
        topic_name: "DurServiceTest".to_string(),
        type_name: "DurServiceType".to_string(),
        participant_guid: GUID::zero(),
        endpoint_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        qos_hash: 0,
        qos: Some(qos),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: false,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    };

    let mut buf = vec![0u8; 2048];
    let len = build_sedp(&sedp_data, &mut buf).expect("SEDP build should succeed");

    // Search for PID_DURABILITY_SERVICE (0x001e) in the output
    let pid_bytes = 0x001eu16.to_le_bytes();
    let found = buf[..len].windows(2).any(|w| w == pid_bytes);
    assert!(
        found,
        "PID_DURABILITY_SERVICE (0x001e) must be present in SEDP output"
    );
}

// =============================================================================
// Test 7: DurabilityService applies to TRANSIENT and PERSISTENT only
// =============================================================================
#[test]
fn test_durability_service_only_active_when_durable() {
    use crate::dds::qos::DurabilityService;
    use crate::dds::QoS;

    let service = DurabilityService::keep_last(100, 5000, 50, 500);

    // VOLATILE and TRANSIENT_LOCAL: the writer's own HISTORY and
    // RESOURCE_LIMITS, untouched. DDS v1.4 Sec.2.2.3.4: for TRANSIENT_LOCAL
    // which samples are kept "depends on other QoS such as HISTORY and
    // RESOURCE_LIMITS"; DURABILITY_SERVICE configures the service for
    // TRANSIENT and PERSISTENT, and the built-in topics table says of a
    // TRANSIENT_LOCAL entity: "Does not apply as DURABILITY is
    // TRANSIENT_LOCAL".
    //
    // Taking KeepLast(100), max_samples 100 and max_instances 1 from the
    // service for TRANSIENT_LOCAL would be wrong: with max_instances 1 it is
    // the one case in which a total and a per-instance limit coincide, so it
    // could not see that a TRANSIENT_LOCAL KEEP_LAST(1) writer of three
    // instances would replay one.
    for qos in [
        QoS::best_effort()
            .volatile()
            .keep_last(10)
            .durability_service(service),
        QoS::reliable()
            .transient_local()
            .keep_last(10)
            .durability_service(service),
    ] {
        let (history, limits) =
            super::builder::derive_history_and_limits(&qos).expect("history derivation");
        assert!(
            matches!(history, crate::qos::History::KeepLast(10)),
            "{:?}: the writer's own depth, got {history:?}",
            qos.durability
        );
        assert_eq!(
            limits, qos.resource_limits,
            "{:?}: the writer's own RESOURCE_LIMITS, unchanged",
            qos.durability
        );
    }

    // TRANSIENT: the writer's cache also plays the service, so it keeps what
    // either requires - the larger depth, and each limit at the larger of
    // the two (the writer default is LENGTH_UNLIMITED, which stays).
    let qos_transient = QoS::reliable()
        .transient()
        .keep_last(10)
        .durability_service(service);
    let (history, limits) = super::builder::derive_history_and_limits(&qos_transient)
        .expect("transient history derivation");
    assert!(
        matches!(history, crate::qos::History::KeepLast(100)),
        "TRANSIENT keeps the service depth when it is the larger, got {history:?}"
    );
    assert_eq!(limits.max_instances, crate::reliability::LENGTH_UNLIMITED);
    assert_eq!(
        limits.max_samples_per_instance,
        crate::reliability::LENGTH_UNLIMITED
    );
}

// =============================================================================
// Test 8: LENGTH_UNLIMITED means no limit
// =============================================================================
#[test]
fn test_durability_service_length_unlimited() {
    let pool = Arc::new(SlabPool::new());

    // Create cache with LENGTH_UNLIMITED for instances and per-instance
    // Use max_samples=60 to stay within SlabPool capacity (64 slots for 16B class)
    let cache = HistoryCache::new_with_durability_service_limits(
        pool,
        60,
        10_000_000,
        History::KeepLast(60),
        LENGTH_UNLIMITED,
        LENGTH_UNLIMITED,
    );

    // Write samples across 10 instances, 5 each = 50 total (within pool limits)
    for instance in 1..=10u64 {
        for sample in 1..=5u64 {
            let seq = (instance - 1) * 5 + sample;
            cache
                .insert_keyed(seq, b"data", instance)
                .expect("insert should succeed with LENGTH_UNLIMITED");
        }
    }

    assert_eq!(
        cache.len(),
        50,
        "LENGTH_UNLIMITED should allow all 50 samples"
    );
    assert_eq!(
        cache.instance_count(),
        10,
        "LENGTH_UNLIMITED should allow all 10 instances"
    );
}

// =============================================================================
// Test 9: SEDP roundtrip (serialize + deserialize DurabilityService)
// =============================================================================
#[test]
fn test_sedp_durability_service_roundtrip() {
    use crate::core::discovery::GUID;
    use crate::dds::qos::DurabilityService;
    use crate::dds::QoS;
    use crate::protocol::discovery::{build_sedp, parse_sedp, SedpData};

    let ds = DurabilityService::keep_last(50, 1000, 10, 100);
    let qos = QoS::reliable().transient_local().durability_service(ds);

    let sedp_data = SedpData {
        topic_name: "RoundtripTest".to_string(),
        type_name: "RoundtripType".to_string(),
        participant_guid: GUID::zero(),
        endpoint_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        qos_hash: 0,
        qos: Some(qos),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: false,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    };

    let mut buf = vec![0u8; 2048];
    let len = build_sedp(&sedp_data, &mut buf).expect("SEDP build should succeed");
    let parsed = parse_sedp(&buf[..len]).expect("SEDP parse should succeed");

    assert_eq!(parsed.topic_name, "RoundtripTest");
    assert_eq!(parsed.type_name, "RoundtripType");

    // Verify the DurabilityService was parsed back
    let parsed_qos = parsed.qos.expect("QoS should be present after roundtrip");
    let parsed_ds = parsed_qos.durability_service;
    assert_eq!(
        parsed_ds.history_depth, 50,
        "DurabilityService.history_depth should roundtrip"
    );
    assert_eq!(
        parsed_ds.max_samples, 1000,
        "DurabilityService.max_samples should roundtrip"
    );
    assert_eq!(
        parsed_ds.max_instances, 10,
        "DurabilityService.max_instances should roundtrip"
    );
    assert_eq!(
        parsed_ds.max_samples_per_instance, 100,
        "DurabilityService.max_samples_per_instance should roundtrip"
    );
}

// =============================================================================
// Test 10: snapshot_payloads_limited with LENGTH_UNLIMITED returns all
// =============================================================================
#[test]
fn test_snapshot_payloads_limited_unlimited() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 100, 10_000_000, History::KeepLast(100));

    for i in 1..=30u64 {
        cache.insert(i, b"data").expect("insert should succeed");
    }

    // LENGTH_UNLIMITED should return all samples
    let all = cache.snapshot_payloads_limited(LENGTH_UNLIMITED);
    assert_eq!(
        all.len(),
        30,
        "LENGTH_UNLIMITED should return all 30 samples"
    );

    // Explicit limit
    let limited = cache.snapshot_payloads_limited(10);
    assert_eq!(limited.len(), 10, "limit=10 should return 10 samples");
    assert_eq!(limited[0].0, 21, "limited should start from seq 21");
    assert_eq!(limited[9].0, 30, "limited should end at seq 30");
}

// =============================================================================
// Test 11: remove_acknowledged only removes seqs <= acked_seq
// =============================================================================
#[test]
fn test_remove_acknowledged() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 100, 10_000_000, History::KeepLast(100));

    for i in 1..=10u64 {
        cache.insert(i, b"data").expect("insert should succeed");
    }
    assert_eq!(cache.len(), 10);

    // Remove acknowledged up to seq 7
    let removed = cache.remove_acknowledged(7);
    assert_eq!(removed, 7, "should remove 7 samples");
    assert_eq!(cache.len(), 3, "should have 3 remaining");
    assert_eq!(cache.oldest_seq(), Some(8), "oldest should be 8");

    // Removing again with same acked_seq should remove nothing
    let removed2 = cache.remove_acknowledged(7);
    assert_eq!(removed2, 0, "no more samples to remove");
}

// =============================================================================
// Test 12: KEEP_ALL with instance limits rejects overflow
// =============================================================================
#[test]
fn test_keep_all_with_instance_limits() {
    let pool = Arc::new(SlabPool::new());

    let cache = HistoryCache::new_with_durability_service_limits(
        pool,
        100, // max_samples
        10_000_000,
        History::KeepAll,
        2, // max_instances
        3, // max_samples_per_instance
    );

    // Fill instance 1 (3 samples)
    for i in 1..=3u64 {
        cache
            .insert_keyed(i, b"data", 1)
            .expect("insert should succeed");
    }

    // Instance 1 is full, next insert for instance 1 should be rejected
    let err = cache.insert_keyed(4, b"data", 1);
    assert!(
        err.is_err(),
        "KEEP_ALL should reject when max_samples_per_instance exceeded"
    );

    // Instance 2 should still work
    cache
        .insert_keyed(5, b"data", 2)
        .expect("instance 2 should accept");

    // Instance 3 should be rejected (max_instances = 2)
    let err = cache.insert_keyed(6, b"data", 3);
    assert!(
        err.is_err(),
        "KEEP_ALL should reject when max_instances exceeded"
    );
}
