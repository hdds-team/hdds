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
    assert_eq!(cache.len(), max_samples, "cache should retain only max_samples");
    assert_eq!(
        cache.oldest_seq(),
        Some(81),
        "oldest should be 81 (100 - 20 + 1)"
    );
    assert_eq!(
        cache.newest_seq(),
        Some(100),
        "newest should be 100"
    );
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

    // Write samples for 5 different instances
    for instance in 1..=5u64 {
        for sample in 1..=3u64 {
            let seq = (instance - 1) * 3 + sample;
            cache
                .insert_keyed(seq, b"test payload", instance)
                .expect("insert should succeed");
        }
    }

    // Should only retain max_instances distinct instances
    assert!(
        cache.instance_count() <= max_instances,
        "instance count {} should be <= max_instances {}",
        cache.instance_count(),
        max_instances
    );
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
// Test 4: Cleanup timer removes old acknowledged samples
// =============================================================================
#[test]
fn test_durability_service_cleanup_timer() {
    use super::cleanup_timer::{spawn_cleanup_timer, CleanupState};
    use std::time::Duration;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        pool,
        100,
        10_000_000,
        History::KeepLast(100),
    ));

    // Insert 20 samples
    for i in 1..=20u64 {
        cache.insert(i, b"test data").expect("insert should succeed");
    }
    assert_eq!(cache.len(), 20);

    // Set up cleanup state: acknowledge samples 1-15
    let state = Arc::new(CleanupState::new());
    state.update_acked_seq(15);

    // Spawn cleanup timer with short interval
    let _handle = spawn_cleanup_timer(cache.clone(), state.clone(), Duration::from_millis(10));

    // Wait for cleanup to run
    std::thread::sleep(Duration::from_millis(100));

    // Samples 1-15 should have been removed
    assert_eq!(
        cache.len(),
        5,
        "should have 5 remaining samples after cleanup"
    );
    assert_eq!(
        cache.oldest_seq(),
        Some(16),
        "oldest seq should be 16 after cleanup"
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

    let qos = QoS::reliable()
        .transient_local()
        .durability_service(crate::dds::qos::DurabilityService::keep_last(50, 1000, 10, 100));

    let sedp_data = SedpData {
        topic_name: "DurServiceTest".to_string(),
        type_name: "DurServiceType".to_string(),
        participant_guid: GUID::zero(),
        endpoint_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        qos_hash: 0,
        qos: Some(qos),
        type_object: None,
        unicast_locators: vec![],
        user_data: None,
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
// Test 7: DurabilityService only active when durability >= TRANSIENT_LOCAL
// =============================================================================
#[test]
fn test_durability_service_only_active_when_durable() {
    use crate::dds::qos::DurabilityService;
    use crate::dds::QoS;

    // VOLATILE writer: DurabilityService limits should NOT affect history derivation
    let qos_volatile = QoS::best_effort()
        .volatile()
        .keep_last(10)
        .durability_service(DurabilityService::keep_last(100, 5000, 50, 500));

    let (history, limits) = super::builder::derive_history_and_limits_test(&qos_volatile)
        .expect("volatile history derivation");

    // With VOLATILE, only the history depth (10) matters, not DurabilityService.
    assert!(
        matches!(history, crate::qos::History::KeepLast(10)),
        "VOLATILE should use QoS history depth, not DurabilityService"
    );
    assert_eq!(
        limits.max_samples, 10,
        "VOLATILE max_samples should follow QoS history depth"
    );

    // TRANSIENT_LOCAL writer: DurabilityService limits SHOULD apply
    let qos_durable = QoS::reliable()
        .transient_local()
        .keep_last(10)
        .durability_service(DurabilityService::keep_last(100, 500, 1, 500));

    let (history2, limits2) = super::builder::derive_history_and_limits_test(&qos_durable)
        .expect("transient_local history derivation");

    // With TRANSIENT_LOCAL, DurabilityService.history_depth (100) wins over QoS history.depth (10)
    assert!(
        matches!(history2, crate::qos::History::KeepLast(100)),
        "TRANSIENT_LOCAL should use DurabilityService depth (100)"
    );
    assert_eq!(
        limits2.max_samples, 100,
        "TRANSIENT_LOCAL max_samples should use DurabilityService depth"
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
    let qos = QoS::reliable()
        .transient_local()
        .durability_service(ds);

    let sedp_data = SedpData {
        topic_name: "RoundtripTest".to_string(),
        type_name: "RoundtripType".to_string(),
        participant_guid: GUID::zero(),
        endpoint_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        qos_hash: 0,
        qos: Some(qos),
        type_object: None,
        unicast_locators: vec![],
        user_data: None,
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
        cache
            .insert(i, b"data")
            .expect("insert should succeed");
    }

    // LENGTH_UNLIMITED should return all samples
    let all = cache.snapshot_payloads_limited(LENGTH_UNLIMITED);
    assert_eq!(all.len(), 30, "LENGTH_UNLIMITED should return all 30 samples");

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
        100,       // max_samples
        10_000_000,
        History::KeepAll,
        2,         // max_instances
        3,         // max_samples_per_instance
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
