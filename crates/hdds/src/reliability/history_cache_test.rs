// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::core::rt::slabpool::SlabPool;
use std::sync::Arc;

fn make_cache() -> HistoryCache {
    let pool = Arc::new(SlabPool::new());
    HistoryCache::new_with_limits(pool, 100, 10_000_000, History::KeepLast(100))
}

#[test]
fn test_cache_new() {
    let cache = make_cache();
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.quota_bytes(), 0);
    assert!(cache.is_empty());
}

#[test]
fn test_cache_insert_get() {
    let cache = make_cache();
    let data = b"Hello, world!";

    cache.insert(42, data).expect("Cache insert should succeed");

    assert_eq!(cache.len(), 1);
    assert_eq!(cache.get(42), Some(data.to_vec()));
    assert_eq!(cache.get(99), None);
}

#[test]
fn test_cache_insert_multiple() {
    let cache = make_cache();

    cache
        .insert(1, b"one")
        .expect("Cache insert should succeed");
    cache
        .insert(2, b"two")
        .expect("Cache insert should succeed");
    cache
        .insert(3, b"three")
        .expect("Cache insert should succeed");

    assert_eq!(cache.len(), 3);
    assert_eq!(cache.get(1), Some(b"one".to_vec()));
    assert_eq!(cache.get(2), Some(b"two".to_vec()));
    assert_eq!(cache.get(3), Some(b"three".to_vec()));
}

#[test]
fn test_cache_evict_oldest() {
    let cache = make_cache();

    cache
        .insert(10, b"first")
        .expect("Cache insert should succeed");
    cache
        .insert(20, b"second")
        .expect("Cache insert should succeed");

    let evicted = cache.evict_oldest();
    assert_eq!(evicted, Some(10));
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.get(10), None);
    assert_eq!(cache.get(20), Some(b"second".to_vec()));
}

#[test]
fn test_cache_capacity_limit() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 10, 10_000_000, History::KeepLast(10));

    for i in 1..=15 {
        cache
            .insert(i, b"data")
            .expect("Cache insert should succeed");
    }

    assert_eq!(cache.len(), 10);
    assert_eq!(cache.oldest_seq(), Some(6));
    assert_eq!(cache.newest_seq(), Some(15));
}

#[test]
fn test_cache_quota_limit() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 1000, 50, History::KeepLast(1000));

    for i in 1..=10 {
        cache
            .insert(i, &[0u8; 10])
            .expect("Cache insert should succeed");
    }

    assert!(cache.quota_bytes() <= 50);
    assert!(cache.len() <= 5);
}

#[test]
fn test_cache_oldest_newest_seq() {
    let cache = make_cache();

    cache
        .insert(100, b"a")
        .expect("Cache insert should succeed");
    cache
        .insert(200, b"b")
        .expect("Cache insert should succeed");
    cache
        .insert(300, b"c")
        .expect("Cache insert should succeed");

    assert_eq!(cache.oldest_seq(), Some(100));
    assert_eq!(cache.newest_seq(), Some(300));
}

#[test]
fn test_cache_clear() {
    let cache = make_cache();

    cache
        .insert(1, b"test")
        .expect("Cache insert should succeed");
    cache
        .insert(2, b"data")
        .expect("Cache insert should succeed");

    cache.clear();

    assert_eq!(cache.len(), 0);
    assert_eq!(cache.quota_bytes(), 0);
    assert_eq!(cache.oldest_seq(), None);
}

#[test]
fn test_cache_get_not_found() {
    let cache = make_cache();
    assert_eq!(cache.get(999), None);
}

#[test]
fn test_cache_quota_tracking() {
    let cache = make_cache();

    cache
        .insert(1, &[0u8; 100])
        .expect("Cache insert should succeed");
    assert_eq!(cache.quota_bytes(), 100);

    cache
        .insert(2, &[0u8; 50])
        .expect("Cache insert should succeed");
    assert_eq!(cache.quota_bytes(), 150);

    cache.evict_oldest();
    assert_eq!(cache.quota_bytes(), 50);
}

#[test]
fn test_cache_fifo_order() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 3, 10_000_000, History::KeepLast(3));

    cache.insert(10, b"a").expect("Cache insert should succeed");
    cache.insert(20, b"b").expect("Cache insert should succeed");
    cache.insert(30, b"c").expect("Cache insert should succeed");
    cache.insert(40, b"d").expect("Cache insert should succeed");

    assert_eq!(cache.len(), 3);
    assert_eq!(cache.get(10), None);
    assert_eq!(cache.get(20), Some(b"b".to_vec()));
    assert_eq!(cache.get(30), Some(b"c".to_vec()));
    assert_eq!(cache.get(40), Some(b"d".to_vec()));
}

#[test]
fn test_cache_with_resource_limits() {
    use crate::qos::ResourceLimits;

    let pool = Arc::new(SlabPool::new());
    let limits = ResourceLimits {
        max_samples: 50,
        max_instances: 1,
        max_samples_per_instance: 50,
        max_quota_bytes: 1000,
    };

    let cache = HistoryCache::new_with_history(pool, &limits, History::KeepLast(50));

    for i in 1..=60 {
        cache
            .insert(i, &[0u8; 10])
            .expect("Cache insert should succeed");
    }

    assert_eq!(cache.len(), 50);
    assert_eq!(cache.oldest_seq(), Some(11));
    assert_eq!(cache.newest_seq(), Some(60));
    assert!(cache.quota_bytes() <= limits.max_quota_bytes);
}

#[test]
fn test_cache_keep_all_rejects_when_full() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 2, 100, History::KeepAll);

    cache.insert(1, b"a").expect("Cache insert should succeed");
    cache.insert(2, b"b").expect("Cache insert should succeed");
    let err = cache
        .insert(3, b"c")
        .expect_err("KeepAll should reject overflow");

    assert!(matches!(err, Error::WouldBlock));
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.oldest_seq(), Some(1));
}

#[test]
fn test_cache_resource_limits_default() {
    use crate::qos::ResourceLimits;

    let pool = Arc::new(SlabPool::new());
    let limits = ResourceLimits::default();

    let cache = HistoryCache::new_with_history(pool, &limits, History::KeepLast(100_000));

    assert_eq!(cache.len(), 0);
    assert_eq!(cache.quota_bytes(), 0);
    assert_eq!(cache.max_samples(), crate::reliability::LENGTH_UNLIMITED);
    assert_eq!(cache.max_quota_bytes(), 100_000_000);
}

// ============================================================================
// Typed change metadata (ChangeKind / ChangeMetadata / CachedChange)
// ============================================================================

#[test]
fn history_cache_insert_get_preserves_legacy_payload() {
    // Legacy `insert` + `get` path must stay byte-identical: plain
    // UserData entry, no coherent markers, no key hash.
    let cache = make_cache();
    let data = b"legacy payload bytes";

    cache.insert(7, data).expect("Cache insert should succeed");

    assert_eq!(cache.get(7), Some(data.to_vec()));
    assert_eq!(cache.get(8), None);

    let change = cache.get_change(7).expect("seq 7 must be cached");
    assert_eq!(change.metadata, ChangeMetadata::user_data());
    assert_eq!(change.metadata.kind, ChangeKind::UserData);
    assert_eq!(cache.coherent_markers(7), Some((None, None)));
}

#[test]
fn history_cache_get_change_returns_payload_and_metadata_atomically() {
    let cache = make_cache();

    cache
        .insert_coherent(11, b"coherent payload", 0, Some(5), Some(9))
        .expect("Cache insert should succeed");

    let change = cache.get_change(11).expect("seq 11 must be cached");
    assert_eq!(change.seq, 11);
    assert_eq!(change.payload, b"coherent payload".to_vec());
    assert_eq!(change.metadata.kind, ChangeKind::UserData);
    assert_eq!(change.metadata.coherent_sn, Some(5));
    assert_eq!(change.metadata.group_sn, Some(9));
    assert_eq!(change.metadata.key_hash, None);

    // Miss stays a miss for both views.
    assert_eq!(cache.get_change(999), None);
    assert_eq!(cache.get(999), None);
}

#[test]
fn history_cache_insert_coherent_with_key_hash_round_trips_16_bytes() {
    let cache = make_cache();
    let key_hash: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];

    cache
        .insert_coherent_with_key_hash(21, b"keyed", 42, Some(3), None, Some(key_hash))
        .expect("Cache insert should succeed");

    let change = cache.get_change(21).expect("seq 21 must be cached");
    assert_eq!(change.metadata.key_hash, Some(key_hash));
    assert_eq!(change.metadata.coherent_sn, Some(3));
    assert_eq!(change.metadata.group_sn, None);
    assert_eq!(change.metadata.kind, ChangeKind::UserData);

    // Legacy views are unchanged by the presence of a key hash.
    assert_eq!(cache.get(21), Some(b"keyed".to_vec()));
    assert_eq!(cache.coherent_markers(21), Some((Some(3), None)));
}

#[test]
fn history_cache_eviction_drops_payload_and_metadata_together() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 2, 10_000_000, History::KeepLast(2));

    cache
        .insert_coherent_with_key_hash(1, b"first", 0, Some(1), Some(1), Some([0xAA; 16]))
        .expect("Cache insert should succeed");
    // Seq 2 and 3 are the SAME instance as seq 1 (same key hash): depth is
    // per instance (DDS 1.4 2.2.3.18), so only a change of that instance
    // can make room for it.
    cache
        .insert_coherent_with_key_hash(2, b"second", 0, None, None, Some([0xAA; 16]))
        .expect("Cache insert should succeed");
    // KeepLast(2): inserting seq 3 evicts seq 1 (payload AND metadata).
    cache
        .insert_coherent_with_key_hash(3, b"third", 0, None, None, Some([0xAA; 16]))
        .expect("Cache insert should succeed");

    assert_eq!(cache.len(), 2);
    assert_eq!(cache.get(1), None, "evicted payload must be gone");
    assert_eq!(cache.get_change(1), None, "evicted metadata must be gone");
    assert_eq!(cache.coherent_markers(1), None);
    assert!(cache.get_change(2).is_some());
    assert!(cache.get_change(3).is_some());
}

#[test]
fn ecs_close_cache_entry_is_kind_ecs_close_with_markers() {
    // An ECS close slot is cached AS an ECS close: EcsClose kind, empty
    // payload, and the wire coherent markers -- so the NACK repair path
    // can bypass ordinary DATA repair and regenerate the dialect-correct
    // close form.
    let cache = make_cache();

    cache
        .insert_ecs_close(30, Some(29), Some(4))
        .expect("ECS close insert should succeed");

    let change = cache.get_change(30).expect("seq 30 must be cached");
    assert_eq!(change.seq, 30);
    assert!(change.payload.is_empty(), "ECS close carries no payload");
    assert_eq!(change.metadata.kind, ChangeKind::EcsClose);
    assert_eq!(change.metadata.coherent_sn, Some(29));
    assert_eq!(change.metadata.group_sn, Some(4));
    assert_eq!(change.metadata.key_hash, None);

    // TOPIC-scope close (no GROUP GSN) keeps group_sn = None.
    cache
        .insert_ecs_close(31, Some(29), None)
        .expect("ECS close insert should succeed");
    let topic_scope = cache.get_change(31).expect("seq 31 must be cached");
    assert_eq!(topic_scope.metadata.kind, ChangeKind::EcsClose);
    assert_eq!(topic_scope.metadata.group_sn, None);

    // Legacy views still work on the slot (payload-only readers see an
    // empty payload, markers view sees the coherent markers).
    assert_eq!(cache.get(30), Some(Vec::new()));
    assert_eq!(cache.coherent_markers(30), Some((Some(29), Some(4))));
}

/// Guard for the size of the metadata carried in every
/// `CacheEntry` slot. `ChangeMetadata`'s own upper bound is enforced by
/// the `const _: () = assert!(...)` next to its definition; this test
/// additionally pins today's exact numbers on 64-bit targets (field
/// reordering / niche packing means the exact byte count is not portable
/// across pointer widths, only the upper bound is -- see that `const _`'s
/// doc) so a future change that grows either struct on the target this
/// suite actually runs on is a visible, deliberate diff instead of a
/// silent memory-footprint regression. Run with `-- --nocapture` to see
/// the printed values directly.
#[test]
fn change_metadata_and_cache_entry_sizes_are_pinned() {
    let metadata_size = core::mem::size_of::<super::ChangeMetadata>();
    let entry_size = core::mem::size_of::<super::CacheEntry>();
    println!("SIZE_PROBE ChangeMetadata={metadata_size} CacheEntry={entry_size}");
    // 72 bytes, including `status_info` (a lifecycle change is a
    // CacheChange, RTPS 2.5 8.2.3). The 64 bytes had no padding left, so
    // one more field costs a full 8-byte step; the alternative, new
    // `ChangeKind` variants, would break a public exhaustive enum.
    // The group sequence information of a GROUP Publisher's change (RTPS
    // 2.5 8.7.5) is kept out of line (`Ring::groups`): no other writer's
    // entry grows for it.
    assert!(
        metadata_size <= 72,
        "ChangeMetadata exceeded its 72-byte budget"
    );
    #[cfg(target_pointer_width = "64")]
    assert_eq!(
        metadata_size, 72,
        "ChangeMetadata size drifted on a 64-bit target"
    );
    #[cfg(target_pointer_width = "64")]
    assert_eq!(
        entry_size, 112,
        "CacheEntry size drifted on a 64-bit target"
    );
}

// ============================================================================
// HISTORY and RESOURCE_LIMITS are per instance (DDS 1.4 2.2.3.18, 2.2.3.19)
// ============================================================================

fn keyed(cache: &HistoryCache, seq: u64, hash: [u8; 16]) -> Result<(), Error> {
    cache.insert_coherent_with_key_hash(seq, b"v", 0, None, None, Some(hash))
}

fn hash(first: u8, last: u8) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = first;
    h[15] = last;
    h
}

fn seqs(cache: &HistoryCache) -> Vec<u64> {
    cache.get_all_samples().iter().map(|s| s.0).collect()
}

#[test]
fn keep_last_depth_is_kept_per_instance() {
    let pool = Arc::new(SlabPool::new());
    let cache =
        HistoryCache::new_with_limits(pool, LENGTH_UNLIMITED, 10_000_000, History::KeepLast(1));
    keyed(&cache, 1, hash(1, 0)).unwrap();
    keyed(&cache, 2, hash(2, 0)).unwrap();
    keyed(&cache, 3, hash(3, 0)).unwrap();
    keyed(&cache, 4, hash(2, 0)).unwrap();
    // One change per instance, the newest of each: instance 2 lost seq 2.
    assert_eq!(seqs(&cache), vec![1, 3, 4]);
    assert_eq!(cache.instance_count(), 3);
}

#[test]
fn the_whole_key_hash_names_the_instance() {
    // Two hashes equal on their first 8 bytes are two instances: a key that
    // fits in 16 bytes IS its key hash, so a shorter prefix merges them.
    let pool = Arc::new(SlabPool::new());
    let cache =
        HistoryCache::new_with_limits(pool, LENGTH_UNLIMITED, 10_000_000, History::KeepLast(1));
    keyed(&cache, 1, hash(7, 1)).unwrap();
    keyed(&cache, 2, hash(7, 2)).unwrap();
    assert_eq!(seqs(&cache), vec![1, 2]);
}

#[test]
fn max_samples_keeps_at_least_one_change_per_instance() {
    // KEEP_LAST(3), max_samples 3: instance A fills the cache, then B and C
    // arrive. DDS 1.4 2.2.2.4.2.11: samples of another instance may be
    // discarded "as long as at least one sample remains for such an
    // instance". A keeps its newest; B and C are both stored.
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 3, 10_000_000, History::KeepLast(3));
    keyed(&cache, 1, hash(0xA, 0)).unwrap();
    keyed(&cache, 2, hash(0xA, 0)).unwrap();
    keyed(&cache, 3, hash(0xA, 0)).unwrap();
    keyed(&cache, 4, hash(0xB, 0)).unwrap();
    keyed(&cache, 5, hash(0xC, 0)).unwrap();
    assert_eq!(seqs(&cache), vec![3, 4, 5]);

    // Every instance is now down to one change: a fourth instance has no
    // one left to take the room from, and is refused rather than evicting.
    let refused = keyed(&cache, 6, hash(0xD, 0));
    assert!(matches!(refused, Err(Error::WouldBlock)), "got {refused:?}");
    assert_eq!(seqs(&cache), vec![3, 4, 5]);

    // An existing instance can still replace its own change.
    keyed(&cache, 7, hash(0xB, 0)).unwrap();
    assert_eq!(seqs(&cache), vec![3, 5, 7]);
}

#[test]
fn a_coherent_set_close_marker_never_evicts_data() {
    // KEEP_LAST(1): the ECS close written after a sample must not count
    // against that sample's instance and push it out of the cache.
    let pool = Arc::new(SlabPool::new());
    let cache =
        HistoryCache::new_with_limits(pool, LENGTH_UNLIMITED, 10_000_000, History::KeepLast(1));
    cache.insert(1, b"data").unwrap();
    cache.insert_ecs_close(2, Some(1), None).unwrap();
    assert_eq!(seqs(&cache), vec![1, 2]);
    assert_eq!(cache.instance_count(), 1, "a marker is no instance");

    // Markers are bounded among themselves by the same depth.
    cache.insert_ecs_close(3, Some(2), None).unwrap();
    assert_eq!(seqs(&cache), vec![1, 3]);
}

#[test]
fn keep_all_refuses_a_full_instance_and_keeps_the_others_open() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_durability_service_limits(
        pool,
        LENGTH_UNLIMITED,
        10_000_000,
        History::KeepAll,
        LENGTH_UNLIMITED,
        2,
    );
    keyed(&cache, 1, hash(1, 0)).unwrap();
    keyed(&cache, 2, hash(1, 0)).unwrap();
    let refused = keyed(&cache, 3, hash(1, 0));
    assert!(matches!(refused, Err(Error::WouldBlock)), "got {refused:?}");
    keyed(&cache, 4, hash(2, 0)).unwrap();
    assert_eq!(seqs(&cache), vec![1, 2, 4]);
}

#[test]
fn removal_paths_keep_the_instance_count_in_step() {
    // Every way out of the ring must give the instance its room back:
    // acknowledgement, explicit eviction and clear.
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_durability_service_limits(
        pool,
        LENGTH_UNLIMITED,
        10_000_000,
        History::KeepAll,
        1,
        LENGTH_UNLIMITED,
    );
    keyed(&cache, 1, hash(1, 0)).unwrap();
    assert!(matches!(
        keyed(&cache, 2, hash(2, 0)),
        Err(Error::ResourceLimitExceeded(_))
    ));
    assert_eq!(cache.remove_acknowledged(1), 1);
    keyed(&cache, 3, hash(2, 0)).expect("acknowledged instance gave its room back");
    assert_eq!(cache.evict_oldest(), Some(3));
    keyed(&cache, 4, hash(3, 0)).expect("evicted instance gave its room back");
    cache.clear();
    keyed(&cache, 5, hash(4, 0)).expect("clear gave the room back");
    assert_eq!(cache.instance_count(), 1);
}

// ============================================================================
// A full history gets room back from acknowledgements (DDS 1.4 2.2.3.18,
// 2.2.2.4.2.11; RTPS 2.5 8.4.1 steps 20-22)
// ============================================================================

fn keep_all(max_samples: usize) -> HistoryCache {
    HistoryCache::new_with_limits(
        Arc::new(SlabPool::new()),
        max_samples,
        10_000_000,
        History::KeepAll,
    )
}

#[test]
fn a_full_reliable_history_gives_up_only_an_acknowledged_change() {
    let cache = keep_all(2);
    cache.insert(1, b"a").unwrap();
    cache.insert(2, b"b").unwrap();
    let refused = cache.insert(3, b"c");
    assert!(matches!(refused, Err(Error::WouldBlock)), "got {refused:?}");
    cache.set_acked_floor(1);
    cache
        .insert(3, b"c")
        .expect("seq 1 is acknowledged by all: its room is free");
    assert_eq!(seqs(&cache), vec![2, 3]);
}

#[test]
fn a_full_best_effort_history_discards_the_oldest() {
    let cache = keep_all(2);
    cache.set_release_policy(false, true);
    cache.insert(1, b"a").unwrap();
    cache.insert(2, b"b").unwrap();
    cache
        .insert(3, b"c")
        .expect("BEST_EFFORT: the old values are discarded");
    assert_eq!(seqs(&cache), vec![2, 3]);
}

#[test]
fn a_best_effort_keep_last_history_drops_rather_than_refuses() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 2, 10_000_000, History::KeepLast(1));
    cache.set_release_policy(false, true);
    keyed(&cache, 1, hash(1, 0)).unwrap();
    keyed(&cache, 2, hash(2, 0)).unwrap();
    keyed(&cache, 3, hash(3, 0)).expect("BEST_EFFORT may drop samples");
    assert_eq!(seqs(&cache), vec![2, 3]);
}

#[test]
fn a_volatile_history_removes_what_every_reader_acknowledged() {
    let cache = keep_all(LENGTH_UNLIMITED);
    cache.set_release_policy(true, false);
    for seq in 1..=3 {
        cache.insert(seq, b"v").unwrap();
    }
    cache.set_acked_floor(2);
    assert_eq!(seqs(&cache), vec![3]);
}

#[test]
fn a_durable_history_keeps_what_every_reader_acknowledged() {
    let cache = keep_all(LENGTH_UNLIMITED);
    cache.set_release_policy(true, true);
    for seq in 1..=3 {
        cache.insert(seq, b"v").unwrap();
    }
    cache.set_acked_floor(2);
    assert_eq!(seqs(&cache), vec![1, 2, 3], "owed to late joiners");
}

#[test]
fn a_blocked_insert_is_woken_by_the_acknowledgement_that_makes_room() {
    let cache = Arc::new(keep_all(1));
    cache.insert(1, b"a").unwrap();
    let acker = {
        let cache = Arc::clone(&cache);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            cache.set_acked_floor(1);
        })
    };
    let start = Instant::now();
    let deadline = start + std::time::Duration::from_secs(10);
    cache
        .insert_with_metadata_until(2, b"b", 0, ChangeMetadata::user_data(), Some(deadline))
        .expect("woken by the acknowledgement, well before the deadline");
    let waited = start.elapsed();
    acker.join().unwrap();
    assert!(
        waited >= std::time::Duration::from_millis(40),
        "did not wait: {waited:?}"
    );
    assert!(
        waited < std::time::Duration::from_secs(5),
        "was not woken: {waited:?}"
    );
    assert_eq!(seqs(&cache), vec![2]);
}

#[test]
fn a_blocked_insert_gives_up_at_its_deadline() {
    let cache = keep_all(1);
    cache.insert(1, b"a").unwrap();
    let start = Instant::now();
    let refused = cache.insert_with_metadata_until(
        2,
        b"b",
        0,
        ChangeMetadata::user_data(),
        Some(start + std::time::Duration::from_millis(60)),
    );
    let waited = start.elapsed();
    assert!(matches!(refused, Err(Error::WouldBlock)), "got {refused:?}");
    assert!(
        waited >= std::time::Duration::from_millis(50),
        "gave up early: {waited:?}"
    );
    assert_eq!(seqs(&cache), vec![1]);
}

#[test]
fn a_sample_larger_than_the_quota_is_refused_without_waiting() {
    let cache = HistoryCache::new_with_limits(Arc::new(SlabPool::new()), 10, 4, History::KeepAll);
    let start = Instant::now();
    let refused = cache.insert_with_metadata_until(
        1,
        b"too long",
        0,
        ChangeMetadata::user_data(),
        Some(start + std::time::Duration::from_secs(5)),
    );
    assert!(
        matches!(refused, Err(Error::ResourceLimitExceeded(_))),
        "got {refused:?}"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "waited for nothing"
    );
}

/// The highest change ever inserted is what a writer has published: it does
/// not move back when changes leave the history, and a number never
/// inserted does not count.
#[test]
fn the_highest_inserted_change_survives_its_removal() {
    let cache = make_cache();
    assert_eq!(cache.highest_inserted(), 0, "nothing written yet");
    cache.insert(5, b"five").expect("insert 5");
    cache.insert(7, b"seven").expect("insert 7");
    assert_eq!(cache.highest_inserted(), 7);
    cache.clear();
    assert_eq!(cache.newest_seq(), None, "the history is empty");
    assert_eq!(cache.highest_inserted(), 7, "but 7 was written");
}

/// A close marker counts towards no limit and leaves with the last member of
/// its set (RTPS v2.5 Sec.8.7.6): KEEP_LAST(1) on one instance, each set
/// replacing the previous set's member. A close whose set lost its member
/// stays within the depth (1 here), and goes once a newer one is orphaned
/// too. A close never takes a data slot: `max_samples` 1 still holds a
/// member and its close.
#[test]
fn a_close_leaves_with_the_last_member_of_its_set() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 1, 10_000_000, History::KeepLast(1));
    let member = |first: u64| ChangeMetadata {
        coherent_sn: Some(first),
        key_hash: Some([0xA; 16]),
        ..ChangeMetadata::user_data()
    };
    cache
        .insert_with_metadata(1, &[1], 0, member(1))
        .expect("1");
    cache.insert_ecs_close(2, Some(1), None).expect("close 2");
    assert!(cache.get_change(1).is_some() && cache.get_change(2).is_some());
    cache
        .insert_with_metadata(3, &[3], 0, member(3))
        .expect("3");
    assert!(cache.get_change(1).is_none(), "1 replaced");
    assert!(
        cache.get_change(2).is_some(),
        "an orphan close within the depth"
    );
    cache.insert_ecs_close(4, Some(3), None).expect("close 4");
    cache
        .insert_with_metadata(5, &[5], 0, member(5))
        .expect("5");
    assert!(cache.get_change(2).is_none(), "the older orphan close goes");
    assert!(cache.get_change(4).is_some(), "the newer stays");
    assert!(cache.get_change(5).is_some());
}

/// A close whose set keeps members is never evicted, however many closes
/// follow: KEEP_LAST(1), every set on its own instance.
#[test]
fn a_close_whose_members_remain_is_never_evicted() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 16, 10_000_000, History::KeepLast(1));
    let mut seq = 1;
    for key in 1..=5u8 {
        let first = seq;
        cache
            .insert_with_metadata(
                seq,
                &[key],
                0,
                ChangeMetadata {
                    coherent_sn: Some(first),
                    key_hash: Some([key; 16]),
                    ..ChangeMetadata::user_data()
                },
            )
            .expect("member");
        cache
            .insert_ecs_close(seq + 1, Some(first), None)
            .expect("close");
        seq += 2;
    }
    for seq in 1..=10 {
        assert!(cache.get_change(seq).is_some(), "seq {seq} kept");
    }
}

/// A history out of `max_samples` makes room with data only: a close whose
/// set keeps a member is not what it gives up. KEEP_LAST(2), `max_samples`
/// 2, sets on two instances.
#[test]
fn room_for_data_is_never_taken_from_a_close() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 2, 10_000_000, History::KeepLast(2));
    let member = |first: u64, key: u8| ChangeMetadata {
        coherent_sn: Some(first),
        key_hash: Some([key; 16]),
        ..ChangeMetadata::user_data()
    };
    cache
        .insert_with_metadata(1, &[1], 0, member(1, 0xA))
        .expect("1");
    cache.insert_ecs_close(2, Some(1), None).expect("close 2");
    cache
        .insert_with_metadata(3, &[3], 0, member(3, 0xB))
        .expect("3");
    cache.insert_ecs_close(4, Some(3), None).expect("close 4");
    cache
        .insert_with_metadata(5, &[5], 0, member(5, 0xB))
        .expect("5");
    assert!(
        cache.get_change(1).is_some(),
        "the last change of its instance"
    );
    assert!(
        cache.get_change(2).is_some(),
        "set 1 keeps its member: its close stays"
    );
    assert!(
        cache.get_change(3).is_none(),
        "room taken from the incoming instance"
    );
}

/// The group sequence information of a GROUP Publisher's change is kept
/// with it, out of line, and leaves with it.
#[test]
fn a_changes_group_tag_lives_and_leaves_with_it() {
    use crate::protocol::group::GroupTag;
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 1, 10_000_000, History::KeepLast(1));
    let tag = GroupTag {
        gsn: 7,
        writer_set: [1, 2, 3, 4],
        set_first_gsn: None,
        part_first_sn: None,
    };
    cache
        .insert_grouped_until(1, &[1], 0, ChangeMetadata::user_data(), Some(tag), None)
        .expect("1");
    assert_eq!(cache.get_change(1).expect("1").group, Some(tag));
    assert_eq!(cache.snapshot_changes()[0].group, Some(tag));
    cache
        .insert_with_metadata(2, &[2], 0, ChangeMetadata::user_data())
        .expect("2 replaces 1");
    assert!(cache.get_change(1).is_none());
    assert_eq!(cache.get_change(2).expect("2").group, None);
    assert_eq!(cache.group_entries_for_test(), 0, "nothing left behind");
}

/// What a GROUP writer's history holds of the GSNs of a range of its
/// changes: the first and last held in the range, the first held above.
#[test]
fn a_group_window_reads_the_gsns_held_in_and_above_a_range() {
    use crate::protocol::group::GroupTag;
    use crate::reliability::GroupWindow;
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 16, 10_000_000, History::KeepAll);
    assert_eq!(cache.group_window(1, 9), GroupWindow::default());
    // SNs 2, 3, 5, 6 with GSNs 10, 12, 15, 16; SN 4 is not held.
    for (seq, gsn) in [(2u64, 10u64), (3, 12), (5, 15), (6, 16)] {
        let tag = GroupTag {
            gsn,
            writer_set: [0; 4],
            set_first_gsn: None,
            part_first_sn: None,
        };
        cache
            .insert_grouped_until(seq, &[1], 0, ChangeMetadata::user_data(), Some(tag), None)
            .expect("insert");
    }
    let window = |first, last| {
        let w = cache.group_window(first, last);
        (w.first_gsn, w.last_gsn, w.unannounced_gsn)
    };
    assert_eq!(window(1, 6), (Some(10), Some(16), None));
    assert_eq!(window(3, 4), (Some(12), Some(12), Some(15)));
    assert_eq!(window(4, 4), (None, None, Some(15)));
    assert_eq!(window(3, 5), (Some(12), Some(15), Some(16)));
    assert_eq!(window(7, 6), (None, None, None), "empty range");
    assert_eq!(window(1, 1), (None, None, Some(10)));
}

/// A pool whose heap tier holds one 200 kB change and not two (the primary
/// classes stop at 128 kB, so such a change goes straight to the heap).
fn one_big_change_pool() -> Arc<SlabPool> {
    Arc::new(SlabPool::with_policy(&crate::qos::MemoryPolicy {
        max_heap_bytes: 300_000,
        ..crate::qos::MemoryPolicy::default()
    }))
}

static BIG_CHANGE: [u8; 200_000] = [0x5A; 200_000];

fn unbounded_keep_all(pool: Arc<SlabPool>) -> HistoryCache {
    HistoryCache::new_with_limits(pool, LENGTH_UNLIMITED, 100_000_000, History::KeepAll)
}

/// DDS 1.4 2.2.3.18 (KEEP_ALL, RELIABLE): the writer blocks until the old
/// values are delivered. Out of slab memory, the insert waits for the
/// acknowledgement that frees a change instead of failing at once.
#[test]
fn an_insert_out_of_memory_waits_for_the_acknowledgement_that_frees_some() {
    let cache = Arc::new(unbounded_keep_all(one_big_change_pool()));
    // A VOLATILE RELIABLE writer's history (`DataWriter` builder): what
    // every reader acknowledged is owed to nobody and is given up at once.
    cache.set_release_policy(true, false);
    cache.insert(1, &BIG_CHANGE).unwrap();
    let acker = {
        let cache = Arc::clone(&cache);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            cache.set_acked_floor(1);
        })
    };
    let start = Instant::now();
    cache
        .insert_with_metadata_until(
            2,
            &BIG_CHANGE,
            0,
            ChangeMetadata::user_data(),
            Some(start + std::time::Duration::from_secs(10)),
        )
        .expect("memory came back well before the deadline");
    let waited = start.elapsed();
    acker.join().unwrap();
    assert!(
        waited >= std::time::Duration::from_millis(40),
        "did not wait: {waited:?}"
    );
    assert!(
        waited < std::time::Duration::from_secs(5),
        "was not woken: {waited:?}"
    );
    assert_eq!(seqs(&cache), vec![2]);
}

/// The pool is shared: memory another holder gives back wakes nobody in
/// this cache, and the insert must still see it before its deadline.
#[test]
fn an_insert_out_of_memory_sees_memory_another_holder_gives_back() {
    let pool = one_big_change_pool();
    let other = Arc::new(unbounded_keep_all(Arc::clone(&pool)));
    other.insert(1, &BIG_CHANGE).unwrap();
    let cache = unbounded_keep_all(pool);
    let releaser = {
        let other = Arc::clone(&other);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert_eq!(other.remove_acknowledged(1), 1);
        })
    };
    let start = Instant::now();
    cache
        .insert_with_metadata_until(
            1,
            &BIG_CHANGE,
            0,
            ChangeMetadata::user_data(),
            Some(start + std::time::Duration::from_secs(10)),
        )
        .expect("the memory given back elsewhere is seen before the deadline");
    let waited = start.elapsed();
    releaser.join().unwrap();
    assert!(
        waited < std::time::Duration::from_secs(5),
        "missed the release: {waited:?}"
    );
    assert_eq!(seqs(&cache), vec![1]);
}

/// DDS 1.4 2.2.2.4.2.11: the wait is bounded by `max_blocking_time`.
#[test]
fn an_insert_out_of_memory_gives_up_at_its_deadline() {
    let cache = unbounded_keep_all(one_big_change_pool());
    cache.insert(1, &BIG_CHANGE).unwrap();
    let start = Instant::now();
    let refused = cache.insert_with_metadata_until(
        2,
        &BIG_CHANGE,
        0,
        ChangeMetadata::user_data(),
        Some(start + std::time::Duration::from_millis(60)),
    );
    let waited = start.elapsed();
    assert!(matches!(refused, Err(Error::WouldBlock)), "got {refused:?}");
    assert!(
        waited >= std::time::Duration::from_millis(50),
        "gave up early: {waited:?}"
    );
    assert_eq!(seqs(&cache), vec![1]);
}

/// No deadline (a BEST_EFFORT writer, a path that may not block): refused
/// at once, as before.
#[test]
fn an_insert_out_of_memory_without_a_deadline_is_refused_at_once() {
    let cache = unbounded_keep_all(one_big_change_pool());
    cache.insert(1, &BIG_CHANGE).unwrap();
    let start = Instant::now();
    let refused =
        cache.insert_with_metadata_until(2, &BIG_CHANGE, 0, ChangeMetadata::user_data(), None);
    assert!(matches!(refused, Err(Error::WouldBlock)), "got {refused:?}");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "waited without a deadline"
    );
}

/// `EcsClose` entries carry a writer's end of set (empty payload,
/// `ChangeMetadata::coherent_sn` = the set's LAST member SN, strictly
/// after every member it closes -- `WriterCoherentBridge::emit_ecs_data`
/// takes the close's SN only once the set's own members are already
/// journaled). `snapshot_for_local_replay` must never hand one to an
/// intra-process late joiner as if it were a sample (it is a payload-less
/// marker, not a change the writer made), and a member belongs to a
/// CLOSED set only when ITS OWN SN is strictly below the highest `EcsClose`
/// SN retained -- not merely below SOME close (an earlier close in a
/// multi-set history must not accidentally "cover" a later, still-open
/// set's members).
#[test]
fn local_replay_excludes_every_ecs_close_and_withholds_only_the_open_sets_members() {
    let cache = make_cache();
    let close_at = |seq: u64, coherent_sn: u64| {
        cache
            .insert_grouped_until(
                seq,
                &[],
                0,
                ChangeMetadata {
                    kind: ChangeKind::EcsClose,
                    coherent_sn: Some(coherent_sn),
                    ..ChangeMetadata::user_data()
                },
                None,
                None,
            )
            .unwrap();
    };
    // Set 1: members at SN 1, 2 (coherent_sn = Some(1), the set's first
    // SN); closed at SN 3 (coherent_sn = Some(2), the set's LAST SN). Not
    // the highest close retained: a filter that only excludes an SN at or
    // above the HIGHEST close (and keeps everything else) would wrongly
    // let this EcsClose itself (SN 3) through as a "member" -- it is below
    // SN 6, the second set's close.
    cache.insert_coherent(1, b"m1", 0, Some(1), None).unwrap();
    cache.insert_coherent(2, b"m2", 0, Some(1), None).unwrap();
    close_at(3, 2);
    // Set 2: members at SN 4, 5 (coherent_sn = Some(4)); closed at SN 6
    // (coherent_sn = Some(5)).
    cache.insert_coherent(4, b"m4", 0, Some(4), None).unwrap();
    cache.insert_coherent(5, b"m5", 0, Some(4), None).unwrap();
    close_at(6, 5);
    // Set 3: one member at SN 7 (coherent_sn = Some(7)); LEFT OPEN, no
    // close journaled for it.
    cache.insert_coherent(7, b"m7", 0, Some(7), None).unwrap();

    let mut seqs: Vec<u64> = cache
        .snapshot_for_local_replay()
        .iter()
        .map(|c| c.seq)
        .collect();
    seqs.sort_unstable();
    assert_eq!(
        seqs,
        vec![1, 2, 4, 5],
        "exactly the two closed sets' members: neither EcsClose entry (SN \
         3, SN 6) replayed as a sample, and nothing from the open third \
         set (SN 7)"
    );
}

/// INFO_TS validity is independent of its value (RTPS v2.5 Sec.8.3.7.9):
/// epoch is known; an unset timestamp is not silently promoted to epoch.
#[test]
fn local_replay_preserves_timestamp_validity_and_fraction() {
    let cache = make_cache();
    for (seq, source_ts, known) in [
        (1, (0, 0), true),
        (2, (0, 0), false),
        (3, (1, 1 << 31), true),
    ] {
        cache
            .insert_grouped_until(
                seq,
                b"value",
                0,
                ChangeMetadata {
                    source_ts,
                    source_ts_known: known,
                    ..ChangeMetadata::user_data()
                },
                None,
                None,
            )
            .unwrap();
    }
    let changes = cache.snapshot_for_local_replay();
    let actual: Vec<_> = changes.iter().map(|c| c.source_timestamp_ns).collect();
    for change in changes {
        cache.slabs.release(change.slab);
    }
    assert_eq!(actual, vec![Some(0), None, Some(1_500_000_000)]);
}

/// RTPS 2.5 8.7.6 forbids presenting an incomplete coherent set. HISTORY
/// replacement may retain repair bytes, but cannot turn a set into a suffix.
#[test]
fn keep_last_replay_suppresses_a_set_truncated_before_its_close() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(1));
    cache
        .insert_coherent(1, b"first", 0, Some(1), None)
        .unwrap();
    cache
        .insert_coherent(2, b"second", 0, Some(1), None)
        .unwrap();
    cache.insert_ecs_close(3, Some(2), None).unwrap();
    assert!(cache.snapshot_for_local_replay().is_empty());
    assert_eq!(
        cache
            .snapshot_changes_for_replay()
            .iter()
            .map(|c| c.seq)
            .collect::<Vec<_>>(),
        vec![3]
    );
    assert_eq!(cache.get_change(2).unwrap().payload, b"second");
    assert!(
        cache.get_change(3).is_some(),
        "ECS remains available for repair"
    );
    assert_eq!(
        cache
            .snapshot_changes()
            .iter()
            .map(|c| c.seq)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
}

/// The integrity rule spans keyed instances; replacing one member does not
/// authorize replaying a different surviving instance from the same set.
#[test]
fn keep_last_replay_suppresses_the_entire_keyed_set_but_keeps_intact_sets() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool.clone(), 16, 10_000_000, History::KeepLast(1));
    let member = |first, key| ChangeMetadata {
        coherent_sn: Some(first),
        key_hash: Some([key; 16]),
        ..ChangeMetadata::user_data()
    };
    cache
        .insert_with_metadata(1, b"old-a", 0, member(1, 1))
        .unwrap();
    cache
        .insert_with_metadata(2, b"old-b", 0, member(1, 2))
        .unwrap();
    cache.insert_ecs_close(3, Some(2), None).unwrap();
    cache
        .insert_with_metadata(4, b"new-a", 0, member(4, 1))
        .unwrap();
    cache.insert_ecs_close(5, Some(4), None).unwrap();
    let replay = cache.snapshot_for_local_replay();
    assert_eq!(replay.iter().map(|c| c.seq).collect::<Vec<_>>(), vec![4]);
    for change in replay {
        pool.release(change.slab);
    }
    assert!(
        cache.get_change(2).is_some(),
        "other-instance repair bytes are preserved"
    );
    assert_eq!(
        cache
            .snapshot_changes_for_replay()
            .iter()
            .filter(|c| c.metadata.kind != ChangeKind::EcsClose)
            .map(|c| c.seq)
            .collect::<Vec<_>>(),
        vec![4]
    );
}

#[derive(Default)]
struct ReplayTestRetention {
    integrity: Arc<CoherentReplayIntegrity>,
}

impl GroupRetention for ReplayTestRetention {
    fn retain(&self, _: u64) {}
    fn release(&self, _: u64) {}
    fn retains_each(&self, sets: &[u64]) -> Vec<bool> {
        vec![true; sets.len()]
    }
    fn generation(&self) -> u64 {
        0
    }
    fn replay_integrity(&self) -> Option<Arc<CoherentReplayIntegrity>> {
        Some(Arc::clone(&self.integrity))
    }
}

fn group_replay_member(cache: &HistoryCache, seq: u64, gsn: u64, set: u64, first: u64, key: u8) {
    cache
        .insert_grouped_until(
            seq,
            &[key],
            0,
            ChangeMetadata {
                coherent_sn: Some(first),
                group_sn: Some(set),
                key_hash: Some([key; 16]),
                ..ChangeMetadata::user_data()
            },
            Some(crate::protocol::group::GroupTag {
                gsn,
                writer_set: [0; 4],
                set_first_gsn: Some(1),
                part_first_sn: None,
            }),
            None,
        )
        .unwrap();
}

/// GROUP integrity belongs to the Publisher, not to individual writer caches.
#[test]
fn keep_last_group_replay_suppresses_another_writers_surviving_half() {
    let pool = Arc::new(SlabPool::new());
    let a = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(1));
    let b = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(1));
    let retention = Arc::new(ReplayTestRetention::default());
    a.set_group_retention(retention.clone());
    b.set_group_retention(retention.clone());
    group_replay_member(&a, 1, 1, 7, 1, 1);
    group_replay_member(&b, 1, 2, 7, 1, 2);
    a.insert_ecs_close(2, Some(1), Some(7)).unwrap();
    b.insert_ecs_close(2, Some(1), Some(7)).unwrap();
    retention.integrity.complete(7);
    let before = b.snapshot_for_local_replay();
    assert_eq!(before.len(), 1);
    assert!(before[0]
        .coherent_replay_valid
        .as_ref()
        .unwrap()
        .load(Ordering::Acquire));
    // Replacing A's member damages the whole GROUP set, including B's ticket
    // that a multi-writer replay has already captured.
    a.insert_with_metadata(
        3,
        b"replacement",
        0,
        ChangeMetadata {
            key_hash: Some([1; 16]),
            ..ChangeMetadata::user_data()
        },
    )
    .unwrap();
    assert!(!before[0]
        .coherent_replay_valid
        .as_ref()
        .unwrap()
        .load(Ordering::Acquire));
    for change in before {
        pool.release(change.slab);
    }
    assert!(b.snapshot_for_local_replay().is_empty());
    assert!(b
        .snapshot_changes_for_replay()
        .iter()
        .all(|c| c.metadata.kind == ChangeKind::EcsClose));
    assert!(b.get_change(1).is_some(), "repair retention is independent");
}

/// A temporary empty history inside an open set must not reset its integrity.
#[test]
fn keep_last_group_integrity_survives_zero_residents_until_staging_completes() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(1));
    let retention = Arc::new(ReplayTestRetention::default());
    cache.set_group_retention(retention.clone());
    group_replay_member(&cache, 1, 1, 9, 1, 1);
    cache.evict_oldest().unwrap();
    assert!(
        retention.integrity.ticket(9).is_some(),
        "outstanding set keeps its invalid ticket"
    );
    group_replay_member(&cache, 2, 2, 9, 1, 1);
    cache.insert_ecs_close(3, Some(2), Some(9)).unwrap();
    retention.integrity.complete(9);
    assert!(cache.snapshot_for_local_replay().is_empty());
    cache.clear();
    assert!(
        retention.integrity.ticket(9).is_none(),
        "completed set without residue releases its state"
    );
}

/// Snapshot references continue owning their bytes after HISTORY replacement.
#[test]
fn keep_last_replay_ticket_invalidation_preserves_snapshot_slab_ownership() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(1));
    cache
        .insert_coherent(1, b"retained", 0, Some(1), None)
        .unwrap();
    cache.insert_ecs_close(2, Some(1), None).unwrap();
    let replay = cache.snapshot_for_local_replay();
    assert_eq!(replay.len(), 1);
    cache.insert(3, b"replacement").unwrap();
    assert!(!replay[0]
        .coherent_replay_valid
        .as_ref()
        .unwrap()
        .load(Ordering::Acquire));
    assert_eq!(
        &pool.get_buffer(replay[0].slab)[..replay[0].len],
        b"retained"
    );
    for change in replay {
        pool.release(change.slab);
    }
}

/// A close may be journaled before an outstanding member. Losing the only
/// resident member in that interval cannot reset the set's integrity ticket.
#[test]
fn keep_last_topic_integrity_survives_a_late_stage_after_its_ecs() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 8, 10_000_000, History::KeepLast(1));
    cache
        .insert_coherent(1, b"first", 0, Some(1), None)
        .unwrap();
    let pending = cache.taking(Producer::Writer, 2);
    cache.insert_ecs_close(3, Some(2), None).unwrap();
    assert_eq!(cache.evict_oldest(), Some(1));
    cache.insert_coherent(2, b"late", 0, Some(1), None).unwrap();
    drop(pending);
    assert!(cache.snapshot_for_local_replay().is_empty());
    assert!(
        cache.get_change(2).is_some(),
        "late repair bytes remain retained"
    );
}

/// Deleting the entire source cache does not make an already captured complete
/// replay a fragment: its references own all captured bytes independently.
#[test]
fn keep_last_complete_snapshot_stays_valid_after_source_cache_destruction() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(1));
    cache
        .insert_coherent(1, b"captured", 0, Some(1), None)
        .unwrap();
    cache.insert_ecs_close(2, Some(1), None).unwrap();
    let replay = cache.snapshot_for_local_replay();
    drop(cache);
    assert_eq!(replay.len(), 1);
    assert!(replay[0]
        .coherent_replay_valid
        .as_ref()
        .unwrap()
        .load(Ordering::Acquire));
    assert_eq!(
        &pool.get_buffer(replay[0].slab)[..replay[0].len],
        b"captured"
    );
    for change in replay {
        pool.release(change.slab);
    }
}

#[test]
fn keep_last_complete_group_snapshot_stays_valid_after_writer_departure() {
    let pool = Arc::new(SlabPool::new());
    let a = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(1));
    let b = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(1));
    let retention = Arc::new(ReplayTestRetention::default());
    a.set_group_retention(retention.clone());
    b.set_group_retention(retention.clone());
    group_replay_member(&a, 1, 1, 11, 1, 1);
    group_replay_member(&b, 1, 2, 11, 1, 2);
    a.insert_ecs_close(2, Some(1), Some(11)).unwrap();
    b.insert_ecs_close(2, Some(1), Some(11)).unwrap();
    retention.integrity.complete(11);
    let replay_a = a.snapshot_for_local_replay();
    let replay_b = b.snapshot_for_local_replay();
    a.leave_group_retention();
    drop(a);
    assert_eq!(replay_a.len(), 1);
    assert_eq!(replay_b.len(), 1);
    for change in replay_a.into_iter().chain(replay_b) {
        assert!(change
            .coherent_replay_valid
            .as_ref()
            .unwrap()
            .load(Ordering::Acquire));
        assert_eq!(
            pool.get_buffer(change.slab)[0],
            if change.gsn == Some(1) { 1 } else { 2 }
        );
        pool.release(change.slab);
    }
}

/// A removed writer's bytes cannot be supplied by future snapshots. The
/// surviving writer's half remains repairable, but cannot start late replay.
#[test]
fn departed_group_history_suppresses_future_local_and_wire_replay() {
    let pool = Arc::new(SlabPool::new());
    let a = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(2));
    let b = HistoryCache::new_with_limits(pool.clone(), 8, 10_000_000, History::KeepLast(2));
    let retention = Arc::new(ReplayTestRetention::default());
    a.set_group_retention(retention.clone());
    b.set_group_retention(retention.clone());
    group_replay_member(&a, 1, 1, 17, 1, 1);
    group_replay_member(&b, 1, 2, 17, 1, 2);
    group_replay_member(&b, 2, 3, 17, 1, 3);
    a.insert_ecs_close(2, Some(1), Some(17)).unwrap();
    b.insert_ecs_close(3, Some(2), Some(17)).unwrap();
    retention.integrity.complete(17);
    a.leave_group_retention();
    assert!(a.snapshot_for_local_replay().is_empty());
    drop(a);
    assert!(
        b.snapshot_for_local_replay().is_empty(),
        "a future local replay cannot reconstruct the departed writer"
    );
    assert!(
        b.snapshot_changes_for_replay()
            .iter()
            .all(|change| change.metadata.kind == ChangeKind::EcsClose),
        "wire replay exposed the surviving fragment"
    );
    assert_eq!(b.snapshot_changes().len(), 3, "repair bytes were removed");
    assert!(b.get_change(1).is_some());
    assert!(b.get_change(2).is_some());
}

/// Ordinary GROUP changes still carry their GSN information when neither
/// coherent_access nor ordered_access requests integrity bookkeeping.
#[test]
fn plain_group_history_preserves_sequence_metadata_without_coherent_access() {
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 1, 10_000_000, History::KeepLast(1));
    let tag = crate::protocol::group::GroupTag {
        gsn: 7,
        writer_set: [1, 2, 3, 4],
        set_first_gsn: None,
        part_first_sn: None,
    };
    let metadata = ChangeMetadata {
        key_hash: Some([3; 16]),
        source_ts: (1, 2),
        source_ts_known: true,
        ..ChangeMetadata::user_data()
    };
    cache
        .insert_plain_until(1, b"one", 0, metadata, Some(tag), None)
        .unwrap();
    let captured = cache.get_change(1).unwrap();
    assert_eq!(captured.group, Some(tag));
    assert_eq!(captured.metadata.key_hash, Some([3; 16]));
    assert_eq!(captured.metadata.source_ts, (1, 2));
    let later = crate::protocol::group::GroupTag { gsn: 8, ..tag };
    cache
        .insert_plain_until(2, b"two", 0, metadata, Some(later), None)
        .unwrap();
    assert!(cache.get_change(1).is_none());
    assert_eq!(cache.get_change(2).unwrap().group, Some(later));
}

/// RTPS 2.5 8.4.2.2.3 / DDS 1.4 2.2.2.4.2.11: a writer blocked on the
/// acknowledgement floor resumes when the floor is published, not at its
/// `max_blocking_time`. The acknowledgement path wakes only counted
/// waiters, so the waiter here is released only once it is counted.
#[test]
fn a_floor_wait_is_woken_by_the_next_acknowledgement_publication() {
    let cache = Arc::new(make_cache());
    let observed = cache.ack_progress();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let waiter = {
        let cache = Arc::clone(&cache);
        std::thread::spawn(move || {
            let start = Instant::now();
            cache.wait_for_floor_change(observed, start + std::time::Duration::from_secs(60));
            let _ = done_tx.send(start.elapsed());
        })
    };
    let counted_by = Instant::now() + std::time::Duration::from_secs(10);
    while cache.ring.lock().unwrap().space_waiters == 0 {
        assert!(Instant::now() < counted_by, "the waiter never blocked");
        std::thread::yield_now();
    }
    cache.set_acked_floor(1);
    let waited = done_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the floor publication did not wake the waiting writer");
    waiter.join().unwrap();
    assert!(waited < std::time::Duration::from_secs(10), "{waited:?}");
    assert_eq!(cache.ring.lock().unwrap().space_waiters, 0);
}

/// Every refused insert is a `cache_insert_errors`, whichever insert made it:
/// the count is taken at the cache's own door, so a caller that swallows the
/// error (the coherent-set close journal does) leaves a trace all the same.
#[test]
fn a_refused_insert_is_counted_whichever_entry_point_made_it() {
    let (metrics, _guard) = crate::telemetry::private_metrics_for_test();
    let pool = Arc::new(SlabPool::new());
    let cache = HistoryCache::new_with_limits(pool, 2, 100, History::KeepAll);

    cache.insert(1, b"a").expect("room");
    cache.insert(2, b"b").expect("room");
    assert_eq!(
        metrics.cache_insert_errors(),
        0,
        "accepted inserts count nothing"
    );

    assert!(cache.insert(3, b"c").is_err());
    assert_eq!(metrics.cache_insert_errors(), 1);
    assert!(cache.insert_keyed(4, b"d", 9).is_err());
    assert!(cache
        .insert_with_metadata(5, b"e", 0, ChangeMetadata::user_data())
        .is_err());
    assert_eq!(
        metrics.cache_insert_errors(),
        3,
        "keyed and metadata inserts are refused through the same door"
    );
}
