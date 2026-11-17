// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::core::rt::SlabHandle;

fn noop_callback() -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(|| {})
}

#[test]
fn test_merger_add_readers() {
    let merger = TopicMerger::new();
    assert_eq!(merger.reader_count(), 0);

    let ring1 = Arc::new(IndexRing::with_capacity(16));
    let ring2 = Arc::new(IndexRing::with_capacity(16));

    let reader1 = MergerReader::new(Arc::clone(&ring1), noop_callback());
    let reader2 = MergerReader::new(Arc::clone(&ring2), noop_callback());

    assert!(merger.add_reader(reader1), "First add should succeed");
    assert!(merger.add_reader(reader2), "Second add should succeed");

    assert_eq!(merger.reader_count(), 2);
}

#[test]
fn test_add_reader_idempotent_no_double_delivery() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let ring = Arc::new(IndexRing::with_capacity(16));

    // Create two MergerReader instances with the same ring Arc
    let reader1 = MergerReader::new(Arc::clone(&ring), noop_callback());
    let reader2 = MergerReader::new(Arc::clone(&ring), noop_callback());

    // First add should succeed
    assert!(merger.add_reader(reader1), "First add should succeed");
    assert_eq!(merger.reader_count(), 1);

    // Second add with same ring should be rejected (idempotent)
    assert!(
        !merger.add_reader(reader2),
        "Duplicate add should be rejected"
    );
    assert_eq!(merger.reader_count(), 1, "Reader count should still be 1");

    // Push entry - should only be delivered once
    let entry = IndexEntry::new(1, SlabHandle::legacy_handle_to_primary(42), 100);
    assert!(merger.push(entry, &pool), "Push should succeed");

    // Only one entry in the ring (not two!)
    let e1 = ring.pop();
    assert!(e1.is_some(), "Should have one entry");
    assert_eq!(e1.unwrap().seq, 1);

    let e2 = ring.pop();
    assert!(
        e2.is_none(),
        "Should NOT have a second entry (no double delivery)"
    );
}

#[test]
fn test_merger_fanout() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();

    let ring1 = Arc::new(IndexRing::with_capacity(16));
    let ring2 = Arc::new(IndexRing::with_capacity(16));

    let reader1 = MergerReader::new(Arc::clone(&ring1), noop_callback());
    let reader2 = MergerReader::new(Arc::clone(&ring2), noop_callback());

    merger.add_reader(reader1);
    merger.add_reader(reader2);

    // Push entry via merger
    let entry = IndexEntry::new(1, SlabHandle::legacy_handle_to_primary(42), 100);
    assert!(
        merger.push(entry, &pool),
        "Should push to at least one reader"
    );

    // Both readers should have the entry (IndexRing now has interior mutability)
    let e1 = ring1.pop();
    let e2 = ring2.pop();

    assert!(e1.is_some(), "Reader 1 should have entry");
    assert!(e2.is_some(), "Reader 2 should have entry");

    assert_eq!(e1.expect("Entry should be present").seq, 1);
    assert_eq!(e2.expect("Entry should be present").seq, 1);
}

#[test]
fn test_remove_reader_tombstone_skips_push() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let ring1 = Arc::new(IndexRing::with_capacity(16));
    let ring2 = Arc::new(IndexRing::with_capacity(16));

    let reader1 = MergerReader::new(Arc::clone(&ring1), noop_callback());
    let id1 = reader1.id();
    assert!(merger.add_reader(reader1));
    assert!(merger.add_reader(MergerReader::new(Arc::clone(&ring2), noop_callback())));
    assert_eq!(merger.reader_count(), 2);

    assert!(
        merger.remove_reader(id1, &pool),
        "first removal must deactivate"
    );
    assert_eq!(merger.reader_count(), 1);

    let entry = IndexEntry::new(1, SlabHandle::legacy_handle_to_primary(42), 100);
    assert!(
        merger.push(entry, &pool),
        "active reader must still receive"
    );
    assert!(ring1.pop().is_none(), "tombstoned reader must not receive");
    assert_eq!(ring2.pop().expect("active reader entry").seq, 1);
}

#[test]
fn test_remove_reader_idempotent() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let ring = Arc::new(IndexRing::with_capacity(16));
    let reader = MergerReader::new(Arc::clone(&ring), noop_callback());
    let id = reader.id();

    assert!(
        !merger.remove_reader(id, &pool),
        "unknown id must be a no-op"
    );
    assert!(merger.add_reader(reader));
    assert!(merger.remove_reader(id, &pool));
    assert!(
        !merger.remove_reader(id, &pool),
        "second removal must return false"
    );
    assert_eq!(merger.reader_count(), 0);
}

#[test]
fn test_tombstone_counts_across_inline_and_overflow() {
    const TOTAL: usize = 20; // 16 inline + 4 overflow
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let rings: Vec<Arc<IndexRing>> = (0..TOTAL)
        .map(|_| Arc::new(IndexRing::with_capacity(16)))
        .collect();
    let mut ids = Vec::new();
    for ring in &rings {
        let reader = MergerReader::new(Arc::clone(ring), noop_callback());
        ids.push(reader.id());
        assert!(merger.add_reader(reader));
    }
    assert_eq!(merger.reader_count(), TOTAL);

    // Tombstone one inline (slot 3) and one overflow (slot 17) reader.
    assert!(merger.remove_reader(ids[3], &pool));
    assert!(merger.remove_reader(ids[17], &pool));
    assert_eq!(merger.reader_count(), TOTAL - 2);

    // Push must still reach live overflow readers even though the
    // active count (18) no longer exceeds the published inline slot
    // count (16): the overflow excursion is gated on active overflow
    // readers, not on the aggregate count.
    let entry = IndexEntry::new(7, SlabHandle::legacy_handle_to_primary(42), 100);
    assert!(merger.push(entry, &pool));
    for (idx, ring) in rings.iter().enumerate() {
        let got = ring.pop();
        if idx == 3 || idx == 17 {
            assert!(got.is_none(), "tombstoned reader {idx} must not receive");
        } else {
            assert_eq!(
                got.expect("live reader must receive").seq,
                7,
                "reader {idx}"
            );
        }
    }
}

#[test]
fn test_add_after_tombstone_re_registers_same_ring() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let ring = Arc::new(IndexRing::with_capacity(16));
    let reader = MergerReader::new(Arc::clone(&ring), noop_callback());
    let id = reader.id();
    assert!(merger.add_reader(reader));
    assert!(merger.remove_reader(id, &pool));
    assert_eq!(merger.reader_count(), 0);

    // Tombstoned ids are absent for the dup-check: the same ring can
    // re-register (fresh slot; the tombstoned slot is never reused).
    assert!(
        merger.add_reader(MergerReader::new(Arc::clone(&ring), noop_callback())),
        "re-registration after tombstone must succeed"
    );
    assert_eq!(merger.reader_count(), 1);

    let entry = IndexEntry::new(9, SlabHandle::legacy_handle_to_primary(42), 100);
    assert!(merger.push(entry, &pool));
    let delivered = ring.pop().expect("re-registered reader entry");
    assert_eq!(delivered.seq, 9);
    assert!(
        delivered.is_exclusive(),
        "sole active reader behind a tombstone must keep the EXCLUSIVE fast path"
    );
    assert!(
        ring.pop().is_none(),
        "exactly one delivery: tombstoned slot must stay skipped"
    );
}

#[test]
fn test_sole_reader_fast_path_survives_churn() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    assert_eq!(
        merger.sole_inline_slot(),
        None,
        "empty merger: no designation"
    );

    // Reader A takes slot 0 and is dropped: the slot stays as a tombstone.
    let ring_a = Arc::new(IndexRing::with_capacity(16));
    let reader_a = MergerReader::new(Arc::clone(&ring_a), noop_callback());
    let id_a = reader_a.id();
    assert!(merger.add_reader(reader_a));
    assert_eq!(merger.sole_inline_slot(), Some(0));
    assert!(merger.remove_reader(id_a, &pool));
    assert_eq!(
        merger.sole_inline_slot(),
        None,
        "tombstoning the sole reader must drop the designation"
    );

    // Reader B lands in slot 1 behind the tombstone and is the only
    // ACTIVE registration: the designation must name slot 1, not
    // disappear because the published slot count is 2.
    let ring_b = Arc::new(IndexRing::with_capacity(16));
    let reader_b = MergerReader::new(Arc::clone(&ring_b), noop_callback());
    let id_b = reader_b.id();
    assert!(merger.add_reader(reader_b));
    assert_eq!(
        merger.sole_inline_slot(),
        Some(1),
        "designation must skip the tombstone"
    );

    let (h1, _) = pool
        .reserve_and_write(&[1u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve h1");
    assert!(merger.push(IndexEntry::new(1, h1, 8), &pool));
    assert!(ring_a.pop().is_none(), "tombstoned ring must not receive");
    let e1 = ring_b.pop().expect("sole reader entry after churn");
    assert!(
        e1.is_exclusive(),
        "post-churn single-reader push must stay EXCLUSIVE"
    );
    // release_exclusive debug-asserts a refcount of exactly 1: it would
    // fire here if the fan-out path had issued an add_ref for this entry.
    pool.release_exclusive(e1.handle);

    // Reader C joins: two active readers, refcounted fan-out again.
    let ring_c = Arc::new(IndexRing::with_capacity(16));
    let reader_c = MergerReader::new(Arc::clone(&ring_c), noop_callback());
    let id_c = reader_c.id();
    assert!(merger.add_reader(reader_c));
    assert_eq!(
        merger.sole_inline_slot(),
        None,
        "two active readers: no designation"
    );
    let (h2, _) = pool
        .reserve_and_write(&[2u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve h2");
    assert!(merger.push(IndexEntry::new(2, h2, 8), &pool));
    let e2b = ring_b.pop().expect("fan-out entry ring_b");
    let e2c = ring_c.pop().expect("fan-out entry ring_c");
    assert!(!e2b.is_exclusive(), "fan-out entries must stay refcounted");
    assert!(!e2c.is_exclusive(), "fan-out entries must stay refcounted");
    pool.release(e2b.handle);
    pool.release(e2c.handle);

    // Reader B leaves: C is the sole active reader again, in slot 2
    // behind two tombstones.
    assert!(merger.remove_reader(id_b, &pool));
    assert_eq!(
        merger.sole_inline_slot(),
        Some(2),
        "remaining single reader must regain the designation"
    );
    let (h3, _) = pool
        .reserve_and_write(&[3u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve h3");
    assert!(merger.push(IndexEntry::new(3, h3, 8), &pool));
    assert!(ring_b.pop().is_none(), "tombstoned ring_b must not receive");
    let e3 = ring_c.pop().expect("sole reader entry after second churn");
    assert!(e3.is_exclusive(), "regained sole reader must be EXCLUSIVE");
    pool.release_exclusive(e3.handle);

    // Reader C leaves: nothing active, a push must free its own slot.
    assert!(merger.remove_reader(id_c, &pool));
    assert_eq!(merger.sole_inline_slot(), None);
    assert_eq!(merger.reader_count(), 0);
    let (h4, _) = pool
        .reserve_and_write(&[4u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve h4");
    assert!(
        !merger.push(IndexEntry::new(4, h4, 8), &pool),
        "push with no active reader must report zero deliveries"
    );
    assert!(ring_c.pop().is_none(), "tombstoned ring_c must not receive");
    let (h5, _) = pool
        .reserve_and_write(&[5u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve h5");
    assert_eq!(h5, h4, "zero-delivery push must have freed the slot");
    pool.release(h5);
}

#[test]
fn test_two_active_readers_never_exclusive_after_churn() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let ring_a = Arc::new(IndexRing::with_capacity(16));
    let ring_b = Arc::new(IndexRing::with_capacity(16));
    let ring_c = Arc::new(IndexRing::with_capacity(16));
    let reader_a = MergerReader::new(Arc::clone(&ring_a), noop_callback());
    let id_a = reader_a.id();
    assert!(merger.add_reader(reader_a));
    assert!(merger.add_reader(MergerReader::new(Arc::clone(&ring_b), noop_callback())));
    assert_eq!(merger.sole_inline_slot(), None);

    // Slot layout after churn: [A tombstone, B active, C active]. The
    // active count is 2 with a tombstone ahead: no designation, and
    // every delivery carries its own reference.
    assert!(merger.remove_reader(id_a, &pool));
    assert_eq!(merger.sole_inline_slot(), Some(1), "B alone is sole");
    assert!(merger.add_reader(MergerReader::new(Arc::clone(&ring_c), noop_callback())));
    assert_eq!(
        merger.sole_inline_slot(),
        None,
        "second active reader must clear the designation"
    );

    let (h, _) = pool
        .reserve_and_write(&[7u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve");
    assert!(merger.push(IndexEntry::new(1, h, 8), &pool));
    assert!(ring_a.pop().is_none(), "tombstoned ring must not receive");
    let eb = ring_b.pop().expect("ring_b entry");
    let ec = ring_c.pop().expect("ring_c entry");
    assert!(!eb.is_exclusive(), "two active readers: never EXCLUSIVE");
    assert!(!ec.is_exclusive(), "two active readers: never EXCLUSIVE");
    // Two refcounted releases free the slot exactly once.
    pool.release(eb.handle);
    pool.release(ec.handle);
    let (h2, _) = pool
        .reserve_and_write(&[8u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve after fan-out");
    assert_eq!(h2, h, "fan-out refs must all be returned");
    pool.release(h2);
}

#[test]
fn test_overflow_sole_reader_stays_refcounted() {
    const TOTAL: usize = INLINE_READERS + 1;
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let rings: Vec<Arc<IndexRing>> = (0..TOTAL)
        .map(|_| Arc::new(IndexRing::with_capacity(16)))
        .collect();
    let mut ids = Vec::new();
    for ring in &rings {
        let reader = MergerReader::new(Arc::clone(ring), noop_callback());
        ids.push(reader.id());
        assert!(merger.add_reader(reader));
    }
    assert_eq!(merger.sole_inline_slot(), None);

    // Tombstone every inline slot: the overflow reader is the only
    // active registration, but it lives outside the inline array so the
    // designation stays off and its delivery stays refcounted.
    for id in &ids[..INLINE_READERS] {
        assert!(merger.remove_reader(*id, &pool));
    }
    assert_eq!(merger.reader_count(), 1);
    assert_eq!(
        merger.sole_inline_slot(),
        None,
        "an overflow-only active reader must not be designated"
    );

    let (h, _) = pool
        .reserve_and_write(&[9u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve");
    assert!(merger.push(IndexEntry::new(1, h, 8), &pool));
    for ring in &rings[..INLINE_READERS] {
        assert!(
            ring.pop().is_none(),
            "tombstoned inline ring must not receive"
        );
    }
    let e = rings[INLINE_READERS].pop().expect("overflow reader entry");
    assert!(
        !e.is_exclusive(),
        "overflow reader must stay on the refcounted path"
    );
    pool.release(e.handle);
    let (h2, _) = pool
        .reserve_and_write(&[10u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve after release");
    assert_eq!(h2, h, "overflow delivery ref must be returned");
    pool.release(h2);
}

#[test]
fn test_inline_plus_overflow_active_never_exclusive() {
    const TOTAL: usize = INLINE_READERS + 1;
    const KEPT_INLINE: usize = 5;
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let rings: Vec<Arc<IndexRing>> = (0..TOTAL)
        .map(|_| Arc::new(IndexRing::with_capacity(16)))
        .collect();
    let mut ids = Vec::new();
    for ring in &rings {
        let reader = MergerReader::new(Arc::clone(ring), noop_callback());
        ids.push(reader.id());
        assert!(merger.add_reader(reader));
    }

    // Keep one inline reader and the overflow reader: one active inline
    // slot alone would qualify, but the live overflow reader must veto
    // the designation or it would miss every sample.
    for (idx, id) in ids[..INLINE_READERS].iter().enumerate() {
        if idx != KEPT_INLINE {
            assert!(merger.remove_reader(*id, &pool));
        }
    }
    assert_eq!(merger.reader_count(), 2);
    assert_eq!(
        merger.sole_inline_slot(),
        None,
        "inline + overflow active readers must not be designated"
    );

    let (h, _) = pool
        .reserve_and_write(&[11u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve");
    assert!(merger.push(IndexEntry::new(1, h, 8), &pool));
    let ei = rings[KEPT_INLINE].pop().expect("kept inline reader entry");
    let eo = rings[INLINE_READERS].pop().expect("overflow reader entry");
    assert!(!ei.is_exclusive(), "fan-out entry must stay refcounted");
    assert!(!eo.is_exclusive(), "fan-out entry must stay refcounted");
    pool.release(ei.handle);
    pool.release(eo.handle);

    // Dropping the overflow reader leaves the kept inline slot as the
    // sole active reader: the designation must come back on it.
    assert!(merger.remove_reader(ids[INLINE_READERS], &pool));
    assert_eq!(merger.sole_inline_slot(), Some(KEPT_INLINE));
    let (h2, _) = pool
        .reserve_and_write(&[12u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve h2");
    assert!(merger.push(IndexEntry::new(2, h2, 8), &pool));
    let e2 = rings[KEPT_INLINE].pop().expect("sole reader entry");
    assert!(
        e2.is_exclusive(),
        "sole inline reader must regain EXCLUSIVE"
    );
    pool.release_exclusive(e2.handle);
}

#[test]
fn test_remove_sole_reader_clears_designation_before_drain() {
    use std::sync::atomic::{fence, AtomicBool};
    use std::sync::Barrier;
    use std::thread;
    use std::time::{Duration, Instant};

    // A spinning observer can only witness the drain in progress if it
    // executes WHILE the drain runs. Two things make that happen:
    //
    // - the observer publishes `ready` once it is past the barrier and
    //   about to spin, and the drain does not start before that flag is
    //   seen: the barrier alone proves the observer was released, not
    //   that it has returned from the barrier's wake-up and is running;
    // - on a single core the observer cannot run concurrently at all,
    //   so a drain shorter than one scheduler slice completes before the
    //   observer gets its turn and the round is inconclusive. Each
    //   inconclusive round doubles the pre-fill so the drain outgrows a
    //   slice and the scheduler is forced to interleave the two threads.
    //
    // Each round uses a fresh merger so the reader always sits in slot 0.
    // Pinned to one core in a debug build, the base round drains in
    // about 2 ms and the second round (about 4 ms of pops plus the
    // observer's ~3 ms slice) is already conclusive; the later rounds
    // are headroom for faster builds and longer slices, and the last
    // one (1 << 20 entries, a 2 M-entry ring) is only ever allocated
    // under that kind of starvation.
    const PREFILL_BASE: usize = 1 << 14;
    const MAX_ROUNDS: usize = 7;
    const READY_TIMEOUT: Duration = Duration::from_secs(10);
    let pool = Arc::new(SlabPool::new());

    let mut conclusive = false;
    let mut prefill = 0usize;
    for round in 0..MAX_ROUNDS {
        prefill = PREFILL_BASE << round;
        let merger = Arc::new(TopicMerger::new());
        // The ring holds capacity - 1 entries.
        let ring = Arc::new(IndexRing::with_capacity(prefill * 2));
        let reader = MergerReader::new(Arc::clone(&ring), noop_callback());
        let id = reader.id();
        assert!(merger.add_reader(reader));
        assert_eq!(merger.sole_inline_slot(), Some(0));

        // Pre-fill the sole reader's ring directly (this thread is the
        // ring's single producer) with refcounted copies of one slot,
        // so the drain has `prefill` releases to perform.
        let (h, _) = pool
            .reserve_and_write(&[0x5Au8; 8], crate::core::rt::Claim::Reader)
            .expect("reserve");
        for seq in 0..prefill {
            pool.add_ref(h);
            assert!(ring.push(IndexEntry::new(seq as u32, h, 8)));
        }
        assert_eq!(ring.len(), prefill);

        let barrier = Arc::new(Barrier::new(2));
        let ready = Arc::new(AtomicBool::new(false));
        let abort = Arc::new(AtomicBool::new(false));
        let observer = {
            let merger = Arc::clone(&merger);
            let ring = Arc::clone(&ring);
            let barrier = Arc::clone(&barrier);
            let ready = Arc::clone(&ready);
            let abort = Arc::clone(&abort);
            thread::spawn(move || {
                barrier.wait();
                ready.store(true, Ordering::Release);
                let mut mid_drain = 0usize;
                let mut stale = 0usize;
                loop {
                    let len = ring.len();
                    // The Relaxed tail read inside len() followed by an
                    // Acquire fence synchronizes with the Release tail
                    // store of the pop that produced it, so every store
                    // remove_reader made before that pop (the tombstone
                    // and the designation clear) is visible below.
                    fence(Ordering::Acquire);
                    if len < prefill {
                        if merger.sole_inline_slot().is_some() {
                            stale += 1;
                        }
                        if len > 0 {
                            mid_drain += 1;
                        }
                    }
                    if len == 0 || abort.load(Ordering::Relaxed) {
                        break;
                    }
                    std::hint::spin_loop();
                }
                (mid_drain, stale)
            })
        };

        barrier.wait();
        let wait_start = Instant::now();
        while !ready.load(Ordering::Acquire) {
            if wait_start.elapsed() >= READY_TIMEOUT {
                abort.store(true, Ordering::Release);
                observer.join().expect("observer thread panicked");
                panic!("observer did not reach its spin loop within {READY_TIMEOUT:?}");
            }
            thread::yield_now();
        }
        assert!(merger.remove_reader(id, &pool));
        let (mid_drain, stale) = observer.join().expect("observer thread panicked");
        assert_eq!(
            stale, 0,
            "designation must be cleared before the drain pops its first entry"
        );
        assert_eq!(merger.sole_inline_slot(), None);
        assert!(ring.pop().is_none(), "tombstoned ring must be drained");

        // Every pre-filled reference came back through the drain; the
        // reserve ref is the last one and its release frees the slot.
        pool.release(h);
        let (h2, _) = pool
            .reserve_and_write(&[0u8; 8], crate::core::rt::Claim::Reader)
            .expect("reserve after drain");
        assert_eq!(h, h2, "drain must have returned every reference");
        pool.release(h2);

        if mid_drain > 0 {
            conclusive = true;
            break;
        }
    }
    assert!(
        conclusive,
        "observer never caught a drain in progress in {MAX_ROUNDS} rounds (last pre-fill {prefill})"
    );
}

#[test]
fn test_push_flags_exclusive_only_for_single_reader() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let ring1 = Arc::new(IndexRing::with_capacity(16));
    assert!(merger.add_reader(MergerReader::new(Arc::clone(&ring1), noop_callback())));

    // Single registered reader: ownership transfers, entry flagged.
    let (h1, _) = pool
        .reserve_and_write(&[1u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve h1");
    assert!(merger.push(IndexEntry::new(1, h1, 8), &pool));
    let e1 = ring1.pop().expect("single-reader entry");
    assert!(e1.is_exclusive(), "single-reader push must flag EXCLUSIVE");
    pool.release_exclusive(e1.handle);

    // Second reader registered: fan-out entries carry refs, no flag.
    let ring2 = Arc::new(IndexRing::with_capacity(16));
    assert!(merger.add_reader(MergerReader::new(Arc::clone(&ring2), noop_callback())));
    let (h2, _) = pool
        .reserve_and_write(&[2u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve h2");
    assert!(merger.push(IndexEntry::new(2, h2, 8), &pool));
    let e2a = ring1.pop().expect("fan-out entry ring1");
    let e2b = ring2.pop().expect("fan-out entry ring2");
    assert!(!e2a.is_exclusive(), "fan-out entries must stay refcounted");
    assert!(!e2b.is_exclusive(), "fan-out entries must stay refcounted");
    pool.release(e2a.handle);
    pool.release(e2b.handle);

    // The slot must be reclaimable afterwards (h1 was freed before
    // h2's reserve, so both handles name the same best-fit slot).
    assert_eq!(h1, h2, "sequential reserves reuse the freed slot");
    let (h3, _) = pool
        .reserve_and_write(&[3u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve h3");
    assert_eq!(h3, h2, "released slot must be reused");
    pool.release(h3);
}

/// A sole reader whose delivery observer is armed holds no EXCLUSIVE entry:
/// the observer reads the payload after the push, on a reference of its own,
/// so the reader must release through the refcount, not free the slot.
#[test]
fn test_sole_reader_with_an_armed_observer_is_not_exclusive() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let ring = Arc::new(IndexRing::with_capacity(16));
    let hint = Arc::new(AtomicU32::new(1));
    let observer = Arc::new(super::DeliveryObserver::new(hint, 1, Box::new(|_, _| {})));
    let reader = MergerReader::new(Arc::clone(&ring), noop_callback()).observed(Some(observer));
    assert!(merger.add_reader(reader));
    let (handle, _) = pool
        .reserve_and_write(&[1u8; 8], crate::core::rt::Claim::Reader)
        .expect("reserve");
    assert!(merger.push(IndexEntry::new(1, handle, 8), &pool));
    let entry = ring.pop().expect("entry");
    assert!(
        !entry.is_exclusive(),
        "an observed delivery stays refcounted"
    );
    pool.release(entry.handle);
}

#[test]
fn test_remove_reader_drains_ring_and_frees_slots() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let ring = Arc::new(IndexRing::with_capacity(16));
    let reader = MergerReader::new(Arc::clone(&ring), noop_callback());
    let id = reader.id();
    assert!(merger.add_reader(reader));

    let payload = [0xABu8; 16];
    let (h, _) = pool
        .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
        .expect("primary reservation");
    let entry = IndexEntry::new(1, h, 16);
    // Single reader: the claim ref transfers into the ring entry.
    assert!(merger.push(entry, &pool));

    // Tombstoning must drain the dead ring and return the ref.
    assert!(merger.remove_reader(id, &pool));
    assert!(ring.pop().is_none(), "tombstoned ring must be drained");
    let (h2, _) = pool
        .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
        .expect("reservation after drain");
    assert_eq!(h, h2, "drain must have freed the slot");
    pool.release(h2);
}

#[test]
fn test_replay_refcount_cache_retains_after_reader_release() {
    use crate::qos::History;

    // TRANSIENT_LOCAL unification: the cache holds a persistent
    // reference per entry; every replay push hands the reader its
    // own reference, so a reader releasing after decode can no
    // longer free the cached payload (pre-B1 latent replay bug).
    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        Arc::clone(&pool),
        8,
        1 << 20,
        History::KeepLast(8),
    ));
    cache.insert(1, b"hist").expect("cache insert");
    let merger = TopicMerger::with_history(Arc::clone(&cache), Arc::clone(&pool));

    let ring = Arc::new(IndexRing::with_capacity(4));
    assert!(merger.add_reader(MergerReader::new(Arc::clone(&ring), noop_callback())));
    let entry = ring.pop().expect("first replayed entry");
    let buf = pool.get_buffer(entry.handle);
    assert_eq!(&buf[..entry.len as usize], b"hist");
    drop(buf);
    pool.release(entry.handle); // reader done with the replay ref

    // The cache must still serve the payload (its own ref is intact).
    assert_eq!(cache.get(1).as_deref(), Some(&b"hist"[..]));

    // A second late joiner gets a fresh replay with its own ref.
    let ring2 = Arc::new(IndexRing::with_capacity(4));
    assert!(merger.add_reader(MergerReader::new(Arc::clone(&ring2), noop_callback())));
    let e2 = ring2.pop().expect("second replayed entry");
    pool.release(e2.handle);
    assert_eq!(cache.get(1).as_deref(), Some(&b"hist"[..]));
}

/// A content filter that rejects every sample whose first byte is zero.
fn reject_zero_first_byte() -> Option<SampleFilter> {
    Some(Arc::new(|bytes: &[u8], _version: CdrVersion| {
        bytes.first().is_some_and(|b| *b != 0)
    }))
}

#[test]
fn test_filtered_sole_reader_skips_rejected_samples_and_frees_the_slot() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let ring = Arc::new(IndexRing::with_capacity(16));
    assert!(merger.add_reader(MergerReader::with_filter(
        Arc::clone(&ring),
        noop_callback(),
        reject_zero_first_byte(),
    )));
    assert_eq!(merger.sole_inline_slot(), Some(0));

    // Rejected on the EXCLUSIVE path: zero deliveries, nothing in the
    // ring, and the caller's reference is dropped so the slot is free.
    let (h_rejected, _) = pool
        .reserve_and_write(&[0u8, 1, 2, 3], crate::core::rt::Claim::Reader)
        .expect("reserve rejected");
    assert!(
        !merger.push(IndexEntry::new(1, h_rejected, 4), &pool),
        "a rejected sample is zero deliveries"
    );
    assert!(
        ring.pop().is_none(),
        "a rejected sample must never enter the reader's ring"
    );
    let (h_accepted, _) = pool
        .reserve_and_write(&[7u8, 1, 2, 3], crate::core::rt::Claim::Reader)
        .expect("reserve accepted");
    assert_eq!(
        h_accepted, h_rejected,
        "the rejected sample's slot must have been freed by the push"
    );

    // Accepted: the fast path is the one every unfiltered reader takes.
    assert!(merger.push(IndexEntry::new(2, h_accepted, 4), &pool));
    let delivered = ring.pop().expect("accepted sample");
    assert_eq!(delivered.seq, 2);
    assert!(
        delivered.is_exclusive(),
        "an accepting filtered sole reader keeps the EXCLUSIVE transfer"
    );
    assert!(ring.pop().is_none());
    pool.release_exclusive(delivered.handle);
}

#[test]
fn test_filtered_reader_in_fanout_owns_no_reference_for_a_rejected_sample() {
    let pool = SlabPool::new();
    let merger = TopicMerger::new();
    let filtered = Arc::new(IndexRing::with_capacity(16));
    let plain = Arc::new(IndexRing::with_capacity(16));
    assert!(merger.add_reader(MergerReader::with_filter(
        Arc::clone(&filtered),
        noop_callback(),
        reject_zero_first_byte(),
    )));
    assert!(merger.add_reader(MergerReader::new(Arc::clone(&plain), noop_callback())));
    assert_eq!(merger.sole_inline_slot(), None);

    // Rejected by the filtered reader only: the plain reader is the single
    // delivery, so its release must free the slot (no reference may have
    // been taken for the skipped reader).
    let (h, _) = pool
        .reserve_and_write(&[0u8, 9, 9, 9], crate::core::rt::Claim::Reader)
        .expect("reserve");
    assert!(
        merger.push(IndexEntry::new(1, h, 4), &pool),
        "the plain reader still receives"
    );
    assert!(
        filtered.pop().is_none(),
        "the filtered reader must not receive the rejected sample"
    );
    let plain_entry = plain.pop().expect("plain reader entry");
    assert_eq!(plain_entry.seq, 1);
    assert!(
        !plain_entry.is_exclusive(),
        "fan-out entries stay refcounted"
    );
    pool.release(plain_entry.handle);
    let (h2, _) = pool
        .reserve_and_write(&[1u8, 9, 9, 9], crate::core::rt::Claim::Reader)
        .expect("reserve after release");
    assert_eq!(
        h2, h,
        "the skipped reader must not have left a reference behind"
    );

    // Accepted by both: two deliveries, two references.
    assert!(merger.push(IndexEntry::new(2, h2, 4), &pool));
    let f = filtered.pop().expect("filtered reader accepted sample");
    let p = plain.pop().expect("plain reader entry");
    assert_eq!((f.seq, p.seq), (2, 2));
    pool.release(f.handle);
    pool.release(p.handle);
    let (h3, _) = pool
        .reserve_and_write(&[2u8; 4], crate::core::rt::Claim::Reader)
        .expect("reserve after fan-out");
    assert_eq!(h3, h2, "both fan-out references must come back");
    pool.release(h3);
}

#[test]
fn test_filtered_late_joiner_replay_skips_rejected_history() {
    use crate::qos::History;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        Arc::clone(&pool),
        8,
        1 << 20,
        History::KeepLast(8),
    ));
    cache
        .insert(1, &[0u8, 0xAA])
        .expect("cache insert rejected");
    cache
        .insert(2, &[1u8, 0xBB])
        .expect("cache insert accepted");
    let merger = TopicMerger::with_history(Arc::clone(&cache), Arc::clone(&pool));

    let ring = Arc::new(IndexRing::with_capacity(8));
    assert!(merger.add_reader(MergerReader::with_filter(
        Arc::clone(&ring),
        noop_callback(),
        reject_zero_first_byte(),
    )));
    let replayed = ring.pop().expect("accepted history entry");
    assert_eq!(replayed.seq, 2);
    assert!(
        ring.pop().is_none(),
        "rejected history must not be replayed to a filtered late joiner"
    );
    pool.release(replayed.handle);

    // The cache keeps both entries: the skipped replay returned only its
    // own reference.
    assert_eq!(cache.get(1).as_deref(), Some(&[0u8, 0xAA][..]));
    assert_eq!(cache.get(2).as_deref(), Some(&[1u8, 0xBB][..]));
}

#[test]
fn test_replay_entries_carry_the_cached_cdr_version() {
    use crate::qos::History;
    use crate::reliability::ChangeMetadata;

    let pool = Arc::new(SlabPool::new());
    let cache = Arc::new(HistoryCache::new_with_limits(
        Arc::clone(&pool),
        8,
        1 << 20,
        History::KeepLast(8),
    ));
    let xcdr1 = ChangeMetadata {
        cdr_version: CdrVersion::Xcdr1,
        ..ChangeMetadata::user_data()
    };
    cache
        .insert_with_metadata(1, b"one", 0, xcdr1)
        .expect("insert xcdr1 sample");
    cache.insert(2, b"two").expect("insert default sample");
    let merger = TopicMerger::with_history(Arc::clone(&cache), Arc::clone(&pool));

    // An unfiltered late joiner sees each entry stamped with the version
    // the cache journaled for it, not the default of `IndexEntry::new`.
    let ring = Arc::new(IndexRing::with_capacity(8));
    assert!(merger.add_reader(MergerReader::new(Arc::clone(&ring), noop_callback())));
    let first = ring.pop().expect("replayed seq 1");
    assert_eq!((first.seq, first.cdr_version), (1, CdrVersion::Xcdr1));
    let second = ring.pop().expect("replayed seq 2");
    assert_eq!((second.seq, second.cdr_version), (2, CdrVersion::Xcdr2));
    assert!(ring.pop().is_none());
    pool.release(first.handle);
    pool.release(second.handle);

    // A content filter on a late joiner is handed that same version.
    let filtered = Arc::new(IndexRing::with_capacity(8));
    let only_xcdr1: Option<SampleFilter> = Some(Arc::new(|_bytes: &[u8], version: CdrVersion| {
        version == CdrVersion::Xcdr1
    }));
    assert!(merger.add_reader(MergerReader::with_filter(
        Arc::clone(&filtered),
        noop_callback(),
        only_xcdr1,
    )));
    let replayed = filtered.pop().expect("the xcdr1 entry passes the filter");
    assert_eq!(replayed.seq, 1);
    assert!(
        filtered.pop().is_none(),
        "the default-version entry must be rejected by a version-aware filter"
    );
    pool.release(replayed.handle);
    assert_eq!(cache.get(1).as_deref(), Some(&b"one"[..]));
    assert_eq!(cache.get(2).as_deref(), Some(&b"two"[..]));
}

/// DDS v1.4 Sec.2.2.3.4: retained DATA is available to every late
/// reader even when storage has room for only the retained payload.
#[test]
fn replay_shares_timestamped_data_when_no_second_slab_fits() {
    use crate::qos::{History, MemoryPolicy};
    use crate::reliability::ChangeMetadata;

    const SIZE: usize = 140_000;
    let pool = Arc::new(SlabPool::with_policy(&MemoryPolicy {
        max_heap_bytes: SIZE,
        reader_reserve_percent: 0,
        ..MemoryPolicy::default()
    }));
    let cache = Arc::new(HistoryCache::new_with_limits(
        Arc::clone(&pool),
        1,
        SIZE,
        History::KeepAll,
    ));
    let payload = vec![0x5a; SIZE];
    cache
        .insert_with_metadata(
            1,
            &payload,
            0,
            ChangeMetadata {
                source_ts: (3, 1 << 31),
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
        )
        .expect("retained DATA");
    assert!(
        pool.reserve_and_write(&payload, Claim::Writer).is_none(),
        "fixture: no second payload fits"
    );
    let merger = TopicMerger::with_history(Arc::clone(&cache), Arc::clone(&pool));
    let mut rings = Vec::new();
    for _ in 0..20 {
        let ring = Arc::new(IndexRing::with_capacity(4));
        assert!(merger.add_reader(MergerReader::new(Arc::clone(&ring), noop_callback())));
        rings.push(ring);
    }
    let mut retained = None;
    for ring in rings {
        let entry = ring
            .pop()
            .expect("every late reader receives retained DATA");
        assert_eq!(entry.timestamp_ns, 3_500_000_000);
        assert!(entry.has_source_ts());
        assert!(entry.is_local_replay());
        assert_eq!(entry.payload_offset(), 0);
        assert_eq!(entry.len as usize, SIZE);
        assert_eq!(*retained.get_or_insert(entry.handle), entry.handle);
        assert_eq!(&*pool.get_buffer(entry.handle), &payload);
        pool.release(entry.handle);
    }
    assert_eq!(cache.get(1).as_deref(), Some(payload.as_slice()));
}
