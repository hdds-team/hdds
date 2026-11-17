// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Multi-thread stress cases for the lock-free hot-path structures
//! landed by the post17 perf waves:
//!
//! - `TopicMerger` inline `OnceLock` reader slots + `inline_published`
//!   Release/Acquire handoff + `reader_count_cache` (merger.rs), plus
//!   reader tombstoning (`remove_reader`) racing a live producer and the
//!   `DataReader::drop` -> merger tombstone wiring
//! - `SlabPool` single-RMW `release_slot` vs the CAS claim loop in
//!   `try_reserve` (slabpool.rs)
//! - `StatusCondition` atomic masks + `waitset_hook_count` fast path
//!   (dds/condition.rs)
//! - `MetricsCollector` lock-free latency ring + fastmod index
//!   (telemetry/metrics.rs)
//!
//! Each case is bounded (< 5 s under plain `cargo test`) so it runs in
//! the normal gate; the same binary is the primary ThreadSanitizer
//! workload (`scripts/tsan-test.sh --test concurrency_stress`).
//!
//! NOTE on the merger cases: `IndexRing` is a documented SPSC ring
//! (one producer per ring). In `merger_push_vs_add_reader` the 4
//! pusher threads share ONE merger (one writer's fan-out), so they are
//! serialized through a test-side mutex -- successive producers, never
//! concurrent ones -- while `add_reader` publication and the overflow
//! RwLock crossover stay fully concurrent. The genuinely concurrent
//! multi-producer topology is legal since the A2 per-(writer, reader)
//! ring fix (each binding owns its ring, so each ring keeps exactly
//! one producer) and is exercised WITHOUT any serialization gate by
//! `merger_per_binding_rings_concurrent_producers` (rt level) and
//! `multi_writer_single_reader_exact_delivery` (DataReader level).
//!
//! `StatusCondition::set_active_statuses` is `pub(crate)` and therefore
//! unreachable from an integration test; the active-mask storm lives in
//! the unit test module instead (`dds/condition/tests.rs`,
//! `test_status_condition_set_active_vs_read_storm`). The case below
//! hammers the public surface (enabled mask, trigger reads, waitset
//! hook churn).

use hdds::core::rt::{
    get_slab_pool, IndexEntry, IndexRing, MergerReader, SlabHandle, SlabPool, TopicMerger,
    WaitsetSignal,
};
use hdds::dds::{Condition, StatusCondition, StatusMask};
use hdds::telemetry::metrics::TAG_LATENCY_P50;
use hdds::telemetry::MetricsCollector;
use hdds::test_support::domains::unique_domain;
use hdds::{Error, Participant, QoS, TransportMode};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Phase-2 marker sequence base for the merger case: entries with
/// `seq >= MARKER_SEQ_BASE` are pushed only after every reader joined.
const MARKER_SEQ_BASE: u32 = 1_000_000;

#[test]
fn merger_push_vs_add_reader() {
    const READERS: usize = 20; // crosses the 16-slot inline boundary
    const PUSHERS: usize = 4;
    const PUSHES_PER_THREAD: usize = 2_000;
    const MARKER_PUSHES: u32 = 64;
    const RING_CAPACITY: usize = 1024;

    let merger = Arc::new(TopicMerger::new());
    // Local pool for the refcount side-table traffic of push(); the
    // legacy fixture handles reference slot 7 without claiming it, so
    // the counters drift but never free anything real.
    let pool = Arc::new(SlabPool::new());
    let rings: Vec<Arc<IndexRing>> = (0..READERS)
        .map(|_| Arc::new(IndexRing::with_capacity(RING_CAPACITY)))
        .collect();
    let notify_count = Arc::new(AtomicUsize::new(0));
    // Test machinery: serializes producers so the SPSC contract of each
    // reader ring holds (at most one producer at a time, mutex handoff
    // gives happens-before between successive producers). Registration
    // via add_reader stays fully concurrent with pushes.
    let push_gate = Arc::new(Mutex::new(()));

    let barrier = Arc::new(Barrier::new(PUSHERS + READERS));
    let mut handles = Vec::new();

    for t in 0..PUSHERS {
        let merger = Arc::clone(&merger);
        let pool = Arc::clone(&pool);
        let barrier = Arc::clone(&barrier);
        let push_gate = Arc::clone(&push_gate);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..PUSHES_PER_THREAD {
                let seq =
                    u32::try_from(t * PUSHES_PER_THREAD + i).expect("phase-1 seq fits in u32");
                let entry = IndexEntry::new(seq, SlabHandle::legacy_handle_to_primary(7), 16);
                let guard = push_gate.lock().expect("push gate poisoned");
                // Lossy by design: rings fill during phase 1, drops OK.
                let _ = merger.push(entry, &pool);
                drop(guard);
            }
        }));
    }

    for ring in &rings {
        let merger = Arc::clone(&merger);
        let barrier = Arc::clone(&barrier);
        let ring = Arc::clone(ring);
        let notify_count = Arc::clone(&notify_count);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let on_data: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                notify_count.fetch_add(1, Ordering::Relaxed);
            });
            let reader = MergerReader::new(ring, on_data);
            assert!(
                merger.add_reader(reader),
                "every ring is unique, add_reader must return true"
            );
        }));
    }

    for handle in handles {
        handle.join().expect("stress thread panicked");
    }

    assert_eq!(
        merger.reader_count(),
        READERS,
        "reader_count_cache must converge to the number of unique readers"
    );

    // Drain phase-1 backlog so phase-2 markers cannot be dropped as full.
    for ring in &rings {
        while ring.pop().is_some() {}
    }

    // Phase 2: every registered ring must receive pushes issued after
    // its registration completed.
    for i in 0..MARKER_PUSHES {
        let entry = IndexEntry::new(
            MARKER_SEQ_BASE + i,
            SlabHandle::legacy_handle_to_primary(7),
            16,
        );
        assert!(
            merger.push(entry, &pool),
            "marker push must reach at least one reader"
        );
    }

    for (idx, ring) in rings.iter().enumerate() {
        let mut markers = 0u32;
        while let Some(entry) = ring.pop() {
            assert!(
                entry.seq >= MARKER_SEQ_BASE,
                "phase-1 backlog was drained, only markers expected"
            );
            markers += 1;
        }
        assert_eq!(
            markers, MARKER_PUSHES,
            "ring {idx} must receive every post-registration push"
        );
    }

    assert!(
        notify_count.load(Ordering::Relaxed) >= (MARKER_PUSHES as usize) * READERS,
        "each accepted push must fire the reader notification callback"
    );
}

#[test]
fn merger_tombstone_under_fire() {
    const READERS: usize = 20; // crosses the 16-slot inline boundary
    const RING_CAPACITY: usize = 256;

    let merger = Arc::new(TopicMerger::new());
    let pool = Arc::new(SlabPool::new());
    let rings: Vec<Arc<IndexRing>> = (0..READERS)
        .map(|_| Arc::new(IndexRing::with_capacity(RING_CAPACITY)))
        .collect();
    let mut ids = Vec::new();
    for ring in &rings {
        let on_data: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
        let reader = MergerReader::new(Arc::clone(ring), on_data);
        ids.push(reader.id());
        assert!(merger.add_reader(reader));
    }
    assert_eq!(merger.reader_count(), READERS);

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));

    // Single producer per the SPSC ring contract: one thread drives all
    // rings through the merger while readers are tombstoned under it.
    let producer = {
        let merger = Arc::clone(&merger);
        let pool = Arc::clone(&pool);
        let stop = Arc::clone(&stop);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            let mut seq = 0u32;
            let mut pushes = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let entry = IndexEntry::new(seq, SlabHandle::legacy_handle_to_primary(7), 16);
                // Lossy by design: rings fill, drops OK.
                let _ = merger.push(entry, &pool);
                seq = seq.wrapping_add(1);
                pushes += 1;
            }
            pushes
        })
    };

    barrier.wait();
    for (idx, id) in ids.iter().enumerate() {
        assert!(
            merger.remove_reader(*id, &pool),
            "reader {idx} must tombstone exactly once"
        );
        assert_eq!(
            merger.reader_count(),
            READERS - idx - 1,
            "active count must track tombstoning under fire"
        );
        thread::yield_now();
    }

    stop.store(true, Ordering::Relaxed);
    let pushes = producer.join().expect("producer thread panicked");
    assert!(pushes > 0, "producer must have pushed during removal");

    assert_eq!(merger.reader_count(), 0);
    for (idx, id) in ids.iter().enumerate() {
        assert!(
            !merger.remove_reader(*id, &pool),
            "second removal of reader {idx} must be a no-op"
        );
    }

    // Every reader tombstoned: a fresh push must reach nobody.
    for ring in &rings {
        while ring.pop().is_some() {}
    }
    let entry = IndexEntry::new(u32::MAX, SlabHandle::legacy_handle_to_primary(7), 16);
    assert!(
        !merger.push(entry, &pool),
        "push must skip every tombstoned reader"
    );
    for (idx, ring) in rings.iter().enumerate() {
        assert!(
            ring.pop().is_none(),
            "ring {idx} must stay empty after tombstoning"
        );
    }
}

/// A2 topology at the rt level: one ring PER writer merger (the
/// per-binding pair a `DataReader` now creates), one producer thread
/// per merger, NO serialization gate. Every ring keeps exactly one
/// producer, so delivery must be EXACT: every push accepted, every
/// entry popped once, in per-writer FIFO order.
#[test]
fn merger_per_binding_rings_concurrent_producers() {
    const WRITERS: usize = 4;
    const PUSHES: usize = 20_000;
    // Rounds up to 32768; capacity-1 usable slots hold the full
    // per-writer volume so no push can ever hit a full ring.
    const RING_CAPACITY: usize = PUSHES + 1;

    let mergers: Vec<Arc<TopicMerger>> =
        (0..WRITERS).map(|_| Arc::new(TopicMerger::new())).collect();
    let pool = Arc::new(SlabPool::new());
    let rings: Vec<Arc<IndexRing>> = (0..WRITERS)
        .map(|_| Arc::new(IndexRing::with_capacity(RING_CAPACITY)))
        .collect();
    for (merger, ring) in mergers.iter().zip(&rings) {
        let on_data: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
        assert!(merger.add_reader(MergerReader::new(Arc::clone(ring), on_data)));
    }

    let barrier = Arc::new(Barrier::new(WRITERS));
    let mut handles = Vec::new();
    for merger in &mergers {
        let merger = Arc::clone(merger);
        let pool = Arc::clone(&pool);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..PUSHES {
                let seq = u32::try_from(i).expect("seq fits in u32");
                let entry = IndexEntry::new(seq, SlabHandle::legacy_handle_to_primary(7), 16);
                assert!(
                    merger.push(entry, &pool),
                    "push {i} must be accepted: the binding ring is sized to the volume"
                );
            }
        }));
    }
    for handle in handles {
        handle.join().expect("producer thread panicked");
    }

    for (idx, ring) in rings.iter().enumerate() {
        let mut expected_seq = 0u32;
        while let Some(entry) = ring.pop() {
            assert_eq!(
                entry.seq, expected_seq,
                "ring {idx}: per-writer FIFO must hold with a single producer"
            );
            expected_seq += 1;
        }
        assert_eq!(
            expected_seq as usize, PUSHES,
            "ring {idx}: exact delivery, no silent loss"
        );
    }
}

#[derive(Debug, Clone, Copy, hdds::DDS)]
struct MwSample {
    writer_id: u32,
    seq: u32,
}

/// End-to-end regression gate (TODO 8.1): N writers bound to ONE
/// DataReader, each writer thread pushing concurrently through its own
/// merger into its own per-binding ring. Pre-A2 this topology put N
/// concurrent producers on the reader's single SPSC ring (silent loss);
/// now delivery must be exact -- no loss, no duplicates, per-writer
/// FIFO -- across the reader's timestamp-merge pump.
#[test]
fn multi_writer_single_reader_exact_delivery() {
    const WRITERS: usize = 4;
    const MSGS: usize = 1_500;
    const DEADLINE: Duration = Duration::from_secs(20);
    const DRAIN_GRACE: Duration = Duration::from_millis(500);
    let expected = WRITERS * MSGS;

    // Intra-process only: no sockets, no discovery traffic on the host.
    // The domain is still leased: 39 was the hdds FLEET domain, and the
    // DomainRegistry that backs intra delivery is keyed by domain id, so a
    // leased id also keeps this test's registry to itself.
    let domain = unique_domain();
    let participant = Participant::builder("concurrency_stress_mw")
        .with_transport(TransportMode::IntraProcess)
        .domain_id(domain.id())
        .build()
        .expect("participant");
    let topic = participant
        .topic::<MwSample>("MwExactDelivery")
        .expect("topic");

    // Writers first so the reader auto-bind sees them all at build.
    let mut writers = Vec::with_capacity(WRITERS);
    let mut mergers = Vec::with_capacity(WRITERS);
    for _ in 0..WRITERS {
        let writer = topic
            .writer()
            .qos(QoS::best_effort().keep_last(1))
            .build()
            .expect("writer");
        mergers.push(writer.merger());
        writers.push(writer);
    }

    let depth = u32::try_from(expected * 2).expect("depth fits in u32");
    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(depth))
        .build()
        .expect("reader");
    // Manual double-bind: dedup is per merger now (each bind would
    // otherwise create a fresh ring), so this must stay a no-op.
    for merger in &mergers {
        reader.bind_to_writer(Arc::clone(merger));
    }
    for (idx, merger) in mergers.iter().enumerate() {
        assert_eq!(
            merger.reader_count(),
            1,
            "merger {idx}: exactly one active registration (auto-bind, deduped re-bind)"
        );
    }

    let writers_done = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(WRITERS + 1));
    let mut handles = Vec::new();
    for (writer_id, writer) in writers.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        let done = Arc::clone(&writers_done);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let start = Instant::now();
            for seq in 0..MSGS {
                let msg = MwSample {
                    writer_id: u32::try_from(writer_id).expect("writer id fits"),
                    seq: u32::try_from(seq).expect("seq fits"),
                };
                loop {
                    match writer.write(&msg) {
                        Ok(()) => break,
                        Err(Error::WouldBlock) => {
                            // Global slab pool momentarily exhausted
                            // (shared with the other tests in this
                            // binary): back off and retry.
                            assert!(
                                start.elapsed() < DEADLINE,
                                "writer {writer_id} starved on WouldBlock"
                            );
                            thread::yield_now();
                        }
                        Err(err) => panic!("writer {writer_id} failed: {err}"),
                    }
                }
            }
            done.fetch_add(1, Ordering::Release);
        }));
    }
    barrier.wait();

    // Drain on this thread: exact-count accounting with per-writer
    // duplicate bitmaps and monotonicity (mirrors contention_bench).
    let words = MSGS.div_ceil(64);
    let mut seen = vec![vec![0u64; words]; WRITERS];
    let mut last_seq = [-1i64; WRITERS];
    let mut received = 0usize;
    let mut dups = 0usize;
    let mut reorders = 0usize;
    let start = Instant::now();
    let mut idle_since: Option<Instant> = None;
    while received < expected {
        match reader.take() {
            Ok(Some(msg)) => {
                idle_since = None;
                received += 1;
                let w = msg.writer_id as usize;
                let s = msg.seq as usize;
                assert!(
                    w < WRITERS && s < MSGS,
                    "corrupt payload: writer_id={w} seq={s} outside scenario space"
                );
                let (word, bit) = (s / 64, s % 64);
                if seen[w][word] & (1u64 << bit) != 0 {
                    dups += 1;
                } else {
                    seen[w][word] |= 1u64 << bit;
                }
                if (s as i64) < last_seq[w] {
                    reorders += 1;
                } else {
                    last_seq[w] = s as i64;
                }
            }
            Ok(None) => {
                assert!(
                    start.elapsed() < DEADLINE,
                    "drain deadline exceeded: received {received}/{expected}"
                );
                if writers_done.load(Ordering::Acquire) == WRITERS {
                    let since = *idle_since.get_or_insert_with(Instant::now);
                    assert!(
                        since.elapsed() < DRAIN_GRACE,
                        "writers done, rings idle: received {received}/{expected}"
                    );
                }
                thread::yield_now();
            }
            Err(err) => panic!("reader take failed: {err}"),
        }
    }
    for handle in handles {
        handle.join().expect("writer thread panicked");
    }

    assert_eq!(
        received, expected,
        "exact delivery across per-binding rings"
    );
    assert_eq!(dups, 0, "no duplicate delivery");
    assert_eq!(reorders, 0, "per-writer FIFO must survive the merge");
    assert!(
        reader.take().expect("post-drain take").is_none(),
        "no stray samples after exact count"
    );
}

#[derive(Clone, Debug, hdds::DDS)]
struct DropProbe {
    value: u32,
}

#[test]
fn datareader_drop_tombstones_writer_merger() {
    // No `.with_transport(...)`, so this one defaults to UdpMulticast and
    // really does bind RTPS sockets (unlike its IntraProcess neighbours).
    // Left on the default transport on purpose -- only the domain moves,
    // off the fleet-wide default 0 and onto a leased id.
    let domain = unique_domain();
    let participant = Participant::builder("concurrency_stress_drop")
        .domain_id(domain.id())
        .build()
        .expect("participant");
    let topic = participant
        .topic::<DropProbe>("TombstoneDropProbe")
        .expect("topic");
    let writer = topic
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer");
    let merger = writer.merger();
    assert_eq!(merger.reader_count(), 0);

    let reader = topic
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader");
    assert_eq!(
        merger.reader_count(),
        1,
        "auto-bind must register the reader with the writer merger"
    );

    // Manual re-bind of the same merger is deduplicated (per-merger
    // binding identity; each accepted bind would otherwise register a
    // fresh per-binding ring).
    reader.bind_to_writer(writer.merger());
    assert_eq!(merger.reader_count(), 1);

    drop(reader);
    assert_eq!(
        merger.reader_count(),
        0,
        "reader drop must tombstone its merger registration"
    );

    // Writer stays healthy with only a tombstoned registration left.
    writer
        .write(&DropProbe { value: 7 })
        .expect("write after reader drop");

    // A fresh reader re-registers (new slot; tombstones are never reused).
    let reader2 = topic
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("second reader");
    assert_eq!(merger.reader_count(), 1);
    drop(reader2);
    assert_eq!(merger.reader_count(), 0);
}

/// Reader churn on one writer: the first reader takes inline slot 0 of
/// the writer's merger, its drop tombstones that slot (never reused),
/// and the replacement reader lands in slot 1. The merger then
/// designates slot 1 as the sole active reader, so every write takes
/// the EXCLUSIVE transfer path into a slot > 0 registration and the
/// reader pump frees each slot through `release_exclusive`. This is
/// the end-to-end shape rmw layers produce (drop + re-create on the
/// same writer), exercised here through the public DDS surface.
///
/// The EXCLUSIVE tag itself is not observable at this level: the pump
/// consumes it inside `take()` (`prepare_sample`) and the slab pool
/// keeps no counter for exclusive vs refcounted releases. What IS
/// checked: exact, in-order delivery of every sample written after
/// the churn, through a merger that reports exactly one active reader.
/// In debug builds the pool additionally `debug_assert`s a sole
/// reference on `release_exclusive`, so a mis-tagged fan-out entry
/// would panic the pump instead of passing silently.
#[test]
fn reader_recreated_after_drop_receives_every_sample() {
    const BATCHES: u32 = 64;
    const BATCH: u32 = 4;
    const DEADLINE: Duration = Duration::from_secs(5);

    let domain = unique_domain();
    let participant = Participant::builder("concurrency_stress_recreate")
        .with_transport(TransportMode::IntraProcess)
        .domain_id(domain.id())
        .build()
        .expect("participant");
    let topic = participant
        .topic::<DropProbe>("TombstoneRecreateProbe")
        .expect("topic");
    let writer = topic
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer");
    let merger = writer.merger();
    assert_eq!(merger.reader_count(), 0);

    // Slot 0: the first reader receives normally, then drops.
    let reader1 = topic
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader1");
    assert_eq!(merger.reader_count(), 1, "auto-bind registers reader1");
    writer
        .write(&DropProbe { value: 0 })
        .expect("write to reader1");
    let first = reader1.take().expect("take on reader1");
    assert_eq!(
        first.map(|s| s.value),
        Some(0),
        "reader1 receives before churn"
    );
    drop(reader1);
    assert_eq!(merger.reader_count(), 0, "reader1 drop tombstones slot 0");

    // Slot 1: the replacement reader on the same writer. Slot 0 stays
    // tombstoned ahead of it, so this registration is the sole active
    // reader at an inline index > 0.
    let reader2 = topic
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader2");
    assert_eq!(merger.reader_count(), 1, "auto-bind registers reader2");
    assert!(
        reader2.take().expect("take on fresh reader2").is_none(),
        "reader2 must not see the pre-churn sample (VOLATILE)"
    );

    // Batches keep the burst well inside the reader ring and history
    // depth so a full ring can never masquerade as a delivery bug.
    let start = Instant::now();
    let mut expected_next: u32 = 1;
    for batch in 0..BATCHES {
        for i in 0..BATCH {
            let value = 1 + batch * BATCH + i;
            loop {
                match writer.write(&DropProbe { value }) {
                    Ok(()) => break,
                    Err(Error::WouldBlock) => {
                        // Global slab pool shared with the other tests
                        // in this binary: transient exhaustion, retry.
                        assert!(start.elapsed() < DEADLINE, "writer starved on WouldBlock");
                        thread::yield_now();
                    }
                    Err(err) => panic!("write {value} failed: {err}"),
                }
            }
        }
        let batch_end = 1 + (batch + 1) * BATCH;
        while expected_next < batch_end {
            match reader2.take().expect("take on reader2") {
                Some(sample) => {
                    assert_eq!(
                        sample.value, expected_next,
                        "in-order delivery through the re-registered slot"
                    );
                    expected_next += 1;
                }
                None => {
                    assert!(
                        start.elapsed() < DEADLINE,
                        "delivery stalled at value {expected_next} of {}",
                        BATCHES * BATCH
                    );
                    thread::yield_now();
                }
            }
        }
    }
    assert_eq!(expected_next, 1 + BATCHES * BATCH, "every sample delivered");
    assert!(
        reader2.take().expect("post-drain take").is_none(),
        "no stray samples after exact count"
    );
    assert_eq!(
        merger.reader_count(),
        1,
        "reader2 stays the sole registration"
    );

    // Writer survives the second churn too (slot 1 tombstoned, no
    // active reader left).
    drop(reader2);
    assert_eq!(merger.reader_count(), 0, "reader2 drop tombstones slot 1");
    writer
        .write(&DropProbe { value: u32::MAX })
        .expect("write with no active reader");
}

/// Two writers -> two bindings with DISTINCT rings (A2). Drop must
/// tombstone each merger with its own binding's ReaderId (ids are ring
/// addresses and the rings now differ per binding).
#[test]
fn drop_tombstones_every_binding() {
    let domain = unique_domain();
    let participant = Participant::builder("concurrency_stress_drop_multi")
        .with_transport(TransportMode::IntraProcess)
        .domain_id(domain.id())
        .build()
        .expect("participant");
    let topic = participant
        .topic::<DropProbe>("TombstoneTwoWriters")
        .expect("topic");
    let writer1 = topic
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer1");
    let writer2 = topic
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer2");
    let merger1 = writer1.merger();
    let merger2 = writer2.merger();

    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(8))
        .build()
        .expect("reader");
    assert_eq!(merger1.reader_count(), 1, "auto-bind to writer1");
    assert_eq!(merger2.reader_count(), 1, "auto-bind to writer2");

    // Re-binding either merger stays a no-op (per-merger dedup).
    reader.bind_to_writer(writer1.merger());
    reader.bind_to_writer(writer2.merger());
    assert_eq!(merger1.reader_count(), 1);
    assert_eq!(merger2.reader_count(), 1);

    // Both bindings deliver through their own ring.
    writer1.write(&DropProbe { value: 1 }).expect("write w1");
    writer2.write(&DropProbe { value: 2 }).expect("write w2");
    let mut got = Vec::new();
    while let Some(sample) = reader.take().expect("take") {
        got.push(sample.value);
    }
    got.sort_unstable();
    assert_eq!(got, vec![1, 2], "one sample from each writer, no dups");

    drop(reader);
    assert_eq!(merger1.reader_count(), 0, "drop must tombstone binding 1");
    assert_eq!(merger2.reader_count(), 0, "drop must tombstone binding 2");

    // Writers stay healthy with only tombstoned registrations left.
    writer1
        .write(&DropProbe { value: 3 })
        .expect("write after drop w1");
    writer2
        .write(&DropProbe { value: 4 })
        .expect("write after drop w2");
}

#[test]
fn slab_reserve_release_storm() {
    const THREADS: usize = 8;
    const ITERS: usize = 2_000;
    const PAYLOAD: usize = 48; // 64-byte class, 64 slots: never exhausts with 8 holders

    let pool = get_slab_pool();
    // Test machinery: detects engine double-hand-out. A slot handle must
    // never be observed live by two threads at once; the mutex protects
    // the tracking set only, not the pool under test.
    let claimed: Arc<Mutex<HashSet<SlabHandle>>> = Arc::new(Mutex::new(HashSet::new()));
    let barrier = Arc::new(Barrier::new(THREADS));

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let pool = Arc::clone(&pool);
        let claimed = Arc::clone(&claimed);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let pattern = u8::try_from(0x10 + t).expect("thread pattern fits in u8");
            barrier.wait();
            let mut done = 0usize;
            while done < ITERS {
                let Some((handle, slice)) = pool.reserve(PAYLOAD) else {
                    // Global pool shared with other tests in this binary;
                    // transient exhaustion is not a failure, retry.
                    thread::yield_now();
                    continue;
                };
                {
                    let mut set = claimed.lock().expect("claim set poisoned");
                    assert!(
                        set.insert(handle),
                        "double hand-out: {handle:?} reserved while already live"
                    );
                }
                slice[..8].fill(pattern);
                thread::yield_now();
                assert!(
                    slice[..8].iter().all(|&b| b == pattern),
                    "slot bytes overwritten while held: overlapping hand-out"
                );
                {
                    let mut set = claimed.lock().expect("claim set poisoned");
                    assert!(set.remove(&handle), "handle vanished from claim set");
                }
                pool.release(handle);
                done += 1;
            }
        }));
    }

    for handle in handles {
        handle.join().expect("slab storm thread panicked");
    }

    assert!(
        claimed.lock().expect("claim set poisoned").is_empty(),
        "all reserved slots must be released"
    );
}

#[test]
fn condition_set_vs_read_storm() {
    const WRITERS: usize = 4;
    const READERS: usize = 4;
    const HOOK_CHURNERS: usize = 2;
    const ITERS: usize = 5_000;

    struct TestSignal {
        id: u64,
        hits: AtomicUsize,
    }
    impl WaitsetSignal for TestSignal {
        fn signal(&self) {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        fn id(&self) -> u64 {
            self.id
        }
    }

    let cond = Arc::new(StatusCondition::new());
    let barrier = Arc::new(Barrier::new(WRITERS + READERS + HOOK_CHURNERS));
    let mut handles = Vec::new();

    for t in 0..WRITERS {
        let cond = Arc::clone(&cond);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..ITERS {
                let mask = match (i + t) % 3 {
                    0 => StatusMask::NONE,
                    1 => StatusMask::DATA_AVAILABLE | StatusMask::SAMPLE_LOST,
                    _ => StatusMask::ALL,
                };
                cond.set_enabled_statuses(mask);
            }
        }));
    }

    for _ in 0..READERS {
        let cond = Arc::clone(&cond);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let none = StatusMask::NONE.bits();
            let pair = (StatusMask::DATA_AVAILABLE | StatusMask::SAMPLE_LOST).bits();
            let all = StatusMask::ALL.bits();
            for _ in 0..ITERS {
                let enabled = cond.get_enabled_statuses().bits();
                assert!(
                    enabled == none || enabled == pair || enabled == all,
                    "enabled mask must never tear: got {enabled:#x}"
                );
                // Active statuses are never set on the public surface,
                // so the trigger must stay false throughout the storm.
                assert!(
                    !cond.get_trigger_value(),
                    "trigger flipped true with no active statuses"
                );
                assert_eq!(cond.get_active_statuses().bits(), 0);
            }
        }));
    }

    for t in 0..HOOK_CHURNERS {
        let cond = Arc::clone(&cond);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let base = 1_000_000_u64 + (t as u64) * (ITERS as u64);
            for i in 0..ITERS {
                let id = base + i as u64;
                let signal: Arc<dyn WaitsetSignal> = Arc::new(TestSignal {
                    id,
                    hits: AtomicUsize::new(0),
                });
                cond.add_waitset_signal(signal);
                cond.remove_waitset_signal(id);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("condition storm thread panicked");
    }

    // Final state must be coherent after the storm.
    cond.set_enabled_statuses(StatusMask::ALL);
    assert_eq!(cond.get_enabled_statuses().bits(), StatusMask::ALL.bits());
    assert!(!cond.get_trigger_value());
}

#[test]
fn metrics_ring_storm() {
    const ADDERS: usize = 8;
    const SNAPSHOTTERS: usize = 2;
    const ITERS: usize = 20_000;
    const CAPACITY: usize = 512;

    let metrics = Arc::new(MetricsCollector::with_capacity(CAPACITY));
    let done = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(ADDERS + SNAPSHOTTERS));
    let mut handles = Vec::new();

    for t in 0..ADDERS {
        let metrics = Arc::clone(&metrics);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..ITERS {
                let end_ns = (t * ITERS + i + 1) as u64;
                metrics.add_latency_sample(0, end_ns);
            }
        }));
    }

    let mut snapshot_handles = Vec::new();
    for _ in 0..SNAPSHOTTERS {
        let metrics = Arc::clone(&metrics);
        let barrier = Arc::clone(&barrier);
        let done = Arc::clone(&done);
        snapshot_handles.push(thread::spawn(move || {
            barrier.wait();
            let mut snapshots = 0usize;
            while !done.load(Ordering::Relaxed) {
                let frame = metrics.snapshot();
                assert!(
                    frame.fields.len() >= 8,
                    "snapshot must always carry the counter fields"
                );
                let count = metrics.latency_sample_count();
                assert!(
                    count <= CAPACITY,
                    "sample count must never exceed ring capacity"
                );
                snapshots += 1;
            }
            snapshots
        }));
    }

    for handle in handles {
        handle.join().expect("metrics adder thread panicked");
    }
    done.store(true, Ordering::Relaxed);
    for handle in snapshot_handles {
        let snapshots = handle.join().expect("snapshot thread panicked");
        assert!(snapshots > 0, "snapshotter must complete at least one pass");
    }

    assert_eq!(
        metrics.latency_sample_count(),
        CAPACITY,
        "ring must saturate at capacity after {} samples",
        ADDERS * ITERS
    );
    let frame = metrics.snapshot();
    assert!(
        frame.fields.iter().any(|f| f.tag == TAG_LATENCY_P50),
        "saturated ring must yield latency percentiles"
    );
}

/// B1 acceptance at the rt level: one producer fans REAL slab payloads
/// out to M rings (multi-binding guard + incr-before-push protocol)
/// while every reader drains its own ring concurrently, verifies the
/// payload bytes against the entry header, and releases through the
/// refcounted path. Two readers churn out mid-traffic (their threads
/// stop first -- SPSC single-consumer -- then remove_reader drains the
/// tombstoned backlog). Payload sizes alternate between a small class
/// and 100 KB so the 128 KB class saturates and the HEAP tier engages
/// (the heap-tier zone). Byte corruption = the generation-tag race
/// reborn; a short heap buffer = the take-the-box race reborn; nonzero
/// heap gauge or unclaimable class at quiescence = refcount leak.
#[test]
fn slab_refcount_fanout_storm() {
    const READERS: usize = 6;
    const CHURNED: usize = 2; // readers 0 and 1 leave mid-traffic
    const PUSHES: usize = 1_200;
    const RING_CAPACITY: usize = 256;
    const BIG_LEN: usize = 100_000;
    const SMALL_LEN: usize = 200;

    let pool = Arc::new(SlabPool::new());
    let merger = Arc::new(TopicMerger::new());
    let rings: Vec<Arc<IndexRing>> = (0..READERS)
        .map(|_| Arc::new(IndexRing::with_capacity(RING_CAPACITY)))
        .collect();
    let mut ids = Vec::new();
    for ring in &rings {
        let on_data: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
        let reader = MergerReader::new(Arc::clone(ring), on_data);
        ids.push(reader.id());
        assert!(merger.add_reader(reader));
    }

    let writer_done = Arc::new(AtomicBool::new(false));
    let stop_flags: Vec<Arc<AtomicBool>> = (0..READERS)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();
    // Waiters: READERS reader threads + the producer + main.
    let barrier = Arc::new(Barrier::new(READERS + 2));

    // Reader threads: pop, verify bytes under the held ref, release.
    let mut reader_handles = Vec::new();
    for (k, ring) in rings.iter().enumerate() {
        let ring = Arc::clone(ring);
        let pool = Arc::clone(&pool);
        let done = Arc::clone(&writer_done);
        let stop = Arc::clone(&stop_flags[k]);
        let barrier = Arc::clone(&barrier);
        reader_handles.push(thread::spawn(move || {
            barrier.wait();
            let mut received = 0usize;
            loop {
                match ring.pop() {
                    Some(entry) => {
                        let len = entry.len as usize;
                        let buf = pool.get_buffer(entry.handle);
                        // A holder must always see the full buffer.
                        assert!(
                            buf.len() >= len,
                            "reader {k}: buffer {} bytes < entry len {} (heap theft)",
                            buf.len(),
                            len
                        );
                        // Bytes must match the generation stamped in
                        // the entry header (slab reuse under a live
                        // handle decodes a FOREIGN payload).
                        let tag = entry.seq.to_le_bytes();
                        assert_eq!(&buf[..4], &tag, "reader {k}: header tag mismatch");
                        let fill = (entry.seq as u8) ^ 0x5A;
                        assert!(
                            buf[4..len].iter().all(|&b| b == fill),
                            "reader {k}: payload fill corrupted at seq {}",
                            entry.seq
                        );
                        drop(buf);
                        pool.release(entry.handle);
                        received += 1;
                    }
                    None => {
                        if stop.load(Ordering::Acquire) {
                            break; // churned out; leftovers drained by remove_reader
                        }
                        if done.load(Ordering::Acquire) && ring.is_empty() {
                            break;
                        }
                        thread::yield_now();
                    }
                }
            }
            received
        }));
    }

    // Producer: real reservations, alternating size classes.
    let producer = {
        let merger = Arc::clone(&merger);
        let pool = Arc::clone(&pool);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            let mut big = vec![0u8; BIG_LEN];
            let mut small = vec![0u8; SMALL_LEN];
            for i in 0..PUSHES {
                let seq = u32::try_from(i).expect("seq fits u32");
                let payload: &mut [u8] = if i % 8 == 0 { &mut big } else { &mut small };
                payload[..4].copy_from_slice(&seq.to_le_bytes());
                let fill = (seq as u8) ^ 0x5A;
                for b in payload[4..].iter_mut() {
                    *b = fill;
                }
                // Bounded retry: readers holding refs can exhaust the
                // class + heap ceiling transiently.
                let handle = loop {
                    match pool.bench_reserve_and_write(payload) {
                        Some(h) => break h,
                        None => thread::yield_now(),
                    }
                };
                let len = u32::try_from(payload.len()).expect("len fits u32");
                let entry = IndexEntry::new(seq, handle, len);
                // Lossy by design (rings may fill); push consumes the ref.
                let _ = merger.push(entry, &pool);
            }
        })
    };

    barrier.wait();

    // Churn UNDER FIRE (mirrors DataReader::Drop): stop two readers,
    // join their threads (the ring is SPSC, remove_reader may only
    // drain once the consumer is gone), then tombstone + drain their
    // backlog while the producer is still firing. Without the prompt
    // drain the parked rings would hold enough references to exhaust
    // the pool and wedge the producer.
    thread::sleep(Duration::from_millis(20));
    let mut reader_handles: Vec<Option<thread::JoinHandle<usize>>> =
        reader_handles.into_iter().map(Some).collect();
    let mut total_received = 0usize;
    for k in 0..CHURNED {
        stop_flags[k].store(true, Ordering::Release);
        let handle = reader_handles[k].take().expect("churned handle present");
        total_received += handle.join().expect("churned reader panicked");
        assert!(
            merger.remove_reader(ids[k], &pool),
            "churned reader {k} must tombstone"
        );
    }

    producer.join().expect("producer thread panicked");
    writer_done.store(true, Ordering::Release);

    for (k, handle) in reader_handles.into_iter().enumerate().skip(CHURNED) {
        let received = handle
            .expect("surviving handle present")
            .join()
            .expect("reader thread panicked");
        assert!(received > 0, "surviving reader {k} must receive samples");
        total_received += received;
    }
    // Surviving readers drained their rings before exiting. Tombstone
    // them too (releases nothing new).
    for id in ids.iter().skip(CHURNED) {
        assert!(merger.remove_reader(*id, &pool));
    }
    // A push in flight during the under-fire tombstone can have landed
    // entries in a churned ring AFTER its drain (the documented
    // single-entry residual window). All producers are gone now: drain
    // the residue so quiescence accounting is exact.
    for ring in rings.iter().take(CHURNED) {
        while let Some(entry) = ring.pop() {
            pool.release(entry.handle);
        }
    }
    assert!(total_received > 0, "storm must deliver samples");

    // Quiescence: every reference returned. The heap gauge must be zero
    // and the 128 KB class must be fully reclaimable (16 slots).
    let (_p, _l, _h, _d, heap_used) = pool.metrics().snapshot();
    assert_eq!(heap_used, 0, "heap bytes leaked: {heap_used}");
    let probe = vec![0u8; BIG_LEN];
    let mut probes = Vec::new();
    for i in 0..16 {
        let h = pool
            .bench_reserve_and_write(&probe)
            .unwrap_or_else(|| panic!("128KB-class slot {i} leaked"));
        probes.push(h);
    }
    // If any probe had spilled to the heap tier, the gauge would be
    // nonzero here: all 16 came from the reclaimed primary class.
    let (_p2, _l2, _h2, _d2, heap_after_probes) = pool.metrics().snapshot();
    assert_eq!(
        heap_after_probes, 0,
        "probe reservations spilled to heap: class slots leaked"
    );
    for h in probes {
        pool.release(h);
    }
}
