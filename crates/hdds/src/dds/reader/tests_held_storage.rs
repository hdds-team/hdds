// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A reliable reader acknowledges a sample its reorder gate holds (RTPS 2.5
//! Sec.8.4.12.2: it is in the reader's keeping), so the sample must be in
//! the reader's keeping BEFORE that: its slab storage taken on arrival,
//! kept through the gate, refused unacknowledged when there is none (the
//! writer sends it again, in order). DDS 1.4 Sec.2.2.3.14: a reliable reader
//! may not make later samples available while earlier ones were never
//! received; Sec.2.2.3.19 footnote 28: a sample refused for want of
//! resources is one "re-sent at a later time".
//!
//! Keeping a held sample in its received form, outside the pool, and taking
//! its storage only at its release, in order, would lose it acknowledged when
//! the pool is out of memory; storing it past the pool's ceiling instead
//! would let the heap tier reach several times its configured bound. The end
//! to end case is a VOLATILE KEEP_ALL pair in one process over UDP: 3000
//! samples of 6 kB, the writer's unacknowledged history filling the
//! process-wide 16 MB pool.
//!
//! A coherent set's staged samples are acknowledged before they can be
//! taken too, but are stored apart, in their reader's own staging budget:
//! `tests_coherent_staging`.

use crate::core::rt;
use crate::engine::Subscriber;
use std::sync::{Arc, Mutex};

const WRITER: [u8; 16] = [0x7C; 16];

/// Over the largest primary class (128 KiB) once re-encoded: stored in
/// the heap tier only, whose ceiling the test sets.
#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Big {
    id: i32,
    body: Vec<u8>,
}

const BODY: usize = 200_000;

fn encoded(seq: u64) -> Vec<u8> {
    let id = i32::try_from(seq).expect("small");
    let sample = Big {
        id,
        body: vec![0x3C; BODY],
    };
    let mut bytes = vec![0u8; BODY + 1024];
    let len = crate::dds::DDS::encode(&sample, &mut bytes, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    bytes.truncate(len);
    bytes
}

/// A reliable KEEP_ALL network subscriber behind a VOLATILE gate, crediting
/// `credit`.
fn subscriber(
    credit: &crate::core::reader::ReaderAckCredit,
    rejected: &Arc<Mutex<crate::dds::listener::SampleRejectedStatus>>,
) -> (Arc<rt::IndexRing>, super::subscriber::ReaderSubscriber<Big>) {
    let ring = Arc::new(rt::IndexRing::with_capacity(16));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let mut sub = super::subscriber::ReaderSubscriber::<Big>::new_with_coherent(
        "t".to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, true))),
        super::subscriber::CoherentConfig {
            coherent_access: false,
            is_group_scope: false,
        },
        None,
        Some(credit.clone()),
        Arc::clone(rejected),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    sub.room = Some(super::admission::HistoryRoom::new(
        &ring,
        crate::reliability::LENGTH_UNLIMITED,
    ));
    sub.register_match_entry_for_test(crate::dds::QoS::reliable().keep_all());
    (ring, sub)
}

fn data(sub: &super::subscriber::ReaderSubscriber<Big>, seq: u64) {
    sub.on_data_with_writer(
        "t",
        WRITER,
        seq,
        &encoded(seq),
        crate::dds::CdrVersion::Xcdr2,
    );
}

/// The application takes everything in the ring: sequences, storage given
/// back to `pool`, places to the room.
fn take_all(
    ring: &rt::IndexRing,
    sub: &super::subscriber::ReaderSubscriber<Big>,
    pool: &rt::SlabPool,
) -> Vec<u64> {
    let mut seqs = Vec::new();
    while let Some(entry) = ring.pop() {
        seqs.push(u64::from(entry.seq));
        pool.release(entry.handle);
        drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
    }
    seqs
}

/// A pool of this thread's own whose heap tier holds `ceiling` bytes, all
/// of it the readers' share (no writer here): what held samples may take.
fn private_pool(ceiling: usize) -> (&'static Arc<rt::SlabPool>, rt::PrivateSlabPoolGuard) {
    let policy = crate::qos::MemoryPolicy {
        max_heap_bytes: ceiling,
        reader_reserve_percent: 100,
        ..crate::qos::MemoryPolicy::default()
    };
    let (pool, guard) = rt::owned_private_slab_pool_for_test(&policy);
    (pool, guard)
}

fn heap_used(pool: &rt::SlabPool) -> usize {
    pool.metrics()
        .heap_bytes_used
        .load(std::sync::atomic::Ordering::Acquire)
}

/// What the reader acknowledges of 1..=`last`: (base, missing).
fn acknowledged(
    credit: &crate::core::reader::ReaderAckCredit,
    last: u64,
    count: u32,
) -> (u64, Vec<u64>) {
    let answer = credit
        .answer_heartbeat(
            &WRITER,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq: i64::try_from(last).expect("small"),
                count,
                final_flag: false,
            },
        )
        .expect("matched");
    (answer.bitmap_base, answer.missing)
}

/// A sample that arrives above a gap while the pool has no room for it is
/// not acknowledged and not held in its received form: it is refused
/// unacknowledged, and the writer sends it again once the samples before it
/// are taken. The sample next in order, with no room either, is stored past
/// the heap tier's ceiling by itself alone (`rt::Claim::Head`), and the tier
/// goes no further. Every sample is delivered, in order.
#[test]
fn a_sample_held_above_a_gap_is_stored_before_it_is_acknowledged() {
    // The heap tier holds one stored sample, not two.
    let ceiling = BODY + BODY / 2;
    let (pool, _pool_guard) = private_pool(ceiling);
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA0; 16],
    );
    credit.match_writer(WRITER);
    let rejected = Arc::new(Mutex::new(
        crate::dds::listener::SampleRejectedStatus::default(),
    ));
    let (ring, sub) = subscriber(&credit, &rejected);
    let within = |step: &str, over: usize| {
        assert!(
            heap_used(pool) <= ceiling + over,
            "{step}: heap tier at {} over its {ceiling} ceiling (+{over})",
            heap_used(pool)
        );
    };
    let one = encoded(1).len() + 16;

    // 1 joins the gate and is stored: the heap tier is full.
    data(&sub, 1);
    within("1 stored", 0);
    // 3 arrives before 2, with no memory to hold it: refused,
    // unacknowledged.
    data(&sub, 3);
    within("3 refused", 0);
    // 2, next in order, with no memory either: stored past the ceiling,
    // by itself alone.
    data(&sub, 2);
    within("2 stored past the ceiling", one);
    assert!(heap_used(pool) > ceiling, "fixture: 2 is past the ceiling");
    // 3, sent again, finds the tier past its ceiling: refused again.
    data(&sub, 3);
    within("3 refused again", one);
    assert_eq!(
        acknowledged(&credit, 3, 1),
        (3, vec![3]),
        "nothing the reader had no storage for is acknowledged"
    );
    // The application takes 1 and 2; the writer sends 3 again.
    let mut taken = take_all(&ring, &sub, pool);
    data(&sub, 3);
    within("3 stored", 0);
    taken.extend(take_all(&ring, &sub, pool));
    assert_eq!(
        taken,
        vec![1, 2, 3],
        "every sample reaches the application, in order"
    );
    assert_eq!(acknowledged(&credit, 3, 2), (4, vec![]));
    assert_eq!(
        rejected.lock().expect("status").total_count,
        2,
        "each copy refused for want of storage is a rejection"
    );
}

/// A window of samples held above a missing one takes storage within the
/// heap tier's ceiling, and keeps the room the missing one needs: the
/// samples past that room are refused unacknowledged, the missing one is
/// stored when it comes, and releases the held ones behind it. The held
/// window must not be stored only at that release, past the ceiling.
#[test]
fn a_held_window_stays_within_the_ceiling_and_keeps_room_for_its_head() {
    // Room for four samples and a half: three held, and the head.
    let ceiling = 4 * BODY + BODY / 2;
    let (pool, _pool_guard) = private_pool(ceiling);
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA0; 16],
    );
    credit.match_writer(WRITER);
    let rejected = Arc::new(Mutex::new(
        crate::dds::listener::SampleRejectedStatus::default(),
    ));
    let (ring, sub) = subscriber(&credit, &rejected);
    data(&sub, 1);
    assert_eq!(take_all(&ring, &sub, pool), vec![1]);
    // 3..=14 above a missing 2 (a ring of 16 has 15 places).
    for seq in 3..=14 {
        data(&sub, seq);
        assert!(heap_used(pool) <= ceiling, "seq {seq}: over the ceiling");
    }
    assert_eq!(
        acknowledged(&credit, 14, 1),
        (2, (2..=14).filter(|&s| !(3..=5).contains(&s)).collect()),
        "three held, stored; the rest refused unacknowledged"
    );
    // The head finds the room kept for it, and releases 3..=5.
    data(&sub, 2);
    assert!(heap_used(pool) <= ceiling, "head stored within the ceiling");
    assert_eq!(take_all(&ring, &sub, pool), vec![2, 3, 4, 5]);
    // The writer sends the rest again, in order, as the application takes.
    let mut taken = Vec::new();
    for seq in 6..=14 {
        data(&sub, seq);
        assert!(heap_used(pool) <= ceiling, "seq {seq}: over the ceiling");
        taken.extend(take_all(&ring, &sub, pool));
    }
    assert_eq!(taken, (6..=14).collect::<Vec<_>>());
    assert_eq!(acknowledged(&credit, 14, 2), (15, vec![]));
    assert_eq!(heap_used(pool), 0, "everything taken, nothing left held");
    assert_eq!(
        pool.metrics()
            .held_heap_bytes
            .load(std::sync::atomic::Ordering::Acquire),
        0,
        "no hold outlives its sample"
    );
}

/// A readers' share smaller than one sample, and a co-located writer's
/// history at its ceiling, which only the reader's acknowledgement frees:
/// the reader's next sample in order is stored past the heap tier's
/// ceiling (`rt::Claim::Head`) rather than refused for good, which would
/// happen if only the head of a gap with samples held above it could pass.
#[test]
fn a_share_smaller_than_a_sample_still_takes_the_next_in_order() {
    let ceiling = BODY + BODY / 2;
    let policy = crate::qos::MemoryPolicy {
        max_heap_bytes: ceiling,
        reader_reserve_percent: 25,
        ..crate::qos::MemoryPolicy::default()
    };
    let (pool, _pool_guard) = rt::owned_private_slab_pool_for_test(&policy);
    let history = pool
        .reserve_and_write(&encoded(9), rt::Claim::Writer)
        .expect("fixture: the writer's history")
        .0;
    assert!(pool
        .reserve_and_write(&encoded(9), rt::Claim::Writer)
        .is_none());
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA0; 16],
    );
    credit.match_writer(WRITER);
    let rejected = Arc::new(Mutex::new(
        crate::dds::listener::SampleRejectedStatus::default(),
    ));
    let (ring, sub) = subscriber(&credit, &rejected);
    data(&sub, 1);
    assert_eq!(acknowledged(&credit, 1, 1), (2, vec![]));
    assert_eq!(take_all(&ring, &sub, pool), vec![1]);
    pool.release(history);
}
