// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Helpers copied from tests_coherent_staging.rs.
//! A coherent reader acknowledges a staged member long before its set
//! commits (RTPS v2.5 Sec.8.4.12.2), so the member is stored first, and its
//! storage is the reader's own: apart from the slab pool's tiers, charged to
//! the reader's staging budget (`staging_budget`, which states the rule).
//! These tests pin that rule: a member is stored before it is acknowledged;
//! a set larger than a set may take is rejected whole, and nothing else
//! rejects a set; a set in order (nothing of its writer awaited below it)
//! is never refused, the sets above a gap share one set's limit, and a
//! member they have no room for is refused unacknowledged and staged once
//! resent; staging takes nothing of what writers and other readers store,
//! nor they of it.

use crate::core::rt;
use crate::engine::Subscriber;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

/// Over the largest primary class (128 KiB) once re-encoded.
#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Big {
    id: i32,
    body: Vec<u8>,
}

const BODY: usize = 200_000;

const A: [u8; 16] = [0x7A; 16];

fn encoded(seq: u64) -> Vec<u8> {
    encoded_of(seq, BODY)
}

/// [`encoded`] with a body of `body` bytes.
fn encoded_of(seq: u64, body: usize) -> Vec<u8> {
    let sample = Big {
        id: i32::try_from(seq).expect("small"),
        body: vec![0x3C; body],
    };
    let mut bytes = vec![0u8; body + 1024];
    let len = crate::dds::DDS::encode(&sample, &mut bytes, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    bytes.truncate(len);
    bytes
}

/// The stored form of every sample here: re-encoded, after its writer's
/// GUID.
fn stored_len() -> usize {
    encoded(1).len() + 16
}

type Rejected = Arc<Mutex<crate::dds::listener::SampleRejectedStatus>>;

/// A reliable KEEP_ALL coherent subscriber (GROUP scope when `group`)
/// crediting `credit`, staging sets of at most `samples` samples.
fn subscriber(
    credit: &crate::core::reader::ReaderAckCredit,
    rejected: &Rejected,
    group: bool,
    samples: usize,
) -> (Arc<rt::IndexRing>, super::subscriber::ReaderSubscriber<Big>) {
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
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
            coherent_access: true,
            is_group_scope: group,
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
    sub.staging = super::staging_budget::StagingBudget::new(samples);
    sub.register_match_entry_for_test(crate::dds::QoS::reliable().keep_all());
    (ring, sub)
}

fn credit_for(writers: &[[u8; 16]]) -> (crate::core::reader::ReaderAckCredit, Rejected) {
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA0; 16],
    );
    for writer in writers {
        credit.match_writer(*writer);
    }
    (credit, Arc::default())
}

/// A pool of this thread's own whose heap tier holds `ceiling` bytes, of
/// which `percent` the readers' share, and whose staging ceiling
/// (`MemoryPolicy::max_staging_bytes`) is `ceiling` too.
fn private_pool(
    ceiling: usize,
    percent: u8,
) -> (&'static Arc<rt::SlabPool>, rt::PrivateSlabPoolGuard) {
    let policy = crate::qos::MemoryPolicy {
        max_heap_bytes: ceiling,
        reader_reserve_percent: percent,
        max_staging_bytes: ceiling,
        ..crate::qos::MemoryPolicy::default()
    };
    let (pool, guard) = rt::owned_private_slab_pool_for_test(&policy);
    (pool, guard)
}

fn member(sub: &super::subscriber::ReaderSubscriber<Big>, writer: [u8; 16], seq: u64, start: u64) {
    sub.on_data_coherent(
        "t",
        writer,
        seq,
        &encoded(seq),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        None,
        None,
    );
}

fn plain(sub: &super::subscriber::ReaderSubscriber<Big>, writer: [u8; 16], seq: u64) {
    sub.on_data_with_writer(
        "t",
        writer,
        seq,
        &encoded(seq),
        crate::dds::CdrVersion::Xcdr2,
    );
}

/// The application takes everything in the ring.
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

/// What the reader acknowledges of `writer`'s `first..=last`: (base,
/// missing).
fn acknowledged(
    credit: &crate::core::reader::ReaderAckCredit,
    writer: [u8; 16],
    first: u64,
    last: u64,
    count: u32,
) -> (u64, Vec<u64>) {
    let answer = credit
        .answer_heartbeat(
            &writer,
            &crate::core::reader::HeartbeatSeen {
                first_seq: i64::try_from(first).expect("small"),
                last_seq: i64::try_from(last).expect("small"),
                count,
                final_flag: false,
            },
        )
        .expect("matched");
    (answer.bitmap_base, answer.missing)
}

fn staged_heap(pool: &rt::SlabPool) -> usize {
    pool.metrics().staged_heap_bytes.load(Ordering::Acquire)
}

fn heap_used(pool: &rt::SlabPool) -> usize {
    pool.metrics().heap_bytes_used.load(Ordering::Acquire)
}

fn tiny(sub: &super::subscriber::ReaderSubscriber<Big>, writer: [u8; 16], seq: u64, start: u64) {
    sub.on_data_coherent(
        "t",
        writer,
        seq,
        &encoded_of(seq, 8),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        None,
        None,
    );
}

fn entries(sub: &super::subscriber::ReaderSubscriber<Big>, writer: [u8; 16]) -> usize {
    sub.coherent_buffer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&writer)
        .map_or(0, Vec::len)
}

/// Q2a: a remote writer opens one TOPIC set and never closes it. Past N
/// members the set is rejected; every later member is acknowledged with no
/// storage and pushed as a staging entry: does the writer's staging stay
/// within MAX_STAGED_PER_WRITER entries?
#[test]
fn v4_a_rejected_set_never_closed_stays_bounded() {
    let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    // The default budget (N = MAX_STAGED_PER_WRITER, 64 in tests).
    let (_ring, sub) = subscriber(&credit, &rejected, false, 4096);
    sub.on_writer_heartbeat(A, 1);
    let cap = super::subscriber::MAX_STAGED_PER_WRITER;
    let count: u64 = 20_000;
    let t0 = std::time::Instant::now();
    for seq in 1..=count {
        tiny(&sub, A, seq, 1);
    }
    let el = t0.elapsed();
    let n = entries(&sub, A);
    eprintln!(
        "v4 Q2a: {count} members of one never-closed set -> {n} staging entries \
         (cap {cap}), size_of BufferedCoherentSample = {} B, staged gauge {} B, \
         acknowledged {:?}, {:?} total",
        std::mem::size_of::<super::subscriber::BufferedCoherentSample>(),
        sub.staging.used(),
        acknowledged(&credit, A, 1, count, 1).0,
        el
    );
    assert!(n <= cap, "{n} staging entries for one writer, bound {cap}");
}

/// Q2a, GROUP scope.
#[test]
fn v4_a_rejected_group_set_never_closed_stays_bounded() {
    const PUBLISHER: [u8; 4] = [0, 0, 1, 8];
    let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (_ring, sub) = subscriber(&credit, &rejected, true, 4096);
    sub.on_writer_heartbeat(A, 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let count: u64 = 20_000;
    for seq in 1..=count {
        sub.on_data_coherent(
            "t",
            A,
            seq,
            &encoded_of(seq, 8),
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            Some(1),
            Some(PUBLISHER),
        );
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let n: usize = sub
        .group_coherent_buffer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .map(|s| s.total_samples())
        .sum();
    let cap = super::subscriber::MAX_STAGED_PER_GROUP;
    eprintln!("v4 Q2a GROUP: {count} members -> {n} group staging entries (cap {cap})");
    assert!(n <= cap, "{n} group staging entries, bound {cap}");
}

/// Q2b: staged storage is outside every process ceiling. W remote writers
/// each open one set of N members in order and never close it; every member
/// is acknowledged. The process pool's ceiling is 1 MiB; what is staged?
#[test]
fn v4_staged_storage_is_within_the_process_ceiling() {
    const W: u8 = 8;
    let ceiling = 1024 * 1024;
    let (pool, _guard) = private_pool(ceiling, 25);
    let writers: Vec<[u8; 16]> = (0..W).map(|i| [0x40 + i; 16]).collect();
    let (credit, rejected) = credit_for(&writers);
    let (_ring, sub) = subscriber(&credit, &rejected, false, 4096);
    let n = super::subscriber::MAX_STAGED_PER_WRITER as u64;
    for w in &writers {
        sub.on_writer_heartbeat(*w, 1);
        for seq in 1..=n {
            member(&sub, *w, seq, 1);
        }
    }
    let staged = staged_heap(pool);
    let acked: Vec<u64> = writers
        .iter()
        .map(|w| acknowledged(&credit, *w, 1, n, 1).0)
        .collect();
    eprintln!(
        "v4 Q2b: {W} writers x {n} members x {} B: staged {staged} B, reader gauge {} B, \
         budget formula {} B, pool ceiling {ceiling} B, heap_used {}, acked bases {acked:?}, \
         rejected {}",
        stored_len(),
        sub.staging.used(),
        sub.staging.budget(),
        heap_used(pool),
        rejected.lock().expect("status").total_count
    );
    assert!(
        sub.staging.used() <= sub.staging.budget(),
        "the claimed bound L x (1 + sets in order) holds"
    );
    assert!(
        staged <= ceiling,
        "{staged} B staged and acknowledged by one reader, past the {ceiling} B ceiling"
    );
}

/// Q3: a set {3, 4}; 3 staged; the KEEP_LAST writer gives 4 up (HEARTBEAT
/// firstSN 5); 4, in flight, arrives late and is dropped by the new rule.
/// The set can never be whole: 3 must not reach the application alone, and
/// the loss must be reported.
#[test]
fn v4_a_set_cut_by_a_heartbeat_is_not_delivered_in_part() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 64);
    sub.on_writer_heartbeat(A, 1);
    plain(&sub, A, 1);
    plain(&sub, A, 2);
    let mut taken = take_all(&ring, &sub, pool);
    member(&sub, A, 3, 3);
    sub.on_writer_heartbeat_range(A, 5, 6);
    member(&sub, A, 4, 3);
    plain(&sub, A, 5);
    plain(&sub, A, 6);
    taken.extend(take_all(&ring, &sub, pool));
    let lost = sub.sample_lost.lock().expect("lost").total_count;
    eprintln!(
        "v4 Q3: taken {taken:?} lost {lost} staged {}",
        sub.staging.used()
    );
    assert!(
        !taken.contains(&3) || taken.contains(&4),
        "member 3 delivered without 4: a set in part ({taken:?})"
    );
    assert_eq!(sub.staging.used(), 0, "nothing left staged");
    assert!(lost >= 1, "4 reported lost");
}

/// Q3b: the same with both members in flight past the HEARTBEAT: a set
/// wholly below the gate is dropped, reported lost (counted once).
#[test]
fn v4_a_set_wholly_below_the_gate_is_reported_lost_once() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 64);
    sub.on_writer_heartbeat(A, 1);
    plain(&sub, A, 1);
    let mut taken = take_all(&ring, &sub, pool);
    sub.on_writer_heartbeat_range(A, 4, 5);
    member(&sub, A, 2, 2);
    member(&sub, A, 3, 2);
    plain(&sub, A, 4);
    plain(&sub, A, 5);
    taken.extend(take_all(&ring, &sub, pool));
    let lost = sub.sample_lost.lock().expect("lost").total_count;
    eprintln!("v4 Q3b: taken {taken:?} lost {lost}");
    assert_eq!(taken, vec![1, 4, 5]);
    assert_eq!(lost, 2, "2 and 3 reported lost, once each");
    assert_eq!(acknowledged(&credit, A, 4, 5, 1), (6, vec![]));
}

/// Q1: KEEP_LAST reader history (depth 1, one instance): sets of 5 members
/// replace each other at commit. Every staged charge must go back.
#[test]
fn v4_max_samples_one_rejects_sets_of_five_and_gives_every_charge_back() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, mut sub) = subscriber(&credit, &rejected, false, 8);
    sub.room = Some(super::admission::HistoryRoom::new(&ring, 1));
    sub.on_writer_heartbeat(A, 1);
    let mut seq = 1;
    let mut taken = Vec::new();
    for _set in 0..50 {
        let start = seq;
        for _ in 0..5 {
            member(&sub, A, seq, start);
            seq += 1;
        }
        if seq % 3 == 0 {
            taken.extend(take_all(&ring, &sub, pool));
        }
    }
    plain(&sub, A, seq);
    taken.extend(take_all(&ring, &sub, pool));
    eprintln!(
        "v4 Q1 keep_last: taken {} samples, staged gauge {} staged heap {} rejected {}",
        taken.len(),
        sub.staging.used(),
        staged_heap(pool),
        rejected.lock().expect("status").total_count
    );
    assert_eq!(acknowledged(&credit, A, 1, seq, 1), (seq + 1, vec![]));
    assert_eq!(sub.staging.used(), 0);
    assert_eq!(staged_heap(pool), 0);
}
