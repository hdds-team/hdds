// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Memory-budget contract tests for coherent-set staging. Each test states
//! the contract it expects (a set must neither stall for good nor be
//! rejected when no cycle needs the room), with each coherent reader
//! staging in a budget of its own (`staging_budget`). The tests run with
//! the reader's default budget, and again in a tight budget.

use crate::core::rt;
use crate::engine::Subscriber;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Vbig {
    id: i32,
    body: Vec<u8>,
}

fn encoded(seq: u64, body: usize) -> Vec<u8> {
    let sample = Vbig {
        id: i32::try_from(seq % 1_000_000).expect("small"),
        body: vec![0x3C; body],
    };
    let mut bytes = vec![0u8; body + 1024];
    let len = crate::dds::DDS::encode(&sample, &mut bytes, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    bytes.truncate(len);
    bytes
}

type Rej = Arc<Mutex<crate::dds::listener::SampleRejectedStatus>>;

fn subscriber(
    credit: &crate::core::reader::ReaderAckCredit,
    rejected: &Rej,
    coherent: bool,
    group: bool,
) -> (
    Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Vbig>,
) {
    subscriber_staging(credit, rejected, coherent, group, None)
}

/// [`subscriber`], staging sets of at most `samples` samples when given.
fn subscriber_staging(
    credit: &crate::core::reader::ReaderAckCredit,
    rejected: &Rej,
    coherent: bool,
    group: bool,
    samples: Option<usize>,
) -> (
    Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Vbig>,
) {
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let mut sub = super::subscriber::ReaderSubscriber::<Vbig>::new_with_coherent(
        "t".to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, true))),
        super::subscriber::CoherentConfig {
            coherent_access: coherent,
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
    if let Some(samples) = samples {
        sub.staging = super::staging_budget::StagingBudget::new(samples);
    }
    sub.register_match_entry_for_test(crate::dds::QoS::reliable().keep_all());
    (ring, sub)
}

fn plain(sub: &super::subscriber::ReaderSubscriber<Vbig>, w: [u8; 16], seq: u64, body: usize) {
    sub.on_data_with_writer(
        "t",
        w,
        seq,
        &encoded(seq, body),
        crate::dds::CdrVersion::Xcdr2,
    );
}

fn member(
    sub: &super::subscriber::ReaderSubscriber<Vbig>,
    w: [u8; 16],
    seq: u64,
    start: u64,
    body: usize,
) {
    sub.on_data_coherent(
        "t",
        w,
        seq,
        &encoded(seq, body),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        None,
        None,
    );
}

fn take_all(
    ring: &rt::IndexRing,
    sub: &super::subscriber::ReaderSubscriber<Vbig>,
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

fn private_pool(
    max_heap_bytes: usize,
    percent: u8,
) -> (&'static Arc<rt::SlabPool>, rt::PrivateSlabPoolGuard) {
    let policy = crate::qos::MemoryPolicy {
        max_heap_bytes,
        reader_reserve_percent: percent,
        ..crate::qos::MemoryPolicy::default()
    };
    let (pool, guard) = rt::owned_private_slab_pool_for_test(&policy);
    (pool, guard)
}

fn credit_for(writers: &[[u8; 16]]) -> (crate::core::reader::ReaderAckCredit, Rej) {
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA3; 16],
    );
    for w in writers {
        credit.match_writer(*w);
    }
    (credit, Arc::default())
}

fn held(pool: &rt::SlabPool) -> usize {
    pool.metrics()
        .held_heap_bytes
        .load(std::sync::atomic::Ordering::Acquire)
}

const W: [u8; 16] = [0x51; 16];
const A: [u8; 16] = [0x5A; 16];
const B: [u8; 16] = [0x5B; 16];

/// Q2 false negative. Plain samples of one writer held above a gap whose
/// head is the (only) member of a coherent set, larger than the head
/// estimate the held samples kept room for. The held samples ("run") are
/// never a victim, the set holds nothing (never a victim): the residue
/// {run, set} has no victim, `Verdict::Wait`, and the writer resends the
/// member forever. Contract: everything is delivered (or the set rejected),
/// no permanent stall.
#[test]
fn m3_a_coherent_head_larger_than_the_estimate_under_a_held_run_does_not_stall() {
    let (pool, _g) = private_pool(1_000_000, 100);
    let (credit, rejected) = credit_for(&[W]);
    let (ring, sub) = subscriber(&credit, &rejected, true, false);
    sub.on_writer_heartbeat(W, 1);
    for seq in 1..=3 {
        plain(&sub, W, seq, 150_000);
    }
    assert_eq!(take_all(&ring, &sub, pool), vec![1, 2, 3]);
    // Set {4} lost; plain 5.. arrive and are held above the gap.
    for seq in 5..=12 {
        plain(&sub, W, seq, 150_000);
    }
    let run = held(pool);
    eprintln!("m3: held by the run: {run}");
    let mut taken = Vec::new();
    for _round in 0..50 {
        member(&sub, W, 4, 4, 400_000);
        for seq in 5..=12 {
            plain(&sub, W, seq, 150_000);
        }
        taken.extend(take_all(&ring, &sub, pool));
        if taken.contains(&12) {
            break;
        }
    }
    let rej = rejected.lock().expect("s").total_count;
    eprintln!("m3: taken={taken:?} rejected={rej} held={}", held(pool));
    assert_eq!(
        sub.staging.used(),
        0,
        "the set's charge given back once delivered"
    );
    assert!(
        taken.contains(&12),
        "permanent stall after 50 resend rounds: run held {run}, member 4 (400 kB) never \
         staged, rejected={rej}, held={}",
        held(pool)
    );
}

/// Q1b / Q2 false positive. Two writers, separate process (no co-located
/// writer: the PATIENCE rationale cannot apply). A's set {1..5} is complete
/// but for its close (its writer slow: the close is its next write). B's set
/// is refused for storage A holds; B's writer resends. No deadlock: A's close
/// needs no hold, A commits, B fits. Contract: neither set is rejected, both
/// are delivered whole once A closes, however many resends B made meanwhile
/// (a 2 s delay at a 100 ms heartbeat is 20 repair rounds).
#[test]
fn m3_a_slow_writers_set_is_not_rejected_by_patience() {
    slow_writers_set(None);
}

/// A budget of sets of five, a third writer's set taking three of
/// five: A's set waits for its slow writer, B's is in order and staged
/// whole beside it; nothing is refused, nothing rejected.
#[test]
fn m3_a_slow_writers_set_in_a_tight_budget_is_delivered() {
    slow_writers_set(Some(5));
}

fn slow_writers_set(samples: Option<usize>) {
    const C: [u8; 16] = [0x5C; 16];
    let (pool, _g) = private_pool(1_000_000, 100);
    let (credit, rejected) = credit_for(&[A, B, C]);
    let (ring, sub) = subscriber_staging(&credit, &rejected, true, false, samples);
    sub.on_writer_heartbeat(A, 1);
    sub.on_writer_heartbeat(B, 11);
    for seq in 1..=5 {
        member(&sub, A, seq, 1, 140_000);
    }
    if samples.is_some() {
        // C's set, open: three of the others' part.
        sub.on_writer_heartbeat(C, 31);
        for seq in 31..=33 {
            member(&sub, C, seq, 31, 140_000);
        }
    }
    member(&sub, B, 11, 11, 140_000);
    member(&sub, B, 12, 11, 140_000);
    let staged = sub.staging.used();
    let mut first_reject_round = None;
    for round in 0..20 {
        member(&sub, B, 13, 11, 140_000);
        // B gives its storage back: rejected.
        if first_reject_round.is_none() && sub.staging.used() < staged {
            first_reject_round = Some(round + 1);
        }
    }
    if samples.is_some() {
        assert_eq!(
            rejected.lock().expect("s").total_count,
            0,
            "B's set is in order: never refused, though C's takes the others' part"
        );
    }
    // A's writer finally writes again: A closes.
    plain(&sub, A, 6, 1_000);
    let mut taken = take_all(&ring, &sub, pool);
    for _ in 0..3 {
        member(&sub, B, 13, 11, 140_000);
        member(&sub, B, 14, 11, 140_000);
        plain(&sub, B, 15, 1_000);
        taken.extend(take_all(&ring, &sub, pool));
    }
    taken.sort_unstable();
    let rej = rejected.lock().expect("s").total_count;
    eprintln!(
        "m3 patience: taken={taken:?} rejected={rej} B_gave_back_after={first_reject_round:?} resends"
    );
    assert_eq!(
        taken,
        vec![1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15],
        "a set was rejected though no wait cycle existed (rejections={rej}, first after \
         {first_reject_round:?} resends of B's member)"
    );
}

/// The same, the refusals coming as ONE burst instead of repair rounds:
/// B's writer writes its set {11..16} back to back (four members refused
/// once each), and a third writer C its set {31..34} (four refused once
/// each). PATIENCE counts refusals, so one burst exhausts it, within one
/// heartbeat period of A's close being due. Each set fits the share alone.
#[test]
fn m3_patience_is_exhausted_by_one_burst() {
    one_burst(None);
}

/// A budget of sets of six: A's, B's and C's sets, each in order,
/// each staged in a set's limit of its own; nothing is rejected.
#[test]
fn m3_one_burst_in_a_tight_budget_rejects_nothing() {
    one_burst(Some(6));
}

fn one_burst(samples: Option<usize>) {
    const C: [u8; 16] = [0x5C; 16];
    let (pool, _g) = private_pool(1_000_000, 100);
    let (credit, rejected) = credit_for(&[A, B, C]);
    let (ring, sub) = subscriber_staging(&credit, &rejected, true, false, samples);
    sub.on_writer_heartbeat(A, 1);
    sub.on_writer_heartbeat(B, 11);
    sub.on_writer_heartbeat(C, 31);
    for seq in 1..=5 {
        member(&sub, A, seq, 1, 140_000);
    }
    for seq in 11..=16 {
        member(&sub, B, seq, 11, 140_000);
    }
    for seq in 31..=34 {
        member(&sub, C, seq, 31, 140_000);
    }
    let rej_after_burst = rejected.lock().expect("s").total_count;
    let held_after = sub.staging.used();
    plain(&sub, A, 6, 1_000);
    let mut taken = take_all(&ring, &sub, pool);
    for _ in 0..6 {
        for seq in 13..=16 {
            member(&sub, B, seq, 11, 140_000);
        }
        plain(&sub, B, 17, 1_000);
        taken.extend(take_all(&ring, &sub, pool));
        for seq in 31..=34 {
            member(&sub, C, seq, 31, 140_000);
        }
        plain(&sub, C, 35, 1_000);
        taken.extend(take_all(&ring, &sub, pool));
    }
    taken.sort_unstable();
    let rej = rejected.lock().expect("s").total_count;
    eprintln!(
        "m3 burst: rejected_after_burst={rej_after_burst} held_after_burst={held_after} \
         rejected_total={rej} taken={taken:?}"
    );
    assert_eq!(
        taken,
        vec![1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15, 16, 17, 31, 32, 33, 34, 35],
        "a set lost to one burst of refusals (rejected after burst={rej_after_burst}, total={rej})"
    );
}

fn gmember(
    sub: &super::subscriber::ReaderSubscriber<Vbig>,
    w: [u8; 16],
    seq: u64,
    start: u64,
    gsn: u64,
    publisher: [u8; 4],
) {
    sub.on_data_coherent(
        "t",
        w,
        seq,
        &encoded(seq, 200_000),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        Some(gsn),
        Some(publisher),
    );
}

/// Q2 false negative, GROUP scope. `commit_order` lists TOPIC sets only
/// (`coherent_buffer`): two GROUP sets of one writer, the later one G2
/// complete but committing only after the earlier G1 (its writer's gate),
/// enter the reduction with no order. G1 waits for its member 4, refused for
/// storage G2 and a third set X hold; X waits for storage too. The reduction
/// takes G2 to finish on its own (it waits for nothing), finds no residue,
/// and every set waits for good. The TOPIC twin below resolves (X, the
/// youngest, gives way). Contract: no permanent stall.
#[test]
fn m3_group_sets_of_one_writer_are_ordered_in_the_reduction() {
    group_sets_of_one_writer(None);
}

/// A budget of sets of three: W's later GROUP set, above the gap of
/// its member 4, takes the others' part; the earlier set, in order, gets
/// its member 4 staged when it is resent.
#[test]
fn m3_group_sets_of_one_writer_in_a_tight_budget_do_not_stall() {
    group_sets_of_one_writer(Some(3));
}

fn group_sets_of_one_writer(samples: Option<usize>) {
    const P: [u8; 4] = [0, 0, 1, 8];
    const Q: [u8; 4] = [0, 0, 2, 8];
    const X: [u8; 16] = [0x58; 16];
    let (pool, _g) = private_pool(1_050_000, 100);
    let (credit, rejected) = credit_for(&[W, X]);
    let (ring, sub) = subscriber_staging(&credit, &rejected, true, true, samples);
    sub.on_writer_heartbeat(W, 1);
    sub.on_writer_heartbeat(X, 1);
    plain(&sub, W, 1, 200_000);
    plain(&sub, X, 1, 200_000);
    let mut taken = take_all(&ring, &sub, pool);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    gmember(&sub, W, 2, 2, 1, P);
    gmember(&sub, W, 3, 2, 1, P);
    // 4 lost; G1's end 5 arrives.
    sub.on_ecs("t", W, 5, 4, Some(1), Some(P));
    gmember(&sub, W, 6, 6, 2, P);
    gmember(&sub, W, 7, 6, 2, P);
    sub.on_ecs("t", W, 8, 7, Some(2), Some(P));
    gmember(&sub, X, 2, 2, 1, Q);
    let staged = sub.staging.used();
    for _round in 0..30 {
        gmember(&sub, X, 3, 2, 1, Q);
        sub.on_ecs("t", X, 4, 3, Some(1), Some(Q));
        gmember(&sub, W, 4, 2, 1, P);
        sub.on_writer_heartbeat_range(W, 4, 8);
        sub.on_writer_heartbeat_range(X, 3, 4);
        taken.extend(take_all(&ring, &sub, pool));
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let h = sub.staging.used();
    eprintln!("m3 group: staged={staged} taken={taken:?} staged_after={h}");
    let mut sorted = taken.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![1, 1, 2, 2, 3, 3, 4, 6, 7],
        "GROUP: every set whole after 30 repair rounds (staged {h}, taken {taken:?})"
    );
    assert_eq!(h, 0);
}

/// TOPIC twin of the GROUP case: resolves.
#[test]
fn m3_topic_twin_of_the_group_case() {
    const X: [u8; 16] = [0x58; 16];
    let (pool, _g) = private_pool(1_050_000, 100);
    let (credit, rejected) = credit_for(&[W, X]);
    let (ring, sub) = subscriber(&credit, &rejected, true, false);
    sub.on_writer_heartbeat(W, 1);
    sub.on_writer_heartbeat(X, 1);
    plain(&sub, W, 1, 200_000);
    plain(&sub, X, 1, 200_000);
    let mut taken = take_all(&ring, &sub, pool);
    member(&sub, W, 2, 2, 200_000);
    member(&sub, W, 3, 2, 200_000);
    member(&sub, W, 5, 5, 200_000);
    member(&sub, W, 6, 5, 200_000);
    plain(&sub, W, 7, 1_000);
    member(&sub, X, 2, 2, 200_000);
    let staged = sub.staging.used();
    for _round in 0..30 {
        member(&sub, X, 3, 2, 200_000);
        plain(&sub, X, 4, 1_000);
        member(&sub, W, 4, 2, 200_000);
        plain(&sub, W, 7, 1_000);
        sub.on_writer_heartbeat_range(W, 4, 7);
        sub.on_writer_heartbeat_range(X, 3, 4);
        taken.extend(take_all(&ring, &sub, pool));
    }
    let h = sub.staging.used();
    eprintln!("m3 topic twin: staged={staged} taken={taken:?} staged_after={h}");
    assert!(
        taken.contains(&7),
        "TOPIC twin stalled: {taken:?} staged {h}"
    );
}

/// Q4 micro-measure: per-sample cost of the non-coherent reliable receive
/// path, in order and held above a one-sample gap (pairs swapped).
#[test]
#[ignore = "micro-measure"]
fn m3_hot_path_non_coherent() {
    for swapped in [false, true] {
        let (pool, _g) = private_pool(16 * 1024 * 1024, 25);
        let (credit, rejected) = credit_for(&[W]);
        let (ring, sub) = subscriber(&credit, &rejected, false, false);
        sub.on_writer_heartbeat(W, 1);
        let payload = encoded(1, 256);
        let n: u64 = 400_000;
        // warm-up
        let deliver = |seq: u64| {
            sub.on_data_with_writer("t", W, seq, &payload, crate::dds::CdrVersion::Xcdr2);
        };
        let mut seq = 1u64;
        let run = |count: u64, seq: &mut u64| {
            let mut i = 0;
            while i < count {
                if swapped {
                    deliver(*seq + 1);
                    deliver(*seq);
                    *seq += 2;
                    i += 2;
                } else {
                    deliver(*seq);
                    *seq += 1;
                    i += 1;
                }
                while let Some(entry) = ring.pop() {
                    pool.release(entry.handle);
                    drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
                }
            }
        };
        run(50_000, &mut seq);
        let t = std::time::Instant::now();
        run(n, &mut seq);
        let ns = t.elapsed().as_nanos() as f64 / n as f64;
        eprintln!("HOTPATH swapped={swapped} ns_per_sample={ns:.1}");
    }
}
