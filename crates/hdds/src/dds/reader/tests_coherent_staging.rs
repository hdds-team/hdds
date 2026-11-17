// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

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
const B: [u8; 16] = [0x7B; 16];
const C: [u8; 16] = [0x7C; 16];

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

/// What each of those is charged to its reader's staging budget: its
/// storage and its entry.
fn charged() -> usize {
    stored_len() + super::staging_budget::ENTRY_COST
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
    subscriber_with_registry(credit, rejected, group, samples, false, None)
}

fn subscriber_with_registry(
    credit: &crate::core::reader::ReaderAckCredit,
    rejected: &Rejected,
    group: bool,
    samples: usize,
    best_effort: bool,
    registry: Option<Arc<crate::engine::TopicRegistry>>,
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
        Arc::new(Mutex::new(if best_effort {
            super::reorder::ReorderGate::new_best_effort()
        } else {
            super::reorder::ReorderGate::new(true, true)
        })),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: group,
        },
        None,
        (!best_effort).then(|| credit.clone()),
        Arc::clone(rejected),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        registry,
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
    sub.register_match_entry_for_test(if best_effort {
        crate::dds::QoS::best_effort().keep_all()
    } else {
        crate::dds::QoS::reliable().keep_all()
    });
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
/// which `percent` the readers' share.
fn private_pool(
    ceiling: usize,
    percent: u8,
) -> (&'static Arc<rt::SlabPool>, rt::PrivateSlabPoolGuard) {
    let policy = crate::qos::MemoryPolicy {
        max_heap_bytes: ceiling,
        reader_reserve_percent: percent,
        ..crate::qos::MemoryPolicy::default()
    };
    let (pool, guard) = rt::owned_private_slab_pool_for_test(&policy);
    (pool, guard)
}

/// [`private_pool`] whose coherent readers stage at most `staging` bytes
/// together (`MemoryPolicy::max_staging_bytes`).
fn private_pool_staging(
    ceiling: usize,
    staging: usize,
) -> (&'static Arc<rt::SlabPool>, rt::PrivateSlabPoolGuard) {
    let policy = crate::qos::MemoryPolicy {
        max_heap_bytes: ceiling,
        max_staging_bytes: staging,
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

/// Staged members are stored, before they are acknowledged, apart from
/// the pool's tiers: here the heap tier is full of samples the
/// application has not taken, and the set is staged all the same, on its
/// own gauge, the heap tier's untouched. Every charge goes back once the
/// set is taken. (Held in the readers' share, a member found no storage
/// there and its writer waited for the application.)
#[test]
fn a_staged_member_is_stored_apart_before_it_is_acknowledged() {
    let one = stored_len();
    let (pool, _guard) = private_pool(2 * one, 100);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 64);
    plain(&sub, A, 1);
    plain(&sub, A, 2);
    assert_eq!(heap_used(pool), 2 * one, "fixture: the heap tier is full");
    for seq in 3..=6 {
        member(&sub, A, seq, 3);
        assert_eq!(
            heap_used(pool),
            2 * one,
            "seq {seq}: the heap tier untouched"
        );
    }
    assert_eq!(staged_heap(pool), 4 * one);
    assert_eq!(sub.staging.used(), 4 * charged(), "the reader's gauge");
    assert_eq!(
        acknowledged(&credit, A, 1, 6, 1),
        (7, vec![]),
        "every member stored, every member acknowledged"
    );
    plain(&sub, A, 7);
    assert_eq!(take_all(&ring, &sub, pool), vec![1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(
        sub.staging.used(),
        0,
        "taken: the reader's charge goes back"
    );
    assert_eq!(staged_heap(pool), 0, "released: the storage goes back");
    assert_eq!(heap_used(pool), 0);
    assert_eq!(rejected.lock().expect("status").total_count, 0);
}

/// A set that alone would take more than a set may (`N` samples of the
/// largest size) is rejected whole: every member acknowledged, the staged
/// ones' storage given back at once, one report per sample, and the
/// writer's stream goes on.
#[test]
fn a_set_larger_than_a_set_may_stage_is_rejected_whole() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 4);
    plain(&sub, A, 1);
    assert_eq!(take_all(&ring, &sub, pool), vec![1]);
    for seq in 2..=6 {
        member(&sub, A, seq, 2);
    }
    assert_eq!(sub.staging.used(), 0, "rejected: its storage given back");
    assert_eq!(staged_heap(pool), 0);
    assert_eq!(
        acknowledged(&credit, A, 1, 6, 1),
        (7, vec![]),
        "every member acknowledged: none is ever sent again"
    );
    plain(&sub, A, 7);
    assert_eq!(take_all(&ring, &sub, pool), vec![7]);
    assert_eq!(rejected.lock().expect("status").total_count, 5);
    // A set of the limit exactly is not.
    for seq in 8..=11 {
        member(&sub, A, seq, 8);
    }
    plain(&sub, A, 12);
    assert_eq!(take_all(&ring, &sub, pool), vec![8, 9, 10, 11, 12]);
    assert_eq!(rejected.lock().expect("status").total_count, 5);
}

/// A set rejected and never closed keeps the same few bytes whatever its
/// length: no staging entry for a member, no storage, every member
/// acknowledged and reported once; the writer's next set closes it and is
/// delivered. (Kept staged until closed, it took one entry per member, for
/// good, and each member walked them all.)
#[test]
fn a_rejected_set_never_closed_takes_no_entry_per_member() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 4);
    sub.on_writer_heartbeat(A, 1);
    let count: u64 = 3000;
    for seq in 1..=count {
        sub.on_data_coherent(
            "t",
            A,
            seq,
            &encoded_of(seq, 8),
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );
        let entries = sub
            .coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&A)
            .map_or(0, Vec::len);
        assert!(entries <= 4, "seq {seq}: {entries} staging entries");
        if seq > 4 {
            assert_eq!(
                sub.staging.used(),
                0,
                "seq {seq}: rejected, it keeps nothing"
            );
            assert_eq!(entries, 0, "seq {seq}: rejected, it takes no entry");
            assert_eq!(
                sub.staged_prepares.load(Ordering::Acquire),
                5,
                "seq {seq}: a member of a set rejected is not even decoded"
            );
        }
    }
    assert_eq!(sub.staging.used(), 0, "rejected: no storage kept");
    assert_eq!(staged_heap(pool), 0);
    assert_eq!(
        acknowledged(&credit, A, 1, count, 1),
        (count + 1, vec![]),
        "every member acknowledged"
    );
    assert_eq!(
        u64::from(rejected.lock().expect("status").total_count),
        count,
        "every sample reported once"
    );
    for seq in count + 1..=count + 2 {
        member(&sub, A, seq, count + 1);
    }
    plain(&sub, A, count + 3);
    assert_eq!(
        take_all(&ring, &sub, pool),
        vec![count + 1, count + 2, count + 3],
        "the next set and what follows are delivered"
    );
    assert_eq!(
        u64::from(rejected.lock().expect("status").total_count),
        count
    );
}

/// A member admitted as its set is rejected on another thread, before it
/// is staged, is not left staged under the set: taken as the set's later
/// members are. Left staged, its set never committed, and the writer's
/// stream waited for it for good.
#[test]
fn a_member_staged_as_its_set_is_rejected_is_not_left_behind() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 4);
    let sub = Arc::new(sub);
    sub.on_writer_heartbeat(A, 1);
    member(&sub, A, 1, 1);
    member(&sub, A, 2, 1);
    let other = Arc::clone(&sub);
    *sub.staging_hook.lock().expect("hook") = Some(Box::new(move || {
        other.reject_staged_set_for_test(A, 1);
    }));
    member(&sub, A, 3, 1);
    member(&sub, A, 4, 1);
    plain(&sub, A, 5);
    assert_eq!(take_all(&ring, &sub, pool), vec![5]);
    assert_eq!(rejected.lock().expect("status").total_count, 4);
    assert_eq!(sub.staging.used(), 0);
    assert!(sub
        .coherent_buffer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&A)
        .is_none_or(Vec::is_empty));
    assert_eq!(acknowledged(&credit, A, 1, 5, 1), (6, vec![]));
}

/// The same for a GROUP set.
#[test]
fn a_group_set_larger_than_a_set_may_stage_is_rejected_whole() {
    const PUBLISHER: [u8; 4] = [0, 0, 1, 8];
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, true, 4);
    sub.on_writer_heartbeat(A, 1);
    plain(&sub, A, 1);
    assert_eq!(take_all(&ring, &sub, pool), vec![1]);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    for seq in 2..=6 {
        sub.on_data_coherent(
            "t",
            A,
            seq,
            &encoded(seq),
            crate::dds::CdrVersion::Xcdr2,
            Some(2),
            Some(1),
            Some(PUBLISHER),
        );
    }
    assert_eq!(sub.staging.used(), 0, "rejected: its storage given back");
    sub.on_ecs("t", A, 7, 6, Some(1), Some(PUBLISHER));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    plain(&sub, A, 8);
    assert_eq!(take_all(&ring, &sub, pool), vec![8]);
    assert_eq!(acknowledged(&credit, A, 1, 8, 1), (9, vec![]));
    assert_eq!(rejected.lock().expect("status").total_count, 5);
}

/// Sets of two in a budget of sets of two. B's and C's sets are above a gap
/// of their writer: B's takes the others' part whole, and C's member is
/// refused unacknowledged. A's set and D's, in order, each take a whole
/// set's limit beside them. Once B's gap is filled, B's set commits, and
/// C's resend finds room. No set is rejected, every set is delivered whole.
#[test]
fn sets_above_a_gap_share_one_set_limit_and_wait_unacknowledged() {
    const D: [u8; 16] = [0x7D; 16];
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A, B, C, D]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 2);
    for writer in [B, C] {
        sub.on_writer_heartbeat(writer, 1);
        plain(&sub, writer, 1);
    }
    let mut taken = take_all(&ring, &sub, pool);
    // B's and C's sets {3, 4}, their 2 lost.
    member(&sub, B, 3, 3);
    member(&sub, B, 4, 3);
    member(&sub, C, 3, 3);
    assert_eq!(
        acknowledged(&credit, C, 1, 3, 1),
        (2, vec![2, 3]),
        "C's member refused, unacknowledged"
    );
    for writer in [A, D] {
        member(&sub, writer, 1, 1);
        member(&sub, writer, 2, 1);
    }
    assert_eq!(sub.staging.used(), 6 * charged());
    assert_eq!(sub.staging.used(), sub.staging.budget(), "A's and D's fit");
    for writer in [A, D] {
        plain(&sub, writer, 3);
    }
    plain(&sub, B, 2);
    plain(&sub, B, 5);
    for _resend in 0..2 {
        plain(&sub, C, 2);
        member(&sub, C, 3, 3);
        member(&sub, C, 4, 3);
        plain(&sub, C, 5);
        taken.extend(take_all(&ring, &sub, pool));
    }
    taken.sort_unstable();
    assert_eq!(
        taken,
        vec![1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5, 5],
        "every set whole"
    );
    assert_eq!(acknowledged(&credit, C, 1, 5, 2), (6, vec![]));
    assert_eq!(
        rejected.lock().expect("status").total_count,
        1,
        "the one refusal, unacknowledged; nothing rejected"
    );
    assert_eq!(sub.staging.used(), 0);
}

/// A writer's later sets staged above the gap of its earlier set take the
/// others' part whole; the earlier set, its members in order, is never
/// refused, though that part is full: it commits, and the later sets after
/// it. Refused, its members waited for the later sets, which waited for
/// it, for good.
#[test]
fn the_set_below_later_sets_is_never_refused() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 2);
    sub.on_writer_heartbeat(A, 1);
    plain(&sub, A, 1);
    let mut taken = take_all(&ring, &sub, pool);
    // Sets {2, 3}, {4, 5}, then 6. {4, 5} arrives first, above the gap.
    member(&sub, A, 4, 4);
    member(&sub, A, 5, 4);
    plain(&sub, A, 6);
    assert!(
        !sub.staging
            .is_in_order(&super::staging_budget::StagedSet::Writer(A, 4)),
        "a set above a gap is not in order"
    );
    assert_eq!(sub.staging.others(), 2 * charged());
    member(&sub, A, 2, 2);
    member(&sub, A, 3, 2);
    assert_eq!(
        acknowledged(&credit, A, 1, 6, 1),
        (7, vec![]),
        "the earlier set staged though the others' part is full"
    );
    taken.extend(take_all(&ring, &sub, pool));
    assert_eq!(taken, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(rejected.lock().expect("status").total_count, 0);
    assert_eq!(sub.staging.used(), 0);
}

/// A writer's first set, before its first HEARTBEAT, has nothing awaited
/// below it: the gate joins at it. It is in order when the others' part is
/// full of another writer's set staged above a gap, and is acknowledged at
/// once; taken to be out of order, it waited for that gap.
#[test]
fn a_writers_first_set_before_any_heartbeat_is_in_order() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A, B]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 2);
    sub.on_writer_heartbeat(B, 1);
    plain(&sub, B, 1);
    // B's set {3, 4} above its lost 2: the others' part, whole.
    member(&sub, B, 3, 3);
    member(&sub, B, 4, 3);
    member(&sub, A, 1, 1);
    member(&sub, A, 2, 1);
    assert_eq!(
        acknowledged(&credit, A, 1, 2, 1),
        (3, vec![]),
        "A's first set staged at once"
    );
    plain(&sub, A, 3);
    let mut taken = take_all(&ring, &sub, pool);
    plain(&sub, B, 2);
    plain(&sub, B, 5);
    taken.extend(take_all(&ring, &sub, pool));
    taken.sort_unstable();
    assert_eq!(taken, vec![1, 1, 2, 2, 3, 3, 4, 5]);
    assert_eq!(rejected.lock().expect("status").total_count, 0);
}

/// A writer's staging is bounded (`MAX_STAGED_PER_WRITER`, 64 in unit
/// tests), and a sample past the bound is refused unacknowledged. Not the
/// sample that fills a gap below what is staged: here 64 sets of two each
/// lost their first member, and their second members, staged, reach the
/// bound. Refused for it, every first member would be refused for good, and
/// every set would wait for one.
#[test]
fn the_member_that_fills_a_gap_is_never_refused_by_the_writers_bound() {
    let cap = super::subscriber::MAX_STAGED_PER_WRITER as u64;
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 64);
    let small = |seq: u64, start: u64| {
        sub.on_data_coherent(
            "t",
            A,
            seq,
            &encoded_of(seq, 100),
            crate::dds::CdrVersion::Xcdr2,
            Some(start),
            None,
            None,
        );
    };
    sub.on_writer_heartbeat(A, 1);
    plain(&sub, A, 1);
    let mut taken = take_all(&ring, &sub, pool);
    // Sets {2k, 2k + 1}, k = 1..=cap; their second members only.
    let last = 2 * cap + 1;
    for start in (2..=last).step_by(2) {
        small(start + 1, start);
    }
    // At the bound, a later set's sample is refused.
    small(last + 1, last + 1);
    assert_eq!(
        acknowledged(&credit, A, 1, last + 1, 1).1.last(),
        Some(&(last + 1)),
        "the bound refuses what extends the staging"
    );
    for start in (2..=last).step_by(2) {
        small(start, start);
    }
    assert_eq!(
        acknowledged(&credit, A, 1, last + 1, 2),
        (last + 1, vec![last + 1]),
        "every gap's filling staged though the bound was reached"
    );
    small(last + 1, last + 1);
    plain(&sub, A, last + 2);
    taken.extend(take_all(&ring, &sub, pool));
    assert_eq!(taken, (1..=last + 2).collect::<Vec<_>>());
    assert_eq!(rejected.lock().expect("status").total_count, 0);
}

/// Two writers' sets, each well inside
/// what a set may take, too big to be staged together in a tight budget.
/// Interleaved, A1 B11 A2 B12 C21 C22, with the writers resending what is
/// not acknowledged: every set delivered whole, none rejected.
#[test]
fn two_writers_sets_interleaved_in_a_tight_budget_are_both_delivered() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A, B, C]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 2);
    let mut taken = Vec::new();
    for _resend in 0..4 {
        member(&sub, A, 1, 1);
        member(&sub, B, 11, 11);
        member(&sub, C, 21, 21);
        member(&sub, A, 2, 1);
        member(&sub, B, 12, 11);
        member(&sub, C, 22, 21);
        plain(&sub, A, 3);
        plain(&sub, B, 13);
        plain(&sub, C, 23);
        taken.extend(take_all(&ring, &sub, pool));
        assert!(sub.staging.used() <= sub.staging.budget());
    }
    taken.sort_unstable();
    assert_eq!(taken, vec![1, 2, 3, 11, 12, 13, 21, 22, 23]);
    assert_eq!(acknowledged(&credit, C, 21, 23, 1), (24, vec![]));
    assert_eq!(sub.staging.used(), 0);
    assert_eq!(staged_heap(pool), 0);
}

/// GROUP order. Publisher P's set 1 (writer PA's part {2, 3}) is lost;
/// its set 2 (PB's part {2}, PA's part {5}) is staged, and must commit
/// after set 1 on PA. Publisher Q's set, above a gap of its writer, takes
/// the others' part whole. Set 1's members, resent, are in order on PA:
/// staged at once, though the others' part is full. Every set is delivered
/// whole. Refused, set 1 waited for Q's gap, set 2 for set 1.
#[test]
fn an_earlier_group_set_in_order_is_staged_when_the_others_part_is_full() {
    const P: [u8; 4] = [0, 0, 1, 8];
    const Q: [u8; 4] = [0, 0, 2, 8];
    // Two writers of P's participant, one of Q's.
    const PA: [u8; 16] = [
        0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0, 0, 1, 2,
    ];
    const PB: [u8; 16] = [
        0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0, 0, 2, 2,
    ];
    const QC: [u8; 16] = [0x7C; 16];
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[PA, PB, QC]);
    let (ring, sub) = subscriber(&credit, &rejected, true, 4);
    for writer in [PA, PB, QC] {
        sub.on_writer_heartbeat(writer, 1);
        plain(&sub, writer, 1);
    }
    let mut taken = take_all(&ring, &sub, pool);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let gmember = |writer: [u8; 16], seq: u64, start: u64, gsn: u64, publisher: [u8; 4]| {
        sub.on_data_coherent(
            "t",
            writer,
            seq,
            &encoded(seq),
            crate::dds::CdrVersion::Xcdr2,
            Some(start),
            Some(gsn),
            Some(publisher),
        );
    };
    gmember(PB, 2, 2, 2, P);
    gmember(PA, 5, 5, 2, P);
    // Q's set {3..=6}, QC's 2 lost: the others' part, whole.
    for seq in 3..=6 {
        gmember(QC, seq, 3, 1, Q);
    }
    assert_eq!(sub.staging.others(), 4 * charged());
    sub.on_ecs("t", PB, 3, 2, Some(2), Some(P));
    sub.on_ecs("t", PA, 6, 5, Some(2), Some(P));
    gmember(PA, 2, 2, 1, P);
    gmember(PA, 3, 2, 1, P);
    assert_eq!(
        acknowledged(&credit, PA, 1, 3, 1),
        (4, vec![]),
        "set 1's part staged at once"
    );
    for _resend in 0..2 {
        sub.on_ecs("t", PA, 4, 3, Some(1), Some(P));
        plain(&sub, QC, 2);
        sub.on_ecs("t", QC, 7, 6, Some(1), Some(Q));
        for writer in [PA, PB, QC] {
            sub.on_writer_heartbeat_range(writer, 1, 7);
        }
        taken.extend(take_all(&ring, &sub, pool));
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    taken.sort_unstable();
    assert_eq!(
        taken,
        vec![1, 1, 1, 2, 2, 2, 3, 3, 4, 5, 5, 6],
        "every set whole"
    );
    assert_eq!(rejected.lock().expect("status").total_count, 0);
    assert_eq!(sub.staging.used(), 0);
}

/// A member arriving after its writer's gate passed its sequence number
/// (its KEEP_LAST writer gave it up: the HEARTBEAT's firstSN moved past it,
/// and the reader reported it lost) is no change to deliver. Staged, its
/// set would be committed and delivered behind the later samples the gate
/// had let through: out of order (this arises with KEEP_LAST writers).
#[test]
fn a_member_below_what_the_gate_passed_is_not_delivered() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 64);
    sub.on_writer_heartbeat(A, 1);
    plain(&sub, A, 1);
    // The writer gave 2..=4 up: its history starts at 5.
    sub.on_writer_heartbeat_range(A, 5, 6);
    plain(&sub, A, 5);
    let mut taken = take_all(&ring, &sub, pool);
    // Sets {3} and {4}, late (the second closes the first), then 6.
    member(&sub, A, 3, 3);
    member(&sub, A, 4, 4);
    plain(&sub, A, 6);
    taken.extend(take_all(&ring, &sub, pool));
    assert_eq!(taken, vec![1, 5, 6], "nothing behind what was delivered");
    assert_eq!(acknowledged(&credit, A, 5, 6, 1), (7, vec![]));
    assert_eq!(sub.staging.used(), 0);
    assert_eq!(rejected.lock().expect("status").total_count, 0);
}

/// Staging competes with no one: two coherent readers of one process each
/// stage a set while the heap tier is full of a writer's history and of
/// samples a third reader has not taken; neither set waits for the others'
/// storage, nor theirs for it.
#[test]
fn staging_takes_nothing_from_writers_or_other_readers() {
    let one = stored_len();
    let (pool, _guard) = private_pool(4 * one, 50);
    let history: Vec<rt::SlabHandle> = std::iter::from_fn(|| {
        pool.reserve_and_write(&encoded(99), rt::Claim::Writer)
            .map(|(h, _)| h)
    })
    .collect();
    assert!(!history.is_empty(), "fixture: a writer's history");
    let (credit, rejected) = credit_for(&[A, B]);
    let (ring_x, sub_x) = subscriber(&credit, &rejected, false, 4);
    let (ring_y, sub_y) = subscriber(&credit, &rejected, false, 4);
    // A third, non-coherent reader fills the rest of the tier.
    let mut filler = Vec::new();
    while let Some((h, _)) = pool.reserve_and_write(&encoded(98), rt::Claim::Reader) {
        filler.push(h);
    }
    let full = heap_used(pool);
    for seq in 1..=4 {
        member(&sub_x, A, seq, 1);
        member(&sub_y, B, seq, 1);
    }
    assert_eq!(heap_used(pool), full, "the heap tier untouched");
    assert_eq!(staged_heap(pool), 8 * one);
    assert_eq!(sub_x.staging.used(), 4 * charged());
    assert_eq!(sub_y.staging.used(), 4 * charged());
    assert_eq!(acknowledged(&credit, A, 1, 4, 1), (5, vec![]));
    assert_eq!(acknowledged(&credit, B, 1, 4, 1), (5, vec![]));
    for h in filler {
        pool.release(h);
    }
    plain(&sub_x, A, 5);
    plain(&sub_y, B, 5);
    assert_eq!(take_all(&ring_x, &sub_x, pool), vec![1, 2, 3, 4, 5]);
    assert_eq!(take_all(&ring_y, &sub_y, pool), vec![1, 2, 3, 4, 5]);
    assert_eq!(staged_heap(pool), 0);
    for h in history {
        pool.release(h);
    }
    assert_eq!(heap_used(pool), 0);
    assert_eq!(rejected.lock().expect("status").total_count, 0);
}

/// A remote flood into one process: eight writers each open a set in
/// order and never close it, three hundred members each, into two readers.
/// What the process stages stays within its staging ceiling
/// (`MemoryPolicy::max_staging_bytes`), but for the one sample stored
/// before it is admitted: a member past it makes room by rejecting sets
/// whole, another reader's included, and nothing is refused. Every member
/// is acknowledged, and is staged or reported rejected; a member of a set
/// rejected costs one lookup (no decode, no storage, no entry).
#[test]
fn a_flood_of_never_closed_sets_stays_within_the_process_staging_ceiling() {
    let ceiling = 2 * 1024 * 1024;
    let (pool, _guard) = private_pool_staging(16 * 1024 * 1024, ceiling);
    let writers: Vec<[u8; 16]> = (0..8).map(|i| [0x50 + i; 16]).collect();
    let readers: Vec<_> = (0..2)
        .map(|_| {
            let (credit, rejected) = credit_for(&writers);
            let (_ring, sub) = subscriber(&credit, &rejected, false, 64);
            let sub = Arc::new(sub);
            let owner: std::sync::Weak<dyn super::staging_budget::StagedOwner> =
                Arc::downgrade(&sub) as _;
            sub.staging.set_owner(owner);
            for w in &writers {
                sub.on_writer_heartbeat(*w, 1);
            }
            (credit, rejected, sub)
        })
        .collect();
    let len = encoded_of(1, 20_000).len() + 16;
    let members: u64 = 300;
    let mut peak = 0;
    for seq in 1..=members {
        for w in &writers {
            for (_, _, sub) in &readers {
                sub.on_data_coherent(
                    "t",
                    *w,
                    seq,
                    &encoded_of(seq, 20_000),
                    crate::dds::CdrVersion::Xcdr2,
                    Some(1),
                    None,
                    None,
                );
                let staged = staged_heap(pool);
                peak = peak.max(staged);
                assert!(
                    staged <= ceiling + len,
                    "seq {seq}: {staged} B staged, ceiling {ceiling} B"
                );
                let charged: usize = readers.iter().map(|(_, _, s)| s.staging.used()).sum();
                assert!(charged <= ceiling, "seq {seq}: {charged} B charged");
            }
        }
    }
    let mut staged_members = 0u64;
    let mut reported = 0u64;
    let mut prepares = 0usize;
    for (credit, rejected, sub) in &readers {
        for w in &writers {
            assert_eq!(
                acknowledged(credit, *w, 1, members, 1),
                (members + 1, vec![])
            );
            let entries = sub
                .coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(w)
                .map_or(0, Vec::len);
            assert!(entries <= super::subscriber::MAX_STAGED_PER_WRITER);
            staged_members += entries as u64;
        }
        reported += u64::from(rejected.lock().expect("status").total_count);
        prepares += sub.staged_prepares.load(Ordering::Acquire);
    }
    eprintln!(
        "flood: peak {peak} B staged of {ceiling} B, {staged_members} members staged, \
         {reported} reported rejected, {prepares} decoded"
    );
    assert!(peak > ceiling / 2, "fixture: the ceiling binds");
    assert_eq!(staged_members + reported, 2 * 8 * members);
    // Each set is decoded at most until it is rejected: N + 1 members.
    assert!(prepares <= 2 * 8 * 65, "{prepares} members decoded");
}

// Coherent-staging edge cases, each as a test.

const PUBLISHER: [u8; 4] = [0, 0, 1, 8];

/// A member of `writer`'s set `start` with a body of 8 bytes.
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

/// A dispose of `writer`'s set `start` (of the GROUP set `gsn` of
/// [`PUBLISHER`] when given): a member with no sample.
fn key_only(
    sub: &super::subscriber::ReaderSubscriber<Big>,
    writer: [u8; 16],
    seq: u64,
    start: u64,
    gsn: Option<u64>,
) {
    sub.on_lifecycle_coherent(
        "t",
        writer,
        seq,
        [0x11; 16],
        crate::engine::subscriber::DisposeKind::Disposed,
        Some(start),
        gsn,
        gsn.map(|_| PUBLISHER),
    );
}

/// The changes of `writer` its reader has staged in TOPIC sets.
fn entries(sub: &super::subscriber::ReaderSubscriber<Big>, writer: [u8; 16]) -> usize {
    sub.coherent_buffer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&writer)
        .map_or(0, Vec::len)
}

/// 1a: a peer stages one member far above its gap, then disposes below
/// it, descending, each of a set of its own. Each is below a member
/// staged, and passed the writer's bound as the filling of a gap; none was
/// charged, and each set, closed by the one above it, committed into the
/// writer's gate, held there above the gap with no bound at all. What a
/// writer has staged or held stays bounded.
#[test]
fn key_only_members_below_a_staged_one_stay_within_the_writers_bound() {
    let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (_ring, sub) = subscriber(&credit, &rejected, false, 64);
    sub.on_writer_heartbeat(A, 1);
    plain(&sub, A, 1);
    let top: u64 = 3_000;
    tiny(&sub, A, top, top);
    for seq in (3..top).rev() {
        key_only(&sub, A, seq, seq, None);
    }
    let staged = entries(&sub, A);
    let held = sub.reorder.lock().expect("gate").held(&A);
    let cap = super::subscriber::MAX_STAGED_PER_WRITER;
    eprintln!(
        "1a: A has {staged} changes staged and {held} held by its gate, charged {} B",
        sub.staging.used()
    );
    assert!(
        staged + held <= 2 * cap,
        "{staged} staged and {held} held for one writer, bound {cap}"
    );
}

/// 1a: a dispose staged in a set is charged like a sample, and counts
/// toward the samples a set may stage: a set of five of them, in a budget
/// of sets of four, is rejected whole.
#[test]
fn key_only_members_are_charged_and_count_toward_a_sets_samples() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 4);
    sub.on_writer_heartbeat(A, 1);
    for seq in 1..=4 {
        key_only(&sub, A, seq, 1, None);
    }
    assert_eq!(entries(&sub, A), 4);
    assert!(sub.staging.used() > 0, "every staged entry is charged");
    key_only(&sub, A, 5, 1, None);
    assert_eq!(entries(&sub, A), 0, "the set rejected whole");
    assert_eq!(sub.staging.used(), 0);
    plain(&sub, A, 6);
    assert_eq!(take_all(&ring, &sub, pool), vec![6]);
    assert_eq!(acknowledged(&credit, A, 1, 6, 1), (7, vec![]));
}

/// 1a: before its first HEARTBEAT the gate of a reader that joins at the
/// writer's HEARTBEAT (not at its first DATA) has no baseline, and every
/// set of the writer counts as in order for the budget. The writer's bound
/// does not take it so: sets that never close, a member each, stay within
/// it.
#[test]
fn a_writers_bound_holds_before_its_first_heartbeat() {
    let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (_ring, sub) = subscriber(&credit, &rejected, false, 64);
    *sub.reorder.lock().expect("gate") = super::reorder::ReorderGate::new(true, false);
    let cap = super::subscriber::MAX_STAGED_PER_WRITER;
    for seq in 1..=3 * cap as u64 {
        tiny(&sub, A, seq, seq);
    }
    let staged = entries(&sub, A);
    assert!(
        staged <= cap,
        "{staged} entries staged for one writer, bound {cap}"
    );
}

/// 1b: a GROUP writer opens a set per change, a fresh GSN each, never
/// closed. Nothing capped how many sets a writer had open; past
/// `MAX_OPEN_GROUP_SETS_PER_WRITER` a change opening one more is refused,
/// but its set in order's.
#[test]
fn a_group_writers_open_sets_are_bounded() {
    let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (_ring, sub) = subscriber(&credit, &rejected, true, 64);
    sub.on_writer_heartbeat(A, 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    // One large sample: what a set may take is that of 64 of it.
    sub.on_data_coherent(
        "t",
        A,
        1,
        &encoded(1),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        Some(1),
        Some(PUBLISHER),
    );
    for seq in 2..=2_000 {
        key_only(&sub, A, seq, seq, Some(seq));
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let open = sub
        .group_coherent_buffer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .filter(|set| set.has_part_of(&A))
        .count();
    let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER;
    eprintln!(
        "1b: {open} GROUP sets open with a part of A, gate next {:?}, missing {:?}",
        sub.reorder.lock().expect("gate").next_seq(&A),
        acknowledged(&credit, A, 1, 2_000, 1).1.len()
    );
    assert!(open <= cap + 1, "{open} GROUP sets open for one writer");
}

/// 1b: at that bound, the writer's set in order still opens: refused, it
/// was refused for good, and the sets above waited for it.
#[test]
fn a_group_writers_set_in_order_opens_past_the_bound() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, true, 64);
    sub.on_writer_heartbeat(A, 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let group = |seq: u64| {
        sub.on_data_coherent(
            "t",
            A,
            seq,
            &encoded_of(seq, 8),
            crate::dds::CdrVersion::Xcdr2,
            Some(seq),
            Some(seq),
            Some(PUBLISHER),
        );
    };
    plain(&sub, A, 1);
    let _ = take_all(&ring, &sub, pool);
    // 2 lost: sets above it, a change each, up to the bound.
    let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER as u64;
    for seq in 3..3 + cap {
        group(seq);
    }
    group(3 + cap);
    group(2);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let (_, missing) = acknowledged(&credit, A, 1, 3 + cap, 1);
    assert_eq!(
        missing,
        vec![3 + cap],
        "one set past the bound refused, 2 staged"
    );
}

/// 3b: a set rejected while its commit has it out of the staging (it waits
/// for places in the history) was put back, its charge kept and its
/// members staged under a set rejected: they were delivered later.
#[test]
fn a_set_rejected_while_its_commit_waits_for_places_gives_its_charge_back() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, mut sub) = subscriber(&credit, &rejected, false, 64);
    sub.room = Some(super::admission::HistoryRoom::new(&ring, 2));
    let sub = Arc::new(sub);
    sub.on_writer_heartbeat(A, 1);
    plain(&sub, A, 1);
    member(&sub, A, 2, 2);
    member(&sub, A, 3, 2);
    let other = Arc::clone(&sub);
    sub.on_next_refused_room(Box::new(move || other.reject_staged_set_for_test(A, 2)));
    // Closes {2, 3}, which needs two places, one free.
    member(&sub, A, 4, 4);
    assert_eq!(entries(&sub, A), 1, "only 4 staged");
    assert_eq!(sub.staging.used(), charged(), "4's charge only");
    let mut taken = take_all(&ring, &sub, pool);
    member(&sub, A, 5, 4);
    plain(&sub, A, 6);
    taken.extend(take_all(&ring, &sub, pool));
    // 6 found no place behind {4, 5}: sent again.
    plain(&sub, A, 6);
    taken.extend(take_all(&ring, &sub, pool));
    assert_eq!(taken, vec![1, 4, 5, 6]);
    // 2 and 3, and 6's refusal for a place.
    assert_eq!(rejected.lock().expect("status").total_count, 3);
    assert_eq!(sub.staging.used(), 0);
}

/// 3b, a GROUP set: rejected while its flush has it out of the staging, it
/// was put back whole.
#[test]
fn a_group_set_rejected_while_its_flush_waits_for_places_gives_its_charge_back() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, mut sub) = subscriber(&credit, &rejected, true, 64);
    sub.room = Some(super::admission::HistoryRoom::new(&ring, 2));
    let sub = Arc::new(sub);
    sub.on_writer_heartbeat(A, 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    plain(&sub, A, 1);
    for seq in [2, 3] {
        sub.on_data_coherent(
            "t",
            A,
            seq,
            &encoded(seq),
            crate::dds::CdrVersion::Xcdr2,
            Some(2),
            Some(2),
            Some(PUBLISHER),
        );
    }
    let key: super::subscriber::GroupSetKey = (A[..12].try_into().expect("prefix"), PUBLISHER, 2);
    let other = Arc::clone(&sub);
    sub.on_next_refused_room(Box::new(move || other.reject_group_set_for_test(key)));
    // Its end: the set needs two places, one free.
    sub.on_ecs("t", A, 4, 3, Some(2), Some(PUBLISHER));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert!(
        sub.group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "nothing staged under the set rejected"
    );
    assert_eq!(sub.staging.used(), 0);
    let mut taken = take_all(&ring, &sub, pool);
    plain(&sub, A, 5);
    taken.extend(take_all(&ring, &sub, pool));
    assert_eq!(taken, vec![1, 5]);
    assert_eq!(rejected.lock().expect("status").total_count, 2);
}

/// `sub`, its staging budget's owner (another reader's member may reject
/// its sets to keep the process within its staging ceiling).
fn owned(
    sub: super::subscriber::ReaderSubscriber<Big>,
) -> Arc<super::subscriber::ReaderSubscriber<Big>> {
    let sub = Arc::new(sub);
    let owner: std::sync::Weak<dyn super::staging_budget::StagedOwner> = Arc::downgrade(&sub) as _;
    sub.staging.set_owner(owner);
    sub
}

/// 1c: sets committed above their writer's gap, held by its gate, keep
/// their charge; rejected, they gave nothing back, and a set in order was
/// then admitted past the process ceiling. The process stays within it,
/// and the set in order finds its room.
#[test]
fn sets_held_by_the_gate_above_a_gap_leave_the_ceiling_whole() {
    let ceiling = 2 * 1024 * 1024;
    let (pool, _guard) = private_pool_staging(16 * 1024 * 1024, ceiling);
    let (credit, rejected) = credit_for(&[A, B]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 64);
    let sub = owned(sub);
    sub.on_writer_heartbeat(A, 1);
    sub.on_writer_heartbeat(B, 1);
    let body = 40_000;
    let m = |writer: [u8; 16], seq: u64, start: u64| {
        sub.on_data_coherent(
            "t",
            writer,
            seq,
            &encoded_of(seq, body),
            crate::dds::CdrVersion::Xcdr2,
            Some(start),
            None,
            None,
        );
    };
    plain(&sub, A, 1);
    let _ = take_all(&ring, &sub, pool);
    // A's 2 lost: its sets {3, 4}, {5, 6}, ... commit, held by its gate.
    for start in (3..=61).step_by(2) {
        m(A, start, start);
        m(A, start + 1, start);
    }
    let held = sub.staging.used();
    eprintln!(
        "1c fixture: charged {held} B, A's entries {}, ring {}, rejected {}",
        entries(&sub, A),
        ring.len(),
        rejected.lock().expect("status").total_count
    );
    // B's set in order, of 40 members, alone within the ceiling.
    let mut peak = 0;
    for seq in 1..=40 {
        m(B, seq, 1);
        peak = peak.max(sub.staging.used());
    }
    m(B, 41, 41);
    eprintln!("1c: A held {held} B, peak {peak} B, ceiling {ceiling} B");
    assert!(
        held > ceiling / 2,
        "fixture: A's held sets fill the ceiling"
    );
    assert!(peak <= ceiling, "{peak} B charged, ceiling {ceiling} B");
    plain(&sub, B, 42);
    let taken = take_all(&ring, &sub, pool);
    assert!(
        (1..=40).all(|seq| taken.contains(&seq)),
        "B's set in order delivered: {taken:?}"
    );
}

/// 2: reader B is flooded by a hostile peer: eight writers, each a set in
/// order never closed. Reader A stages small sets of its own writer, its
/// application taking each at once. The youngest set of the process in
/// order gave way to B's members: A's. A, within its share of the ceiling,
/// loses nothing.
#[test]
fn a_reader_within_its_share_loses_nothing_to_a_flooded_reader() {
    let ceiling = 2 * 1024 * 1024;
    let (pool, _guard) = private_pool_staging(16 * 1024 * 1024, ceiling);
    let hostile: Vec<[u8; 16]> = (0..8).map(|i| [0x50 + i; 16]).collect();
    let (credit_a, rejected_a) = credit_for(&[A]);
    let (ring_a, sub_a) = subscriber(&credit_a, &rejected_a, false, 64);
    let sub_a = owned(sub_a);
    sub_a.on_writer_heartbeat(A, 1);
    let (credit_b, rejected_b) = credit_for(&hostile);
    let (_ring_b, sub_b) = subscriber(&credit_b, &rejected_b, false, 64);
    let sub_b = owned(sub_b);
    for w in &hostile {
        sub_b.on_writer_heartbeat(*w, 1);
    }
    let body = 20_000;
    let on = |sub: &super::subscriber::ReaderSubscriber<Big>, w: [u8; 16], seq: u64, start| {
        sub.on_data_coherent(
            "t",
            w,
            seq,
            &encoded_of(seq, body),
            crate::dds::CdrVersion::Xcdr2,
            Some(start),
            None,
            None,
        );
    };
    let mut taken = Vec::new();
    let mut next_a = 1;
    for seq in 1..=200 {
        for w in &hostile {
            on(&sub_b, *w, seq, 1);
        }
        if seq % 2 == 0 {
            // A's set {next_a, next_a + 1}, closed by the next one's start.
            on(&sub_a, A, next_a, next_a);
            on(&sub_a, A, next_a + 1, next_a);
            next_a += 2;
            on(&sub_a, A, next_a, next_a);
            taken.extend(take_all(&ring_a, &sub_a, pool));
        }
    }
    plain(&sub_a, A, next_a + 1);
    taken.extend(take_all(&ring_a, &sub_a, pool));
    let lost_a = rejected_a.lock().expect("status").total_count;
    let lost_b = rejected_b.lock().expect("status").total_count;
    eprintln!(
        "2: A took {} samples, A rejected {lost_a}, B rejected {lost_b}",
        taken.len()
    );
    assert!(lost_b > 0, "fixture: the ceiling binds");
    assert_eq!(lost_a, 0, "A lost a set to B's flood");
    assert_eq!(taken, (1..=next_a + 1).collect::<Vec<_>>());
}

/// 4: one reader, one writer: sets above the writer's gap that together
/// need more than the sets above a gap may take. Refused unacknowledged,
/// resent by their writer; once the gap is filled every set commits, none
/// rejected: the reader's own refusals wait on nothing they hold.
#[test]
fn sets_above_a_gap_past_their_limit_never_stall_their_reader() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, false, 2);
    sub.on_writer_heartbeat(A, 1);
    plain(&sub, A, 1);
    let mut taken = take_all(&ring, &sub, pool);
    // Sets {2, 3}, {4, 5}, {6, 7}, {8, 9}, then 10; 2 lost.
    let send = |seq: u64| {
        if seq == 10 {
            plain(&sub, A, 10);
        } else {
            member(&sub, A, seq, seq - seq % 2);
        }
    };
    for seq in 3..=10 {
        send(seq);
    }
    let first_missing = acknowledged(&credit, A, 1, 10, 1).1;
    assert!(
        first_missing.len() > 1,
        "fixture: the sets above the gap past their limit, refused: {first_missing:?}"
    );
    for round in 2..12 {
        let (_, missing) = acknowledged(&credit, A, 1, 10, round);
        for seq in missing {
            send(seq);
        }
        taken.extend(take_all(&ring, &sub, pool));
    }
    assert_eq!(taken, (1..=10).collect::<Vec<_>>());
    assert_eq!(sub.staging.used(), 0);
    // Each refusal is reported (unacknowledged); no set rejected.
    let reported = rejected.lock().expect("status").total_count;
    assert!(reported <= 4, "{reported} reports: a set was rejected");
}

/// End-only controls consume the same open-set budget as DATA. A missing
/// member or missing publisher end must not permit unbounded metadata.
#[test]
fn group_end_only_controls_share_the_open_set_bound() {
    let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER;
    for dialect in 0..4 {
        let (credit, rejected) = credit_for(&[A]);
        let (_ring, sub) = subscriber(&credit, &rejected, true, 64);
        sub.on_writer_heartbeat(A, 1);
        for set in 1..=3 * cap as u64 {
            let marker = 2 * set;
            match dialect {
                0 => sub.on_ecs("t", A, marker, marker - 1, Some(set), Some(PUBLISHER)),
                1 => sub.on_coherent_end_marker(
                    "t",
                    A,
                    Some(set),
                    Some(PUBLISHER),
                    marker - 1,
                    Some(1),
                    marker,
                ),
                2 => sub.on_coherent_end(
                    "t",
                    A,
                    Some(set),
                    Some(PUBLISHER),
                    Some(marker - 1),
                    Some(1),
                ),
                _ => sub.on_group_change(
                    A,
                    crate::engine::GroupChange {
                        seq: marker,
                        group_sn: set,
                        publisher_entity_id: PUBLISHER,
                        writer_set: [1; 4],
                        gsn: Some(marker),
                        part_first_sn: Some(marker - 1),
                    },
                ),
            }
        }
        assert_eq!(
            sub.group_coherent_buffer.lock().expect("sets").len(),
            cap,
            "dialect {dialect}: end-only metadata is bounded"
        );
        // The metadata-only entries count when a DATA opens another set.
        key_only(&sub, A, 10_000, 10_000, Some(10_000));
        assert_eq!(sub.group_coherent_buffer.lock().expect("sets").len(), cap);
        assert_eq!(acknowledged(&credit, A, 10_000, 10_000, 1).1, vec![10_000]);
    }
}

/// Discovery's one matched writer of this test Publisher.
struct SingleWriterGroupRoster;

impl super::subscriber::GroupRoster for SingleWriterGroupRoster {
    fn writers_of(
        &self,
        prefix: &[u8; 12],
        publisher: [u8; 4],
        _topic: &str,
    ) -> Vec<([u8; 4], bool)> {
        if prefix[..] == A[..12] && publisher == PUBLISHER {
            vec![(A[12..].try_into().expect("entity"), true)]
        } else {
            Vec::new()
        }
    }
}

/// A reliable end refused for metadata room is still owed (RTPS v2.5
/// Sec.8.4.12). Its repair closes once a completed set gives room back;
/// duplicate markers never reopen a completed set.
#[test]
fn group_end_refused_at_the_bound_is_repairable_after_room_returns() {
    let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER as u64;
    for spec in [false, true] {
        for standalone in [false, true] {
            let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
            let (credit, rejected) = credit_for(&[A]);
            let (_ring, sub) = subscriber(&credit, &rejected, true, 64);
            let writer_set =
                crate::protocol::group::group_digest([A[12..].try_into().expect("entity")]);
            if spec {
                assert!(sub
                    .group_roster
                    .set(Arc::new(SingleWriterGroupRoster))
                    .is_ok());
            }
            // Join at HEARTBEAT history, before any end can overtake its
            // first DATA. The usual fixture joins at its first DATA.
            *sub.reorder.lock().expect("gate") = super::reorder::ReorderGate::new(true, false);
            sub.on_writer_heartbeat(A, 1);
            assert_eq!(sub.reorder.lock().expect("gate").next_seq(&A), Some(1));
            // Seed the ACK proxy before the first marker; seeding on that
            // marker would join after the member whose late arrival we test.
            assert_eq!(acknowledged(&credit, A, 1, 2, 1).1, vec![1, 2]);
            let close = |set: u64| {
                let marker = 2 * set;
                if spec {
                    sub.on_group_change(
                        A,
                        crate::engine::GroupChange {
                            seq: marker,
                            group_sn: set,
                            publisher_entity_id: PUBLISHER,
                            writer_set,
                            gsn: Some(marker),
                            part_first_sn: Some(marker - 1),
                        },
                    );
                }
                if standalone {
                    sub.on_coherent_end_marker(
                        "t",
                        A,
                        Some(set),
                        Some(PUBLISHER),
                        marker - 1,
                        Some(1),
                        marker,
                    );
                } else {
                    sub.on_ecs("t", A, marker, marker - 1, Some(set), Some(PUBLISHER));
                }
            };
            for set in 1..=cap {
                close(set);
            }
            let refused = 2 * (cap + 1);
            close(cap + 1);
            assert!(
                acknowledged(&credit, A, 1, refused, 2).1.contains(&refused),
                "the refused marker is unacknowledged"
            );
            // The first end overtook its only member; that member closes
            // an existing part even while all metadata slots are taken.
            crate::engine::router::set_route_writer_is_hdds_for_test(true);
            key_only(&sub, A, 1, 1, Some(1));
            crate::engine::router::set_route_writer_is_hdds_for_test(false);
            let open = sub.group_coherent_buffer.lock().expect("sets").len();
            assert_eq!(
                open,
                cap as usize - 1,
                "spec={spec} standalone={standalone}, gate {:?}, first {:?}",
                sub.reorder.lock().expect("gate").next_seq(&A),
                sub.group_coherent_buffer.lock().expect("sets").get(&(
                    A[..12].try_into().expect("prefix"),
                    PUBLISHER,
                    1
                ))
            );
            close(1);
            assert_eq!(
                sub.group_coherent_buffer.lock().expect("sets").len(),
                cap as usize - 1,
                "a duplicate does not reopen a completed set even with room"
            );
            close(cap + 1);
            assert!(!acknowledged(&credit, A, 1, refused, 3).1.contains(&refused));
            assert_eq!(
                sub.group_coherent_buffer.lock().expect("sets").len(),
                cap as usize
            );
            close(1);
            assert_eq!(
                sub.group_coherent_buffer.lock().expect("sets").len(),
                cap as usize
            );
        }
    }
}

/// Metadata preceding a refused DATA is bounded even when every callback
/// names the writer's current sequence and claims a different GROUP set.
#[test]
fn group_member_metadata_without_admitted_data_is_bounded() {
    let (credit, rejected) = credit_for(&[A]);
    let (_ring, sub) = subscriber(&credit, &rejected, true, 64);
    *sub.reorder.lock().expect("gate") = super::reorder::ReorderGate::new(true, false);
    sub.on_writer_heartbeat(A, 1);
    assert_eq!(sub.reorder.lock().expect("gate").next_seq(&A), Some(1));
    let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER;
    for set in 1..=3 * cap as u64 {
        sub.on_group_change(
            A,
            crate::engine::GroupChange {
                seq: 1,
                group_sn: set,
                publisher_entity_id: PUBLISHER,
                writer_set: [1; 4],
                gsn: None,
                part_first_sn: None,
            },
        );
    }
    assert_eq!(
        sub.group_coherent_buffer.lock().expect("sets").len(),
        cap + 1,
        "exactly one metadata entry may use the in-order set exception"
    );
}

fn spec_registry(writers: &[[u8; 16]]) -> Arc<crate::engine::TopicRegistry> {
    let registry = Arc::new(crate::engine::TopicRegistry::new());
    for writer in writers {
        registry.register_writer_guid(*writer, "t".to_string());
        registry.register_writer_partition(*writer, crate::qos::partition::Partition::default());
        registry
            .register_writer_ownership_kind(*writer, crate::qos::ownership::OwnershipKind::Shared);
        registry.record_writer_group_dialect(
            *writer,
            crate::protocol::group::GroupDialect::Spec,
            Some(PUBLISHER),
        );
    }
    registry
}

struct PairGroupRoster([u8; 16]);
impl super::subscriber::GroupRoster for PairGroupRoster {
    fn writers_of(
        &self,
        prefix: &[u8; 12],
        publisher: [u8; 4],
        _topic: &str,
    ) -> Vec<([u8; 4], bool)> {
        if prefix[..] == A[..12] && publisher == PUBLISHER {
            vec![
                (A[12..].try_into().expect("entity"), true),
                (self.0[12..].try_into().expect("entity"), true),
            ]
        } else {
            Vec::new()
        }
    }
}

/// A BEST_EFFORT writer's later sets are current heads while another
/// Publisher writer's ends are delayed. A refused head does not change the
/// wire dialect or discard the already accepted parts of those older sets.
#[test]
fn group_best_effort_heads_at_the_bound_preserve_accepted_sibling_parts() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let mut sibling = A;
    sibling[15] += 1;
    let (credit, rejected) = credit_for(&[A, sibling]);
    let registry = spec_registry(&[A, sibling]);
    let (ring, sub) = subscriber_with_registry(&credit, &rejected, true, 64, true, Some(registry));
    assert!(sub
        .group_roster
        .set(Arc::new(PairGroupRoster(sibling)))
        .is_ok());
    let writer_set = crate::protocol::group::group_digest([
        A[12..].try_into().expect("entity"),
        sibling[12..].try_into().expect("entity"),
    ]);
    let metadata = |writer, seq, group_sn, gsn, part_first_sn| {
        sub.on_group_change(
            writer,
            crate::engine::GroupChange {
                seq,
                group_sn,
                publisher_entity_id: PUBLISHER,
                writer_set,
                gsn: Some(gsn),
                part_first_sn,
            },
        );
    };
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    metadata(sibling, 1, 1, 2, None);
    sub.on_data_coherent(
        "t",
        sibling,
        1,
        &encoded_of(200, 8),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        Some(1),
        Some(PUBLISHER),
    );
    let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER as u64;
    for set in 1..=cap + 2 {
        let seq = 2 * set - 1;
        let group = 3 * set - 2;
        metadata(A, seq, group, group, None);
        sub.on_data_coherent(
            "t",
            A,
            seq,
            &encoded_of(set, 8),
            crate::dds::CdrVersion::Xcdr2,
            Some(seq),
            Some(group),
            Some(PUBLISHER),
        );
        metadata(A, seq + 1, group, group + 2, Some(seq));
        sub.on_ecs("t", A, seq + 1, seq, Some(group), Some(PUBLISHER));
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    {
        let sets = sub.group_coherent_buffer.lock().expect("sets");
        assert_eq!(
            sets.len(),
            cap as usize + 1,
            "metadata and DATA share one bound"
        );
        assert!(
            sets.get(&(A[..12].try_into().expect("prefix"), PUBLISHER, 1))
                .expect("the first set is retained")
                .has_part_of(&sibling),
            "refusing another writer's metadata keeps this accepted sibling part"
        );
    }
    // The missing sibling end closes the first set as a whole; neither
    // accepted sample was discarded by the later writer's local limit.
    metadata(sibling, 2, 1, 3, Some(1));
    sub.on_ecs("t", sibling, 2, 1, Some(1), Some(PUBLISHER));
    let mut values = Vec::new();
    while let Some(entry) = ring.pop() {
        let bytes = pool.get_buffer(entry.handle);
        let sample = <Big as crate::dds::DDS>::decode(
            &bytes[16..entry.len as usize],
            crate::dds::CdrVersion::Xcdr2,
        )
        .expect("stored sample");
        values.push(sample.id);
        drop(bytes);
        pool.release(entry.handle);
        drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
    }
    assert_eq!(values, vec![1, 200]);
}

/// A reliable current head whose DATA was refused can later leave the
/// writer's history. Its metadata alone must not retain the extra slot
/// and prevent the next repairable head from preserving its spec dialect.
#[test]
fn group_reliable_passed_metadata_only_head_gives_the_next_head_room() {
    for filtered_first in [false, true] {
        let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
        let (credit, rejected) = credit_for(&[A]);
        let registry = spec_registry(&[A]);
        let (_ring, sub) =
            subscriber_with_registry(&credit, &rejected, true, 64, false, Some(registry));
        *sub.reorder.lock().expect("gate") = super::reorder::ReorderGate::new(true, false);
        sub.on_writer_heartbeat(A, 1);
        let writer_set =
            crate::protocol::group::group_digest([A[12..].try_into().expect("entity")]);
        let metadata = |seq, group_sn, part_first_sn| {
            sub.on_group_change(
                A,
                crate::engine::GroupChange {
                    seq,
                    group_sn,
                    publisher_entity_id: PUBLISHER,
                    writer_set,
                    gsn: Some(seq),
                    part_first_sn,
                },
            );
        };
        let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER;
        for i in 0..cap {
            metadata(100 + i as u64, 100 + i as u64, Some(100 + i as u64));
        }
        // The callback precedes DATA resource admission. No DATA from this
        // part is staged; its writer gives it up before a later head arrives.
        metadata(1, 1, None);
        assert_eq!(
            sub.group_coherent_buffer.lock().expect("sets").len(),
            cap + 1
        );
        let head = if filtered_first {
            sub.on_writer_gap_filtered(A, 1, 2, Vec::new(), 1);
            // The first sample was filtered, but a later announced sample of
            // the same part was genuinely lost, already reported by its GAP.
            metadata(2, 1, None);
            sub.on_writer_gap(A, 2, 3, Vec::new());
            3
        } else {
            sub.on_writer_gap(A, 1, 2, Vec::new());
            2
        };
        assert_eq!(sub.reorder.lock().expect("gate").next_seq(&A), Some(head));
        metadata(head, head, None);
        let sets = sub.group_coherent_buffer.lock().expect("sets");
        assert_eq!(
            sets.len(),
            cap + 1,
            "only the passed metadata-only head retires"
        );
        let prefix = A[..12].try_into().expect("prefix");
        assert!(!sets.contains_key(&(prefix, PUBLISHER, 1)));
        assert!(
            sets.contains_key(&(prefix, PUBLISHER, head)),
            "the next real head has metadata"
        );
    }
}

/// RTPS v2.5 Sec.8.4.12: a sample below the delivery baseline cannot
/// reopen a set through its preceding GROUP metadata. END metadata still
/// closes existing parts, and a current head can reserve its extra slot.
#[test]
fn group_stale_sample_metadata_cannot_take_the_current_heads_slot() {
    use super::tests_history_limits::{encoded as keyed_encoded, Keyed, NetworkReader};
    for best_effort in [false, true] {
        let qos = if best_effort {
            crate::dds::QoS::best_effort().keep_all()
        } else {
            crate::dds::QoS::reliable().keep_all()
        };
        let gate = if best_effort {
            super::reorder::ReorderGate::new_best_effort()
        } else {
            super::reorder::ReorderGate::new(true, false)
        };
        let net = NetworkReader::<Keyed>::with_parts(
            "group-stale-metadata",
            qos,
            gate,
            crate::qos::ownership::OwnershipKind::default(),
            super::subscriber::CoherentConfig {
                coherent_access: true,
                is_group_scope: true,
            },
        );
        net.subscriber.on_writer_heartbeat(A, 1_000);
        net.subscriber.on_data_with_writer(
            &net.topic,
            A,
            1_000,
            &keyed_encoded(&Keyed { id: 1, value: 1 }),
            crate::dds::CdrVersion::Xcdr2,
        );
        let _ = net.take_all();
        assert_eq!(
            net.subscriber.reorder.lock().expect("gate").next_seq(&A),
            Some(1_001)
        );
        let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER;
        let writer_set =
            crate::protocol::group::group_digest([A[12..].try_into().expect("entity")]);
        let metadata = |seq: u64, end: bool| {
            net.subscriber.on_group_change(
                A,
                crate::engine::GroupChange {
                    seq,
                    group_sn: seq,
                    publisher_entity_id: PUBLISHER,
                    writer_set,
                    gsn: Some(seq),
                    part_first_sn: end.then_some(seq - 1),
                },
            );
        };
        for seq in 1..=3 * cap as u64 {
            metadata(seq, false);
        }
        assert!(
            net.subscriber
                .group_coherent_buffer
                .lock()
                .expect("sets")
                .is_empty(),
            "best_effort={best_effort}: stale DATA metadata stages nothing"
        );
        metadata(999, true);
        assert_eq!(
            net.subscriber
                .group_coherent_buffer
                .lock()
                .expect("sets")
                .len(),
            1,
            "END metadata keeps its existing close semantics"
        );
        for i in 0..cap - 1 {
            metadata(1_003 + 2 * i as u64, true);
        }
        assert_eq!(
            net.subscriber
                .group_coherent_buffer
                .lock()
                .expect("sets")
                .len(),
            cap
        );
        metadata(1_001, false);
        let sets = net.subscriber.group_coherent_buffer.lock().expect("sets");
        assert_eq!(
            sets.len(),
            cap + 1,
            "the current head still reserves its extra slot"
        );
        assert!(sets.contains_key(&(A[..12].try_into().expect("prefix"), PUBLISHER, 1_001)));
    }
}

/// A locally refused GROUP marker still arrived on a BEST_EFFORT reader.
/// Its SN is excluded from the next observed gap, even past the duplicate
/// window; reliable refusal remains repairable in the companion test.
#[test]
fn group_end_refused_for_metadata_room_is_received_on_best_effort() {
    use super::tests_history_limits::{encoded as keyed_encoded, Keyed, NetworkReader};
    for standalone in [false, true] {
        let net = NetworkReader::<Keyed>::with_parts(
            "group-refused-control-receipt",
            crate::dds::QoS::best_effort().keep_all(),
            super::reorder::ReorderGate::new_best_effort(),
            crate::qos::ownership::OwnershipKind::default(),
            super::subscriber::CoherentConfig {
                coherent_access: true,
                is_group_scope: true,
            },
        );
        let data = |seq| {
            net.subscriber.on_data_with_writer(
                &net.topic,
                A,
                seq,
                &keyed_encoded(&Keyed { id: 1, value: 1 }),
                crate::dds::CdrVersion::Xcdr2,
            )
        };
        data(1);
        let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER;
        // Announcements precede their associated controls. They occupy all
        // normal metadata slots without receiving a separate writer SN.
        for i in 0..cap {
            net.subscriber.on_group_change(
                A,
                crate::engine::GroupChange {
                    seq: 100 + i as u64,
                    group_sn: 100 + i as u64,
                    publisher_entity_id: PUBLISHER,
                    writer_set: [1; 4],
                    gsn: None,
                    part_first_sn: Some(99 + i as u64),
                },
            );
        }
        assert_eq!(
            net.subscriber
                .group_coherent_buffer
                .lock()
                .expect("sets")
                .len(),
            cap
        );
        if standalone {
            net.subscriber.on_coherent_end_marker(
                &net.topic,
                A,
                Some(1),
                Some(PUBLISHER),
                1,
                Some(1),
                2,
            );
        } else {
            net.subscriber
                .on_ecs(&net.topic, A, 2, 1, Some(1), Some(PUBLISHER));
        }
        assert_eq!(
            net.subscriber
                .group_coherent_buffer
                .lock()
                .expect("sets")
                .len(),
            cap
        );
        assert_eq!(net.lost(), 0);
        data(8_194);
        assert_eq!(
            net.lost(),
            8_191,
            "standalone={standalone}: only SN3 through SN8193 were absent"
        );
    }
}

/// RTPS v2.5 Sec.9.6.4.5 requires WriterGroupInfo on a spec GROUP
/// DATA. Missing required metadata refuses only that member, even with
/// plenty of room; its absence cannot reclassify older accepted parts.
#[test]
fn group_spec_data_without_required_metadata_is_refused() {
    let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (_ring, sub) = subscriber_with_registry(
        &credit,
        &rejected,
        true,
        64,
        false,
        Some(spec_registry(&[A])),
    );
    *sub.reorder.lock().expect("gate") = super::reorder::ReorderGate::new(true, false);
    sub.on_writer_heartbeat(A, 1);
    let writer_set = crate::protocol::group::group_digest([A[12..].try_into().expect("entity")]);
    sub.on_group_change(
        A,
        crate::engine::GroupChange {
            seq: 1,
            group_sn: 1,
            publisher_entity_id: PUBLISHER,
            writer_set,
            gsn: Some(1),
            part_first_sn: None,
        },
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    sub.on_data_coherent(
        "t",
        A,
        1,
        &encoded_of(1, 8),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        Some(1),
        Some(PUBLISHER),
    );
    // Another set's DATA arrives without its required inline announcement.
    sub.on_data_coherent(
        "t",
        A,
        3,
        &encoded_of(3, 8),
        crate::dds::CdrVersion::Xcdr2,
        Some(3),
        Some(4),
        Some(PUBLISHER),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let sets = sub.group_coherent_buffer.lock().expect("sets");
    assert_eq!(sets.len(), 1, "missing metadata cannot create a legacy set");
    assert_eq!(
        sets.values().next().expect("accepted set").total_samples(),
        1
    );
    drop(sets);
    assert_eq!(
        acknowledged(&credit, A, 1, 3, 1).1,
        vec![2, 3],
        "the malformed member remains unacknowledged"
    );
}

/// The END can run after a DATA takes its staging reservation but before
/// it finishes admission. Its known first SN keeps an empty reserved part
/// incomplete, so the set never commits in pieces.
#[test]
fn group_end_waits_for_a_reserved_member_still_being_admitted() {
    let (pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = credit_for(&[A]);
    let (ring, sub) = subscriber(&credit, &rejected, true, 64);
    let sub = owned(sub);
    *sub.reorder.lock().expect("gate") = super::reorder::ReorderGate::new(true, false);
    sub.on_writer_heartbeat(A, 1);
    let closing = Arc::clone(&sub);
    let observed_ring = Arc::clone(&ring);
    *sub.hold_hook.lock().expect("hook") = Some(Box::new(move || {
        closing.on_ecs("t", A, 2, 1, Some(1), Some(PUBLISHER));
        assert!(
            observed_ring.pop().is_none(),
            "END cannot commit a partial set"
        );
        assert_eq!(closing.group_coherent_buffer.lock().expect("sets").len(), 1);
    }));
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    sub.on_data_coherent(
        "t",
        A,
        1,
        &encoded_of(1, 8),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        Some(1),
        Some(PUBLISHER),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(take_all(&ring, &sub, pool), vec![1]);
    assert!(sub.group_coherent_buffer.lock().expect("sets").is_empty());
}

/// A BEST_EFFORT compound DATA refused before coherent staging publishes
/// neither its value nor its inline lifecycle. A later fresh compound
/// change may commit after another Publisher writer returns room.
#[test]
fn group_best_effort_refused_compound_waits_for_an_accepted_fresh_set() {
    use super::tests_history_limits::NetworkReader;
    use crate::dds::{InstanceHandle, InstanceState, QoS};
    use crate::engine::subscriber::DisposeKind;
    let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
    let net = NetworkReader::<Big>::with_parts(
        "group-refused-inline-lifecycle",
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    let mut sibling = A;
    sibling[15] += 1;
    assert!(net
        .subscriber
        .group_roster
        .set(Arc::new(PairGroupRoster(sibling)))
        .is_ok());
    let writer_set = crate::protocol::group::group_digest([
        A[12..].try_into().expect("entity"),
        sibling[12..].try_into().expect("entity"),
    ]);
    let metadata = |writer, seq, group_sn, gsn, part_first_sn| {
        net.subscriber.on_group_change(
            writer,
            crate::engine::GroupChange {
                seq,
                group_sn,
                publisher_entity_id: PUBLISHER,
                writer_set,
                gsn: Some(gsn),
                part_first_sn,
            },
        )
    };
    let data = |writer, seq, group, value| {
        net.subscriber.on_data_coherent(
            &net.topic,
            writer,
            seq,
            &encoded_of(value, 8),
            crate::dds::CdrVersion::Xcdr2,
            Some(seq),
            Some(group),
            Some(PUBLISHER),
        )
    };
    let handle = InstanceHandle::nil();
    net.subscriber.on_data_with_writer(
        &net.topic,
        A,
        1,
        &encoded_of(0, 8),
        crate::dds::CdrVersion::Xcdr2,
    );
    assert_eq!(net.take_all().len(), 1);
    assert_eq!(
        net.reader.cache().instances().state_of(handle),
        InstanceState::Alive
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    metadata(sibling, 1, 4, 5, None);
    data(sibling, 1, 4, 200);
    let cap = super::subscriber::MAX_OPEN_GROUP_SETS_PER_WRITER as u64;
    for set in 1..=cap + 1 {
        let seq = 2 * set;
        let group = 3 * set + 1;
        metadata(A, seq, group, group, None);
        data(A, seq, group, set);
        metadata(A, seq + 1, group, group + 2, Some(seq));
        net.subscriber
            .on_ecs(&net.topic, A, seq + 1, seq, Some(group), Some(PUBLISHER));
    }
    assert_eq!(
        net.subscriber
            .group_coherent_buffer
            .lock()
            .expect("sets")
            .len(),
        cap as usize + 1
    );
    let refused_seq = 2 * (cap + 2);
    let refused_group = 3 * (cap + 2) + 1;
    metadata(A, refused_seq, refused_group, refused_group, None);
    {
        let _inline = crate::engine::router::inline_lifecycle_scope_for_test(
            A,
            refused_seq,
            handle.0,
            DisposeKind::Disposed,
            true,
        );
        data(A, refused_seq, refused_group, 998);
    }
    assert_eq!(
        net.reader.cache().instances().state_of(handle),
        InstanceState::Alive,
        "refused coherent lifecycle cannot escape its set"
    );
    assert_eq!(
        net.reader.cache().instances().generation_counts(handle),
        (0, 0)
    );
    assert!(net.take_all().is_empty());
    metadata(
        A,
        refused_seq + 1,
        refused_group,
        refused_group + 2,
        Some(refused_seq),
    );
    net.subscriber.on_ecs(
        &net.topic,
        A,
        refused_seq + 1,
        refused_seq,
        Some(refused_group),
        Some(PUBLISHER),
    );
    // BEST_EFFORT cannot repair the refused SN. B's delayed first END
    // commits the first accepted set and frees one context for a fresh SN.
    metadata(sibling, 2, 4, 6, Some(1));
    net.subscriber
        .on_ecs(&net.topic, sibling, 2, 1, Some(4), Some(PUBLISHER));
    let first = net.take_all();
    assert_eq!(
        first.iter().map(|sample| sample.id).collect::<Vec<_>>(),
        vec![1, 200]
    );
    let fresh_seq = refused_seq + 2;
    let fresh_group = refused_group + 3;
    metadata(A, fresh_seq, fresh_group, fresh_group, None);
    {
        let _inline = crate::engine::router::inline_lifecycle_scope_for_test(
            A,
            fresh_seq,
            handle.0,
            DisposeKind::Disposed,
            true,
        );
        data(A, fresh_seq, fresh_group, 999);
    }
    assert_eq!(
        net.reader.cache().instances().state_of(handle),
        InstanceState::Alive,
        "the accepted lifecycle still waits for the complete set"
    );
    metadata(
        A,
        fresh_seq + 1,
        fresh_group,
        fresh_group + 1,
        Some(fresh_seq),
    );
    net.subscriber.on_ecs(
        &net.topic,
        A,
        fresh_seq + 1,
        fresh_seq,
        Some(fresh_group),
        Some(PUBLISHER),
    );
    // Each earlier set's END GSN is its first GSN + 2: B wrote a member
    // after A, but B's intervening DATA/END pairs were lost. The fresh
    // set has only A's member, so its END GSN is first + 1. B's first
    // DATA/END used SN1/2, every intervening set two more SNs, and this
    // fresh idle END takes the next SN without inventing another member.
    let sibling_end = 2 * (cap + 2) + 1;
    metadata(
        sibling,
        sibling_end,
        fresh_group,
        fresh_group + 1,
        Some(sibling_end),
    );
    net.subscriber.on_ecs(
        &net.topic,
        sibling,
        sibling_end,
        sibling_end - 1,
        Some(fresh_group),
        Some(PUBLISHER),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(
        net.reader.cache().instances().state_of(handle),
        InstanceState::NotAliveDisposed
    );
    assert_eq!(
        net.take_all()
            .iter()
            .map(|sample| sample.id)
            .collect::<Vec<_>>(),
        vec![999]
    );
    net.subscriber.on_data_with_writer(
        &net.topic,
        A,
        fresh_seq + 2,
        &encoded_of(1000, 8),
        crate::dds::CdrVersion::Xcdr2,
    );
    let revived = net.reader.take().expect("take").expect("revived sample");
    assert_eq!(revived.id, 1000);
    assert_eq!(
        net.reader.cache().instances().generation_counts(handle),
        (1, 0),
        "only the committed compound disposed this instance"
    );
}

/// Filtered changes are not required for coherent completeness (RTPS
/// v2.5 Sec.8.7.6). Passing an unstaged filtered announcement cannot retire
/// its set and discard another writer's accepted member.
#[test]
fn group_filtered_unstaged_announcer_preserves_an_accepted_sibling_part() {
    for history in 0..3 {
        use super::tests_history_limits::NetworkReader;
        let (_pool, _guard) = private_pool(16 * 1024 * 1024, 25);
        let net = NetworkReader::<Big>::with_parts(
            "group-filtered-announcer",
            crate::dds::QoS::reliable().keep_all(),
            super::reorder::ReorderGate::new(true, false),
            crate::qos::ownership::OwnershipKind::Shared,
            super::subscriber::CoherentConfig {
                coherent_access: true,
                is_group_scope: true,
            },
        );
        let mut sibling = A;
        sibling[15] += 1;
        net.credit.match_writer(sibling);
        net.subscriber.on_writer_heartbeat(A, 1);
        net.subscriber.on_writer_heartbeat(sibling, 1);
        // The real reliable HEARTBEAT seeds the ACK proxy as well as the
        // subscriber gate, before controls can overtake the first DATA.
        let _ = acknowledged(&net.credit, A, 1, 2, 1);
        let _ = acknowledged(&net.credit, sibling, 1, 2, 1);
        assert!(net
            .subscriber
            .group_roster
            .set(Arc::new(PairGroupRoster(sibling)))
            .is_ok());
        let writer_set = crate::protocol::group::group_digest([
            A[12..].try_into().expect("entity"),
            sibling[12..].try_into().expect("entity"),
        ]);
        let metadata = |writer, seq, gsn, part_first_sn| {
            net.subscriber.on_group_change(
                writer,
                crate::engine::GroupChange {
                    seq,
                    group_sn: 1,
                    publisher_entity_id: PUBLISHER,
                    writer_set,
                    gsn: Some(gsn),
                    part_first_sn,
                },
            )
        };
        metadata(A, 1, 1, None);
        let filtering = Arc::clone(&net.subscriber);
        *net.subscriber.hold_hook.lock().expect("hook") = Some(Box::new(move || {
            // The writer's filter declaration overtakes local DATA admission.
            filtering.on_writer_gap_filtered(A, 1, 2, Vec::new(), 1);
        }));
        crate::engine::router::set_route_writer_is_hdds_for_test(true);
        net.subscriber.on_data_coherent(
            &net.topic,
            A,
            1,
            &encoded_of(111, 8),
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            Some(1),
            Some(PUBLISHER),
        );
        metadata(sibling, 1, 2, None);
        net.subscriber.on_data_coherent(
            &net.topic,
            sibling,
            1,
            &encoded_of(200, 8),
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            Some(1),
            Some(PUBLISHER),
        );
        assert_eq!(
            net.subscriber.reorder.lock().expect("gate").next_seq(&A),
            Some(2)
        );
        if history == 1 {
            // This real received change rolls SeenSeqs past the old sample.
            // The independent filter record must still protect its part.
            net.subscriber.on_writer_non_data(A, 8_194);
        } else if history == 2 {
            // Disjoint future filtered ranges exhaust the bounded filter map
            // without crossing missing END2. Its pruned history is unknown.
            for i in 0..300 {
                let seq = 20_000 + 2 * i;
                net.subscriber
                    .on_writer_gap_filtered(A, seq, seq + 1, Vec::new(), 1);
            }
            assert!(
                net.subscriber
                    .reorder
                    .lock()
                    .expect("gate")
                    .filtered_history_floor(&A)
                    > 1
            );
        }
        metadata(A, 2, 3, Some(1));
        if history == 2 {
            crate::engine::router::set_route_writer_is_hdds_for_test(false);
            let sets = net.subscriber.group_coherent_buffer.lock().expect("sets");
            assert_eq!(sets.len(), 1, "unknown filter history cannot retire a set");
            assert_eq!(
                sets.values().next().expect("set").total_samples(),
                1,
                "the accepted sibling member is retained"
            );
            continue;
        }
        net.subscriber
            .on_ecs(&net.topic, A, 2, 1, Some(1), Some(PUBLISHER));
        assert_eq!(
            net.subscriber.reorder.lock().expect("gate").next_seq(&A),
            Some(3),
            "history={history}: END2 must remain repairable after filtered SN1"
        );
        metadata(sibling, 2, 3, Some(1));
        net.subscriber
            .on_ecs(&net.topic, sibling, 2, 1, Some(1), Some(PUBLISHER));
        crate::engine::router::set_route_writer_is_hdds_for_test(false);
        assert_eq!(
            net.take_all()
                .iter()
                .map(|sample| sample.id)
                .collect::<Vec<_>>(),
            vec![200],
            "history={history}: the relevant sibling part must commit"
        );
        assert_eq!(
            net.lost(),
            0,
            "the filtered part did not make the set incomplete"
        );
    }
}
