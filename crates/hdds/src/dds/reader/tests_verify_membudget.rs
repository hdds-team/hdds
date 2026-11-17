// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Memory-budget contract tests. Each test states the contract it expects.

use crate::core::rt;
use crate::engine::Subscriber;
use std::sync::{Arc, Mutex};

const WRITER: [u8; 16] = [0x5D; 16];

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Vbig {
    id: i32,
    body: Vec<u8>,
}

fn encoded(seq: u64, body: usize) -> Vec<u8> {
    let sample = Vbig {
        id: i32::try_from(seq).expect("small"),
        body: vec![0x3C; body],
    };
    let mut bytes = vec![0u8; body + 1024];
    let len = crate::dds::DDS::encode(&sample, &mut bytes, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    bytes.truncate(len);
    bytes
}

fn subscriber(
    credit: &crate::core::reader::ReaderAckCredit,
    rejected: &Arc<Mutex<crate::dds::listener::SampleRejectedStatus>>,
    coherent: bool,
) -> (
    Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Vbig>,
) {
    let ring = Arc::new(rt::IndexRing::with_capacity(64));
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

fn data(sub: &super::subscriber::ReaderSubscriber<Vbig>, seq: u64, body: usize) {
    sub.on_data_with_writer(
        "t",
        WRITER,
        seq,
        &encoded(seq, body),
        crate::dds::CdrVersion::Xcdr2,
    );
}

fn coherent(sub: &super::subscriber::ReaderSubscriber<Vbig>, seq: u64, start: u64, body: usize) {
    sub.on_data_coherent(
        "t",
        WRITER,
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

fn fixture(
    coherent_access: bool,
) -> (
    crate::core::reader::ReaderAckCredit,
    Arc<Mutex<crate::dds::listener::SampleRejectedStatus>>,
) {
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA1; 16],
    );
    credit.match_writer(WRITER);
    let _ = coherent_access;
    let rejected = Arc::new(Mutex::new(
        crate::dds::listener::SampleRejectedStatus::default(),
    ));
    (credit, rejected)
}

/// `reader_reserve_percent: 0` is a documented value ("writers may take
/// the whole pool"). A coherent set of two tiny samples, in order, with the
/// application taking everything and the writer resending what is refused:
/// the set must be delivered. Staged members are stored apart, in the
/// reader's own staging budget, not held in the readers' share
/// (`SlabPool::hold`), where no hold would ever be granted with no share.
#[test]
fn v1_coherent_set_is_delivered_with_no_reader_share() {
    let (pool, _g) = private_pool(16 * 1024 * 1024, 0);
    let (credit, rejected) = fixture(true);
    let (ring, sub) = subscriber(&credit, &rejected, true);
    let mut taken = Vec::new();
    for _round in 0..5 {
        coherent(&sub, 1, 1, 8);
        coherent(&sub, 2, 1, 8);
        data(&sub, 3, 8);
        taken.extend(take_all(&ring, &sub, pool));
        if taken.len() >= 3 {
            break;
        }
    }
    assert_eq!(
        taken,
        vec![1, 2, 3],
        "a two-sample coherent set never commits (rejected={:?})",
        rejected.lock().expect("s").total_count
    );
}

/// V1b. The same with no heap tier at all (`max_heap_bytes: 0`): a set of
/// tiny samples, stored in size classes, is held and delivered.
#[test]
fn v1b_coherent_set_is_delivered_with_no_heap_tier() {
    let (pool, _g) = private_pool(0, 25);
    let (credit, rejected) = fixture(true);
    let (ring, sub) = subscriber(&credit, &rejected, true);
    coherent(&sub, 1, 1, 8);
    coherent(&sub, 2, 1, 8);
    data(&sub, 3, 8);
    assert_eq!(take_all(&ring, &sub, pool), vec![1, 2, 3]);
}

/// Default share (25 %). A reader may store one sample larger than the
/// readers' share of the heap tier (here 300 kB with a 1 MB heap tier,
/// 250 kB share; with the default 16 MiB tier: any sample over 4 MiB).
/// The size estimate (`head_estimate`) must not stay pinned at that value,
/// or no hold would be granted from then on: every later coherent set of
/// this reader, however small, must still be delivered.
#[test]
fn v2_one_large_sample_does_not_disable_coherent_sets_for_good() {
    let (pool, _g) = private_pool(1_000_000, 25);
    let (credit, rejected) = fixture(true);
    let (ring, sub) = subscriber(&credit, &rejected, true);
    data(&sub, 1, 300_000);
    assert_eq!(take_all(&ring, &sub, pool), vec![1], "fixture: 1 stored");
    let mut taken = Vec::new();
    for _round in 0..5 {
        coherent(&sub, 2, 2, 8);
        coherent(&sub, 3, 2, 8);
        data(&sub, 4, 8);
        taken.extend(take_all(&ring, &sub, pool));
        if taken.len() >= 3 {
            break;
        }
    }
    assert_eq!(
        taken,
        vec![2, 3, 4],
        "small coherent set after one large sample"
    );
}

/// V2b. The same for a reader without coherent access: after one sample
/// larger than the readers' share, a few smaller ones bring the head
/// estimate back down, and a sample above a gap is held again (it arrives
/// with its head, both delivered at once; refused, it would not be).
#[test]
fn v2b_one_large_sample_does_not_disable_holding_for_good() {
    let (pool, _g) = private_pool(1_000_000, 25);
    let (credit, rejected) = fixture(false);
    let (ring, sub) = subscriber(&credit, &rejected, false);
    data(&sub, 1, 300_000);
    assert_eq!(take_all(&ring, &sub, pool), vec![1], "fixture: 1 stored");
    for seq in 2..=9 {
        data(&sub, seq, 100_000);
        assert_eq!(take_all(&ring, &sub, pool), vec![seq]);
    }
    data(&sub, 11, 100_000);
    data(&sub, 10, 100_000);
    assert_eq!(
        take_all(&ring, &sub, pool),
        vec![10, 11],
        "11 held above 10 once the estimate came down"
    );
}

/// A coherent set whose members need more than the readers' share of
/// the heap tier (6 x 200 kB, share 1.1 MB). The application takes
/// eagerly, the writer resends what is refused: the set can never be
/// staged whole, the earlier members stay held, the writer stalls for good.
#[test]
fn v3_coherent_set_larger_than_the_share_is_resolved() {
    let (pool, _g) = private_pool(1_100_000, 100);
    let (credit, rejected) = fixture(true);
    let (ring, sub) = subscriber(&credit, &rejected, true);
    let mut taken = Vec::new();
    for _round in 0..5 {
        for seq in 1..=6 {
            coherent(&sub, seq, 1, 200_000);
        }
        data(&sub, 7, 8);
        taken.extend(take_all(&ring, &sub, pool));
        if !taken.is_empty() {
            break;
        }
    }
    let rejected = rejected.lock().expect("s").total_count;
    assert!(
        !taken.is_empty(),
        "set larger than the share: nothing ever delivered, writer stalled \
         (rejections={rejected}, held={})",
        pool.metrics()
            .held_heap_bytes
            .load(std::sync::atomic::Ordering::Acquire)
    );
}

/// Head estimate miss under a writer at its legal ceiling. Heap tier
/// 1.6 MB, share 25 % (400 kB): a writer's persistent history (a
/// TRANSIENT_LOCAL one, say) at its 1.2 MB ceiling. The reader stores 150
/// kB samples; 3 is held above a missing 2 (150 kB held + 150 kB head
/// estimate = 300 kB <= 400 kB). The missing 2 is 300 kB: 1.2 M + 150 k +
/// 300 k > 1.6 M. Refused unacknowledged, resent forever; 3 is held forever.
#[test]
fn v4_head_larger_than_the_estimate_is_eventually_stored() {
    let (pool, _g) = private_pool(1_600_000, 25);
    let (credit, rejected) = fixture(false);
    let (ring, sub) = subscriber(&credit, &rejected, false);
    // The co-located writer's history, at its ceiling.
    let mut writer = Vec::new();
    while let Some((h, _)) = pool.reserve_and_write(&vec![0u8; 200_000], rt::Claim::Writer) {
        writer.push(h);
    }
    assert_eq!(writer.len(), 6, "fixture: writer at 1.2 MB");
    data(&sub, 1, 150_000);
    assert_eq!(take_all(&ring, &sub, pool), vec![1]);
    data(&sub, 3, 150_000);
    let mut taken = Vec::new();
    for _round in 0..5 {
        data(&sub, 2, 300_000);
        taken.extend(take_all(&ring, &sub, pool));
        if !taken.is_empty() {
            break;
        }
    }
    let rejected_n = rejected.lock().expect("s").total_count;
    for h in writer {
        pool.release(h);
    }
    assert_eq!(
        taken,
        vec![2, 3],
        "the head never fits, 3 stays held (rejections={rejected_n})"
    );
}

/// V5a. Concurrency on one size class: 8 writer threads and 4 reader
/// threads claiming 100 kB (only the 128 KiB class, 16 slots, 4 kept)
/// and releasing at once, 200k iterations. A writer count above 12 or a
/// reader claim that fails (each reader holds at most one slot, so at most
/// 3 others + 12 writers are taken) breaks the reserve.
#[test]
fn v5a_class_reserve_holds_under_contention() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let pool = Arc::new(rt::SlabPool::with_policy(&crate::qos::MemoryPolicy {
        max_heap_bytes: 0,
        ..crate::qos::MemoryPolicy::default()
    }));
    let writers_held = Arc::new(AtomicUsize::new(0));
    let max_writers = Arc::new(AtomicUsize::new(0));
    let reader_fail = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let payload = vec![7u8; 100_000];
    std::thread::scope(|s| {
        for _ in 0..8 {
            let (pool, wh, mw, stop, p) = (
                Arc::clone(&pool),
                Arc::clone(&writers_held),
                Arc::clone(&max_writers),
                Arc::clone(&stop),
                payload.clone(),
            );
            s.spawn(move || {
                let mut mine = Vec::new();
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    if let Some((h, _)) = pool.reserve_and_write(&p, rt::Claim::Writer) {
                        let n = wh.fetch_add(1, Ordering::SeqCst) + 1;
                        mw.fetch_max(n, Ordering::SeqCst);
                        mine.push(h);
                    }
                    i += 1;
                    if i.is_multiple_of(3) {
                        if let Some(h) = mine.pop() {
                            wh.fetch_sub(1, Ordering::SeqCst);
                            pool.release(h);
                        }
                    }
                }
                for h in mine {
                    wh.fetch_sub(1, Ordering::SeqCst);
                    pool.release(h);
                }
            });
        }
        let mut readers = Vec::new();
        for _ in 0..4 {
            let (pool, rf, p) = (Arc::clone(&pool), Arc::clone(&reader_fail), payload.clone());
            readers.push(s.spawn(move || {
                for _ in 0..50_000 {
                    match pool.reserve_and_write(&p[..], rt::Claim::Reader) {
                        Some((h, _)) => pool.release(h),
                        None => {
                            rf.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }));
        }
        for r in readers {
            r.join().expect("reader");
        }
        stop.store(true, Ordering::SeqCst);
    });
    let mw = max_writers.load(Ordering::SeqCst);
    let rf = reader_fail.load(Ordering::SeqCst);
    eprintln!("V5a max_writers={mw} reader_failures={rf}");
    assert!(mw <= 12, "writers held {mw} > 12 slots");
    assert_eq!(rf, 0, "a reader claim failed with the reserve owed to it");
}

/// V5b. Heap tier under contention: writers never above their 750 kB
/// ceiling, the gauge never above 1 MB, a single reader (200 kB at a time)
/// never refused.
#[test]
fn v5b_heap_reserve_and_gauge_hold_under_contention() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let pool = Arc::new(rt::SlabPool::with_policy(&crate::qos::MemoryPolicy {
        max_heap_bytes: 1_000_000,
        large_pool: crate::qos::LargePoolConfig::default(),
        ..crate::qos::MemoryPolicy::default()
    }));
    let writer_bytes = Arc::new(AtomicUsize::new(0));
    let max_writer = Arc::new(AtomicUsize::new(0));
    let max_gauge = Arc::new(AtomicUsize::new(0));
    let reader_fail = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let big = vec![1u8; 200_000];
    std::thread::scope(|s| {
        for _ in 0..8 {
            let (pool, wb, mw, stop, p) = (
                Arc::clone(&pool),
                Arc::clone(&writer_bytes),
                Arc::clone(&max_writer),
                Arc::clone(&stop),
                big.clone(),
            );
            s.spawn(move || {
                let mut mine = Vec::new();
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    if let Some((h, _)) = pool.reserve_and_write(&p, rt::Claim::Writer) {
                        let n = wb.fetch_add(p.len(), Ordering::SeqCst) + p.len();
                        mw.fetch_max(n, Ordering::SeqCst);
                        mine.push(h);
                    }
                    i += 1;
                    if i.is_multiple_of(2) {
                        if let Some(h) = mine.pop() {
                            wb.fetch_sub(p.len(), Ordering::SeqCst);
                            pool.release(h);
                        }
                    }
                }
                for h in mine {
                    wb.fetch_sub(p.len(), Ordering::SeqCst);
                    pool.release(h);
                }
            });
        }
        {
            let (pool, mg, stop) = (Arc::clone(&pool), Arc::clone(&max_gauge), Arc::clone(&stop));
            s.spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let g = pool.metrics().heap_bytes_used.load(Ordering::SeqCst);
                    mg.fetch_max(g, Ordering::SeqCst);
                }
            });
        }
        let (pool2, rf, p) = (Arc::clone(&pool), Arc::clone(&reader_fail), big.clone());
        let r = s.spawn(move || {
            for _ in 0..100_000 {
                match pool2.reserve_and_write(&p, rt::Claim::Reader) {
                    Some((h, _)) => pool2.release(h),
                    None => {
                        rf.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        });
        r.join().expect("reader");
        stop.store(true, Ordering::SeqCst);
    });
    let (mw, mg, rf) = (
        max_writer.load(Ordering::SeqCst),
        max_gauge.load(Ordering::SeqCst),
        reader_fail.load(Ordering::SeqCst),
    );
    eprintln!("V5b max_writer_bytes={mw} max_gauge={mg} reader_failures={rf}");
    assert!(mw <= 750_000, "writer heap {mw} > 750 000");
    assert!(mg <= 1_000_000, "gauge {mg} > ceiling");
    assert_eq!(rf, 0, "reader refused with its share owed");
}

/// Measure (prints, never fails): what a writers-only process gets of
/// the default pool, per payload size, vs the whole pool (the claim: a
/// reader gets what a writer gets).
#[test]
fn v7_writer_share_capacity_default_policy() {
    for size in [64usize, 1024, 6000, 60_000, 200_000, 1_000_000] {
        let count = |claim: rt::Claim| {
            let pool = rt::SlabPool::with_policy(&crate::qos::MemoryPolicy::default());
            let p = vec![0u8; size];
            let mut hs = Vec::new();
            while let Some((h, _)) = pool.reserve_and_write(&p, claim) {
                hs.push(h);
                if hs.len() > 200_000 {
                    break;
                }
            }
            let n = hs.len();
            for h in hs {
                pool.release(h);
            }
            n
        };
        let (w, r) = (count(rt::Claim::Writer), count(rt::Claim::Reader));
        eprintln!(
            "pool-share size={size} writer_burst={w} whole_pool={r} ratio={:.3}",
            w as f64 / r as f64
        );
    }
}

/// Controls: the same scenarios inside their bounds deliver (so the scenarios above
/// fail on the bound, not on the fixture).
#[test]
fn c1_coherent_set_with_default_share_is_delivered() {
    let (pool, _g) = private_pool(16 * 1024 * 1024, 25);
    let (credit, rejected) = fixture(true);
    let (ring, sub) = subscriber(&credit, &rejected, true);
    coherent(&sub, 1, 1, 8);
    coherent(&sub, 2, 1, 8);
    data(&sub, 3, 8);
    assert_eq!(take_all(&ring, &sub, pool), vec![1, 2, 3]);
}

#[test]
fn c2_small_coherent_set_without_a_large_sample_is_delivered() {
    let (pool, _g) = private_pool(1_000_000, 25);
    let (credit, rejected) = fixture(true);
    let (ring, sub) = subscriber(&credit, &rejected, true);
    data(&sub, 1, 8);
    assert_eq!(take_all(&ring, &sub, pool), vec![1]);
    coherent(&sub, 2, 2, 8);
    coherent(&sub, 3, 2, 8);
    data(&sub, 4, 8);
    assert_eq!(take_all(&ring, &sub, pool), vec![2, 3, 4]);
}

#[test]
fn c3_coherent_set_within_the_share_is_delivered() {
    let (pool, _g) = private_pool(1_100_000, 100);
    let (credit, rejected) = fixture(true);
    let (ring, sub) = subscriber(&credit, &rejected, true);
    for seq in 1..=4 {
        coherent(&sub, seq, 1, 200_000);
    }
    data(&sub, 5, 8);
    assert_eq!(take_all(&ring, &sub, pool), vec![1, 2, 3, 4, 5]);
}

#[test]
fn c4_head_within_the_estimate_is_stored() {
    let (pool, _g) = private_pool(1_600_000, 25);
    let (credit, rejected) = fixture(false);
    let (ring, sub) = subscriber(&credit, &rejected, false);
    let mut writer = Vec::new();
    while let Some((h, _)) = pool.reserve_and_write(&vec![0u8; 200_000], rt::Claim::Writer) {
        writer.push(h);
    }
    data(&sub, 1, 150_000);
    assert_eq!(take_all(&ring, &sub, pool), vec![1]);
    data(&sub, 3, 150_000);
    data(&sub, 2, 150_000);
    let taken = take_all(&ring, &sub, pool);
    for h in writer {
        pool.release(h);
    }
    assert_eq!(taken, vec![2, 3]);
}

/// Noisy neighbour: reader A (KEEP_ALL, application never takes) and
/// reader B of the same process. A's received samples are reader claims,
/// which may take every tier whole, the readers' share included: once A
/// filled the pool, B stores nothing and its writer stalls for as long as
/// A's application does not take. The share is per process, not per reader.
#[test]
#[ignore = "finding v6: the readers' share is per process, not per reader"]
fn v6_a_reader_that_never_takes_does_not_starve_another() {
    let (pool, _g) = private_pool(1_000_000, 25);
    let (credit_a, rejected_a) = fixture(false);
    let (_ring_a, sub_a) = subscriber(&credit_a, &rejected_a, false);
    let (credit_b, rejected_b) = fixture(false);
    let (ring_b, sub_b) = subscriber(&credit_b, &rejected_b, false);
    // A receives 200 kB samples until refused (never taken).
    for seq in 1..=40 {
        data(&sub_a, seq, 200_000);
    }
    data(&sub_b, 1, 200_000);
    let taken = take_all(&ring_b, &sub_b, pool);
    assert_eq!(
        taken,
        vec![1],
        "B starved by A (heap used {})",
        pool.metrics()
            .heap_bytes_used
            .load(std::sync::atomic::Ordering::Acquire)
    );
}

/// Two writers' coherent sets, each well
/// inside the readers' share alone (2 x 200 kB of a 500 kB share), too big
/// to be staged together. Interleaved, A1 B11 A2 B12, the collision on the
/// pool-wide share must not reject A's set whole, acknowledged and never
/// delivered. Nothing in B's set waits for A's: A's members refused
/// unacknowledged, or B's set not admitted until A's commits, and the
/// writers' resends deliver both. The writers resend what is not
/// acknowledged (here: everything, a duplicate is dropped).
#[test]
fn availability_two_concurrent_small_sets_from_two_writers_must_both_deliver() {
    const WRITER_A: [u8; 16] = [0xA1; 16];
    const WRITER_B: [u8; 16] = [0xB2; 16];
    let (pool, _g) = private_pool(2_000_000, 25);
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xC3; 16],
    );
    credit.match_writer(WRITER_A);
    credit.match_writer(WRITER_B);
    let rejected = Arc::new(Mutex::new(
        crate::dds::listener::SampleRejectedStatus::default(),
    ));
    let (ring, sub) = subscriber(&credit, &rejected, true);
    let send_coherent = |writer: [u8; 16], seq: u64, start: u64| {
        sub.on_data_coherent(
            "t",
            writer,
            seq,
            &encoded(seq, 200_000),
            crate::dds::CdrVersion::Xcdr2,
            Some(start),
            None,
            None,
        );
    };
    let send_plain = |writer: [u8; 16], seq: u64| {
        sub.on_data_with_writer(
            "t",
            writer,
            seq,
            &encoded(seq, 8),
            crate::dds::CdrVersion::Xcdr2,
        );
    };
    let mut taken = Vec::new();
    for _resend in 0..3 {
        send_coherent(WRITER_A, 1, 1);
        send_coherent(WRITER_B, 11, 11);
        send_coherent(WRITER_A, 2, 1);
        send_coherent(WRITER_B, 12, 11);
        send_plain(WRITER_A, 3);
        send_plain(WRITER_B, 13);
        taken.extend(take_all(&ring, &sub, pool));
    }
    taken.sort_unstable();
    assert_eq!(
        taken,
        vec![1, 2, 3, 11, 12, 13],
        "both sets delivered, each once"
    );
    assert_eq!(
        pool.metrics()
            .held_heap_bytes
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
}
