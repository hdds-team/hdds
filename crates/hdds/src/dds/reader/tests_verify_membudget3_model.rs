// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A REALISTIC load model of the staging table,
//! derived from `tests_memory_model.rs` (same real writer HistoryCache, real
//! ReaderSubscriber, simulated network), with:
//! - the DEFAULT MemoryPolicy (16 MiB heap tier, 25 % readers' share),
//! - 1-4 writers, each with a size profile in 100 B ..= 64 KiB,
//! - coherent sets of 1-20 samples (TOPIC scope),
//! - a reader that takes promptly (rare, short take stalls),
//! - bursts (a whole set written back to back), moderate loss (1-5 %),
//!   light reordering and duplicates, rare short receive stalls,
//! - writer and reader in one process (shared pool) or two.
//!
//! Measured per seed: sets rejected whole, permanent stalls, partial or
//! out-of-order delivery. Any rejection under this load is a failure: no
//! set here is larger than a set may stage, and the reader takes promptly.
//!
//! `HDDS_M3_STAGING` sets the samples a set may stage (`N`), the
//! reader's default otherwise (`MAX_STAGED_PER_WRITER`: 64 in unit tests,
//! 4096 in a build).

use super::admission::HistoryRoom;
use crate::core::reader::{HeartbeatSeen, ReaderAckCredit, ReaderProxyRegistry};
use crate::core::rt;
use crate::engine::Subscriber as _;
use crate::reliability::HistoryCache;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Msg {
    id: i32,
    body: Vec<u8>,
}

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance_permille(&mut self, p: u64) -> bool {
        self.below(1000) < p
    }
}

fn encoded(seq: u64, body: usize) -> Vec<u8> {
    let sample = Msg {
        id: (seq % 1_000_000) as i32,
        body: vec![0x3C; body],
    };
    let mut bytes = vec![0u8; body + 1024];
    let len = crate::dds::DDS::encode(&sample, &mut bytes, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    bytes.truncate(len);
    bytes
}

type Rejected = Arc<Mutex<crate::dds::listener::SampleRejectedStatus>>;

struct Side {
    guid: [u8; 16],
    base: u64,
    cache: HistoryCache,
    set_of: Vec<Option<u64>>,
    body_of: Vec<usize>,
    total: u64,
    next_write: u64,
    refused_in_a_row: u32,
    heartbeats: u32,
    acked_through: u64,
    weight: u64,
}

impl Side {
    fn idx(&self, seq: u64) -> usize {
        (seq - self.base - 1) as usize
    }
    fn last(&self) -> u64 {
        self.base + self.total
    }
    fn owns(&self, seq: u64) -> bool {
        seq > self.base && seq <= self.last()
    }
}

/// Owner of a pool the test frees at the end of the seed (the
/// `private_slab_pool_for_test` hook wants a `&'static`).
struct OwnedPool(*mut Arc<rt::SlabPool>);
impl OwnedPool {
    fn new(policy: &crate::qos::MemoryPolicy) -> Self {
        Self(Box::into_raw(Box::new(Arc::new(
            rt::SlabPool::with_policy(policy),
        ))))
    }
    fn get(&self) -> &'static Arc<rt::SlabPool> {
        // SAFETY: freed only in `free`, after every user is dropped.
        unsafe { &*self.0 }
    }
    fn free(self) {
        // SAFETY: allocated by Box::into_raw in `new`, freed once.
        unsafe { drop(Box::from_raw(self.0)) }
    }
}

#[derive(Default, Debug, Clone)]
pub(super) struct Outcome {
    pub sets: u64,
    pub sets_rejected: u64,
    pub stalled: bool,
    pub wrong: bool,
    pub timeouts: u32,
    pub max_held: usize,
    pub max_heap: usize,
    pub max_staged: usize,
    pub reports: u32,
    pub summary: String,
}

struct Run {
    shared: bool,
    reader_pool: &'static Arc<rt::SlabPool>,
    writer_pool: &'static Arc<rt::SlabPool>,
    credit: ReaderAckCredit,
    ring: Arc<rt::IndexRing>,
    sub: Option<super::subscriber::ReaderSubscriber<Msg>>,
    rejected: Rejected,
    sides: Vec<Side>,
    net: VecDeque<(usize, u64)>,
    receive_stalled: u32,
    take_stalled: u32,
    loss_permille: u64,
    timeouts: u32,
    delivered: Vec<u64>,
    max_held: usize,
    max_heap: usize,
    max_staged: usize,
    last_answer: Vec<(u64, Vec<u64>, usize, Option<u64>)>,
}

fn take_stall_max() -> u64 {
    std::env::var("HDDS_M3_TAKE_STALL_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}

const PROFILES: [&str; 6] = ["100B", "1KiB", "8KiB", "32KiB", "64KiB", "mixed"];

fn body_for(rng: &mut Rng, profile: usize) -> usize {
    match profile {
        0 => 100,
        1 => 1024,
        2 => 8192,
        3 => 32_768,
        4 => 65_536,
        _ => 100 + rng.below(65_536 - 100 + 1) as usize,
    }
}

impl Run {
    fn sub(&self) -> &super::subscriber::ReaderSubscriber<Msg> {
        self.sub.as_ref().expect("sub")
    }

    fn write_one(&mut self, w: usize, rng: &mut Rng) -> bool {
        let side = &mut self.sides[w];
        if side.next_write > side.total {
            return false;
        }
        let seq = side.base + side.next_write;
        let body = side.body_of[side.idx(seq)];
        let _g = rt::private_slab_pool_for_test(self.writer_pool);
        match side.cache.insert(seq, &encoded(seq, body)) {
            Ok(()) => {
                side.next_write += 1;
                side.refused_in_a_row = 0;
                if seq == side.base + 1 {
                    drop(_g);
                    self.receive(w, seq);
                } else if !rng.chance_permille(self.loss_permille) {
                    self.send(w, seq);
                }
                true
            }
            Err(_) => {
                side.refused_in_a_row += 1;
                if side.refused_in_a_row >= 40 {
                    self.timeouts += 1;
                    side.refused_in_a_row = 0;
                }
                false
            }
        }
    }

    fn pick(&mut self, rng: &mut Rng) -> usize {
        let total: u64 = self.sides.iter().map(|s| s.weight).sum();
        let mut x = rng.below(total);
        for (i, s) in self.sides.iter().enumerate() {
            if x < s.weight {
                return i;
            }
            x -= s.weight;
        }
        0
    }

    fn write(&mut self, rng: &mut Rng) {
        let w = self.pick(rng);
        // A burst: the rest of the current set back to back (30 %).
        if rng.below(100) < 30 {
            loop {
                let side = &self.sides[w];
                if side.next_write > side.total {
                    break;
                }
                let seq = side.base + side.next_write;
                let cur = side.set_of[side.idx(seq)];
                if !self.write_one(w, rng) {
                    break;
                }
                let side = &self.sides[w];
                if side.next_write > side.total {
                    break;
                }
                let next = side.base + side.next_write;
                if cur.is_none() || side.set_of[side.idx(next)] != cur {
                    break;
                }
            }
        } else {
            self.write_one(w, rng);
        }
    }

    fn send(&mut self, w: usize, seq: u64) {
        if self.receive_stalled > 0 && self.net.len() >= 64 {
            return;
        }
        if !self.net.contains(&(w, seq)) {
            self.net.push_back((w, seq));
        }
    }

    fn deliver(&mut self, rng: &mut Rng, lossy: bool) {
        if self.receive_stalled > 0 {
            return;
        }
        // A few datagrams per step.
        for _ in 0..(1 + rng.below(4)) {
            if self.net.is_empty() {
                return;
            }
            let at = if lossy && rng.chance_permille(30) {
                rng.below(self.net.len() as u64) as usize
            } else {
                0
            };
            let Some((w, seq)) = self.net.remove(at) else {
                return;
            };
            if lossy && rng.chance_permille(10) {
                self.net.push_back((w, seq));
            }
            self.receive(w, seq);
        }
    }

    fn receive(&mut self, w: usize, seq: u64) {
        let _g = rt::private_slab_pool_for_test(self.reader_pool);
        let side = &self.sides[w];
        let body = side.body_of[side.idx(seq)];
        match side.set_of[side.idx(seq)] {
            Some(start) => self.sub().on_data_coherent(
                "m",
                side.guid,
                seq,
                &encoded(seq, body),
                crate::dds::CdrVersion::Xcdr2,
                Some(start),
                None,
                None,
            ),
            None => self.sub().on_data_with_writer(
                "m",
                side.guid,
                seq,
                &encoded(seq, body),
                crate::dds::CdrVersion::Xcdr2,
            ),
        }
    }

    fn take(&mut self) {
        if self.take_stalled > 0 {
            return;
        }
        let _g = rt::private_slab_pool_for_test(self.reader_pool);
        while let Some(entry) = self.ring.pop() {
            self.delivered.push(u64::from(entry.seq));
            self.reader_pool.release(entry.handle);
            drop(self.sub().room.as_ref().map(HistoryRoom::adopt));
        }
    }

    fn heartbeat(&mut self, w: usize, lossy: bool, rng: &mut Rng) {
        let Some(last) = self.sides[w].cache.newest_seq() else {
            return;
        };
        let first = self.sides[w].cache.oldest_seq().unwrap_or(last);
        self.sides[w].heartbeats += 1;
        let guid = self.sides[w].guid;
        let Some(answer) = self.credit.answer_heartbeat(
            &guid,
            &HeartbeatSeen {
                first_seq: first as i64,
                last_seq: last as i64,
                count: self.sides[w].heartbeats,
                final_flag: false,
            },
        ) else {
            return;
        };
        if self.last_answer.len() < self.sides.len() {
            self.last_answer
                .resize(self.sides.len(), (0, Vec::new(), 0, None));
        }
        let missing_head: Vec<u64> = answer.missing.iter().copied().take(6).collect();
        self.last_answer[w] = (
            answer.bitmap_base,
            missing_head,
            answer.missing.len(),
            self.sides[w].cache.oldest_seq(),
        );
        self.sides[w].acked_through = answer.bitmap_base.saturating_sub(1);
        {
            let _g = rt::private_slab_pool_for_test(self.reader_pool);
            self.sub().on_writer_heartbeat_range(guid, first, last);
        }
        let _g = rt::private_slab_pool_for_test(self.writer_pool);
        let through = self.sides[w].acked_through;
        self.sides[w].cache.remove_acknowledged(through);
        for seq in answer.missing {
            if self.sides[w].cache.get(seq).is_some()
                && (!lossy || !rng.chance_permille(self.loss_permille))
            {
                self.send(w, seq);
            }
        }
    }

    fn step(&mut self, rng: &mut Rng, lossy: bool) {
        self.receive_stalled = self.receive_stalled.saturating_sub(1);
        self.take_stalled = self.take_stalled.saturating_sub(1);
        match rng.below(100) {
            0..=24 => self.write(rng),
            25..=69 => self.deliver(rng, lossy),
            70..=84 => {
                let w = rng.below(self.sides.len() as u64) as usize;
                self.heartbeat(w, lossy, rng);
            }
            85 if lossy => self.receive_stalled = 1 + rng.below(10) as u32,
            86 if lossy => self.take_stalled = 1 + rng.below(take_stall_max()) as u32,
            _ => self.deliver(rng, lossy),
        }
        // Prompt reader: takes after nearly every step.
        if rng.below(100) < 90 {
            self.take();
        }
        let m = self.reader_pool.metrics();
        self.max_held = self
            .max_held
            .max(m.held_heap_bytes.load(std::sync::atomic::Ordering::Relaxed));
        self.max_staged = self.max_staged.max(self.sub().staging.used());
        self.max_heap = self
            .max_heap
            .max(m.heap_bytes_used.load(std::sync::atomic::Ordering::Relaxed));
    }

    fn done(&self) -> bool {
        self.sides.iter().all(|s| {
            s.next_write > s.total
                && s.acked_through >= s.last()
                && self.delivered.contains(&s.last())
        })
    }
}

pub(super) fn run_seed(
    seed: u64,
    writers_override: Option<usize>,
    shared_override: Option<bool>,
) -> Outcome {
    let mut rng = Rng::new(seed);
    let shared = shared_override.unwrap_or_else(|| rng.below(2) == 0);
    let policy = crate::qos::MemoryPolicy::default();
    let reader_owned = OwnedPool::new(&policy);
    let writer_owned = if shared {
        None
    } else {
        Some(OwnedPool::new(&policy))
    };
    let reader_pool = reader_owned.get();
    let writer_pool = writer_owned.as_ref().map_or(reader_pool, OwnedPool::get);
    let nwriters = writers_override.unwrap_or(1 + rng.below(4) as usize);
    let loss_permille = 10 + rng.below(41); // 1-5 %
    let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
    let rejected: Rejected = Arc::default();
    let ring = Arc::new(rt::IndexRing::with_capacity(4096));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let mut sub = super::subscriber::ReaderSubscriber::<Msg>::new_with_coherent(
        "m".to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, true))),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
        None,
        Some(credit.clone()),
        Arc::clone(&rejected),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    sub.room = Some(HistoryRoom::new(
        &ring,
        crate::reliability::LENGTH_UNLIMITED,
    ));
    if let Some(samples) = std::env::var("HDDS_M3_STAGING")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        sub.staging = super::staging_budget::StagingBudget::new(samples);
    }
    sub.register_match_entry_for_test(crate::dds::QoS::reliable().keep_all());
    let mut sides = Vec::new();
    let mut profiles = Vec::new();
    let mut nsets = 0u64;
    for w in 0..nwriters {
        let guid = [0x71 + w as u8; 16];
        credit.match_writer(guid);
        let base = (w as u64) * 100_000;
        let drawn = rng.below(PROFILES.len() as u64) as usize;
        let profile = std::env::var("HDDS_M3_PROFILE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(drawn);
        profiles.push(PROFILES[profile]);
        let total = 50 + rng.below(250);
        let mut set_of = vec![None; total as usize];
        let mut seq = 2u64;
        while seq < total {
            let gap = rng.below(4);
            seq += gap;
            if seq >= total {
                break;
            }
            let len = (1 + rng.below(20)).min(total - seq);
            for m in seq..seq + len {
                set_of[(m - 1) as usize] = Some(base + seq);
            }
            nsets += 1;
            seq += len;
        }
        let body_of = (0..total).map(|_| body_for(&mut rng, profile)).collect();
        let cache = HistoryCache::new_with_limits(
            Arc::clone(writer_pool),
            crate::reliability::LENGTH_UNLIMITED,
            usize::MAX,
            crate::qos::History::KeepAll,
        );
        cache.set_release_policy(true, false);
        // Writers at different rates (1x..20x): a slow writer's set waits
        // longer for its close.
        let weight = [1u64, 2, 5, 10, 20][rng.below(5) as usize];
        sides.push(Side {
            guid,
            base,
            cache,
            set_of,
            body_of,
            total,
            next_write: 1,
            refused_in_a_row: 0,
            heartbeats: 0,
            acked_through: base,
            weight,
        });
    }
    let mut run = Run {
        shared,
        reader_pool,
        writer_pool,
        credit,
        ring,
        sub: Some(sub),
        rejected,
        sides,
        net: VecDeque::new(),
        receive_stalled: 0,
        take_stalled: 0,
        loss_permille,
        timeouts: 0,
        delivered: Vec::new(),
        max_held: 0,
        max_heap: 0,
        max_staged: 0,
        last_answer: Vec::new(),
    };
    for w in 0..run.sides.len() {
        run.write_one(w, &mut rng);
    }
    let schedule = 1500 + rng.below(2500);
    for _ in 0..schedule {
        run.step(&mut rng, true);
    }
    let mut drain = 0;
    while !run.done() && drain < 60_000 {
        run.receive_stalled = 0;
        run.take_stalled = 0;
        run.step(&mut rng, false);
        drain += 1;
    }
    let mut out = Outcome {
        sets: nsets,
        stalled: !run.done(),
        timeouts: run.timeouts,
        max_held: run.max_held,
        max_heap: run.max_heap,
        max_staged: run.max_staged,
        reports: run.rejected.lock().expect("s").total_count as u32,
        ..Outcome::default()
    };
    let delivered: std::collections::BTreeSet<u64> = run.delivered.iter().copied().collect();
    if !out.stalled {
        for side in &run.sides {
            let mut expected = Vec::new();
            let mut seq = side.base + 1;
            while seq <= side.last() {
                let Some(start) = side.set_of[side.idx(seq)] else {
                    expected.push(seq);
                    seq += 1;
                    continue;
                };
                let members: Vec<u64> = (seq..=side.last())
                    .take_while(|&m| side.set_of[side.idx(m)] == Some(start))
                    .collect();
                let got = members.iter().filter(|m| delivered.contains(m)).count();
                if got == members.len() {
                    expected.extend(&members);
                } else if got == 0 {
                    out.sets_rejected += 1;
                } else {
                    out.wrong = true;
                    expected.extend(&members);
                }
                seq += members.len() as u64;
            }
            let got: Vec<u64> = run
                .delivered
                .iter()
                .copied()
                .filter(|&s| side.owns(s))
                .collect();
            if got != expected {
                out.wrong = true;
            }
        }
    }
    out.summary = format!(
        "seed {seed} shared={} writers={} profiles={profiles:?} weights={:?} loss={}permille \
         sets={} max_held={} max_heap={} max_staged={} sample_rejected_reports={} rejected_sets={} stalled={} wrong={} timeouts={} delivered={} drain={drain}",
        run.shared,
        run.sides.len(),
        run.sides.iter().map(|s| s.weight).collect::<Vec<_>>(),
        loss_permille,
        out.sets,
        out.max_held,
        out.max_heap,
        out.max_staged,
        out.reports,
        out.sets_rejected,
        out.stalled,
        out.wrong,
        out.timeouts,
        run.delivered.len(),
    );
    if out.stalled {
        out.summary.push_str(&format!(
            " STALL: written {:?} acked {:?} last_answers(base,missing,n,oldest)={:?} net={} held={}",
            run.sides.iter().map(|s| (s.next_write - 1, s.total)).collect::<Vec<_>>(),
            run.sides.iter().map(|s| s.acked_through - s.base).collect::<Vec<_>>(),
            run.last_answer,
            run.net.len(),
            run.reader_pool
                .metrics()
                .held_heap_bytes
                .load(std::sync::atomic::Ordering::Acquire)
        ));
    }
    // Tear down under the reader pool's hook (held storage gives back to it).
    {
        let _g = rt::private_slab_pool_for_test(run.reader_pool);
        drop(run.sub.take());
        let _w = rt::private_slab_pool_for_test(run.writer_pool);
        drop(std::mem::take(&mut run.sides));
        drop(std::mem::take(&mut run.net));
        while let Some(e) = run.ring.pop() {
            run.reader_pool.release(e.handle);
        }
    }
    let _ = &run.rejected;
    drop(run);
    if let Some(w) = writer_owned {
        w.free();
    }
    reader_owned.free();
    out
}

fn sweep(writers: Option<usize>, shared: Option<bool>) {
    let n: u64 = std::env::var("HDDS_M3_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let start: u64 = std::env::var("HDDS_M3_START")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let (mut sets, mut rej_sets, mut seeds_rej, mut stalls, mut wrong, mut timeouts) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut any_held, mut max_held, mut refusing, mut max_staged) = (0u64, 0usize, 0u64, 0usize);
    let mut bad = Vec::new();
    for seed in start..start + n {
        let o = run_seed(seed, writers, shared);
        sets += o.sets;
        if o.max_held > 0 {
            any_held += 1;
        }
        max_held = max_held.max(o.max_held);
        max_staged = max_staged.max(o.max_staged);
        if o.reports > 0 {
            refusing += 1;
        }
        rej_sets += o.sets_rejected;
        if o.sets_rejected > 0 {
            seeds_rej += 1;
        }
        if o.stalled {
            stalls += 1;
        }
        if o.wrong {
            wrong += 1;
        }
        if o.timeouts > 0 {
            timeouts += 1;
        }
        if std::env::var_os("HDDS_M3_TRACE").is_some()
            || o.sets_rejected > 0
            || o.stalled
            || o.wrong
        {
            eprintln!("{}", o.summary);
        }
        if o.sets_rejected > 0 || o.stalled || o.wrong {
            bad.push(seed);
        }
    }
    eprintln!(
        "M3 REALISTIC writers={writers:?} shared={shared:?}: {n} seeds, {sets} sets; \
         {seeds_rej} seeds with >=1 set rejected whole ({rej_sets} sets rejected), \
         {stalls} permanent stalls, {wrong} wrong deliveries, {timeouts} seeds with a TIMEOUT; {any_held} seeds with heap-tier holds (max {max_held} B of share 4194304), {refusing} seeds with any SAMPLE_REJECTED report (unacked refusals included), staged at most {max_staged} B"
    );
    assert!(
        bad.is_empty(),
        "seeds with a rejection/stall/wrong delivery: {bad:?}"
    );
}

#[test]
#[ignore = "seed sweep: HDDS_M3_SEEDS"]
fn m3_realistic_sweep() {
    sweep(None, None);
}

#[test]
#[ignore = "seed sweep: HDDS_M3_SEEDS"]
fn m3_realistic_sweep_4_writers_shared() {
    sweep(Some(4), Some(true));
}

#[test]
#[ignore = "one seed: HDDS_M3_SEED"]
fn m3_realistic_one_seed() {
    let seed = std::env::var("HDDS_M3_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let o = run_seed(seed, None, None);
    eprintln!("{}", o.summary);
}
