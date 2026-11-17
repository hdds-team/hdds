// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Model-based schedules of the memory a RELIABLE pair takes: real writer
//! histories (`HistoryCache`, the writer's claim on the slab pool) and a
//! real reader (`ReaderSubscriber` with its history room, reorder gate,
//! acknowledgement state and coherent staging budget), joined by a
//! simulated network.
//!
//! Each seed draws, deterministically (xorshift64*): whether the writers
//! and the reader share one pool (one process) or the reader has its own
//! (two processes), the pool's heap tier (in samples) and the readers'
//! share of it (`reader_reserve_percent`: 1, 25, 50 or 93, the ends of the
//! accepted range among them), whether the reader has coherent access
//! (TOPIC scope) and, if so, how many samples a set may stage (`N` of
//! `staging_budget`: the default, or a tight 3, 8 or 32), one to four
//! writers, each KEEP_ALL or KEEP_LAST (depth 4, 16 or 64: it gives up an
//! unacknowledged sample, a loss its reader reports), each writing coherent
//! sets when the reader is coherent (mostly of one to six samples, in a
//! quarter of the runs up to 300), how many samples each writes, and a
//! schedule of steps: writes (a write the pool refuses is retried; refused
//! for `TIMEOUT_STEPS` steps in a row, it is a TIMEOUT the application
//! writes again), deliveries in or out of order, losses, duplicates, stalls
//! of the reader's receive pipeline (during which the socket buffer
//! overflows), stalls of the application's take, and HEARTBEATs answered by
//! the reader, after which a writer gives up what is acknowledged and
//! repairs what is asked. A drain follows, as a network would end: no loss,
//! no stall, until everything is written, acknowledged and taken.
//!
//! Samples are over the largest size class, so they live in the heap tier,
//! whose gauge then tells exactly what each side stores.
//!
//! What it checks:
//! 1. at every step, `heap_bytes_used` within `max_heap_bytes`, but for
//!    one sample past it in the reader's pool (the head of a gap,
//!    `rt::Claim::Head`), and the reader's staging gauge within its budget:
//!    a set's limit `L` for the sets above a gap, and `L` for each writer's
//!    set in order;
//! 2. at every acknowledgement, the samples of no set acknowledged and not
//!    yet taken are all in the reader's storage: no ACK without reserved
//!    storage (a KEEP_LAST writer's sample it gave up aside);
//! 3. a burst whose writers' and reader's storage fits under the writers'
//!    part of the pool is written without a single TIMEOUT;
//! 4. never a permanent stall: the drain ends with every sample written,
//!    acknowledged, delivered at most once and in order per writer, nothing
//!    left held or staged;
//! 5. no unreported loss: a coherent set is delivered whole or not at all;
//!    one not delivered is larger than a set may stage (rejected whole,
//!    each sample reported SAMPLE_REJECTED) or lost a sample its KEEP_LAST
//!    writer gave up; every sample not delivered and of no rejected set is
//!    one a KEEP_LAST writer gave up, and is reported SAMPLE_LOST.

use super::admission::HistoryRoom;
use crate::core::reader::{HeartbeatSeen, ReaderAckCredit, ReaderProxyRegistry};
use crate::core::rt;
use crate::engine::Subscriber as _;
use crate::reliability::HistoryCache;
use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

/// Where each writer's sequences start: writer `w` writes `w * BASE + 1..`.
const BASE: u64 = 10_000;

/// Over the largest primary class (128 KiB), once encoded: heap tier only.
const BODY: usize = 132_000;

/// A write refused this many steps in a row times out.
const TIMEOUT_STEPS: u32 = 40;

/// Datagrams the socket buffer holds while the receive pipeline stalls.
const SOCKET: usize = 12;

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Big {
    id: i32,
    body: Vec<u8>,
}

/// xorshift64*: deterministic, no dependency.
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

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

fn encoded(seq: u64) -> Vec<u8> {
    let sample = Big {
        id: i32::try_from(seq).expect("small"),
        body: vec![0x3C; BODY],
    };
    let mut bytes = vec![0u8; BODY + 1024];
    let len = crate::dds::DDS::encode(&sample, &mut bytes, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    bytes.truncate(len);
    bytes
}

/// A pool the run owns: the accessors a run switches between hand out
/// `&'static`, which the owner bounds (it is the last field of the run).
fn owned_pool(policy: &crate::qos::MemoryPolicy) -> rt::TestOwned<Arc<rt::SlabPool>> {
    rt::TestOwned::new(Arc::new(rt::SlabPool::with_policy(policy)))
}

fn heap_used(pool: &rt::SlabPool) -> usize {
    pool.metrics().heap_bytes_used.load(Ordering::Acquire)
}

/// The SAMPLE_REJECTED status a subscriber reports into.
type Rejected = Arc<Mutex<crate::dds::listener::SampleRejectedStatus>>;

/// A reliable KEEP_ALL network subscriber behind a VOLATILE gate, crediting
/// `credit`, with a history of `places`, TOPIC-scope coherent access when
/// `coherent`, staging sets of at most `staging` samples.
fn subscriber(
    credit: &ReaderAckCredit,
    places: usize,
    coherent: bool,
    staging: usize,
    rejected: &Rejected,
) -> (Arc<rt::IndexRing>, super::subscriber::ReaderSubscriber<Big>) {
    let ring = Arc::new(rt::IndexRing::with_capacity(places + 1));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let mut sub = super::subscriber::ReaderSubscriber::<Big>::new_with_coherent(
        "m".to_string(),
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
    sub.room = Some(HistoryRoom::new(
        &ring,
        crate::reliability::LENGTH_UNLIMITED,
    ));
    sub.staging = super::staging_budget::StagingBudget::new(staging);
    sub.register_match_entry_for_test(crate::dds::QoS::reliable().keep_all());
    (ring, sub)
}

/// One writer of a run: its history and what the reader acknowledged of
/// it. Its sequences are `base + 1..=base + total`, so that the reader's
/// ring tells the writers' samples apart.
struct Side {
    guid: [u8; 16],
    base: u64,
    cache: HistoryCache,
    /// KEEP_LAST depth, `None` for KEEP_ALL.
    keep_last: Option<usize>,
    /// For each of its sequences (index `seq - base - 1`), the first
    /// sequence of its coherent set, if it is a set's.
    set_of: Vec<Option<u64>>,
    total: u64,
    /// Next sequence to write, relative (1-based).
    next_write: u64,
    refused_in_a_row: u32,
    heartbeats: u32,
    /// Highest sequence acknowledged contiguously (`base - 1`), absolute.
    acked_through: u64,
    /// Sequences its KEEP_LAST history gave up before they were
    /// acknowledged.
    given_up: BTreeSet<u64>,
}

impl Side {
    fn set_of(&self, seq: u64) -> Option<u64> {
        self.set_of[(seq - self.base - 1) as usize]
    }

    fn last(&self) -> u64 {
        self.base + self.total
    }

    fn owns(&self, seq: u64) -> bool {
        seq > self.base && seq <= self.last()
    }
}

/// The sets of one writer of `total` samples from `base`: the first sample
/// joins the gate, the last closes the last set (samples of no set); sets
/// of one to six between them, of up to 300 when `large`.
fn draw_sets(
    rng: &mut Rng,
    base: u64,
    total: u64,
    coherent: bool,
    large: bool,
) -> Vec<Option<u64>> {
    let mut set_of = vec![None; total as usize];
    if coherent {
        let mut seq = 2u64;
        while seq < total {
            if rng.chance(40) {
                let len = if large && rng.chance(15) {
                    7 + rng.below(294)
                } else {
                    1 + rng.below(6)
                };
                let len = len.min(total - seq);
                for member in seq..seq + len {
                    set_of[(member - 1) as usize] = Some(base + seq);
                }
                seq += len;
            } else {
                seq += 1;
            }
        }
    }
    set_of
}

/// One seed's run.
struct Run {
    seed: u64,
    shared: bool,
    reader_pool: &'static Arc<rt::SlabPool>,
    writer_pool: &'static Arc<rt::SlabPool>,
    max_heap: usize,
    writer_ceiling: usize,
    credit: ReaderAckCredit,
    ring: Arc<rt::IndexRing>,
    sub: super::subscriber::ReaderSubscriber<Big>,
    rejected: Rejected,
    coherent: bool,
    staging: usize,
    sides: Vec<Side>,
    /// Encoded length of every sample (the writer stores it), and of the
    /// reader's stored form (a 16-byte writer GUID before it).
    writer_len: usize,
    reader_len: usize,
    timeouts: u32,
    net: VecDeque<(usize, u64)>,
    receive_stalled: u32,
    take_stalled: u32,
    /// Samples of sets rejected whole, samples lost, and samples of sets
    /// both too large and broken, which either report may tell.
    rejected_samples: u64,
    lost_samples: u64,
    either_samples: u64,
    delivered: Vec<u64>,
    violations: Vec<String>,
    /// The pools `reader_pool` and `writer_pool` point into, freed with the
    /// run: declared last so everything holding the pools drops first.
    _reader_owner: rt::TestOwned<Arc<rt::SlabPool>>,
    _writer_owner: Option<rt::TestOwned<Arc<rt::SlabPool>>>,
}

impl Run {
    /// `tight_sets`: a coherent run's history may have few places (see
    /// `memory_model_sets_in_a_tight_history`).
    fn new(seed: u64, rng: &mut Rng, tight_sets: bool) -> Self {
        let shared = rng.chance(50);
        let writer_len = encoded(1).len();
        let reader_len = writer_len + 16;
        // The heap tier, in samples: room for a handful to a few dozen.
        let samples_of_heap = 4 + rng.below(40) as usize;
        let max_heap = samples_of_heap * reader_len + rng.below(reader_len as u64) as usize;
        let policy = crate::qos::MemoryPolicy {
            max_heap_bytes: max_heap,
            reader_reserve_percent: [1u8, 25, 25, 50, 93][rng.below(5) as usize],
            ..crate::qos::MemoryPolicy::default()
        };
        assert!(policy.check_reader_reserve_percent().is_ok());
        let mut policy = policy;
        // A share that leaves writers' part of the heap tier no room for one
        // sample makes every write of it fail (TIMEOUT), by configuration:
        // drawn again as the default.
        if max_heap - max_heap * usize::from(policy.reader_reserve_percent) / 100 < writer_len {
            policy.reader_reserve_percent = 25;
        }
        let percent = usize::from(policy.reader_reserve_percent);
        let share = max_heap * percent / 100;
        let writer_ceiling = max_heap - share;
        let reader_owner = owned_pool(&policy);
        let reader_pool = reader_owner.get();
        let writer_owner = (!shared).then(|| owned_pool(&policy));
        let writer_pool = writer_owner
            .as_ref()
            .map_or(reader_pool, |owner| owner.get());
        let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
        let places = [15usize, 63, 255][rng.below(3) as usize];
        let coherent = rng.chance(50);
        let places = if coherent && !tight_sets { 255 } else { places };
        let staging = [
            super::subscriber::MAX_STAGED_PER_WRITER,
            super::subscriber::MAX_STAGED_PER_WRITER,
            3,
            8,
            32,
        ][rng.below(5) as usize];
        let rejected: Rejected = Arc::default();
        let (ring, sub) = subscriber(&credit, places, coherent, staging, &rejected);
        let writers = 1 + rng.below(4);
        let large = coherent && rng.chance(25);
        let mut sides = Vec::new();
        for w in 0..writers {
            let guid = [0x6D + w as u8; 16];
            credit.match_writer(guid);
            let base = w * BASE;
            let total = if large {
                1 + rng.below(700)
            } else {
                1 + rng.below(120)
            };
            let keep_last = rng
                .chance(30)
                .then(|| [4usize, 16, 64][rng.below(3) as usize]);
            let history = keep_last.map_or(crate::qos::History::KeepAll, |depth| {
                crate::qos::History::KeepLast(u32::try_from(depth).expect("small"))
            });
            let cache = HistoryCache::new_with_limits(
                Arc::clone(writer_pool),
                crate::reliability::LENGTH_UNLIMITED,
                usize::MAX,
                history,
            );
            // A VOLATILE RELIABLE writer's history: what is acknowledged
            // goes.
            cache.set_release_policy(true, false);
            let set_of = draw_sets(rng, base, total, coherent, large);
            sides.push(Side {
                guid,
                base,
                cache,
                keep_last,
                total: set_of.len() as u64,
                set_of,
                next_write: 1,
                refused_in_a_row: 0,
                heartbeats: 0,
                acked_through: base,
                given_up: BTreeSet::new(),
            });
        }
        Self {
            seed,
            shared,
            reader_pool,
            writer_pool,
            _reader_owner: reader_owner,
            _writer_owner: writer_owner,
            max_heap,
            writer_ceiling,
            credit,
            ring,
            sub,
            rejected,
            coherent,
            staging,
            sides,
            writer_len,
            reader_len,
            timeouts: 0,
            net: VecDeque::new(),
            receive_stalled: 0,
            take_stalled: 0,
            rejected_samples: 0,
            lost_samples: 0,
            either_samples: 0,
            delivered: Vec::new(),
            violations: Vec::new(),
        }
    }

    fn violation(&mut self, what: String) {
        if self.violations.len() < 8 {
            self.violations.push(what);
        }
    }

    /// The application writes the next sample of writer `w`, if any is
    /// left.
    fn write_side(&mut self, w: usize, rng: &mut Rng, lossy: bool) {
        let side = &mut self.sides[w];
        if side.next_write > side.total {
            return;
        }
        let seq = side.base + side.next_write;
        let _pool_guard = rt::private_slab_pool_for_test(self.writer_pool);
        let oldest = side.cache.oldest_seq();
        match side.cache.insert(seq, &encoded(seq)) {
            Ok(()) => {
                side.next_write += 1;
                side.refused_in_a_row = 0;
                // What a KEEP_LAST history gave up for it, unacknowledged.
                if let (Some(_), Some(from)) = (side.keep_last, oldest) {
                    let to = side.cache.oldest_seq().unwrap_or(seq);
                    let through = side.acked_through;
                    side.given_up.extend((from..to).filter(|&s| s > through));
                }
                if seq == side.base + 1 {
                    // The VOLATILE reader's join point: it arrives first
                    // (one arriving later would be history from before
                    // the join).
                    self.receive(w, seq);
                } else if !lossy || !rng.chance(15) {
                    self.send(w, seq);
                }
            }
            Err(_) => {
                side.refused_in_a_row += 1;
                if side.refused_in_a_row >= TIMEOUT_STEPS {
                    // TIMEOUT: nothing of it remains; the application
                    // writes it again.
                    self.timeouts += 1;
                    side.refused_in_a_row = 0;
                }
            }
        }
    }

    fn pick(&mut self, rng: &mut Rng) -> usize {
        rng.below(self.sides.len() as u64) as usize
    }

    fn write(&mut self, rng: &mut Rng, lossy: bool) {
        let w = self.pick(rng);
        self.write_side(w, rng, lossy);
    }

    /// A datagram on its way; dropped when the socket buffer is full while
    /// the receive pipeline stalls. A repair of a sample already on its way
    /// is not sent again (a writer coalesces the repairs it is asked for).
    fn send(&mut self, w: usize, seq: u64) {
        if self.receive_stalled > 0 && self.net.len() >= SOCKET {
            return;
        }
        if !self.net.contains(&(w, seq)) {
            self.net.push_back((w, seq));
        }
    }

    fn deliver(&mut self, rng: &mut Rng, lossy: bool) {
        if self.receive_stalled > 0 || self.net.is_empty() {
            return;
        }
        let at = if lossy && rng.chance(20) {
            rng.below(self.net.len() as u64) as usize
        } else {
            0
        };
        let Some((w, seq)) = self.net.remove(at) else {
            return;
        };
        if lossy && rng.chance(5) {
            self.net.push_back((w, seq));
        }
        self.receive(w, seq);
    }

    /// The reader receives writer `w`'s `seq`.
    fn receive(&mut self, w: usize, seq: u64) {
        let _pool_guard = rt::private_slab_pool_for_test(self.reader_pool);
        let side = &self.sides[w];
        match side.set_of(seq) {
            Some(start) => self.sub.on_data_coherent(
                "m",
                side.guid,
                seq,
                &encoded(seq),
                crate::dds::CdrVersion::Xcdr2,
                Some(start),
                None,
                None,
            ),
            None => self.sub.on_data_with_writer(
                "m",
                side.guid,
                seq,
                &encoded(seq),
                crate::dds::CdrVersion::Xcdr2,
            ),
        }
    }

    fn take(&mut self) {
        if self.take_stalled > 0 {
            return;
        }
        let _pool_guard = rt::private_slab_pool_for_test(self.reader_pool);
        while let Some(entry) = self.ring.pop() {
            self.delivered.push(u64::from(entry.seq));
            self.reader_pool.release(entry.handle);
            drop(self.sub.room.as_ref().map(HistoryRoom::adopt));
        }
    }

    /// How many samples the reader stores in the heap tier, read off its
    /// gauge (staged samples are stored apart, `staged_heap_bytes`).
    fn reader_stored(&self) -> usize {
        let reader_bytes = if self.shared {
            let history: usize = self.sides.iter().map(|s| s.cache.len()).sum();
            heap_used(self.reader_pool).saturating_sub(history * self.writer_len)
        } else {
            heap_used(self.reader_pool)
        };
        reader_bytes / self.reader_len
    }

    fn heartbeat(&mut self, lossy: bool, rng: &mut Rng) {
        let w = self.pick(rng);
        let Some(last) = self.sides[w].cache.newest_seq() else {
            return;
        };
        let first = self.sides[w].cache.oldest_seq().unwrap_or(last);
        self.sides[w].heartbeats += 1;
        let guid = self.sides[w].guid;
        let answer = self.credit.answer_heartbeat(
            &guid,
            &HeartbeatSeen {
                first_seq: i64::try_from(first).expect("small"),
                last_seq: i64::try_from(last).expect("small"),
                count: self.sides[w].heartbeats,
                final_flag: false,
            },
        );
        let Some(answer) = answer else {
            self.violation("no answer from a matched reader".to_string());
            return;
        };
        // Invariant 2: everything acknowledged and not yet taken is in the
        // reader's storage.
        let side = &self.sides[w];
        let acked: Vec<u64> = (side.base + 1..=last)
            .filter(|&s| s < answer.bitmap_base || !answer.missing.contains(&s))
            .collect();
        let taken: BTreeSet<u64> = self.delivered.iter().copied().collect();
        let owed = acked
            .iter()
            .filter(|&&s| {
                !taken.contains(&s) && side.set_of(s).is_none() && !side.given_up.contains(&s)
            })
            .count();
        let stored = self.reader_stored();
        if owed > stored {
            self.violation(format!(
                "{owed} samples acknowledged and not taken, {stored} stored"
            ));
        }
        self.sides[w].acked_through = answer.bitmap_base.saturating_sub(1);
        {
            // What the HEARTBEAT tells the reader's subscriber (a set waiting
            // for the gap below it to be known commits then).
            let _pool_guard = rt::private_slab_pool_for_test(self.reader_pool);
            self.sub.on_writer_heartbeat_range(guid, first, last);
        }
        let _pool_guard = rt::private_slab_pool_for_test(self.writer_pool);
        let acked_through = self.sides[w].acked_through;
        self.sides[w].cache.remove_acknowledged(acked_through);
        for seq in answer.missing {
            if self.sides[w].cache.get(seq).is_some() && (!lossy || !rng.chance(15)) {
                self.send(w, seq);
            }
        }
    }

    /// Invariant 1, after every step: the reader's pool may be past its
    /// ceiling by one sample, the head of a gap (`rt::Claim::Head`), the
    /// writers' alone never; the reader's staging within its budget.
    fn check_ceilings(&mut self, step: &str) {
        let writer_ceiling = if self.shared {
            self.max_heap + self.reader_len
        } else {
            self.max_heap
        };
        for (name, pool, ceiling) in [
            ("reader", self.reader_pool, self.max_heap + self.reader_len),
            ("writer", self.writer_pool, writer_ceiling),
        ] {
            let used = heap_used(pool);
            if used > ceiling {
                self.violation(format!(
                    "{step}: {name} pool heap tier at {used}, over {ceiling}"
                ));
            }
        }
        // L for each set in order, one per writer at most, and L for the
        // sets above a gap.
        let staging = &self.sub.staging;
        let (staged, others, limit) = (staging.used(), staging.others(), staging.set_limit());
        let budget = limit * (1 + self.sides.len());
        if staged > budget || others > limit || staged > staging.budget() {
            self.violation(format!(
                "{step}: the reader stages {staged} ({others} above a gap), over its budget \
                 {budget} ({limit} a set)"
            ));
        }
    }

    fn step(&mut self, rng: &mut Rng, lossy: bool) {
        self.receive_stalled = self.receive_stalled.saturating_sub(1);
        self.take_stalled = self.take_stalled.saturating_sub(1);
        match rng.below(100) {
            0..=29 => self.write(rng, lossy),
            30..=64 => self.deliver(rng, lossy),
            65..=79 => self.take(),
            80..=91 => self.heartbeat(lossy, rng),
            92..=95 if lossy => self.receive_stalled = 1 + rng.below(60) as u32,
            96..=99 if lossy => self.take_stalled = 1 + rng.below(400) as u32,
            _ => self.deliver(rng, lossy),
        }
        self.check_ceilings("step");
    }

    /// Everything written and acknowledged, and each writer's last sample
    /// (of no set) delivered: every set before it committed, rejected or
    /// lost.
    fn done(&self) -> bool {
        self.sides.iter().all(|side| {
            side.next_write > side.total
                && side.acked_through >= side.last()
                && self.delivered.contains(&side.last())
        })
    }

    /// Invariant 5 for writer `w`, once done: what it delivered is in order,
    /// each set whole or absent, and each absence explained. Counts the
    /// samples of sets rejected whole and the samples lost.
    fn check_writer(&mut self, w: usize) {
        let delivered: Vec<u64> = self
            .delivered
            .iter()
            .copied()
            .filter(|&s| self.sides[w].owns(s))
            .collect();
        if delivered.windows(2).any(|p| p[0] >= p[1]) {
            let first = delivered
                .windows(2)
                .find(|p| p[0] >= p[1])
                .map(|p| (p[0], p[1]));
            self.violation(format!("writer {w}: out of order or twice: {first:?}"));
        }
        let got: BTreeSet<u64> = delivered.into_iter().collect();
        // What one set may take of the reader's staging budget: a set is
        // rejected whole if and only if it is larger (all samples here have
        // one size, so that `N` is the bound). `L` follows the sets staged
        // now (none, once done): `N` samples of the one size.
        let limit = self
            .staging
            .clamp(1, super::subscriber::MAX_STAGED_PER_WRITER)
            * self.reader_len;
        let mut found = Vec::new();
        let side = &self.sides[w];
        let mut seq = side.base + 1;
        while seq <= side.last() {
            let Some(start) = side.set_of(seq) else {
                if !got.contains(&seq) {
                    if side.given_up.contains(&seq) {
                        self.lost_samples += 1;
                    } else {
                        found.push(format!("writer {w}: {seq}, of no set, never delivered"));
                    }
                }
                seq += 1;
                continue;
            };
            let members: Vec<u64> = (seq..=side.last())
                .take_while(|&m| side.set_of(m) == Some(start))
                .collect();
            let n = members.len() as u64;
            let have = members.iter().filter(|m| got.contains(m)).count();
            // (Or than the history's places, which a tight history may
            // have fewer of: `HistoryRoom::never_holds`.)
            let larger = members.len() > self.staging
                || members.len() * self.reader_len > limit
                || members.len() > self.ring.usable_capacity();
            // Broken: a member given up, or the sample after it, which tells
            // where it ends (the reader cannot tell a lost member from a
            // lost close).
            let after = members.last().map_or(seq, |&m| m + 1);
            let broken =
                members.iter().any(|m| side.given_up.contains(m)) || side.given_up.contains(&after);
            if have == members.len() {
                if larger {
                    found.push(format!(
                        "writer {w}: set {start}+{n} larger than a set may stage delivered"
                    ));
                }
            } else if have != 0 {
                found.push(format!("writer {w}: set {start}+{n} delivered in part"));
            } else if larger && broken {
                self.either_samples += n;
            } else if larger {
                self.rejected_samples += n;
            } else if broken {
                self.lost_samples += n;
            } else {
                found.push(format!(
                    "writer {w}: set {start}+{n} not delivered, neither too large nor broken"
                ));
            }
            seq += n;
        }
        for what in found {
            self.violation(what);
        }
    }

    fn run(mut self, rng: &mut Rng) -> (Vec<String>, String) {
        // The under-ceiling burst: the writers' histories and the reader's
        // storage of every sample fit in the writers' part of the pool
        // (shared), or the histories alone do (separate pools).
        let all: usize = self.sides.iter().map(|s| s.total as usize).sum();
        let fits = if self.shared {
            all * (self.writer_len + self.reader_len) <= self.writer_ceiling
        } else {
            all * self.writer_len <= self.writer_ceiling
        };
        // Each writer's first sample is the VOLATILE reader's join point,
        // received as it is written (`write_side`).
        for w in 0..self.sides.len() {
            self.write_side(w, rng, false);
        }
        let schedule = 200 + rng.below(1500);
        for _ in 0..schedule {
            self.step(rng, true);
        }
        let mut drain = 0u64;
        while !self.done() && drain < 200_000 {
            self.receive_stalled = 0;
            self.take_stalled = 0;
            self.step(rng, false);
            drain += 1;
        }
        let done = self.done();
        if done {
            for w in 0..self.sides.len() {
                self.check_writer(w);
            }
        }
        let summary = format!(
            "seed {} shared={} heap={}x share={}x coherent={} staging={} writers={} keep_last={:?} \
             places={} total={} written={} acked={} delivered={} rejected_whole={} lost={} \
             timeouts={} drain={drain}",
            self.seed,
            self.shared,
            self.max_heap / self.reader_len,
            (self.max_heap - self.writer_ceiling) / self.reader_len,
            self.coherent,
            self.staging,
            self.sides.len(),
            self.sides.iter().map(|s| s.keep_last).collect::<Vec<_>>(),
            self.ring.usable_capacity(),
            self.sides.iter().map(|s| s.total).sum::<u64>(),
            self.sides.iter().map(|s| s.next_write - 1).sum::<u64>(),
            self.sides
                .iter()
                .map(|s| s.acked_through - s.base)
                .sum::<u64>(),
            self.delivered.len(),
            self.rejected_samples,
            self.lost_samples,
            self.timeouts,
        );
        // Invariant 4.
        if !done {
            let state = format!(
                "permanent stall: written {} of {}, acknowledged through {:?}, delivered {}, \
                 history {}, reader stores {}, stages {}",
                self.sides.iter().map(|s| s.next_write - 1).sum::<u64>(),
                self.sides.iter().map(|s| s.total).sum::<u64>(),
                self.sides
                    .iter()
                    .map(|s| s.acked_through)
                    .collect::<Vec<_>>(),
                self.delivered.len(),
                self.sides.iter().map(|s| s.cache.len()).sum::<usize>(),
                self.reader_stored(),
                self.sub.staging.used(),
            );
            self.violation(state);
        } else {
            // Invariant 5: every loss reported.
            let reported = u64::from(self.rejected.lock().expect("status").total_count);
            if reported < self.rejected_samples {
                self.violation(format!(
                    "{} samples of sets rejected whole, {reported} reported",
                    self.rejected_samples
                ));
            }
            let lost = u64::from(self.sub.sample_lost.lock().expect("status").total_count);
            if lost < self.lost_samples {
                self.violation(format!(
                    "{} samples lost, {lost} reported",
                    self.lost_samples
                ));
            }
            let all = self.rejected_samples + self.lost_samples + self.either_samples;
            if reported + lost < all {
                self.violation(format!(
                    "{all} samples rejected or lost, {} reported",
                    reported + lost
                ));
            }
            let held = self
                .reader_pool
                .metrics()
                .held_heap_bytes
                .load(Ordering::Acquire);
            let staged = self.sub.staging.used();
            if held != 0 || staged != 0 {
                self.violation(format!(
                    "{held} bytes still held, {staged} staged once everything is taken"
                ));
            }
        }
        // Invariant 3.
        if fits && self.timeouts != 0 {
            self.violation(format!(
                "a burst under the writers' ceiling timed out {} times",
                self.timeouts
            ));
        }
        (self.violations, summary)
    }
}

fn run_seed(seed: u64) -> (Vec<String>, String) {
    run_seed_with(seed, false)
}

fn run_seed_with(seed: u64, tight_sets: bool) -> (Vec<String>, String) {
    let mut rng = Rng::new(seed);
    let run = Run::new(seed, &mut rng, tight_sets);
    run.run(&mut rng)
}

fn run_seeds(seeds: std::ops::Range<u64>) {
    run_seeds_with(seeds, false);
}

fn run_seeds_with(seeds: std::ops::Range<u64>, tight_sets: bool) {
    let mut failed = Vec::new();
    let (mut timed_out, mut shared, mut many, mut rejecting, mut losing, mut keep_last) =
        (0, 0, 0, 0, 0, 0);
    let count = seeds.end - seeds.start;
    for seed in seeds {
        let (violations, summary) = run_seed_with(seed, tight_sets);
        if std::env::var_os("HDDS_MODEL_TRACE").is_some() {
            eprintln!("{summary}");
        }
        if summary.contains("shared=true") {
            shared += 1;
        }
        if !summary.contains("timeouts=0 ") {
            timed_out += 1;
        }
        if !summary.contains("writers=1 ") {
            many += 1;
        }
        if summary.contains("Some(") {
            keep_last += 1;
        }
        if !summary.contains("rejected_whole=0 ") {
            rejecting += 1;
        }
        if !summary.contains(" lost=0 ") {
            losing += 1;
        }
        if !violations.is_empty() {
            failed.push(format!("{summary}\n    {}", violations.join("\n    ")));
        }
    }
    eprintln!(
        "memory model: {count} seeds, {shared} with one shared pool, {many} with several writers, \
         {keep_last} with a KEEP_LAST writer, {rejecting} rejecting a set whole, {losing} losing \
         samples, {timed_out} with a TIMEOUT"
    );
    assert!(
        failed.is_empty(),
        "{} of {count} seeds violate the memory invariants:\n{}",
        failed.len(),
        failed.join("\n")
    );
}

#[test]
fn memory_model_schedules() {
    run_seeds(0..48);
}

#[test]
#[ignore = "long: HDDS_MODEL_SEEDS seeds (default 2000), HDDS_MODEL_TIGHT for tight draws"]
fn memory_model_schedules_long() {
    let n = std::env::var("HDDS_MODEL_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000u64);
    let start = std::env::var("HDDS_MODEL_START")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000u64);
    run_seeds_with(
        start..start + n,
        std::env::var_os("HDDS_MODEL_TIGHT").is_some(),
    );
}

#[test]
#[ignore = "one seed: HDDS_MODEL_SEED"]
fn memory_model_one_seed() {
    let seed = std::env::var("HDDS_MODEL_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let _ = env_logger::builder().is_test(true).try_init();
    let (violations, summary) = run_seed(seed);
    eprintln!("{summary}");
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// A sample of no set delivered ahead of the coherent set before it: out
/// of order, DDS v1.4 Sec.2.2.3.14. A reorder-gate property, not a memory
/// one: the set's members are acknowledged when staged, so the
/// writer purges them (or, KEEP_LAST, gives them up) and its next
/// HEARTBEAT's firstSN is above them; the gate's fast-forward
/// (`ReorderGate::on_heartbeat`, "history purged") would move its base past
/// sequences that were staged, not lost, and release the sample of no set
/// above them; the set, committed later, would be released by `on_staged`
/// below the base, after it. The gate therefore keeps a staged change's
/// place (`ReorderGate::hold_staged`). The seeds that pin it: a coherent set
/// that waits for places (a history of few places: 6, 37 and 64 of the
/// tight draws, KEEP_ALL writers only) or for its end (12527 and 25323 of
/// the schedules, KEEP_LAST writers).
#[test]
fn memory_model_the_gate_keeps_staged_places() {
    let mut failed = Vec::new();
    for (seed, tight) in [
        (6, true),
        (37, true),
        (64, true),
        (12527, false),
        (25323, false),
    ] {
        let (violations, summary) = run_seed_with(seed, tight);
        if !violations.is_empty() {
            failed.push(format!("{summary}\n    {}", violations.join("\n    ")));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

/// A KEEP_LAST writer's purge crosses changes that never arrived while the
/// gate waits below at a staged place (recorded irrelevant); a delayed copy
/// of one arrives after all and the gate holds it, yet it stayed recorded
/// as crossed. A set's member staged so: the gate's count of the places it
/// owes left it out, the writer's later sets took every place of a history
/// of 15, and the set waited for places for good (seed 30927 of the tight
/// draws, a permanent stall), or the gate crossed the held place and
/// released what followed first (27655, out of order). A DATA of no set
/// held so: the gate jumped over it and released it below the base, after
/// what followed it (18965, out of order). A sequence the gate crosses
/// ahead is now final, as one below the base: a late copy is refused its
/// place (`ReorderGate::hold_staged`) or dropped (`ReorderGate::on_data`),
/// reported lost once (it was given up by its KEEP_LAST writer).
#[test]
fn memory_model_a_late_copy_of_a_crossed_sequence_keeps_order() {
    let mut failed = Vec::new();
    for seed in [18965, 27655, 30927] {
        let (violations, summary) = run_seed_with(seed, true);
        if !violations.is_empty() {
            failed.push(format!("{summary}\n    {}", violations.join("\n    ")));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

#[test]
#[ignore = "seed sweep: HDDS_VR_SEEDS comma list, tight draws"]
fn memory_model_vr_seeds() {
    let seeds: Vec<u64> = std::env::var("HDDS_VR_SEEDS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.parse().ok())
        .collect();
    for seed in seeds {
        let (violations, summary) = run_seed_with(seed, true);
        eprintln!("VR {summary}\n    {}", violations.join("\n    "));
    }
}
