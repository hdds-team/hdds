// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The liveliness scheduler's state, with no thread and no clock of its
//! own: every operation is told what time it is.
//!
//! A remote writer whose lease this participant watches is a `Watch`: the
//! [`Renewal`] that asserts it (its participant's traffic for AUTOMATIC,
//! DDS v1.4 Sec.2.2.3.11), its lease, whether it is alive. The heap holds
//! one entry per alive watch, `(deadline, key, generation)`: a fired entry
//! re-reads the renewal and is re-armed or declares the writer not alive;
//! an entry of an older generation is ignored. An infinite lease has no
//! entry. A writer not alive has none either: what makes it alive again is
//! a renewal, which reports itself (`resumed`).
//!
//! The renewal path never decides anything. It stores the instant it was
//! renewed, and when the previous renewal is at least the shortest lease
//! that depends on it in the past, it reports both instants (`resumed`):
//! the one point where a writer that expired and resumed before its entry
//! fired is still recorded not alive, then alive. A scheduler that runs
//! late therefore loses no transition.
//!
//! The same heap times this participant's own assertion: one entry
//! (`SEND_KEY`) every third of the shortest finite AUTOMATIC lease among
//! its writers (RTPS v2.5 Sec.8.4.13.5, Sec.8.7.2.2).
//!
//! The same heap also carries DEADLINE watches (`super::deadline`, DDS
//! v1.4 Sec.2.2.3.7): one entry per instance, in `deadlines` rather than
//! `watches` (a disjoint `WatchKey` range, drawn from the same counter) --
//! unlike a LIVELINESS `Watch`'s one-shot not-alive, a fired DEADLINE
//! entry is always re-armed while it is watched (Sec.2.2.4.1: a missed
//! instance reports once per elapsed period, not once ever).
//!
//! The same heap also carries a reliable writer's periodic HEARTBEAT
//! (RTPS v2.5 Sec.8.4.7.2), one entry per writer in `heartbeats`: like a
//! DEADLINE entry, it is always re-armed while watched (unconditional,
//! no renewal to check), but it carries no RTPS knowledge of its own --
//! firing only clones a `Weak<dyn HeartbeatSink>` into the `Outcome`, the
//! writer side (`crate::dds::writer::heartbeat_scheduler`) builds and
//! sends the actual packet. `Core` never calls `HeartbeatSink::fire`
//! itself: the scheduler thread (`super::scheduler::deliver`) does, off
//! its own thread, so a send that blocks never holds up the heap.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use super::clock::{Nanos, INFINITE};
use super::deadline::{DeadlineSink, FilterWakeSink, InstanceDeadline};
use crate::dds::reader::InstanceHandle;

/// One watch (a remote writer of a local reader, or a local writer's own
/// lease), unique for the participant's life.
pub(crate) type WatchKey = u64;

/// The heap key of this participant's own AUTOMATIC assertion (RTPS v2.5
/// Sec.8.4.13.5): fires unconditionally, every period.
const SEND_KEY: WatchKey = 0;

/// The heap key of this participant's own MANUAL_BY_PARTICIPANT assertion
/// (RTPS v2.5 Sec.8.4.13.5): fires on the same period rule, but only
/// actually asserts when a writer of that kind acted since the last time
/// (`ManualSendTimer`).
const MANUAL_SEND_KEY: WatchKey = 1;

/// What a periodic HEARTBEAT watch (RTPS v2.5 Sec.8.4.7.2) fires: a
/// reliable writer. `fire` builds and sends its periodic HEARTBEAT; it
/// runs on a thread other than the scheduler's own (`super::scheduler::
/// deliver`), so it may do real I/O without holding up the heap. It is
/// never a user callback (RTPS wire traffic only, not an application
/// listener), unlike `LivelinessSink::transition` / `DeadlineSink::missed`,
/// which still go through the notice queue for that reason.
pub(crate) trait HeartbeatSink: Send + Sync {
    fn fire(&self);
}

/// A writer's single in-flight-or-queued HEARTBEAT slot: the admission
/// gate and deletion barrier (without it, dispatch would
/// queue one `Outcome::Heartbeat` per elapsed period with no bound and
/// no per-writer serialization, so a slow send would accumulate concurrent
/// fires of the same writer, and a writer's drop would not wait for a send
/// already handed to the sender). `true` means a job for this watch is
/// either sitting in the sender's queue or being run by it right now;
/// `Core::fire_heartbeat` only produces an `Outcome::Heartbeat` when it
/// can claim this (`try_begin`), so a tick that comes due while the
/// previous one is still in flight is coalesced -- skipped, not queued
/// -- rather than piling up. The sender clears it (`end`) once that run
/// returns, whether or not the sink was still there to fire.
pub(crate) struct HeartbeatPending {
    busy: Mutex<bool>,
    idle: Condvar,
}

impl HeartbeatPending {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            busy: Mutex::new(false),
            idle: Condvar::new(),
        })
    }

    /// Claims the slot for a new dispatch. `false` means one is already
    /// in flight or queued: the caller coalesces (produces no `Outcome`
    /// for this tick) instead of adding a second one.
    fn try_begin(&self) -> bool {
        let mut busy = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        if *busy {
            return false;
        }
        *busy = true;
        true
    }

    /// The sender calls this once a dispatched job has run (or been
    /// abandoned, `fire` never called): frees the slot for the next
    /// period's tick and wakes a writer drop waiting in [`wait_idle`].
    pub(crate) fn end(&self) {
        let mut busy = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        *busy = false;
        self.idle.notify_all();
    }

    /// A writer's deletion barrier (RTPS v2.5 Sec.8.4.7.2's periodic
    /// HEARTBEAT must not outlive the writer that sends it): waits,
    /// bounded, for any dispatch already queued or running for this
    /// watch to call [`end`]. `true`: idle before the bound; `false`: the
    /// caller gives up and proceeds anyway (same shape as
    /// `core::rt::shutdown::join_bounded`, which this mirrors for a
    /// condition instead of a thread handle).
    pub(crate) fn wait_idle(&self, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        let mut busy = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        while *busy {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let (guard, timeout) = self
                .idle
                .wait_timeout(busy, left)
                .unwrap_or_else(|e| e.into_inner());
            busy = guard;
            if timeout.timed_out() && *busy {
                return false;
            }
        }
        true
    }

    /// Tests only: whether the slot is currently claimed.
    #[cfg(test)]
    pub(crate) fn is_busy_for_test(&self) -> bool {
        *self.busy.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What is told a watch's transitions: the local reader.
pub(crate) trait LivelinessSink: Send + Sync {
    /// The writer of `key` became alive (`true`) or not alive (`false`).
    /// Returns the queue of application calls this filled, to be told on
    /// a thread other than the scheduler's.
    fn transition(
        &self,
        key: WatchKey,
        alive: bool,
    ) -> Option<Arc<crate::dds::reader::notices::Ordered>>;
}

/// When a source of liveliness assertions was last heard (the traffic of
/// a remote participant, its manual assertions, a writer's data), and the
/// shortest lease that depends on it.
pub(crate) struct Renewal {
    id: u64,
    last: AtomicU64,
    /// The shortest finite lease among the watches it asserts; INFINITE
    /// with none.
    threshold: AtomicU64,
}

impl Renewal {
    pub(crate) fn new(id: u64, now: Nanos) -> Self {
        Self {
            id,
            last: AtomicU64::new(now),
            threshold: AtomicU64::new(INFINITE),
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// Renewed at `now`. The previous renewal when it is at least the
    /// shortest dependent lease in the past (a writer may have expired
    /// since): the caller reports it (`Core::resumed`). Two relaxed
    /// accesses otherwise.
    #[inline]
    pub(crate) fn renew(&self, now: Nanos) -> Option<Nanos> {
        let old = self.last.fetch_max(now, Ordering::Relaxed);
        let threshold = self.threshold.load(Ordering::Relaxed);
        (threshold != INFINITE && now.saturating_sub(old) >= threshold).then_some(old)
    }

    pub(crate) fn last(&self) -> Nanos {
        self.last.load(Ordering::Relaxed)
    }
}

struct Watch {
    renewal: Arc<Renewal>,
    lease: Nanos,
    /// When the watch began, or last became alive: no renewal before it
    /// counts for it.
    since: Nanos,
    alive: bool,
    generation: u64,
    sink: Weak<dyn LivelinessSink>,
}

impl Watch {
    /// The instant this watch expires if nothing renews it after `last`.
    fn expiry(&self, last: Nanos) -> Nanos {
        last.max(self.since).saturating_add(self.lease)
    }
}

/// What the scheduler thread does once its lock is released.
pub(crate) enum Outcome {
    /// Tell `sink` the writer of `key` became alive or not alive.
    Transition {
        sink: Weak<dyn LivelinessSink>,
        key: WatchKey,
        alive: bool,
    },
    /// Assert this participant's AUTOMATIC liveliness on the wire.
    Send,
    /// Assert this participant's MANUAL_BY_PARTICIPANT liveliness on the
    /// wire: a writer of that kind acted since the last one.
    SendManual,
    /// Tell `sink` that `handle`'s TIME_BASED_FILTER window ended (DDS v1.4
    /// Sec.2.2.3.12): a parked sample is due to be shown.
    FilterWake {
        sink: Weak<dyn FilterWakeSink>,
        handle: InstanceHandle,
    },
    /// Tell `sink` that `handle`'s instance missed one DEADLINE period
    /// (DDS v1.4 Sec.2.2.3.7, Sec.2.2.4.1).
    DeadlineMissed {
        sink: Weak<dyn DeadlineSink>,
        handle: InstanceHandle,
    },
    /// A reliable writer's periodic HEARTBEAT period elapsed
    /// (RTPS v2.5 Sec.8.4.7.2): `sink` builds and sends it. Already
    /// admitted through `pending` (`HeartbeatPending::try_begin`): the
    /// dispatcher runs `sink.fire()` (or abandons it, sink gone) then
    /// calls `pending.end()`, exactly once, whichever happens.
    Heartbeat {
        sink: Weak<dyn HeartbeatSink>,
        pending: Arc<HeartbeatPending>,
    },
}

/// One instance's DEADLINE watch (`super::deadline`): `period` is the
/// reader's or writer's own QoS period, fixed for the watch's life (DEADLINE
/// is not re-evaluated on a later `set_qos`). `instance` is the hot-path cell the reader/writer touches on
/// every sample/write; this entry reads it, never writes it.
struct DeadlineWatch {
    instance: Arc<InstanceDeadline>,
    handle: InstanceHandle,
    period: Nanos,
    /// The next instant a miss is due, if `instance` is not touched past
    /// `next_due - period` first: starts at registration time plus one
    /// `period`, and on each reported miss advances by exactly one more
    /// `period` -- NEVER recomputed as `instance.last() + period`, which
    /// would stay the same forever while `instance` stays silent and
    /// loop the scheduler on this entry without end. A touch newer than
    /// what this already accounts for (`instance.last() + period >
    /// next_due`) jumps it forward instead (DDS v1.4 Sec.2.2.3.7: the
    /// period restarts from the last sample).
    next_due: Nanos,
    generation: u64,
    sink: Weak<dyn DeadlineSink>,
}

/// One writer's periodic HEARTBEAT watch (RTPS v2.5 Sec.8.4.7.2): `period`
/// is fixed for the watch's life (the default period -- QoS does not configure it). Always re-armed while watched,
/// unconditionally, like a DEADLINE entry and unlike a LIVELINESS `Watch`'s
/// one-shot expiry: a reliable writer with unacked data sends one of these
/// every period for as long as it exists.
struct HeartbeatWatch {
    sink: Weak<dyn HeartbeatSink>,
    period: Nanos,
    generation: u64,
    /// This watch's admission gate and deletion barrier, shared with the
    /// writer side through `watch_heartbeat`'s return value.
    pending: Arc<HeartbeatPending>,
}

struct SendTimer {
    period: Nanos,
    generation: u64,
}

/// The MANUAL_BY_PARTICIPANT send timer: like [`SendTimer`], but gated on
/// `renewal` (the participant-wide renewal every such writer's `write()`,
/// `assert_liveliness()`, dispose or unregister renews) having moved past
/// `last_sent` -- the "only when something happened since the last
/// check", unlike AUTOMATIC's unconditional period.
struct ManualSendTimer {
    period: Nanos,
    generation: u64,
    renewal: Arc<Renewal>,
    last_sent: Nanos,
}

#[derive(Default)]
pub(crate) struct Core {
    heap: BinaryHeap<Reverse<(Nanos, WatchKey, u64)>>,
    watches: HashMap<WatchKey, Watch>,
    /// Renewal id -> the watches it asserts.
    by_renewal: HashMap<u64, Vec<WatchKey>>,
    /// The finite AUTOMATIC leases of this participant's writers, by id.
    local_leases: BTreeMap<u64, Nanos>,
    send: Option<SendTimer>,
    /// The finite MANUAL_BY_PARTICIPANT leases of this participant's
    /// writers, by id.
    local_leases_manual: BTreeMap<u64, Nanos>,
    send_manual: Option<ManualSendTimer>,
    generation: u64,
    /// DEADLINE watches (`super::deadline`), one per instance; disjoint
    /// `WatchKey`s from `watches`, sharing this `Core`'s heap and
    /// generation counter.
    deadlines: HashMap<WatchKey, DeadlineWatch>,
    /// Periodic HEARTBEAT watches (RTPS v2.5 Sec.8.4.7.2), one per
    /// reliable writer; disjoint `WatchKey`s from `watches`/`deadlines`,
    /// sharing this `Core`'s heap and generation counter.
    heartbeats: HashMap<WatchKey, HeartbeatWatch>,
    /// Window ends of parked TIME_BASED_FILTER samples (`super::deadline`
    /// `FilterWakeSink`), one per park; disjoint `WatchKey`s, same heap.
    filter_wakes: HashMap<WatchKey, FilterWake>,
}

/// One pending wake for a parked TIME_BASED_FILTER sample.
struct FilterWake {
    sink: Weak<dyn FilterWakeSink>,
    handle: InstanceHandle,
    generation: u64,
}

impl Core {
    fn next_generation(&mut self) -> u64 {
        self.generation += 1;
        self.generation
    }

    fn arm(&mut self, deadline: Nanos, key: WatchKey) -> u64 {
        self.compact_heap();
        let generation = self.next_generation();
        self.heap.push(Reverse((deadline, key, generation)));
        generation
    }

    /// Watch the writer of `key`, alive from `now`, asserted by `renewal`.
    pub(crate) fn watch(
        &mut self,
        key: WatchKey,
        renewal: Arc<Renewal>,
        lease: Nanos,
        sink: Weak<dyn LivelinessSink>,
        now: Nanos,
    ) {
        self.unwatch(key);
        let generation = if lease == INFINITE {
            self.next_generation()
        } else {
            self.arm(now.saturating_add(lease), key)
        };
        let rid = renewal.id();
        self.watches.insert(
            key,
            Watch {
                renewal,
                lease,
                since: now,
                alive: true,
                generation,
                sink,
            },
        );
        self.by_renewal.entry(rid).or_default().push(key);
        self.update_threshold(rid);
    }

    /// Stop watching `key` (its writer unmatched, its reader deleted). Its
    /// heap entry, if any, is left to be ignored.
    pub(crate) fn unwatch(&mut self, key: WatchKey) {
        let Some(watch) = self.watches.remove(&key) else {
            return;
        };
        let rid = watch.renewal.id();
        if let Some(keys) = self.by_renewal.get_mut(&rid) {
            keys.retain(|k| *k != key);
            if keys.is_empty() {
                self.by_renewal.remove(&rid);
            }
        }
        // The renewal may still be shared by other watches.
        let threshold = self.threshold_of(rid);
        watch.renewal.threshold.store(threshold, Ordering::Relaxed);
        self.compact_heap();
    }

    fn threshold_of(&self, rid: u64) -> Nanos {
        self.by_renewal
            .get(&rid)
            .into_iter()
            .flatten()
            .filter_map(|k| self.watches.get(k))
            .map(|w| w.lease)
            .min()
            .unwrap_or(INFINITE)
    }

    fn update_threshold(&self, rid: u64) {
        let threshold = self.threshold_of(rid);
        if let Some(watch) = self
            .by_renewal
            .get(&rid)
            .and_then(|keys| keys.first())
            .and_then(|k| self.watches.get(k))
        {
            watch.renewal.threshold.store(threshold, Ordering::Relaxed);
        }
    }

    /// The renewal `rid` was renewed at `at` after `old`, the previous
    /// renewal, at least its threshold earlier. Each watch it asserts that
    /// is not alive becomes alive; each alive one that was not renewed for
    /// a whole lease before `at` (its entry did not fire yet) is recorded
    /// not alive, then alive.
    pub(crate) fn resumed(&mut self, rid: u64, old: Nanos, at: Nanos, out: &mut Vec<Outcome>) {
        let keys = self.by_renewal.get(&rid).cloned().unwrap_or_default();
        for key in keys {
            let Some(watch) = self.watches.get(&key) else {
                continue;
            };
            let lease = watch.lease;
            let expired_unseen = watch.alive && watch.expiry(old) <= at;
            if watch.alive && !expired_unseen {
                continue;
            }
            let sink = watch.sink.clone();
            if expired_unseen {
                out.push(Outcome::Transition {
                    sink: sink.clone(),
                    key,
                    alive: false,
                });
            }
            out.push(Outcome::Transition {
                sink,
                key,
                alive: true,
            });
            let generation = self.arm(at.saturating_add(lease), key);
            if let Some(watch) = self.watches.get_mut(&key) {
                watch.alive = true;
                watch.since = at;
                watch.generation = generation;
            }
        }
    }

    /// The earliest heap entry, which may be stale.
    pub(crate) fn next_deadline(&self) -> Option<Nanos> {
        self.heap.peek().map(|Reverse((deadline, _, _))| *deadline)
    }

    /// Fire every entry due at `now`.
    pub(crate) fn advance(&mut self, now: Nanos, out: &mut Vec<Outcome>) {
        while let Some(&Reverse((deadline, key, generation))) = self.heap.peek() {
            if deadline > now {
                return;
            }
            self.heap.pop();
            if key == SEND_KEY {
                self.fire_send(generation, now, out);
            } else if key == MANUAL_SEND_KEY {
                self.fire_send_manual(generation, now, out);
            } else if self.deadlines.contains_key(&key) {
                self.fire_deadline(key, generation, now, out);
            } else if self.heartbeats.contains_key(&key) {
                self.fire_heartbeat(key, generation, now, out);
            } else if self.filter_wakes.contains_key(&key) {
                self.fire_filter_wake(key, out);
            } else {
                self.fire_watch(key, generation, now, out);
            }
        }
    }

    fn fire_watch(&mut self, key: WatchKey, generation: u64, now: Nanos, out: &mut Vec<Outcome>) {
        let Some(watch) = self.watches.get(&key) else {
            return;
        };
        if watch.generation != generation || !watch.alive {
            return;
        }
        let expiry = watch.expiry(watch.renewal.last());
        if expiry > now {
            let generation = self.arm(expiry, key);
            if let Some(watch) = self.watches.get_mut(&key) {
                watch.generation = generation;
            }
            return;
        }
        let sink = watch.sink.clone();
        if let Some(watch) = self.watches.get_mut(&key) {
            watch.alive = false;
        }
        out.push(Outcome::Transition {
            sink,
            key,
            alive: false,
        });
    }

    /// Watch `instance`'s DEADLINE `period` for `handle` (DDS v1.4
    /// Sec.2.2.3.7), alive from `now`. `period` must be finite -- the
    /// caller never watches an infinite deadline (zero cost, matching the
    /// default, `super::deadline` module doc).
    pub(crate) fn watch_deadline(
        &mut self,
        key: WatchKey,
        instance: Arc<InstanceDeadline>,
        handle: InstanceHandle,
        period: Nanos,
        sink: Weak<dyn DeadlineSink>,
        now: Nanos,
    ) {
        debug_assert_ne!(period, INFINITE, "an infinite DEADLINE is never watched");
        debug_assert!(period > 0, "a zero DEADLINE is never watched");
        let next_due = now.saturating_add(period);
        let generation = self.arm(next_due, key);
        self.deadlines.insert(
            key,
            DeadlineWatch {
                instance,
                handle,
                period,
                next_due,
                generation,
                sink,
            },
        );
    }

    /// Wake the application at `at` for the parked TIME_BASED_FILTER sample
    /// of `handle`. The wake is told to `sink` on the notices thread (never
    /// here); a stale entry only wakes once more than needed.
    pub(crate) fn arm_filter_wake(
        &mut self,
        key: WatchKey,
        sink: Weak<dyn FilterWakeSink>,
        handle: InstanceHandle,
        at: Nanos,
    ) {
        let generation = self.arm(at, key);
        self.filter_wakes.insert(
            key,
            FilterWake {
                sink,
                handle,
                generation,
            },
        );
    }

    /// A popped wake entry: tell its sink, once.
    fn fire_filter_wake(&mut self, key: WatchKey, out: &mut Vec<Outcome>) {
        let Some(release) = self.filter_wakes.remove(&key) else {
            return;
        };
        out.push(Outcome::FilterWake {
            sink: release.sink,
            handle: release.handle,
        });
    }

    /// Stop watching an instance and bound storage for cancelled entries.
    pub(crate) fn unwatch_deadline(&mut self, key: WatchKey) {
        self.deadlines.remove(&key);
        self.compact_heap();
    }

    /// Watch a reliable writer's periodic HEARTBEAT (RTPS v2.5
    /// Sec.8.4.7.2), armed one `period` from `now` -- the first HEARTBEAT
    /// is due only after a full period elapses, same as the dedicated
    /// thread this replaces (`writer::heartbeat_scheduler::heartbeat_loop`
    /// always slept one period before its first send). Returns this
    /// watch's `HeartbeatPending`: the caller (`Shared::watch_heartbeat`)
    /// hands it to the writer side so its own drop can wait for an
    /// in-flight send (the deletion barrier).
    pub(crate) fn watch_heartbeat(
        &mut self,
        key: WatchKey,
        sink: Weak<dyn HeartbeatSink>,
        period: Nanos,
        now: Nanos,
    ) -> Arc<HeartbeatPending> {
        let generation = self.arm(now.saturating_add(period), key);
        let pending = HeartbeatPending::new();
        self.heartbeats.insert(
            key,
            HeartbeatWatch {
                sink,
                period,
                generation,
                pending: Arc::clone(&pending),
            },
        );
        pending
    }

    /// Stop watching a writer's HEARTBEAT (deleted, or no longer
    /// reliable): its heap entry, if any, is left to go stale.
    pub(crate) fn unwatch_heartbeat(&mut self, key: WatchKey) {
        self.heartbeats.remove(&key);
        self.compact_heap();
    }

    /// Amortized reclamation: retain at most twice the number of live
    /// watches plus a small constant before discarding stale generations.
    fn compact_heap(&mut self) {
        let live = self.watches.len()
            + self.deadlines.len()
            + self.heartbeats.len()
            + self.filter_wakes.len()
            + usize::from(self.send.is_some())
            + usize::from(self.send_manual.is_some());
        if self.heap.len() <= live.saturating_mul(2).saturating_add(64) {
            return;
        }
        let Self {
            heap,
            watches,
            deadlines,
            heartbeats,
            filter_wakes,
            send,
            send_manual,
            ..
        } = self;
        heap.retain(|Reverse((_, key, generation))| {
            if *key == SEND_KEY {
                return send
                    .as_ref()
                    .is_some_and(|timer| timer.generation == *generation);
            }
            if *key == MANUAL_SEND_KEY {
                return send_manual
                    .as_ref()
                    .is_some_and(|timer| timer.generation == *generation);
            }
            if let Some(watch) = deadlines.get(key) {
                return watch.generation == *generation;
            }
            if let Some(watch) = heartbeats.get(key) {
                return watch.generation == *generation;
            }
            if let Some(release) = filter_wakes.get(key) {
                return release.generation == *generation;
            }
            watches
                .get(key)
                .is_some_and(|watch| watch.alive && watch.generation == *generation)
        });
        heap.shrink_to(heap.len().max(64));
    }

    /// The shared per-entry rule (DDS v1.4 Sec.2.2.3.7, Sec.2.2.4.1). Both
    /// `fire_deadline` (a popped heap entry) and `check_deadline_now` (the
    /// lazy path, no heap pop) call exactly this -- the one evaluation
    /// function the mutant below exercises.
    ///
    /// First resyncs `watch.next_due` to any touch newer than what it
    /// already accounts for (a sample/write restarts the period from
    /// itself); then says whether the (possibly just-resynced) boundary
    /// is due, advancing it by exactly one more `period` when it is.
    /// That advance is unconditional on `due`, never recomputed from
    /// `instance.last()`: while an instance stays silent, `last` never
    /// moves, so re-deriving the next boundary from it on every call
    /// would produce the SAME boundary forever -- `advance`'s `while`
    /// loop would then pop this entry back off the heap at the same
    /// `now` without end. Advancing the watch's OWN boundary by one
    /// period per report is what makes each elapsed period cost exactly
    /// one `Outcome` (DDS v1.4 Sec.2.2.4.1: "each deadline period the
    /// total_count will be incremented by one"), not an infinite one.
    ///
    /// Mutant: changing `<=` to `<` makes a period that has JUST fully
    /// elapsed (`now == next_due`) stop counting as due --
    /// `tests_deadline::a_period_that_just_elapsed_is_a_miss` fails
    /// against it (consistent with a LIVELINESS `Watch`'s own `fire_watch`,
    /// which expires on `expiry <= now` too).
    ///
    /// Late updates are evaluated before their timestamp is overwritten
    /// (`touch_deadline`). A timestamp newer than the heap boundary can
    /// also represent several timely updates, so it alone proves no miss.
    fn deadline_due(watch: &mut DeadlineWatch, now: Nanos) -> bool {
        // Lock order is scheduler state, then instance publication. The
        // update path releases publication before requesting state.
        let instance = Arc::clone(&watch.instance);
        let mut publication = instance
            .publication
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(at) = *publication {
            if Self::deadline_boundary_due(watch, at) {
                return true;
            }
            instance.touch(at);
            *publication = None;
        }
        Self::deadline_boundary_due(watch, now)
    }

    fn deadline_boundary_due(watch: &mut DeadlineWatch, now: Nanos) -> bool {
        let last = watch.instance.last();
        let touched_through = last.saturating_add(watch.period);
        if touched_through > watch.next_due {
            watch.next_due = touched_through;
        }
        if watch.next_due <= now {
            watch.next_due = watch.next_due.saturating_add(watch.period);
            true
        } else {
            false
        }
    }

    /// A popped heap entry (`advance`): a stale generation (superseded by
    /// a later re-arm, or unwatched) is ignored. Otherwise always
    /// re-arms at the watch's (possibly just-advanced) `next_due` --
    /// DDS v1.4 Sec.2.2.4.1's "each deadline period" cadence when due, so
    /// a scheduler running behind still reports one event per elapsed
    /// period as `advance`'s own `while` loop keeps popping this key back
    /// off a heap entry that is still due; the same stale-fire recompute
    /// as a LIVELINESS `Watch` (`fire_watch`) when a touch raced the pop.
    fn fire_deadline(
        &mut self,
        key: WatchKey,
        generation: u64,
        now: Nanos,
        out: &mut Vec<Outcome>,
    ) {
        let Some(watch) = self.deadlines.get_mut(&key) else {
            return;
        };
        if watch.generation != generation {
            return;
        }
        let due = Self::deadline_due(watch, now);
        if due {
            out.push(Outcome::DeadlineMissed {
                sink: watch.sink.clone(),
                handle: watch.handle,
            });
        }
        let next_due = watch.next_due;
        let generation = self.arm(next_due, key);
        if let Some(watch) = self.deadlines.get_mut(&key) {
            watch.generation = generation;
        }
    }

    /// A popped HEARTBEAT heap entry (`advance`): a stale generation
    /// (superseded by an unwatch) is ignored. Otherwise unconditionally
    /// pushes `Outcome::Heartbeat` and re-arms at `now + period` -- from
    /// the CURRENT instant, not from the entry's own (possibly stale)
    /// deadline. Unlike `fire_deadline`, which chases the original
    /// boundary so a scheduler running late still reports one event per
    /// elapsed period, a HEARTBEAT catches up by firing once and
    /// rescheduling one period from whenever that happens: exactly what
    /// the dedicated thread this replaces did on every
    /// `thread::sleep(period)` wakeup (no catch-up burst if the thread
    /// -- or now the scheduler pass -- ran behind). There is also no
    /// renewal to check, unlike a LIVELINESS `Watch`: a reliable writer's
    /// periodic HEARTBEAT fires every period regardless of traffic
    /// (RTPS v2.5 Sec.8.4.7.2).
    ///
    /// Mutant: dropping the re-arm (returning after the `push` with no
    /// `self.arm` call) makes `a_heartbeat_fires_every_period_while_watched`
    /// fail at its second period: only one `Outcome::Heartbeat` would ever
    /// be produced.
    ///
    /// Admission: `watch.pending.try_begin()` must succeed before this
    /// produces an `Outcome` at all. A tick that comes due while the
    /// previous one is still queued or running (a slow sink, or sends
    /// piling up faster than the sender drains them) finds it already
    /// claimed and is coalesced -- the watch still re-arms for its next
    /// period either way, so the cadence continues, but no second job
    /// for the same writer is ever created while one is outstanding
    /// (`tests_scheduler::a_slow_sink_never_overlaps_its_own_fires`).
    fn fire_heartbeat(
        &mut self,
        key: WatchKey,
        generation: u64,
        now: Nanos,
        out: &mut Vec<Outcome>,
    ) {
        let Some(watch) = self.heartbeats.get(&key) else {
            return;
        };
        if watch.generation != generation {
            return;
        }
        if watch.pending.try_begin() {
            out.push(Outcome::Heartbeat {
                sink: watch.sink.clone(),
                pending: Arc::clone(&watch.pending),
            });
        }
        let period = watch.period;
        let generation = self.arm(now.saturating_add(period), key);
        if let Some(watch) = self.heartbeats.get_mut(&key) {
            watch.generation = generation;
        }
    }

    /// The lazy take()/write() check (`Shared::check_deadline`): evaluate
    /// `key` right now, with no heap pop. Not due does nothing -- the
    /// existing heap entry, whichever key it names, still correctly
    /// tracks this watch (`fire_deadline` self-corrects a stale one), so
    /// no heap churn on every lazy call that finds nothing overdue (the
    /// common case once the scheduler is running). Due fires and re-arms
    /// exactly like `fire_deadline`; the heap entry this supersedes is
    /// left to go stale, same as everywhere else in this module.
    pub(crate) fn check_deadline_now(&mut self, key: WatchKey, now: Nanos, out: &mut Vec<Outcome>) {
        let Some(watch) = self.deadlines.get_mut(&key) else {
            return;
        };
        let mut missed = false;
        while Self::deadline_due(watch, now) {
            missed = true;
            out.push(Outcome::DeadlineMissed {
                sink: watch.sink.clone(),
                handle: watch.handle,
            });
        }
        if !missed {
            return;
        }
        let next_due = watch.next_due;
        let generation = self.arm(next_due, key);
        if let Some(watch) = self.deadlines.get_mut(&key) {
            watch.generation = generation;
        }
    }

    /// Evaluate all elapsed periods before a late update replaces the
    /// last timestamp. Called under the scheduler state lock, like firing.
    pub(crate) fn touch_deadline(&mut self, key: WatchKey, now: Nanos, out: &mut Vec<Outcome>) {
        if let Some(watch) = self.deadlines.get(&key) {
            let mut publication = watch
                .instance
                .publication
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // The scheduler may already have consumed this publication.
            if now > watch.instance.last() {
                *publication = Some(now);
            }
        }
        self.check_deadline_now(key, now, out);
    }

    /// Entries in `deadlines`: tests only.
    #[cfg(test)]
    pub(crate) fn deadline_watch_count_for_test(&self) -> usize {
        self.deadlines.len()
    }

    /// Entries in `heartbeats`: tests only.
    #[cfg(test)]
    pub(crate) fn heartbeat_watch_count_for_test(&self) -> usize {
        self.heartbeats.len()
    }

    fn fire_send(&mut self, generation: u64, now: Nanos, out: &mut Vec<Outcome>) {
        let Some(period) = self
            .send
            .as_ref()
            .filter(|s| s.generation == generation)
            .map(|s| s.period)
        else {
            return;
        };
        out.push(Outcome::Send);
        let generation = self.arm(now.saturating_add(period), SEND_KEY);
        if let Some(send) = self.send.as_mut() {
            send.generation = generation;
        }
    }

    /// The MANUAL_BY_PARTICIPANT send entry fired: assert only if the
    /// participant-wide renewal moved since the last time this fired,
    /// unlike AUTOMATIC's unconditional `fire_send`.
    fn fire_send_manual(&mut self, generation: u64, now: Nanos, out: &mut Vec<Outcome>) {
        let Some(timer) = self
            .send_manual
            .as_ref()
            .filter(|s| s.generation == generation)
        else {
            return;
        };
        let period = timer.period;
        let last = timer.renewal.last();
        if last != timer.last_sent {
            out.push(Outcome::SendManual);
        }
        let generation = self.arm(now.saturating_add(period), MANUAL_SEND_KEY);
        if let Some(send) = self.send_manual.as_mut() {
            send.generation = generation;
            send.last_sent = last;
        }
    }

    /// A writer of this participant with a finite AUTOMATIC lease (`id`
    /// unique to it) appears, or changes its lease.
    pub(crate) fn set_local_lease(&mut self, id: u64, lease: Nanos, now: Nanos) {
        if lease == INFINITE {
            self.remove_local_lease(id);
            return;
        }
        self.local_leases.insert(id, lease);
        self.reschedule_send(now);
    }

    /// The writer `id` is gone.
    pub(crate) fn remove_local_lease(&mut self, id: u64) {
        if self.local_leases.remove(&id).is_some() {
            // A longer period takes effect at the next assertion.
            let period = Self::period_of(&self.local_leases);
            match (period, self.send.as_mut()) {
                (Some(period), Some(send)) => send.period = period,
                _ => self.send = None,
            }
        }
    }

    /// A third of the shortest lease in `leases`, at least one nanosecond.
    fn period_of(leases: &BTreeMap<u64, Nanos>) -> Option<Nanos> {
        leases.values().min().map(|lease| (lease / 3).max(1))
    }

    fn reschedule_send(&mut self, now: Nanos) {
        let Some(period) = Self::period_of(&self.local_leases) else {
            self.send = None;
            return;
        };
        // A first or a shorter period asserts at once: a peer may start a
        // writer's lease at its match, and the new lease is the shortest.
        if self.send.as_ref().is_some_and(|s| period >= s.period) {
            if let Some(send) = self.send.as_mut() {
                send.period = period;
            }
            return;
        }
        let generation = self.arm(now, SEND_KEY);
        self.send = Some(SendTimer { period, generation });
    }

    /// The period of this participant's own AUTOMATIC assertion, if it
    /// asserts.
    #[cfg(test)]
    pub(crate) fn send_period_for_test(&self) -> Option<Nanos> {
        self.send.as_ref().map(|s| s.period)
    }

    /// A writer of this participant with a finite MANUAL_BY_PARTICIPANT
    /// lease (`id` unique to it) appears, or changes its lease. `renewal`
    /// is the participant-wide renewal every MANUAL_BY_PARTICIPANT
    /// writer's assertion renews (the same `Arc` every call: cheap to
    /// pass again).
    pub(crate) fn set_local_lease_manual(
        &mut self,
        id: u64,
        lease: Nanos,
        now: Nanos,
        renewal: Arc<Renewal>,
    ) {
        if lease == INFINITE {
            self.remove_local_lease_manual(id);
            return;
        }
        self.local_leases_manual.insert(id, lease);
        self.reschedule_send_manual(now, renewal);
    }

    /// The MANUAL_BY_PARTICIPANT writer `id` is gone.
    pub(crate) fn remove_local_lease_manual(&mut self, id: u64) {
        if self.local_leases_manual.remove(&id).is_some() {
            let period = Self::period_of(&self.local_leases_manual);
            match (period, self.send_manual.as_mut()) {
                (Some(period), Some(send)) => send.period = period,
                _ => self.send_manual = None,
            }
        }
    }

    fn reschedule_send_manual(&mut self, now: Nanos, renewal: Arc<Renewal>) {
        let Some(period) = Self::period_of(&self.local_leases_manual) else {
            self.send_manual = None;
            return;
        };
        if let Some(send) = self.send_manual.as_mut() {
            if period >= send.period {
                send.period = period;
                send.renewal = renewal;
                return;
            }
        }
        // A first timer, or a shorter period: (re)arm at once, symmetric
        // with AUTOMATIC's `reschedule_send`. `last_sent` carries over
        // from any existing timer -- an assertion already made in the
        // current period must not be marked "already reported" just
        // because a new, shorter-leased sibling changed the period; only
        // a brand first timer has nothing to carry, and samples
        // `renewal.last()` (nothing could have been asserted through
        // this mechanism before it existed).
        let last_sent = self
            .send_manual
            .as_ref()
            .map_or_else(|| renewal.last(), |send| send.last_sent);
        let generation = self.arm(now, MANUAL_SEND_KEY);
        self.send_manual = Some(ManualSendTimer {
            period,
            generation,
            renewal,
            last_sent,
        });
    }

    /// The period of this participant's own MANUAL_BY_PARTICIPANT
    /// assertion, if it asserts.
    #[cfg(test)]
    pub(crate) fn send_period_manual_for_test(&self) -> Option<Nanos> {
        self.send_manual.as_ref().map(|s| s.period)
    }

    /// Entries in the heap, stale ones included.
    #[cfg(test)]
    pub(crate) fn heap_len_for_test(&self) -> usize {
        self.heap.len()
    }

    #[cfg(test)]
    pub(crate) fn heap_capacity_for_test(&self) -> usize {
        self.heap.capacity()
    }

    /// Whether `key` is watched and alive.
    #[cfg(test)]
    pub(crate) fn is_alive(&self, key: WatchKey) -> Option<bool> {
        self.watches.get(&key).map(|w| w.alive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const MS: Nanos = 1_000_000;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(WatchKey, bool)>>);

    impl LivelinessSink for Recorder {
        fn transition(
            &self,
            key: WatchKey,
            alive: bool,
        ) -> Option<Arc<crate::dds::reader::notices::Ordered>> {
            self.0.lock().unwrap().push((key, alive));
            None
        }
    }

    fn deliver(out: Vec<Outcome>) -> usize {
        let mut sends = 0;
        for outcome in out {
            match outcome {
                Outcome::Transition { sink, key, alive } => {
                    if let Some(sink) = sink.upgrade() {
                        sink.transition(key, alive);
                    }
                }
                Outcome::Send | Outcome::SendManual => sends += 1,
                Outcome::DeadlineMissed { .. }
                | Outcome::FilterWake { .. }
                | Outcome::Heartbeat { .. } => {}
            }
        }
        sends
    }

    fn sink_of(r: &Arc<Recorder>) -> Weak<dyn LivelinessSink> {
        let s: Arc<dyn LivelinessSink> = Arc::clone(r) as Arc<dyn LivelinessSink>;
        Arc::downgrade(&s)
    }

    #[test]
    fn a_silent_writer_expires_once_at_its_lease() {
        let rec = Arc::new(Recorder::default());
        let renewal = Arc::new(Renewal::new(1, 0));
        let mut core = Core::default();
        core.watch(7, Arc::clone(&renewal), 100 * MS, sink_of(&rec), 0);
        let mut out = Vec::new();
        core.advance(99 * MS, &mut out);
        assert!(out.is_empty());
        core.advance(100 * MS, &mut out);
        core.advance(500 * MS, &mut out);
        deliver(out);
        assert_eq!(*rec.0.lock().unwrap(), vec![(7, false)]);
    }

    #[test]
    fn a_renewed_writer_stays_alive() {
        let rec = Arc::new(Recorder::default());
        let renewal = Arc::new(Renewal::new(1, 0));
        let mut core = Core::default();
        core.watch(7, Arc::clone(&renewal), 100 * MS, sink_of(&rec), 0);
        let mut out = Vec::new();
        for t in (50..1000).step_by(50) {
            assert!(renewal.renew(t * MS).is_none());
            core.advance(t * MS, &mut out);
        }
        assert!(out.is_empty());
        assert_eq!(core.is_alive(7), Some(true));
    }

    /// The scheduler ran late: the writer expired and was renewed again
    /// before its entry fired. Recorded not alive, then alive, once.
    #[test]
    fn an_expiry_the_scheduler_did_not_see_is_recorded() {
        let rec = Arc::new(Recorder::default());
        let renewal = Arc::new(Renewal::new(1, 0));
        let mut core = Core::default();
        core.watch(7, Arc::clone(&renewal), 100 * MS, sink_of(&rec), 0);
        let mut out = Vec::new();
        let old = renewal
            .renew(150 * MS)
            .expect("a renewal after a whole lease reports");
        core.resumed(1, old, 150 * MS, &mut out);
        core.advance(200 * MS, &mut out);
        deliver(out);
        assert_eq!(*rec.0.lock().unwrap(), vec![(7, false), (7, true)]);
        assert_eq!(core.is_alive(7), Some(true));
    }

    /// An entry superseded by a re-arm is dropped when it fires: a writer
    /// that resumes over and over keeps one live entry, not one per resume.
    #[test]
    fn a_superseded_entry_does_not_outlive_its_generation() {
        let rec = Arc::new(Recorder::default());
        let renewal = Arc::new(Renewal::new(1, 0));
        let mut core = Core::default();
        core.watch(7, Arc::clone(&renewal), 100 * MS, sink_of(&rec), 0);
        let mut t = 0;
        let mut out = Vec::new();
        for _ in 0..20 {
            t += 150 * MS;
            let old = renewal.renew(t).expect("reported");
            core.resumed(1, old, t, &mut out);
        }
        for _ in 0..200 {
            t += 50 * MS;
            assert!(renewal.renew(t).is_none());
            core.advance(t, &mut out);
        }
        deliver(out);
        assert_eq!(core.heap_len_for_test(), 1);
    }

    #[test]
    fn an_infinite_lease_has_no_entry() {
        let rec = Arc::new(Recorder::default());
        let renewal = Arc::new(Renewal::new(1, 0));
        let mut core = Core::default();
        core.watch(7, Arc::clone(&renewal), INFINITE, sink_of(&rec), 0);
        assert_eq!(core.next_deadline(), None);
        assert!(renewal.renew(u64::MAX / 2).is_none());
    }

    #[test]
    fn the_assertion_follows_the_shortest_local_lease() {
        let mut core = Core::default();
        core.set_local_lease(1, 900 * MS, 0);
        assert_eq!(core.send_period_for_test(), Some(300 * MS));
        core.set_local_lease(2, 300 * MS, 10 * MS);
        assert_eq!(core.send_period_for_test(), Some(100 * MS));
        let mut out = Vec::new();
        core.advance(10 * MS, &mut out);
        // The first entry (at 0) is superseded by the shorter lease's.
        assert_eq!(
            deliver(std::mem::take(&mut out)),
            1,
            "a shorter lease asserts at once"
        );
        core.advance(110 * MS, &mut out);
        assert_eq!(deliver(std::mem::take(&mut out)), 1);
        core.remove_local_lease(2);
        assert_eq!(core.send_period_for_test(), Some(300 * MS));
        core.remove_local_lease(1);
        core.advance(10_000 * MS, &mut out);
        assert_eq!(deliver(out), 0, "no writer, no assertion");
    }

    /// RTPS v2.5 Sec.8.4.13.5: unlike AUTOMATIC, which asserts every
    /// period unconditionally, MANUAL_BY_PARTICIPANT asserts only when the
    /// participant-wide renewal moved since the last check.
    /// Mutant: dropping the `last != timer.last_sent` gate in
    /// `fire_send_manual` (always pushing `SendManual`) makes the first
    /// two assertions below fail (they expect 0, a periodic-unconditional
    /// send would report 1).
    #[test]
    fn the_manual_assertion_only_fires_when_something_happened_since_the_last_check() {
        let mut core = Core::default();
        let renewal = Arc::new(Renewal::new(1, 0));
        core.set_local_lease_manual(1, 300 * MS, 0, Arc::clone(&renewal));
        assert_eq!(core.send_period_manual_for_test(), Some(100 * MS));
        let mut out = Vec::new();
        core.advance(0, &mut out);
        assert_eq!(
            deliver(std::mem::take(&mut out)),
            0,
            "armed at once like AUTOMATIC, but nothing happened yet"
        );
        core.advance(100 * MS, &mut out);
        assert_eq!(
            deliver(std::mem::take(&mut out)),
            0,
            "a whole period passed with no write()/assert_liveliness()"
        );
        // A MANUAL_BY_PARTICIPANT writer acted.
        renewal.renew(150 * MS);
        core.advance(200 * MS, &mut out);
        assert_eq!(
            deliver(std::mem::take(&mut out)),
            1,
            "the next check sees the renewal moved"
        );
        core.advance(300 * MS, &mut out);
        assert_eq!(
            deliver(std::mem::take(&mut out)),
            0,
            "quiet again: already reported, not resent"
        );
        core.remove_local_lease_manual(1);
        assert_eq!(core.send_period_manual_for_test(), None);
    }

    /// A shorter-leased sibling registering mid-period must not swallow an
    /// assertion the current timer had not reported yet: writer A is
    /// MANUAL_BY_PARTICIPANT with a 300 ms lease (period 100 ms), asserts
    /// at t=60ms, then writer B registers at t=60ms with a 30 ms lease
    /// (period 10 ms) -- the "replace" branch of `reschedule_send_manual`.
    /// Mutant: resampling `last_sent` from `renewal.last()` in that branch
    /// (the pre-fix shape) makes the assertion at t=60ms report 0 instead
    /// of 1 below, because the replace itself would mark it "already
    /// seen" before `fire_send_manual` ever ran.
    #[test]
    fn replacing_a_shorter_manual_period_does_not_swallow_an_earlier_assertion() {
        let mut core = Core::default();
        let renewal = Arc::new(Renewal::new(1, 0));
        core.set_local_lease_manual(1, 300 * MS, 0, Arc::clone(&renewal));
        assert_eq!(core.send_period_manual_for_test(), Some(100 * MS));
        // A asserts at t=60ms, before any check has run.
        renewal.renew(60 * MS);
        // At t=60ms, B registers with a shorter lease: period drops to
        // 10ms, the "replace" branch.
        core.set_local_lease_manual(2, 30 * MS, 60 * MS, Arc::clone(&renewal));
        assert_eq!(core.send_period_manual_for_test(), Some(10 * MS));
        // The replace re-arms at once (symmetric with AUTOMATIC): the
        // t=60ms assertion must still be seen now, not silently marked
        // "already reported" by the period change itself.
        let mut out = Vec::new();
        core.advance(60 * MS, &mut out);
        assert_eq!(
            deliver(out),
            1,
            "the assertion made before the period changed must still be sent"
        );
    }

    #[derive(Default)]
    struct DeadlineRecorder(Mutex<Vec<InstanceHandle>>);

    impl DeadlineSink for DeadlineRecorder {
        fn missed(
            &self,
            handle: InstanceHandle,
        ) -> Option<Arc<crate::dds::reader::notices::Ordered>> {
            self.0.lock().unwrap().push(handle);
            None
        }
    }

    fn deadline_sink_of(r: &Arc<DeadlineRecorder>) -> Weak<dyn DeadlineSink> {
        let s: Arc<dyn DeadlineSink> = Arc::clone(r) as Arc<dyn DeadlineSink>;
        Arc::downgrade(&s)
    }

    fn deliver_deadlines(out: Vec<Outcome>) -> Vec<InstanceHandle> {
        let mut missed = Vec::new();
        for outcome in out {
            if let Outcome::DeadlineMissed { sink, handle } = outcome {
                if let Some(sink) = sink.upgrade() {
                    sink.missed(handle);
                    missed.push(handle);
                }
            }
        }
        missed
    }

    fn handle_of(byte: u8) -> InstanceHandle {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        InstanceHandle::new(bytes)
    }

    /// DDS v1.4 Sec.2.2.4.1: "each deadline period the total_count will
    /// be incremented by one for each instance for which data was not
    /// received" -- sustained silence past a 100 ms period reports one
    /// miss at 100 ms and another at 200 ms, not a single one-shot event.
    #[test]
    fn a_silent_instance_is_missed_once_per_elapsed_period() {
        let rec = Arc::new(DeadlineRecorder::default());
        let instance = InstanceDeadline::new(0);
        let mut core = Core::default();
        core.watch_deadline(
            7,
            Arc::clone(&instance),
            handle_of(1),
            100 * MS,
            deadline_sink_of(&rec),
            0,
        );
        let mut out = Vec::new();
        core.advance(99 * MS, &mut out);
        assert!(out.is_empty(), "not due yet");
        core.advance(100 * MS, &mut out);
        assert_eq!(
            deliver_deadlines(std::mem::take(&mut out)),
            vec![handle_of(1)]
        );
        core.advance(199 * MS, &mut out);
        assert!(out.is_empty(), "the next period has not fully elapsed");
        core.advance(200 * MS, &mut out);
        assert_eq!(
            deliver_deadlines(out),
            vec![handle_of(1)],
            "a second whole period of silence is a second miss"
        );
    }

    /// A sample that touches the instance before the period elapses
    /// cancels that period's miss, and the next period is timed from the
    /// touch, not from the original registration.
    ///
    /// Mutant: dropping the `next_due <= now` check in `deadline_due`
    /// (always reporting due) makes this test fail at `core.advance(100 *
    /// MS, ...)`, where it must find nothing.
    #[test]
    fn a_touch_before_the_period_elapses_is_not_a_miss() {
        let rec = Arc::new(DeadlineRecorder::default());
        let instance = InstanceDeadline::new(0);
        let mut core = Core::default();
        core.watch_deadline(
            7,
            Arc::clone(&instance),
            handle_of(1),
            100 * MS,
            deadline_sink_of(&rec),
            0,
        );
        instance.touch(50 * MS);
        let mut out = Vec::new();
        core.advance(100 * MS, &mut out);
        assert!(
            out.is_empty(),
            "the touch at 50ms moved the boundary to 150ms"
        );
        core.advance(150 * MS, &mut out);
        assert_eq!(deliver_deadlines(out), vec![handle_of(1)]);
    }

    /// A period that has JUST fully elapsed (`now == next_due` exactly)
    /// already counts as a miss (DDS v1.4 Sec.2.2.3.7), consistent with
    /// a LIVELINESS `Watch` expiring on `expiry <= now` too.
    ///
    /// Mutant: changing `<=` to `<` in `deadline_due` makes this test
    /// fail: `now == next_due` would stop counting as due.
    #[test]
    fn a_period_that_just_elapsed_is_a_miss() {
        let rec = Arc::new(DeadlineRecorder::default());
        let instance = InstanceDeadline::new(0);
        let mut core = Core::default();
        core.watch_deadline(
            7,
            Arc::clone(&instance),
            handle_of(1),
            100 * MS,
            deadline_sink_of(&rec),
            0,
        );
        let mut out = Vec::new();
        // check_deadline_now at exactly t=100ms, with no touch since
        // registration: due (the period fully elapsed by this instant).
        core.check_deadline_now(7, 100 * MS, &mut out);
        assert_eq!(deliver_deadlines(out), vec![handle_of(1)]);
    }

    /// Two instances on the same reader, one silent and one not: only the
    /// silent one is reported.
    #[test]
    fn two_instances_one_missing_reports_only_the_silent_one() {
        let rec = Arc::new(DeadlineRecorder::default());
        let silent = InstanceDeadline::new(0);
        let fed = InstanceDeadline::new(0);
        let mut core = Core::default();
        core.watch_deadline(
            7,
            Arc::clone(&silent),
            handle_of(1),
            100 * MS,
            deadline_sink_of(&rec),
            0,
        );
        core.watch_deadline(
            8,
            Arc::clone(&fed),
            handle_of(2),
            100 * MS,
            deadline_sink_of(&rec),
            0,
        );
        fed.touch(90 * MS);
        let mut out = Vec::new();
        core.advance(100 * MS, &mut out);
        assert_eq!(
            deliver_deadlines(out),
            vec![handle_of(1)],
            "instance 2 was fed at 90ms, its next boundary is 190ms"
        );
    }

    /// The lazy check (`check_deadline_now`) and the scheduler's own
    /// `advance` share the exact same evaluation: whichever runs first
    /// for a key consumes the due miss, the other finds nothing left.
    #[test]
    fn the_lazy_check_and_advance_do_not_double_count() {
        let rec = Arc::new(DeadlineRecorder::default());
        let instance = InstanceDeadline::new(0);
        let mut core = Core::default();
        core.watch_deadline(
            7,
            Arc::clone(&instance),
            handle_of(1),
            100 * MS,
            deadline_sink_of(&rec),
            0,
        );
        let mut out = Vec::new();
        // The lazy path runs first and consumes the miss.
        core.check_deadline_now(7, 100 * MS, &mut out);
        assert_eq!(
            deliver_deadlines(std::mem::take(&mut out)),
            vec![handle_of(1)]
        );
        // The scheduler's own `advance`, reaching the (now stale) heap
        // entry armed at registration time, finds nothing more: the lazy
        // call already re-armed the live entry for the next period.
        core.advance(100 * MS, &mut out);
        assert!(out.is_empty(), "no double count");
        assert_eq!(
            core.heap_len_for_test(),
            1,
            "the stale entry is superseded, not duplicated"
        );
    }

    /// A touch that lands AT OR AFTER the boundary already being tracked
    /// still reports the period it arrived after (the DEADLINE
    /// counterpart of LIVELINESS's `an_expiry_the_scheduler_did_not_see_is_recorded`):
    /// a sample at t=150ms, with nothing before it since registration at
    /// t=0 and a 100ms period, means the [0,100] period was missed
    /// BEFORE the sample arrived -- `check_deadline_now` (the lazy path,
    /// so no heap pop needs to race anything) must still find it due.
    ///
    /// Mutant: storing the late timestamp before evaluating the watch
    /// erases the elapsed period and fails this test.
    #[test]
    fn a_touch_after_its_own_boundary_still_reports_the_period_it_missed() {
        let rec = Arc::new(DeadlineRecorder::default());
        let instance = InstanceDeadline::new(0);
        let mut core = Core::default();
        core.watch_deadline(
            7,
            Arc::clone(&instance),
            handle_of(1),
            100 * MS,
            deadline_sink_of(&rec),
            0,
        );
        // The touch arrives at 150ms: 50ms after the 100ms boundary this
        // watch is still tracking (nothing has run `advance`/`check_deadline_now`
        // yet, so `next_due` is still 100ms -- the registration value).
        let mut out = Vec::new();
        core.touch_deadline(7, 150 * MS, &mut out);
        assert_eq!(
            deliver_deadlines(out),
            vec![handle_of(1)],
            "the period that elapsed before the late touch is still a miss"
        );
        // Quiet from the touch (150ms) for a full period: no new miss
        // until 250ms.
        let mut out = Vec::new();
        core.check_deadline_now(7, 249 * MS, &mut out);
        assert!(out.is_empty(), "not due yet from the touch at 150ms");
        core.check_deadline_now(7, 250 * MS, &mut out);
        assert_eq!(deliver_deadlines(out), vec![handle_of(1)]);
    }

    #[derive(Default)]
    struct HeartbeatRecorder(Mutex<Vec<()>>);

    impl HeartbeatSink for HeartbeatRecorder {
        fn fire(&self) {
            self.0.lock().unwrap().push(());
        }
    }

    fn heartbeat_sink_of(r: &Arc<HeartbeatRecorder>) -> Weak<dyn HeartbeatSink> {
        let s: Arc<dyn HeartbeatSink> = Arc::clone(r) as Arc<dyn HeartbeatSink>;
        Arc::downgrade(&s)
    }

    fn deliver_heartbeats(out: Vec<Outcome>) -> usize {
        let mut fired = 0;
        for outcome in out {
            if let Outcome::Heartbeat { sink, pending } = outcome {
                if let Some(sink) = sink.upgrade() {
                    sink.fire();
                    fired += 1;
                }
                pending.end();
            }
        }
        fired
    }

    /// RTPS v2.5 Sec.8.4.7.2: a reliable writer's periodic HEARTBEAT fires
    /// every period unconditionally -- no renewal, no traffic condition,
    /// unlike a LIVELINESS `Watch`. The first one is due only after a
    /// full period (same as the dedicated thread it replaces, which always
    /// slept first).
    ///
    /// Mutant: arming the first entry at `now` instead of `now + period`
    /// in `watch_heartbeat` makes the first `advance(0, ..)` below produce
    /// a HEARTBEAT, which this test does not expect.
    #[test]
    fn a_heartbeat_fires_every_period_while_watched() {
        let rec = Arc::new(HeartbeatRecorder::default());
        let mut core = Core::default();
        core.watch_heartbeat(7, heartbeat_sink_of(&rec), 100 * MS, 0);
        let mut out = Vec::new();
        core.advance(0, &mut out);
        assert_eq!(
            deliver_heartbeats(out),
            0,
            "the first period has not elapsed yet"
        );
        for n in 1..=5 {
            let mut out = Vec::new();
            core.advance(n * 100 * MS, &mut out);
            assert_eq!(deliver_heartbeats(out), 1, "period {n} fires exactly once");
        }
        assert_eq!(rec.0.lock().unwrap().len(), 5);
    }

    /// `unwatch_heartbeat` (the writer is deleted) stops future
    /// HEARTBEATs: its stale heap entry is ignored when it fires.
    #[test]
    fn unwatch_heartbeat_stops_future_fires() {
        let rec = Arc::new(HeartbeatRecorder::default());
        let mut core = Core::default();
        core.watch_heartbeat(7, heartbeat_sink_of(&rec), 100 * MS, 0);
        assert_eq!(core.heartbeat_watch_count_for_test(), 1);
        core.unwatch_heartbeat(7);
        assert_eq!(core.heartbeat_watch_count_for_test(), 0);
        let mut out = Vec::new();
        core.advance(500 * MS, &mut out);
        assert!(out.is_empty(), "unwatched: no more HEARTBEATs");
    }

    /// Two writers on independent periods: each fires on its own cadence.
    /// `advance` re-arms a fired entry from the instant IT fires, not
    /// from its stale deadline, so a pass that reaches a HEARTBEAT late
    /// still reports exactly one event for it, never a catch-up burst
    /// (unlike a DEADLINE entry): at `now=100ms`, writer B's entry due at
    /// 60ms fires once and reschedules to 130ms, so its 90ms boundary
    /// (nominally also elapsed by 100ms) is never separately reported.
    #[test]
    fn two_writers_heartbeat_on_independent_periods() {
        let rec_a = Arc::new(HeartbeatRecorder::default());
        let rec_b = Arc::new(HeartbeatRecorder::default());
        let mut core = Core::default();
        core.watch_heartbeat(7, heartbeat_sink_of(&rec_a), 100 * MS, 0);
        core.watch_heartbeat(8, heartbeat_sink_of(&rec_b), 30 * MS, 0);
        let mut out = Vec::new();
        core.advance(30 * MS, &mut out);
        deliver_heartbeats(std::mem::take(&mut out));
        assert_eq!(rec_a.0.lock().unwrap().len(), 0);
        assert_eq!(rec_b.0.lock().unwrap().len(), 1);
        core.advance(100 * MS, &mut out);
        deliver_heartbeats(out);
        assert_eq!(rec_a.0.lock().unwrap().len(), 1, "A's 100ms boundary fired");
        assert_eq!(
            rec_b.0.lock().unwrap().len(),
            2,
            "B's 60ms boundary fired once, coalescing its 90ms boundary"
        );
    }

    /// Dispatch has a per-writer admission gate: without it, a tick that
    /// came due while the previous one was still queued or running would
    /// get a SECOND `Outcome::Heartbeat`, with no bound on how many could
    /// pile up for one slow writer. The rule: a tick due while `pending` is still claimed is coalesced --
    /// no `Outcome` at all for that period, not queued for later -- and
    /// the watch still re-arms, so it is not missed forever, only
    /// skipped until the in-flight one finishes.
    ///
    /// Mutant: removing the `watch.pending.try_begin()` gate in
    /// `fire_heartbeat` (always pushing) makes the second `advance` below
    /// report 1 instead of 0: the slow sink's still-outstanding job would
    /// get a second one stacked on top of it.
    #[test]
    fn a_heartbeat_is_coalesced_while_the_previous_one_is_still_in_flight() {
        let rec = Arc::new(HeartbeatRecorder::default());
        let mut core = Core::default();
        let pending = core.watch_heartbeat(7, heartbeat_sink_of(&rec), 100 * MS, 0);
        let mut out = Vec::new();
        core.advance(100 * MS, &mut out);
        assert_eq!(out.len(), 1, "the first period admits a job");
        assert!(
            pending.is_busy_for_test(),
            "the slot stays claimed until the sender calls end()"
        );
        // The sender has not finished (and so not called `end()`) yet:
        // simulate a slow send by advancing without delivering.
        out.clear();
        core.advance(200 * MS, &mut out);
        assert!(
            out.is_empty(),
            "a tick due while the first job is still in flight is coalesced"
        );
        // The sender finishes the first (and only admitted) job.
        pending.end();
        out.clear();
        core.advance(300 * MS, &mut out);
        assert_eq!(out.len(), 1, "idle again: the next period admits normally");
    }

    /// `unwatch_deadline` (the instance was retired, or the reader/writer
    /// was dropped) stops future misses; a resumed registration (a
    /// revived instance) is independent of the one it replaces.
    #[test]
    fn unwatch_deadline_stops_future_misses() {
        let rec = Arc::new(DeadlineRecorder::default());
        let instance = InstanceDeadline::new(0);
        let mut core = Core::default();
        core.watch_deadline(
            7,
            Arc::clone(&instance),
            handle_of(1),
            100 * MS,
            deadline_sink_of(&rec),
            0,
        );
        assert_eq!(core.deadline_watch_count_for_test(), 1);
        core.unwatch_deadline(7);
        assert_eq!(core.deadline_watch_count_for_test(), 0);
        let mut out = Vec::new();
        core.advance(500 * MS, &mut out);
        assert!(out.is_empty(), "unwatched: no more misses");
    }
}
