// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The thread that runs a participant's liveliness (`hdds-liveliness`).
//!
//! One per participant. It fires the [`Core`]'s due entries, takes the
//! renewals that reported themselves (`Shared::resumed`), and then, with no
//! lock held, tells each watch's sink its transitions and asserts this
//! participant's liveliness when due. A sink only updates its status and
//! queues what the application is told (`notices::Ordered`); the queues are
//! told on a thread of their own, never on this one: an application
//! listener cannot hold the scheduler.
//!
//! The thread stops and is joined, bounded, when its participant is
//! dropped (`core::rt::shutdown::join_bounded`).
//!
//! Periodic HEARTBEATs (`Outcome::Heartbeat`) go to a SEPARATE, single,
//! long-lived `hdds-hb-sender` thread (`heartbeat_worker`), never to
//! the per-batch `hdds-notices` thread application callbacks use: spawning a
//! brand new `hdds-notices` thread for every nonempty batch is costly with
//! many writers, and running callbacks before HEARTBEATs in it would let a
//! blocked listener delay every HEARTBEAT of that batch too. `Core::fire_heartbeat`'s admission gate
//! (`HeartbeatPending`) also means at most one job per writer is ever
//! queued or running here at a time, so two DIFFERENT writers' jobs
//! never race each other on this thread. The SAME writer's count can
//! still be allocated from TWO threads, though -- this one (periodic)
//! and the application's own, on-write ("piggyback") or
//! MANUAL_BY_TOPIC assert-liveliness thread -- and the shared atomic
//! `count` alone only orders ALLOCATION, not which one reaches the
//! wire first. `HeartbeatSchedulerState::send_serial`
//! (`with_next_count` / `try_with_next_count`) closes that: allocate
//! and transmit for one writer run as a single critical section,
//! whichever origin, so the wire order matches allocation order too
//! (RTPS v2.5 Sec.8.3.8.6). On THIS thread specifically it is
//! `try_lock`, skipping the tick entirely on contention, never waiting
//! on a lock the writer's own thread holds. A panicking sink cannot
//! take the worker down either (`catch_unwind` around `sink.fire()`):
//! the other writers' periodic HEARTBEATs keep going.
//!
//! Trade-off, by design, documented rather than hidden: because it is ONE thread processing jobs
//! strictly one at a time, a single blocked send would delay every
//! OTHER writer's periodic HEARTBEAT behind it in the queue, where the
//! dedicated-thread-per-writer design this replaces gave each writer
//! independent progress. The ONE thing that let a `sendto()` actually
//! block there, by POSIX semantics -- `transport::UdpTransport`'s socket
//! being a plain blocking `std::net::UdpSocket`, with no write timeout
//! anywhere in this crate -- is closed for this path specifically: every
//! transmit `dds::writer::heartbeat_scheduler::send_heartbeat_to_readers`
//! makes is the best-effort, non-blocking send
//! (`UdpTransport::send_user_data_unicast_best_effort`,
//! `send_user_data_multicast_best_effort`, `MSG_DONTWAIT` under the
//! hood), so a kernel buffer that is ever actually full drops that one
//! tick (legal: a HEARTBEAT is periodic and idempotent) instead of
//! blocking this worker. The fd's own blocking mode never changes, so
//! every OTHER sender sharing the same socket (DATA, ACKNACK,
//! SPDP/SEDP, the on-write "piggyback" HEARTBEAT) keeps the exact send
//! it always had.
//!
//! Left open: `MSG_DONTWAIT` has no portable equivalent in this crate's
//! `libc` for Windows (no per-call non-blocking flag in Winsock); on
//! that target the periodic send still blocks under the same reasoned
//! (not measured) worst case as before -- a Linux default send buffer
//! is on the order of 200 KiB, and HEARTBEAT traffic is small (tens of
//! bytes) and periodic (100 ms by default), so filling it needs a send
//! rate or an interface stall far past anything one participant's own
//! HEARTBEATs produce. (The BSD family -- FreeBSD/DragonFly/NetBSD/
//! OpenBSD -- DOES have `MSG_DONTWAIT` in this crate's pinned `libc`;
//! checked against the exact source files.)
//!
//! Also left open, listed rather than silently claimed closed: the
//! socket send is not the only thing this worker can wait on while
//! building one writer's periodic HEARTBEAT.
//! `HistoryCache::oldest_seq` takes the history ring's mutex, twice
//! (once inside its own lifespan-pruning pass, once to read the front),
//! and pruning itself may take a further slab-release lock; `WriterWindows
//! ::send_classed`'s classic-dialect path takes its own peers mutex
//! (released before the transmit syscall, but still a blocking
//! acquisition); `EndpointRegistry`'s reader-locator lookups are
//! blocking `RwLock` reads; and every `log::` call in this path goes
//! through the ordinary synchronous logger, which can itself block on
//! `Output::write` under its own global lock. None of these are NEW --
//! they are inherent to the shared structures -- and none is the
//! kernel socket send closed here, but a thread paused inside
//! one of them (holding it) would still delay this worker, and so every
//! writer queued behind it. Converting them to a try-and-defer-the-tick
//! discipline, the same shape `send_serial`'s periodic side already
//! uses, is the natural next step but was not done here: `HistoryCache`
//! and the window table are shared with the write()/dispose()/ACKNACK
//! paths far beyond this one call site, and changing their locking
//! discipline is a larger, separate change, not a contained one.
//! Logging's own global lock is wider still and not specific to this
//! path at all. The claim made here is narrower and precise:
//! the kernel socket send can no longer be the thing that blocks this
//! worker on the platforms `MSG_DONTWAIT` covers; it is not "nothing
//! can block this worker."

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::Duration;

use super::clock::{lease_nanos, LivelinessClock, Nanos};
use super::deadline::{DeadlineSink, FilterWakeSink, InstanceDeadline};
use super::leases::{
    Core, HeartbeatPending, HeartbeatSink, LivelinessSink, Outcome, Renewal, WatchKey,
};
use crate::dds::reader::notices::Ordered;
use crate::dds::reader::InstanceHandle;

/// One admitted HEARTBEAT dispatch (`HeartbeatPending::try_begin` already
/// succeeded for it): the worker upgrades `sink` and fires it, or
/// abandons it quietly if the writer is already gone, then always calls
/// `pending.end()` -- exactly once, whichever happens -- freeing the
/// writer's slot for its next period.
struct HeartbeatJob {
    sink: Weak<dyn HeartbeatSink>,
    pending: Arc<HeartbeatPending>,
}

impl Drop for HeartbeatJob {
    /// RAII: releases the admission slot (`HeartbeatPending::end`)
    /// whenever this job is dropped, whatever the reason -- normal
    /// completion, a dispatch failure (queue full or disconnected), or
    /// a job still buffered in the channel when it is torn down
    /// (`stop_heartbeat_worker`'s drop of the sender; `mpsc` runs the
    /// destructor of every unreceived buffered message). A manual-call-only
    /// release would leave exactly the last two cases' `pending` flags
    /// stuck forever, coalescing that writer out of every later period
    /// for good.
    fn drop(&mut self) {
        self.pending.end();
    }
}

/// Bound on the per-participant HEARTBEAT send queue. `Core::
/// fire_heartbeat`'s admission gate already limits it to at most one
/// entry per watched writer at a time, so this is generous headroom
/// above any realistic writer count on one participant, not the thing
/// doing the bounding: a full queue means the gate itself is not
/// holding, which `try_send`'s `Full` case below treats as a dropped
/// tick (logged), never a block of the scheduler thread.
const HEARTBEAT_QUEUE_BOUND: usize = 4096;

/// The scheduler's state, shared with the participant's readers and
/// writers and with its receive path.
pub(crate) struct Shared {
    clock: Arc<dyn LivelinessClock>,
    state: Mutex<State>,
    /// Wakes the thread: a new entry, a reported renewal, a stop.
    wake: Condvar,
    /// The thread is idle (`settle`).
    idle: Condvar,
    /// Watch keys and local lease ids; 0 is the send entry's.
    next_key: AtomicU64,
    next_renewal: AtomicU64,
    /// The remote participants a watch depends on, by GUID prefix: what
    /// their traffic renews (`heard_from`, `manual_from`).
    remotes: RwLock<HashMap<[u8; 12], RemoteParticipant>>,
    /// Entries of `remotes`: the receive path does nothing while it is 0.
    tracked: AtomicUsize,
    /// The participant-wide renewal every MANUAL_BY_PARTICIPANT writer's
    /// `write()`, `assert_liveliness()`, dispose or unregister renews
    /// (RTPS v2.5 Sec.8.4.13.5), and `DomainParticipant::assert_liveliness`.
    /// Created lazily, once, the first thing that needs it (`local_manual_renewal`).
    local_manual: Mutex<Option<Arc<Renewal>>>,
    /// The sender side of the single `hdds-hb-sender` worker's queue.
    /// `None` once stopped (`stop_heartbeat_worker`): a late dispatch then
    /// just releases the job's `pending` slot instead of sending.
    heartbeat_tx: Mutex<Option<SyncSender<HeartbeatJob>>>,
    /// The worker thread's handle, joined bounded on `stop_heartbeat_worker`.
    heartbeat_worker: Mutex<Option<JoinHandle<()>>>,
    /// Set by `stop_heartbeat_worker`: a job still buffered in the queue
    /// at that point (admitted before the stop, not yet drained) is
    /// released without ever calling `sink.fire()`, so a participant's
    /// drop never lets a leftover periodic HEARTBEAT reach the wire
    /// either, matching the per-writer deletion barrier.
    heartbeat_stop: Arc<AtomicBool>,
    /// This participant's own scheduler thread's id, recorded by `run`
    /// the moment it starts. `is_on_its_own_heartbeat_threads` reads it
    /// to recognize a deletion barrier called FROM that thread (for
    /// example a writer destroyed by a listener/sink callback
    /// that itself runs on the scheduler, `deliver`'s `Transition`
    /// handling) -- which must never wait on itself.
    scheduler_thread_id: OnceLock<ThreadId>,
    /// Likewise for the `hdds-hb-sender` thread.
    sender_thread_id: OnceLock<ThreadId>,
}

/// What renews the writers of one remote participant (DDS v1.4
/// Sec.2.2.3.11): any traffic of it its AUTOMATIC writers, its manual
/// assertions (ParticipantMessage MANUAL, the data of one of its
/// MANUAL_BY_PARTICIPANT writers) those writers.
pub(crate) struct RemoteParticipant {
    pub(crate) automatic: Arc<Renewal>,
    pub(crate) manual: Arc<Renewal>,
    /// The watches that hold it (`Shared::remote`, `Shared::release`).
    users: usize,
}

#[derive(Default)]
struct State {
    core: Core,
    /// Renewals that reported themselves: `(renewal id, previous, at)`.
    resumed: Vec<(u64, Nanos, Nanos)>,
    stop: bool,
    settle_requested: u64,
    settled: u64,
}

impl Shared {
    pub(crate) fn new(clock: Arc<dyn LivelinessClock>) -> Arc<Self> {
        let shared = Arc::new(Self {
            clock,
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
            idle: Condvar::new(),
            // 0 and 1 are reserved for this participant's own AUTOMATIC
            // and MANUAL_BY_PARTICIPANT send entries (`SEND_KEY`,
            // `MANUAL_SEND_KEY` in `leases.rs`).
            next_key: AtomicU64::new(2),
            next_renewal: AtomicU64::new(1),
            remotes: RwLock::new(HashMap::new()),
            tracked: AtomicUsize::new(0),
            local_manual: Mutex::new(None),
            heartbeat_tx: Mutex::new(None),
            heartbeat_worker: Mutex::new(None),
            heartbeat_stop: Arc::new(AtomicBool::new(false)),
            scheduler_thread_id: OnceLock::new(),
            sender_thread_id: OnceLock::new(),
        });
        shared.start_heartbeat_worker();
        shared
    }

    /// Spawns the single `hdds-hb-sender` worker and installs its
    /// sender/handle, done AFTER `self` exists (not inside `new`'s own
    /// `Arc::new` call) so the worker's first line can record its own
    /// `ThreadId` into `self` (`is_on_its_own_heartbeat_threads`).
    fn start_heartbeat_worker(self: &Arc<Self>) {
        let (tx, rx) = sync_channel(HEARTBEAT_QUEUE_BOUND);
        let worker_stop = Arc::clone(&self.heartbeat_stop);
        let worker_shared = Arc::clone(self);
        let worker = thread::Builder::new()
            .name("hdds-hb-sender".to_string())
            .spawn(move || {
                let _ = worker_shared.sender_thread_id.set(thread::current().id());
                heartbeat_worker(rx, worker_stop);
            })
            .map_err(|e| {
                log::error!(
                    "[liveliness] heartbeat sender thread not started ({e}); \
                     periodic HEARTBEATs will be dropped"
                );
            })
            .ok();
        // Only keep the sender if its worker actually exists: otherwise
        // every `try_send` would succeed into a channel nothing drains
        // (bounded, so it would eventually just fill and start refusing)
        // instead of the clean "no worker" path `dispatch_heartbeat` takes.
        let heartbeat_tx = worker.is_some().then_some(tx);
        *self.heartbeat_tx.lock().unwrap_or_else(|e| e.into_inner()) = heartbeat_tx;
        *self
            .heartbeat_worker
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = worker;
    }

    /// Whether the CALLING thread is this participant's own scheduler
    /// thread ("hdds-liveliness") or its HEARTBEAT sender
    /// ("hdds-hb-sender"). A deletion barrier must never wait on either
    /// from a call running on one of them -- it would be waiting for
    /// work that very thread has to do, which it cannot while blocked
    /// (for example a writer destroyed by a sink callback
    /// `deliver` runs inline on the scheduler thread, or, in principle,
    /// by a `HeartbeatSink::fire` body on the sender thread).
    /// `HeartbeatSchedulerState::revoke_sends` already gives the real
    /// "no HEARTBEAT after drop returns" guarantee with no wait needed.
    pub(crate) fn is_on_its_own_heartbeat_threads(&self) -> bool {
        let me = thread::current().id();
        self.scheduler_thread_id.get() == Some(&me) || self.sender_thread_id.get() == Some(&me)
    }

    /// The renewals of the remote participant `prefix`, held until a
    /// matching `release`.
    pub(crate) fn remote(&self, prefix: [u8; 12]) -> (Arc<Renewal>, Arc<Renewal>) {
        let mut remotes = self.remotes.write().unwrap_or_else(|e| e.into_inner());
        let entry = remotes.entry(prefix).or_insert_with(|| RemoteParticipant {
            automatic: self.renewal(),
            manual: self.renewal(),
            users: 0,
        });
        entry.users += 1;
        let renewals = (Arc::clone(&entry.automatic), Arc::clone(&entry.manual));
        self.tracked.store(remotes.len(), Ordering::Relaxed);
        renewals
    }

    /// One holder of `prefix` no longer needs it.
    pub(crate) fn release(&self, prefix: &[u8; 12]) {
        let mut remotes = self.remotes.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = remotes.get_mut(prefix) {
            entry.users = entry.users.saturating_sub(1);
            if entry.users == 0 {
                remotes.remove(prefix);
            }
        }
        self.tracked.store(remotes.len(), Ordering::Relaxed);
    }

    /// A datagram from the participant `prefix` was received: it renews
    /// its AUTOMATIC writers. Once per datagram (not per sample), one
    /// relaxed load when no remote writer is watched.
    #[inline]
    pub(crate) fn heard_from(&self, prefix: &[u8; 12]) {
        if self.tracked.load(Ordering::Relaxed) == 0 {
            return;
        }
        self.heard_from_tracked(prefix);
    }

    #[inline(never)]
    fn heard_from_tracked(&self, prefix: &[u8; 12]) {
        let remotes = self.remotes.read().unwrap_or_else(|e| e.into_inner());
        if let Some(remote) = remotes.get(prefix) {
            self.renew(&remote.automatic);
        }
    }

    /// The participant `prefix` asserted its liveliness manually
    /// (ParticipantMessage of kind MANUAL_LIVELINESS_UPDATE, RTPS v2.5
    /// Sec.8.4.13.5): it renews its MANUAL_BY_PARTICIPANT writers.
    pub(crate) fn manual_from(&self, prefix: &[u8; 12]) {
        if self.tracked.load(Ordering::Relaxed) == 0 {
            return;
        }
        let remotes = self.remotes.read().unwrap_or_else(|e| e.into_inner());
        if let Some(remote) = remotes.get(prefix) {
            self.renew(&remote.manual);
        }
    }

    #[cfg(test)]
    pub(crate) fn tracked_for_test(&self) -> usize {
        self.tracked.load(Ordering::Relaxed)
    }

    /// Whether any remote participant is tracked at all: the same relaxed
    /// load `heard_from`/`manual_from` gate on. A caller doing heavier
    /// work than either of those alone (parsing a submessage, say) before
    /// it would otherwise call them can check this first, to skip that
    /// work too when nothing is watching.
    #[inline]
    pub(crate) fn has_tracked_remotes(&self) -> bool {
        self.tracked.load(Ordering::Relaxed) != 0
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[inline]
    pub(crate) fn now(&self) -> Nanos {
        self.clock.now()
    }

    /// A new source of assertions, renewed from now.
    pub(crate) fn renewal(&self) -> Arc<Renewal> {
        let id = self.next_renewal.fetch_add(1, Ordering::Relaxed);
        Arc::new(Renewal::new(id, self.now()))
    }

    /// Watch a writer asserted by `renewal` with `lease`, alive from now;
    /// its transitions go to `sink`.
    pub(crate) fn watch(
        &self,
        renewal: Arc<Renewal>,
        lease: Duration,
        sink: Weak<dyn LivelinessSink>,
    ) -> WatchKey {
        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        let now = self.now();
        self.state()
            .core
            .watch(key, renewal, lease_nanos(lease), sink, now);
        self.wake.notify_one();
        key
    }

    pub(crate) fn unwatch(&self, key: WatchKey) {
        self.state().core.unwatch(key);
    }

    /// Watch `instance`'s DEADLINE `period` for `handle` (DDS v1.4
    /// Sec.2.2.3.7, `super::deadline` module doc): `period` must be
    /// finite, same contract as `watch_deadline`'s `Core` counterpart.
    pub(crate) fn watch_deadline(
        &self,
        instance: Arc<InstanceDeadline>,
        handle: InstanceHandle,
        period: Duration,
        sink: Weak<dyn DeadlineSink>,
    ) -> WatchKey {
        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        let now = instance.last();
        self.state()
            .core
            .watch_deadline(key, instance, handle, lease_nanos(period), sink, now);
        self.wake.notify_one();
        key
    }

    pub(crate) fn unwatch_deadline(&self, key: WatchKey) {
        self.state().core.unwatch_deadline(key);
    }

    /// Watch a reliable writer's periodic HEARTBEAT (RTPS v2.5
    /// Sec.8.4.7.2): `sink` fires every `period` while watched, never on
    /// this scheduler's own thread (`deliver`).
    pub(crate) fn watch_heartbeat(
        self: &Arc<Self>,
        sink: Weak<dyn HeartbeatSink>,
        period: Duration,
    ) -> HeartbeatWatchHandle {
        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        let now = self.now();
        let pending = self
            .state()
            .core
            .watch_heartbeat(key, sink, lease_nanos(period), now);
        self.wake.notify_one();
        HeartbeatWatchHandle {
            shared: Arc::clone(self),
            key,
            pending,
        }
    }

    /// Dispatch an admitted HEARTBEAT job to the single `hdds-hb-sender`
    /// worker (never the scheduler thread, never the `hdds-notices`
    /// application-callback thread). A failed dispatch (no worker, or the
    /// queue is full -- see [`HEARTBEAT_QUEUE_BOUND`]) still releases
    /// `pending`: otherwise a tick lost here would coalesce every later
    /// one for the same writer forever, mistaking "could not send" for
    /// "still in flight".
    fn dispatch_heartbeat(&self, sink: Weak<dyn HeartbeatSink>, pending: Arc<HeartbeatPending>) {
        let tx = self.heartbeat_tx.lock().unwrap_or_else(|e| e.into_inner());
        let Some(tx) = tx.as_ref() else {
            drop(tx);
            pending.end();
            return;
        };
        let job = HeartbeatJob { sink, pending };
        // Either arm's returned job is dropped at the end of it, which
        // releases `pending` (`HeartbeatJob::drop`) -- no separate
        // manual call to forget.
        match tx.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_dropped)) => {
                log::warn!(
                    "[liveliness] HEARTBEAT send queue full ({HEARTBEAT_QUEUE_BOUND} jobs); \
                     one tick dropped"
                );
            }
            Err(TrySendError::Disconnected(_dropped)) => {}
        }
    }

    /// Stop the HEARTBEAT worker, bounded: dropping the sender closes the
    /// queue (`heartbeat_worker`'s `recv()` then drains what was already
    /// buffered -- each job released, never fired, see
    /// `heartbeat_worker`'s own stop handling -- and returns `Err`), then
    /// joins the thread. Called from `Scheduler::stop`, after the
    /// liveliness thread itself is joined so no later tick can be
    /// dispatched into a queue already closing.
    fn stop_heartbeat_worker(&self) {
        self.heartbeat_stop.store(true, Ordering::Release);
        *self.heartbeat_tx.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let handle = self
            .heartbeat_worker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(handle) = handle {
            crate::core::rt::shutdown::join_bounded(handle, "heartbeat sender");
        }
    }

    /// Record periods elapsed before disposal or unregistration, then
    /// cancel future periods in the same arbitration as timer firing.
    pub(crate) fn finish_deadline(&self, key: WatchKey) {
        let now = self.now();
        let mut out = Vec::new();
        {
            let mut state = self.state();
            state.core.check_deadline_now(key, now, &mut out);
            state.core.unwatch_deadline(key);
        }
        deliver(self, out, &|| {}, &|| {});
    }

    /// The lazy take()/write() check (`ReaderDeadlines::check_now`,
    /// `WriterDeadlines::check_instance`): evaluate `key` right now, under the
    /// exact same lock and per-entry function the scheduler thread uses
    /// (`Core::check_deadline_now` / `Core::fire_deadline`), so the two
    /// never double-count a miss (`super::deadline` module doc). Unlike a
    /// scheduler-found miss, delivered on a thread of its own, this call
    /// tells its outcome inline: the caller is the application's own
    /// take()/write() thread, never the scheduler's, so the "never on the
    /// scheduler thread" rule in this module's doc does not apply to it.
    pub(crate) fn check_deadline(&self, key: WatchKey) {
        let now = self.now();
        let mut out = Vec::new();
        self.state().core.check_deadline_now(key, now, &mut out);
        for outcome in out {
            let Outcome::DeadlineMissed { sink, handle } = outcome else {
                continue;
            };
            let Some(sink) = sink.upgrade() else { continue };
            if let Some(queue) = sink.missed(handle) {
                queue.tell();
            }
        }
    }

    /// Wake the application for `handle`'s parked TIME_BASED_FILTER sample
    /// at `at` (scheduler time). Wakes the thread so the new entry is armed.
    pub(crate) fn arm_filter_wake(
        &self,
        sink: Weak<dyn FilterWakeSink>,
        handle: InstanceHandle,
        at: Nanos,
    ) -> WatchKey {
        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        self.state().core.arm_filter_wake(key, sink, handle, at);
        self.wake.notify_one();
        key
    }

    /// A late update must preserve every period that elapsed before it.
    /// Status notices are handed off, never called under the instance lock
    /// held by the reception/write path.
    pub(crate) fn touch_deadline(&self, key: WatchKey, now: Nanos) {
        let mut out = Vec::new();
        self.state().core.touch_deadline(key, now, &mut out);
        deliver(self, out, &|| {}, &|| {});
    }

    #[cfg(test)]
    pub(crate) fn deadline_watch_count_for_test(&self) -> usize {
        self.state().core.deadline_watch_count_for_test()
    }

    /// `renewal` was renewed at `at`, `old` being the previous renewal
    /// (`Renewal::renew` reported it): arbitrated on the thread.
    pub(crate) fn resumed(&self, renewal: &Renewal, old: Nanos, at: Nanos) {
        self.state().resumed.push((renewal.id(), old, at));
        self.wake.notify_one();
    }

    /// Renew `renewal` now, reporting it when it may resume a writer.
    #[inline]
    pub(crate) fn renew(&self, renewal: &Renewal) {
        let now = self.now();
        if let Some(old) = renewal.renew(now) {
            self.resumed(renewal, old, now);
        }
    }

    /// A writer of this participant with AUTOMATIC liveliness and `lease`:
    /// the participant asserts at least every third of it while the value
    /// lives. `None` for an infinite lease (nothing to assert).
    pub(crate) fn local_writer(self: &Arc<Self>, lease: Duration) -> Option<LocalWriterLease> {
        let lease = lease_nanos(lease);
        if lease == super::clock::INFINITE {
            return None;
        }
        let id = self.next_key.fetch_add(1, Ordering::Relaxed);
        let now = self.now();
        self.state().core.set_local_lease(id, lease, now);
        self.wake.notify_one();
        Some(LocalWriterLease {
            shared: Arc::clone(self),
            id,
        })
    }

    /// The participant-wide renewal every MANUAL_BY_PARTICIPANT writer's
    /// assertion renews (RTPS v2.5 Sec.8.4.13.5), created once and
    /// shared for the participant's life.
    pub(crate) fn local_manual_renewal(&self) -> Arc<Renewal> {
        let mut slot = self.local_manual.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(renewal) = slot.as_ref() {
            return Arc::clone(renewal);
        }
        let renewal = self.renewal();
        *slot = Some(Arc::clone(&renewal));
        renewal
    }

    /// A writer of this participant with MANUAL_BY_PARTICIPANT liveliness
    /// and `lease`: the participant asserts at most every third of the
    /// shortest such lease, and only when one of them acted since the
    /// last check. `None` for an infinite lease (nothing to assert).
    pub(crate) fn local_manual_writer(
        self: &Arc<Self>,
        lease: Duration,
    ) -> Option<ManualWriterLease> {
        let lease = lease_nanos(lease);
        if lease == super::clock::INFINITE {
            return None;
        }
        let id = self.next_key.fetch_add(1, Ordering::Relaxed);
        let now = self.now();
        let renewal = self.local_manual_renewal();
        self.state()
            .core
            .set_local_lease_manual(id, lease, now, renewal);
        self.wake.notify_one();
        Some(ManualWriterLease {
            shared: Arc::clone(self),
            id,
        })
    }

    /// A MANUAL_BY_TOPIC writer's own hand on its liveliness: renewed by
    /// its own `write()`/`assert_liveliness()`/dispose/unregister alone.
    pub(crate) fn writer_assert_own(self: &Arc<Self>) -> WriterAssert {
        WriterAssert {
            shared: Arc::clone(self),
            renewal: self.renewal(),
        }
    }

    /// A MANUAL_BY_PARTICIPANT writer's hand on its liveliness: the
    /// participant-wide renewal, shared with every other writer of that
    /// kind and with `DomainParticipant::assert_liveliness`.
    pub(crate) fn writer_assert_participant(self: &Arc<Self>) -> WriterAssert {
        WriterAssert {
            shared: Arc::clone(self),
            renewal: self.local_manual_renewal(),
        }
    }

    /// Tests only: wait until the thread has done everything due now,
    /// its transitions told to their sinks.
    #[cfg(test)]
    pub(crate) fn settle(&self) {
        let mut state = self.state();
        state.settle_requested += 1;
        let wanted = state.settle_requested;
        self.wake.notify_one();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while state.settled < wanted && !state.stop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!left.is_zero(), "the liveliness scheduler did not settle");
            state = self
                .idle
                .wait_timeout(state, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    #[cfg(test)]
    pub(crate) fn is_alive_for_test(&self, key: WatchKey) -> Option<bool> {
        self.state().core.is_alive(key)
    }
}

/// The finite AUTOMATIC lease of a writer of this participant, for as
/// long as it lives (`Shared::local_writer`).
pub(crate) struct LocalWriterLease {
    shared: Arc<Shared>,
    id: u64,
}

impl Drop for LocalWriterLease {
    fn drop(&mut self) {
        self.shared.state().core.remove_local_lease(self.id);
    }
}

/// The finite MANUAL_BY_PARTICIPANT lease of a writer of this participant,
/// for as long as it lives (`Shared::local_manual_writer`).
pub(crate) struct ManualWriterLease {
    shared: Arc<Shared>,
    id: u64,
}

impl Drop for ManualWriterLease {
    fn drop(&mut self) {
        self.shared.state().core.remove_local_lease_manual(self.id);
    }
}

/// One reliable writer's periodic HEARTBEAT watch (`Shared::
/// watch_heartbeat`), for as long as it lives. Dropped (the writer is
/// deleted, or stops being reliable) before any further HEARTBEAT fires
/// for it: `unwatch_heartbeat` leaves its heap entry to go stale, same as
/// every other watch kind in this module.
pub(crate) struct HeartbeatWatchHandle {
    shared: Arc<Shared>,
    key: WatchKey,
    pending: Arc<HeartbeatPending>,
}

impl HeartbeatWatchHandle {
    /// This watch's admission gate and deletion barrier
    /// (`HeartbeatPending::wait_idle`): the writer side's own drop waits
    /// on it, bounded, before it can drop the sink itself -- no HEARTBEAT
    /// already queued or running for this writer reaches the wire after
    /// that returns.
    pub(crate) fn pending(&self) -> &Arc<HeartbeatPending> {
        &self.pending
    }

    /// Whether the calling thread is this watch's own participant's
    /// scheduler or HEARTBEAT sender thread -- see
    /// `Shared::is_on_its_own_heartbeat_threads`.
    pub(crate) fn is_on_its_own_scheduler_or_sender_thread(&self) -> bool {
        self.shared.is_on_its_own_heartbeat_threads()
    }
}

impl Drop for HeartbeatWatchHandle {
    fn drop(&mut self) {
        self.shared.state().core.unwatch_heartbeat(self.key);
    }
}

/// A writer's own hand on its liveliness (`Shared::writer_assert_own`,
/// `Shared::writer_assert_participant`): `write()`, `dispose()`,
/// `unregister_instance()` and `assert_liveliness()` call
/// [`assert`](Self::assert) to renew it. One relaxed store, no lock: safe
/// on the `write()` hot path.
pub(crate) struct WriterAssert {
    shared: Arc<Shared>,
    renewal: Arc<Renewal>,
}

impl WriterAssert {
    #[inline]
    pub(crate) fn assert(&self) {
        self.shared.renew(&self.renewal);
    }

    /// The renewal this hand renews, to watch it for LIVELINESS_LOST
    /// (`Shared::watch`): the writer side's own hand and its watch must
    /// renew and watch the exact same `Renewal`.
    pub(crate) fn renewal(&self) -> Arc<Renewal> {
        Arc::clone(&self.renewal)
    }
}

/// The participant's liveliness thread; stopped and joined when dropped.
pub(crate) struct Scheduler {
    shared: Arc<Shared>,
    handle: Option<JoinHandle<()>>,
}

impl Scheduler {
    /// Start the thread over `shared`; `send` asserts this participant's
    /// AUTOMATIC liveliness on the wire, `send_manual` its
    /// MANUAL_BY_PARTICIPANT liveliness (RTPS v2.5 Sec.8.4.13.5).
    pub(crate) fn start(
        shared: Arc<Shared>,
        send: Box<dyn Fn() + Send>,
        send_manual: Box<dyn Fn() + Send>,
    ) -> std::io::Result<Self> {
        let thread_shared = Arc::clone(&shared);
        let handle = std::thread::Builder::new()
            .name("hdds-liveliness".to_string())
            .spawn(crate::core::rt::shutdown::owned(move || {
                let _ = thread_shared
                    .scheduler_thread_id
                    .set(thread::current().id());
                run(&thread_shared, &*send, &*send_manual);
            }))?;
        Ok(Self {
            shared,
            handle: Some(handle),
        })
    }

    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    /// Stop the thread and join it (bounded), then the HEARTBEAT sender:
    /// in that order, so the liveliness thread cannot dispatch a new job
    /// into a queue the sender is already closing.
    pub(crate) fn stop(&mut self) {
        self.shared.state().stop = true;
        self.shared.wake.notify_all();
        self.shared.idle.notify_all();
        if let Some(handle) = self.handle.take() {
            crate::core::rt::shutdown::join_bounded(handle, "liveliness scheduler");
        }
        self.shared.stop_heartbeat_worker();
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(shared: &Shared, send: &dyn Fn(), send_manual: &dyn Fn()) {
    let mut state = shared.state();
    loop {
        if state.stop {
            return;
        }
        let now = shared.clock.now();
        let mut out = Vec::new();
        for (rid, old, at) in std::mem::take(&mut state.resumed) {
            state.core.resumed(rid, old, at, &mut out);
        }
        state.core.advance(now, &mut out);
        if !out.is_empty() {
            drop(state);
            deliver(shared, out, send, send_manual);
            state = shared.state();
            continue;
        }
        state.settled = state.settle_requested;
        shared.idle.notify_all();
        let wait = state
            .core
            .next_deadline()
            .and_then(|deadline| shared.clock.sleep_for(deadline.saturating_sub(now)));
        state = match wait {
            Some(timeout) => {
                shared
                    .wake
                    .wait_timeout(state, timeout)
                    .unwrap_or_else(|e| e.into_inner())
                    .0
            }
            None => shared.wake.wait(state).unwrap_or_else(|e| e.into_inner()),
        };
    }
}

/// Tell the sinks their transitions and assert when due, and dispatch any
/// due periodic HEARTBEATs to the single `hdds-hb-sender` worker
/// (`Shared::dispatch_heartbeat`). The queues the sinks filled are told
/// on a thread of their own (`hdds-notices`), entirely separate from the
/// HEARTBEAT path, so a blocked listener never delays a HEARTBEAT batched
/// alongside it.
fn deliver(shared: &Shared, out: Vec<Outcome>, send: &dyn Fn(), send_manual: &dyn Fn()) {
    let mut queues: Vec<Arc<Ordered>> = Vec::new();
    for outcome in out {
        match outcome {
            Outcome::Transition { sink, key, alive } => {
                let Some(sink) = sink.upgrade() else { continue };
                if let Some(queue) = sink.transition(key, alive) {
                    if !queues.iter().any(|q| Arc::ptr_eq(q, &queue)) {
                        queues.push(queue);
                    }
                }
            }
            Outcome::Send => send(),
            Outcome::SendManual => send_manual(),
            Outcome::FilterWake { sink, handle } => {
                let Some(sink) = sink.upgrade() else { continue };
                if let Some(queue) = sink.wake(handle) {
                    if !queues.iter().any(|q| Arc::ptr_eq(q, &queue)) {
                        queues.push(queue);
                    }
                }
            }
            Outcome::DeadlineMissed { sink, handle } => {
                let Some(sink) = sink.upgrade() else { continue };
                if let Some(queue) = sink.missed(handle) {
                    if !queues.iter().any(|q| Arc::ptr_eq(q, &queue)) {
                        queues.push(queue);
                    }
                }
            }
            Outcome::Heartbeat { sink, pending } => shared.dispatch_heartbeat(sink, pending),
        }
    }
    if queues.is_empty() {
        return;
    }
    let told = queues.clone();
    let spawned = std::thread::Builder::new()
        .name("hdds-notices".to_string())
        .spawn(move || {
            for queue in told {
                queue.tell();
            }
        });
    if let Err(e) = spawned {
        // The entity owns each queue; a later handoff can drain it.
        // Application callbacks must never run on the scheduler thread.
        log::error!("[liveliness] notice thread not started ({e}); calls remain queued");
    }
}

/// The single, long-lived HEARTBEAT sender a participant's scheduler
/// runs: one job at a time, strictly in dispatch order, so two writers
/// can never interleave sends and a writer's own successive periods
/// never overlap (`Core::fire_heartbeat`'s admission gate already keeps
/// at most one of its jobs queued or running here). Ends when its
/// channel is closed and drained (`Shared::stop_heartbeat_worker`
/// drops the sender); `stop` is checked per job so a job already
/// buffered when a stop was requested is released without ever firing,
/// not drained as one last send.
fn heartbeat_worker(rx: Receiver<HeartbeatJob>, stop: Arc<AtomicBool>) {
    while let Ok(job) = rx.recv() {
        if !stop.load(Ordering::Acquire) {
            if let Some(sink) = job.sink.upgrade() {
                // A panicking sink would take the whole single worker
                // down with it: `pending.end()` is the statement right
                // after this call, which a panic skips, and every OTHER
                // writer's periodic HEARTBEAT would then stop too once
                // the thread died.
                // Isolating the call keeps this thread alive for every
                // job after this one; `job`'s own `Drop` still frees
                // THIS job's slot regardless of which branch runs.
                if let Err(panic) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink.fire()))
                {
                    log::error!(
                        "[liveliness] a periodic HEARTBEAT sink panicked ({}); that tick is \
                         lost, the sender continues for every other writer",
                        panic_message(&panic)
                    );
                }
            }
        }
        // `job`'s own `Drop` releases `pending` here either way.
    }
    log::debug!("[liveliness] heartbeat sender stopped");
}

/// A short, printable description of a caught panic's payload (`Box<dyn
/// Any + Send>`): the two shapes `panic!`/`assert!` actually produce.
fn panic_message(panic: &Box<dyn std::any::Any + Send>) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}
