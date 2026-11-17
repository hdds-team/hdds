// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Room in a reader's history and storage for its samples, reserved before
//! a sample is acknowledged and given back when the application takes it.
//!
//! A RELIABLE reader acknowledges a sample by crediting it to its
//! WriterProxy; the writer then never sends it again. A reader with no room
//! left, in its history or in the slab pool that stores its samples
//! ([`Prepared`]), must therefore refuse the sample BEFORE crediting it: DDS
//! v1.4 Sec.2.2.3.19 has a RELIABLE service "discard the sample at the
//! DataReader in order not to lose existing samples", footnote 28: "So that
//! the sample can be re-sent at a later time". RTPS v2.5 Sec.8.4.12.2 (T8)
//! puts the order the same way: `add_change`, then `received_change_set`.
//!
//! The history a sample holds a place in is everything between its
//! admission and the application's `take`: the reorder gate, the reader's
//! network ring, and the reader's sample cache, which `take` fills from the
//! ring. A place is a [`HistorySlot`]; it is created by
//! [`HistoryRoom::reserve`], travels with the sample (inside the ring it is
//! carried by the entry itself, see [`HistorySlot::into_ring`] and
//! [`HistoryRoom::adopt`]), and is given back when it is dropped wherever
//! the sample is discarded on the way. In the sample cache the place is a
//! flag on the cached sample instead (see [`HistorySlot::into_cache`]): the
//! cache gives the places of the samples it removes back in bulk, at each
//! removal, so that the cached sample itself carries no drop glue. Counting
//! the ring instead gave a place back as soon as `take` moved a sample into
//! the cache, where it still lived: the cache then held more than the room
//! had granted, and its KEEP_ALL bound silently evicted the oldest.
//!
//! A KEEP_LAST reader's cache keeps the newest samples of each instance
//! rather than refuse them, so it holds no place: its room bounds the
//! network ring only ([`HistoryRoom::ring_only`]), and a place is given back
//! as its entry leaves the ring. Without it, a full ring dropped the newest
//! sample after its acknowledgement, and the application kept an older value
//! for good. A full KEEP_LAST ring does not refuse the newest sample either:
//! DDS v1.4 Sec.2.2.3.18 keeps the most recent `depth` values of each
//! instance, so the producer first drops from the ring the samples a newer
//! `depth` of their instance already replaces (see
//! [`HistoryRoom::keep_last`] and [`HistoryRoom::consume`]); only a ring
//! full of samples the history still keeps refuses.
//!
//! A sample the reorder gate holds is acknowledged on arrival: it takes its
//! place in the history, and its instance count, then, KEEP_ALL and
//! KEEP_LAST alike, keeping free what the gap below it needs (see
//! [`HistoryRoom::reserve_for`]). Taken only at its release, a KEEP_LAST
//! reader's place could be refused there, a ring full of the newest values
//! of other instances or an instance beyond `max_instances`: a loss, the
//! sample acknowledged and never sent again. Its storage is taken before
//! its acknowledgement too, and travels through the gate with it
//! ([`Prepared`]): stored only at its release, it found the slab pool full
//! there, and was lost the same way. Held storage keeps the room the gap's
//! head needs ([`rt::SlabPool::hold`]): the slab pool is shared by every
//! reader of the process, and the sample the gate waits for would find
//! none, the held samples never released.

use crate::core::rt;
use std::collections::HashMap;
use std::sync::atomic::{fence, AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// A retry of the coherent sets waiting for room (`HistoryRoom::on_room`).
pub(crate) type Retry = Arc<dyn Fn() + Send + Sync>;

/// Where the retries `HistoryRoom::came_back` schedules run: a thread of
/// the reader's own (its `Lane`), started when its room comes back while a
/// set waits, which runs the reader's retries in turn with none of its
/// locks held and ends once none is left. A retry commits and delivers
/// (an application listener runs on it); it must not run on the thread
/// that gave room back (see `came_back`). Retries are idempotent: one
/// scheduled while another runs finds nothing, or what came since.
///
/// One lane per reader: a thread of the process shared by every reader ran
/// each reader's listeners in turn, and one listener that blocked held
/// every other reader's waiting sets behind it.
pub(crate) mod retries {
    use super::Retry;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// How long a lane's thread waits for the next retry before it ends:
    /// under sustained backpressure (a set that waits for room, room given
    /// back, again) the next retry wakes the thread rather than start one.
    const IDLE: std::time::Duration = std::time::Duration::from_secs(3);

    /// One reader's retries: whether its thread runs, whether a retry is
    /// due, the thread to wake when one is.
    pub(crate) struct Lane {
        running: AtomicBool,
        due: AtomicBool,
        /// The lane's thread, while it runs: woken when a retry is due.
        thread: parking_lot::Mutex<Option<std::thread::Thread>>,
        /// When a retry is due without an event to schedule it
        /// (`schedule_at`): the earliest asked. The thread does not end
        /// while one is pending.
        wake_at: parking_lot::Mutex<Option<std::time::Instant>>,
        /// How long the thread waits for a retry before it ends (`IDLE`).
        idle: std::time::Duration,
        /// Tests only: run once by the lane's thread when it found no
        /// retry due, before it marks itself stopped.
        #[cfg(test)]
        tail_hook: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl Default for Lane {
        fn default() -> Self {
            Self::with_idle(IDLE)
        }
    }

    impl Lane {
        /// A lane whose thread waits `idle` for a retry before it ends.
        pub(crate) fn with_idle(idle: std::time::Duration) -> Self {
            Self {
                running: AtomicBool::new(false),
                due: AtomicBool::new(false),
                thread: parking_lot::Mutex::new(None),
                wake_at: parking_lot::Mutex::new(None),
                idle,
                #[cfg(test)]
                tail_hook: parking_lot::Mutex::new(None),
            }
        }

        /// Wait up to `idle` for a retry to be due, or until the time a
        /// retry was asked for (`schedule_at`), however later; whether one
        /// is due.
        fn wait_for_due(&self) -> bool {
            let idle_end = std::time::Instant::now() + self.idle;
            loop {
                if self.due.load(Ordering::SeqCst) {
                    return true;
                }
                let now = std::time::Instant::now();
                let deadline = {
                    let mut wake_at = self.wake_at.lock();
                    match *wake_at {
                        Some(at) if at <= now => {
                            *wake_at = None;
                            self.due.store(true, Ordering::SeqCst);
                            return true;
                        }
                        Some(at) => at,
                        None => idle_end,
                    }
                };
                let left = deadline.saturating_duration_since(now);
                if left.is_zero() {
                    return false;
                }
                // A retry scheduled before this park unparked the thread
                // already: the park returns at once (its token is kept).
                std::thread::park_timeout(left);
            }
        }
    }

    #[cfg(test)]
    thread_local! {
        /// Tests only: retries queued on this thread, run by `run_queued`
        /// (deterministic schedules), instead of the worker's.
        // @audit-ok: cfg(test) only, one queue per test thread, never shared
        static QUEUED: std::cell::RefCell<Option<Vec<Retry>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Run `retry` on `lane`'s thread at `at` (or as soon after as the
    /// thread is free), with no event to schedule it: a bound that must
    /// expire whatever the traffic. The thread is started if it is not
    /// running, and does not end before then; the earliest time asked
    /// wins.
    pub(crate) fn schedule_at(lane: &Arc<Lane>, retry: Retry, at: std::time::Instant) {
        #[cfg(test)]
        {
            let queued = QUEUED.with(|q| {
                q.borrow_mut()
                    .as_mut()
                    .map(|queue| queue.push(retry.clone()))
                    .is_some()
            });
            if queued {
                return;
            }
        }
        {
            let mut wake_at = lane.wake_at.lock();
            *wake_at = Some(wake_at.map_or(at, |earlier| earlier.min(at)));
        }
        if lane.running.swap(true, Ordering::SeqCst) {
            if let Some(thread) = lane.thread.lock().as_ref() {
                thread.unpark();
            }
            return;
        }
        spawn_worker(lane, retry);
    }

    /// Run `retry` off this thread, on `lane`'s: started if it is not
    /// running; if it is, it runs `retry` once more before it ends.
    pub(crate) fn schedule(lane: &Arc<Lane>, retry: Retry) {
        #[cfg(test)]
        {
            let queued = QUEUED.with(|q| {
                q.borrow_mut()
                    .as_mut()
                    .map(|queue| queue.push(retry.clone()))
                    .is_some()
            });
            if queued {
                return;
            }
        }
        lane.due.store(true, Ordering::SeqCst);
        if lane.running.swap(true, Ordering::SeqCst) {
            // Its thread runs: it finds `due` set before it ends, woken if
            // it waits.
            if let Some(thread) = lane.thread.lock().as_ref() {
                thread.unpark();
            }
            return;
        }
        spawn_worker(lane, retry);
    }

    /// Start `lane`'s thread (its `running` flag already set), running
    /// `retry` each time one is due.
    fn spawn_worker(lane: &Arc<Lane>, retry: Retry) {
        let worker = Arc::clone(lane);
        let spawned = std::thread::Builder::new()
            .name("hdds-coherent-retry".to_string())
            .spawn(move || {
                *worker.thread.lock() = Some(std::thread::current());
                loop {
                    while worker.due.swap(false, Ordering::SeqCst) {
                        // A panicking retry (an application listener) does
                        // not stop the next.
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| retry()));
                    }
                    if worker.wait_for_due() {
                        continue;
                    }
                    #[cfg(test)]
                    if let Some(hook) = worker.tail_hook.lock().take() {
                        hook();
                    }
                    worker.running.store(false, Ordering::SeqCst);
                    // A retry scheduled between the last check and the
                    // store above found the thread running and left it to
                    // it.
                    if !(worker.due.load(Ordering::SeqCst) || worker.wake_at.lock().is_some())
                        || worker.running.swap(true, Ordering::SeqCst)
                    {
                        break;
                    }
                }
            });
        if let Err(e) = spawned {
            lane.running.store(false, Ordering::SeqCst);
            log::warn!("[READER] no coherent-set retry thread: {e}");
        }
    }

    /// A retry scheduled while the lane's thread is ending, after it
    /// found none due and before it marked itself stopped, still runs:
    /// the scheduler found the thread running and left the retry to it.
    #[cfg(test)]
    #[test]
    fn a_retry_scheduled_as_the_lane_ends_runs() {
        let lane = Arc::new(Lane::with_idle(std::time::Duration::from_millis(10)));
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let retry: Retry = Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        let again = (Arc::clone(&lane), Arc::clone(&retry));
        *lane.tail_hook.lock() = Some(Box::new(move || schedule(&again.0, again.1)));
        schedule(&lane, retry);
        let t0 = std::time::Instant::now();
        while runs.load(Ordering::SeqCst) < 2 && t0.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    /// A retry asked for at a time runs then, with no event, even past the
    /// lane's idle wait, and not before.
    #[cfg(test)]
    #[test]
    fn a_retry_asked_for_at_a_time_runs_then() {
        let lane = Arc::new(Lane::with_idle(std::time::Duration::from_millis(10)));
        let ran_at = Arc::new(parking_lot::Mutex::new(None));
        let record = Arc::clone(&ran_at);
        let retry: Retry = Arc::new(move || {
            record.lock().get_or_insert(std::time::Instant::now());
        });
        let at = std::time::Instant::now() + std::time::Duration::from_millis(120);
        schedule_at(&lane, retry, at);
        let t0 = std::time::Instant::now();
        while ran_at.lock().is_none() && t0.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let ran = ran_at.lock().expect("the retry ran");
        assert!(ran >= at, "not before the time asked");
    }

    /// Under sustained backpressure the lane's thread is woken, not started
    /// again: a retry due while it waits runs on the same thread. Started
    /// for each retry, it cost a thread spawn per wait for room.
    #[cfg(test)]
    #[test]
    fn a_waiting_lane_thread_runs_the_next_retry() {
        let lane = Arc::new(Lane::with_idle(std::time::Duration::from_secs(5)));
        let ran_on = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let record = Arc::clone(&ran_on);
        let retry: Retry = Arc::new(move || {
            record.lock().push(std::thread::current().id());
        });
        let wait_for = |n: usize| {
            let t0 = std::time::Instant::now();
            while ran_on.lock().len() < n && t0.elapsed() < std::time::Duration::from_secs(5) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        };
        let started = std::time::Instant::now();
        for n in 1..=20 {
            schedule(&lane, Arc::clone(&retry));
            wait_for(n);
            // The retry ran, the thread waits for the next.
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "a retry waited for the idle timeout: the waiting thread was not woken"
        );
        let ran_on = ran_on.lock();
        assert_eq!(ran_on.len(), 20);
        assert!(
            ran_on.iter().all(|id| *id == ran_on[0]),
            "one thread for the whole run"
        );
    }

    /// Tests only: from now on, this thread's retries are queued until
    /// `run_queued`.
    #[cfg(test)]
    pub(crate) fn queue_on_this_thread() {
        QUEUED.with(|q| *q.borrow_mut() = Some(Vec::new()));
    }

    /// Tests only: run the retries queued on this thread, those they queue
    /// included, until none is left; whether any ran.
    #[cfg(test)]
    pub(crate) fn run_queued() -> bool {
        let mut ran = false;
        loop {
            let batch = QUEUED.with(|q| q.borrow_mut().as_mut().map(std::mem::take));
            let Some(batch) = batch.filter(|b| !b.is_empty()) else {
                return ran;
            };
            for retry in batch {
                ran = true;
                retry();
            }
        }
    }
}

/// Where a DataWriter of the same process waits for room in a RELIABLE
/// reader's history, and how the reader wakes it.
///
/// DDS v1.4 Sec.2.2.3.14: a RELIABLE `write` "may block if the modification
/// would cause data to be lost or else cause one of the limits specified in
/// the RESOURCE_LIMITS to be exceeded", for at most `max_blocking_time`. A
/// local reader has no repair path: what the writer's merger cannot push is
/// lost, so the writer waits here instead, woken when the reader frees
/// something (a take that gives places back, a pop of a full ring).
///
/// The protocol is the store-buffering one: the waiter counts itself in
/// `waiters`, then re-checks its condition; the reader makes its change,
/// then reads `waiters`. Both sides order the two steps with a sequentially
/// consistent operation (a SeqCst read-modify-write, or a SeqCst fence), so
/// at least one of them sees the other: either the waiter's re-check sees
/// the room and it does not sleep, or the reader sees the waiter and wakes
/// it, under the lock the waiter sleeps with. A reader with no waiter pays
/// one load.
pub(crate) struct RoomWait {
    /// Writers between their count and the end of their sleep.
    waiters: AtomicUsize,
    /// Held by a waiter from its count to its sleep, and by a waker to
    /// notify: a wake-up cannot fall between the two.
    lock: parking_lot::Mutex<()>,
    cond: parking_lot::Condvar,
    retries: parking_lot::Mutex<Vec<Retry>>,
    /// Set when the reader is torn down: no room will come, and its
    /// registrations are tombstoned.
    closed: AtomicBool,
}

impl RoomWait {
    pub(crate) fn new() -> Self {
        Self {
            waiters: AtomicUsize::new(0),
            lock: parking_lot::Mutex::new(()),
            cond: parking_lot::Condvar::new(),
            retries: parking_lot::Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        }
    }

    /// The reader freed something with a SeqCst read-modify-write (a place
    /// given back), or under the lock the waiter's re-check takes (an
    /// instance count): wake the writers waiting, if any.
    #[inline]
    pub(crate) fn freed(&self) {
        if self.waiters.load(Ordering::SeqCst) != 0 {
            self.wake();
        }
    }

    /// The reader freed a ring slot with a plain release store (a pop of a
    /// full ring): the fence orders it before the read of `waiters`.
    #[inline]
    pub(crate) fn freed_slot(&self) {
        fence(Ordering::SeqCst);
        self.freed();
    }

    #[cold]
    #[inline(never)]
    fn wake(&self) {
        {
            let _lock = self.lock.lock();
            self.cond.notify_all();
        }
        let retries = std::mem::take(&mut *self.retries.lock());
        self.waiters.fetch_sub(retries.len(), Ordering::SeqCst);
        // These callbacks only schedule work on a retry lane. A reader may
        // still hold its cache or consumer gate while returning room.
        for retry in retries {
            retry();
        }
    }

    /// The reader is torn down: wake every writer waiting, for good.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.wake();
    }

    /// Arm a one-shot retry after a failed admission released every
    /// tentative reservation, then probe again to close the wake-up gap.
    pub(crate) fn retry_when_room(&self, retry: Retry, blocked: &mut dyn FnMut() -> bool) {
        {
            let mut retries = self.retries.lock();
            self.waiters.fetch_add(1, Ordering::SeqCst);
            retries.push(retry);
        }
        fence(Ordering::SeqCst);
        if self.closed.load(Ordering::SeqCst) || !blocked() {
            self.wake();
        }
    }

    /// Wait while `blocked()` holds, until `deadline`. Returns whether the
    /// wait ended with `blocked()` false (or the reader torn down); `false`
    /// is a timeout. `blocked` runs under this wait's lock, after the
    /// waiter is counted: it must not take a lock the reader holds while it
    /// wakes (the reader's consumer gate), and it may take the history
    /// room's lock, which no waker holds while it wakes.
    pub(crate) fn wait_while(&self, deadline: Instant, mut blocked: impl FnMut() -> bool) -> bool {
        let mut lock = self.lock.lock();
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return true;
            }
            self.waiters.fetch_add(1, Ordering::SeqCst);
            fence(Ordering::SeqCst);
            let still = blocked();
            if !still {
                self.waiters.fetch_sub(1, Ordering::SeqCst);
                return true;
            }
            let timed_out = self.cond.wait_until(&mut lock, deadline).timed_out();
            self.waiters.fetch_sub(1, Ordering::SeqCst);
            if timed_out {
                return self.closed.load(Ordering::SeqCst) || !blocked();
            }
        }
    }
}

/// The RESOURCE_LIMITS bound (DDS v1.4 Sec.2.2.3.19) a sample found its
/// reader's history at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bound {
    /// No place left: `max_samples`, or the network ring's capacity.
    Samples,
    /// A sample of a new instance, with `max_instances` already managed.
    Instances,
    /// `max_samples_per_instance` samples of its instance already held.
    SamplesPerInstance,
    /// A sample the reorder gate would hold would leave its instance, or
    /// the instance slots, less room than the gap below it may need (see
    /// [`HistoryRoom::reserve_for`]). Not a bound the sample is beyond: it
    /// comes again once in order and is judged then.
    GapHeadroom,
    /// A KEEP_LAST history keeping `max_samples` samples across its
    /// instances, and a sample that would grow it (its instance holds fewer
    /// than `depth`): dropping replaced samples does not make room for it.
    Kept,
}

/// What a [`HistoryRoom`] counts per instance, under its lock.
struct Held {
    /// For a room that bounds instances ([`HistoryRoom::bounded`]): the
    /// samples each instance has in the history, admitted and not yet taken
    /// or replaced. An instance whose count fell to zero stays while
    /// `max_instances` is finite, until a new instance needs its room and
    /// no writer holds it any more (see [`HistoryRoom::reserve_for`]).
    instances: HashMap<[u8; 16], usize>,
    /// For a KEEP_LAST(`depth`) room bounded by `max_samples`
    /// ([`HistoryRoom::kept_depth`]): the samples the history keeps, the
    /// sum over instances of `min(samples, depth)`. A sample beyond `depth`
    /// of its instance is about to be replaced, and grows nothing.
    kept: usize,
}

/// The places of one reader's history, as seen by everything that
/// delivers into it.
///
/// Every producer of the reader's network ring takes a place before it
/// pushes, so a reserved push always finds room in the ring: the ring holds
/// at most the places granted, and the room grants at most the ring's
/// usable capacity.
///
/// The room is also the reader's RESOURCE_LIMITS `max_samples` for what
/// arrives from the network (DDS v1.4 Sec.2.2.3.19): a RELIABLE KEEP_ALL
/// reader at that limit refuses the next sample, unacknowledged, and never
/// holds more.
pub(crate) struct HistoryRoom {
    /// Places this history can hold: `max_samples`, within the network
    /// ring's usable capacity.
    capacity: usize,
    /// Places held by admitted samples not yet taken by the application.
    /// An atomic, outside `taken`: a room that counts no instance takes and
    /// gives back a place per sample with one read-modify-write and no lock
    /// (a KEEP_ALL reader's local writers take one per write). A room that
    /// counts instances takes its places under `taken`, with its instance
    /// counts, as one step; places given back need no lock either (a place
    /// given back only makes more room).
    places: AtomicUsize,
    /// The instances held, when the room bounds them.
    taken: parking_lot::Mutex<Held>,
    /// RESOURCE_LIMITS `max_instances`, LENGTH_UNLIMITED for none.
    max_instances: usize,
    /// RESOURCE_LIMITS `max_samples_per_instance` of a KEEP_ALL history,
    /// LENGTH_UNLIMITED for none and for KEEP_LAST, whose newer sample
    /// replaces the oldest of its instance rather than exceed it.
    max_per_instance: usize,
    /// The HISTORY depth of a KEEP_LAST reader ([`HistoryRoom::ring_only`]),
    /// `None` for KEEP_ALL. For a BEST_EFFORT KEEP_ALL reader, its finite
    /// `max_samples_per_instance`: the samples of an instance it keeps,
    /// discarding the older ones the same way (see `discards_old`).
    keep_last: Option<usize>,
    /// The places bound the network ring only, and are given back as its
    /// entries leave it: the reader's cache keeps the newest samples rather
    /// than refuse them, and holds no place. KEEP_LAST, and BEST_EFFORT
    /// KEEP_ALL.
    ring_only: bool,
    /// A BEST_EFFORT KEEP_ALL history: at its RESOURCE_LIMITS "the old
    /// values will be discarded" (DDS v1.4 Sec.2.2.3.18). Its cache discards
    /// the oldest samples past `max_samples` and past
    /// `max_samples_per_instance` of an instance; a full ring drops what
    /// those replace, then its oldest sample.
    discards_old: bool,
    /// RESOURCE_LIMITS `max_samples` of a KEEP_LAST history, which its
    /// places (the network ring) do not bound: the samples it keeps across
    /// its instances ([`Held::kept`]). LENGTH_UNLIMITED for none and for
    /// KEEP_ALL, whose places it bounds.
    max_kept: usize,
    /// Held by whoever pops the network ring. The ring has one consumer, the
    /// reader; a KEEP_LAST producer that finds the ring full becomes its
    /// consumer for as long as it drops what the history no longer keeps,
    /// and this lock is what makes it the only one.
    consumer: parking_lot::Mutex<()>,
    /// Set when a coherent set, closed and complete, waits for places to
    /// commit into (`ReaderSubscriber::try_commit_sets`); cleared by the
    /// first place or instance given back, which schedules `retry`.
    waiting: std::sync::atomic::AtomicBool,
    /// What a place given back schedules when a set waits for room: the
    /// subscriber tries its waiting sets again (`retries`). Set by whoever
    /// builds the subscriber.
    retry: parking_lot::Mutex<Option<Retry>>,
    /// Where `retry` runs (`retries`): this reader's own.
    lane: Arc<retries::Lane>,
    /// The local writers waiting for room (see [`RoomWait`]), woken when a
    /// place or an instance count is given back (`came_back`).
    wait: Option<Arc<RoomWait>>,
}

impl HistoryRoom {
    /// `max_samples` is the reader's RESOURCE_LIMITS value;
    /// LENGTH_UNLIMITED leaves the ring as the only bound.
    #[cfg(test)]
    pub(crate) fn new(ring: &rt::IndexRing, max_samples: usize) -> Arc<Self> {
        Arc::new(Self::build(
            Self::keep_all_capacity(ring, max_samples),
            None,
        ))
    }

    /// `max_samples` within the ring's usable capacity.
    fn keep_all_capacity(ring: &rt::IndexRing, max_samples: usize) -> usize {
        let usable = ring.usable_capacity();
        if max_samples == crate::reliability::LENGTH_UNLIMITED {
            usable
        } else {
            max_samples.min(usable)
        }
    }

    fn build(capacity: usize, keep_last: Option<usize>) -> Self {
        Self {
            capacity,
            places: AtomicUsize::new(0),
            taken: parking_lot::Mutex::new(Held {
                instances: HashMap::new(),
                kept: 0,
            }),
            max_instances: crate::reliability::LENGTH_UNLIMITED,
            max_per_instance: crate::reliability::LENGTH_UNLIMITED,
            keep_last,
            ring_only: keep_last.is_some(),
            discards_old: false,
            max_kept: crate::reliability::LENGTH_UNLIMITED,
            consumer: parking_lot::Mutex::new(()),
            waiting: std::sync::atomic::AtomicBool::new(false),
            retry: parking_lot::Mutex::new(None),
            lane: Arc::new(retries::Lane::default()),
            wait: None,
        }
    }

    /// Whether a reader of `qos` discards its old values at its
    /// RESOURCE_LIMITS rather than refuse the new ones: BEST_EFFORT KEEP_ALL
    /// (DDS v1.4 Sec.2.2.3.18, "If the reliability kind is BEST_EFFORT, then
    /// the old values will be discarded"), unless PRESENTATION
    /// `coherent_access`: a set is presented whole (Sec.2.2.3.6), and
    /// discarding the oldest value could cut one already in the history.
    /// Such a reader drops the new sample instead, which Sec.2.2.3.19 allows
    /// a BEST_EFFORT service ("allowed to drop samples"), and a set that
    /// does not fit is refused whole.
    pub(crate) fn discards_old_values(qos: &crate::dds::QoS) -> bool {
        matches!(qos.history, crate::dds::qos::History::KeepAll)
            && matches!(qos.reliability, crate::dds::qos::Reliability::BestEffort)
            && !qos.presentation.coherent_access
    }

    /// The room of a reader's network ring with its HISTORY and
    /// RESOURCE_LIMITS: [`new`](Self::new) for KEEP_ALL,
    /// [`ring_only`](Self::ring_only) for KEEP_LAST, and the instance
    /// bounds of both. A KEEP_LAST history never exceeds
    /// `max_samples_per_instance` (it is at least the depth, and a newer
    /// sample replaces the oldest of its instance): only `max_instances`
    /// bounds its instances.
    ///
    /// A BEST_EFFORT KEEP_ALL history discards its old values at its limits
    /// rather than refuse the new ones (DDS v1.4 Sec.2.2.3.18): its places
    /// bound the network ring only, like a KEEP_LAST history's, and its
    /// `max_samples` and `max_samples_per_instance` are kept by its cache
    /// (see `discards_old`); only `max_instances` refuses.
    pub(crate) fn bounded(
        ring: &rt::IndexRing,
        history: crate::dds::qos::History,
        discards_old: bool,
        limits: &crate::qos::ResourceLimits,
        wait: Option<Arc<RoomWait>>,
    ) -> Arc<Self> {
        let mut room = match history {
            crate::dds::qos::History::KeepAll if discards_old => {
                let per_instance = (limits.max_samples_per_instance
                    != crate::reliability::LENGTH_UNLIMITED)
                    .then_some(limits.max_samples_per_instance);
                let mut room = Self::build(ring.usable_capacity(), per_instance);
                room.ring_only = true;
                room.discards_old = true;
                room
            }
            crate::dds::qos::History::KeepAll => {
                let mut room = Self::build(Self::keep_all_capacity(ring, limits.max_samples), None);
                room.max_per_instance = limits.max_samples_per_instance;
                room
            }
            crate::dds::qos::History::KeepLast(depth) => {
                let mut room = Self::build(ring.usable_capacity(), Some(depth as usize));
                room.max_kept = limits.max_samples;
                room
            }
        };
        room.max_instances = limits.max_instances;
        room.wait = wait;
        Arc::new(room)
    }

    /// Whether this room counts the samples of each instance, which only a
    /// finite `max_instances` or KEEP_ALL `max_samples_per_instance` asks
    /// for. A room that does not pays nothing for instances.
    #[inline]
    pub(crate) fn counts_instances(&self) -> bool {
        self.max_instances != crate::reliability::LENGTH_UNLIMITED
            || self.max_per_instance != crate::reliability::LENGTH_UNLIMITED
            || self.max_kept != crate::reliability::LENGTH_UNLIMITED
    }

    /// The depth a KEEP_LAST history bounded by `max_samples` counts what
    /// it keeps with ([`Held::kept`]); `None` when it counts nothing.
    #[inline]
    fn kept_depth(&self) -> Option<usize> {
        self.keep_last
            .filter(|_| self.max_kept != crate::reliability::LENGTH_UNLIMITED)
    }

    /// The room of a KEEP_LAST(`depth`) reader's network ring: as many
    /// places as the ring holds, given back as entries leave the ring (its
    /// cache keeps the newest samples of each instance rather than refuse
    /// them, and holds no place).
    #[cfg(test)]
    pub(crate) fn ring_only(ring: &rt::IndexRing, depth: usize) -> Arc<Self> {
        Arc::new(Self::build(ring.usable_capacity(), Some(depth)))
    }

    /// The HISTORY depth of a KEEP_LAST reader, whose full ring makes room
    /// for a newer sample rather than refuse it; `None` for KEEP_ALL (a
    /// BEST_EFFORT KEEP_ALL reader's finite `max_samples_per_instance`, see
    /// the field).
    pub(crate) fn keep_last(&self) -> Option<usize> {
        self.keep_last
    }

    /// Whether the places bound the network ring only (see the field).
    pub(crate) fn bounds_ring_only(&self) -> bool {
        self.ring_only
    }

    /// Whether a full ring drops its oldest sample rather than refuse a
    /// newer one: a BEST_EFFORT KEEP_ALL history (see the field).
    pub(crate) fn discards_old(&self) -> bool {
        self.discards_old
    }

    /// The network ring's consumer side: every pop of the ring happens under
    /// this guard, the reader's and a KEEP_LAST producer's alike. Taken
    /// before the producer's push lock, never after it.
    pub(crate) fn consume(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.consumer.lock()
    }

    /// The bound a coherent set of samples of `instances` (one entry per
    /// sample, `None` when its instance is unknown) exceeds even in an
    /// empty history, if any: it can never be committed whole.
    pub(crate) fn never_holds(&self, instances: &[Option<[u8; 16]>]) -> Option<Bound> {
        if instances.len() > self.capacity {
            return Some(Bound::Samples);
        }
        if !self.counts_instances() {
            return None;
        }
        let mut per: HashMap<[u8; 16], usize> = HashMap::new();
        for key in instances.iter().flatten() {
            *per.entry(*key).or_default() += 1;
        }
        if per.values().any(|&n| n > self.max_per_instance) {
            return Some(Bound::SamplesPerInstance);
        }
        if per.len() > self.max_instances {
            return Some(Bound::Instances);
        }
        None
    }

    /// What a place given back schedules once a coherent set waits for
    /// room (see [`came_back`](Self::came_back)), in place of what was set
    /// before.
    pub(crate) fn on_room(&self, retry: Box<dyn Fn() + Send + Sync>) {
        *self.retry.lock() = Some(Arc::from(retry));
    }

    /// Try the waiting sets again at `at`, whatever gives room back or not:
    /// a bound on a set's wait that must expire with no traffic
    /// (`ReaderSubscriber::refresh_group_rosters`). Nothing without a
    /// retry wired.
    pub(crate) fn retry_at(&self, at: std::time::Instant) {
        let retry = self.retry.lock().clone();
        if let Some(retry) = retry {
            retries::schedule_at(&self.lane, retry, at);
        }
    }

    /// A coherent set, closed and complete, found too little room to commit
    /// into: the next place or instance given back, whatever gives it back,
    /// schedules a retry ([`came_back`](Self::came_back)).
    pub(crate) fn wait_for_room(&self) {
        self.waiting
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// The one door every place and instance count comes back through
    /// (a slot dropped, [`give_back`](Self::give_back),
    /// [`release_instance`](Self::release_instance)), after its lock is
    /// released: if a set waits for room, its retry is scheduled, off this
    /// thread (`retries`). The thread giving room back may hold any of the
    /// reader's locks (its cache's, its ring's consumer guard) and may be
    /// delivering: an application's listener taking from inside
    /// `on_data_available`. Committing here would deliver under those
    /// locks, into that listener. One relaxed load when no set waits.
    ///
    /// The same door wakes the local writers waiting for room
    /// ([`RoomWait::freed`]: one load when none waits).
    #[inline]
    fn came_back(&self) {
        if let Some(wait) = self.wait.as_ref() {
            wait.freed();
        }
        if !self.waiting.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if self
            .waiting
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            let retry = self.retry.lock().clone();
            if let Some(retry) = retry {
                retries::schedule(&self.lane, retry);
            }
        }
    }

    /// A place for one sample, or `None` when the reader has no room for it.
    ///
    /// `keep` is the number of places that must stay free after this one:
    /// for a sample the reorder gate will hold, one per earlier sequence the
    /// gate still awaits ([`ReorderGate::places_to_keep`]). A held sample
    /// that took the place of an awaited one would leave the gap unfilled
    /// and itself unreleasable; keeping one place only let the gap fill one
    /// sequence per repair round. A sample that goes straight to the ring
    /// keeps nothing and may take the last place.
    ///
    /// [`ReorderGate::places_to_keep`]: super::reorder::ReorderGate::places_to_keep
    #[cfg(test)]
    pub(crate) fn reserve(self: &Arc<Self>, keep: usize) -> Option<HistorySlot> {
        self.reserve_for(keep, 0, None, |_| false).ok()
    }

    /// [`reserve`](Self::reserve) for a sample of instance `instance`, which
    /// the slot also counts when the room bounds instances: refused with the
    /// [`Bound`] it would exceed. `None` for a sample whose instance is not
    /// known (it then counts toward no instance).
    ///
    /// An instance stays managed while the history holds a sample of it or
    /// a writer holds it registered (DDS v1.4 Sec.2.2.3.22: the reader
    /// reclaims an instance that has no writers and whose samples were all
    /// taken). `held_by_a_writer` says the second; it is asked only when a
    /// new instance finds `max_instances` reached, for the instances with no
    /// sample left, which are then forgotten if no writer holds them.
    ///
    /// `headroom` is, for a sample the reorder gate will hold, the number of
    /// earlier sequences it awaits; 0 for a sample that goes straight on.
    /// Places are kept for those (`keep`), and instances too: a held sample
    /// counts for its instance until the gap below it fills, and the gap's
    /// samples may be of its instance or of new ones. It is refused
    /// ([`Bound::GapHeadroom`]) unless, once counted, its instance still has
    /// `headroom` samples to go before `max_samples_per_instance` and
    /// `headroom` instances are still free before `max_instances`, its own
    /// instance managed or new: a held sample keeps its instance managed
    /// until released, even once its writer let it go. Without that, held samples could take every sample
    /// of their instance or every instance slot while they wait, and the
    /// awaited sample, refused for that limit at every resend, would never
    /// come: the gate would hold them for good. The other writers' gaps are
    /// not counted here: their held samples keep the same room for their own
    /// gaps, and what an in-order sample takes, the application can take
    /// back.
    pub(crate) fn reserve_for(
        self: &Arc<Self>,
        keep: usize,
        headroom: usize,
        instance: Option<[u8; 16]>,
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> Result<HistorySlot, Bound> {
        let instance = self.count_place(keep, headroom, instance, held_by_a_writer)?;
        Ok(HistorySlot {
            room: Some(Arc::clone(self)),
            instance,
        })
    }

    /// [`reserve_for`](Self::reserve_for) for a local sample pushed into a
    /// ring right away (never held by a reorder gate: no headroom): what it
    /// counts is carried by the ring entry, as [`HistorySlot::into_ring`]
    /// would leave it, and no slot is built (a slot holds the room alive,
    /// one more read-modify-write each way). The place and the instance
    /// count go back the way a ring entry's do.
    pub(crate) fn reserve_in_ring(
        &self,
        instance: Option<[u8; 16]>,
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> Result<(), Bound> {
        self.count_place(0, 0, instance, held_by_a_writer)
            .map(|_| ())
    }

    /// Keep capacity for earlier local Publisher changes still being encoded.
    pub(crate) fn reserve_in_ring_ordered(
        &self,
        keep: usize,
        instance: Option<[u8; 16]>,
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> Result<(), Bound> {
        self.count_place(keep, keep, instance, held_by_a_writer)
            .map(|_| ())
    }

    pub(crate) fn reserve_instance_ordered(
        &self,
        key: [u8; 16],
        keep: usize,
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> Result<(), Bound> {
        let mut taken = self.taken.lock();
        let new = !taken.instances.contains_key(&key);
        self.admit_instance(&mut taken, key, &held_by_a_writer)?;
        if !self.leaves_headroom(&mut taken, key, keep, &held_by_a_writer)
            || self.max_kept.saturating_sub(taken.kept) < keep
        {
            Self::forget_sample(&mut taken, &key, self.max_instances, self.kept_depth());
            if new {
                taken.instances.remove(&key);
            }
            return Err(Bound::GapHeadroom);
        }
        Ok(())
    }

    /// Read-only companion to ordered instance admission, safe under RoomWait.
    pub(crate) fn has_instance_room_ordered(
        &self,
        key: &[u8; 16],
        keep: usize,
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> bool {
        if !self.counts_instances() {
            return true;
        }
        let taken = self.taken.lock();
        let samples = taken.instances.get(key).copied();
        let occupied = taken
            .instances
            .iter()
            .filter(|(other, count)| **count != 0 || **other == *key || held_by_a_writer(other))
            .count();
        let instances = occupied + usize::from(samples.is_none());
        let grows = self
            .kept_depth()
            .is_some_and(|depth| samples.unwrap_or(0) < depth);
        self.max_per_instance.saturating_sub(samples.unwrap_or(0)) > keep
            && self.max_instances.saturating_sub(instances) >= keep
            && self
                .max_kept
                .saturating_sub(taken.kept + usize::from(grows))
                >= keep
    }

    /// The counting of [`reserve_for`](Self::reserve_for): a place and, in
    /// a room that bounds instances, one sample of `instance`. Returns the
    /// instance counted.
    fn count_place(
        &self,
        keep: usize,
        headroom: usize,
        instance: Option<[u8; 16]>,
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> Result<Option<[u8; 16]>, Bound> {
        if !self.counts_instances() {
            // Places alone: one compare-and-swap, the same bound.
            let mut places = self.places.load(Ordering::SeqCst);
            loop {
                if self.capacity.saturating_sub(places) <= keep {
                    return Err(Bound::Samples);
                }
                match self.places.compare_exchange_weak(
                    places,
                    places + 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(now) => places = now,
                }
            }
            return Ok(None);
        }
        // Places and instances under the lock, as one step: every reserver
        // of this room takes it.
        let mut taken = self.taken.lock();
        let free = self
            .capacity
            .saturating_sub(self.places.load(Ordering::SeqCst));
        if free <= keep {
            return Err(Bound::Samples);
        }
        if let Some(key) = instance {
            let new = !taken.instances.contains_key(&key);
            self.admit_instance(&mut taken, key, &held_by_a_writer)?;
            if headroom > 0 && !self.leaves_headroom(&mut taken, key, headroom, &held_by_a_writer) {
                // Leave no trace: the count just taken, and the instance if
                // this sample made it.
                Self::forget_sample(&mut taken, &key, self.max_instances, self.kept_depth());
                if new {
                    taken.instances.remove(&key);
                }
                return Err(Bound::GapHeadroom);
            }
        }
        self.places.fetch_add(1, Ordering::SeqCst);
        drop(taken);
        Ok(instance)
    }

    /// Whether, with one more sample of instance `key` counted, the history
    /// still has room for `headroom` more samples of that instance and
    /// `headroom` more instances. Empty instances no writer holds are forgotten first
    /// if the slots are short.
    fn leaves_headroom(
        &self,
        taken: &mut Held,
        key: [u8; 16],
        headroom: usize,
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> bool {
        let unlimited = crate::reliability::LENGTH_UNLIMITED;
        let samples = taken.instances.get(&key).copied().unwrap_or(0);
        if self.max_per_instance != unlimited
            && self.max_per_instance.saturating_sub(samples) < headroom
        {
            return false;
        }
        if self.max_instances == unlimited {
            return true;
        }
        let slots = |taken: &Held| self.max_instances.saturating_sub(taken.instances.len());
        if slots(taken) >= headroom {
            return true;
        }
        taken
            .instances
            .retain(|other, samples| *other == key || *samples > 0 || held_by_a_writer(other));
        slots(taken) >= headroom
    }

    /// Count one more sample of instance `key` in a room that bounds
    /// instances, taking no place: a sample whose place is bounded
    /// elsewhere (a KEEP_LAST reader's local ring) but whose instance counts
    /// toward `max_instances` and `max_samples_per_instance`. The count goes
    /// back with [`release_instance`](Self::release_instance).
    pub(crate) fn reserve_instance(
        &self,
        key: [u8; 16],
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> Result<(), Bound> {
        if !self.counts_instances() {
            return Ok(());
        }
        self.admit_instance(&mut self.taken.lock(), key, held_by_a_writer)
    }

    /// Whether one more sample of instance `key` would be admitted now
    /// (see [`admit_instance`](Self::admit_instance)), without counting it
    /// nor forgetting any instance.
    pub(crate) fn has_instance_room(
        &self,
        key: &[u8; 16],
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> bool {
        if !self.counts_instances() {
            return true;
        }
        let taken = self.taken.lock();
        let samples = taken.instances.get(key).copied();
        let instance_room = match samples {
            Some(samples) => samples < self.max_per_instance,
            None => {
                taken.instances.len() < self.max_instances
                    || taken
                        .instances
                        .iter()
                        .any(|(key, samples)| *samples == 0 && !held_by_a_writer(key))
            }
        };
        let grows = self
            .kept_depth()
            .is_some_and(|depth| samples.unwrap_or(0) < depth);
        instance_room && !(grows && taken.kept >= self.max_kept)
    }

    /// Count one more sample of instance `key`, or the bound it exceeds.
    fn admit_instance(
        &self,
        taken: &mut Held,
        key: [u8; 16],
        held_by_a_writer: impl Fn(&[u8; 16]) -> bool,
    ) -> Result<(), Bound> {
        if !taken.instances.contains_key(&key) && taken.instances.len() >= self.max_instances {
            taken
                .instances
                .retain(|key, samples| *samples > 0 || held_by_a_writer(key));
            if taken.instances.len() >= self.max_instances {
                return Err(Bound::Instances);
            }
        }
        let samples = taken.instances.entry(key).or_insert(0);
        if *samples >= self.max_per_instance {
            return Err(Bound::SamplesPerInstance);
        }
        // KEEP_LAST: a sample beyond `depth` replaces the oldest of its
        // instance; one below grows the history, which `max_samples` bounds
        // (DDS v1.4 Sec.2.2.3.19).
        let grows = self.kept_depth().is_some_and(|depth| *samples < depth);
        if grows && taken.kept >= self.max_kept {
            return Err(Bound::Kept);
        }
        *samples += 1;
        if grows {
            taken.kept += 1;
        }
        Ok(())
    }

    /// One sample of instance `key` left the history: taken, replaced, or
    /// dropped on the way. Its place, if it held one, is given back
    /// separately.
    pub(crate) fn release_instance(&self, key: &[u8; 16]) {
        {
            let mut taken = self.taken.lock();
            Self::forget_sample(&mut taken, key, self.max_instances, self.kept_depth());
        }
        self.came_back();
    }

    fn forget_sample(
        taken: &mut Held,
        key: &[u8; 16],
        max_instances: usize,
        kept_depth: Option<usize>,
    ) {
        let Some(samples) = taken.instances.get_mut(key) else {
            debug_assert!(false, "an instance sample given back twice");
            return;
        };
        debug_assert!(*samples > 0, "an instance sample given back twice");
        *samples = samples.saturating_sub(1);
        if kept_depth.is_some_and(|depth| *samples < depth) {
            taken.kept = taken.kept.saturating_sub(1);
        }
        // Without a bound on instances an empty one is never asked about
        // again: forget it now.
        if *samples == 0 && max_instances == crate::reliability::LENGTH_UNLIMITED {
            taken.instances.remove(key);
        }
    }

    /// The place of an entry just popped from the network ring: every entry
    /// there was pushed by [`HistorySlot::into_ring`], which kept its place
    /// counted. Nothing is counted here; the place is given back when the
    /// returned slot is dropped.
    pub(crate) fn adopt(self: &Arc<Self>) -> HistorySlot {
        HistorySlot {
            room: Some(Arc::clone(self)),
            instance: None,
        }
    }

    /// The place, and the instance count of `instance` when the room counts
    /// instances, of a ring entry just dropped for a newer sample of the
    /// same instance, handed to that sample: nothing is given back nor
    /// counted, the newer sample holds what the older held.
    pub(crate) fn hand_over(self: &Arc<Self>, instance: Option<[u8; 16]>) -> HistorySlot {
        HistorySlot {
            room: Some(Arc::clone(self)),
            instance: instance.filter(|_| self.counts_instances()),
        }
    }

    /// Give back the places of `count` samples that left a sample cache
    /// (see [`HistorySlot::into_cache`]). One lock for the whole batch.
    pub(crate) fn give_back(&self, count: usize) {
        if count == 0 {
            return;
        }
        self.give_back_places(count);
        self.came_back();
    }

    /// Whether [`reserve_for`](Self::reserve_for) with `keep` would find a
    /// place free now, without taking it.
    pub(crate) fn has_place(&self, keep: usize) -> bool {
        self.free() > keep
    }

    /// The places not taken now. A snapshot: another producer may take
    /// one the next instant.
    pub(crate) fn free(&self) -> usize {
        self.capacity
            .saturating_sub(self.places.load(Ordering::SeqCst))
    }

    /// Give back `count` places.
    fn give_back_places(&self, count: usize) {
        let before = self.places.fetch_sub(count, Ordering::SeqCst);
        // Every place given back was counted by `reserve`: more than that
        // would grant places that do not exist.
        debug_assert!(before >= count, "a history place given back twice");
        if before < count {
            self.places.fetch_add(count - before, Ordering::SeqCst);
        }
    }

    /// Tests only: the samples counted for all instances.
    #[cfg(test)]
    pub(crate) fn instance_samples(&self) -> usize {
        self.taken.lock().instances.values().sum()
    }

    #[cfg(test)]
    pub(crate) fn taken(&self) -> usize {
        self.places.load(Ordering::SeqCst)
    }
}

/// One sample's place in its reader's history, from its admission until the
/// application takes it or it is discarded. Given back on drop.
pub(crate) struct HistorySlot {
    /// `None` once the place was handed to a ring entry.
    room: Option<Arc<HistoryRoom>>,
    /// The instance this slot counts a sample of, in a room that bounds
    /// instances ([`HistoryRoom::reserve_for`]).
    instance: Option<[u8; 16]>,
}

impl HistorySlot {
    /// The sample is in the network ring now: its entry carries the place,
    /// and its instance count, until [`HistoryRoom::adopt`] takes the place
    /// back out with the entry (the reader that pops it gives the instance
    /// count to the cached sample, or back to the room).
    pub(crate) fn into_ring(mut self) {
        self.room = None;
        self.instance = None;
    }

    /// The sample is in the sample cache of a reader whose history is
    /// `room`: the cached sample keeps the place counted as a flag, and the
    /// cache gives it back with [`HistoryRoom::give_back`] when the sample
    /// leaves it. Returns whether the slot held a place of `room`; a slot of
    /// another room (never built by the reader) is given back to its own
    /// room here, so the counts stay exact and the sample holds no place.
    pub(crate) fn into_cache(mut self, room: &Arc<HistoryRoom>) -> bool {
        // The cache counts instances with its own flag: a slot that came
        // out of the ring (`HistoryRoom::adopt`) carries none.
        debug_assert!(self.instance.is_none(), "an instance count into a cache");
        match self.room.take() {
            Some(own) if Arc::ptr_eq(&own, room) => true,
            other => {
                debug_assert!(other.is_none(), "a place handed to another room's cache");
                self.room = other;
                false
            }
        }
    }
}

/// The instance of a sample a reader stored in its network ring, `None`
/// when its bytes do not decode.
pub(crate) fn ring_entry_instance<T: crate::dds::DDS>(
    entry: &rt::IndexEntry,
    slab_pool: &rt::SlabPool,
) -> Option<[u8; 16]> {
    if !T::has_key() {
        return Some([0; 16]);
    }
    let buf = slab_pool.get_buffer(entry.handle);
    let len = (entry.len as usize).min(buf.len());
    let prefix = entry.payload_offset();
    let start = if prefix != 0 && len >= prefix {
        prefix
    } else {
        0
    };
    T::decode(&buf[start..len], entry.cdr_version)
        .ok()
        .map(|msg| msg.compute_key())
}

/// What a sample becomes once it is decoded, filtered and copied into the
/// slab pool for the application, before the reader acknowledges it.
///
/// A RELIABLE reader must hold the storage a sample needs before it credits
/// the sample (see the module comment): storing after the credit made a
/// sample the slab pool refused lost for good, the writer never asked for
/// it again. The storage is taken where the history place is taken, and
/// travels with the sample through the reorder gate.
pub(crate) enum Prepared {
    /// The sample is in the slab pool, ready to be pushed to the ring.
    Stored(StoredSample),
    /// The sample was received but delivers nothing: it does not decode or
    /// the content filter rejects it. Received all
    /// the same, so it is acknowledged; it still passes the reorder gate so
    /// the gate does not wait for it.
    Discard,
    /// The sample decodes but cannot be re-encoded for the ring: received,
    /// delivers nothing, and its writer, which still writes instance `key`,
    /// is recorded as such when it leaves the gate.
    Unstorable { key: [u8; 16] },
    /// A dispose or unregister that is a member of a coherent set (RTPS v2.5
    /// Sec.8.7.6, `ReaderSubscriber::on_lifecycle_coherent`): no sample; the
    /// instance's transition is applied when the set is delivered, in the
    /// set's order.
    Lifecycle {
        key: [u8; 16],
        kind: crate::engine::subscriber::DisposeKind,
    },
}

impl Prepared {
    /// Attach a D=1 lifecycle even when the DATA's value was filtered out.
    pub(crate) fn with_inline_lifecycle<T: crate::dds::DDS>(
        mut self,
        lifecycle: Option<([u8; 16], crate::engine::subscriber::DisposeKind)>,
    ) -> Self {
        let Some((key, kind)) = lifecycle else {
            return self;
        };
        match &mut self {
            Self::Stored(stored) => {
                let key = stored
                    .msg
                    .downcast_ref::<T>()
                    .map_or(key, crate::dds::DDS::compute_key);
                stored.inline_lifecycle = Some((key, kind));
                self
            }
            Self::Discard => Self::Lifecycle { key, kind },
            Self::Unstorable { key } => Self::Lifecycle { key: *key, kind },
            Self::Lifecycle { .. } => self,
        }
    }

    /// Keep the storage of a sample acknowledged before it can be taken
    /// ([`StoredSample::hold`]); a sample with no storage needs none.
    pub(crate) fn hold(&mut self, head: usize) -> bool {
        match self {
            Prepared::Stored(stored) => stored.hold(head),
            Prepared::Discard | Prepared::Unstorable { .. } | Prepared::Lifecycle { .. } => true,
        }
    }

    pub(crate) fn slab_handle(&self) -> Option<rt::SlabHandle> {
        match self {
            Prepared::Stored(stored) => stored.handle,
            _ => None,
        }
    }

    /// The length of its storage, if it has any.
    pub(crate) fn stored_len(&self) -> Option<usize> {
        match self {
            Prepared::Stored(stored) => stored
                .handle
                .map(|_| usize::try_from(stored.len).unwrap_or(usize::MAX)),
            Prepared::Discard | Prepared::Unstorable { .. } | Prepared::Lifecycle { .. } => None,
        }
    }

    /// The decoded sample, when it was stored by a reader of `T`.
    pub(crate) fn sample<T: 'static>(&self) -> Option<&T> {
        match self {
            Prepared::Stored(stored) => stored.msg.downcast_ref::<T>(),
            Prepared::Discard | Prepared::Unstorable { .. } | Prepared::Lifecycle { .. } => None,
        }
    }
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Prepared::Stored(_) => f.write_str("Prepared::Stored"),
            Prepared::Discard => f.write_str("Prepared::Discard"),
            Prepared::Unstorable { .. } => f.write_str("Prepared::Unstorable"),
            Prepared::Lifecycle { .. } => f.write_str("Prepared::Lifecycle"),
        }
    }
}

/// A sample copied into the slab pool, with its decoded value. Its slab
/// buffer is released when it is dropped, wherever the sample is discarded
/// on the way to the ring.
pub(crate) struct StoredSample {
    /// A legacy wire hash captured while preparing this exact sample.
    pub(crate) legacy_key_hash: Option<[u8; 16]>,
    /// A lifecycle carried by the same DATA, applied after its value at release.
    pub(crate) inline_lifecycle: Option<([u8; 16], crate::engine::subscriber::DisposeKind)>,
    /// `None` once taken by [`StoredSample::take`].
    handle: Option<rt::SlabHandle>,
    len: u32,
    /// The decoded sample, a `T` of the reader that stored it.
    msg: Box<dyn std::any::Any + Send>,
    /// What [`rt::SlabPool::hold`] charged while the sample cannot be
    /// taken (held by the reorder gate above a gap): given back when this
    /// is dropped, taken for the ring or discarded.
    held: Option<usize>,
}

impl StoredSample {
    pub(crate) fn new(
        handle: rt::SlabHandle,
        len: u32,
        msg: Box<dyn std::any::Any + Send>,
    ) -> Self {
        Self {
            legacy_key_hash: None,
            inline_lifecycle: None,
            handle: Some(handle),
            len,
            msg,
            held: None,
        }
    }

    /// Keep this storage for a sample acknowledged before it can be taken
    /// ([`rt::SlabPool::hold`]), leaving room for a head of `head` bytes;
    /// whether it is kept. Refused, the sample must be refused before it is
    /// acknowledged.
    pub(crate) fn hold(&mut self, head: usize) -> bool {
        if self.held.is_some() {
            return true;
        }
        let Some(handle) = self.handle else {
            return false;
        };
        let len = usize::try_from(self.len).unwrap_or(usize::MAX);
        self.held = rt::get_slab_pool_ref().hold(handle, len, head);
        self.held.is_some()
    }

    /// Give back what a hold charged.
    fn unhold(&mut self) {
        if let Some(charged) = self.held.take() {
            rt::get_slab_pool_ref().unhold(charged);
        }
    }

    /// The slab buffer, its length and the decoded sample; `None` (the
    /// buffer released) for a sample that is not a `T`, which only a reader
    /// of another type could have stored.
    pub(crate) fn take<T: 'static>(mut self) -> Option<(rt::SlabHandle, u32, T)> {
        let handle = self.handle.take()?;
        let msg = std::mem::replace(&mut self.msg, Box::new(()));
        match msg.downcast::<T>() {
            Ok(msg) => Some((handle, self.len, *msg)),
            Err(_) => {
                debug_assert!(false, "a stored sample of another type");
                rt::get_slab_pool_ref().release(handle);
                None
            }
        }
    }
}

impl Drop for StoredSample {
    fn drop(&mut self) {
        self.unhold();
        if let Some(handle) = self.handle.take() {
            rt::get_slab_pool_ref().release(handle);
        }
    }
}

impl HistorySlot {
    /// Give the place (and instance count) back without scheduling a retry
    /// of the sets waiting for room: for a commit that takes the places of
    /// a whole set, all or none, and lets go of those it took when one is
    /// refused. Through `came_back`, the retry that commit runs in would be
    /// scheduled again by its own refusal, and again, for as long as the set
    /// does not fit.
    ///
    /// The local writers waiting for room are woken all the same
    /// ([`RoomWait`]): the room is back for them.
    pub(crate) fn give_back_quietly(mut self) {
        if let Some(room) = self.room.take() {
            room.give_back_places(1);
            if let Some(key) = self.instance.take() {
                let mut taken = room.taken.lock();
                HistoryRoom::forget_sample(&mut taken, &key, room.max_instances, room.kept_depth());
            }
            if let Some(wait) = room.wait.as_ref() {
                wait.freed();
            }
        }
    }
}

impl Drop for HistorySlot {
    fn drop(&mut self) {
        if let Some(room) = self.room.take() {
            // Every slot given back was counted by `reserve`: one more
            // `adopt` than `into_ring` would grant a place that does not
            // exist.
            room.give_back_places(1);
            if let Some(key) = self.instance.take() {
                let mut taken = room.taken.lock();
                HistoryRoom::forget_sample(&mut taken, &key, room.max_instances, room.kept_depth());
            }
            room.came_back();
        }
    }
}

impl std::fmt::Debug for HistorySlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HistorySlot")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_room_retry_cannot_miss_capacity_returned_during_arming() {
        let wait = super::RoomWait::new();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        wait.retry_when_room(
            std::sync::Arc::new(move || {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
            &mut || {
                // The return races the probe, after registration.
                wait.freed();
                true
            },
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        wait.freed();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn a_room_retry_probes_after_capacity_was_already_returned() {
        let wait = super::RoomWait::new();
        wait.freed();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        wait.retry_when_room(
            std::sync::Arc::new(move || {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
            &mut || false,
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    use super::*;

    fn room(capacity: usize) -> Arc<HistoryRoom> {
        HistoryRoom::new(
            &rt::IndexRing::with_capacity(capacity),
            crate::reliability::LENGTH_UNLIMITED,
        )
    }

    #[test]
    fn a_slot_is_given_back_when_it_is_dropped() {
        let room = room(4);
        let slot = room.reserve(0).expect("room");
        assert_eq!(room.taken(), 1);
        drop(slot);
        assert_eq!(room.taken(), 0);
    }

    #[test]
    fn a_place_stays_taken_through_the_ring_until_the_sample_leaves_the_history() {
        let room = room(4);
        assert_eq!(room.capacity, 3);
        room.reserve(0).expect("first of three").into_ring();
        room.reserve(0).expect("second of three").into_ring();
        let cached = room.adopt();
        assert_eq!(room.taken(), 2, "moving out of the ring gives nothing back");
        let _third = room.reserve(0).expect("third of three");
        assert!(
            room.reserve(0).is_none(),
            "full: one in the ring, one in the cache, one on its way"
        );
        drop(cached);
        assert!(
            room.reserve(0).is_some(),
            "taking a sample gives its place back"
        );
    }

    #[test]
    fn max_samples_bounds_the_room_within_the_ring() {
        let ring = rt::IndexRing::with_capacity(8);
        assert_eq!(HistoryRoom::new(&ring, 3).capacity, 3);
        assert_eq!(HistoryRoom::new(&ring, 7).capacity, 7);
        assert_eq!(
            HistoryRoom::new(&ring, 8).capacity,
            7,
            "the ring's usable capacity"
        );
        assert_eq!(
            HistoryRoom::new(&ring, crate::reliability::LENGTH_UNLIMITED).capacity,
            7
        );
        let room = HistoryRoom::new(&ring, 2);
        let _first = room.reserve(0).expect("one of two");
        let _second = room.reserve(0).expect("two of two");
        assert!(room.reserve(0).is_none(), "at max_samples");
    }

    #[test]
    fn a_place_handed_to_the_ring_does_not_keep_the_room_alive() {
        let room = room(4);
        room.reserve(0).expect("room").into_ring();
        assert_eq!(Arc::strong_count(&room), 1);
        drop(room.adopt());
        assert_eq!(Arc::strong_count(&room), 1);
        assert_eq!(room.taken(), 0);
    }

    #[test]
    fn a_held_sample_leaves_a_place_for_every_awaited_one() {
        let room = room(8);
        assert_eq!(room.capacity, 7);
        let _held = room.reserve(3).expect("seven free, three kept");
        let _held = room.reserve(3).expect("six free, three kept");
        let _held = room.reserve(3).expect("five free, three kept");
        let _held = room.reserve(3).expect("four free, three kept");
        assert!(
            room.reserve(3).is_none(),
            "three free: the three awaited ones need them"
        );
        let _awaited = room.reserve(0).expect("an awaited sample");
        let _awaited = room.reserve(0).expect("an awaited sample");
        let _awaited = room.reserve(0).expect("the last awaited sample");
        assert!(room.reserve(0).is_none(), "full");
    }
}
