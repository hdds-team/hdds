// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DEADLINE (DDS v1.4 Sec.2.2.3.7), evaluated on the participant's
//! liveliness scheduler, per INSTANCE: a reader instance that gets no new
//! sample within its deadline period raises REQUESTED_DEADLINE_MISSED
//! (Sec.2.2.4.1); a writer instance not written within its period raises
//! OFFERED_DEADLINE_MISSED. Both are one heap entry per instance, on the
//! SAME scheduler thread, clock and heap as LIVELINESS (`super::scheduler`,
//! `super::leases::Core`): an application blocked on a WaitSet, or one
//! relying only on a listener, is now told even if it never calls
//! take()/read()/write() again.
//!
//! Sec.2.2.4.1: "each deadline period the total_count will be incremented
//! by one for each instance for which data was not received" -- a missed
//! instance keeps firing every period while it stays silent, unlike a
//! LIVELINESS watch's one-shot not-alive transition. A fired entry is
//! therefore always re-armed while it is watched, for its own next
//! period, computed from the period boundary just evaluated (not from
//! "now"): a scheduler that runs late still reports one event per elapsed
//! period, not one event per wake-up (`Core::fire_deadline`).
//!
//! Disposal ends an instance's existence (DDS v1.4 Sec.2.2.3.23.3), so
//! its watch stops. A reader retains its watch in NOT_ALIVE_NO_WRITERS:
//! Sec.2.2.3.23.2 uses DEADLINE to report lost periodic connectivity.
//! Removing the reader's instance information also stops its watch.
//! A writer stops watching on disposal or unregistration, which ends its
//! responsibility to update. A later sample/write starts a new watch.
//!
//! The write()/take() lazy check (`Shared::check_deadline`) and the
//! scheduler's firing (`Core::advance`) run the exact same per-entry
//! evaluation (`Core::fire_deadline`/`Core::check_deadline_now`, both
//! built on `Core::deadline_due`), under the same state lock: whichever
//! runs first for an entry consumes its due miss and re-arms it, so the
//! other finds nothing left to report. No separate bookkeeping, so no
//! double counting between the two paths.
//!
//! Hot path cost (DDS v1.4 Sec.2.2.3.7, "infinite" default): an infinite
//! deadline never creates a [`ReaderDeadlines`]/[`WriterDeadlines`] at all
//! (same `*_enabled` gate as before asynchronous detection) -- zero cost. A finite
//! one uses a map lookup and a per-instance publication lock for the
//! clock capture and relaxed timestamp store. The writer's lazy check
//! evaluates only the written instance under the scheduler state lock;
//! no operation scans other instances on write. Nothing is added to
//! `CachedSample`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use super::clock::{lease_nanos, Nanos};
use super::leases::WatchKey;
use super::scheduler::Shared;
use crate::dds::listener::{OfferedDeadlineMissedStatus, RequestedDeadlineMissedStatus};
use crate::dds::reader::notices::{Notice, Ordered};
use crate::dds::reader::InstanceHandle;
use crate::dds::{StatusCondition, StatusMask};

/// The instant one instance last got a sample (reader) or was written
/// (writer): one relaxed store per sample/write on the hot path, read by
/// the scheduler and by the lazy check. The publication lock covers the
/// clock capture and timestamp store; evaluation takes the same lock. A
/// late update leaves a pending timestamp until old periods are counted.
pub(crate) struct InstanceDeadline {
    last: AtomicU64,
    // The clock capture and store are atomic with respect to evaluation.
    // A late arrival is published here until its old periods are counted.
    // Endpoint updates retain their instance-map lock until evaluation
    // finishes, so another update cannot overwrite a pending timestamp.
    pub(super) publication: Mutex<Option<Nanos>>,
}

impl InstanceDeadline {
    pub(crate) fn new(now: Nanos) -> Arc<Self> {
        Arc::new(Self {
            last: AtomicU64::new(now),
            publication: Mutex::new(None),
        })
    }

    /// Publish arrival before evaluation can pass it. A late arrival
    /// carries its timestamp to the common evaluator, which counts only
    /// periods preceding that arrival before restarting the period.
    fn update(&self, shared: &Shared, period: Duration) -> Option<Nanos> {
        let mut publication = self.publication.lock().unwrap_or_else(|e| e.into_inner());
        let now = shared.now();
        if now >= self.last().saturating_add(lease_nanos(period)) {
            *publication = Some(now);
            Some(now)
        } else {
            self.touch(now);
            None
        }
    }

    /// A sample arrived, or the instance was written, now. Concurrent
    /// publication and evaluation hold `publication`.
    #[inline]
    pub(crate) fn touch(&self, now: Nanos) {
        self.last.store(now, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn last(&self) -> Nanos {
        self.last.load(Ordering::Relaxed)
    }
}

/// A reader that parks TIME_BASED_FILTER samples (DDS v1.4 Sec.2.2.3.12).
/// The scheduler calls `wake` at the instant a parked sample's window ends;
/// it returns the queue the wake is told on, never run on the scheduler.
/// The sample itself is not touched there: the reader shows it at its next
/// access, and the wake only tells the application one is due.
pub(crate) trait FilterWakeSink: Send + Sync {
    fn wake(&self, handle: InstanceHandle) -> Option<Arc<Ordered>>;
}

/// What a DEADLINE watch's firing tells: `handle`'s instance missed one
/// period (DDS v1.4 Sec.2.2.4.1). Returns the queue of application calls
/// this filled: the scheduler path tells it on a thread of its own
/// (never the scheduler's, same rule as `LivelinessSink`); the lazy path
/// (`Shared::check_deadline`) tells it inline, on the caller's own
/// take()/write() thread, exactly as the previous lazy check did.
pub(crate) trait DeadlineSink: Send + Sync {
    fn missed(&self, handle: InstanceHandle) -> Option<Arc<Ordered>>;
}

/// One instance's watch: its own lease-style timer on the scheduler
/// (`Shared::watch_deadline`) and the queue entry here, paired so
/// `remove_instance`/`close` can unwatch exactly what was armed.
struct Entry {
    key: WatchKey,
    cell: Arc<InstanceDeadline>,
}

pub(crate) type ReaderDeadlineListener =
    Box<dyn Fn(RequestedDeadlineMissedStatus) -> Option<Notice> + Send + Sync>;

/// A reader's per-instance DEADLINE watches (DDS v1.4 Sec.2.2.3.7):
/// REQUESTED_DEADLINE_MISSED (Sec.2.2.4.1) when an instance's period
/// elapses with no new sample. `None` on the reader when its QoS deadline
/// is infinite (no `ReaderDeadlines` created at all): see the module doc.
pub(crate) struct ReaderDeadlines {
    shared: Arc<Shared>,
    me: Weak<ReaderDeadlines>,
    period: Duration,
    instances: Mutex<HashMap<InstanceHandle, Entry>>,
    closed: AtomicBool,
    condition: Arc<StatusCondition>,
    listener: ReaderDeadlineListener,
    notices: Arc<Ordered>,
    status: Mutex<RequestedDeadlineMissedStatus>,
}

impl ReaderDeadlines {
    pub(crate) fn new(
        shared: Arc<Shared>,
        period: Duration,
        condition: Arc<StatusCondition>,
        listener: ReaderDeadlineListener,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            shared,
            me: me.clone(),
            period,
            instances: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            condition,
            listener,
            notices: Arc::default(),
            status: Mutex::new(RequestedDeadlineMissedStatus::default()),
        })
    }

    fn sink(&self) -> Weak<dyn DeadlineSink> {
        let me: Weak<dyn DeadlineSink> = self.me.clone();
        me
    }

    /// A sample of `handle` arrived, now: its DEADLINE period (Sec.2.2.3.7)
    /// restarts here. A timely update publishes under its instance lock;
    /// a NEW one is registered with the scheduler, its period starting
    /// now -- an instance never missed before it was ever seen. "Now" is
    /// always the scheduler's own clock (`Shared::now`), read here rather
    /// than taken from the caller: the instant compared against a
    /// watch's expiry must come from the same clock as the watch itself,
    /// never a reader-local timestamp (e.g. `current_time_ns`, used for
    /// LIFESPAN) that could run ahead of or behind it.
    pub(crate) fn on_sample(&self, handle: InstanceHandle) {
        let mut instances = self.instances.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        if let Some(entry) = instances.get(&handle) {
            if let Some(now) = entry.cell.update(&self.shared, self.period) {
                self.shared.touch_deadline(entry.key, now);
            }
            return;
        }
        let now = self.shared.now();
        let cell = InstanceDeadline::new(now);
        let key = self
            .shared
            .watch_deadline(Arc::clone(&cell), handle, self.period, self.sink());
        instances.insert(handle, Entry { key, cell });
    }

    /// Tests only: whether `handle`'s DEADLINE is watched.
    #[cfg(test)]
    pub(crate) fn watches(&self, handle: InstanceHandle) -> bool {
        self.instances
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&handle)
    }

    /// `handle` was disposed or its instance information was removed:
    /// see the module doc for why its watch stops.
    pub(crate) fn remove_instance(&self, handle: InstanceHandle) {
        let removed = self
            .instances
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&handle);
        if let Some(entry) = removed {
            self.shared.finish_deadline(entry.key);
        }
    }

    /// The lazy take()/read() check (`DataReader::check_requested_deadline`):
    /// re-evaluate every instance this reader currently watches, right
    /// now -- see the module doc on why this is safe against the
    /// scheduler running concurrently.
    pub(crate) fn check_now(&self) {
        let keys: Vec<WatchKey> = {
            let instances = self.instances.lock().unwrap_or_else(|e| e.into_inner());
            instances.values().map(|e| e.key).collect()
        };
        for key in keys {
            self.shared.check_deadline(key);
        }
    }

    /// The REQUESTED_DEADLINE_MISSED status (DDS v1.4 Sec.2.2.4.2.1):
    /// reading it resets its change.
    pub(crate) fn status(&self) -> RequestedDeadlineMissedStatus {
        let mut status = self.state();
        let snapshot = status.clone();
        status.total_count_change = 0;
        self.condition
            .clear_active_status(StatusMask::REQUESTED_DEADLINE_MISSED);
        snapshot
    }

    fn state(&self) -> std::sync::MutexGuard<'_, RequestedDeadlineMissedStatus> {
        self.status.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Nothing more is watched (the reader is deleted), and nothing more
    /// reaches its listener.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.notices.close();
        let keys: Vec<WatchKey> = {
            let mut instances = self.instances.lock().unwrap_or_else(|e| e.into_inner());
            instances.drain().map(|(_, e)| e.key).collect()
        };
        for key in keys {
            self.shared.unwatch_deadline(key);
        }
    }
}

impl DeadlineSink for ReaderDeadlines {
    fn missed(&self, handle: InstanceHandle) -> Option<Arc<Ordered>> {
        let mut status = self.state();
        status.total_count = status.total_count.saturating_add(1);
        status.total_count_change = status.total_count_change.saturating_add(1);
        status.last_instance_handle = Some(handle);
        let snapshot = status.clone();
        let notice = match (self.listener)(snapshot) {
            Some(call) => {
                status.total_count_change = 0;
                self.condition
                    .clear_active_status(StatusMask::REQUESTED_DEADLINE_MISSED);
                call
            }
            None => {
                self.condition
                    .raise_active_statuses(StatusMask::REQUESTED_DEADLINE_MISSED);
                let condition = Arc::clone(&self.condition);
                Box::new(move || {
                    condition.notify_waitsets_for(StatusMask::REQUESTED_DEADLINE_MISSED)
                })
            }
        };
        let overflow = self.notices.push(notice).err();
        drop(status);
        if let Some(notice) = overflow {
            // A full queue: told on a thread of its own all the same
            // (same fallback as `ReaderLiveliness::transition`).
            let spawned = std::thread::Builder::new()
                .name("hdds-notices".to_string())
                .spawn(notice);
            if let Err(e) = spawned {
                log::error!(
                    "[liveliness] a REQUESTED_DEADLINE_MISSED call is lost: no thread ({e})"
                );
            }
        }
        Some(Arc::clone(&self.notices))
    }
}

impl Drop for ReaderDeadlines {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) type WriterDeadlineListener =
    Box<dyn Fn(OfferedDeadlineMissedStatus) -> Option<Notice> + Send + Sync>;

/// A writer's per-instance DEADLINE watches (DDS v1.4 Sec.2.2.3.7):
/// OFFERED_DEADLINE_MISSED (Sec.2.2.4.1) when an instance goes unwritten
/// past its period. `None` on the writer when its QoS deadline is
/// infinite: see the module doc.
pub(crate) struct WriterDeadlines {
    shared: Arc<Shared>,
    me: Weak<WriterDeadlines>,
    period: Duration,
    // Only a standalone writer must evaluate its other instances lazily.
    lazy_only: bool,
    // None retains a disposed registration without an active watch.
    instances: Mutex<HashMap<InstanceHandle, Option<Entry>>>,
    closed: AtomicBool,
    condition: Arc<StatusCondition>,
    listener: WriterDeadlineListener,
    notices: Arc<Ordered>,
    status: Mutex<OfferedDeadlineMissedStatus>,
}

impl WriterDeadlines {
    pub(crate) fn new(
        shared: Arc<Shared>,
        period: Duration,
        condition: Arc<StatusCondition>,
        listener: WriterDeadlineListener,
        lazy_only: bool,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            shared,
            me: me.clone(),
            period,
            lazy_only,
            instances: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            condition,
            listener,
            notices: Arc::default(),
            status: Mutex::new(OfferedDeadlineMissedStatus::default()),
        })
    }

    fn sink(&self) -> Weak<dyn DeadlineSink> {
        let me: Weak<dyn DeadlineSink> = self.me.clone();
        me
    }

    /// Explicit registration manages an instance before its first write
    /// (DDS v1.4 Sec.2.2.3.21). Repeated registration is not an update.
    pub(crate) fn register_instance(&self, handle: InstanceHandle) {
        let mut instances = self.instances.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        if let std::collections::hash_map::Entry::Vacant(slot) = instances.entry(handle) {
            let cell = InstanceDeadline::new(self.shared.now());
            let key =
                self.shared
                    .watch_deadline(Arc::clone(&cell), handle, self.period, self.sink());
            slot.insert(Some(Entry { key, cell }));
        }
    }

    /// `handle` was written, now: its DEADLINE period (Sec.2.2.3.7)
    /// restarts here. See `ReaderDeadlines::on_sample` on why "now" is
    /// always read from the scheduler's own clock here, not the caller's.
    pub(crate) fn on_write(&self, handle: InstanceHandle) {
        let mut instances = self.instances.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        if let Some(Some(entry)) = instances.get(&handle) {
            if let Some(now) = entry.cell.update(&self.shared, self.period) {
                self.shared.touch_deadline(entry.key, now);
            }
            return;
        }
        let now = self.shared.now();
        let cell = InstanceDeadline::new(now);
        let key = self
            .shared
            .watch_deadline(Arc::clone(&cell), handle, self.period, self.sink());
        instances.insert(handle, Some(Entry { key, cell }));
    }

    /// Disposal ends existence but retains registration (DDS v1.4
    /// Sec.2.2.3.23.3). An idempotent register cannot restart this timer.
    pub(crate) fn dispose_instance(&self, handle: InstanceHandle) {
        let removed = {
            let mut instances = self.instances.lock().unwrap_or_else(|e| e.into_inner());
            if self.closed.load(Ordering::Relaxed) {
                return;
            }
            instances.insert(handle, None).flatten()
        };
        if let Some(entry) = removed {
            self.shared.finish_deadline(entry.key);
        }
    }

    /// Unregistration ends the writer association as well as its timer.
    pub(crate) fn remove_instance(&self, handle: InstanceHandle) {
        let removed = self
            .instances
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&handle)
            .flatten();
        if let Some(entry) = removed {
            self.shared.finish_deadline(entry.key);
        }
    }

    /// A participant's scheduler handles silent instances independently,
    /// so its lazy write path evaluates only the written instance. A
    /// standalone writer has no scheduler: check every active instance
    /// there, using the same per-watch evaluation and notification policy.
    pub(crate) fn check_instance(&self, handle: InstanceHandle) {
        if self.lazy_only {
            let keys: Vec<_> = self
                .instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .filter_map(|entry| entry.as_ref().map(|entry| entry.key))
                .collect();
            for key in keys {
                self.shared.check_deadline(key);
            }
            return;
        }
        let key = self
            .instances
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&handle)
            .and_then(Option::as_ref)
            .map(|entry| entry.key);
        if let Some(key) = key {
            self.shared.check_deadline(key);
        }
    }

    /// The OFFERED_DEADLINE_MISSED status (DDS v1.4 Sec.2.2.4.2.1): reading
    /// it resets its change.
    pub(crate) fn status(&self) -> OfferedDeadlineMissedStatus {
        let mut status = self.state();
        let snapshot = status.clone();
        status.total_count_change = 0;
        self.condition
            .clear_active_status(StatusMask::OFFERED_DEADLINE_MISSED);
        snapshot
    }

    fn state(&self) -> std::sync::MutexGuard<'_, OfferedDeadlineMissedStatus> {
        self.status.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Nothing more is watched (the writer is deleted), and nothing more
    /// reaches its listener.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.notices.close();
        let keys: Vec<WatchKey> = {
            let mut instances = self.instances.lock().unwrap_or_else(|e| e.into_inner());
            instances
                .drain()
                .filter_map(|(_, e)| e.map(|entry| entry.key))
                .collect()
        };
        for key in keys {
            self.shared.unwatch_deadline(key);
        }
    }
}

impl DeadlineSink for WriterDeadlines {
    fn missed(&self, handle: InstanceHandle) -> Option<Arc<Ordered>> {
        let mut status = self.state();
        status.total_count = status.total_count.saturating_add(1);
        status.total_count_change = status.total_count_change.saturating_add(1);
        status.last_instance_handle = Some(handle);
        let snapshot = status.clone();
        let notice = match (self.listener)(snapshot) {
            Some(call) => {
                status.total_count_change = 0;
                self.condition
                    .clear_active_status(StatusMask::OFFERED_DEADLINE_MISSED);
                call
            }
            None => {
                self.condition
                    .raise_active_statuses(StatusMask::OFFERED_DEADLINE_MISSED);
                let condition = Arc::clone(&self.condition);
                Box::new(move || condition.notify_waitsets_for(StatusMask::OFFERED_DEADLINE_MISSED))
            }
        };
        let overflow = self.notices.push(notice).err();
        drop(status);
        if let Some(notice) = overflow {
            let spawned = std::thread::Builder::new()
                .name("hdds-notices".to_string())
                .spawn(notice);
            if let Err(e) = spawned {
                log::error!(
                    "[liveliness] an OFFERED_DEADLINE_MISSED call is lost: no thread ({e})"
                );
            }
        }
        Some(Arc::clone(&self.notices))
    }
}

impl Drop for WriterDeadlines {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::liveliness::LivelinessClock;
    use std::sync::mpsc;

    // DDS v1.4 Sec.2.2.3.7: an update at 90 ms meets a 100 ms period,
    // even when its publication is delayed across evaluation at 100 ms.
    #[test]
    fn timely_publication_is_arbitrated_for_reader_and_writer() {
        struct Clock {
            now: AtomicU64,
            captured: mpsc::SyncSender<()>,
            resume: Mutex<mpsc::Receiver<()>>,
        }
        impl LivelinessClock for Clock {
            fn now(&self) -> Nanos {
                let now = self.now.load(Ordering::SeqCst);
                if std::thread::current().name() == Some("deadline-arrival") {
                    self.captured.send(()).unwrap();
                    self.resume.lock().unwrap().recv().unwrap();
                }
                now
            }
            fn sleep_for(&self, _: Nanos) -> Option<Duration> {
                None
            }
        }
        for (writer_side, arrival_ms, evaluation_ms, expected) in [
            (false, 90, 100, 0),
            (true, 90, 100, 0),
            (false, 190, 200, 1),
            (true, 190, 200, 1),
        ] {
            let (captured, seen) = mpsc::sync_channel(0);
            let (resume, paused) = mpsc::channel();
            let clock = Arc::new(Clock {
                now: AtomicU64::new(0),
                captured,
                resume: Mutex::new(paused),
            });
            let shared = Shared::new(clock.clone());
            let reader = ReaderDeadlines::new(
                shared.clone(),
                Duration::from_millis(100),
                Arc::new(StatusCondition::new()),
                Box::new(|_| None),
            );
            let writer = WriterDeadlines::new(
                shared.clone(),
                Duration::from_millis(100),
                Arc::new(StatusCondition::new()),
                Box::new(|_| None),
                false,
            );
            let handle = InstanceHandle::new([1; 16]);
            let (_key, cell) = if writer_side {
                writer.on_write(handle);
                let instances = writer.instances.lock().unwrap();
                let entry = instances.get(&handle).unwrap().as_ref().unwrap();
                (entry.key, entry.cell.clone())
            } else {
                reader.on_sample(handle);
                let instances = reader.instances.lock().unwrap();
                let entry = instances.get(&handle).unwrap();
                (entry.key, entry.cell.clone())
            };
            let _scheduler = crate::dds::liveliness::scheduler::Scheduler::start(
                shared.clone(),
                Box::new(|| {}),
                Box::new(|| {}),
            )
            .unwrap();
            shared.settle();
            clock.now.store(arrival_ms * 1_000_000, Ordering::SeqCst);
            let r = reader.clone();
            let w = writer.clone();
            let arrival = std::thread::Builder::new()
                .name("deadline-arrival".into())
                .spawn(move || {
                    if writer_side {
                        w.on_write(handle)
                    } else {
                        r.on_sample(handle)
                    }
                })
                .unwrap();
            seen.recv_timeout(Duration::from_secs(5)).unwrap();
            clock.now.store(evaluation_ms * 1_000_000, Ordering::SeqCst);
            // This probe is a deterministic interleaving hook. With no
            // publication barrier, complete evaluation before releasing
            // the captured arrival; with a barrier it must wait for it.
            let publication_pending = cell.publication.try_lock().is_err();
            let mut evaluation = Some(std::thread::spawn(move || shared.settle()));
            if !publication_pending {
                evaluation.take().unwrap().join().unwrap();
            }
            resume.send(()).unwrap();
            arrival.join().unwrap();
            if publication_pending {
                evaluation.take().unwrap().join().unwrap();
            }
            let count = if writer_side {
                writer.status().total_count
            } else {
                reader.status().total_count
            };
            assert_eq!(count, expected, "only periods before arrival can miss (writer={writer_side}, arrival_ms={arrival_ms})");
        }
    }
}
