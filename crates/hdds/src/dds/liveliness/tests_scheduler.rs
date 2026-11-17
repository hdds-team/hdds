// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The scheduler thread, on a clock the tests move.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use super::clock::ManualClock;
use super::leases::{HeartbeatSink, LivelinessSink, WatchKey};
use super::scheduler::{HeartbeatWatchHandle, Scheduler, Shared};
use crate::dds::reader::notices::Ordered;

/// What the application call of a transition saw: its key, its state,
/// the name of the thread that told it.
type Told = (WatchKey, bool, Option<String>);

/// Records each transition, and queues one application call per
/// transition in its `Ordered`, as a reader does.
struct Sink {
    seen: Mutex<Vec<(WatchKey, bool)>>,
    queue: Arc<Ordered>,
    told: mpsc::Sender<Told>,
}

impl LivelinessSink for Sink {
    fn transition(&self, key: WatchKey, alive: bool) -> Option<Arc<Ordered>> {
        self.seen.lock().unwrap().push((key, alive));
        let told = self.told.clone();
        let _ = self.queue.push(Box::new(move || {
            let name = std::thread::current().name().map(str::to_string);
            let _ = told.send((key, alive, name));
        }));
        Some(Arc::clone(&self.queue))
    }
}

fn sink() -> (Arc<Sink>, mpsc::Receiver<Told>) {
    let (tx, rx) = mpsc::channel();
    let sink = Arc::new(Sink {
        seen: Mutex::new(Vec::new()),
        queue: Arc::new(Ordered::default()),
        told: tx,
    });
    (sink, rx)
}

fn weak(sink: &Arc<Sink>) -> Weak<dyn LivelinessSink> {
    let s: Arc<dyn LivelinessSink> = Arc::clone(sink) as Arc<dyn LivelinessSink>;
    Arc::downgrade(&s)
}

fn started(clock: &Arc<ManualClock>) -> (Scheduler, Arc<AtomicUsize>) {
    let (scheduler, sends, _manual) = started_with_manual(clock);
    (scheduler, sends)
}

/// Like [`started`], plus a counter of the MANUAL_BY_PARTICIPANT sends.
fn started_with_manual(
    clock: &Arc<ManualClock>,
) -> (Scheduler, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let shared = Shared::new(Arc::clone(clock) as Arc<dyn super::LivelinessClock>);
    let sends = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&sends);
    let manual_sends = Arc::new(AtomicUsize::new(0));
    let manual_counted = Arc::clone(&manual_sends);
    let scheduler = Scheduler::start(
        shared,
        Box::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        }),
        Box::new(move || {
            manual_counted.fetch_add(1, Ordering::SeqCst);
        }),
    )
    .expect("thread");
    (scheduler, sends, manual_sends)
}

#[test]
fn a_silent_writer_is_declared_not_alive_when_its_lease_passes() {
    let clock = Arc::new(ManualClock::new(0));
    let (scheduler, _) = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (sink, rx) = sink();
    let renewal = shared.renewal();
    let key = shared.watch(
        Arc::clone(&renewal),
        Duration::from_millis(100),
        weak(&sink),
    );
    clock.advance(Duration::from_millis(99));
    shared.settle();
    assert_eq!(shared.is_alive_for_test(key), Some(true));
    clock.advance(Duration::from_millis(1));
    shared.settle();
    assert_eq!(shared.is_alive_for_test(key), Some(false));
    let (k, alive, thread) = rx.recv_timeout(Duration::from_secs(5)).expect("told");
    assert_eq!((k, alive), (key, false));
    assert_ne!(
        thread.as_deref(),
        Some("hdds-liveliness"),
        "a listener never runs on the scheduler thread"
    );
}

/// The receive path renews after the lease passed, before the thread ran:
/// not alive, then alive, both recorded.
#[test]
fn a_writer_that_resumes_before_the_scheduler_runs_is_recorded_not_alive_once() {
    let clock = Arc::new(ManualClock::new(0));
    let (scheduler, _) = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (sink, rx) = sink();
    let renewal = shared.renewal();
    let key = shared.watch(
        Arc::clone(&renewal),
        Duration::from_millis(100),
        weak(&sink),
    );
    shared.settle();
    // The clock jumps past the lease and the traffic resumes in one step:
    // the thread never sees the lease end with no renewal after it.
    clock.advance(Duration::from_millis(150));
    shared.renew(&renewal);
    shared.settle();
    assert_eq!(*sink.seen.lock().unwrap(), vec![(key, false), (key, true)]);
    for want in [false, true] {
        let (_, alive, _) = rx.recv_timeout(Duration::from_secs(5)).expect("told");
        assert_eq!(alive, want);
    }
    clock.advance(Duration::from_millis(50));
    shared.renew(&renewal);
    shared.settle();
    assert_eq!(
        sink.seen.lock().unwrap().len(),
        2,
        "renewed in time: nothing more"
    );
}

#[test]
fn a_renewed_writer_becomes_alive_again() {
    let clock = Arc::new(ManualClock::new(0));
    let (scheduler, _) = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (sink, _rx) = sink();
    let renewal = shared.renewal();
    let key = shared.watch(
        Arc::clone(&renewal),
        Duration::from_millis(100),
        weak(&sink),
    );
    clock.advance(Duration::from_millis(200));
    shared.settle();
    clock.advance(Duration::from_millis(10));
    shared.renew(&renewal);
    shared.settle();
    assert_eq!(*sink.seen.lock().unwrap(), vec![(key, false), (key, true)]);
    assert_eq!(shared.is_alive_for_test(key), Some(true));
}

#[test]
fn the_participant_asserts_every_third_of_its_shortest_lease() {
    let clock = Arc::new(ManualClock::new(0));
    let (scheduler, sends) = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    assert!(shared.local_writer(Duration::from_secs(u64::MAX)).is_none());
    let lease = shared
        .local_writer(Duration::from_millis(300))
        .expect("finite");
    shared.settle();
    assert_eq!(sends.load(Ordering::SeqCst), 1, "at once");
    for n in 2..=5 {
        clock.advance(Duration::from_millis(100));
        shared.settle();
        assert_eq!(sends.load(Ordering::SeqCst), n);
    }
    drop(lease);
    clock.advance(Duration::from_secs(10));
    shared.settle();
    assert_eq!(sends.load(Ordering::SeqCst), 5, "no writer, no assertion");
}

/// Dropped, the scheduler has stopped its thread and joined it: what the
/// thread owned (here its send hook) is gone when the drop returns.
#[test]
fn the_scheduler_thread_is_joined_when_dropped() {
    let clock = Arc::new(ManualClock::new(0));
    let shared = Shared::new(Arc::clone(&clock) as Arc<dyn super::LivelinessClock>);
    let (tx, rx) = mpsc::channel::<()>();
    let scheduler = Scheduler::start(
        Arc::clone(&shared),
        Box::new(move || {
            let _ = tx.send(());
        }),
        Box::new(|| {}),
    )
    .expect("thread");
    let _lease = shared.local_writer(Duration::from_millis(30));
    shared.settle();
    assert!(rx.try_recv().is_ok());
    drop(scheduler);
    assert!(
        matches!(rx.try_recv(), Err(mpsc::TryRecvError::Disconnected)),
        "the thread and its hook are gone"
    );
}

/// Records each fire and the name of the thread it ran on.
struct HeartbeatRecorder {
    told: mpsc::Sender<Option<String>>,
}

impl HeartbeatSink for HeartbeatRecorder {
    fn fire(&self) {
        let name = std::thread::current().name().map(str::to_string);
        let _ = self.told.send(name);
    }
}

fn heartbeat_sink() -> (Arc<HeartbeatRecorder>, mpsc::Receiver<Option<String>>) {
    let (tx, rx) = mpsc::channel();
    (Arc::new(HeartbeatRecorder { told: tx }), rx)
}

/// Waits, bounded, until the sender has released `watch`'s writer slot
/// (`HeartbeatPending::end`), which it does only after `fire` returned.
fn await_slot_free(watch: &HeartbeatWatchHandle) {
    assert!(
        watch.pending().wait_idle(Duration::from_secs(30)),
        "the sender never released the writer's HEARTBEAT slot"
    );
}

fn weak_heartbeat(sink: &Arc<HeartbeatRecorder>) -> Weak<dyn HeartbeatSink> {
    let s: Arc<dyn HeartbeatSink> = Arc::clone(sink) as Arc<dyn HeartbeatSink>;
    Arc::downgrade(&s)
}

/// RTPS v2.5 Sec.8.4.7.2: a watched writer's periodic HEARTBEAT fires
/// every period, on a thread that is never the scheduler's own.
#[test]
fn a_heartbeat_watch_fires_every_period_off_the_scheduler_thread() {
    let clock = Arc::new(ManualClock::new(0));
    let (scheduler, _) = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (sink, rx) = heartbeat_sink();
    let watch = shared.watch_heartbeat(weak_heartbeat(&sink), Duration::from_millis(100));
    clock.advance(Duration::from_millis(99));
    shared.settle();
    assert!(
        rx.try_recv().is_err(),
        "the first period has not elapsed yet"
    );
    clock.advance(Duration::from_millis(1));
    shared.settle();
    let thread = rx.recv_timeout(Duration::from_secs(5)).expect("fired");
    assert_ne!(
        thread.as_deref(),
        Some("hdds-liveliness"),
        "a HEARTBEAT send never runs on the scheduler thread"
    );
    // The recorder reports from inside `fire`; the sender frees the
    // writer's slot only after `fire` returns. A tick that comes due before
    // that is coalesced by design (`HeartbeatPending`), so wait for the slot:
    // the second period must find the first one fully done.
    await_slot_free(&watch);
    clock.advance(Duration::from_millis(100));
    shared.settle();
    rx.recv_timeout(Duration::from_secs(5))
        .expect("fired again one period later");
}

/// Dropping the watch handle (the writer is deleted) stops future fires:
/// its stale heap entry is ignored when it would otherwise fire.
#[test]
fn dropping_the_heartbeat_watch_stops_future_fires() {
    let clock = Arc::new(ManualClock::new(0));
    let (scheduler, _) = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (sink, rx) = heartbeat_sink();
    let watch = shared.watch_heartbeat(weak_heartbeat(&sink), Duration::from_millis(100));
    clock.advance(Duration::from_millis(100));
    shared.settle();
    rx.recv_timeout(Duration::from_secs(5)).expect("fired once");
    drop(watch);
    clock.advance(Duration::from_secs(10));
    shared.settle();
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "the watch was dropped: no more HEARTBEATs"
    );
}

/// A sink whose `fire` always panics.
struct PanickingHeartbeatSink;

impl HeartbeatSink for PanickingHeartbeatSink {
    fn fire(&self) {
        panic!("deliberate panic from a test sink");
    }
}

/// A panicking sink must not take the single `hdds-hb-sender` worker down
/// with it: if nothing isolated `sink.fire()`, the panic would unwind out of
/// the worker's loop and kill its thread, and every OTHER writer's periodic
/// HEARTBEAT would stop along with the panicking one's -- permanently, since
/// nothing restarts the worker.
///
/// This watches a panicking sink and a normal one on the same
/// scheduler, registered so the panicking one's entry is due first
/// (lower key); it must fire and panic WITHOUT taking the normal one's
/// HEARTBEAT down, on this period and the next.
///
/// Mutant: removing the `catch_unwind` around `sink.fire()` in
/// `heartbeat_worker` makes this fail: the second period's `recv_timeout`
/// times out because the worker thread died on the first one.
#[test]
fn a_panicking_sink_does_not_kill_the_worker_for_other_writers() {
    let clock = Arc::new(ManualClock::new(0));
    let (scheduler, _) = started(&clock);
    let shared = Arc::clone(scheduler.shared());

    let panicking: Arc<dyn HeartbeatSink> = Arc::new(PanickingHeartbeatSink);
    let panicking_watch =
        shared.watch_heartbeat(Arc::downgrade(&panicking), Duration::from_millis(100));

    let (good, rx) = heartbeat_sink();
    let good_watch = shared.watch_heartbeat(weak_heartbeat(&good), Duration::from_millis(100));

    for period in 1..=2 {
        clock.advance(Duration::from_millis(100));
        shared.settle();
        rx.recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|e| panic!("period {period}: the other writer's HEARTBEAT did not fire ({e}); the worker likely died on the panicking one"));
        // Both jobs of this period must be fully done (slots freed after
        // `fire` returned or panicked) before the next tick comes due, or
        // the next tick is coalesced by design and never fires.
        await_slot_free(&good_watch);
        await_slot_free(&panicking_watch);
    }
}

/// A writer destroyed by code running ON
/// the scheduler or sender thread itself (a sink callback `deliver`
/// invokes inline that happens to own and drop the last reference to a
/// writer) must not let its deletion barrier wait on either thread --
/// it would be waiting for work that very thread has to do. This pins
/// the detection both that barrier and its callbacks rely on:
/// `transition` (which runs on the scheduler thread) and `fire` (the
/// sender thread) each see themselves recognized, and this test's own
/// thread is recognized as neither.
///
/// Mutant: removing either `ThreadId::set` call (`Scheduler::start`,
/// `Shared::start_heartbeat_worker`), or making
/// `is_on_its_own_heartbeat_threads` always return `false`, makes the
/// matching assertion below fail.
#[test]
fn the_scheduler_and_sender_threads_recognize_themselves() {
    let clock = Arc::new(ManualClock::new(0));
    let (scheduler, _) = started(&clock);
    let shared = Arc::clone(scheduler.shared());

    assert!(
        !shared.is_on_its_own_heartbeat_threads(),
        "this test's own thread is neither the scheduler's nor the sender's"
    );

    struct SelfCheckSink {
        shared: Arc<Shared>,
        seen: Mutex<Option<bool>>,
    }
    impl LivelinessSink for SelfCheckSink {
        fn transition(&self, _key: WatchKey, _alive: bool) -> Option<Arc<Ordered>> {
            *self.seen.lock().unwrap() = Some(self.shared.is_on_its_own_heartbeat_threads());
            None
        }
    }
    let sink = Arc::new(SelfCheckSink {
        shared: Arc::clone(&shared),
        seen: Mutex::new(None),
    });
    let renewal = shared.renewal();
    let sink_weak: Weak<dyn LivelinessSink> = {
        let s: Arc<dyn LivelinessSink> = Arc::clone(&sink) as Arc<dyn LivelinessSink>;
        Arc::downgrade(&s)
    };
    let _key = shared.watch(renewal, Duration::from_millis(100), sink_weak);
    clock.advance(Duration::from_millis(100));
    shared.settle();
    assert_eq!(
        *sink.seen.lock().unwrap(),
        Some(true),
        "transition() runs on the scheduler's own thread, which must recognize itself"
    );

    struct SelfCheckHeartbeat {
        shared: Arc<Shared>,
        tx: mpsc::Sender<bool>,
    }
    impl HeartbeatSink for SelfCheckHeartbeat {
        fn fire(&self) {
            let _ = self.tx.send(self.shared.is_on_its_own_heartbeat_threads());
        }
    }
    let (tx, rx) = mpsc::channel();
    let hb_sink: Arc<dyn HeartbeatSink> = Arc::new(SelfCheckHeartbeat {
        shared: Arc::clone(&shared),
        tx,
    });
    let _hb_watch = shared.watch_heartbeat(Arc::downgrade(&hb_sink), Duration::from_millis(100));
    clock.advance(Duration::from_millis(100));
    shared.settle();
    assert!(
        rx.recv_timeout(Duration::from_secs(5)).expect("fired"),
        "fire() runs on the sender's own thread, which must recognize itself"
    );
}

/// A closed queue (the reader is deleted) tells nothing more.
#[test]
fn no_call_reaches_a_closed_queue() {
    let clock = Arc::new(ManualClock::new(0));
    let (scheduler, _) = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (sink, rx) = sink();
    let renewal = shared.renewal();
    let _key = shared.watch(renewal, Duration::from_millis(10), weak(&sink));
    sink.queue.close();
    clock.advance(Duration::from_millis(20));
    shared.settle();
    assert_eq!(sink.seen.lock().unwrap().len(), 1);
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
}
