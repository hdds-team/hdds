// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `WriterLiveliness` (LIVELINESS_LOST), on a clock the tests move.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::clock::ManualClock;
use super::scheduler::{Scheduler, Shared};
use super::writer::WriterLiveliness;
use crate::dds::listener::LivelinessLostStatus;
use crate::dds::reader::notices::Notice;
use crate::dds::StatusCondition;

fn started(clock: &Arc<ManualClock>) -> (Scheduler, Arc<Shared>) {
    let shared = Shared::new(Arc::clone(clock) as Arc<dyn super::LivelinessClock>);
    let scheduler =
        Scheduler::start(Arc::clone(&shared), Box::new(|| {}), Box::new(|| {})).expect("thread");
    (scheduler, shared)
}

/// Records every LIVELINESS_LOST status reported through the listener.
/// No listener installed: the status getter / StatusCondition path (the
/// `None` arm of `WriterLiveliness::report`), which does NOT reset
/// `total_count_change` itself -- only a read through `status()` does.
fn no_listener() -> super::writer::LivelinessLostListener {
    Box::new(|_status| None)
}

fn listener() -> (
    super::writer::LivelinessLostListener,
    Arc<Mutex<Vec<LivelinessLostStatus>>>,
) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let f: super::writer::LivelinessLostListener = Box::new(move |status: LivelinessLostStatus| {
        recorded.lock().unwrap().push(status);
        Some(Box::new(|| {}) as Notice)
    });
    (f, seen)
}

/// RTPS/DDS v1.4 Sec.2.2.4.1: a writer silent past its lease raises
/// LIVELINESS_LOST once, total_count 1.
/// Mutant: flipping `if !alive` to `if alive` in
/// `WriterLiveliness::transition` makes this report nothing (it would
/// only fire on a resumption, which never happens here).
#[test]
fn a_writer_silent_past_its_lease_raises_liveliness_lost() {
    let clock = Arc::new(ManualClock::new(0));
    let (_scheduler, shared) = started(&clock);
    let (listener_fn, seen) = listener();
    let condition = Arc::new(StatusCondition::new());
    let renewal = shared.renewal();
    let wl = WriterLiveliness::new(
        Arc::clone(&shared),
        renewal,
        Duration::from_millis(100),
        condition,
        listener_fn,
    );
    clock.advance(Duration::from_millis(100));
    shared.settle();
    let snapshot = seen.lock().unwrap().clone();
    assert_eq!(snapshot.len(), 1, "exactly one loss reported");
    assert_eq!(snapshot[0].total_count, 1);
    assert_eq!(snapshot[0].total_count_change, 1);
    drop(wl);
}

/// A renewal within the lease keeps the writer alive: nothing raised.
#[test]
fn a_writer_renewed_within_its_lease_raises_nothing() {
    let clock = Arc::new(ManualClock::new(0));
    let (_scheduler, shared) = started(&clock);
    let (listener_fn, seen) = listener();
    let condition = Arc::new(StatusCondition::new());
    let renewal = shared.renewal();
    let wl = WriterLiveliness::new(
        Arc::clone(&shared),
        Arc::clone(&renewal),
        Duration::from_millis(100),
        condition,
        listener_fn,
    );
    for t in (50..500).step_by(50) {
        clock.advance(Duration::from_millis(50));
        shared.renew(&renewal);
        shared.settle();
        let _ = t;
    }
    assert!(seen.lock().unwrap().is_empty());
    drop(wl);
}

/// "Expired then resumed before the timer ran": the
/// receive path renews past the lease in one step, before the scheduler
/// thread ever observed the expiry. The loss is still counted exactly
/// once -- LIVELINESS_LOST has no "regained" half to report a second
/// time.
/// Mutant: removing the `if !alive` guard (reporting on every
/// transition) makes `seen.len()` 2, not 1.
#[test]
fn a_resumption_after_the_lease_passed_still_counts_the_loss_once() {
    let clock = Arc::new(ManualClock::new(0));
    let (_scheduler, shared) = started(&clock);
    let (listener_fn, seen) = listener();
    let condition = Arc::new(StatusCondition::new());
    let renewal = shared.renewal();
    let wl = WriterLiveliness::new(
        Arc::clone(&shared),
        Arc::clone(&renewal),
        Duration::from_millis(100),
        condition,
        listener_fn,
    );
    clock.advance(Duration::from_millis(150));
    shared.renew(&renewal);
    shared.settle();
    assert_eq!(seen.lock().unwrap().len(), 1, "one loss, not two");
    drop(wl);
}

/// `get_liveliness_lost_status`-style read-and-reset (DDS v1.4
/// Sec.2.2.4.2.1): `total_count` stays, `total_count_change` resets.
#[test]
fn status_read_resets_the_change_not_the_total() {
    let clock = Arc::new(ManualClock::new(0));
    let (_scheduler, shared) = started(&clock);
    let condition = Arc::new(StatusCondition::new());
    let renewal = shared.renewal();
    let wl = WriterLiveliness::new(
        Arc::clone(&shared),
        renewal,
        Duration::from_millis(100),
        condition,
        no_listener(),
    );
    clock.advance(Duration::from_millis(100));
    shared.settle();
    let first = wl.status();
    assert_eq!((first.total_count, first.total_count_change), (1, 1));
    let second = wl.status();
    assert_eq!(
        (second.total_count, second.total_count_change),
        (1, 0),
        "total survives the read, the change does not"
    );
    drop(wl);
}

/// Dropped, a `WriterLiveliness`'s watch is gone: a shared
/// MANUAL_BY_PARTICIPANT renewal does not keep firing for it.
#[test]
fn a_dropped_writer_liveliness_stops_watching() {
    let clock = Arc::new(ManualClock::new(0));
    let (_scheduler, shared) = started(&clock);
    let (listener_fn, seen) = listener();
    let condition = Arc::new(StatusCondition::new());
    let renewal = shared.renewal();
    let wl = WriterLiveliness::new(
        Arc::clone(&shared),
        Arc::clone(&renewal),
        Duration::from_millis(100),
        condition,
        listener_fn,
    );
    drop(wl);
    clock.advance(Duration::from_millis(200));
    shared.settle();
    assert!(seen.lock().unwrap().is_empty());
}
