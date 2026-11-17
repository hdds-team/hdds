// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `WaitSet::notify()` must actually wake a blocked `wait()`.
//!
//! Its documentation promises exactly that. A `notify()` that only wrote the
//! driver's event would wake the waiter, which would re-scan its conditions,
//! find nothing triggered and go back to sleep. With `wait(None)` - the shape a
//! shutdown path uses, since there is no condition to raise and no sensible
//! timeout - the thread would never return at all.
//!
//! These tests are the callers that pin that property.

use hdds::dds::{Condition, GuardCondition, WaitSet};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// The shutdown shape: no conditions attached, no timeout. The
/// thread must come back.
#[test]
fn notify_wakes_a_waiter_that_has_no_conditions_and_no_timeout() {
    let ws = Arc::new(WaitSet::new());
    let (tx, rx) = mpsc::channel();

    let waiter = Arc::clone(&ws);
    let handle = thread::spawn(move || {
        let result = waiter.wait(None);
        let _ = tx.send(result.is_ok());
    });

    // Let the waiter get all the way into the blocking wait.
    thread::sleep(Duration::from_millis(200));
    ws.notify();

    let woke = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("notify() must wake a blocked wait(None); it never returned");
    assert!(woke, "the woken wait must not report an error");
    handle.join().expect("waiter thread");
}

/// With a condition attached and a long timeout, the waiter must come back on
/// the notify rather than sit out its own deadline.
#[test]
fn notify_wakes_a_waiter_before_its_timeout() {
    let guard = Arc::new(GuardCondition::new());
    let condition: Arc<dyn Condition> = guard.clone();
    let ws = Arc::new(WaitSet::new());
    ws.attach_condition(condition).expect("attach");

    let (tx, rx) = mpsc::channel();
    let waiter = Arc::clone(&ws);
    let handle = thread::spawn(move || {
        let result = waiter.wait(Some(Duration::from_secs(30)));
        let _ = tx.send(result);
    });

    thread::sleep(Duration::from_millis(200));
    ws.notify();

    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("notify() must wake the waiter well before its 30 s timeout");
    let woken = result.expect("a manual wake is not an error");
    assert!(
        woken.is_empty(),
        "a manual wake reports no triggered condition, since none was triggered"
    );
    handle.join().expect("waiter thread");
}

/// Level-triggered, not edge: a notify that lands before anyone is inside
/// `wait()` must be honoured by the next call. On a shutdown path the race
/// between raising the flag and entering the wait cannot be won by the caller,
/// so losing the notify would hang the process exactly when it is trying to
/// stop.
#[test]
fn a_notify_that_arrives_before_the_wait_is_not_lost() {
    let ws = WaitSet::new();
    ws.notify();

    let woken = ws
        .wait(None)
        .expect("the pending notify must make this return immediately");
    assert!(woken.is_empty());
}

/// And it is consumed: the wake is not sticky, or every later wait would return
/// instantly and the WaitSet would be useless after one shutdown signal.
#[test]
fn a_consumed_notify_does_not_wake_the_next_wait() {
    let ws = WaitSet::new();
    ws.notify();
    let _ = ws.wait(None).expect("first wait consumes the notify");

    // Nothing is attached and no notify is pending, so this must reach its
    // timeout rather than return.
    let result = ws.wait(Some(Duration::from_millis(300)));
    assert!(
        result.is_err(),
        "a consumed notify must not keep waking later waits"
    );
}
