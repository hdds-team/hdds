// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Two WaitSets attached to the SAME condition must not disarm each other.
//!
//! A `WaitSet` owns its own driver, and each driver numbers its slots from 1.
//! The identifier a condition stores for an attached WaitSet is that slot id,
//! so two WaitSets attached to one condition can both present id 1. Removing
//! one of them by id then matched BOTH hooks, and the surviving WaitSet was
//! never signalled again while believing it was still attached: its `wait()`
//! blocks to its timeout with the condition true, and nothing reports it.
//!
//! DDS v1.4 puts no limit on how many WaitSets may observe a condition, and
//! the shape is ordinary: one thread waiting on data, another on a guard, both
//! watching the same entity.

use hdds::dds::{Condition, GuardCondition, WaitSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Wake A from ANOTHER thread while it is already blocked.
///
/// This detail is the whole test. Raising the trigger BEFORE calling `wait()`
/// proves nothing: `wait()` re-reads the trigger value and returns on its own,
/// without the hook ever being used, so such a test passes whether or not the
/// hook survived. The hook is only exercised when the trigger is raised while
/// the waiter is already asleep.
fn wake_while_blocked(waiter: &WaitSet, guard: &Arc<GuardCondition>) -> usize {
    std::thread::scope(|scope| {
        let g = Arc::clone(guard);
        scope.spawn(move || {
            // Long enough that the waiter is inside wait() and asleep.
            std::thread::sleep(Duration::from_millis(250));
            g.set_trigger_value(true);
        });
        let started = Instant::now();
        // `Err(WouldBlock)` is how `wait()` reports an expired timeout, so it
        // IS the failure this test looks for: the waiter slept its full budget
        // with the condition true. Returned as 0 rather than unwrapped, so the
        // caller's assertion message explains the defect instead of a panic
        // deep in a helper.
        let woken = match waiter.wait(Some(Duration::from_secs(3))) {
            Ok(list) => list.len(),
            Err(_) => 0,
        };
        assert!(
            woken == 0 || started.elapsed() < Duration::from_secs(3),
            "the waiter returned conditions only after its full timeout"
        );
        woken
    })
}

/// Detaching B must leave A armed.
#[test]
fn detaching_one_waitset_must_not_disarm_the_other() {
    let guard = Arc::new(GuardCondition::new());
    let condition: Arc<dyn Condition> = guard.clone();

    let a = WaitSet::new();
    let b = WaitSet::new();
    a.attach_condition(condition.clone()).expect("attach a");
    b.attach_condition(condition.clone()).expect("attach b");

    b.detach_condition(condition.clone()).expect("detach b");

    // A is still attached. Raise the trigger while A is ALREADY BLOCKED, so
    // only a surviving hook can wake it.
    let woken = wake_while_blocked(&a, &guard);

    assert!(
        woken > 0,
        "A was still attached but was never woken: detaching B removed A's hook \
         from the condition, because both WaitSets present the same per-driver \
         slot id and removal matched on id alone"
    );
}

/// Dropping B must leave A armed. Same defect, reached through `Drop` rather
/// than an explicit detach, which is the likelier way to meet it.
#[test]
fn dropping_one_waitset_must_not_disarm_the_other() {
    let guard = Arc::new(GuardCondition::new());
    let condition: Arc<dyn Condition> = guard.clone();

    let a = WaitSet::new();
    {
        let b = WaitSet::new();
        b.attach_condition(condition.clone()).expect("attach b");
        a.attach_condition(condition.clone()).expect("attach a");
    } // b dropped here

    let woken = wake_while_blocked(&a, &guard);

    assert!(
        woken > 0,
        "A was still attached but was never woken: dropping B removed A's hook"
    );
}

/// The complement, so the fix cannot be "never remove anything": detaching B
/// must actually stop B from being signalled.
#[test]
fn detaching_still_removes_the_right_hook() {
    let guard = Arc::new(GuardCondition::new());
    let condition: Arc<dyn Condition> = guard.clone();

    let a = WaitSet::new();
    let b = WaitSet::new();
    a.attach_condition(condition.clone()).expect("attach a");
    b.attach_condition(condition.clone()).expect("attach b");

    b.detach_condition(condition.clone()).expect("detach b");
    guard.set_trigger_value(true);

    // B has nothing attached any more, so it has nothing to report.
    // An empty WaitSet may also refuse to wait rather than return an empty
    // list; either answer is correct, only reporting the condition is wrong.
    if let Ok(list) = b.wait(Some(Duration::from_millis(300))) {
        assert!(
            list.is_empty(),
            "B was detached and must not report the condition"
        );
    }
}
