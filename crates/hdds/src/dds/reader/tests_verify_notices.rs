// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The hand-off and the scopes of the deferred notices, attacked.

use super::notices::{notify, Notice, Ordered, Scope};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Drive `q` so that its second notice is told by the hand-off thread:
/// a first notice told on a thread of its own (budget 1), a second pushed
/// while the first runs.
fn hand_off_second(q: &Arc<Ordered>, second: Notice) -> std::thread::JoinHandle<()> {
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    assert!(q
        .push(Box::new(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
        }))
        .is_ok());
    let teller = {
        let q = Arc::clone(q);
        std::thread::spawn(move || q.tell())
    };
    started_rx.recv().unwrap();
    assert!(q.push(second).is_ok());
    q.tell(); // telling already: returns
    release_tx.send(()).unwrap();
    teller
}

/// Two entities' overflow notices: a listener of entity A told by A's
/// hand-off that waits (bounded) for a listener of entity B sees it told:
/// B's notice is not queued behind A's.
#[test]
fn vn_a_hand_off_thread_is_shared_across_entities() {
    let a = Arc::new(Ordered::default());
    let b = Arc::new(Ordered::default());
    let b_told = Arc::new(AtomicBool::new(false));
    let a_saw_b = Arc::new(Mutex::new(None::<bool>));
    let (a1_started_tx, a1_started_rx) = mpsc::channel::<()>();
    let a1: Notice = {
        let b_told = Arc::clone(&b_told);
        let a_saw_b = Arc::clone(&a_saw_b);
        Box::new(move || {
            let _ = a1_started_tx.send(());
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !b_told.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            *a_saw_b.lock().unwrap() = Some(b_told.load(Ordering::SeqCst));
        })
    };
    let ta = hand_off_second(&a, a1);
    ta.join().unwrap();
    a1_started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let a1_thread_is_hand_off = true;
    let b1: Notice = {
        let b_told = Arc::clone(&b_told);
        Box::new(move || b_told.store(true, Ordering::SeqCst))
    };
    let tb = hand_off_second(&b, b1);
    tb.join().unwrap();
    // Wait for A's listener verdict.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while a_saw_b.lock().unwrap().is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(a1_thread_is_hand_off);
    assert_eq!(
        *a_saw_b.lock().unwrap(),
        Some(true),
        "entity B's listener was held behind entity A's on the one hand-off thread"
    );
}

/// A Scope inside another Scope, the outer domain closed (its entry
/// unregistered) before the inner is told: the inner (live) entity's
/// notices are told all the same.
#[test]
fn vn_d_nested_scope_strands_the_inner_domain_when_the_outer_closes() {
    let outer = Arc::new(Ordered::default());
    let inner = Arc::new(Ordered::default());
    let told = Arc::new(AtomicBool::new(false));
    {
        let _o = Scope::enter(&outer);
        {
            let _i = Scope::enter(&inner);
            let t = Arc::clone(&told);
            notify(move || t.store(true, Ordering::SeqCst));
        }
        outer.close();
    }
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        told.load(Ordering::SeqCst),
        "the inner (live) entity's notice was never told: its tell was dropped with the outer domain"
    );
}
