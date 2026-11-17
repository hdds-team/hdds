// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The deferred notices attacked: a slow listener behind a fast producer,
//! listeners that panic while a delivery unwinds.

use super::notices::{notify, Delivering, Notice, Ordered};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A slow listener and a second producer thread: the thread that told
/// first is not held telling the producer's statuses (they go to the
/// hand-off thread), and the queue stays bounded.
#[test]
fn v3a_a_teller_is_not_held_by_a_fast_producer() {
    let q = Arc::new(Ordered::default());
    let started = Arc::new(AtomicBool::new(false));
    let told = Arc::new(AtomicUsize::new(0));
    let slow = |started: &Arc<AtomicBool>, told: &Arc<AtomicUsize>| -> Notice {
        let (started, told) = (Arc::clone(started), Arc::clone(told));
        Box::new(move || {
            started.store(true, Ordering::SeqCst);
            told.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_micros(500));
        })
    };
    assert!(q.push(slow(&started, &told)).is_ok());
    let teller = {
        let q = Arc::clone(&q);
        std::thread::spawn(move || {
            let t0 = Instant::now();
            q.tell();
            t0.elapsed()
        })
    };
    while !started.load(Ordering::SeqCst) {
        std::thread::yield_now();
    }
    let mut given_back = 0;
    for _ in 1..=20_000u32 {
        match q.push(slow(&started, &told)) {
            Ok(()) => q.tell(),
            Err(own) => {
                given_back += 1;
                own();
            }
        }
    }
    let teller_time = teller.join().unwrap();
    eprintln!("teller held {teller_time:?}; producer told {given_back} of its own");
    assert!(
        teller_time < Duration::from_millis(100),
        "one tell() of one status held its thread {teller_time:?}"
    );
}

/// Unwinding: a held notice that tells an `Ordered` whose first listener
/// panics: both are told, then the next held notice.
#[test]
fn v4_ordered_tell_with_a_panicking_listener_during_unwinding_does_not_abort() {
    let q = Arc::new(Ordered::default());
    let after = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicUsize::new(0));
    for n in 1..=2u32 {
        let seen = Arc::clone(&seen);
        assert!(q
            .push(Box::new(move || {
                seen.fetch_add(1, Ordering::SeqCst);
                if n == 1 {
                    panic!("listener panics during unwinding");
                }
            }))
            .is_ok());
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
        let (q, after) = (Arc::clone(&q), Arc::clone(&after));
        move || {
            let _d = Delivering::enter();
            notify(move || q.tell());
            notify(move || after.store(true, Ordering::SeqCst));
            panic!("the delivery panics");
        }
    }));
    assert!(r.is_err());
    assert_eq!(seen.load(Ordering::SeqCst), 2, "both statuses told");
    assert!(after.load(Ordering::SeqCst), "the next held notice told");
}

/// A nested delivery inside a held notice told during unwinding, whose own
/// inner notice panics.
#[test]
fn v4b_nested_delivery_inside_a_notice_during_unwinding() {
    let told = Arc::new(AtomicUsize::new(0));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
        let told = Arc::clone(&told);
        move || {
            let _d = Delivering::enter();
            let t = Arc::clone(&told);
            notify(move || {
                let _inner = Delivering::enter();
                let t2 = Arc::clone(&t);
                notify(move || {
                    t2.fetch_add(1, Ordering::SeqCst);
                    panic!("inner panics");
                });
                notify(move || {
                    t.fetch_add(1, Ordering::SeqCst);
                });
            });
            panic!("outer");
        }
    }));
    assert!(r.is_err());
    assert_eq!(told.load(Ordering::SeqCst), 2);
}
