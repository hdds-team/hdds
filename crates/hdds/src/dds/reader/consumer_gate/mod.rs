// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The reader's ring consumer gate (see the `consumer_gate` field of
//! `DataReader`), in one of two builds.
//!
//! - Default: [`cas`], one `AtomicBool` taken by compare-and-swap on every
//!   acquisition. Plain acquire/release atomics, inside the Rust memory
//!   model; the cert-friendly build.
//! - Feature `fast-consumer-gate`: [`owned`], where a reader drained by a
//!   single thread enters with plain stores and loads and the first other
//!   consumer engages the compare-and-swap for good through a
//!   `membarrier(2)` handshake. Its argument rests on the Linux kernel's
//!   membarrier contract and on a compiler fence acting as a compiler
//!   barrier, outside the Rust abstract memory model. Where the barrier is
//!   unavailable (not Linux, Miri, refused at runtime) every gate starts in
//!   the compare-and-swap regime.
//!
//! Without the feature, the `owned` module is not compiled at all: no
//! `membarrier` system call and none of its `unsafe` is in the build.

#[cfg(not(feature = "fast-consumer-gate"))]
mod cas;
#[cfg(not(feature = "fast-consumer-gate"))]
pub(super) use cas::{ConsumerGate, ConsumerGuard};

#[cfg(feature = "fast-consumer-gate")]
mod owned;
#[cfg(feature = "fast-consumer-gate")]
pub(super) use owned::{ConsumerGate, ConsumerGuard};

/// What every build of the gate must do, run against the build's own gate.
#[cfg(test)]
mod tests {
    use super::ConsumerGate;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    /// Each test lane exercises the gate it ships: the default lane the
    /// compare-and-swap gate, the all-features lane the owned gate.
    #[test]
    fn the_build_selects_its_gate() {
        let name = std::any::type_name::<ConsumerGate>();
        if cfg!(feature = "fast-consumer-gate") {
            assert!(name.ends_with("owned::ConsumerGate"), "{name}");
        } else {
            assert!(name.ends_with("cas::ConsumerGate"), "{name}");
        }
    }

    #[test]
    fn a_gate_is_taken_again_once_released() {
        let gate = ConsumerGate::new();
        for _ in 0..3 {
            drop(gate.lock());
        }
    }

    /// A consumer on another thread waits for the section in progress.
    #[test]
    fn a_consumer_on_another_thread_waits_for_the_section_in_progress() {
        let gate = Arc::new(ConsumerGate::new());
        let section = gate.lock();
        let (entered_tx, entered_rx) = mpsc::channel();
        let other = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                let guard = gate.lock();
                entered_tx.send(()).expect("send");
                drop(guard);
            })
        };
        assert!(
            entered_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "another consumer entered during a section"
        );
        drop(section);
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the other consumer enters once the section ends");
        other.join().expect("other");
        drop(gate.lock());
    }

    /// Two threads, many fresh gates: each section does a read-modify-write
    /// of a shared counter split into a Relaxed load and store, so any
    /// overlap of two sections loses an increment. On the owned gate this
    /// crosses the engagement on every fresh gate.
    #[test]
    fn sections_of_two_threads_never_overlap() {
        const GATES: usize = 200;
        const PER_THREAD: u64 = 2_000;
        for _ in 0..GATES {
            let gate = Arc::new(ConsumerGate::new());
            let counter = Arc::new(AtomicU64::new(0));
            drop(gate.lock());
            let other = {
                let gate = Arc::clone(&gate);
                let counter = Arc::clone(&counter);
                std::thread::spawn(move || {
                    for _ in 0..PER_THREAD {
                        let _guard = gate.lock();
                        let value = counter.load(Ordering::Relaxed);
                        std::hint::spin_loop();
                        counter.store(value + 1, Ordering::Relaxed);
                    }
                })
            };
            for _ in 0..PER_THREAD {
                let _guard = gate.lock();
                let value = counter.load(Ordering::Relaxed);
                std::hint::spin_loop();
                counter.store(value + 1, Ordering::Relaxed);
            }
            other.join().expect("other");
            assert_eq!(counter.load(Ordering::Relaxed), 2 * PER_THREAD);
        }
    }
}
