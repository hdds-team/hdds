// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Ultra-low latency wake notification with atomic fast-path.
//!
//! Wakes the router thread when a receive thread (or the shared-memory
//! poller) has pushed a datagram into the participant's rx ring.
//!
//! # Architecture
//! - Atomic flag for lock-free fast-path (hot traffic, consumer spinning)
//! - Thread park/unpark for idle wake (sporadic traffic)
//!
//! The idle wake is park/unpark rather than a mutex + condvar, which would
//! make `notify` take the mutex to see whether the consumer sleeps, go
//! through the condvar's own queue, and have the woken consumer re-take the
//! mutex before returning. Park/unpark is one futex wake on the consumer's
//! own thread parker (Linux), with no shared lock on either side.
//!
//! # No lost wakeup
//! `notify` stores `data_ready` then loads `sleeping`; `wait_timeout` stores
//! `sleeping` then loads `data_ready`, both sequentially consistent. Of the
//! two loads at least one sees the other side's store: either the consumer
//! sees the data and does not park, or the producer sees the sleeper and
//! unparks it, and an unpark that lands before the park makes the park
//! return at once (std's park token).

use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::Thread;
use std::time::{Duration, Instant};

/// Wake notification with atomic fast-path for ultra-low latency.
///
/// Uses a two-tier notification system:
/// 1. Atomic flag for lock-free notification (checked by spin loop)
/// 2. Park/unpark of the waiting thread (used when idle)
///
/// Built for ONE waiting thread at a time (the router). `notify` unparks
/// the thread that most recently entered `wait_timeout`.
///
/// # Example
/// ```ignore
/// let notifier = Arc::new(WakeNotifier::new());
///
/// // Producer (listener thread) - lock-free!
/// ring.push(item);
/// notifier.notify();  // Just atomic store
///
/// // Consumer spin phase - lock-free!
/// if notifier.check_and_clear() {
///     // Data available, no lock acquired
/// }
///
/// // Consumer sleep phase - parks the thread
/// notifier.wait_timeout(Duration::from_millis(10));
/// ```
#[derive(Debug)]
pub struct WakeNotifier {
    /// Atomic flag for lock-free fast-path
    data_ready: AtomicBool,
    /// True while the waiter is (about to be) parked.
    sleeping: AtomicBool,
    /// The thread `notify` unparks; written by `wait_timeout` only.
    waiter: Mutex<Option<Thread>>,
}

impl WakeNotifier {
    /// Create a new wake notifier.
    #[inline]
    pub fn new() -> Self {
        Self {
            data_ready: AtomicBool::new(false),
            sleeping: AtomicBool::new(false),
            waiter: Mutex::new(None),
        }
    }

    /// Notify that data is available (lock-free fast-path).
    ///
    /// An atomic store, plus one futex wake when the waiter is parked.
    #[inline]
    pub fn notify(&self) {
        self.data_ready.store(true, Ordering::SeqCst);
        if self.sleeping.load(Ordering::SeqCst) {
            if let Some(t) = self.waiter.lock().as_ref() {
                t.unpark();
            }
        }
    }

    /// Check if data is ready and clear the flag (lock-free).
    ///
    /// Used by the spin loop for fast polling without lock overhead.
    #[inline]
    pub fn check_and_clear(&self) -> bool {
        self.data_ready.swap(false, Ordering::Acquire)
    }

    /// Check if data is ready without clearing (lock-free peek).
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.data_ready.load(Ordering::Acquire)
    }

    /// Wait for notification with timeout (blocking).
    ///
    /// Used when the spin loop exhausts and the router goes to sleep.
    /// Returns immediately if data_ready flag is set.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait
    ///
    /// # Returns
    /// * `true` if notified
    /// * `false` if timed out
    #[inline]
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        // Fast-path: check atomic first (no lock!)
        if self.data_ready.swap(false, Ordering::Acquire) {
            return true;
        }

        // Slow-path: register as the waiter, then announce the sleep.
        {
            let me = std::thread::current();
            let mut waiter = self.waiter.lock();
            if waiter.as_ref().map(Thread::id) != Some(me.id()) {
                *waiter = Some(me);
            }
        }
        self.sleeping.store(true, Ordering::SeqCst);

        // A timeout too large for an Instant waits without a deadline, as
        // the condvar this replaces did.
        let deadline = Instant::now().checked_add(timeout);
        let notified = loop {
            // Double-check after announcing (see the module docs).
            if self.data_ready.swap(false, Ordering::SeqCst) {
                break true;
            }
            // Returns on unpark, on a stale unpark token, spuriously, or at
            // the deadline: the loop re-checks the flag every time.
            match deadline {
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        break false;
                    }
                    std::thread::park_timeout(deadline - now);
                }
                None => std::thread::park(),
            }
        };
        self.sleeping.store(false, Ordering::SeqCst);
        notified
    }

    /// Create a shared notifier wrapped in Arc.
    #[inline]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl Default for WakeNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_atomic_fast_path() {
        let notifier = WakeNotifier::new();

        // Fast path should work without any locks
        assert!(!notifier.is_ready());
        notifier.notify();
        assert!(notifier.is_ready());
        assert!(notifier.check_and_clear());
        assert!(!notifier.is_ready());
    }

    #[test]
    fn test_notify_wakes_waiter() {
        let notifier = Arc::new(WakeNotifier::new());
        let n = Arc::clone(&notifier);

        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            n.notify();
        });

        let start = std::time::Instant::now();
        let woken = notifier.wait_timeout(Duration::from_millis(100));
        let elapsed = start.elapsed();

        assert!(woken, "Should be woken by notify");
        assert!(elapsed < Duration::from_millis(50), "Should wake quickly");

        handle.join().unwrap();
    }

    #[test]
    fn test_timeout_without_notify() {
        let notifier = WakeNotifier::new();

        let start = std::time::Instant::now();
        let woken = notifier.wait_timeout(Duration::from_millis(10));
        let elapsed = start.elapsed();

        assert!(!woken, "Should timeout without notify");
        assert!(
            elapsed >= Duration::from_millis(9),
            "Should wait approximately timeout"
        );
    }

    #[test]
    fn test_immediate_return_if_pending() {
        let notifier = WakeNotifier::new();

        // Pre-notify
        notifier.notify();

        let start = std::time::Instant::now();
        let woken = notifier.wait_timeout(Duration::from_millis(100));
        let elapsed = start.elapsed();

        assert!(woken, "Should return immediately if pending");
        assert!(
            elapsed < Duration::from_millis(5),
            "Should be nearly instant"
        );
    }

    /// Ping-pong between a producer and a parked consumer, the router's
    /// shape: each round the consumer waits, the producer notifies at a
    /// varying point of that wait (before the park, during it). A lost
    /// wakeup shows as a wait that runs to its 2 s timeout.
    #[test]
    fn no_wakeup_is_lost_across_many_park_unpark_rounds() {
        use std::sync::atomic::AtomicU64;
        let notifier = Arc::new(WakeNotifier::new());
        let round = Arc::new(AtomicU64::new(0));
        const ROUNDS: u64 = 2000;
        let (n, r) = (Arc::clone(&notifier), Arc::clone(&round));
        let producer = thread::spawn(move || {
            for i in 1..=ROUNDS {
                while r.load(Ordering::Acquire) < i {
                    std::hint::spin_loop();
                }
                for _ in 0..(i % 7) * 50 {
                    std::hint::spin_loop();
                }
                n.notify();
            }
        });
        for i in 1..=ROUNDS {
            round.store(i, Ordering::Release);
            let start = std::time::Instant::now();
            let woken = notifier.wait_timeout(Duration::from_secs(2));
            assert!(
                woken && start.elapsed() < Duration::from_secs(1),
                "round {i}: woken={woken} after {:?}",
                start.elapsed()
            );
        }
        producer.join().unwrap();
    }

    #[test]
    fn a_timeout_past_what_an_instant_holds_waits_for_the_notify() {
        let notifier = Arc::new(WakeNotifier::new());
        let n = Arc::clone(&notifier);
        let producer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            n.notify();
        });
        assert!(notifier.wait_timeout(Duration::MAX));
        producer.join().unwrap();
    }

    #[test]
    fn test_concurrent_notify_and_wait() {
        let notifier = Arc::new(WakeNotifier::new());

        for _ in 0..100 {
            let n1 = Arc::clone(&notifier);
            let n2 = Arc::clone(&notifier);

            let producer = thread::spawn(move || {
                for _ in 0..100 {
                    n1.notify();
                    std::hint::spin_loop();
                }
            });

            let consumer = thread::spawn(move || {
                let mut received = 0;
                for _ in 0..100 {
                    if n2.check_and_clear() {
                        received += 1;
                    }
                    std::hint::spin_loop();
                }
                received
            });

            producer.join().unwrap();
            let _ = consumer.join().unwrap();
        }
    }
}
