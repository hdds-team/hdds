// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The compare-and-swap consumer gate: the default build's, unchanged from
//! the gate `DataReader` carried before the `fast-consumer-gate` feature.

use std::sync::atomic::{AtomicBool, Ordering};

/// Mutual exclusion among the consumers of a reader's rings (see the
/// `consumer_gate` field of `DataReader`).
///
/// One `AtomicBool`, not a mutex: the uncontended path, which is every
/// acquisition on the crown take path, is one `compare_exchange` and one
/// `store`, where a parking mutex pays a second read-modify-write on
/// release. Contention is the condition case only (a WaitSet thread
/// evaluating while the application thread takes): the loser spins
/// briefly, then yields, and the holder's critical section is bounded by
/// one pump plus one cache pass. There is no poisoning to consider: the
/// guard releases on unwind like a `parking_lot` guard.
pub(crate) struct ConsumerGate {
    held: AtomicBool,
}

/// Holds the [`ConsumerGate`] until dropped.
pub(crate) struct ConsumerGuard<'a> {
    gate: &'a ConsumerGate,
}

impl ConsumerGate {
    pub(crate) const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
        }
    }

    /// Acquire the gate, spinning (then yielding) while another consumer
    /// holds it.
    #[inline]
    pub(crate) fn lock(&self) -> ConsumerGuard<'_> {
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return ConsumerGuard { gate: self };
        }
        self.lock_contended()
    }

    #[cold]
    #[inline(never)]
    fn lock_contended(&self) -> ConsumerGuard<'_> {
        let mut spins: u32 = 0;
        loop {
            if !self.held.load(Ordering::Relaxed)
                && self
                    .held
                    .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return ConsumerGuard { gate: self };
            }
            if spins < 64 {
                spins += 1;
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
    }
}

impl Drop for ConsumerGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        self.gate.held.store(false, Ordering::Release);
    }
}
