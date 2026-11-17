// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The time the liveliness scheduler reads.
//!
//! Every instant the scheduler and the renewal records compare is a count
//! of nanoseconds on one clock (`Nanos`), so a test can drive time instead
//! of sleeping: `ManualClock` only moves when told to, and the scheduler
//! then waits for a poke rather than for a timeout.

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Nanoseconds on a [`LivelinessClock`].
pub(crate) type Nanos = u64;

/// A lease that never expires.
pub(crate) const INFINITE: Nanos = u64::MAX;

/// The clock of a participant's liveliness.
pub(crate) trait LivelinessClock: Send + Sync {
    /// Now, in nanoseconds since the clock's origin.
    fn now(&self) -> Nanos;

    /// How long the scheduler may sleep for `ns` of this clock: `Some`
    /// for a clock that moves on its own, `None` for one that only moves
    /// when a test advances it (the scheduler then waits for a poke).
    fn sleep_for(&self, ns: Nanos) -> Option<Duration>;
}

/// The monotonic clock, from the instant it was made.
pub(crate) struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    pub(crate) fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl LivelinessClock for MonotonicClock {
    #[inline]
    fn now(&self) -> Nanos {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn sleep_for(&self, ns: Nanos) -> Option<Duration> {
        Some(Duration::from_nanos(ns))
    }
}

/// A clock that moves only when told to (`advance`).
#[cfg(test)]
#[derive(Default)]
pub(crate) struct ManualClock {
    now: AtomicU64,
}

#[cfg(test)]
impl ManualClock {
    pub(crate) fn new(start: Nanos) -> Self {
        Self {
            now: AtomicU64::new(start),
        }
    }

    pub(crate) fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        self.now.fetch_add(by, Ordering::SeqCst);
    }
}

#[cfg(test)]
impl LivelinessClock for ManualClock {
    fn now(&self) -> Nanos {
        self.now.load(Ordering::SeqCst)
    }

    fn sleep_for(&self, _ns: Nanos) -> Option<Duration> {
        None
    }
}

/// `lease` in nanoseconds; [`INFINITE`] for the infinite one (DDS v1.4
/// Sec.2.2.3.11 default) and for one too long to count in nanoseconds.
pub(crate) fn lease_nanos(lease: Duration) -> Nanos {
    if lease == Duration::from_secs(u64::MAX) {
        return INFINITE;
    }
    u64::try_from(lease.as_nanos()).unwrap_or(INFINITE)
}
