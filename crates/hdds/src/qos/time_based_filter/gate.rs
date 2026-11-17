// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The application-boundary half of TIME_BASED_FILTER (DDS v1.4
//! Sec.2.2.3.12).
//!
//! The policy says the application does not want to *see* more than one
//! sample of an instance per `minimum_separation`, and that HISTORY and
//! RELIABILITY "apply after the TIME_BASED_FILTER has been applied". So the
//! separation is measured between the instants two samples become visible to
//! the application, not between their arrivals: a sample that arrives a
//! fraction of a millisecond before the window of the previous one closes is
//! not of interest *yet*, and is neither shown early nor lost.
//!
//! [`Gate`] is that rule for one instance, free of any reader type:
//!
//! - a sample offered while the window is open is shown at once and closes
//!   the window for `minimum_separation`;
//! - a sample offered while it is closed is parked, a newer one replacing
//!   it (the filter selects one sample per window, and "in steady state the
//!   system should guarantee delivery [of] the last sample");
//! - a parked sample is shown at the first access at or after the end of the
//!   window, never before it.
//!
//! A shown sample always closes the window, so two shown samples are never
//! closer than `minimum_separation`, whatever order the calls come in.

use std::time::{Duration, Instant};

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    // @audit-ok: cfg(test) only, one override per test thread, set and read
    // by the same thread within one test
    static TEST_NOW: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// The instant the filter reads. The system's monotonic clock; a test pins
/// it for its own thread with [`set_test_now`].
#[inline]
pub(crate) fn now() -> Instant {
    #[cfg(test)]
    if let Some(pinned) = TEST_NOW.with(Cell::get) {
        return pinned;
    }
    Instant::now()
}

/// Tests only: pin [`now`] on this thread (`None` releases it).
#[cfg(test)]
pub(crate) fn set_test_now(at: Option<Instant>) {
    TEST_NOW.with(|cell| cell.set(at));
}

/// When a sample was produced: its timestamp (the writer's source timestamp
/// when it stamped the change, else its reception), and the writer whose
/// clock that is. Only two stamps of one writer are comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp {
    pub(crate) writer: Option<[u8; 16]>,
    pub(crate) nanos: u64,
}

/// What [`Gate::offer`] decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Offered<S> {
    /// The sample now visible to the application, if any: the offered one
    /// when the window was open and nothing was parked, otherwise the
    /// parked one that was due (the offered one is then parked behind it,
    /// order kept).
    pub(crate) shown: Option<S>,
    /// A parked sample the offered one replaced; it is never shown.
    pub(crate) replaced: Option<S>,
    /// When the parked sample next becomes due, if this call parked a sample
    /// and that instant is not the one already announced: parked into an
    /// empty slot, or replacing a sample whose instant it moved. The
    /// instant to wake the application for.
    pub(crate) wake_at: Option<Instant>,
}

struct Parked<S> {
    sample: S,
    stamp: Option<Stamp>,
}

/// One instance's window and parked sample.
///
/// The separation a sample must keep from the one shown before it is of
/// two kinds. The application must not *see* two samples closer than
/// `separation` (the window, from the instant the previous one became
/// visible); that is strict. And the filter selects the samples "of
/// interest" from a stream: a sample produced less than `separation` (less
/// a jitter allowance, 5 percent) after the previously shown one, by its
/// writer's clock, is the wrong pick when the writer is faster than the
/// separation, and waits for a newer one; it is shown anyway after waiting a
/// full separation, so the last sample of a stream is never lost.
pub(crate) struct Gate<S> {
    shown_at: Option<Instant>,
    shown_stamp: Option<Stamp>,
    parked: Option<Parked<S>>,
}

impl<S> Default for Gate<S> {
    fn default() -> Self {
        Self {
            shown_at: None,
            shown_stamp: None,
            parked: None,
        }
    }
}

impl<S> Gate<S> {
    /// Is the window open at `now`: nothing shown yet, or a full
    /// `separation` elapsed since the last shown sample.
    pub(crate) fn open(&self, separation: Duration, now: Instant) -> bool {
        match self.shown_at {
            None => true,
            Some(at) => now.saturating_duration_since(at) >= separation,
        }
    }

    /// Was a sample with `stamp` produced late enough after the one shown?
    fn picked(&self, separation: Duration, stamp: Option<Stamp>) -> bool {
        let (Some(shown), Some(stamp)) = (self.shown_stamp, stamp) else {
            return true;
        };
        if shown.writer != stamp.writer {
            return true;
        }
        let sep = u64::try_from(separation.as_nanos()).unwrap_or(u64::MAX);
        let allowance = sep / 20;
        stamp.nanos.saturating_add(allowance) >= shown.nanos.saturating_add(sep)
    }

    /// Has a full separation passed since the window ended: a sample that is
    /// not a good pick has waited long enough for a better one.
    fn waited_out(&self, separation: Duration, now: Instant) -> bool {
        match (self.shown_at, separation.checked_mul(2)) {
            (Some(at), Some(twice)) => now.saturating_duration_since(at) >= twice,
            (None, _) => true,
            (Some(_), None) => false,
        }
    }

    /// Is the parked sample to be shown at `now`: the window is open and it
    /// is a good pick or has waited a full separation for a better one.
    fn parked_due(&self, separation: Duration, now: Instant) -> bool {
        let Some(parked) = self.parked.as_ref() else {
            return false;
        };
        self.open(separation, now)
            && (self.picked(separation, parked.stamp) || self.waited_out(separation, now))
    }

    fn show(&mut self, now: Instant, stamp: Option<Stamp>) {
        self.shown_at = Some(now);
        self.shown_stamp = stamp;
    }

    /// Would a sample received at `now`, produced at `stamp`, be shown at
    /// once: nothing waits ahead of it, the window is open and it is a good
    /// pick.
    pub(crate) fn shows_at_once(
        &self,
        separation: Duration,
        now: Instant,
        stamp: Option<Stamp>,
    ) -> bool {
        self.parked.is_none() && self.open(separation, now) && self.picked(separation, stamp)
    }

    /// Show a sample at once, whatever its pick: for a reader that cannot
    /// let a sample wait, which keeps the strict rule (one sample per
    /// separation) and so shows every sample that finds the window open.
    pub(crate) fn show_now(&mut self, now: Instant, stamp: Option<Stamp>, sample: S) -> Offered<S> {
        let replaced = self.parked.take().map(|older| older.sample);
        self.show(now, stamp);
        Offered {
            shown: Some(sample),
            replaced,
            wake_at: None,
        }
    }

    /// Offer a sample received at `now`, produced at `stamp`.
    pub(crate) fn offer(
        &mut self,
        separation: Duration,
        now: Instant,
        stamp: Option<Stamp>,
        sample: S,
    ) -> Offered<S> {
        if self.parked_due(separation, now) {
            // The older parked sample goes first; the offered one waits a
            // full separation behind it.
            if let Some(older) = self.parked.take() {
                self.show(now, older.stamp);
                self.parked = Some(Parked { sample, stamp });
                return Offered {
                    shown: Some(older.sample),
                    replaced: None,
                    wake_at: self.ready_at(separation),
                };
            }
        }
        let announced = self.ready_at(separation);
        let replaced = self.parked.take().map(|older| older.sample);
        if self.open(separation, now) && self.picked(separation, stamp) {
            self.show(now, stamp);
            return Offered {
                shown: Some(sample),
                replaced,
                wake_at: None,
            };
        }
        self.parked = Some(Parked { sample, stamp });
        // A replacement may move the instant the parked sample is due (a
        // better pick is due when the window ends, a poorer one when it has
        // waited): the application is woken for the new instant.
        let ready = self.ready_at(separation);
        Offered {
            shown: None,
            replaced,
            wake_at: if ready == announced { None } else { ready },
        }
    }

    /// The parked sample, if it is due at `now`; it is shown now.
    pub(crate) fn due(&mut self, separation: Duration, now: Instant) -> Option<S> {
        if !self.parked_due(separation, now) {
            return None;
        }
        let parked = self.parked.take()?;
        self.show(now, parked.stamp);
        Some(parked.sample)
    }

    /// When the parked sample becomes due, `None` if nothing is parked or
    /// it never will (a separation too long to be added to an instant).
    pub(crate) fn ready_at(&self, separation: Duration) -> Option<Instant> {
        let parked = self.parked.as_ref()?;
        // Nothing shown yet: nothing keeps the sample waiting.
        let Some(shown_at) = self.shown_at else {
            return Some(now());
        };
        let window = shown_at.checked_add(separation)?;
        if self.picked(separation, parked.stamp) {
            Some(window)
        } else {
            window.checked_add(separation)
        }
    }

    /// The parked sample, without taking it.
    pub(crate) fn parked_sample(&self) -> Option<&S> {
        self.parked.as_ref().map(|parked| &parked.sample)
    }

    /// Whether a sample is parked.
    pub(crate) fn is_parked(&self) -> bool {
        self.parked.is_some()
    }

    /// Take the parked sample out without showing it (the instance changed
    /// under it, or the reader is going away).
    pub(crate) fn discard(&mut self) -> Option<S> {
        self.parked.take().map(|parked| parked.sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEP: Duration = Duration::from_secs(1);

    fn t(ms: u64, base: Instant) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn first_sample_is_shown_at_once() {
        let base = Instant::now();
        let mut gate = Gate::default();
        let out = gate.offer(SEP, base, None, 1);
        assert_eq!(out.shown, Some(1));
        assert!(!gate.is_parked());
    }

    #[test]
    fn a_sample_a_hair_early_is_parked_not_shown() {
        let base = Instant::now();
        let mut gate = Gate::default();
        gate.offer(SEP, base, None, 1);
        let out = gate.offer(SEP, t(999, base), None, 2);
        assert_eq!(out.shown, None);
        assert_eq!(out.wake_at, Some(t(1000, base)));
        assert!(gate.is_parked());
    }

    #[test]
    fn a_parked_sample_is_not_due_before_the_window_ends() {
        let base = Instant::now();
        let mut gate = Gate::default();
        gate.offer(SEP, base, None, 1);
        gate.offer(SEP, t(999, base), None, 2);
        assert_eq!(gate.due(SEP, t(999, base)), None);
        assert_eq!(gate.due(SEP, t(1000, base)), Some(2));
    }

    #[test]
    fn the_newest_parked_sample_wins() {
        let base = Instant::now();
        let mut gate = Gate::default();
        gate.offer(SEP, base, None, 1);
        gate.offer(SEP, t(100, base), None, 2);
        let out = gate.offer(SEP, t(200, base), None, 3);
        assert_eq!(out.replaced, Some(2));
        assert_eq!(gate.due(SEP, t(1000, base)), Some(3));
    }

    #[test]
    fn a_replacement_that_keeps_the_due_instant_does_not_announce_it_again() {
        let base = Instant::now();
        let mut gate = Gate::default();
        gate.offer(SEP, base, None, 1);
        let first = gate.offer(SEP, t(100, base), None, 2);
        assert_eq!(first.wake_at, Some(t(1000, base)));
        let out = gate.offer(SEP, t(200, base), None, 3);
        assert_eq!(out.replaced, Some(2));
        assert_eq!(out.wake_at, None, "still due at 1000: already announced");
    }

    fn stamp(ms: u64) -> Option<Stamp> {
        Some(Stamp {
            writer: Some([1; 16]),
            nanos: ms * 1_000_000,
        })
    }

    #[test]
    fn a_replacement_that_moves_the_due_instant_announces_the_new_one() {
        let base = Instant::now();
        let mut gate = Gate::default();
        gate.offer(SEP, base, stamp(0), 1);
        // A poor pick: due a full separation after the window ends, 2000.
        let poor = gate.offer(SEP, t(100, base), stamp(100), 2);
        assert_eq!(poor.wake_at, Some(t(2000, base)));
        // A good pick replaces it: due when the window ends, 1000.
        let good = gate.offer(SEP, t(990, base), stamp(990), 3);
        assert_eq!(good.replaced, Some(2));
        assert_eq!(good.wake_at, Some(t(1000, base)));
        assert_eq!(gate.due(SEP, t(1000, base)), Some(3));
        // And the other way round: a poor pick behind a good one is due
        // later than the good one was.
        let mut gate = Gate::default();
        gate.offer(SEP, base, stamp(0), 1);
        let good = gate.offer(SEP, t(990, base), stamp(990), 2);
        assert_eq!(good.wake_at, Some(t(1000, base)));
        let poor = gate.offer(SEP, t(995, base), stamp(100), 3);
        assert_eq!(poor.replaced, Some(2));
        assert_eq!(poor.wake_at, Some(t(2000, base)));
        assert_eq!(gate.due(SEP, t(1999, base)), None);
        assert_eq!(gate.due(SEP, t(2000, base)), Some(3));
    }

    #[test]
    fn a_stream_that_keeps_arriving_cannot_postpone_the_fallback() {
        let base = Instant::now();
        let mut gate = Gate::default();
        gate.offer(SEP, base, stamp(0), 0);
        // Stamps that never advance: no sample is a good pick. One arrives
        // every 100 ms; the poll finds the window open from 1000 on.
        let mut shown = None;
        for k in 1..=40u64 {
            let at = t(100 * k, base);
            let out = gate.offer(SEP, at, stamp(0), k);
            if out.shown.is_some() {
                shown = Some((100 * k, out.shown));
                break;
            }
            if let Some(sample) = gate.due(SEP, at) {
                shown = Some((100 * k, Some(sample)));
                break;
            }
        }
        let (at_ms, sample) = shown.expect("a stream must not starve the application");
        assert_eq!(at_ms, 2000, "a full separation after the window ended");
        assert_eq!(sample, Some(19), "the newest parked");
    }

    #[test]
    fn a_sample_without_a_stamp_is_always_a_good_pick() {
        let base = Instant::now();
        let mut gate = Gate::default();
        gate.offer(SEP, base, stamp(0), 1);
        gate.offer(SEP, t(100, base), None, 2);
        assert_eq!(gate.ready_at(SEP), Some(t(1000, base)));
    }

    #[test]
    fn a_separation_too_long_for_an_instant_does_not_panic() {
        let base = Instant::now();
        let huge = Duration::MAX;
        let mut gate = Gate::default();
        assert_eq!(gate.offer(huge, base, None, 1).shown, Some(1));
        let parked = gate.offer(huge, t(10, base), None, 2);
        assert_eq!(parked.shown, None);
        assert_eq!(parked.wake_at, None, "it is never due");
        let again = gate.offer(huge, t(20, base), stamp(5), 3);
        assert_eq!(again.replaced, Some(2));
        assert_eq!(gate.ready_at(huge), None);
        assert_eq!(gate.due(huge, t(30, base)), None);
        assert!(gate.is_parked());
    }

    #[test]
    fn a_shown_sample_closes_the_window_for_a_full_separation() {
        let base = Instant::now();
        let mut gate = Gate::default();
        gate.offer(SEP, base, None, 1);
        // Shown late (the application polled at 1050): the next window
        // starts there, not at the arrival.
        assert_eq!(gate.due(SEP, t(1050, base)), None);
        gate.offer(SEP, t(999, base), None, 2);
        assert_eq!(gate.due(SEP, t(1050, base)), Some(2));
        gate.offer(SEP, t(1100, base), None, 3);
        assert_eq!(gate.due(SEP, t(2049, base)), None);
        assert_eq!(gate.due(SEP, t(2050, base)), Some(3));
    }

    #[test]
    fn an_open_offer_behind_a_parked_sample_keeps_order_and_separation() {
        let base = Instant::now();
        let mut gate = Gate::default();
        gate.offer(SEP, base, None, 1);
        gate.offer(SEP, t(999, base), None, 2);
        // Nobody called `due`: the window is open when 3 arrives. The older
        // parked sample is the one shown; 3 waits a full separation.
        let out = gate.offer(SEP, t(1001, base), None, 3);
        assert_eq!(out.shown, Some(2));
        assert_eq!(out.wake_at, Some(t(2001, base)));
        assert_eq!(gate.due(SEP, t(2000, base)), None);
        assert_eq!(gate.due(SEP, t(2001, base)), Some(3));
    }
}
