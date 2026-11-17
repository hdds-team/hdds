// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! What the router thread does when its receive ring runs empty: how long
//! it spins before it parks, and what it counts while doing so.
//!
//! The counters are plain integers owned by the router thread and copied
//! into [`RouterMetrics`] with relaxed stores at the spin/park transitions
//! only, so a pop that succeeds at once pays nothing for them.

use crate::config::env_flags::RouterSpin;
use crate::engine::router::RouterMetrics;
use crossbeam::queue::ArrayQueue;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// The router thread's ring poll: a pop, then, when the ring is empty, the
/// spin `HDDS_ROUTER_SPIN_US` chose. The caller parks when it returns
/// nothing.
#[derive(Debug)]
pub(crate) struct RouterSpinner {
    mode: RouterSpin,
    /// The spin's wall clock: read when the ring runs empty and when a
    /// spin ends, never on a pop that succeeds at once.
    clock: Instant,
    counters: SpinCounters,
    adaptive: AdaptiveSpin,
    /// Adaptive only: when the ring was found empty, until the next pop
    /// succeeds (the policy's "block"); survives a park that times out.
    empty_since_ns: Option<u64>,
}

impl RouterSpinner {
    pub(crate) fn new(mode: RouterSpin, metrics: &RouterMetrics) -> Self {
        if let RouterSpin::Fixed(budget) = mode {
            metrics
                .spin_budget_ns
                .store(duration_ns(budget), Ordering::Relaxed);
        }
        Self {
            mode,
            clock: Instant::now(),
            counters: SpinCounters::default(),
            adaptive: AdaptiveSpin::new(),
            empty_since_ns: None,
        }
    }

    fn now_ns(&self) -> u64 {
        duration_ns(self.clock.elapsed())
    }

    /// The next item of `ring`, or `None` once the spin found nothing and
    /// the caller should park.
    #[inline]
    pub(crate) fn pop<T>(&mut self, ring: &ArrayQueue<T>, metrics: &RouterMetrics) -> Option<T> {
        if let Some(item) = ring.pop() {
            if self.empty_since_ns.is_some() {
                // First pop after a park: the block's end.
                self.end_block();
            }
            return Some(item);
        }
        self.spin(ring, metrics)
    }

    /// The router thread is about to park.
    #[inline]
    pub(crate) fn park(&mut self, metrics: &RouterMetrics) {
        self.counters.park(metrics);
    }

    fn end_block(&mut self) {
        if let Some(since) = self.empty_since_ns.take() {
            let blocked = self.now_ns().saturating_sub(since);
            self.adaptive.on_block_end(blocked);
        }
    }

    /// The ring was empty: a wall-time budget, fixed or learned. Every spin
    /// is timed so a miss can be counted as wasted CPU.
    #[inline(never)]
    fn spin<T>(&mut self, ring: &ArrayQueue<T>, metrics: &RouterMetrics) -> Option<T> {
        let budget_ns = match self.mode {
            RouterSpin::Fixed(budget) => duration_ns(budget),
            RouterSpin::Adaptive => {
                let now = self.now_ns();
                self.empty_since_ns.get_or_insert(now);
                let budget = self.adaptive.budget_ns(now);
                metrics.spin_budget_ns.store(budget, Ordering::Relaxed);
                budget
            }
        };
        if budget_ns == 0 {
            return None;
        }
        let spin_start = self.now_ns();
        let spun = loop {
            for _ in 0..16 {
                std::hint::spin_loop();
                if let Some(item) = ring.pop() {
                    self.counters.hit(metrics);
                    self.end_block();
                    return Some(item);
                }
            }
            let spun = self.now_ns().saturating_sub(spin_start);
            if spun >= budget_ns {
                break spun;
            }
        };
        self.counters.miss(spun, metrics);
        if self.mode == RouterSpin::Adaptive {
            self.adaptive
                .on_spin_miss(spin_start.saturating_add(spun), spun);
        }
        None
    }
}

fn duration_ns(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// The router thread's own spin counters; see the fields of the same names
/// in [`RouterMetrics`].
#[derive(Debug, Default)]
struct SpinCounters {
    hits: u64,
    misses: u64,
    ns_wasted: u64,
    parks: u64,
}

impl SpinCounters {
    /// A spin popped a datagram.
    #[inline]
    fn hit(&mut self, metrics: &RouterMetrics) {
        self.hits += 1;
        metrics.spin_hits.store(self.hits, Ordering::Relaxed);
    }

    /// A spin of `spun_ns` found nothing.
    #[inline]
    fn miss(&mut self, spun_ns: u64, metrics: &RouterMetrics) {
        self.misses += 1;
        self.ns_wasted = self.ns_wasted.saturating_add(spun_ns);
        metrics.spin_misses.store(self.misses, Ordering::Relaxed);
        metrics
            .spin_ns_wasted
            .store(self.ns_wasted, Ordering::Relaxed);
    }

    /// The router thread is about to park.
    #[inline]
    fn park(&mut self, metrics: &RouterMetrics) {
        self.parks += 1;
        metrics.parks.store(self.parks, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Adaptive budget (`HDDS_ROUTER_SPIN_US=adaptive`)
// ---------------------------------------------------------------------------
//
// Every constant of the policy is here. The figures quoted are from a
// ping/pong request/reply harness on loopback.

/// First non-zero budget, and the floor below which a shrinking budget
/// drops to zero. One spin round (16 ring polls with `PAUSE` between them)
/// plus the clock read that ends it costs on the order of a microsecond,
/// so 2 us is the shortest budget that is still mostly polling rather than
/// bookkeeping. Doubling from here reaches 16 us, which covers the 10 to
/// 12 us loopback request/reply turnaround, in four steps.
pub(crate) const ADAPTIVE_SPIN_START_NS: u64 = 2_000;

/// Largest budget, and the longest ring-empty interval that counts as
/// "a spin would have caught it". Every fixed budget from 15 to 50 us gave
/// the same back-to-back p50 on loopback (15.0 us against 22.5 us without
/// a spin); 50 us leaves room for turnarounds that include wire time or an
/// 8 KiB reply, while staying under the 100 us period of 10 kHz traffic,
/// so periodic gaps at 10 kHz or slower read as "too long to spin for".
pub(crate) const ADAPTIVE_SPIN_MAX_NS: u64 = 50_000;

/// Growth factor after a block a bigger spin would have caught. Doubling
/// (as KVM halt-polling does) converges from 0 to a 12 us turnaround in
/// four blocks, so a back-to-back exchange pays the park path for only its
/// first few round trips.
pub(crate) const ADAPTIVE_SPIN_GROW: u64 = 2;

/// Divisor after a block longer than [`ADAPTIVE_SPIN_MAX_NS`]. Halving
/// rather than resetting keeps a burst that resumes after one silence
/// within one doubling of its learned budget, while periodic traffic
/// (every gap long) reaches 0 from the maximum in five gaps: 1 kHz and
/// 10 kHz showed no p50 gain from any budget, only CPU (+32% and +93% for
/// 20 us against 0).
pub(crate) const ADAPTIVE_SPIN_SHRINK: u64 = 2;

/// Length of the waste accounting window. Long enough to hold 100 periods
/// of 1 kHz traffic, short enough that a budget forced to zero comes back
/// within a tenth of a second once the traffic changes.
pub(crate) const ADAPTIVE_WASTE_WINDOW_NS: u64 = 100_000_000;

/// Missed-spin time allowed per window before the budget is forced to 0
/// until the window rolls: 5% of one core. A 20 us spin at 10 kHz cost
/// about 20 us of CPU per round trip over spin 0 (4.08 against 2.11 s per
/// 100 000), a fifth of a core over the two processes; the cap bounds a
/// workload the rules misjudge at a quarter of that per router thread.
/// The window is fixed, not sliding: at a window boundary the bound is
/// 2 x 5 ms within any 100 ms, which keeps the arithmetic to two integers.
pub(crate) const ADAPTIVE_WASTE_CAP_NS: u64 = ADAPTIVE_WASTE_WINDOW_NS / 20;

/// The adaptive spin budget of one router thread, as a pure state machine
/// over a caller-supplied nanosecond clock, in the style of KVM's
/// halt-polling:
///
/// * a BLOCK is the time from the moment the router found its ring empty
///   to the next successful pop, whether a spin caught the datagram or a
///   park/wake did;
/// * a block no longer than the budget needs nothing;
/// * a block longer than the budget but no longer than
///   [`ADAPTIVE_SPIN_MAX_NS`] means a bigger spin would have caught it:
///   the budget GROWS;
/// * a block longer than [`ADAPTIVE_SPIN_MAX_NS`] means no allowed spin
///   would have: the budget SHRINKS;
/// * missed-spin time is summed per [`ADAPTIVE_WASTE_WINDOW_NS`]; past
///   [`ADAPTIVE_WASTE_CAP_NS`] the budget handed out is 0 until the window
///   rolls (the learned value is kept).
#[derive(Debug, Clone)]
struct AdaptiveSpin {
    learned_ns: u64,
    window_start_ns: u64,
    window_wasted_ns: u64,
}

impl AdaptiveSpin {
    /// Starts at no spin: a router that has seen nothing spins for nothing.
    const fn new() -> Self {
        Self {
            learned_ns: 0,
            window_start_ns: 0,
            window_wasted_ns: 0,
        }
    }

    fn roll_window(&mut self, now_ns: u64) {
        if now_ns.saturating_sub(self.window_start_ns) >= ADAPTIVE_WASTE_WINDOW_NS {
            self.window_start_ns = now_ns;
            self.window_wasted_ns = 0;
        }
    }

    /// The budget for a spin starting at `now_ns`: the learned one, or 0
    /// while this window's missed spins are over the cap.
    fn budget_ns(&mut self, now_ns: u64) -> u64 {
        self.roll_window(now_ns);
        if self.window_wasted_ns >= ADAPTIVE_WASTE_CAP_NS {
            0
        } else {
            self.learned_ns
        }
    }

    /// A spin that started before `now_ns` ran `spun_ns` without a datagram.
    fn on_spin_miss(&mut self, now_ns: u64, spun_ns: u64) {
        self.roll_window(now_ns);
        self.window_wasted_ns = self.window_wasted_ns.saturating_add(spun_ns);
    }

    /// The ring stayed empty for `blocked_ns` before a pop succeeded.
    fn on_block_end(&mut self, blocked_ns: u64) {
        if blocked_ns <= self.learned_ns {
            return;
        }
        if blocked_ns <= ADAPTIVE_SPIN_MAX_NS {
            self.learned_ns = if self.learned_ns == 0 {
                ADAPTIVE_SPIN_START_NS
            } else {
                (self.learned_ns * ADAPTIVE_SPIN_GROW).min(ADAPTIVE_SPIN_MAX_NS)
            };
        } else {
            let shrunk = self.learned_ns / ADAPTIVE_SPIN_SHRINK;
            self.learned_ns = if shrunk < ADAPTIVE_SPIN_START_NS {
                0
            } else {
                shrunk
            };
        }
    }

    /// The learned budget, ignoring the waste cap.
    #[cfg(test)]
    fn learned_ns(&self) -> u64 {
        self.learned_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    const US: u64 = 1_000;

    fn load(a: &std::sync::atomic::AtomicU64) -> u64 {
        a.load(Ordering::Relaxed)
    }

    /// A pop that succeeds at once counts nothing.
    #[test]
    fn an_immediate_pop_counts_nothing() {
        for mode in [
            RouterSpin::Fixed(Duration::from_micros(20)),
            RouterSpin::Adaptive,
        ] {
            let metrics = RouterMetrics::new();
            let mut spinner = RouterSpinner::new(mode, &metrics);
            let ring = ArrayQueue::new(4);
            ring.push(7u32).expect("room");
            assert_eq!(spinner.pop(&ring, &metrics), Some(7));
            assert_eq!(load(&metrics.spin_hits), 0);
            assert_eq!(load(&metrics.spin_misses), 0);
            assert_eq!(load(&metrics.parks), 0);
        }
    }

    /// An item pushed during a long fixed spin is a hit, not a park.
    #[test]
    fn an_item_arriving_during_the_spin_is_a_hit() {
        let metrics = RouterMetrics::new();
        let mut spinner = RouterSpinner::new(RouterSpin::Fixed(Duration::from_secs(10)), &metrics);
        assert_eq!(load(&metrics.spin_budget_ns), 10_000_000_000);
        let ring = Arc::new(ArrayQueue::new(4));
        let pusher = {
            let ring = Arc::clone(&ring);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                ring.push(9u32).expect("room");
            })
        };
        assert_eq!(spinner.pop(&ring, &metrics), Some(9));
        pusher.join().expect("pusher");
        assert_eq!(load(&metrics.spin_hits), 1);
        assert_eq!(load(&metrics.spin_misses), 0);
        assert_eq!(load(&metrics.spin_ns_wasted), 0);
    }

    /// A fixed spin that runs out is a miss charged with at least its
    /// budget; a zero budget spins, misses and charges nothing.
    #[test]
    fn a_spin_that_runs_out_is_a_miss_charged_with_its_time() {
        let metrics = RouterMetrics::new();
        let mut spinner =
            RouterSpinner::new(RouterSpin::Fixed(Duration::from_micros(200)), &metrics);
        let ring = ArrayQueue::<u32>::new(4);
        assert_eq!(spinner.pop(&ring, &metrics), None);
        spinner.park(&metrics);
        assert_eq!(load(&metrics.spin_misses), 1);
        assert!(load(&metrics.spin_ns_wasted) >= 200 * US);
        assert_eq!(load(&metrics.parks), 1);

        let metrics = RouterMetrics::new();
        let mut spinner = RouterSpinner::new(RouterSpin::Fixed(Duration::ZERO), &metrics);
        assert_eq!(spinner.pop(&ring, &metrics), None);
        assert_eq!(load(&metrics.spin_misses), 0);
        assert_eq!(load(&metrics.spin_ns_wasted), 0);
    }

    /// Adaptive, through the real poll: a learned budget is spun and
    /// charged to the waste window, and a block longer than the maximum
    /// (a park that waited 2 ms) halves it.
    #[test]
    fn adaptive_poll_spins_its_budget_and_a_long_block_shrinks_it() {
        let metrics = RouterMetrics::new();
        let mut spinner = RouterSpinner::new(RouterSpin::Adaptive, &metrics);
        spinner.adaptive.learned_ns = 16 * US;
        let ring = ArrayQueue::new(4);
        assert_eq!(spinner.pop(&ring, &metrics), None);
        assert_eq!(load(&metrics.spin_budget_ns), 16 * US);
        assert_eq!(load(&metrics.spin_misses), 1);
        assert!(load(&metrics.spin_ns_wasted) >= 16 * US);
        assert!(spinner.adaptive.window_wasted_ns >= 16 * US);
        spinner.park(&metrics);
        std::thread::sleep(Duration::from_millis(2));
        ring.push(1u32).expect("room");
        assert_eq!(spinner.pop(&ring, &metrics), Some(1));
        assert_eq!(spinner.adaptive.learned_ns(), 8 * US);
        assert_eq!(spinner.empty_since_ns, None, "the block ended");
    }

    /// Adaptive, a datagram caught by the spin ends the block there: the
    /// next block starts fresh. (The learned budget is set out of range
    /// here only so the spin outlasts the pushing thread's sleep.)
    #[test]
    fn adaptive_hit_ends_the_block() {
        let metrics = RouterMetrics::new();
        let mut spinner = RouterSpinner::new(RouterSpin::Adaptive, &metrics);
        spinner.adaptive.learned_ns = 10_000_000_000;
        let ring = Arc::new(ArrayQueue::new(4));
        let pusher = {
            let ring = Arc::clone(&ring);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                ring.push(3u32).expect("room");
            })
        };
        assert_eq!(spinner.pop(&ring, &metrics), Some(3));
        pusher.join().expect("pusher");
        assert_eq!(load(&metrics.spin_hits), 1);
        assert_eq!(spinner.empty_since_ns, None, "the hit ended the block");
        assert_eq!(spinner.adaptive.learned_ns(), 10_000_000_000);
    }

    /// Adaptive with nothing learned does not spin: it parks at once and
    /// counts no miss.
    #[test]
    fn adaptive_poll_with_nothing_learned_parks_without_a_miss() {
        let metrics = RouterMetrics::new();
        let mut spinner = RouterSpinner::new(RouterSpin::Adaptive, &metrics);
        let ring = ArrayQueue::<u32>::new(4);
        assert_eq!(spinner.pop(&ring, &metrics), None);
        assert_eq!(load(&metrics.spin_misses), 0);
        assert_eq!(load(&metrics.spin_budget_ns), 0);
        assert!(spinner.empty_since_ns.is_some(), "the block started");
    }

    /// Drives the policy the way the router loop does, for one block of
    /// `gap_ns` starting at `*now`: spin with the budget handed out; if the
    /// gap is longer, the spin misses (and is charged), the router parks,
    /// and the block ends at the datagram plus `wake_ns` of wake latency.
    /// Returns whether the spin caught the datagram.
    fn block(p: &mut AdaptiveSpin, now: &mut u64, gap_ns: u64, wake_ns: u64) -> bool {
        let start = *now;
        let budget = p.budget_ns(start);
        if gap_ns <= budget {
            *now = start + gap_ns;
            p.on_block_end(gap_ns);
            true
        } else {
            if budget > 0 {
                p.on_spin_miss(start + budget, budget);
            }
            *now = start + gap_ns + wake_ns;
            p.on_block_end(gap_ns + wake_ns);
            false
        }
    }

    /// Back-to-back request/reply: every gap is a 12 us turnaround. The
    /// budget grows until a spin covers it, then every reply is caught.
    #[test]
    fn back_to_back_converges_to_a_budget_that_covers_the_turnaround() {
        let mut p = AdaptiveSpin::new();
        let mut now = 0;
        for _ in 0..10 {
            block(&mut p, &mut now, 12 * US, 3 * US);
        }
        assert!(p.learned_ns() >= 12 * US, "learned {}", p.learned_ns());
        assert!(p.learned_ns() <= ADAPTIVE_SPIN_MAX_NS);
        let caught = (0..1000)
            .filter(|_| block(&mut p, &mut now, 12 * US, 3 * US))
            .count();
        assert_eq!(caught, 1000, "every reply caught once converged");
    }

    /// Periodic traffic at 1 kHz: every gap is 1 ms. Starting from the
    /// largest budget, the policy reaches 0 and stays there.
    #[test]
    fn periodic_1khz_converges_to_no_spin() {
        let mut p = AdaptiveSpin::new();
        p.learned_ns = ADAPTIVE_SPIN_MAX_NS;
        let mut now = 0;
        for _ in 0..10 {
            block(&mut p, &mut now, 1_000 * US, 3 * US);
        }
        assert_eq!(p.learned_ns(), 0);
        for _ in 0..1000 {
            assert!(!block(&mut p, &mut now, 1_000 * US, 3 * US));
            assert_eq!(p.budget_ns(now), 0);
        }
    }

    /// 10 kHz (100 us gaps) is also too long to spin for.
    #[test]
    fn periodic_10khz_converges_to_no_spin() {
        let mut p = AdaptiveSpin::new();
        p.learned_ns = ADAPTIVE_SPIN_MAX_NS;
        let mut now = 0;
        for _ in 0..10 {
            block(&mut p, &mut now, 100 * US, 3 * US);
        }
        assert_eq!(p.learned_ns(), 0);
    }

    /// Bursts of back-to-back exchanges separated by a second of silence:
    /// one silence costs one halving, so the burst that follows catches
    /// its replies again after at most one more miss.
    #[test]
    fn bursts_separated_by_silence_keep_most_of_their_budget() {
        let mut p = AdaptiveSpin::new();
        let mut now = 0;
        for _ in 0..10 {
            block(&mut p, &mut now, 12 * US, 3 * US);
        }
        let converged = p.learned_ns();
        let mut missed_after_silence = 0;
        for _ in 0..20 {
            block(&mut p, &mut now, 1_000_000 * US, 3 * US);
            assert_eq!(p.learned_ns(), converged / ADAPTIVE_SPIN_SHRINK);
            for i in 0..100 {
                if !block(&mut p, &mut now, 12 * US, 3 * US) {
                    assert_eq!(i, 0, "only the first reply of a burst may miss");
                    missed_after_silence += 1;
                }
            }
            assert_eq!(p.learned_ns(), converged);
        }
        assert!(missed_after_silence <= 20);
    }

    /// A block longer than the maximum shrinks the budget, and a shrink
    /// below the start value lands on 0 rather than on a uselessly short
    /// spin.
    #[test]
    fn shrink_halves_and_floors_at_zero() {
        let mut p = AdaptiveSpin::new();
        p.learned_ns = 16 * US;
        p.on_block_end(ADAPTIVE_SPIN_MAX_NS + 1);
        assert_eq!(p.learned_ns(), 8 * US);
        p.learned_ns = ADAPTIVE_SPIN_START_NS;
        p.on_block_end(ADAPTIVE_SPIN_MAX_NS + 1);
        assert_eq!(p.learned_ns(), 0);
        p.on_block_end(ADAPTIVE_SPIN_MAX_NS + 1);
        assert_eq!(p.learned_ns(), 0);
    }

    /// Growth starts at the start value, doubles, stops at the maximum,
    /// and a block exactly at the maximum still counts as catchable.
    #[test]
    fn grow_starts_doubles_and_caps() {
        let mut p = AdaptiveSpin::new();
        p.on_block_end(ADAPTIVE_SPIN_MAX_NS);
        assert_eq!(p.learned_ns(), ADAPTIVE_SPIN_START_NS);
        p.on_block_end(ADAPTIVE_SPIN_MAX_NS);
        assert_eq!(p.learned_ns(), 2 * ADAPTIVE_SPIN_START_NS);
        for _ in 0..20 {
            p.on_block_end(ADAPTIVE_SPIN_MAX_NS);
        }
        assert_eq!(p.learned_ns(), ADAPTIVE_SPIN_MAX_NS);
        // A caught block changes nothing.
        p.on_block_end(1);
        assert_eq!(p.learned_ns(), ADAPTIVE_SPIN_MAX_NS);
    }

    /// Gaps of 40 us: a 50 us spin would catch them, but they
    /// end up missing anyway half the time (e.g. alternating 40 us and
    /// 1 ms). The missed time is capped at 5% of a core per window, and
    /// the cap releases when the window rolls.
    #[test]
    fn the_waste_cap_forces_no_spin_until_the_window_rolls() {
        let mut p = AdaptiveSpin::new();
        p.learned_ns = ADAPTIVE_SPIN_MAX_NS;
        // A first window has gone by: this call opens the next at `now`.
        let mut now = ADAPTIVE_WASTE_WINDOW_NS + 7;
        p.budget_ns(now);
        let window_start = now;
        let mut wasted = 0;
        while p.budget_ns(now) > 0 {
            p.on_spin_miss(now + ADAPTIVE_SPIN_MAX_NS, ADAPTIVE_SPIN_MAX_NS);
            wasted += ADAPTIVE_SPIN_MAX_NS;
            now += 100 * US;
            assert!(now - window_start < ADAPTIVE_WASTE_WINDOW_NS);
        }
        assert!(wasted >= ADAPTIVE_WASTE_CAP_NS);
        assert!(wasted < ADAPTIVE_WASTE_CAP_NS + ADAPTIVE_SPIN_MAX_NS);
        assert_eq!(
            p.learned_ns(),
            ADAPTIVE_SPIN_MAX_NS,
            "the cap keeps the learned value"
        );
        assert_eq!(p.budget_ns(window_start + ADAPTIVE_WASTE_WINDOW_NS - 1), 0);
        assert_eq!(
            p.budget_ns(window_start + ADAPTIVE_WASTE_WINDOW_NS),
            ADAPTIVE_SPIN_MAX_NS
        );
    }

    /// The pathological mix the cap exists for: short gaps a spin would
    /// catch interleaved with a long one, so the budget keeps growing and
    /// shrinking and every long gap (and the short gap after it) is a
    /// missed spin, close to half a core uncapped. Over a second, the
    /// missed time stays within the cap of each window (twice the cap
    /// across a window boundary), and the cap does engage.
    #[test]
    fn alternating_short_and_long_gaps_waste_at_most_the_cap() {
        let mut p = AdaptiveSpin::new();
        let mut now = 0;
        let mut wasted_per_window = std::collections::BTreeMap::<u64, u64>::new();
        while now < 1_000_000 * US {
            for gap in [30 * US, 30 * US, 30 * US, 70 * US] {
                let start = now;
                let budget = p.budget_ns(start);
                if gap > budget && budget > 0 {
                    *wasted_per_window
                        .entry(start / ADAPTIVE_WASTE_WINDOW_NS)
                        .or_default() += budget;
                }
                block(&mut p, &mut now, gap, 3 * US);
            }
        }
        assert!(
            wasted_per_window
                .values()
                .any(|&w| w >= ADAPTIVE_WASTE_CAP_NS),
            "the mix wastes up to the cap: {wasted_per_window:?}"
        );
        for (w, wasted) in wasted_per_window {
            assert!(
                wasted <= 2 * ADAPTIVE_WASTE_CAP_NS + ADAPTIVE_SPIN_MAX_NS,
                "window {w}: {wasted} ns wasted"
            );
        }
    }
}
