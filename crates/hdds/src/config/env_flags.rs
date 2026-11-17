// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Process-lifetime answers for the environment knobs that sit on packet
//! paths.
//!
//! # Why this module exists (the measurement)
//!
//! `std::env::var` is not free and it is not constant. Measured on a
//! benchmark host (performance governor): **31.42 ns** per call
//! with a 20-variable environment, and the cost is **linear in environment
//! size** - 152.4 ns at 60 variables, 267.2 ns at 100 variables, roughly
//! 2.9 ns per entry. It also takes a process-wide reader lock over the
//! environment block, and a participant runs four listener threads, so the
//! per-packet reads were also contending with each other.
//!
//! Before this module, nine call sites on packet paths each did their own
//! `env::var` - two per received datagram in the multicast listener, two
//! per routed sample in the router, three per *sent* packet in
//! `UdpTransport` (those three also allocated a `String` to run
//! `contains`), one per SPDP announcement, one per unknown-writer GUID
//! miss - plus four more on the SEDP/matching paths. That is one reader
//! per site; this module is one reader per *question*.
//!
//! # The contract: read once, on first use
//!
//! Each knob is answered the first time anything asks for it and that
//! answer is kept for the life of the process. **A knob set after the
//! first packet is not seen.** That is deliberate, not an accident of
//! caching: the environment of a running process is not a control surface,
//! and treating it as one is what makes the read expensive in the first
//! place.
//!
//! This is safe on this tree because nothing writes these four variables
//! after HDDS is running. A sweep of `set_var` across `crates/` finds:
//!
//! - `HDDS_LOG_UDP` is written at the top of `main()` in two examples
//!   (`examples/test_two_participant_discovery.rs`,
//!   `examples/test_spdp_discovery.rs`), both before any HDDS object
//!   exists.
//! - `RUST_LOG` is written by `rmw-hdds`'s `EnvConfig::apply_log_level`
//!   (`crates/rmw-hdds/src/env_config.rs`), called from `ffi.rs` at
//!   context init, before any participant is built and therefore before
//!   any packet is sent.
//! - `HDDS_INTEROP_DIAGNOSTICS` and
//!   `HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC` are never written
//!   anywhere in this workspace; they are operator-set only.
//!
//! That sweep is a snapshot, not a guarantee about
//! the future: a new `set_var` on one of these four names after a
//! participant exists would silently be a no-op from this module's point
//! of view.
//!
//! A fifth variable, `HDDS_ROUTER_SPIN_US` is a number
//! or `adaptive` rather than a flag, so it has its own process-lifetime cell
//! ([`router_spin`]) and its own decoder ([`parse_router_spin_us`])
//! instead of a [`Knob`]; same contract: read once, when the first router
//! thread starts. No `set_var` of it exists anywhere in the workspace.
//!
//! # Why the language agrees
//!
//! `std::env::set_var` and `remove_var` became `unsafe` in edition 2024
//! for exactly this reason: writing the environment of a process that has
//! already started threads races with every concurrent `getenv`, including
//! the ones inside libc. This crate is on edition 2021, where they are
//! still safe by signature, but the hazard is the same one. Reading each
//! knob once, before the threads that would race are doing anything
//! interesting, is the shape that stays correct under both editions.
//!
//! # Testing seam
//!
//! There is exactly ONE cache per kind of answer ([`Knob::get`] for the
//! flags, [`router_spin`] for the one number) and one decoder per
//! question ([`is_present`], [`selects_hdds_debug`],
//! [`parse_router_spin_us`]). A defect in caching, in
//! polarity, or in a variable name therefore has exactly one place to
//! live, and the unit tests below address those places directly rather
//! than trying to observe them through nine call sites. The end-to-end
//! contract that needs a real process environment - "the answer is fixed
//! by the first read", and the `demux` gate seen from both sides - is
//! pinned by three single-test integration binaries
//! (`tests/env_flags_answer_is_fixed_by_first_read.rs`,
//! `tests/env_flags_fallback_off_by_default.rs`,
//! `tests/env_flags_fallback_on_when_set.rs`). Each mutates process-global
//! environment and so must not share a process with a parallel reader; the
//! gate needs two of them because a cached knob can only show one side per
//! process.

use std::env::VarError;
use std::sync::OnceLock;

/// One knob: the variable that carries it, the rule that reads that
/// variable, and the process-lifetime answer.
///
/// The `decide` indirection exists so the polarity of a knob (present vs
/// absent, substring vs presence) is a named function that a test can call
/// with a synthetic `Result`, instead of behaviour that can only be reached
/// by mutating the environment of the test process.
struct Knob {
    /// The environment variable name, written as a literal at the
    /// definition site. Deliberately NOT a shared constant: a test that
    /// pinned the name against the same constant the lookup uses would
    /// pass no matter what that constant said.
    var: &'static str,
    /// How this knob reads its variable's value.
    decide: fn(Result<String, VarError>) -> bool,
    /// The answer, computed at most once for the life of the process.
    answer: OnceLock<bool>,
}

impl Knob {
    const fn new(var: &'static str, decide: fn(Result<String, VarError>) -> bool) -> Self {
        Self {
            var,
            decide,
            answer: OnceLock::new(),
        }
    }

    /// The knob's answer. The first caller in the process reads the
    /// environment; every later caller, on this thread or any other, gets
    /// that same answer without touching the environment again.
    #[inline]
    fn get(&self) -> bool {
        *self
            .answer
            .get_or_init(|| (self.decide)(std::env::var(self.var)))
    }
}

/// Presence test: the knob is ON when the variable is set to anything at
/// all, including the empty string.
///
/// This is the exact semantics of the `std::env::var(..).is_ok()` that the
/// call sites used before. A non-UTF-8 value reads as `Err(NotUnicode)` and
/// therefore as OFF, which is also what `is_ok()` did.
fn is_present(value: Result<String, VarError>) -> bool {
    value.is_ok()
}

/// Substring test: ON when the value CONTAINS `hdds=debug`.
///
/// `RUST_LOG` is a filter expression, not a flag: `RUST_LOG=info` must not
/// turn HDDS debug logging on, and `RUST_LOG=warn,hdds=debug` must. A
/// presence test here would make every process that sets `RUST_LOG` at all
/// pay for per-packet debug formatting.
fn selects_hdds_debug(value: Result<String, VarError>) -> bool {
    match value {
        Ok(filter) => filter.contains("hdds=debug"),
        Err(_) => false,
    }
}

static INTEROP_DIAGNOSTICS: Knob = Knob::new("HDDS_INTEROP_DIAGNOSTICS", is_present);
static ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC: Knob =
    Knob::new("HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC", is_present);
static UDP_SEND_DEBUG_LOG: Knob = Knob::new("RUST_LOG", selects_hdds_debug);
static SPDP_ANNOUNCE_DEBUG_LOG: Knob = Knob::new("HDDS_LOG_UDP", is_present);

/// Interop diagnostics: dump submessage enumerations, DATA payload heads,
/// SEDP QoS PIDs, and run the diagnostic matcher alongside the real one.
///
/// ON when `HDDS_INTEROP_DIAGNOSTICS` is set to anything.
#[inline]
pub fn interop_diagnostics() -> bool {
    INTEROP_DIAGNOSTICS.get()
}

/// The unknown-writer fallback in `engine::demux`: bind a writer GUID that
/// no SEDP announced to the single local topic that has subscribers.
///
/// ON when `HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC` is set to anything.
/// The fallback is OFF by default - it is a discovery workaround for peers
/// that do not announce SEDP Publications, and guessing a topic is not
/// something to do unasked.
#[inline]
pub fn route_unknown_writer_to_single_topic() -> bool {
    ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC.get()
}

/// Per-sent-packet debug logging in `transport::udp`.
///
/// ON when `RUST_LOG` CONTAINS `hdds=debug`. Not a presence test: see
/// [`selects_hdds_debug`].
#[inline]
pub fn udp_send_debug_log() -> bool {
    UDP_SEND_DEBUG_LOG.get()
}

/// Per-announcement debug logging in the SPDP announce loop.
///
/// ON when `HDDS_LOG_UDP` is set to anything.
#[inline]
pub fn spdp_announce_debug_log() -> bool {
    SPDP_ANNOUNCE_DEBUG_LOG.get()
}

/// Upper bound on a numeric [`router_spin`] budget: the router's own idle wait is
/// 10 ms, so a spin longer than that is never what anyone means.
pub const ROUTER_SPIN_BUDGET_MAX_US: u64 = 10_000;

/// What the router thread does, once its receive ring runs empty, before it
/// parks; chosen by `HDDS_ROUTER_SPIN_US`, read once per process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterSpin {
    /// A whole number of microseconds: spin for that much wall time,
    /// clamped to [`ROUTER_SPIN_BUDGET_MAX_US`]; `0` does not spin at all,
    /// parking at once.
    Fixed(std::time::Duration),
    /// Variable unset, empty or not understood, or set to `adaptive` (any
    /// case): the default. Each router thread learns its budget from how
    /// long its ring stays empty, between 0 and 50 us, and stops spinning
    /// while its missed spins exceed 5% of a core (see `engine::router_spin`).
    Adaptive,
}

/// Reads `HDDS_ROUTER_SPIN_US`: a whole number of microseconds clamped to
/// [`ROUTER_SPIN_BUDGET_MAX_US`]. Unset, empty, negative, not a number, or
/// `adaptive` (any case) reads as [`RouterSpin::Adaptive`], the default.
fn parse_router_spin_us(value: Result<String, VarError>) -> RouterSpin {
    let Ok(value) = value else {
        return RouterSpin::Adaptive;
    };
    let value = value.trim();
    if value.eq_ignore_ascii_case("adaptive") {
        return RouterSpin::Adaptive;
    }
    match value.parse::<u64>() {
        Ok(us) => RouterSpin::Fixed(std::time::Duration::from_micros(
            us.min(ROUTER_SPIN_BUDGET_MAX_US),
        )),
        Err(_) => RouterSpin::Adaptive,
    }
}

static ROUTER_SPIN: OnceLock<RouterSpin> = OnceLock::new();

/// How the router thread spins on its receive ring, after the ring runs
/// empty, before it parks; read once per process.
///
/// [`RouterSpin::Adaptive`] is the default (`HDDS_ROUTER_SPIN_US` unset,
/// empty, or `adaptive`): each thread learns its own budget. A whole number
/// of microseconds spins that much wall time instead, fixed; `0` restores
/// the old park-immediately behaviour (no spin at all). The historical
/// 200-`PAUSE` spin (duration depending on the CPU microarchitecture) has
/// been removed: measured on loopback, it
/// was dominated by adaptive on p50 in every regime, and by `0` on CPU.
///
/// A spin wins only when the next datagram arrives within it: the router
/// then skips a park and a futex wake. Otherwise it is CPU spent per
/// datagram for nothing. Back-to-back request/reply at 64 B went from
/// ~23.8 us p50 (no spin) to ~16.5 us with a 20 us fixed budget or with
/// adaptive, the two statistically equal; at a fixed 1/5/10 kHz rate no
/// budget changed the p50 (adaptive's learned budget stays at 0 there),
/// and a fixed 20 us budget cost noticeably more CPU for no p50 gain. The
/// router's `spin_hits`, `spin_misses` and `spin_ns_wasted` counters
/// (`RouterMetrics`) count what any setting catches and burns on a given
/// workload; see docs/changelog.md and docs/reference/environment-vars.md for
/// the full measurement table.
#[inline]
pub fn router_spin() -> RouterSpin {
    *ROUTER_SPIN.get_or_init(|| parse_router_spin_us(std::env::var("HDDS_ROUTER_SPIN_US")))
}

#[cfg(test)]
mod tests {
    use super::{
        is_present, parse_router_spin_us, selects_hdds_debug, Knob, RouterSpin,
        INTEROP_DIAGNOSTICS, ROUTER_SPIN_BUDGET_MAX_US, ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC,
        SPDP_ANNOUNCE_DEBUG_LOG, UDP_SEND_DEBUG_LOG,
    };
    use std::env::VarError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A decoder that answers differently on every call, so a `Knob` that
    /// did NOT cache would be visible without touching the process
    /// environment.
    fn different_every_call(_value: Result<String, VarError>) -> bool {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        CALLS.fetch_add(1, Ordering::Relaxed) == 0
    }

    /// The name is never set by anything; what this knob reads does not
    /// matter, only how many times it reads it.
    static CACHE_PROBE: Knob = Knob::new(
        "HDDS_ENV_FLAGS_CACHE_PROBE_THIS_NAME_IS_NEVER_SET",
        different_every_call,
    );

    /// The caching contract, observed without mutating the environment:
    /// `different_every_call` returns true on its first call and false
    /// afterwards, so three `true`s can only mean the decoder ran once.
    ///
    /// Kills: dropping `get_or_init` from [`Knob::get`] and calling the
    /// decoder on every access.
    #[test]
    fn a_knob_runs_its_decoder_exactly_once() {
        assert!(CACHE_PROBE.get(), "first read runs the decoder");
        assert!(CACHE_PROBE.get(), "second read must not run the decoder");
        assert!(CACHE_PROBE.get(), "nor the third");
    }

    /// Presence polarity, both sides.
    ///
    /// `VarError::NotPresent` is the absent case; `NotUnicode` is a value
    /// this crate cannot read, and OFF is what `env::var(..).is_ok()`
    /// answered for it before this module existed.
    #[test]
    fn is_present_is_on_only_when_the_variable_is_set() {
        assert!(!is_present(Err(VarError::NotPresent)));
        assert!(!is_present(Err(VarError::NotUnicode("x".into()))));
        assert!(is_present(Ok(String::new())), "empty value is still set");
        assert!(is_present(Ok("1".to_string())));
        assert!(is_present(Ok("0".to_string())), "no value is parsed");
    }

    /// `RUST_LOG` is a filter expression: the rule is CONTAINS
    /// `hdds=debug`, not "is set".
    ///
    /// Kills: turning [`selects_hdds_debug`] into a presence test - the
    /// `RUST_LOG=info` case below is set and must still be OFF.
    #[test]
    fn selects_hdds_debug_matches_the_substring_not_the_presence() {
        assert!(!selects_hdds_debug(Err(VarError::NotPresent)));
        assert!(!selects_hdds_debug(Ok(String::new())), "set but empty");
        assert!(!selects_hdds_debug(Ok("info".to_string())), "set but other");
        assert!(!selects_hdds_debug(Ok("hdds=trace".to_string())));
        assert!(selects_hdds_debug(Ok("hdds=debug".to_string())));
        assert!(selects_hdds_debug(Ok("warn,hdds=debug".to_string())));
        assert!(selects_hdds_debug(Ok("hdds=debug,h2=off".to_string())));
    }

    /// Each knob reads the variable its documentation names.
    ///
    /// The expected names are typed out here as literals on purpose: a
    /// test that compared `INTEROP_DIAGNOSTICS.var` against a shared
    /// constant would pass for any value that constant took.
    #[test]
    fn each_knob_is_wired_to_its_own_variable() {
        assert_eq!(INTEROP_DIAGNOSTICS.var, "HDDS_INTEROP_DIAGNOSTICS");
        assert_eq!(
            ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC.var,
            "HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC"
        );
        assert_eq!(UDP_SEND_DEBUG_LOG.var, "RUST_LOG");
        assert_eq!(SPDP_ANNOUNCE_DEBUG_LOG.var, "HDDS_LOG_UDP");
    }

    /// Each knob reads its variable with the rule its documentation
    /// names.
    ///
    /// Pinned by BEHAVIOUR, not by function-pointer identity: `Ok("info")`
    /// is a value the two rules disagree about (set, so present; no
    /// `hdds=debug`, so not a debug selector), so this fails if any knob is
    /// wired to the other rule. `RUST_LOG=info` is also the case that
    /// matters in the field - it is what a ROS 2 node gets by default.
    #[test]
    fn each_knob_is_wired_to_its_own_rule() {
        let set_but_not_debug = || Ok("info".to_string());
        assert!(
            (INTEROP_DIAGNOSTICS.decide)(set_but_not_debug()),
            "interop diagnostics is a presence test"
        );
        assert!(
            (ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC.decide)(set_but_not_debug()),
            "the unknown-writer fallback is a presence test"
        );
        assert!(
            !(UDP_SEND_DEBUG_LOG.decide)(set_but_not_debug()),
            "RUST_LOG=info must NOT turn per-packet udp debug logging on"
        );
        assert!(
            (SPDP_ANNOUNCE_DEBUG_LOG.decide)(set_but_not_debug()),
            "HDDS_LOG_UDP is a presence test"
        );
    }

    /// The public accessors are stable across calls.
    ///
    /// This is the caching contract as a CALLER sees it. It cannot tell a
    /// cached read from a repeated one on its own - the environment does
    /// not change under `cargo test` - which is why
    /// `a_knob_runs_its_decoder_exactly_once` above and the
    /// `env_flags_answer_is_fixed_by_first_read` integration binary exist.
    /// What it does pin is that no accessor is stateful in some other way.
    #[test]
    fn every_accessor_answers_the_same_thing_twice() {
        assert_eq!(super::interop_diagnostics(), super::interop_diagnostics());
        assert_eq!(
            super::route_unknown_writer_to_single_topic(),
            super::route_unknown_writer_to_single_topic()
        );
        assert_eq!(super::udp_send_debug_log(), super::udp_send_debug_log());
        assert_eq!(
            super::spdp_announce_debug_log(),
            super::spdp_announce_debug_log()
        );
    }

    #[test]
    fn router_spin_reads_adaptive_or_whole_microseconds_and_clamps() {
        use std::time::Duration;
        let v = |x: &str| parse_router_spin_us(Ok(x.to_string()));
        assert_eq!(
            parse_router_spin_us(Err(VarError::NotPresent)),
            RouterSpin::Adaptive
        );
        assert_eq!(v(""), RouterSpin::Adaptive);
        assert_eq!(v("-5"), RouterSpin::Adaptive);
        assert_eq!(v("1.5"), RouterSpin::Adaptive);
        assert_eq!(v("twenty"), RouterSpin::Adaptive);
        assert_eq!(v("adaptiv"), RouterSpin::Adaptive);
        assert_eq!(v("adaptive"), RouterSpin::Adaptive);
        assert_eq!(v(" Adaptive\n"), RouterSpin::Adaptive);
        assert_eq!(v("0"), RouterSpin::Fixed(Duration::ZERO));
        assert_eq!(v(" 20 "), RouterSpin::Fixed(Duration::from_micros(20)));
        assert_eq!(
            v("99999999"),
            RouterSpin::Fixed(Duration::from_micros(ROUTER_SPIN_BUDGET_MAX_US))
        );
    }
}
