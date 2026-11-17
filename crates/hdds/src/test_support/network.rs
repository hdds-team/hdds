// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Pin every test participant in this process onto the loopback interface,
//! so discovery-dependent tests stop reporting host routing instead of
//! HDDS's own behavior.
//!
//! # The diagnosis
//!
//! On a host where a VPN/tunnel client (Cloudflare WARP, WireGuard, ...) has
//! installed itself as the default route for multicast, the kernel routes
//! RTPS's well-known multicast groups into the tunnel instead of the LAN
//! NIC, regardless of how many other multicast-capable interfaces exist:
//!
//! ```text
//! $ ip route get 239.255.0.2
//! multicast 239.255.0.2 dev CloudflareWARP table 65743 src 172.16.0.2
//! ```
//!
//! Two participants that both auto-detect their interface still find each
//! other (both land on the tunnel), but a participant pinned to the LAN NIC
//! (`HDDS_INTERFACE=<lan ip>`) sends multicast nobody listening on
//! `INADDR_ANY` ever sees, and vice versa. Without the pin, tests that need
//! discovery fail at their own "SPDP discovery never completed" assertion;
//! with `HDDS_INTERFACE=lo` they pass. The cause is the host's routing
//! table, not a sandbox limitation.
//!
//! This module pins `127.0.0.1` rather than the name `lo`: `transport::
//! multicast::resolve_forced_interface` tries an IPv4 parse before an
//! interface-name lookup, so the numeric address resolves with no
//! `getifaddrs` round trip and, unlike `lo`, is spelled the same way on
//! every platform this crate targets (macOS names the loopback device
//! `lo0`).
//!
//! `HDDS_INTERFACE` (see `transport::multicast`) is HDDS's existing,
//! documented answer to "which interface should this participant use", the
//! same knob a deployment behind a VPN or on a multi-NIC host is told to
//! set. Pointing it at loopback removes host routing from the picture
//! entirely: two participants in the same process or two sibling processes
//! on the same machine always share `127.0.0.1`, independent of whatever
//! tunnel, container bridge or second NIC the test happens to run behind.
//!
//! # Why this is wired into [`super::domains::unique_domain`], not left for
//! each test to remember
//!
//! A test author cannot forget to call this, because they cannot write a
//! working multi-participant test without leasing a domain first (see that
//! module's own reasoning about hardcoded domain ids) -- the domain lease
//! is already the one call every such test makes before touching the
//! transport layer. Piggy-backing here means every EXISTING discovery test
//! (this crate has dozens) became hermetic without editing any of them, and
//! nothing about the file a future test lives in matters: forgetting this
//! module is a different failure than forgetting a step, it would require
//! forgetting to lease a domain, which fails that test immediately for an
//! unrelated reason (a hardcoded domain colliding with another test).
//!
//! It does not belong to [`super::domains`] itself: that module's whole
//! reasoning is about port arbitration, not network interfaces, and a
//! reader auditing "why did this test bind loopback" should find that
//! reasoning here, one hop away, rather than buried in a doc comment about
//! ephemeral port ranges.
//!
//! # Why a `Once`, not a bare `std::env::set_var` at call time
//!
//! `transport::multicast::resolve_forced_interface` resolves `HDDS_INTERFACE`
//! into a `std::sync::OnceLock` the first time ANYTHING in the process reads
//! it, and caches that answer for the rest of the process's life (see that
//! function's doc comment: "the variable cannot change under us"). That is
//! the right contract for production, where the environment genuinely is
//! fixed for the life of the process, but it turns a bare `set_var` here
//! into a race: `cargo test`'s default harness runs every `#[test]` in a
//! `--lib` binary on its own thread, so which thread's call to `set_var`
//! (if any) happens-before the first thread to call
//! `resolve_forced_interface` is unspecified. Two threads calling this
//! function at the same moment could interleave as read-then-write on one
//! of them, caching `None` for the whole process even though both callers
//! wanted `lo`.
//!
//! [`std::sync::Once::call_once`] removes the race instead of narrowing it:
//! it gives every caller, including concurrent ones, a total order and a
//! barrier. The first caller to reach it runs the closure (and only that
//! one does); every other caller -- this thread or another, right now or
//! moments later -- blocks until that closure has finished and its effects
//! (the env var write) are visible, before either one can go on to build a
//! participant and reach `resolve_forced_interface` itself. Calling this at
//! the very start of every domain lease is what makes that guarantee land
//! where it matters: no test in this process can reach the transport layer
//! before this function has already run to completion at least once.
//!
//! An explicit `HDDS_INTERFACE` already set by the operator (running the
//! suite on a host with clean routing, or deliberately reproducing a
//! specific interface's behavior) is left untouched -- this only fills in
//! the gap, it never overrides a deliberate choice.

use std::sync::Once;

static PIN_ONCE: Once = Once::new();

/// Force every participant built by this process onto the loopback
/// interface, unless `HDDS_INTERFACE` is already set.
///
/// Idempotent and safe to call from any thread, any number of times: only
/// the first call (racing or not) has any effect, every other call returns
/// immediately once that first call has completed. See the module docs for
/// why this exists and why it is a [`Once`] rather than a plain env write.
///
/// Called automatically by [`super::domains::try_unique_domain`] -- most
/// tests never need to call this directly.
pub fn pin_loopback_interface() {
    PIN_ONCE.call_once(|| {
        if std::env::var_os("HDDS_INTERFACE").is_none() {
            std::env::set_var("HDDS_INTERFACE", "127.0.0.1");
        }
    });
}

/// Runs [`pin_loopback_interface`] before `main` in the `--lib` unit-test
/// binary, closing a gap [`super::domains::try_unique_domain`] alone leaves
/// open.
///
/// Example: `core::discovery::spdp_announcer::tests::
/// advertised_locators_disabled_mode` builds a raw `UdpTransport` directly
/// (via `build_transport_for_mode`), with no `Participant` and no domain
/// lease anywhere in it. With `--test-threads=1` that test can run before
/// any `security::e2e_tests` test, and its `UdpTransport::new` call reaches
/// `transport::multicast::resolve_forced_interface` first -- with
/// `HDDS_INTERFACE` still genuinely unset, caching `None` in that
/// function's process-lifetime `OnceLock` before `try_unique_domain` (and
/// this module's pin) ever runs. The outcome then depends on test ordering,
/// not on the code under test. A test author cannot be expected to know
/// every OTHER test in a large binary well enough to avoid this
/// ordering hazard, so the fix does not depend on one: this must run
/// before the FIRST test of any kind, not before the first test that
/// happens to lease a domain.
///
/// `.init_array` is what glibc (and musl) call before `main` for every
/// entry linked into it, in a Rust binary or otherwise -- the same
/// mechanism the `ctor` crate wraps, used directly here to avoid adding a
/// dependency for one static initializer. `#[used]` stops the linker from
/// discarding a static nothing in the crate appears to reference. Scoped to
/// `cfg(test)`, so this exists ONLY in the `--lib` test binary (`cfg(test)`
/// is false when this crate is compiled as an ordinary dependency, which is
/// how every integration test under `tests/` and every downstream crate
/// pulls it in -- see [`pin_loopback_interface`]'s doc for how those are
/// covered instead) and `target_os = "linux"`, the only OS this suite's
/// tests actually run on (the `x86_64-apple-darwin` / `x86_64-pc-windows-gnu`
/// gates are `cargo check`, which never enables `cfg(test)` without
/// `--tests`, so this code is not even compiled there).
#[cfg(all(test, target_os = "linux"))]
mod pre_main {
    use super::pin_loopback_interface;

    #[used]
    #[link_section = ".init_array"]
    static PIN_BEFORE_MAIN: extern "C" fn() = run;

    extern "C" fn run() {
        pin_loopback_interface();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_loopback_interface_is_idempotent_and_does_not_panic() {
        pin_loopback_interface();
        pin_loopback_interface();
        // Whatever the ambient environment was, HDDS_INTERFACE is now set
        // to *something* (either the operator's choice or "lo").
        assert!(std::env::var_os("HDDS_INTERFACE").is_some());
    }
}
