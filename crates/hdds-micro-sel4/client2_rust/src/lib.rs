// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Microkit PD staticlib - three mutually exclusive behaviours behind
//! Cargo features, selected at build time.
//!
//! The PD exposes two `extern "C"` entry points consumed by the C
//! wrappers at `crates/hdds-micro-sel4/microkit/client2_rust_wrapper.c` and
//! `client3_rust_wrapper.c`:
//! - [`rust_init`]: called from the PD's `init()` once per boot with a
//!   `Sel4RingInit` built from the validated `.net_client_config` blob.
//! - [`rust_notified`]: called from the PD's `notified(ch)` on every
//!   inbound Microkit channel notification.
//!
//! Modes (one and only one per build):
//! - **default (no feature)** - echo. Drains RX, echoes each
//!   UDP datagram back to its source. Built by
//!   `scripts/run-echo-rust.sh`.
//! - **`publisher`** - Per inbound kick, emits one
//!   CDR-encoded `Temperature` sample via `hdds_micro::MicroWriter`,
//!   addressed back to the kick's source. Built by
//!   `scripts/run-hdds-pub.sh`.
//! - **`subscriber`** - Parses each inbound UDP datagram as
//!   RTPS DATA via `hdds_micro::MicroReader`, logs `RX seq=<n>` to the
//!   kernel debug UART. Built by `scripts/run-hdds-sub.sh`.
//!
//! The additional `intra-guest` feature selects the intra-guest variant of
//! `publisher` / `subscriber` (see `Cargo.toml`); it is built by
//! `microkit/echo_loopback.mk`.
//!
//! Single-threaded by construction: a Microkit PD has one entry path,
//! one event loop, no concurrency. Static-mut state held by each mode
//! is sound because the Microkit contract guarantees `init` precedes
//! any `notified`, and notifications are serialised by the kernel.

#![no_std]
#![allow(unsafe_code)]

use core::panic::PanicInfo;

// Feature exclusivity guard - Cargo features are additive, so we
// enforce mutual exclusion at compile time rather than relying on
// build scripts. Without this guard, `--features "publisher subscriber"`
// would pull both modules in and produce duplicate-symbol errors at
// link time - clearer to fail here with an actionable message.
#[cfg(all(feature = "publisher", feature = "subscriber"))]
compile_error!(
    "client2_rust: features `publisher` and `subscriber` are mutually exclusive; pick one"
);

#[cfg(any(feature = "publisher", feature = "subscriber"))]
mod dbg;

#[cfg(all(not(feature = "publisher"), not(feature = "subscriber")))]
mod echo;
#[cfg(feature = "publisher")]
mod publisher;
#[cfg(feature = "subscriber")]
mod subscriber;

// Make the `use ... as mode;` cfgs mutually exclusive too, so that a
// (rejected-by-compile_error!) build with both features set doesn't
// also generate a noisy E0252 "name `mode` defined multiple times"
// diagnostic on top of the explicit feature-mutex error.
#[cfg(all(not(feature = "publisher"), not(feature = "subscriber")))]
use echo as mode;
#[cfg(feature = "publisher")]
use publisher as mode;
#[cfg(all(not(feature = "publisher"), feature = "subscriber"))]
use subscriber as mode;

use hdds_micro_sel4::Sel4RingInit;

/// Initialise the PD-mode-specific state from the validated sDDF init
/// blob.
///
/// # Safety
/// - `init` must point to a fully populated `Sel4RingInit` with all
///   pointer fields satisfying their respective safety contracts
///   (see `hdds_micro_sel4::Sel4Ring::new`).
/// - Must be called exactly once per PD lifetime, before any
///   `rust_notified` call. The Microkit kernel enforces this.
#[no_mangle]
pub unsafe extern "C" fn rust_init(init: *const Sel4RingInit) {
    // SAFETY: caller (C wrapper) guarantees `init` is a valid
    // pointer to a `Sel4RingInit` for the lifetime of this call.
    let init_ref = unsafe { &*init };
    // SAFETY: forwarded to mode-specific init which upholds its own
    // single-shot invariant (see `echo::init` / `publisher::init`
    // / `subscriber::init`).
    unsafe { mode::init(init_ref) };
}

/// React to a Microkit notification.
///
/// # Safety
/// - `rust_init` must have completed before this is called.
/// - Microkit guarantees single-threaded entry.
#[no_mangle]
pub unsafe extern "C" fn rust_notified(ch: u32) {
    // SAFETY: forwarded to mode-specific handler which gates on its
    // own `INITIALIZED` flag (defensive belt over Microkit's
    // init-before-notify contract).
    unsafe { mode::notified(ch) };
}

/// Microkit PDs cannot unwind - abort on panic via a low-power `wfe`
/// loop. A future improvement is to call `sddf_dprintf` first to
/// print the panic message on the serial PD.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // A halted PD must not stay silent on the UART.
    #[cfg(any(feature = "publisher", feature = "subscriber"))]
    dbg::dbg_line("hdds-sel4: PANIC (PD halted)");
    loop {
        // SAFETY: `wfe` is a hint to the CPU; no memory accesses, no
        // Rust state involved.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}
