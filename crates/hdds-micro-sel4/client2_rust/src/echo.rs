// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Echo mode (default build).
//!
//! Drains the RX queue, echoes each UDP datagram back to its source
//! `(src_ip, src_port)`. The round-trip is checked by
//! `crates/hdds-micro-sel4/scripts/run-echo-rust.sh` against 10.0.2.17:1235 via
//! SLIRP hostfwd port 1241.

use core::mem::MaybeUninit;

use hdds_micro_sel4::{PacketRing, RingError, Sel4Ring, Sel4RingInit};

/// The PD's single `Sel4Ring` instance. `static mut` + `MaybeUninit`
/// is the idiomatic Microkit-PD pattern: one writer in `init`,
/// readers in `notified`, all serialised by the Microkit kernel.
static mut SEL4_RING: MaybeUninit<Sel4Ring> = MaybeUninit::uninit();

/// Set to `true` after `init` returns. Defensively gates
/// `notified` against a malformed build that wires notifications
/// before init.
static mut INITIALIZED: bool = false;

/// PD echo buffer. Sized for a single Ethernet payload (MTU 1500); UDP
/// datagrams larger than `Sel4Ring::slot_mtu()` (1472) cannot reach us
/// (they would be rejected by IPv4 fragmentation guards earlier in the
/// stack).
const ECHO_BUF_LEN: usize = 1500;

/// # Safety
/// Single-shot - see `lib.rs::rust_init` contract.
#[allow(static_mut_refs)]
pub(crate) unsafe fn init(init: &Sel4RingInit) {
    // SAFETY: `Sel4Ring::new` is `unsafe` because it wraps the raw
    // sDDF resource pointers; the C wrapper has validated those via
    // `net_config_check_magic`.
    let ring = unsafe { Sel4Ring::new(init) };
    // SAFETY: Microkit guarantees `init` runs exactly once before
    // any `notified` call.
    unsafe {
        SEL4_RING.write(ring);
        INITIALIZED = true;
    }
}

/// Echo handler. Drains `try_dequeue_rx` until empty, replying each
/// UDP datagram back to its source. `RingError::Empty` ends the drain.
/// Other errors (`Full` = TX queue saturated, `TooLarge` = buffer too
/// small) are silently dropped - UDP is best-effort and the goal is
/// round-trip on a quiescent SLIRP host, not back-pressure
/// resilience.
///
/// # Safety
/// Single-threaded Microkit entry - see `lib.rs::rust_notified`.
#[allow(static_mut_refs)]
pub(crate) unsafe fn notified(_ch: u32) {
    // SAFETY: `INITIALIZED` rejects the call if `init` did not run.
    let initialised = unsafe { INITIALIZED };
    if !initialised {
        return;
    }
    // SAFETY: Microkit serialises PD entries - no concurrent reader
    // or writer of SEL4_RING exists.
    let ring: &mut Sel4Ring = unsafe { SEL4_RING.assume_init_mut() };

    let mut buf = [0u8; ECHO_BUF_LEN];
    loop {
        match ring.try_dequeue_rx(&mut buf) {
            Ok((n, src_ip, src_port)) => {
                // Echo back. TX failures (queue full, no ARP) are
                // silently dropped - best-effort UDP. Explicit match
                // (not `let _ =`) so impossible variants assert loudly.
                match ring.enqueue_tx(&buf[..n], src_ip, src_port) {
                    Ok(()) => {}
                    Err(RingError::Full) | Err(RingError::TooLarge) => {}
                    Err(RingError::Empty) => {
                        debug_assert!(false, "Empty is RX-only; enqueue_tx cannot return it")
                    }
                }
            }
            Err(RingError::Empty) => break,
            Err(RingError::Full) | Err(RingError::TooLarge) => {
                break;
            }
        }
    }
}
