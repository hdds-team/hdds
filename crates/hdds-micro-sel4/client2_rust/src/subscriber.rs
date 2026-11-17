// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! RTPS subscriber mode (`--features subscriber`).
//!
//! Each `notified()` drains the RX queue; every UDP datagram is fed to
//! `hdds_micro::MicroReader::read`, which parses the RTPS header + DATA
//! submessage and exposes the CDR payload. We decode the same
//! `Temperature` layout the embedded publisher emits and log one
//! `RX seq=<n>` line per sample to the kernel debug UART
//! (`microkit_dbg_puts` via `crate::dbg::dbg_label_u64`), so the host
//! test harness can grep the QEMU serial for sample-count + monotonicity.
//!
//! No TX path in the default build: the subscriber never sends. The
//! Sel4Ring TX queues stay seeded but unused. The ARP cache populates
//! passively from the host's Ethernet frames (no broadcast probes).
//! With the `intra-guest` feature (intra-guest pair) the subscriber also
//! sends wake-up probes to the publisher PD; see below.

use core::mem::MaybeUninit;

use hdds_micro::cdr::CdrDecoder;
use hdds_micro::rtps::{EntityId, Locator};
use hdds_micro::{MicroParticipant, MicroReader};
#[cfg(feature = "intra-guest")]
use hdds_micro::Error as MicroError;

#[cfg(feature = "intra-guest")]
use hdds_micro::transport::Transport;

use hdds_micro_sel4::{drain_queue, Sel4Ring, Sel4RingInit, Sel4UdpTransport, LOCAL_PORT};

use crate::dbg;

/// Domain id handed to the participant. Informational for hdds-micro
/// (it is not written to the wire); the port is fixed by `LOCAL_PORT`.
#[cfg(feature = "lan")]
const DOMAIN_ID: u32 = 205;
#[cfg(not(feature = "lan"))]
const DOMAIN_ID: u32 = 105;

/// Per-boot instance value for the GUID prefix. This PD has no per-boot
/// entropy source yet, so the value is a constant; see the crate README.
const PD_INSTANCE: u32 = 2;

/// Publisher locator for the intra-guest pair: sibling PD at
/// 10.0.2.17:LOCAL_PORT (33650 when `intra-guest` is on). The subscriber
/// kicks this address to wake the publisher's capture-on-first-kick
/// path, replacing the host-driven kick loop of the host-to-guest
/// builds.
#[cfg(feature = "intra-guest")]
const PUBLISHER_IP_INTRA_GUEST: [u8; 4] = [10, 0, 2, 17];

/// Reader entity id for the single Temperature subscriber. `0xc7` is
/// the RTPS suffix for a user-defined Reader with key.
const READER_ENTITY: EntityId = EntityId::new([0, 0, 0x01, 0xc7]);

const TOPIC_NAME: &str = "Temperature";

/// Subscriber PD state. Held in a single `static mut` initialised
/// exactly once by `init`.
#[cfg_attr(not(feature = "stats"), allow(dead_code))]
struct SubState {
    participant: MicroParticipant<Sel4UdpTransport<Sel4Ring>>,
    reader: MicroReader,
    /// Last seq we saw: the intra-guest ARP fixup checks it.
    #[cfg_attr(not(feature = "intra-guest"), allow(dead_code))]
    last_seq: i64,
    /// Notifications received so far: the tick count for ARP retries.
    ticks: u64,
    /// Counters for the `stats` build: samples decoded, highest seq seen,
    /// seq below the highest (reorder or repeat), seq equal to the highest.
    rx: u64,
    max_seq: u64,
    below_max: u64,
    at_max: u64,
    /// Frames consumed without a sample for this reader (malformed, foreign,
    /// oversized). They do not stop the drain.
    skipped: u64,
}

static mut SUB_STATE: MaybeUninit<SubState> = MaybeUninit::uninit();
static mut INITIALIZED: bool = false;

/// # Safety
/// Single-shot: see the `rust_init` contract in `lib.rs`.
#[allow(static_mut_refs)]
pub(crate) unsafe fn init(init_blob: &Sel4RingInit) {
    // SAFETY: `Sel4Ring::new` is unsafe because it wraps raw sDDF
    // resource pointers; the C wrapper has validated those via
    // `net_config_check_magic` before assembling the blob.
    let ring = unsafe { Sel4Ring::new(init_blob) };
    // local_ip from the C wrapper's Sel4RingInit blob: see the matching
    // comment in publisher.rs. The intra-guest pair uses 10.0.2.17 for
    // the publisher and 10.0.2.18 for the subscriber.
    let local_locator = Locator::udpv4(init_blob.local_ip, LOCAL_PORT);
    let transport = Sel4UdpTransport::new(ring, local_locator);

    let participant = match MicroParticipant::with_instance(DOMAIN_ID, transport, PD_INSTANCE) {
        Ok(p) => p,
        Err(_) => {
            // Wedge, as for the reader below: continuing would leave
            // SUB_STATE uninitialised while the PD keeps running.
            dbg::dbg_line("hdds-sel4: subscriber init FAILED (MicroParticipant)");
            loop {
                // SAFETY: `wfe` is a CPU hint, no memory access.
                unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
            }
        }
    };

    let reader = match MicroReader::new(participant.guid_prefix(), READER_ENTITY, TOPIC_NAME) {
        Ok(r) => r,
        Err(_) => {
            // Topic name is a short compile-time constant, so this branch
            // is unreachable in practice. Logging and continuing would
            // leave SUB_STATE half-initialised, so we wedge here.
            dbg::dbg_line("hdds-sel4: subscriber init FAILED (MicroReader::new)");
            loop {
                // SAFETY: `wfe` is a CPU hint, no memory access.
                unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
            }
        }
    };

    let state = SubState {
        participant,
        reader,
        last_seq: 0,
        ticks: 0,
        rx: 0,
        max_seq: 0,
        below_max: 0,
        at_max: 0,
        skipped: 0,
    };

    // SAFETY: Microkit guarantees `init` runs exactly once before
    // any `notified` call.
    unsafe {
        SUB_STATE.write(state);
        INITIALIZED = true;
    }

    dbg::dbg_line("hdds-sel4: subscriber ready (topic=Temperature)");

    // Intra-guest wake-up: kick the publisher with one probe datagram so
    // it learns our locator and starts emitting. Without this, the
    // publisher's `notified()` is never invoked (no host harness, no
    // timer) and the system idles forever.
    #[cfg(feature = "intra-guest")]
    {
        // SAFETY: `INITIALIZED` is true; the state was just written.
        let s: &mut SubState = unsafe { SUB_STATE.assume_init_mut() };
        send_probe(s);
    }
}

/// Send a zero-byte UDP datagram to the publisher. Errors are silent:
/// `ResourceExhausted` means the TX queue is full and the publisher
/// will be kicked again on the next sample receive; harder failures
/// surface as a debug line.
#[cfg(feature = "intra-guest")]
fn send_probe(state: &mut SubState) {
    let dest = Locator::udpv4(PUBLISHER_IP_INTRA_GUEST, LOCAL_PORT);
    match state.participant.transport_mut().send(&[], &dest) {
        Ok(_) => {}
        Err(MicroError::ResourceExhausted) => {}
        Err(_) => {
            dbg::dbg_line("hdds-sel4: WARN probe send failed");
        }
    }
}

/// Subscriber notified handler. Drains RX; each successfully-decoded
/// sample emits one `RX seq=<n>` line, formatted on the stack and
/// written via `dbg_label_u64` (default build). The `stats` build prints
/// one cumulative `STAT` line per drain pass instead.
///
/// # Safety
/// Single-threaded Microkit entry.
#[allow(static_mut_refs)]
pub(crate) unsafe fn notified(_ch: u32) {
    // SAFETY: `INITIALIZED` rejects the call if `init` did not run.
    let initialised = unsafe { INITIALIZED };
    if !initialised {
        return;
    }
    // SAFETY: Microkit serialises PD entries: no concurrent reader
    // or writer of SUB_STATE exists.
    let state: &mut SubState = unsafe { SUB_STATE.assume_init_mut() };

    // ARP retries advance one tick per notification (see publisher.rs).
    #[cfg(feature = "stats")]
    let before = state.rx + state.skipped;
    state.ticks = state.ticks.wrapping_add(1);
    state.participant.transport_mut().tick_arp(state.ticks);

    // Drain to an empty queue. Malformed or foreign frames are skipped, not
    // a reason to stop: a drain that stops early leaves frames queued and the
    // ring does not notify again (see crates/hdds-micro-sel4/src/drain.rs).
    let drained = drain_queue(
        &mut state.reader,
        state.participant.transport_mut(),
        &mut state.skipped,
        |seq, payload| {
            // Out-of-order arrival is legal for BEST_EFFORT and is not reported
            // as a warning: WARN lines are for frames that were skipped. The
            // stats build counts it (below_max).
            state.last_seq = seq;

            // Decode the Temperature payload (sensor_id u32, value f32,
            // timestamp u64). A payload-level failure under a valid RTPS
            // header is reported and the sample is not counted.
            let mut dec = CdrDecoder::new(payload);
            if dec.decode_u32().is_err() || dec.decode_f32().is_err() || dec.decode_u64().is_err() {
                dbg::dbg_line("hdds-sel4: WARN decode failed");
                return;
            }

            #[cfg(not(feature = "stats"))]
            dbg::dbg_label_u64("RX ", "seq", seq as u64);

            #[cfg(feature = "stats")]
            {
                state.rx += 1;
                let s = seq as u64;
                if s > state.max_seq {
                    state.max_seq = s;
                } else if s == state.max_seq {
                    state.at_max += 1;
                } else {
                    state.below_max += 1;
                }
            }
        },
    );
    let _delivered = match drained {
        Ok(n) => n,
        Err(_) => {
            dbg::dbg_line("hdds-sel4: WARN drain error");
            0
        }
    };

    // Intra-guest ping-pong (intra-guest only): re-kick the publisher after a
    // drain that delivered samples, so it has a reason to emit the next one.
    #[cfg(feature = "intra-guest")]
    if _delivered > 0 {
        send_probe(state);
    }

    // One cumulative line per drain pass that delivered samples (stats build).
    #[cfg(feature = "stats")]
    if state.rx + state.skipped != before {
        dbg::dbg_fields(
            "STAT",
            &[
                ("rx", state.rx),
                ("max", state.max_seq),
                ("below", state.below_max),
                ("at_max", state.at_max),
                ("skipped", state.skipped),
            ],
        );
    }

    // ARP fixup retry: the initial probe from `init` returns
    // `ResourceExhausted` until the ARP cache populates (the very first
    // send emits a broadcast ARP request, not the UDP payload itself).
    // Without a retry here, the wake-up that follows ARP resolution
    // (no sample decoded yet) would never reissue the probe and the
    // system would wedge.
    //
    // The retry is gated to the window before the first sample. Once
    // `last_seq > 0` the steady-state ping-pong is driven by the
    // per-sample `send_probe` inside the receive loop above; firing the
    // tail probe unconditionally turned every wake (RX and TX-free
    // returns) into one extra send, which doubled the publisher's
    // effective rate and could amplify under tail-end TX-free wakes.
    #[cfg(feature = "intra-guest")]
    if state.last_seq == 0 {
        send_probe(state);
    }
}
