// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! RTPS publisher mode (`--features publisher`).
//!
//! Each `notified()` drains the RX queue; every UDP datagram (the
//! "kick") triggers one CDR-encoded `Temperature` sample emitted as an
//! RTPS DATA submessage back to the kick's source.
//!
//! The destination follows the source of the latest kick (see `publish_one`).
//! Under QEMU `-netdev user` (libslirp) a host-side `hostfwd` UDP rule
//! installs a non-expiring listener, so kicks from any host source land
//! in the guest with the sender's source port preserved (libslirp only
//! rewrites the source IP to the SLIRP virtual host address). As long as
//! the host-side kick socket keeps the same local port, the guest sees a
//! stable `(src_ip, src_port)` pair.
//!
//! A subscriber that restarts on a new source port is followed: its first
//! kick re-points the writer (`MicroWriter::set_dest_locator`), and the
//! next sample goes to the new source. The writer keeps its sequence number.
//!
//! The egress path is plain UDP to the kick's source `(src_ip, src_port)`,
//! the same path the echo mode uses.

use core::mem::MaybeUninit;

use hdds_micro::cdr::CdrEncoder;
use hdds_micro::rtps::{EntityId, Locator};
use hdds_micro::{Error as MicroError, MicroParticipant, MicroWriter, Transport};

use hdds_micro_sel4::{Sel4Ring, Sel4RingInit, Sel4UdpTransport, LOCAL_PORT};

use crate::dbg;

/// Domain id handed to the participant. Informational for hdds-micro
/// (it is not written to the wire); the port is fixed by `LOCAL_PORT`.
#[cfg(feature = "lan")]
const DOMAIN_ID: u32 = 205;
#[cfg(not(feature = "lan"))]
const DOMAIN_ID: u32 = 105;

/// Per-boot instance value for the GUID prefix. This PD has no per-boot
/// entropy source yet, so the value is a constant; see the crate README.
const PD_INSTANCE: u32 = 1;

/// Writer entity id for the single Temperature publisher. `0xc2` is
/// the RTPS suffix for a user-defined Writer with key (matches what
/// `MicroParticipant::allocate_entity_id(true)` produces for the first
/// allocation).
const WRITER_ENTITY: EntityId = EntityId::new([0, 0, 0x01, 0xc2]);

/// Fixed sensor id stamped on every Temperature sample. Tweakable from
/// the host-side parser; the value itself does not matter (only
/// sequence monotonicity does).
const SENSOR_ID: u32 = 42;

/// Topic name announced by the writer. Must match the subscriber's
/// expectation in `crates/hdds-micro-sel4/host-tools/hdds_sub`.
const TOPIC_NAME: &str = "Temperature";

/// CDR scratch buffer for one Temperature sample (3 fields, max 24
/// bytes incl. padding); kept oversized for safety.
const CDR_BUF_LEN: usize = 64;

/// Inbound (kick) scratch buffer. The kick payload contents are
/// discarded; we only need it to consume the slot via `try_recv`.
const KICK_BUF_LEN: usize = 256;

/// Publisher PD state. Held in a single `static mut` initialised
/// exactly once by `init`.
struct PubState {
    participant: MicroParticipant<Sel4UdpTransport<Sel4Ring>>,
    /// Sample counter: drives the timestamp field and lets the host
    /// subscriber check sequence monotonicity independently of RTPS
    /// writer seq numbers.
    counter: u64,
    /// Built on first kick (once we know who the host is). `None`
    /// until then.
    writer: Option<MicroWriter>,
    /// Destination the writer currently sends to.
    writer_dest: Option<Locator>,
    /// Notifications received so far: the tick count for ARP retries.
    ticks: u64,
}

static mut PUB_STATE: MaybeUninit<PubState> = MaybeUninit::uninit();
static mut INITIALIZED: bool = false;

/// # Safety
/// Single-shot: see the `rust_init` contract in `lib.rs`.
#[allow(static_mut_refs)]
pub(crate) unsafe fn init(init_blob: &Sel4RingInit) {
    // SAFETY: `Sel4Ring::new` is unsafe because it wraps raw sDDF
    // resource pointers; the C wrapper has validated those via
    // `net_config_check_magic` before assembling the blob.
    let ring = unsafe { Sel4Ring::new(init_blob) };
    // local_ip comes from the C wrapper's Sel4RingInit blob: each PD
    // wrapper stamps its own IP, so the same Rust crate can back PDs
    // with different addresses (the intra-guest pair uses 10.0.2.17 for
    // the publisher and 10.0.2.18 for the subscriber).
    let local_locator = Locator::udpv4(init_blob.local_ip, LOCAL_PORT);
    let transport = Sel4UdpTransport::new(ring, local_locator);

    // The participant derives the GUID prefix from the locator and the
    // instance value, so the PD uses the same scheme as every other
    // hdds-micro participant instead of a local copy of it.
    let participant = match MicroParticipant::with_instance(DOMAIN_ID, transport, PD_INSTANCE) {
        Ok(p) => p,
        Err(_) => {
            dbg::dbg_line("hdds-sel4: publisher init FAILED (MicroParticipant)");
            return;
        }
    };

    let state = PubState {
        participant,
        counter: 0,
        writer: None,
        writer_dest: None,
        ticks: 0,
    };

    // SAFETY: Microkit guarantees `init` runs exactly once before
    // any `notified` call.
    unsafe {
        PUB_STATE.write(state);
        INITIALIZED = true;
    }

    dbg::dbg_line("hdds-sel4: publisher ready (topic=Temperature)");
}

/// Publisher notified handler. Drains RX; each kick triggers one
/// RTPS DATA emission. ARP frames are absorbed inside `try_recv`
/// (Sel4Ring handles them inline) and surface as `ResourceExhausted`
/// once the queue is drained.
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
    // or writer of PUB_STATE exists.
    let state: &mut PubState = unsafe { PUB_STATE.assume_init_mut() };

    // ARP retries advance one tick per notification. This PD has no
    // readable timer, so the ticks are a count of events, not time.
    state.ticks = state.ticks.wrapping_add(1);
    state.participant.transport_mut().tick_arp(state.ticks);

    // The drain stops on any error: ResourceExhausted (empty queue),
    // BufferTooSmall, TransportError or InvalidParameter. None of them
    // asks for a retry inside the same `notified` cycle.
    let mut kick_buf = [0u8; KICK_BUF_LEN];
    loop {
        match state.participant.transport_mut().try_recv(&mut kick_buf) {
            Ok((_n, src_locator)) => publish_one(state, src_locator),
            // Oversized kick: consumed by the transport, keep draining.
            Err(MicroError::BufferTooSmall) => {}
            Err(_) => break,
        }
    }
}

/// Emit a single CDR-encoded Temperature sample to `dest`, building
/// the writer lazily on the first kick.
fn publish_one(state: &mut PubState, dest: Locator) {
    if state.writer.is_none() {
        // Construct on first kick now that we know the destination.
        // Failure here would mean the topic name does not fit the
        // writer's static buffer (63-char limit). TOPIC_NAME is short
        // enough that this cannot fail in practice; the `match`
        // asserts that loudly in debug builds.
        match MicroWriter::new(state.participant.guid_prefix(), WRITER_ENTITY, TOPIC_NAME, dest) {
            Ok(w) => {
                state.writer = Some(w);
                state.writer_dest = Some(dest);
            }
            Err(_) => {
                debug_assert!(false, "MicroWriter::new must succeed for short topic name");
                return;
            }
        }
    }

    // Follow the latest kicker: a subscriber that restarted on a new source
    // port must get the next sample, not the stale destination.
    if state.writer_dest != Some(dest) {
        if let Some(w) = state.writer.as_mut() {
            w.set_dest_locator(dest);
        }
        state.writer_dest = Some(dest);
    }

    let writer = match state.writer.as_mut() {
        Some(w) => w,
        None => return,
    };

    state.counter = state.counter.wrapping_add(1);

    // Encode payload: sensor_id (u32) + value (f32) + timestamp (u64).
    // Same layout as crates/hdds-micro/examples/temperature_pubsub.rs:
    // the host subscriber decodes in the same order.
    let mut cdr_buf = [0u8; CDR_BUF_LEN];
    let mut enc = CdrEncoder::new(&mut cdr_buf);
    if enc.encode_u32(SENSOR_ID).is_err()
        || enc.encode_f32(temperature_for(state.counter)).is_err()
        || enc.encode_u64(state.counter).is_err()
    {
        return;
    }
    let payload = enc.finish();

    // Drop any transport-level failure silently: BEST_EFFORT semantics.
    // Same posture as the echo binary.
    let _ = writer.write(payload, state.participant.transport_mut());
}

/// Synthetic temperature value that increases monotonically with the
/// sample counter, modulo a small range, so host-side decoders can
/// eyeball the stream.
fn temperature_for(counter: u64) -> f32 {
    20.0 + ((counter % 200) as f32) * 0.05
}
