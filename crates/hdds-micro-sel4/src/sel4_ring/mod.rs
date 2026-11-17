// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! `Sel4Ring` - `PacketRing` backend over sDDF shared-memory queues.
//!
//! Module layout:
//! - [`netstack`]: Eth/IPv4/UDP/ARP framing. Pure-data, host-testable.
//! - [`arp`]: ARP cache + active-resolution state machine.
//! - [`queue`]: `NetQueueHeader`, atomics, SeqCst signal protocol -
//!   the one place this crate holds `unsafe`.
//! - This file: [`Sel4Ring`] glue + [`PacketRing`] impl + the C-side
//!   handoff struct [`Sel4RingInit`].
//!
//! All submodules compile on host without the `microkit` feature so
//! `cargo test` exercises the framing, ARP, and queue-state logic
//! without a real seL4 environment. The Microkit-only piece is the
//! `microkit_notify` FFI inside `queue.rs`, which is stubbed to a
//! no-op on host.

#![allow(unsafe_code)]

pub mod arp;
pub mod netstack;
pub mod queue;

use core::ptr::NonNull;

use crate::ring::{PacketRing, RingError};

use self::netstack::{Ipv4Addr, MacAddr, ParsedFrame};
use self::queue::{ConsumerHandle, DataRegion, DrainVerdict, NetQueueHeader, ProducerHandle};

/// Opaque pointer type the C wrapper hands us for each shared queue
/// header. Internally we cast to `SharedHeaderPtr`; keeping the
/// FFI surface as `*mut u8` avoids leaking the struct into the public
/// API and matches the C side, which holds the same address as a
/// `void *` / `net_queue_t *` interchangeably.
pub type SharedHeaderPtr = *mut u8;

/// One sDDF data-region slot, in bytes. Matches the value the C
/// `echo_server` example uses and the `lib_sddf_lwip` default.
pub const NET_BUFFER_SIZE: usize = 2048;

/// Largest UDP payload a single slot can carry.
/// 1500 (Ethernet MTU) - 20 (IPv4 hdr) - 8 (UDP hdr) = 1472.
pub const SLOT_MTU: usize = 1472;

/// Source port stamped on outgoing UDP datagrams.
///
/// The host-driven modes (echo, publisher, subscriber) use 1235
/// (matches the QEMU SLIRP hostfwd that pipes host port 1235/1238/1241
/// to the PD's IP:1235). The intra-guest mode (feature `intra-guest`) runs
/// entirely inside the guest with no hostfwd and uses 33650, the RTPS
/// port base of domain id 105 (7400 + 250 * 105), so it cannot collide
/// with a host-driven test running on the same host. The port is a
/// compile-time constant, not a `Sel4UdpTransport::new` parameter.
#[cfg(all(not(feature = "intra-guest"), not(feature = "lan")))]
pub const LOCAL_PORT: u16 = 1235;
/// Intra-guest override of [`LOCAL_PORT`] - see the constant's main
/// docstring for the rationale.
#[cfg(all(feature = "intra-guest", not(feature = "lan")))]
pub const LOCAL_PORT: u16 = 33650;

/// LAN override of [`LOCAL_PORT`]: the RTPS port base of domain id 205
/// (7400 + 250 * 205), used when the PD is on a real network segment.
#[cfg(feature = "lan")]
pub const LOCAL_PORT: u16 = 58650;

/// Resource handoff from the Microkit C wrapper to Rust.
///
/// All sDDF ABI parsing stays on the C side (against the
/// authoritative `sddf/network/config.h`); Rust only receives the
/// sanitised pointers / sizes packed into this struct.
///
/// The struct is `#[repr(C)]` so the C wrapper can construct it
/// literal-style and pass `&Sel4RingInit` over the FFI boundary.
#[repr(C)]
pub struct Sel4RingInit {
    /// Local MAC handed to us by sDDF (driver-provided / configured).
    pub mac: [u8; 6],
    /// Layout padding.
    pub _pad0: [u8; 2],

    /// RX free-queue header (we produce empty slots back to `copy`).
    pub rx_free_header: SharedHeaderPtr,
    /// RX active-queue header (`copy` produces frames, we consume).
    pub rx_active_header: SharedHeaderPtr,
    /// RX data-region base (read-only from this side).
    pub rx_data_vaddr: *mut u8,
    /// RX data-region size in bytes.
    pub rx_data_size: usize,
    /// RX queue capacity (power of two, <= 32768).
    pub rx_num_buffers: u16,
    /// Microkit channel id used to notify the RX side.
    pub rx_channel_id: u8,
    /// Layout padding.
    pub _pad1: u8,

    /// TX free-queue header (we consume slots out of the seeded pool).
    pub tx_free_header: SharedHeaderPtr,
    /// TX active-queue header (we produce filled slots to virt_tx).
    pub tx_active_header: SharedHeaderPtr,
    /// TX data-region base.
    pub tx_data_vaddr: *mut u8,
    /// TX data-region size in bytes.
    pub tx_data_size: usize,
    /// TX queue capacity (power of two, <= 32768).
    pub tx_num_buffers: u16,
    /// Microkit channel id used to notify the TX side.
    pub tx_channel_id: u8,
    /// Layout padding.
    pub _pad2: u8,

    /// Local IPv4 address. Hard-coded by the C wrapper (SLIRP layout:
    /// 10.0.2.{15,16,17}); there is no DHCP client in this crate.
    pub local_ip: [u8; 4],
}

/// `PacketRing` implementation over sDDF queues.
///
/// Single-PD, single-peer. Holds four queue handles (two free + two
/// active), two data regions, an ARP cache, and at most one in-flight
/// ARP resolution. All non-data state is `Copy` or small heap-free
/// structs; no `Vec`/`Box`/`Arc` ever appears here.
pub struct Sel4Ring {
    mac: MacAddr,
    local_ip: Ipv4Addr,

    rx_free: ProducerHandle,
    rx_active: ConsumerHandle,
    tx_free: ConsumerHandle,
    tx_active: ProducerHandle,

    rx_data: DataRegion,
    tx_data: DataRegion,

    arp: arp::ArpCache,
    pending_arp: Option<arp::PendingArp>,
    /// Last tick handed to [`Sel4Ring::tick_arp`]. New resolutions start
    /// their deadline from it.
    last_tick: u64,
}

/// Classification of a peeked RX frame.
///
/// Split from [`netstack::ParsedFrame`] because the UDP variant borrows
/// into the shared RX data region; we copy the payload into the
/// caller's buffer inside `classify_inbound`, then return a fully owned
/// `InboundOutcome` so the caller can release the `rx_data` borrow
/// before mutating queue state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundOutcome {
    DeliverUdp {
        len: usize,
        src_ip: Ipv4Addr,
        src_port: u16,
    },
    /// Payload doesn't fit in caller's buffer; do NOT commit so the
    /// caller can re-peek with a bigger one.
    TooLarge,
    /// Recycle the slot and continue draining.
    Drop,
    /// ARP frame extracted; caller dispatches via `handle_arp`.
    Arp(netstack::ParsedArp),
}

impl Sel4Ring {
    /// Build a `Sel4Ring` from the C wrapper's resource handoff.
    ///
    /// # Safety
    /// Every pointer in `init` MUST satisfy the safety contracts of
    /// [`queue::ProducerHandle::new`], [`queue::ConsumerHandle::new`],
    /// and [`queue::DataRegion::new`] - i.e. point to live shared
    /// memory of the declared size, mapped into the calling PD, for
    /// the entire lifetime of the returned `Sel4Ring`. The C wrapper
    /// is required to call `net_config_check_magic` against the
    /// `.net_client_config` blob before assembling `init`; that gates
    /// these guarantees against sdfgen-side wire-format drift.
    pub unsafe fn new(init: &Sel4RingInit) -> Self {
        // Capacity / sizing invariants.
        assert!(
            init.rx_num_buffers.is_power_of_two() && init.rx_num_buffers <= 32768,
            "rx_num_buffers must be a power of two <= 32768"
        );
        assert!(
            init.tx_num_buffers.is_power_of_two() && init.tx_num_buffers <= 32768,
            "tx_num_buffers must be a power of two <= 32768"
        );
        assert!(
            init.rx_data_size >= (init.rx_num_buffers as usize) * NET_BUFFER_SIZE,
            "rx_data_size smaller than rx_num_buffers * NET_BUFFER_SIZE"
        );
        assert!(
            init.tx_data_size >= (init.tx_num_buffers as usize) * NET_BUFFER_SIZE,
            "tx_data_size smaller than tx_num_buffers * NET_BUFFER_SIZE"
        );

        // Cast the opaque `*mut u8` headers (FFI shape) into typed
        // `NonNull<NetQueueHeader>` for the handle constructors. The
        // C side has already validated they point to mapped 8-byte-
        // aligned regions of the right size via `net_config_check_magic`.
        let rx_free_hdr = NonNull::new(init.rx_free_header as *mut NetQueueHeader)
            .expect("rx_free_header non-null");
        let rx_active_hdr = NonNull::new(init.rx_active_header as *mut NetQueueHeader)
            .expect("rx_active_header non-null");
        let tx_free_hdr = NonNull::new(init.tx_free_header as *mut NetQueueHeader)
            .expect("tx_free_header non-null");
        let tx_active_hdr = NonNull::new(init.tx_active_header as *mut NetQueueHeader)
            .expect("tx_active_header non-null");
        let rx_data_base = NonNull::new(init.rx_data_vaddr).expect("rx_data_vaddr non-null");
        let tx_data_base = NonNull::new(init.tx_data_vaddr).expect("tx_data_vaddr non-null");

        let rx_channel = init.rx_channel_id as u32;
        let tx_channel = init.tx_channel_id as u32;

        // Seed `tx_free` with the descriptor pool.
        // We hold the producer role on `tx_free` only during init -
        // after the seed, virt_tx is the steady-state producer (it
        // returns drained slots to us). A temporary `ProducerHandle`
        // does all the SeqCst publishes and is dropped before we
        // re-acquire the queue as a `ConsumerHandle`.
        {
            // SAFETY: `tx_free_hdr` was freshly zeroed by the Microkit
            // loader; we are the sole writer until this block exits.
            let mut tx_free_seed =
                unsafe { ProducerHandle::new(tx_free_hdr, init.tx_num_buffers, tx_channel) };
            for i in 0..init.tx_num_buffers {
                let offset = (i as u64) * (NET_BUFFER_SIZE as u64);
                let ok = tx_free_seed.publish(offset, 0);
                // Keep this as `assert!` (not `debug_assert!`) - slot
                // leaks on a stripped check in release builds are silent
                // and irrecoverable. Per-init cost is negligible.
                assert!(ok, "tx_free seed must fit in an empty queue");
            }
            // A single batched notify after the full seed - without this
            // kick, virt_tx may sleep through the entire initial fill.
            tx_free_seed.maybe_notify_seqcst();
        }

        Self {
            mac: init.mac,
            local_ip: init.local_ip,
            // SAFETY: each `new` wraps a pointer the caller has
            // declared valid for the lifetime of this struct.
            rx_free: unsafe { ProducerHandle::new(rx_free_hdr, init.rx_num_buffers, rx_channel) },
            rx_active: unsafe {
                ConsumerHandle::new(rx_active_hdr, init.rx_num_buffers, rx_channel)
            },
            tx_free: unsafe {
                ConsumerHandle::new(tx_free_hdr, init.tx_num_buffers, tx_channel)
            },
            tx_active: unsafe {
                ProducerHandle::new(tx_active_hdr, init.tx_num_buffers, tx_channel)
            },
            rx_data: unsafe { DataRegion::new(rx_data_base, init.rx_data_size) },
            tx_data: unsafe { DataRegion::new(tx_data_base, init.tx_data_size) },
            arp: arp::ArpCache::new(),
            pending_arp: None,
            last_tick: 0,
        }
    }

    /// Free function (no `&self`) so the caller can call it while
    /// holding an immutable borrow on `self.rx_data` (via `frame`)
    /// and a mutable borrow on the caller's `buf`. Returning an owned
    /// `InboundOutcome` releases both borrows once classification
    /// completes.
    fn classify_inbound(
        local_ip: Ipv4Addr,
        local_port: u16,
        frame: &[u8],
        buf: &mut [u8],
    ) -> InboundOutcome {
        match netstack::parse_frame(frame) {
            None => InboundOutcome::Drop,
            Some(ParsedFrame::Arp(a)) => InboundOutcome::Arp(a),
            Some(ParsedFrame::Ipv4Udp(p)) => {
                if p.dst_ip != local_ip || p.dst_port != local_port {
                    InboundOutcome::Drop
                } else if p.payload.len() > buf.len() {
                    InboundOutcome::TooLarge
                } else {
                    let n = p.payload.len();
                    buf[..n].copy_from_slice(p.payload);
                    InboundOutcome::DeliverUdp {
                        len: n,
                        src_ip: p.src_ip,
                        src_port: p.src_port,
                    }
                }
            }
        }
    }

    /// Claim the next free TX buffer, or arrange a wake-up for when one
    /// is returned.
    ///
    /// When `tx_free` is empty, the consumer recipe (sDDF) requests a
    /// signal from the driver. The driver notifies this PD on its next
    /// return of a buffer, and the caller's `notified` runs then. If the
    /// driver returned a buffer while we were requesting, the recheck
    /// reports `Continue` and the buffer is claimed here.
    fn claim_tx_slot(&mut self) -> Result<queue::Slot, RingError> {
        if let Some(slot) = self.tx_free.peek_acquire() {
            return Ok(slot);
        }
        match self.tx_free.request_signal_with_recheck() {
            DrainVerdict::Continue => self.tx_free.peek_acquire().ok_or(RingError::Full),
            DrainVerdict::Sleep => Err(RingError::Full),
        }
    }

    /// React to an ARP frame: update cache, optionally clear
    /// `pending_arp`, optionally emit a reply.
    ///
    /// Reply failure (TX queue saturated) is silently dropped - the
    /// peer will retry per RFC 826, and the RX slot is recycled by
    /// the caller regardless.
    ///
    /// The cache does not age entries, so the learn timestamp is unused:
    /// every `learn` call here passes `now = 0`.
    fn handle_arp(&mut self, frame: netstack::ParsedArp) {
        let action = arp::handle_arp_frame(
            &frame,
            self.local_ip,
            &mut self.arp,
            &mut self.pending_arp,
            0,
        );
        if let arp::ArpAction::Reply { peer_mac, peer_ip } = action {
            // Prefer an explicit match over `let _ =`
            // so the intent (silent drop on TX-side back-pressure) is
            // self-documenting and impossible-variants assert loudly
            // instead of being silently swallowed.
            match self.try_emit_arp_reply(peer_mac, peer_ip) {
                Ok(()) | Err(RingError::Full) => {}
                Err(RingError::TooLarge) => {
                    debug_assert!(false, "ARP reply (42 bytes) always fits in NET_BUFFER_SIZE")
                }
                Err(RingError::Empty) => {
                    debug_assert!(false, "Empty is RX-only; TX emit cannot return it")
                }
            }
        }
    }

    /// Best-effort ARP reply emit. Returns `RingError::Full` when TX
    /// queue is saturated; caller's responsibility to drop silently.
    fn try_emit_arp_reply(
        &mut self,
        peer_mac: MacAddr,
        peer_ip: Ipv4Addr,
    ) -> Result<(), RingError> {
        let slot = self.claim_tx_slot()?;
        let tx_buf = self
            .tx_data
            .slice_mut(slot.offset, NET_BUFFER_SIZE)
            .ok_or(RingError::Full)?;
        let len = netstack::build_arp_reply(tx_buf, self.mac, self.local_ip, peer_mac, peer_ip)
            .ok_or(RingError::TooLarge)?;
        self.tx_free.commit_seqcst();
        let ok = self.tx_active.publish(slot.offset, len as u16);
        // Total descriptors across {tx_free, tx_active,
        // in-flight} = tx_num_buffers; we just consumed a tx_free slot, so
        // tx_active has at most tx_num_buffers-1 occupied = always one free.
        // Kept as `assert!` (not `debug_assert!`) because a violation
        // means silently leaking a descriptor in release builds, which
        // is unrecoverable until PD restart.
        assert!(ok, "tx_active must accept the slot we just claimed from tx_free");
        self.tx_active.maybe_notify_seqcst();
        Ok(())
    }

    /// Emit a broadcast ARP request. Caller is responsible for
    /// setting `pending_arp` AFTER this returns Ok.
    fn try_emit_arp_request(&mut self, dest_ip: Ipv4Addr) -> Result<(), RingError> {
        let slot = self.claim_tx_slot()?;
        let tx_buf = self
            .tx_data
            .slice_mut(slot.offset, NET_BUFFER_SIZE)
            .ok_or(RingError::Full)?;
        let len = netstack::build_arp_request(tx_buf, self.mac, self.local_ip, dest_ip)
            .ok_or(RingError::TooLarge)?;
        self.tx_free.commit_seqcst();
        let ok = self.tx_active.publish(slot.offset, len as u16);
        assert!(ok, "tx_active must accept the slot we just claimed from tx_free");
        self.tx_active.maybe_notify_seqcst();
        Ok(())
    }

    /// Test / observability hook - number of cache learning attempts
    /// the binding rejected because the ARP cache was full.
    pub fn arp_rejected_inserts(&self) -> u32 {
        self.arp.rejected_inserts()
    }

    /// Drive the ARP retry / cooldown state machine forward.
    ///
    /// `now` is a tick count chosen by the caller, one tick per call.
    /// If `pending_arp` is `InFlight` and its deadline has elapsed, this
    /// re-emits the ARP request and spends one retry. When the retries
    /// are exhausted it moves to `Failed` for
    /// [`arp::ARP_FAILED_BACKOFF_TICKS`]; after that backoff the next
    /// tick clears it, and a later `enqueue_tx` starts a fresh resolution.
    ///
    /// The PD calls this once per notification it receives. A PD that
    /// receives no notification does not tick, so a lost reply is only
    /// retried when the next notification arrives. The ticks are not a
    /// measure of time: a PD has no readable timer (see the crate README).
    ///
    /// A retry that finds no free TX buffer is not spent (see
    /// [`arp::defer_retry`]).
    pub fn tick_arp(&mut self, now: u64) {
        self.last_tick = now;
        if let arp::PendingTick::Retry { dest_ip } =
            arp::tick_pending(&mut self.pending_arp, now)
        {
            match self.try_emit_arp_request(dest_ip) {
                Ok(()) => {}
                // No TX buffer: the request was not sent, so the retry is
                // not spent. It is due again at the next tick, which the
                // tx_free wake-up from `claim_tx_slot` provides.
                Err(RingError::Full) => arp::defer_retry(&mut self.pending_arp, now),
                Err(RingError::TooLarge) => {
                    debug_assert!(false, "ARP request (42 bytes) always fits")
                }
                Err(RingError::Empty) => {
                    debug_assert!(false, "Empty is RX-only; TX emit cannot return it")
                }
            }
        }
    }
}

// Lock `Sel4RingInit` size at compile time so the C wrapper can
// mirror the layout with a matching `_Static_assert`. Field walk:
// mac[6] + pad[2] = 8; RX group = 4 x 8-byte pointer/size fields +
// u16/u8/u8 + 4 bytes implicit padding = 40; TX group = the same 32 +
// u16/u8/u8, with local_ip[4] filling the 4 trailing bytes = 40.
// Total 88 bytes, align 8.
const _: () = {
    assert!(core::mem::size_of::<Sel4RingInit>() == 88);
    assert!(core::mem::align_of::<Sel4RingInit>() == 8);
};

impl PacketRing for Sel4Ring {
    fn enqueue_tx(
        &mut self,
        data: &[u8],
        dest_ip: [u8; 4],
        dest_port: u16,
    ) -> Result<(), RingError> {
        if data.len() > SLOT_MTU {
            return Err(RingError::TooLarge);
        }

        // Resolve dest MAC. Three outcomes:
        // - cached -> fall through and build the UDP frame
        // - in-flight (any dest) -> return Full; caller retries
        // - not cached, slot free -> emit ARP request, return Full
        let dest_mac = match self.arp.lookup(dest_ip) {
            Some(m) => m,
            None => {
                if self.pending_arp.is_some() {
                    // Single-in-flight design: any pending
                    // resolution blocks new ones.
                    return Err(RingError::Full);
                }
                self.try_emit_arp_request(dest_ip)?;
                // State recorded ONLY after a successful emit. A
                // `?`-propagated failure above leaves `pending_arp` at
                // None so a future call can try again.
                self.pending_arp = Some(arp::start_resolution(dest_ip, self.last_tick));
                return Err(RingError::Full);
            }
        };

        // Claim, build, publish, maybe-notify. When no TX buffer is
        // free, `claim_tx_slot` requests a wake-up from the driver, so
        // this send is not left waiting for unrelated RX traffic.
        let slot = self.claim_tx_slot()?;
        let tx_buf = self
            .tx_data
            .slice_mut(slot.offset, NET_BUFFER_SIZE)
            .ok_or(RingError::Full)?;
        let len = netstack::build_udp_frame(
            tx_buf,
            self.mac,
            dest_mac,
            self.local_ip,
            dest_ip,
            LOCAL_PORT,
            dest_port,
            data,
        )
        .ok_or(RingError::TooLarge)?;
        self.tx_free.commit_seqcst();
        let ok = self.tx_active.publish(slot.offset, len as u16);
        assert!(ok, "tx_active must accept the slot we just claimed from tx_free");
        self.tx_active.maybe_notify_seqcst();
        Ok(())
    }

    fn try_dequeue_rx(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(usize, [u8; 4], u16), RingError> {
        loop {
            // Acquire-load tail (inside peek_acquire). On empty,
            // run the full consumer recipe; verdict tells us
            // whether to drain again or sleep.
            let slot = match self.rx_active.peek_acquire() {
                Some(s) => s,
                None => match self.rx_active.request_signal_with_recheck() {
                    DrainVerdict::Continue => continue,
                    DrainVerdict::Sleep => return Err(RingError::Empty),
                },
            };

            // Borrow `self.rx_data` immutably (via `frame`); `buf` is
            // already borrowed mutably from outside `self`. `classify_inbound`
            // is a free fn so it doesn't take any borrow on `self`,
            // letting us release both at the end of this `let`.
            let outcome = match self.rx_data.slice(slot.offset, slot.len) {
                None => InboundOutcome::Drop,
                Some(frame) => Self::classify_inbound(self.local_ip, LOCAL_PORT, frame, buf),
            };

            match outcome {
                InboundOutcome::DeliverUdp {
                    len,
                    src_ip,
                    src_port,
                } => {
                    self.rx_active.commit_seqcst();
                    let ok = self.rx_free.publish(slot.offset, 0);
                    assert!(ok, "rx_free must accept the slot we just consumed from rx_active");
                    self.rx_free.maybe_notify_seqcst();
                    return Ok((len, src_ip, src_port));
                }
                InboundOutcome::TooLarge => {
                    // Cardinal rule: do NOT commit. Next call with
                    // a bigger buffer will re-peek the same slot.
                    return Err(RingError::TooLarge);
                }
                InboundOutcome::Drop => {
                    self.rx_active.commit_seqcst();
                    let ok = self.rx_free.publish(slot.offset, 0);
                    assert!(ok, "rx_free must accept the slot we just consumed from rx_active");
                    self.rx_free.maybe_notify_seqcst();
                    continue;
                }
                InboundOutcome::Arp(a) => {
                    self.handle_arp(a);
                    self.rx_active.commit_seqcst();
                    let ok = self.rx_free.publish(slot.offset, 0);
                    assert!(ok, "rx_free must accept the slot we just consumed from rx_active");
                    self.rx_free.maybe_notify_seqcst();
                    continue;
                }
            }
        }
    }

    fn slot_mtu(&self) -> usize {
        SLOT_MTU
    }
}

#[cfg(test)]
mod tests {
    //! Host-side smoke tests for `Sel4Ring`.
    //!
    //! We fabricate a complete shared-memory layout (four queue
    //! headers + two data regions) on the heap and drive `Sel4Ring`
    //! through `enqueue_tx`/`try_dequeue_rx` from a single thread.
    //! Cross-PD concurrency is not exercised here; it needs a QEMU run.

    use super::*;

    /// Heap-backed sDDF arena: one queue's header + descriptor table.
    ///
    /// Backed by `Vec<u64>` (not `Vec<u8>`) so the allocation is
    /// language-guaranteed 8-byte aligned. `NetQueueHeader` is
    /// `repr(C, align(8))` and casting a u8-aligned pointer to it is
    /// UB.
    struct QueueBacking {
        words: Vec<u64>,
    }
    impl QueueBacking {
        fn new(capacity: u16) -> Self {
            let sz = core::mem::size_of::<NetQueueHeader>()
                + (capacity as usize) * core::mem::size_of::<queue::NetBuffDesc>();
            let words = sz.div_ceil(core::mem::size_of::<u64>());
            Self {
                words: vec![0u64; words],
            }
        }
        fn header_ptr(&mut self) -> SharedHeaderPtr {
            self.words.as_mut_ptr() as SharedHeaderPtr
        }
    }

    /// Same 8-aligned backing for the data regions (which carry the
    /// network frames). Misaligned data regions are not technically UB
    /// (the bytes have no alignment requirement), but keeping all
    /// host-side backing 8-aligned matches the real Microkit layout.
    fn aligned_zero_data(size: usize) -> Vec<u64> {
        let words = size.div_ceil(core::mem::size_of::<u64>());
        vec![0u64; words]
    }

    /// A complete fake sDDF environment for one Sel4Ring instance.
    struct Harness {
        _rx_free: QueueBacking,
        _rx_active: QueueBacking,
        _tx_free: QueueBacking,
        _tx_active: QueueBacking,
        _rx_data: Vec<u64>,
        _tx_data: Vec<u64>,
    }

    fn build_ring(capacity: u16) -> (Sel4Ring, Harness) {
        let mut rx_free = QueueBacking::new(capacity);
        let mut rx_active = QueueBacking::new(capacity);
        let mut tx_free = QueueBacking::new(capacity);
        let mut tx_active = QueueBacking::new(capacity);

        let region_size = (capacity as usize) * NET_BUFFER_SIZE;
        let mut rx_data = aligned_zero_data(region_size);
        let mut tx_data = aligned_zero_data(region_size);

        let init = Sel4RingInit {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            _pad0: [0; 2],
            rx_free_header: rx_free.header_ptr(),
            rx_active_header: rx_active.header_ptr(),
            rx_data_vaddr: rx_data.as_mut_ptr() as *mut u8,
            rx_data_size: region_size,
            rx_num_buffers: capacity,
            rx_channel_id: 1,
            _pad1: 0,
            tx_free_header: tx_free.header_ptr(),
            tx_active_header: tx_active.header_ptr(),
            tx_data_vaddr: tx_data.as_mut_ptr() as *mut u8,
            tx_data_size: region_size,
            tx_num_buffers: capacity,
            tx_channel_id: 2,
            _pad2: 0,
            local_ip: [10, 0, 2, 17],
        };

        // SAFETY: every pointer above is alive for the lifetime of
        // the returned `Harness`, which the caller binds to a local
        // alongside the ring. Capacity is 4 (power of two, <= 32768).
        // Sizes match `capacity * NET_BUFFER_SIZE`.
        let ring = unsafe { Sel4Ring::new(&init) };
        (
            ring,
            Harness {
                _rx_free: rx_free,
                _rx_active: rx_active,
                _tx_free: tx_free,
                _tx_active: tx_active,
                _rx_data: rx_data,
                _tx_data: tx_data,
            },
        )
    }

    #[test]
    fn new_seeds_tx_free_and_reports_mtu() {
        let (ring, _h) = build_ring(4);
        assert_eq!(ring.slot_mtu(), SLOT_MTU);
    }

    #[test]
    fn enqueue_to_unknown_ip_emits_arp_and_returns_full() {
        let (mut ring, _h) = build_ring(4);
        // No ARP cache entry for the destination -> expect an ARP
        // request to be emitted and the call to return Full so the
        // caller retries after the reply lands.
        let result = ring.enqueue_tx(b"hello", [10, 0, 2, 2], 9999);
        assert_eq!(result, Err(RingError::Full));
        // pending_arp must be set after a successful ARP emit.
        assert!(ring.pending_arp.is_some());
    }

    #[test]
    fn enqueue_oversize_payload_returns_too_large() {
        let (mut ring, _h) = build_ring(4);
        let big = [0u8; SLOT_MTU + 1];
        let result = ring.enqueue_tx(&big, [10, 0, 2, 2], 9999);
        assert_eq!(result, Err(RingError::TooLarge));
    }

    #[test]
    fn enqueue_succeeds_after_arp_cache_warmed() {
        let (mut ring, _h) = build_ring(4);
        // Pre-populate the ARP cache so the TX path skips ARP.
        let peer_mac: MacAddr = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let peer_ip: Ipv4Addr = [10, 0, 2, 2];
        assert!(ring.arp.learn(peer_ip, peer_mac, 0));

        let result = ring.enqueue_tx(b"hi", peer_ip, 9999);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn try_dequeue_returns_empty_on_idle_queue() {
        let (mut ring, _h) = build_ring(4);
        let mut buf = [0u8; 128];
        let r = ring.try_dequeue_rx(&mut buf);
        assert_eq!(r, Err(RingError::Empty));
    }

    #[test]
    fn enqueue_tx_then_check_wire_bytes_via_inbound_classification() {
        // End-to-end smoke test: an enqueue produces wire bytes that
        // a sibling parser must accept. We do this by reading back
        // the bytes from tx_data via Sel4Ring's own slice helper -
        // but `tx_data` isn't pub. So we reach in via the harness
        // (which holds the backing). The cleaner
        // host check is just that enqueue_tx succeeds; bit-level
        // wire validation is done in netstack's own tests.
        let (mut ring, _h) = build_ring(4);
        let peer_ip: Ipv4Addr = [10, 0, 2, 2];
        let peer_mac: MacAddr = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        assert!(ring.arp.learn(peer_ip, peer_mac, 0));

        for i in 0..3u8 {
            let payload = [i; 10];
            assert_eq!(
                ring.enqueue_tx(&payload, peer_ip, 9999),
                Ok(())
            );
        }
        // tx_active now holds 3 published slots; nothing on RX side.
        let mut buf = [0u8; 128];
        assert_eq!(ring.try_dequeue_rx(&mut buf), Err(RingError::Empty));
    }

    // ----- Driver-side helpers for the ARP and tx_free wake-up tests -----
    //
    // The ring is the producer of tx_active and the consumer of tx_free;
    // the driver (virtualiser) plays the other side here. `drain_tx`
    // takes every published frame and returns its buffer, as the driver
    // does. `inject_rx` puts one frame on rx_active.

    const OUR_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const OUR_IP: Ipv4Addr = [10, 0, 2, 17];
    const PEER_MAC: MacAddr = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
    const PEER_IP: Ipv4Addr = [10, 0, 2, 2];

    fn hdr(p: SharedHeaderPtr) -> NonNull<NetQueueHeader> {
        NonNull::new(p as *mut NetQueueHeader).expect("header non-null")
    }

    /// Driver side of tx_active: copy out every published frame and hand
    /// each buffer back on tx_free (with the driver's notify recipe).
    fn drain_tx(h: &mut Harness, cap: u16) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let tx_active_hdr = hdr(h._tx_active.header_ptr());
        let tx_free_hdr = hdr(h._tx_free.header_ptr());
        let base = h._tx_data.as_ptr() as *const u8;
        // SAFETY: the headers and the data region belong to `h`, which
        // outlives this call; this test thread is the only accessor.
        unsafe {
            let mut active = ConsumerHandle::new(tx_active_hdr, cap, 2);
            let mut free = ProducerHandle::new(tx_free_hdr, cap, 2);
            while let Some(slot) = active.peek_acquire() {
                let bytes =
                    core::slice::from_raw_parts(base.add(slot.offset as usize), slot.len as usize);
                frames.push(bytes.to_vec());
                active.commit_seqcst();
                assert!(free.publish(slot.offset, 0), "tx_free accepts the returned buffer");
                free.maybe_notify_seqcst();
            }
        }
        frames
    }

    /// Driver side of rx_active: place one frame at the start of the RX
    /// data region and publish it.
    fn inject_rx(h: &mut Harness, cap: u16, frame: &[u8]) {
        let rx_active_hdr = hdr(h._rx_active.header_ptr());
        let dst = h._rx_data.as_mut_ptr() as *mut u8;
        // SAFETY: the RX region holds `cap * NET_BUFFER_SIZE` bytes and a
        // frame is far smaller than one buffer; `h` outlives the call.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), dst, frame.len());
            let mut prod = ProducerHandle::new(rx_active_hdr, cap, 1);
            assert!(prod.publish(0, frame.len() as u16));
        }
    }

    /// Value of the consumer_signalled word of tx_free (0 = wake requested).
    fn tx_free_signalled(h: &mut Harness) -> u32 {
        // SAFETY: the header lives in `h`'s backing, which is alive here.
        unsafe {
            (*(h._tx_free.header_ptr() as *const NetQueueHeader))
                .consumer_signalled
                .load(core::sync::atomic::Ordering::SeqCst)
        }
    }

    fn host_notifies() -> u32 {
        queue::HOST_NOTIFIES.with(|c| c.get())
    }

    /// True if `frame` is an ARP request asking for `ip`.
    fn is_arp_request_for(frame: &[u8], ip: Ipv4Addr) -> bool {
        frame.len() >= 42
            && frame[12..14] == [0x08, 0x06]
            && frame[20..22] == [0x00, 0x01]
            && frame[38..42] == ip
    }

    /// True if `frame` is an IPv4 UDP frame to `mac`.
    fn is_udp_to(frame: &[u8], mac: MacAddr) -> bool {
        frame.len() >= 42 && frame[0..6] == mac && frame[12..14] == [0x08, 0x00]
    }

    fn arp_reply_from_peer() -> Vec<u8> {
        let mut buf = [0u8; 64];
        let n = netstack::build_arp_reply(&mut buf, PEER_MAC, PEER_IP, OUR_MAC, OUR_IP)
            .expect("reply fits");
        buf[..n].to_vec()
    }

    #[test]
    fn lost_first_arp_reply_is_retried_and_send_succeeds() {
        let (mut ring, mut h) = build_ring(4);
        assert_eq!(ring.enqueue_tx(b"hi", PEER_IP, 9999), Err(RingError::Full));
        let first = drain_tx(&mut h, 4);
        assert_eq!(first.len(), 1);
        assert!(is_arp_request_for(&first[0], PEER_IP));

        // The first reply is lost. Nothing is due before the deadline.
        ring.tick_arp(arp::ARP_REQUEST_DEADLINE_TICKS - 1);
        assert!(drain_tx(&mut h, 4).is_empty());

        // At the deadline the request is re-sent, once.
        ring.tick_arp(arp::ARP_REQUEST_DEADLINE_TICKS);
        let retry = drain_tx(&mut h, 4);
        assert_eq!(retry.len(), 1);
        assert!(is_arp_request_for(&retry[0], PEER_IP));

        // The reply to the retry arrives and is consumed from RX.
        inject_rx(&mut h, 4, &arp_reply_from_peer());
        let mut buf = [0u8; 128];
        assert_eq!(ring.try_dequeue_rx(&mut buf), Err(RingError::Empty));
        assert!(ring.pending_arp.is_none());

        // The send now goes out to the peer's MAC.
        assert_eq!(ring.enqueue_tx(b"hi", PEER_IP, 9999), Ok(()));
        let sent = drain_tx(&mut h, 4);
        assert_eq!(sent.len(), 1);
        assert!(is_udp_to(&sent[0], PEER_MAC));
        assert_eq!(&sent[0][sent[0].len() - 2..], b"hi");
    }

    #[test]
    fn arp_retries_are_bounded_then_fall_back_after_cooldown() {
        let (mut ring, mut h) = build_ring(4);
        assert_eq!(ring.enqueue_tx(b"hi", PEER_IP, 9999), Err(RingError::Full));
        let mut sent = drain_tx(&mut h, 4).len(); // initial request
        for t in [arp::ARP_REQUEST_DEADLINE_TICKS, 2 * arp::ARP_REQUEST_DEADLINE_TICKS, 3 * arp::ARP_REQUEST_DEADLINE_TICKS] {
            ring.tick_arp(t);
            sent += drain_tx(&mut h, 4).len(); // retries 1..=3
        }
        assert_eq!(sent, 1 + arp::ARP_RETRIES_MAX as usize);

        // Budget spent: the next tick gives up and sends nothing more.
        ring.tick_arp(4 * arp::ARP_REQUEST_DEADLINE_TICKS);
        assert!(drain_tx(&mut h, 4).is_empty());
        let failed_until = 4 * arp::ARP_REQUEST_DEADLINE_TICKS + arp::ARP_FAILED_BACKOFF_TICKS;
        assert!(matches!(
            ring.pending_arp,
            Some(arp::PendingArp::Failed { cooldown_until, .. }) if cooldown_until == failed_until
        ));

        // During the backoff, sends fail without emitting anything.
        assert_eq!(ring.enqueue_tx(b"hi", PEER_IP, 9999), Err(RingError::Full));
        ring.tick_arp(failed_until - 1);
        assert!(drain_tx(&mut h, 4).is_empty());
        assert!(ring.pending_arp.is_some());

        // After the backoff the state clears and a new resolution starts.
        ring.tick_arp(failed_until);
        assert!(ring.pending_arp.is_none());
        assert_eq!(ring.enqueue_tx(b"hi", PEER_IP, 9999), Err(RingError::Full));
        let fresh = drain_tx(&mut h, 4);
        assert_eq!(fresh.len(), 1);
        assert!(is_arp_request_for(&fresh[0], PEER_IP));
    }

    #[test]
    fn resolution_deadline_starts_from_the_current_tick() {
        let (mut ring, _h) = build_ring(4);
        ring.tick_arp(5);
        assert_eq!(ring.enqueue_tx(b"hi", PEER_IP, 9999), Err(RingError::Full));
        assert!(matches!(
            ring.pending_arp,
            Some(arp::PendingArp::InFlight { deadline, .. }) if deadline == 5 + arp::ARP_REQUEST_DEADLINE_TICKS
        ));
    }

    #[test]
    fn tx_free_empty_cached_send_requests_wake_and_free_notifies() {
        let (mut ring, mut h) = build_ring(4);
        for ip in [[10, 0, 2, 2], [10, 0, 2, 3], [10, 0, 2, 4], [10, 0, 2, 5]] {
            assert!(ring.arp.learn(ip, PEER_MAC, 0));
            assert_eq!(ring.enqueue_tx(b"x", ip, 9999), Ok(()));
        }
        // tx_free is empty: the send fails and asks for a wake-up.
        assert_eq!(ring.enqueue_tx(b"x", PEER_IP, 9999), Err(RingError::Full));
        assert_eq!(tx_free_signalled(&mut h), 0, "driver must be asked to notify");

        // The driver returns the buffers: exactly one notification is due.
        let before = host_notifies();
        assert_eq!(drain_tx(&mut h, 4).len(), 4);
        assert_eq!(host_notifies(), before + 1);
        assert_eq!(tx_free_signalled(&mut h), 1);

        assert_eq!(ring.enqueue_tx(b"x", PEER_IP, 9999), Ok(()));
    }

    #[test]
    fn tx_free_empty_not_cached_branch_requests_wake_without_arp_state() {
        let (mut ring, mut h) = build_ring(4);
        for ip in [[10, 0, 2, 2], [10, 0, 2, 3], [10, 0, 2, 4], [10, 0, 2, 5]] {
            assert!(ring.arp.learn(ip, PEER_MAC, 0));
            assert_eq!(ring.enqueue_tx(b"x", ip, 9999), Ok(()));
        }
        // Unknown destination and no TX buffer: no ARP request can be
        // emitted, so no resolution state is recorded either.
        assert_eq!(ring.enqueue_tx(b"x", [10, 0, 2, 9], 9999), Err(RingError::Full));
        assert!(ring.pending_arp.is_none());
        assert_eq!(tx_free_signalled(&mut h), 0);

        let before = host_notifies();
        assert_eq!(drain_tx(&mut h, 4).len(), 4);
        assert_eq!(host_notifies(), before + 1);

        // With a buffer back, the same destination now starts resolution.
        assert_eq!(ring.enqueue_tx(b"x", [10, 0, 2, 9], 9999), Err(RingError::Full));
        let arp_frames = drain_tx(&mut h, 4);
        assert_eq!(arp_frames.len(), 1);
        assert!(is_arp_request_for(&arp_frames[0], [10, 0, 2, 9]));
    }

    #[test]
    fn retry_deferred_while_tx_free_empty_is_sent_on_wake() {
        let (mut ring, mut h) = build_ring(4);
        assert_eq!(ring.enqueue_tx(b"hi", PEER_IP, 9999), Err(RingError::Full));
        // Use up the other three buffers, so the retry finds none free.
        for ip in [[10, 0, 2, 3], [10, 0, 2, 4], [10, 0, 2, 5]] {
            assert!(ring.arp.learn(ip, PEER_MAC, 0));
            assert_eq!(ring.enqueue_tx(b"x", ip, 9999), Ok(()));
        }

        // The retry is due but cannot be sent: it is not spent, and the
        // failed claim asked the driver for a wake-up.
        ring.tick_arp(arp::ARP_REQUEST_DEADLINE_TICKS);
        assert_eq!(tx_free_signalled(&mut h), 0);
        assert!(matches!(
            ring.pending_arp,
            Some(arp::PendingArp::InFlight { retries_left, deadline, .. })
                if retries_left == arp::ARP_RETRIES_MAX && deadline == arp::ARP_REQUEST_DEADLINE_TICKS
        ));

        // The driver frees buffers; the next tick sends the same retry.
        let frames = drain_tx(&mut h, 4);
        assert_eq!(frames.len(), 4);
        ring.tick_arp(arp::ARP_REQUEST_DEADLINE_TICKS);
        assert!(matches!(
            ring.pending_arp,
            Some(arp::PendingArp::InFlight { retries_left, .. })
                if retries_left == arp::ARP_RETRIES_MAX - 1
        ));
        let retry = drain_tx(&mut h, 4);
        assert_eq!(retry.len(), 1);
        assert!(is_arp_request_for(&retry[0], PEER_IP));
    }
}
