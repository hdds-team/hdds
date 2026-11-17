// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! [`Sel4UdpTransport`] - adapter that makes any [`PacketRing`] look like
//! an `hdds-micro::Transport`.
//!
//! Design choices:
//!
//! - `send()` maps directly to `enqueue_tx`; any non-UDPv4 locator fails
//!   with [`hdds_micro::Error::InvalidParameter`] because the ring only
//!   carries IPv4 bytes.
//! - `recv()` is implemented as a busy-poll over `try_dequeue_rx`. On the
//!   seL4 side the caller is expected to yield via `sel4::wait_notify()`
//!   instead; we keep the blocking impl feature-gated to `std` so the
//!   `no_std` builds don't depend on any sleep primitive.
//! - `try_recv()` returns `Error::ResourceExhausted` on empty, exactly
//!   matching the contract stated in `hdds-micro`'s `Transport` trait.
//! - `mtu()` reports the ring's slot size (`PacketRing::slot_mtu`), not
//!   a hard-coded constant.
//!
//! The type is generic in the ring so unit tests drive it with a
//! `MockRing` while the seL4 build instantiates it with `Sel4Ring`.

use hdds_micro::error::{Error as MicroError, Result as MicroResult};
use hdds_micro::rtps::Locator;
use hdds_micro::transport::Transport;

use crate::locator::locator_to_ipv4;
use crate::sel4_ring::{Sel4Ring, SLOT_MTU};
use crate::ring::{PacketRing, RingError};

/// `Transport` impl backed by any `PacketRing`.
///
/// The transport owns its ring; there is no interior mutability - all
/// state is reachable through `&mut self`. This mirrors the single-PD
/// model on Microkit (one transport per protection domain).
pub struct Sel4UdpTransport<R: PacketRing> {
    ring: R,
    local: Locator,
    /// Scratch that consumes an oversized frame in `try_recv`.
    discard: [u8; SLOT_MTU],
}

impl<R: PacketRing> Sel4UdpTransport<R> {
    /// Build a new transport bound to `local` (the address reported to
    /// `hdds-micro` and stamped on outgoing SEDP announcements).
    pub fn new(ring: R, local: Locator) -> Self {
        Self { ring, local, discard: [0u8; SLOT_MTU] }
    }

    /// Access the underlying ring. Intended for test assertions only;
    /// hidden from `cargo doc` because it leaks the ring type into the
    /// public surface.
    #[doc(hidden)]
    pub fn ring(&self) -> &R {
        &self.ring
    }
}

fn ring_err_to_micro(e: RingError) -> MicroError {
    match e {
        // Empty (RX) and Full (TX) are both "retry later" signals -
        // `hdds-micro::Error` has no dedicated `WouldBlock`, so we map
        // them to `ResourceExhausted` (the contract already used for
        // `try_recv`). `TransportError` is reserved for hard failures.
        RingError::Empty | RingError::Full => MicroError::ResourceExhausted,
        RingError::TooLarge => MicroError::BufferTooSmall,
    }
}

impl Sel4UdpTransport<Sel4Ring> {
    /// Drive the ARP retry and cooldown state machine by one tick (see
    /// [`Sel4Ring::tick_arp`]). The PD calls this once per notification.
    pub fn tick_arp(&mut self, tick: u64) {
        self.ring.tick_arp(tick);
    }
}

impl<R: PacketRing> Transport for Sel4UdpTransport<R> {
    fn init(&mut self) -> MicroResult<()> {
        // Ring is handed over fully initialized (sDDF queues are set up
        // by the Microkit system loader before the PD starts). Nothing
        // to do here for now.
        Ok(())
    }

    fn send(&mut self, data: &[u8], dest: &Locator) -> MicroResult<usize> {
        let (ip, port) = locator_to_ipv4(dest).ok_or(MicroError::InvalidParameter)?;
        self.ring
            .enqueue_tx(data, ip, port)
            .map_err(ring_err_to_micro)?;
        Ok(data.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> MicroResult<(usize, Locator)> {
        // Blocking `recv` is only available on `std` builds where it
        // yields to the scheduler between polls. Under `no_std`
        // (real Microkit PD), a PD must wait on a channel notification
        // via the Microkit syscalls - a bare Rust `recv` cannot do that
        // without help, so we refuse to pretend we can and return
        // `TransportError`. Callers in a PD should drive I/O with
        // `try_recv` + their own `wait_notify` loop.
        #[cfg(feature = "std")]
        {
            loop {
                match self.ring.try_dequeue_rx(buf) {
                    Ok((n, ip, port)) => {
                        let src = Locator::udpv4(ip, port);
                        return Ok((n, src));
                    }
                    Err(RingError::Empty) => {
                        std::thread::yield_now();
                        continue;
                    }
                    Err(other) => return Err(ring_err_to_micro(other)),
                }
            }
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = buf;
            Err(MicroError::TransportError)
        }
    }

    fn try_recv(&mut self, buf: &mut [u8]) -> MicroResult<(usize, Locator)> {
        match self.ring.try_dequeue_rx(buf) {
            Ok((n, ip, port)) => Ok((n, Locator::udpv4(ip, port))),
            // The ring keeps an oversized frame queued (its contract). Consume
            // it here, as a UDP recv discards a datagram that does not fit, so
            // the frames behind it stay reachable. Reported as BufferTooSmall.
            Err(RingError::TooLarge) => {
                let _ = self.ring.try_dequeue_rx(&mut self.discard);
                Err(MicroError::BufferTooSmall)
            }
            Err(e) => Err(ring_err_to_micro(e)),
        }
    }

    fn local_locator(&self) -> Locator {
        self.local
    }

    fn mtu(&self) -> usize {
        self.ring.slot_mtu()
    }

    fn shutdown(&mut self) -> MicroResult<()> {
        // sDDF queues are torn down by the system when the PD exits.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdds_micro::rtps::Locator;

    #[cfg(feature = "std")]
    use crate::mock_ring::mock_pair;

    #[cfg(feature = "std")]
    #[test]
    fn send_then_try_recv_roundtrip() {
        let (ring_a, ring_b) = mock_pair(([10, 0, 0, 1], 7400), ([10, 0, 0, 2], 7401));
        let mut a = Sel4UdpTransport::new(ring_a, Locator::udpv4([10, 0, 0, 1], 7400));
        let mut b = Sel4UdpTransport::new(ring_b, Locator::udpv4([10, 0, 0, 2], 7401));

        let payload = b"RTPS\x02\x05\x00\x00\xff\xee";
        let dst = Locator::udpv4([10, 0, 0, 2], 7401);
        let n = a.send(payload, &dst).unwrap();
        assert_eq!(n, payload.len());

        let mut buf = [0u8; 64];
        let (rx_n, src) = b.try_recv(&mut buf).unwrap();
        assert_eq!(&buf[..rx_n], payload);
        assert_eq!(src, Locator::udpv4([10, 0, 0, 1], 7400));
    }

    #[cfg(feature = "std")]
    #[test]
    fn try_recv_empty_is_resource_exhausted() {
        let (_a, ring_b) = mock_pair(([10, 0, 0, 1], 7400), ([10, 0, 0, 2], 7401));
        let mut b = Sel4UdpTransport::new(ring_b, Locator::udpv4([10, 0, 0, 2], 7401));
        let mut buf = [0u8; 32];
        assert_eq!(b.try_recv(&mut buf), Err(MicroError::ResourceExhausted));
    }

    #[cfg(feature = "std")]
    #[test]
    fn send_rejects_non_udpv4() {
        let (ring_a, _b) = mock_pair(([10, 0, 0, 1], 7400), ([10, 0, 0, 2], 7401));
        let mut a = Sel4UdpTransport::new(ring_a, Locator::udpv4([10, 0, 0, 1], 7400));
        let result = a.send(b"x", &Locator::INVALID);
        assert_eq!(result, Err(MicroError::InvalidParameter));
    }

    #[cfg(feature = "std")]
    #[test]
    fn mtu_reflects_ring_slot_size() {
        let (ring_a, _b) = mock_pair(([10, 0, 0, 1], 7400), ([10, 0, 0, 2], 7401));
        let expected = ring_a.slot_mtu();
        let a = Sel4UdpTransport::new(ring_a, Locator::udpv4([10, 0, 0, 1], 7400));
        assert_eq!(a.mtu(), expected);
    }

    #[cfg(feature = "std")]
    #[test]
    fn local_locator_is_returned_as_is() {
        let (ring_a, _b) = mock_pair(([10, 0, 0, 1], 7400), ([10, 0, 0, 2], 7401));
        let local = Locator::udpv4([10, 0, 0, 1], 7400);
        let a = Sel4UdpTransport::new(ring_a, local);
        assert_eq!(a.local_locator(), local);
    }
}
