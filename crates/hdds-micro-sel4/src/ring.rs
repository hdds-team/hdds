// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! [`PacketRing`] - the contract between the transport layer and the
//! underlying shared-memory / sDDF / mock ring buffer.
//!
//! Semantics are modelled on the sDDF network free/active queue pair:
//! - TX: the transport pushes a packet; the ring is responsible for
//!   handing it to the driver (or to a paired mock).
//! - RX: the transport polls for incoming packets into a caller-owned
//!   buffer. There is no "peek" - on success the slot is consumed.
//!
//! All I/O is non-blocking. Blocking semantics on top (`Transport::recv`)
//! are built by spin-polling `try_dequeue_rx`.

/// Errors that a [`PacketRing`] can surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    /// No packet available right now. Expected path for polling.
    Empty,
    /// TX queue is saturated. Caller may retry later.
    Full,
    /// Packet does not fit in a ring slot (or in the caller RX buffer).
    TooLarge,
}

/// Abstraction over a bidirectional datagram queue.
///
/// Implementations:
/// - [`crate::MockRing`] - host-side, backed by `VecDeque`. Used for
///   unit/integration tests.
/// - [`crate::Sel4Ring`] - seL4 sDDF net binding (the Microkit notify
///   call is behind feature `microkit`).
pub trait PacketRing {
    /// Enqueue a datagram for transmission to `(dest_ip, dest_port)`.
    ///
    /// The ring is expected to copy the bytes; the caller may drop `data`
    /// after this returns.
    fn enqueue_tx(
        &mut self,
        data: &[u8],
        dest_ip: [u8; 4],
        dest_port: u16,
    ) -> Result<(), RingError>;

    /// Try to pull a received datagram into `buf`.
    ///
    /// On success returns `(len, src_ip, src_port)` where `len` is the
    /// number of bytes written to the head of `buf`.
    ///
    /// Returns [`RingError::Empty`] if nothing is pending (expected path
    /// in a poll loop), or [`RingError::TooLarge`] if the incoming packet
    /// does not fit in `buf`.
    fn try_dequeue_rx(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(usize, [u8; 4], u16), RingError>;

    /// Maximum payload a single packet can carry through this ring.
    ///
    /// Used by the transport layer to report its MTU to `hdds-micro`.
    fn slot_mtu(&self) -> usize;
}
