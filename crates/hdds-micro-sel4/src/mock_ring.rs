// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Host-side mock of [`PacketRing`].
//!
//! Not compiled on `no_std` targets (depends on `alloc` + `std::sync`).
//! Two `MockRing` handles produced by [`mock_pair`] share a back-to-back
//! FIFO: whatever A transmits appears on B's RX queue, and vice-versa.
//! This lets us spin up two `Sel4UdpTransport`s in one test process and
//! run a full `MicroParticipant` pub/sub over pure in-memory transport.

use core::sync::atomic::{AtomicU32, Ordering};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::ring::{PacketRing, RingError};

/// Default payload ceiling used by [`mock_pair`] - matches the MTU that
/// `Sel4UdpTransport` reports (1472 = 1500 - 20 IP - 8 UDP).
pub const MOCK_DEFAULT_MTU: usize = 1472;

#[derive(Debug)]
struct Slot {
    payload: Vec<u8>,
    src_ip: [u8; 4],
    src_port: u16,
}

#[derive(Default, Debug)]
struct Lane {
    queue: VecDeque<Slot>,
}

#[derive(Debug)]
struct Shared {
    a_to_b: Mutex<Lane>,
    b_to_a: Mutex<Lane>,
    mtu: usize,
    // Per-lane capacity: if a lane already holds this many packets,
    // further enqueues on that lane return RingError::Full. 0 = unbounded
    // (the default - used by integration tests that want zero loss).
    capacity: usize,
    // Instrumentation for tests - lets us assert "no drops" without
    // reaching into the queues.
    tx_count: AtomicU32,
    rx_count: AtomicU32,
}

/// Which side of the pair a given `MockRing` represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    A,
    B,
}

/// Host-only mock [`PacketRing`] that pairs with a peer.
///
/// Construct via [`mock_pair`]. Every `MockRing` remembers its own
/// "local" IP/port - sent out as the source on the peer's RX side.
#[derive(Debug)]
pub struct MockRing {
    shared: Arc<Shared>,
    side: Side,
    local_ip: [u8; 4],
    local_port: u16,
}

impl MockRing {
    /// Packets successfully pushed through TX since creation (both
    /// sides count into the same shared counter).
    pub fn tx_count(&self) -> u32 {
        self.shared.tx_count.load(Ordering::Relaxed)
    }

    /// Packets successfully pulled through RX since creation.
    pub fn rx_count(&self) -> u32 {
        self.shared.rx_count.load(Ordering::Relaxed)
    }

    fn tx_lane(&self) -> &Mutex<Lane> {
        match self.side {
            Side::A => &self.shared.a_to_b,
            Side::B => &self.shared.b_to_a,
        }
    }

    fn rx_lane(&self) -> &Mutex<Lane> {
        match self.side {
            Side::A => &self.shared.b_to_a,
            Side::B => &self.shared.a_to_b,
        }
    }
}

impl PacketRing for MockRing {
    fn enqueue_tx(
        &mut self,
        data: &[u8],
        _dest_ip: [u8; 4],
        _dest_port: u16,
    ) -> Result<(), RingError> {
        if data.len() > self.shared.mtu {
            return Err(RingError::TooLarge);
        }
        // NOTE: `_dest_ip` / `_dest_port` are ignored in the mock - the
        // pair is a direct pipe. In the real sDDF impl these become the
        // UDP header fields that the driver fills in. See
        // `docs/MOCK_LIMITATIONS.md` for the full list of known gaps.
        let slot = Slot {
            payload: data.to_vec(),
            src_ip: self.local_ip,
            src_port: self.local_port,
        };
        let mut lane = self.tx_lane().lock().expect("mock lane poisoned");
        if self.shared.capacity > 0 && lane.queue.len() >= self.shared.capacity {
            return Err(RingError::Full);
        }
        lane.queue.push_back(slot);
        self.shared.tx_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn try_dequeue_rx(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(usize, [u8; 4], u16), RingError> {
        let mut lane = self.rx_lane().lock().expect("mock lane poisoned");
        let slot = lane.queue.pop_front().ok_or(RingError::Empty)?;
        if slot.payload.len() > buf.len() {
            // Put it back - caller gets a real error and can retry with
            // a larger buffer instead of silently losing the packet.
            lane.queue.push_front(slot);
            return Err(RingError::TooLarge);
        }
        let len = slot.payload.len();
        buf[..len].copy_from_slice(&slot.payload);
        self.shared.rx_count.fetch_add(1, Ordering::Relaxed);
        Ok((len, slot.src_ip, slot.src_port))
    }

    fn slot_mtu(&self) -> usize {
        self.shared.mtu
    }
}

/// Build a matched pair of `MockRing`s with the given local addresses
/// and default MTU.
pub fn mock_pair(
    local_a: ([u8; 4], u16),
    local_b: ([u8; 4], u16),
) -> (MockRing, MockRing) {
    mock_pair_with_mtu(local_a, local_b, MOCK_DEFAULT_MTU)
}

/// Build a matched pair with an explicit MTU (useful to stress the
/// `TooLarge` path).
pub fn mock_pair_with_mtu(
    local_a: ([u8; 4], u16),
    local_b: ([u8; 4], u16),
    mtu: usize,
) -> (MockRing, MockRing) {
    mock_pair_inner(local_a, local_b, mtu, 0)
}

/// Build a matched pair with per-lane capacity (packets). When a lane
/// holds `capacity` packets, further `enqueue_tx` calls on that side
/// return [`RingError::Full`]. Used by the backpressure tests.
///
/// `capacity = 0` means unbounded (same as [`mock_pair`]).
pub fn mock_pair_with_capacity(
    local_a: ([u8; 4], u16),
    local_b: ([u8; 4], u16),
    capacity: usize,
) -> (MockRing, MockRing) {
    mock_pair_inner(local_a, local_b, MOCK_DEFAULT_MTU, capacity)
}

fn mock_pair_inner(
    local_a: ([u8; 4], u16),
    local_b: ([u8; 4], u16),
    mtu: usize,
    capacity: usize,
) -> (MockRing, MockRing) {
    let shared = Arc::new(Shared {
        a_to_b: Mutex::new(Lane::default()),
        b_to_a: Mutex::new(Lane::default()),
        mtu,
        capacity,
        tx_count: AtomicU32::new(0),
        rx_count: AtomicU32::new(0),
    });
    let a = MockRing {
        shared: Arc::clone(&shared),
        side: Side::A,
        local_ip: local_a.0,
        local_port: local_a.1,
    };
    let b = MockRing {
        shared,
        side: Side::B,
        local_ip: local_b.0,
        local_port: local_b.1,
    };
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single_packet() {
        let (mut a, mut b) = mock_pair(([10, 0, 0, 1], 1111), ([10, 0, 0, 2], 2222));

        a.enqueue_tx(b"hello", [10, 0, 0, 2], 2222).unwrap();

        let mut buf = [0u8; 64];
        let (n, src_ip, src_port) = b.try_dequeue_rx(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(src_ip, [10, 0, 0, 1]);
        assert_eq!(src_port, 1111);
    }

    #[test]
    fn rx_empty_when_no_traffic() {
        let (_, mut b) = mock_pair(([10, 0, 0, 1], 1111), ([10, 0, 0, 2], 2222));
        let mut buf = [0u8; 32];
        assert_eq!(b.try_dequeue_rx(&mut buf), Err(RingError::Empty));
    }

    #[test]
    fn tx_too_large_rejected() {
        let (mut a, _b) = mock_pair_with_mtu(
            ([10, 0, 0, 1], 1111),
            ([10, 0, 0, 2], 2222),
            16,
        );
        let big = [0u8; 32];
        assert_eq!(
            a.enqueue_tx(&big, [10, 0, 0, 2], 2222),
            Err(RingError::TooLarge)
        );
    }

    #[test]
    fn tx_full_when_capacity_reached() {
        // Capacity of 2 on each lane - push 2 fine, 3rd is Full.
        let (mut a, mut b) = mock_pair_with_capacity(
            ([10, 0, 0, 1], 1111),
            ([10, 0, 0, 2], 2222),
            2,
        );
        a.enqueue_tx(b"x", [10, 0, 0, 2], 2222).unwrap();
        a.enqueue_tx(b"y", [10, 0, 0, 2], 2222).unwrap();
        assert_eq!(
            a.enqueue_tx(b"z", [10, 0, 0, 2], 2222),
            Err(RingError::Full)
        );

        // Drain on the peer's RX side - capacity frees up.
        let mut buf = [0u8; 4];
        let (_, _, _) = b.try_dequeue_rx(&mut buf).unwrap();
        a.enqueue_tx(b"z", [10, 0, 0, 2], 2222).unwrap();
    }

    #[test]
    fn rx_too_small_keeps_packet() {
        let (mut a, mut b) = mock_pair(([10, 0, 0, 1], 1111), ([10, 0, 0, 2], 2222));
        a.enqueue_tx(&[1, 2, 3, 4, 5, 6, 7, 8], [10, 0, 0, 2], 2222)
            .unwrap();

        let mut tiny = [0u8; 4];
        assert_eq!(b.try_dequeue_rx(&mut tiny), Err(RingError::TooLarge));

        // Still there - pull with a big enough buffer.
        let mut big = [0u8; 16];
        let (n, _, _) = b.try_dequeue_rx(&mut big).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&big[..n], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn bidirectional_fifo_order() {
        let (mut a, mut b) = mock_pair(([10, 0, 0, 1], 1111), ([10, 0, 0, 2], 2222));
        for i in 0..10u8 {
            a.enqueue_tx(&[i], [10, 0, 0, 2], 2222).unwrap();
            b.enqueue_tx(&[100 + i], [10, 0, 0, 1], 1111).unwrap();
        }
        for i in 0..10u8 {
            let mut buf = [0u8; 4];
            let (n, _, _) = b.try_dequeue_rx(&mut buf).unwrap();
            assert_eq!(n, 1);
            assert_eq!(buf[0], i);

            let (n, _, _) = a.try_dequeue_rx(&mut buf).unwrap();
            assert_eq!(n, 1);
            assert_eq!(buf[0], 100 + i);
        }
    }
}
