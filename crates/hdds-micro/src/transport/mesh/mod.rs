// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Mesh Multi-hop Transport for HDDS Micro
//!
//! Implements a simple flooding-based mesh protocol that allows messages
//! to be relayed across multiple hops to extend range.
//!
//! ## Architecture
//!
//! ```text
//! +--------------+   LoRa    +--------------+   LoRa    +--------------+
//! |  Node A      | ~~~~~~~~~ |  Node B      | ~~~~~~~~~ |  Gateway     |
//! |  (Sensor)    |  Hop 1    |  (Relay)     |  Hop 2    |              |
//! +--------------+           +--------------+           +--------------+
//! ```
//!
//! ## Protocol
//!
//! - Simple controlled flooding with TTL
//! - Duplicate detection via sequence cache
//! - Optional RSSI-based neighbor tracking
//! - Configurable relay behavior

#![allow(dead_code)]

mod header;
mod neighbor;
mod router;
mod seen;

pub use header::{MeshFlags, MeshHeader, MESH_HEADER_SIZE};
pub use neighbor::{Neighbor, NeighborTable};
pub use router::{MeshConfig, MeshRouter, RelayDecision};
pub use seen::SeenCache;

use crate::error::{Error, Result};
use crate::transport::Transport;

/// Maximum mesh hops (TTL)
pub const MAX_TTL: u8 = 7;

/// Default TTL for new messages
pub const DEFAULT_TTL: u8 = 3;

/// Mesh transport wrapper
///
/// Wraps an underlying transport (LoRa, HC-12) and adds mesh routing.
pub struct MeshTransport<T: Transport, const NEIGHBORS: usize, const SEEN: usize> {
    /// Underlying transport
    inner: T,
    /// Mesh router
    router: MeshRouter<NEIGHBORS, SEEN>,
    /// Our node ID
    node_id: u8,
    /// Sequence number for outgoing messages
    seq: u16,
    /// Receive buffer for mesh header + payload
    rx_buf: [u8; 256],
}

impl<T: Transport, const NEIGHBORS: usize, const SEEN: usize> MeshTransport<T, NEIGHBORS, SEEN> {
    /// Create a new mesh transport
    pub fn new(inner: T, node_id: u8, config: MeshConfig) -> Self {
        Self {
            inner,
            router: MeshRouter::new(node_id, config),
            node_id,
            seq: 0,
            rx_buf: [0u8; 256],
        }
    }

    /// Get our node ID
    pub fn node_id(&self) -> u8 {
        self.node_id
    }

    /// Get next sequence number
    fn next_seq(&mut self) -> u16 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        seq
    }

    /// Send a message (originates from this node)
    pub fn send_mesh(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() > 255 - MESH_HEADER_SIZE {
            return Err(Error::BufferTooSmall);
        }

        let header = MeshHeader {
            src: self.node_id,
            dst: 0xFF, // Broadcast
            seq: self.next_seq(),
            ttl: self.router.config().default_ttl,
            flags: MeshFlags::empty(),
            hop_count: 0,
        };

        self.send_with_header(&header, payload)
    }

    /// Send to a specific destination
    pub fn send_to(&mut self, dest: u8, payload: &[u8]) -> Result<()> {
        if payload.len() > 255 - MESH_HEADER_SIZE {
            return Err(Error::BufferTooSmall);
        }

        let header = MeshHeader {
            src: self.node_id,
            dst: dest,
            seq: self.next_seq(),
            ttl: self.router.config().default_ttl,
            flags: MeshFlags::empty(),
            hop_count: 0,
        };

        self.send_with_header(&header, payload)
    }

    /// Send with a specific header
    fn send_with_header(&mut self, header: &MeshHeader, payload: &[u8]) -> Result<()> {
        let mut buf = [0u8; 256];
        let header_len = header.encode(&mut buf)?;

        let total_len = header_len + payload.len();
        if total_len > buf.len() {
            return Err(Error::BufferTooSmall);
        }

        buf[header_len..total_len].copy_from_slice(payload);

        // Use broadcast locator for mesh
        let locator = crate::rtps::Locator::udpv4([255, 255, 255, 255], 0);
        self.inner.send(&buf[..total_len], &locator)?;
        Ok(())
    }

    /// Receive a message (may be for us or needs relay)
    ///
    /// Returns `Some((src_node, payload))` if message is for us.
    /// Automatically relays messages that need forwarding.
    pub fn recv_mesh(&mut self, buf: &mut [u8]) -> Result<Option<(u8, usize)>> {
        // Try to receive from underlying transport
        let (len, _locator) = match self.inner.try_recv(&mut self.rx_buf) {
            Ok(result) => result,
            Err(Error::ResourceExhausted) => return Ok(None),
            Err(e) => return Err(e),
        };

        if len < MESH_HEADER_SIZE {
            return Ok(None); // Too short for mesh header
        }

        // Decode mesh header
        let header = match MeshHeader::decode(&self.rx_buf[..len]) {
            Ok(h) => h,
            Err(_) => return Ok(None), // Invalid header
        };

        // Get RSSI if available (for neighbor tracking)
        let rssi = self.inner.last_rssi();

        // Let router decide what to do
        let decision = self.router.process_received(&header, rssi);

        match decision {
            RelayDecision::Deliver => {
                // Message is for us, copy payload to output buffer
                let payload_start = MESH_HEADER_SIZE;
                let payload_len = len - payload_start;

                if payload_len > buf.len() {
                    return Err(Error::BufferTooSmall);
                }

                buf[..payload_len].copy_from_slice(&self.rx_buf[payload_start..len]);
                Ok(Some((header.src, payload_len)))
            }
            RelayDecision::Relay(new_header) => {
                // Need to relay this message
                let payload_start = MESH_HEADER_SIZE;
                let payload_len = len - payload_start;

                // Copy payload first to avoid borrow conflict
                let is_for_us = header.dst == 0xFF || header.dst == self.node_id;
                let should_deliver = is_for_us && payload_len <= buf.len();

                if should_deliver {
                    buf[..payload_len].copy_from_slice(&self.rx_buf[payload_start..len]);
                }

                // Now we can borrow rx_buf again for relay
                let mut relay_buf = [0u8; 256];
                relay_buf[..payload_len].copy_from_slice(&self.rx_buf[payload_start..len]);

                // Send with updated header (decremented TTL, incremented hop)
                let _ = self.send_with_header(&new_header, &relay_buf[..payload_len]);

                if should_deliver {
                    Ok(Some((header.src, payload_len)))
                } else {
                    Ok(None)
                }
            }
            RelayDecision::Drop => {
                // Duplicate or TTL expired
                Ok(None)
            }
        }
    }

    /// Get neighbor table reference
    pub fn neighbors(&self) -> &NeighborTable<NEIGHBORS> {
        self.router.neighbors()
    }

    /// Get router statistics
    pub fn stats(&self) -> MeshStats {
        self.router.stats()
    }

    /// Get mutable reference to underlying transport
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Get reference to underlying transport
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

/// Mesh statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MeshStats {
    /// Messages originated by us
    pub tx_originated: u32,
    /// Messages relayed
    pub tx_relayed: u32,
    /// Messages received for us
    pub rx_delivered: u32,
    /// Messages dropped (duplicate)
    pub rx_duplicate: u32,
    /// Messages dropped (TTL expired)
    pub rx_ttl_expired: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::NullTransport;

    #[test]
    fn test_mesh_transport_creation() {
        let inner = NullTransport::default();
        let config = MeshConfig::default();
        let mesh: MeshTransport<_, 8, 32> = MeshTransport::new(inner, 1, config);

        assert_eq!(mesh.node_id(), 1);
    }

    #[test]
    fn test_mesh_sequence_increment() {
        let inner = NullTransport::default();
        let config = MeshConfig::default();
        let mut mesh: MeshTransport<_, 8, 32> = MeshTransport::new(inner, 1, config);

        assert_eq!(mesh.next_seq(), 0);
        assert_eq!(mesh.next_seq(), 1);
        assert_eq!(mesh.next_seq(), 2);
    }
}
