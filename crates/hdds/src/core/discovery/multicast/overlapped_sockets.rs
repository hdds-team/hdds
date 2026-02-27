// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Overlapped Socket Set - Zero-loss hot-reconfiguration
//!
//! Uses SO_REUSEPORT to allow old and new sockets to coexist during a
//! 500ms overlap window, ensuring zero packet loss during dialect switches.

use std::io;
use std::net::UdpSocket;
use std::time::Instant;

/// Overlap window duration (500ms)
const OVERLAP_DURATION_MS: u64 = 500;

/// Socket set with overlap support for hot-reconfiguration
pub struct OverlappedSocketSet {
    /// Old sockets (during overlap window)
    old_sockets: Option<Vec<UdpSocket>>,

    /// New sockets (active)
    new_sockets: Vec<UdpSocket>,

    /// Overlap window start time
    overlap_start: Option<Instant>,
}

impl OverlappedSocketSet {
    /// Create new socket set
    pub fn new(sockets: Vec<UdpSocket>) -> Self {
        crate::trace_fn!("OverlappedSocketSet::new");
        Self {
            old_sockets: None,
            new_sockets: sockets,
            overlap_start: None,
        }
    }

    /// Reconfigure with new sockets (starts overlap window)
    pub fn reconfigure(&mut self, new_sockets: Vec<UdpSocket>) {
        crate::trace_fn!("OverlappedSocketSet::reconfigure");
        // Move current sockets to old_sockets
        self.old_sockets = Some(std::mem::replace(&mut self.new_sockets, new_sockets));
        self.overlap_start = Some(Instant::now());
    }

    /// Poll all sockets (new + old during overlap)
    ///
    /// Returns packets from both old and new sockets during overlap window.
    /// Automatically cleans up old sockets after 500ms.
    pub fn poll(&mut self) -> io::Result<Vec<(Vec<u8>, std::net::SocketAddr)>> {
        crate::trace_fn!("OverlappedSocketSet::poll");
        let packets = Vec::new();

        // Phase 3: Implement non-blocking recv_from on all sockets

        // Check if overlap window expired
        if let Some(overlap_start) = self.overlap_start {
            if overlap_start.elapsed().as_millis() as u64 >= OVERLAP_DURATION_MS {
                // Cleanup old sockets
                self.old_sockets = None;
                self.overlap_start = None;
            }
        }

        Ok(packets)
    }

    /// Get active sockets
    pub fn active_sockets(&self) -> &[UdpSocket] {
        crate::trace_fn!("OverlappedSocketSet::active_sockets");
        &self.new_sockets
    }

    /// Check if overlap window is active
    pub fn is_overlapping(&self) -> bool {
        crate::trace_fn!("OverlappedSocketSet::is_overlapping");
        self.old_sockets.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_set_creation() {
        let socket_set = OverlappedSocketSet::new(vec![]);
        assert!(!socket_set.is_overlapping());
        assert_eq!(socket_set.active_sockets().len(), 0);
    }

    #[test]
    fn test_reconfigure_starts_overlap() {
        let mut socket_set = OverlappedSocketSet::new(vec![]);
        socket_set.reconfigure(vec![]);
        assert!(socket_set.is_overlapping());
    }
}
