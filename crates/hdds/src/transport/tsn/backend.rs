// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TSN backend trait - OS abstraction for TSN operations.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use super::config::TsnConfig;
use super::probe::TsnCapabilities;

/// OS abstraction for TSN operations.
///
/// Implemented by:
/// - `LinuxTsnBackend`: Full support on Linux (SO_PRIORITY, SO_TXTIME)
/// - `NullTsnBackend`: Stub for unsupported platforms
pub trait TsnBackend: Send + Sync {
    /// Apply socket options (SO_PRIORITY, SO_TXTIME).
    ///
    /// Called when creating/configuring a socket for TSN traffic.
    fn apply_socket_opts(&self, sock: &UdpSocket, cfg: &TsnConfig) -> io::Result<()>;

    /// Send with optional txtime (SCM_TXTIME via sendmsg).
    ///
    /// If `txtime` is None, falls back to regular send.
    /// If `txtime` is Some(ns), uses SCM_TXTIME ancillary data.
    fn send_with_txtime(
        &self,
        sock: &UdpSocket,
        buf: &[u8],
        addr: SocketAddr,
        txtime: Option<u64>,
        cfg: &TsnConfig,
    ) -> io::Result<usize>;

    /// Probe the TSN capabilities of an interface.
    ///
    /// Detects: SO_TXTIME support, qdisc (ETF/TAPRIO/mqprio), HW timestamping.
    fn probe(&self, iface: &str) -> io::Result<TsnCapabilities>;

    /// Drain the error queue (drops ETF).
    ///
    /// Returns statistics about late/dropped packets from ETF qdisc.
    fn drain_error_queue(&self, sock: &UdpSocket) -> TsnErrorStats;

    /// Check if SO_TXTIME is supported on this backend.
    fn supports_txtime(&self) -> bool;

    /// Get the current time from the specified clock.
    fn clock_gettime(&self, cfg: &TsnConfig) -> io::Result<u64>;
}

/// Statistics from draining the error queue.
#[derive(Clone, Debug, Default)]
pub struct TsnErrorStats {
    /// Packets dropped because they were late (missed ETF deadline).
    pub dropped_late: u64,
    /// Packets dropped for other reasons.
    pub dropped_other: u64,
}

impl TsnErrorStats {
    /// Create empty stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total dropped packets.
    pub fn total_dropped(&self) -> u64 {
        self.dropped_late + self.dropped_other
    }

    /// Merge with another stats instance.
    pub fn merge(&mut self, other: &TsnErrorStats) {
        self.dropped_late += other.dropped_late;
        self.dropped_other += other.dropped_other;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_stats_default() {
        let stats = TsnErrorStats::default();
        assert_eq!(stats.dropped_late, 0);
        assert_eq!(stats.dropped_other, 0);
        assert_eq!(stats.total_dropped(), 0);
    }

    #[test]
    fn test_error_stats_merge() {
        let mut stats1 = TsnErrorStats {
            dropped_late: 5,
            dropped_other: 2,
        };
        let stats2 = TsnErrorStats {
            dropped_late: 3,
            dropped_other: 1,
        };

        stats1.merge(&stats2);
        assert_eq!(stats1.dropped_late, 8);
        assert_eq!(stats1.dropped_other, 3);
        assert_eq!(stats1.total_dropped(), 11);
    }
}
