// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ReliableWriterProxy - Per-reader state for Reliable Writer
//!
//! Implements RTPS Sec.8.4.7 StatefulWriter behavior:
//! - Tracks highest sequence number acknowledged by each reader
//! - Detects which readers need retransmission (NACK repair)
//! - Manages HEARTBEAT timing per reader
//! - Manages proxy lifecycle (expiry based on lease_duration)
//!
//! # RTPS Compliance
//!
//! Per RTPS v2.5 Sec.8.4.7, a StatefulWriter maintains per-reader state:
//! - `highest_sent_seq_num_`: last sequence sent to this reader
//! - `highest_acked_seq_num_`: highest contiguous seq acknowledged
//! - ACKNACK response handling for gap detection

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, Instant};

/// RTPS Writer state per matched remote reader (RTPS Sec.8.4.7 ReaderProxy)
///
/// Tracks acknowledgment state from a remote Reader to determine:
/// - Which samples need retransmission (NACK repair)
/// - When to send HEARTBEATs
/// - Whether the reader is synchronized
pub struct ReliableWriterProxy {
    /// Remote reader GUID (16 bytes = guid_prefix + entity_id)
    reader_guid: [u8; 16],

    /// Unicast address for sending DATA/HEARTBEAT to this reader
    unicast_addr: SocketAddr,

    /// Highest sequence number acknowledged by this reader
    /// Updated from ACKNACK bitmapBase
    last_acked_seq: AtomicI64,

    /// Last time we sent a HEARTBEAT to this reader
    last_heartbeat_time: Instant,

    /// Whether this reader is synchronized (has all data)
    /// Set when ACKNACK has Final=1 and empty bitmap
    is_synchronized: AtomicBool,

    /// Lease duration from SPDP/SEDP (for expiry)
    lease_duration: Duration,

    /// Last activity time (for expiry check)
    last_seen: Instant,
}

impl ReliableWriterProxy {
    /// Create a new proxy for a matched remote reader
    pub fn new(reader_guid: [u8; 16], unicast_addr: SocketAddr, lease_duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            reader_guid,
            unicast_addr,
            last_acked_seq: AtomicI64::new(0),
            last_heartbeat_time: now,
            is_synchronized: AtomicBool::new(false),
            lease_duration,
            last_seen: now,
        }
    }

    /// Process an incoming ACKNACK from this reader
    ///
    /// # Arguments
    /// - `acked_seq`: bitmapBase from ACKNACK (next seq reader wants)
    /// - `has_gaps`: true if bitmap has bits set (reader missing samples)
    ///
    /// # Returns
    /// List of sequence numbers that need retransmission (if any)
    pub fn on_acknack(&self, acked_seq: i64, has_gaps: bool) -> Vec<i64> {
        // Update last seen time
        // Note: We can't update last_seen directly as it's not atomic
        // This is a limitation - consider using AtomicU64 for timestamp

        // Update acknowledged sequence
        let prev_acked = self
            .last_acked_seq
            .fetch_max(acked_seq - 1, Ordering::SeqCst);

        // Update synchronized state
        if !has_gaps && acked_seq > prev_acked {
            self.is_synchronized.store(true, Ordering::SeqCst);
        } else if has_gaps {
            self.is_synchronized.store(false, Ordering::SeqCst);
        }

        // Return sequences that need repair (simplified - just return empty for now)
        // Full implementation would track sent samples and return those in bitmap
        Vec::new()
    }

    /// Check if we should send a HEARTBEAT to this reader
    ///
    /// # Arguments
    /// - `min_interval`: Minimum time between HEARTBEATs
    pub fn needs_heartbeat(&self, min_interval: Duration) -> bool {
        self.last_heartbeat_time.elapsed() >= min_interval
    }

    /// Mark that we sent a HEARTBEAT to this reader
    pub fn heartbeat_sent(&mut self) {
        self.last_heartbeat_time = Instant::now();
        self.last_seen = Instant::now();
    }

    /// Check if proxy expired (peer gone)
    pub fn is_expired(&self) -> bool {
        self.last_seen.elapsed() > self.lease_duration.mul_f32(1.5)
    }

    /// Check if reader is synchronized (has all data we sent)
    pub fn is_synchronized(&self) -> bool {
        self.is_synchronized.load(Ordering::SeqCst)
    }

    /// Get the reader GUID
    pub fn reader_guid(&self) -> &[u8; 16] {
        &self.reader_guid
    }

    /// Get unicast address for this reader
    pub fn unicast_addr(&self) -> SocketAddr {
        self.unicast_addr
    }

    /// Get last acknowledged sequence number
    pub fn last_acked_seq(&self) -> i64 {
        self.last_acked_seq.load(Ordering::SeqCst)
    }

    /// Get lease duration
    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    /// Update unicast address (e.g., from SEDP update)
    pub fn set_unicast_addr(&mut self, addr: SocketAddr) {
        self.unicast_addr = addr;
    }

    /// Update lease duration (e.g., from SEDP update)
    pub fn set_lease_duration(&mut self, duration: Duration) {
        self.lease_duration = duration;
    }

    /// Touch the proxy (update last_seen without other changes)
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_guid(id: u8) -> [u8; 16] {
        let mut guid = [0u8; 16];
        guid[0] = id;
        guid
    }

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    #[test]
    fn test_new_proxy() {
        let proxy =
            ReliableWriterProxy::new(make_guid(1), make_addr(7400), Duration::from_secs(10));

        assert_eq!(proxy.last_acked_seq(), 0);
        assert!(!proxy.is_synchronized());
        assert!(!proxy.is_expired());
    }

    #[test]
    fn test_on_acknack_updates_state() {
        let proxy =
            ReliableWriterProxy::new(make_guid(1), make_addr(7400), Duration::from_secs(10));

        // ACKNACK with bitmapBase=5 means reader wants seq 5, has 1-4
        let _ = proxy.on_acknack(5, false);

        assert_eq!(proxy.last_acked_seq(), 4);
        assert!(proxy.is_synchronized());
    }

    #[test]
    fn test_on_acknack_with_gaps() {
        let proxy =
            ReliableWriterProxy::new(make_guid(1), make_addr(7400), Duration::from_secs(10));

        // First: synchronized
        let _ = proxy.on_acknack(5, false);
        assert!(proxy.is_synchronized());

        // Then: has gaps
        let _ = proxy.on_acknack(5, true);
        assert!(!proxy.is_synchronized());
    }

    #[test]
    fn test_needs_heartbeat() {
        let mut proxy =
            ReliableWriterProxy::new(make_guid(1), make_addr(7400), Duration::from_secs(10));

        // Just created - needs heartbeat after interval
        assert!(!proxy.needs_heartbeat(Duration::from_secs(1)));

        // After sending heartbeat
        proxy.heartbeat_sent();
        assert!(!proxy.needs_heartbeat(Duration::from_millis(10)));
    }

    #[test]
    fn test_expiry() {
        let proxy =
            ReliableWriterProxy::new(make_guid(1), make_addr(7400), Duration::from_millis(1));

        assert!(!proxy.is_expired());

        // Sleep past expiry (1ms * 1.5 = 1.5ms)
        std::thread::sleep(Duration::from_millis(3));

        assert!(proxy.is_expired());
    }
}
