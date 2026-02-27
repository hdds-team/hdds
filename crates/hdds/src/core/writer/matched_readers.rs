// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! MatchedReadersRegistry - Thread-safe registry of matched readers for a Writer
//!
//!
//! Provides concurrent access to ReliableWriterProxy instances, allowing:
//! - Control thread: ACKNACK handling, HEARTBEAT scheduling
//! - Data thread: Unicast address lookup for DATA delivery
//!
//! Uses DashMap for lock-free concurrent access.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::proxy::ReliableWriterProxy;

/// Thread-safe registry of ReliableWriterProxy instances for a Writer endpoint
///
/// Shared between control thread (ACKNACK handling) and data thread (DATA sending).
pub struct MatchedReadersRegistry {
    /// Map from reader GUID to proxy state
    proxies: Arc<DashMap<[u8; 16], ReliableWriterProxy>>,
}

impl Default for MatchedReadersRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchedReadersRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            proxies: Arc::new(DashMap::new()),
        }
    }

    /// Add or update a matched reader
    ///
    /// Called when SEDP discovers a new reader or updates an existing one.
    pub fn add_reader(
        &self,
        reader_guid: [u8; 16],
        unicast_addr: SocketAddr,
        lease_duration: Duration,
    ) {
        self.proxies
            .entry(reader_guid)
            .and_modify(|proxy| {
                proxy.set_unicast_addr(unicast_addr);
                proxy.set_lease_duration(lease_duration);
                proxy.touch();
            })
            .or_insert_with(|| ReliableWriterProxy::new(reader_guid, unicast_addr, lease_duration));
    }

    /// Process an ACKNACK from a reader
    ///
    /// # Arguments
    /// - `reader_guid`: 16-byte GUID of the reader
    /// - `acked_seq`: bitmapBase from ACKNACK
    /// - `has_gaps`: true if bitmap has bits set
    ///
    /// # Returns
    /// Sequences needing retransmission (if any)
    pub fn on_acknack(&self, reader_guid: &[u8; 16], acked_seq: i64, has_gaps: bool) -> Vec<i64> {
        if let Some(proxy) = self.proxies.get(reader_guid) {
            proxy.on_acknack(acked_seq, has_gaps)
        } else {
            Vec::new()
        }
    }

    /// Get all unicast addresses for matched readers
    ///
    /// Used for sending DATA to all readers (multicast fallback or unicast fan-out).
    pub fn get_all_addrs(&self) -> Vec<SocketAddr> {
        self.proxies.iter().map(|p| p.unicast_addr()).collect()
    }

    /// Get readers that need a HEARTBEAT
    ///
    /// # Arguments
    /// - `min_interval`: Minimum time between HEARTBEATs
    ///
    /// # Returns
    /// List of (reader_guid, unicast_addr) pairs needing HEARTBEAT
    pub fn get_needing_heartbeat(&self, min_interval: Duration) -> Vec<([u8; 16], SocketAddr)> {
        self.proxies
            .iter()
            .filter(|p| p.needs_heartbeat(min_interval))
            .map(|p| (*p.reader_guid(), p.unicast_addr()))
            .collect()
    }

    /// Get the slowest reader (lowest last_acked_seq)
    ///
    /// Used to determine which samples can be discarded from history.
    ///
    /// # Returns
    /// (reader_guid, last_acked_seq) of the slowest reader, or None if empty
    pub fn slowest_reader(&self) -> Option<([u8; 16], i64)> {
        self.proxies
            .iter()
            .min_by_key(|p| p.last_acked_seq())
            .map(|p| (*p.reader_guid(), p.last_acked_seq()))
    }

    /// Check if all readers are synchronized
    ///
    /// Returns true if all matched readers have acknowledged all sent data.
    pub fn all_synchronized(&self) -> bool {
        !self.proxies.is_empty() && self.proxies.iter().all(|p| p.is_synchronized())
    }

    /// Remove a reader (e.g., when SEDP reports it gone)
    pub fn remove(&self, reader_guid: &[u8; 16]) -> bool {
        self.proxies.remove(reader_guid).is_some()
    }

    /// Cleanup expired proxies
    ///
    /// # Returns
    /// Number of proxies removed
    pub fn cleanup_expired(&self) -> usize {
        let before = self.proxies.len();
        self.proxies.retain(|_, proxy| !proxy.is_expired());
        before - self.proxies.len()
    }

    /// Number of matched readers
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Clear all proxies
    pub fn clear(&self) {
        self.proxies.clear();
    }

    /// Get proxy for a reader (for inspection/debugging)
    pub fn get_proxy(
        &self,
        reader_guid: &[u8; 16],
    ) -> Option<dashmap::mapref::one::Ref<'_, [u8; 16], ReliableWriterProxy>> {
        self.proxies.get(reader_guid)
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
    fn test_add_reader() {
        let registry = MatchedReadersRegistry::new();

        assert!(registry.is_empty());

        registry.add_reader(make_guid(1), make_addr(7400), Duration::from_secs(10));

        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_get_all_addrs() {
        let registry = MatchedReadersRegistry::new();

        registry.add_reader(make_guid(1), make_addr(7400), Duration::from_secs(10));
        registry.add_reader(make_guid(2), make_addr(7401), Duration::from_secs(10));
        registry.add_reader(make_guid(3), make_addr(7402), Duration::from_secs(10));

        let addrs = registry.get_all_addrs();
        assert_eq!(addrs.len(), 3);
    }

    #[test]
    fn test_on_acknack() {
        let registry = MatchedReadersRegistry::new();
        let guid = make_guid(1);

        registry.add_reader(guid, make_addr(7400), Duration::from_secs(10));

        // ACKNACK with bitmapBase=5
        let _ = registry.on_acknack(&guid, 5, false);

        // Check proxy state
        let proxy = registry.get_proxy(&guid).expect("proxy should exist");
        assert_eq!(proxy.last_acked_seq(), 4);
        assert!(proxy.is_synchronized());
    }

    #[test]
    fn test_slowest_reader() {
        let registry = MatchedReadersRegistry::new();

        registry.add_reader(make_guid(1), make_addr(7400), Duration::from_secs(10));
        registry.add_reader(make_guid(2), make_addr(7401), Duration::from_secs(10));
        registry.add_reader(make_guid(3), make_addr(7402), Duration::from_secs(10));

        // Reader 1 acks up to 10, reader 2 up to 5, reader 3 up to 8
        let _ = registry.on_acknack(&make_guid(1), 11, false);
        let _ = registry.on_acknack(&make_guid(2), 6, false);
        let _ = registry.on_acknack(&make_guid(3), 9, false);

        let (slowest_guid, slowest_seq) = registry.slowest_reader().expect("should have readers");
        assert_eq!(slowest_guid[0], 2);
        assert_eq!(slowest_seq, 5);
    }

    #[test]
    fn test_all_synchronized() {
        let registry = MatchedReadersRegistry::new();

        registry.add_reader(make_guid(1), make_addr(7400), Duration::from_secs(10));
        registry.add_reader(make_guid(2), make_addr(7401), Duration::from_secs(10));

        // Initially not synchronized
        assert!(!registry.all_synchronized());

        // Both readers ack without gaps
        let _ = registry.on_acknack(&make_guid(1), 5, false);
        let _ = registry.on_acknack(&make_guid(2), 5, false);

        assert!(registry.all_synchronized());

        // One has gaps
        let _ = registry.on_acknack(&make_guid(1), 5, true);
        assert!(!registry.all_synchronized());
    }

    #[test]
    fn test_remove() {
        let registry = MatchedReadersRegistry::new();
        let guid = make_guid(1);

        registry.add_reader(guid, make_addr(7400), Duration::from_secs(10));
        assert_eq!(registry.len(), 1);

        assert!(registry.remove(&guid));
        assert!(registry.is_empty());

        // Remove non-existent
        assert!(!registry.remove(&guid));
    }

    #[test]
    fn test_cleanup_expired() {
        let registry = MatchedReadersRegistry::new();

        // Add with very short lease
        registry.add_reader(make_guid(1), make_addr(7400), Duration::from_millis(1));
        registry.add_reader(make_guid(2), make_addr(7401), Duration::from_secs(100));

        assert_eq!(registry.len(), 2);

        // Wait for first to expire
        std::thread::sleep(Duration::from_millis(3));

        let removed = registry.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(registry.len(), 1);
    }
}
