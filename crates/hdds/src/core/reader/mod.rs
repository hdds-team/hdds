// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reliable Reader State Machine -- RTPS Sec.8.4.9
//!
//! This module provides state tracking for reliable data reception.
//! It implements the WriterProxy concept from RTPS, allowing a Reader
//! to correctly respond to HEARTBEATs with proper ACKNACK messages.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |  ReaderProxyRegistry (thread-safe, shared)                 |
//! |  +---------------------------------------------------------+|
//! |  |  DashMap<WriterGUID, ReliableReaderProxy>              ||
//! |  +---------------------------------------------------------+|
//! |                                                             |
//! |  Used by:                                                   |
//! |  - Control thread: on_heartbeat() -> AcknackDecision        |
//! |  - Listener thread: on_data() -> update sequence tracking   |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Thread Safety
//!
//! Uses DashMap for lock-free concurrent access from multiple threads.

mod proxy;

pub use proxy::{AcknackDecision, ReliableReaderProxy};

use dashmap::DashMap;
use std::sync::Arc;

/// Thread-safe registry of ReliableReaderProxy instances
///
/// Shared between control thread (HEARTBEAT handling) and listener
/// thread (DATA reception tracking).
#[derive(Debug, Clone)]
pub struct ReaderProxyRegistry {
    /// Map from writer GUID to proxy state
    proxies: Arc<DashMap<[u8; 16], ReliableReaderProxy>>,
}

impl Default for ReaderProxyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ReaderProxyRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            proxies: Arc::new(DashMap::new()),
        }
    }

    /// Process a HEARTBEAT from a remote writer
    ///
    /// Creates proxy if not exists, then delegates to proxy.on_heartbeat().
    ///
    /// # Arguments
    /// - `writer_guid`: 16-byte GUID (guid_prefix + entity_id)
    /// - `first_seq`: firstAvailableSeqNumber from HEARTBEAT
    /// - `last_seq`: lastSeqNumber from HEARTBEAT
    /// - `count`: HEARTBEAT count
    /// - `final_flag`: FinalFlag from HEARTBEAT
    ///
    /// # Returns
    /// Decision on whether/how to send ACKNACK
    pub fn on_heartbeat(
        &self,
        writer_guid: [u8; 16],
        first_seq: i64,
        last_seq: i64,
        count: u32,
        final_flag: bool,
    ) -> AcknackDecision {
        let mut proxy = self
            .proxies
            .entry(writer_guid)
            .or_insert_with(|| ReliableReaderProxy::new(writer_guid));

        proxy.on_heartbeat(first_seq, last_seq, count, final_flag)
    }

    /// Record that DATA was received from a remote writer
    ///
    /// Creates proxy if not exists, then updates highest_received_seq.
    ///
    /// # Arguments
    /// - `writer_guid`: 16-byte GUID (guid_prefix + entity_id)
    /// - `seq`: Sequence number from DATA submessage
    pub fn on_data(&self, writer_guid: [u8; 16], seq: i64) {
        let mut proxy = self
            .proxies
            .entry(writer_guid)
            .or_insert_with(|| ReliableReaderProxy::new(writer_guid));

        proxy.on_data(seq);
    }

    /// Mark that ACKNACK was sent for a writer (for rate limiting)
    pub fn mark_acknack_sent(&self, writer_guid: &[u8; 16]) {
        if let Some(mut proxy) = self.proxies.get_mut(writer_guid) {
            proxy.mark_acknack_sent();
        }
    }

    /// Get proxy for a writer (for inspection/debugging)
    pub fn get_proxy(&self, writer_guid: &[u8; 16]) -> Option<ReliableReaderProxy> {
        self.proxies.get(writer_guid).map(|p| p.clone())
    }

    /// Number of tracked writers
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Remove a proxy (e.g., when peer disconnects)
    pub fn remove(&self, writer_guid: &[u8; 16]) -> Option<ReliableReaderProxy> {
        self.proxies.remove(writer_guid).map(|(_, p)| p)
    }

    /// Clear all proxies
    pub fn clear(&self) {
        self.proxies.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_guid(id: u8) -> [u8; 16] {
        let mut guid = [0u8; 16];
        guid[0] = id;
        guid
    }

    #[test]
    fn test_registry_creates_proxy_on_heartbeat() {
        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(1);

        assert!(registry.is_empty());

        let decision = registry.on_heartbeat(guid, 1, 1, 1, false);

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(matches!(
            decision,
            AcknackDecision::NeedData { bitmap_base: 1 }
        ));
    }

    #[test]
    fn test_registry_data_updates_state() {
        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(1);

        // First: HEARTBEAT creates proxy
        let _ = registry.on_heartbeat(guid, 1, 1, 1, false);

        // Receive DATA
        registry.on_data(guid, 1);

        // Next HEARTBEAT should show synchronized
        let decision = registry.on_heartbeat(guid, 1, 1, 2, false);
        assert!(matches!(
            decision,
            AcknackDecision::Synchronized { bitmap_base: 2 }
        ));
    }

    #[test]
    fn test_registry_multiple_writers() {
        let registry = ReaderProxyRegistry::new();
        let guid1 = make_guid(1);
        let guid2 = make_guid(2);

        registry.on_heartbeat(guid1, 1, 1, 1, false);
        registry.on_heartbeat(guid2, 1, 5, 1, false);

        assert_eq!(registry.len(), 2);

        // Update only guid1
        registry.on_data(guid1, 1);

        // guid1 synchronized, guid2 still needs data
        let d1 = registry.on_heartbeat(guid1, 1, 1, 2, false);
        let d2 = registry.on_heartbeat(guid2, 1, 5, 2, false);

        assert!(matches!(d1, AcknackDecision::Synchronized { .. }));
        assert!(matches!(d2, AcknackDecision::NeedData { bitmap_base: 1 }));
    }

    #[test]
    fn test_registry_remove() {
        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(1);

        registry.on_heartbeat(guid, 1, 1, 1, false);
        assert_eq!(registry.len(), 1);

        registry.remove(&guid);
        assert!(registry.is_empty());
    }
}
