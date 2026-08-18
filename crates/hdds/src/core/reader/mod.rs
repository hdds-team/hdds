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

    /// Record a GAP from a remote writer (RTPS v2.5 Sec.8.3.7.4): the
    /// `start..=end` span plus every sequence in `extra_seqs` is irrelevant and
    /// counts as received, so the ACKNACK base can advance past it and it is
    /// never NACKed again.
    pub fn on_gap(&self, writer_guid: [u8; 16], start: i64, end: i64, extra_seqs: &[u64]) {
        let mut proxy = self
            .proxies
            .entry(writer_guid)
            .or_insert_with(|| ReliableReaderProxy::new(writer_guid));

        proxy.on_irrelevant_range(start, end);
        for &seq in extra_seqs {
            if let Ok(seq) = i64::try_from(seq) {
                proxy.on_irrelevant(seq);
            }
        }
    }

    /// `readerSNState` for the next ACKNACK to `writer_guid` (RTPS v2.5
    /// Sec.8.3.7.1): `(base, missing)` where `base` is the first sequence we
    /// have not received — everything below it is acknowledged — and `missing`
    /// lists the still-absent sequences up to the writer's announced `last_seq`.
    ///
    /// Reflects every sample recorded via [`Self::on_data`], so a reader that
    /// consumed 1..N acknowledges with `base = N + 1` and an empty missing-set.
    pub fn acknack_state(
        &self,
        writer_guid: [u8; 16],
        first_seq: i64,
        last_seq: i64,
    ) -> (u64, Vec<u64>) {
        let mut proxy = self
            .proxies
            .entry(writer_guid)
            .or_insert_with(|| ReliableReaderProxy::new(writer_guid));

        proxy.advance_to_first_available(first_seq);
        let base = proxy.acknack_base().max(1) as u64;
        let missing = proxy.missing_up_to(last_seq);
        (base, missing)
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
    fn test_registry_acknack_state_advances_after_consuming_samples() {
        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(7);

        // Nothing received yet: base 1, all three announced samples missing.
        assert_eq!(registry.acknack_state(guid, 1, 3), (1, vec![1, 2, 3]));

        registry.on_data(guid, 1);
        registry.on_data(guid, 2);
        registry.on_data(guid, 3);

        // After consuming 1..3 the ACKNACK must say "expecting 4, nothing missing".
        let (base, missing) = registry.acknack_state(guid, 1, 3);
        assert_eq!(
            base, 4,
            "readerSNState.base must advance past consumed samples"
        );
        assert!(
            missing.is_empty(),
            "missing-set must be empty, got {:?}",
            missing
        );
    }

    /// The whole fix depends on `proxies` being an `Arc<DashMap>` that
    /// `.clone()` shares: the router records receptions on the `TopicRegistry`
    /// copy while the control thread reads its own clone. If a future refactor
    /// makes `clone()` deep, this test fails instead of silently reverting the
    /// ACKNACK fix.
    #[test]
    fn test_cloned_registry_shares_acknack_state() {
        let registry = ReaderProxyRegistry::new();
        let control_thread_view = registry.clone();
        let guid = make_guid(11);

        registry.on_data(guid, 1);
        registry.on_data(guid, 2);

        let (base, missing) = control_thread_view.acknack_state(guid, 1, 2);
        assert_eq!(base, 3, "clone must observe receptions from the original");
        assert!(missing.is_empty());

        // ...and the other direction, since either side may see a sample first.
        control_thread_view.on_data(guid, 3);
        assert_eq!(registry.acknack_state(guid, 1, 3), (4, vec![]));
        assert_eq!(registry.len(), 1, "clones must not fork the proxy map");
    }

    /// GAP retires irrelevant sequence numbers (RTPS v2.5 Sec.8.3.7.4) so a
    /// mid-stream hole cannot stall the ACKNACK base forever.
    #[test]
    fn test_gap_advances_acknack_base_over_irrelevant_samples() {
        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(12);

        registry.on_data(guid, 1);
        registry.on_data(guid, 2);

        // Writer announces 1..4; without the GAP, 3 blocks the base at 3.
        assert_eq!(registry.acknack_state(guid, 1, 4), (3, vec![3, 4]));

        registry.on_gap(guid, 3, 3, &[]);
        registry.on_data(guid, 4);

        let (base, missing) = registry.acknack_state(guid, 1, 4);
        assert_eq!(base, 5, "GAP'd sample must not hold the base back");
        assert!(
            missing.is_empty(),
            "nothing left to NACK, got {:?}",
            missing
        );
    }

    /// A GAP ahead of a real hole must not falsely acknowledge the hole.
    #[test]
    fn test_gap_ahead_of_hole_keeps_base_and_drops_gapped_seq_from_missing() {
        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(13);

        // 1 never arrives; the writer GAPs 2..=3.
        registry.on_gap(guid, 2, 3, &[]);

        let (base, missing) = registry.acknack_state(guid, 1, 4);
        assert_eq!(base, 1, "the real hole at 1 must still be reported");
        assert_eq!(missing, vec![1, 4]);

        registry.on_data(guid, 1);
        assert_eq!(registry.acknack_state(guid, 1, 3), (4, vec![]));
    }

    /// readerSNState base must advance past consumed samples (RTPS 2.5 §8.3.7.1):
    /// after consuming 1..3 the ACKNACK bytes carry `bitmapBase=4`, `numBits=0`.
    #[test]
    fn test_acknack_packet_bytes_advance_past_consumed_samples() {
        use crate::protocol::builder::build_acknack_packet_with_final;

        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(9);
        for seq in 1..=3 {
            registry.on_data(guid, seq);
        }

        let (seq_base, missing) = registry.acknack_state(guid, 1, 3);
        let packet = build_acknack_packet_with_final(
            [1u8; 12],
            [2u8; 12],
            [0x00, 0x00, 0x0d, 0x07],
            [0x00, 0x00, 0x01, 0x02],
            seq_base,
            &missing,
            42,
            missing.is_empty(),
        );

        // 20B RTPS header + 16B INFO_DST + 4B submessage header
        assert_eq!(packet[36], 0x06, "expected ACKNACK submessage");
        assert_eq!(packet[37] & 0x02, 0x02, "Final flag must be set");
        let base_high = i32::from_le_bytes([packet[48], packet[49], packet[50], packet[51]]) as i64;
        let base_low = u32::from_le_bytes([packet[52], packet[53], packet[54], packet[55]]) as i64;
        assert_eq!((base_high << 32) | base_low, 4, "bitmapBase must be 4");
        let num_bits = u32::from_le_bytes([packet[56], packet[57], packet[58], packet[59]]);
        assert_eq!(num_bits, 0, "missing-set must be empty");
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
