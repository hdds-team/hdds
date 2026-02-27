// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reliable Reader Proxy -- RTPS Sec.8.4.9 State Machine
//!
//! Tracks per-writer state for reliable data reception. This implements the
//! "WriterProxy" concept from RTPS spec, used by a Reader to track each
//! remote Writer's sequence numbers.
//!
//! # Problem Solved
//!
//! Without this state, HDDS sends incorrect ACKNACK responses:
//! - bitmapBase always 1 (should be highest_received + 1)
//! - Final flag always 0 (should be 1 when synchronized)
//!
//! This causes infinite HEARTBEAT->ACKNACK loops (66k messages vs 4).
//!
//! # RTPS Compliance
//!
//! Per RTPS v2.5 Sec.8.4.9, a StatefulReader maintains:
//! - `changes_from_writer_low_mark_`: highest contiguous seq received
//! - Missing changes set for gap detection
//! - HEARTBEAT response timing
//!
//! We implement a simplified version suitable for SEDP (1-2 samples).

use std::time::{Duration, Instant};

/// Minimum interval between ACKNACK responses (like FastDDS heartbeat_response_delay)
const ACKNACK_RATE_LIMIT_MS: u64 = 10;

/// Decision after processing a HEARTBEAT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcknackDecision {
    /// Ignore duplicate HEARTBEAT (same or lower count)
    Ignore,

    /// We have all announced data, send ACKNACK with Final=1
    /// bitmapBase = highest_received + 1 (requesting next seq)
    Synchronized { bitmap_base: i64 },

    /// Missing data, send ACKNACK with Final=0
    /// bitmapBase = highest_received + 1 (requesting from there)
    NeedData { bitmap_base: i64 },

    /// Rate-limited, don't send ACKNACK yet
    RateLimited,
}

/// Per-writer state for reliable Reader (RTPS Sec.8.4.9 WriterProxy)
///
/// Tracks sequence numbers received from a remote Writer to generate
/// correct ACKNACK responses with proper bitmapBase and Final flag.
#[derive(Debug, Clone)]
pub struct ReliableReaderProxy {
    /// Remote writer GUID (guid_prefix + entity_id)
    writer_guid: [u8; 16],

    /// Highest sequence number we have received (contiguous from 1)
    /// Equivalent to FastDDS `changes_from_writer_low_mark_`
    highest_received_seq: i64,

    /// Maximum sequence number announced by writer (from last HEARTBEAT)
    /// Equivalent to FastDDS `max_sequence_number_`
    expected_max_seq: i64,

    /// Last HEARTBEAT count seen (for duplicate detection)
    last_hb_count: u32,

    /// Last time we sent an ACKNACK (for rate limiting)
    last_acknack_time: Option<Instant>,

    /// Rate limit duration
    rate_limit: Duration,
}

impl ReliableReaderProxy {
    /// Create a new proxy for tracking a remote writer
    pub fn new(writer_guid: [u8; 16]) -> Self {
        Self {
            writer_guid,
            highest_received_seq: 0, // Nothing received yet
            expected_max_seq: 0,
            last_hb_count: 0,
            last_acknack_time: None,
            rate_limit: Duration::from_millis(ACKNACK_RATE_LIMIT_MS),
        }
    }

    /// Get the writer GUID this proxy tracks
    pub fn writer_guid(&self) -> &[u8; 16] {
        &self.writer_guid
    }

    /// Get the highest sequence number received
    pub fn highest_received_seq(&self) -> i64 {
        self.highest_received_seq
    }

    /// Process an incoming HEARTBEAT and decide ACKNACK response
    ///
    /// # Arguments
    /// - `first_seq`: firstAvailableSeqNumber from HEARTBEAT
    /// - `last_seq`: lastSeqNumber from HEARTBEAT
    /// - `count`: HEARTBEAT count (for duplicate detection)
    /// - `_final_flag`: FinalFlag from HEARTBEAT (currently unused)
    ///
    /// # Returns
    /// Decision on whether/how to send ACKNACK
    pub fn on_heartbeat(
        &mut self,
        first_seq: i64,
        last_seq: i64,
        count: u32,
        _final_flag: bool,
    ) -> AcknackDecision {
        // Duplicate detection: ignore if same or lower count
        if count <= self.last_hb_count && self.last_hb_count > 0 {
            log::trace!(
                "[PROXY] Ignoring duplicate HEARTBEAT count={} (last={})",
                count,
                self.last_hb_count
            );
            return AcknackDecision::Ignore;
        }

        // Update state from HEARTBEAT
        self.last_hb_count = count;
        self.expected_max_seq = last_seq;

        // If writer has no data (lastSeq < firstSeq or lastSeq = 0), nothing to request
        if last_seq < first_seq || last_seq == 0 {
            log::trace!(
                "[PROXY] Writer has no data (first={}, last={})",
                first_seq,
                last_seq
            );
            // Still synchronized (nothing to get)
            return AcknackDecision::Synchronized {
                bitmap_base: first_seq.max(1),
            };
        }

        // Rate limiting check
        if let Some(last_time) = self.last_acknack_time {
            if last_time.elapsed() < self.rate_limit {
                log::trace!(
                    "[PROXY] Rate limited, elapsed={:?} < {:?}",
                    last_time.elapsed(),
                    self.rate_limit
                );
                return AcknackDecision::RateLimited;
            }
        }

        // Calculate bitmapBase: next sequence we want
        // If we've received seq 1, we want seq 2 -> bitmapBase = 2
        let bitmap_base = (self.highest_received_seq + 1).max(first_seq);

        // Check if synchronized (we have everything writer announced)
        if self.highest_received_seq >= last_seq {
            log::debug!(
                "[PROXY] Synchronized: received={} >= expected={}, bitmapBase={}",
                self.highest_received_seq,
                last_seq,
                bitmap_base
            );
            AcknackDecision::Synchronized { bitmap_base }
        } else {
            log::debug!(
                "[PROXY] NeedData: received={} < expected={}, bitmapBase={}",
                self.highest_received_seq,
                last_seq,
                bitmap_base
            );
            AcknackDecision::NeedData { bitmap_base }
        }
    }

    /// Record that we received a DATA with given sequence number
    ///
    /// Updates `highest_received_seq` to track progress.
    pub fn on_data(&mut self, seq: i64) {
        if seq > self.highest_received_seq {
            log::debug!(
                "[PROXY] Received DATA seq={}, updating highest from {} to {}",
                seq,
                self.highest_received_seq,
                seq
            );
            self.highest_received_seq = seq;
        }
    }

    /// Record that we sent an ACKNACK (for rate limiting)
    pub fn mark_acknack_sent(&mut self) {
        self.last_acknack_time = Some(Instant::now());
    }

    /// Check if we are synchronized with the writer
    pub fn is_synchronized(&self) -> bool {
        self.highest_received_seq >= self.expected_max_seq && self.expected_max_seq > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_proxy_needs_data() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // First HEARTBEAT: writer has seq 1
        let decision = proxy.on_heartbeat(1, 1, 1, false);

        // We have nothing, need data starting at seq 1
        assert!(matches!(
            decision,
            AcknackDecision::NeedData { bitmap_base: 1 }
        ));
    }

    #[test]
    fn test_synchronized_after_data() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // Receive DATA seq 1
        proxy.on_data(1);

        // HEARTBEAT says writer has seq 1
        let decision = proxy.on_heartbeat(1, 1, 1, false);

        // We have seq 1, synchronized, bitmapBase = 2 (next expected)
        assert!(matches!(
            decision,
            AcknackDecision::Synchronized { bitmap_base: 2 }
        ));
        assert!(proxy.is_synchronized());
    }

    #[test]
    fn test_duplicate_heartbeat_ignored() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // First HEARTBEAT
        let _ = proxy.on_heartbeat(1, 1, 1, false);
        proxy.mark_acknack_sent();

        // Same count -> ignore
        let decision = proxy.on_heartbeat(1, 1, 1, false);
        assert!(matches!(decision, AcknackDecision::Ignore));
    }

    #[test]
    fn test_empty_writer() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // Writer has no data (lastSeq = 0)
        let decision = proxy.on_heartbeat(1, 0, 1, false);

        // Synchronized (nothing to get)
        assert!(matches!(decision, AcknackDecision::Synchronized { .. }));
    }

    #[test]
    fn test_bitmap_base_advances() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // Receive DATA seq 1, 2, 3
        proxy.on_data(1);
        proxy.on_data(2);
        proxy.on_data(3);

        // HEARTBEAT says writer has up to seq 5
        let decision = proxy.on_heartbeat(1, 5, 1, false);

        // bitmapBase should be 4 (next after highest received)
        assert!(matches!(
            decision,
            AcknackDecision::NeedData { bitmap_base: 4 }
        ));
    }
}
