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
//! - a low mark: highest seq at or below which everything is received or irrelevant
//! - Missing changes set for gap detection
//! - HEARTBEAT response timing
//!
//! We implement a simplified version suitable for SEDP (1-2 samples).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Minimum interval between ACKNACK responses (like FastDDS heartbeat_response_delay)
const ACKNACK_RATE_LIMIT_MS: u64 = 10;

/// Upper bound on the out-of-order ("received ahead of the low mark") set.
/// Past this we drop the set, which can only cause a redundant NACK — the
/// writer retransmits and the reader dedups — never a lost sample.
const MAX_RECEIVED_AHEAD: usize = 4096;

/// Maximum span a single ACKNACK bitmap can cover (RTPS v2.5 Sec.8.3.5.5).
const MAX_BITMAP_BITS: i64 = 256;

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

    /// Low mark: the highest SN below which everything is received or irrelevant
    /// (RTPS 2.5 §8.3.7.1/§8.3.7.4); `readerSNState.base` is `low_mark + 1`.
    highest_received_seq: i64,

    /// Sequences received *above* the low mark (i.e. arrived out of order).
    /// They are excluded from the ACKNACK missing-set so we never re-request
    /// a sample we already hold.
    received_ahead: BTreeSet<i64>,

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
            received_ahead: BTreeSet::new(),
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

    /// Get the highest contiguously received sequence number (low mark)
    pub fn highest_received_seq(&self) -> i64 {
        self.highest_received_seq
    }

    /// `readerSNState.base` for the next ACKNACK: the first sequence number we
    /// have NOT received (RTPS v2.5 Sec.8.3.7.1 — everything below is acked).
    pub fn acknack_base(&self) -> i64 {
        self.highest_received_seq + 1
    }

    /// Sequences the writer announced (up to `last_seq`) that we still miss.
    /// Empty once every announced sample has been received, which is what makes
    /// the writer's `wait_for_acknowledgments()` complete.
    pub fn missing_up_to(&self, last_seq: i64) -> Vec<u64> {
        let base = self.acknack_base();
        if last_seq < base {
            return Vec::new();
        }
        // The cap is on the bitmap *span* (base..base+256), not on the number of
        // reported sequences (RTPS v2.5 Sec.8.3.5.5).
        (base..=last_seq)
            .take_while(|seq| *seq < base + MAX_BITMAP_BITS)
            .filter(|seq| !self.received_ahead.contains(seq))
            .filter_map(|seq| u64::try_from(seq).ok())
            .collect()
    }

    /// Samples below the writer's announced `firstSN` are no longer available
    /// (RTPS v2.5 Sec.8.3.7.5), so treat them as irrelevant and move the low
    /// mark up instead of NACKing them forever.
    pub fn advance_to_first_available(&mut self, first_seq: i64) {
        if first_seq - 1 > self.highest_received_seq {
            self.highest_received_seq = first_seq - 1;
            self.drain_received_ahead();
        }
    }

    /// Fold any already-received sequences that are now contiguous into the
    /// low mark.
    fn drain_received_ahead(&mut self) {
        self.received_ahead
            .retain(|&seq| seq > self.highest_received_seq);
        while self.received_ahead.remove(&(self.highest_received_seq + 1)) {
            self.highest_received_seq += 1;
        }
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

        // Samples below the writer's firstSN can never arrive; skip them so the
        // ACKNACK base can advance (RTPS v2.5 Sec.8.3.7.5).
        self.advance_to_first_available(first_seq);

        // Calculate bitmapBase: next sequence we want
        // If we've received seq 1, we want seq 2 -> bitmapBase = 2
        let bitmap_base = self.acknack_base();

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

    /// Record that we received a DATA with given sequence number.
    ///
    /// Advances the contiguous low mark (and folds in any out-of-order samples
    /// that became contiguous); an out-of-order arrival is remembered so it is
    /// not re-requested, but does NOT move the low mark past the hole.
    pub fn on_data(&mut self, seq: i64) {
        if seq <= self.highest_received_seq {
            return; // duplicate or already acknowledged
        }

        if seq == self.highest_received_seq + 1 {
            self.highest_received_seq = seq;
            self.drain_received_ahead();
        } else {
            if self.received_ahead.len() >= MAX_RECEIVED_AHEAD {
                // Bounded state: forgetting these only costs a redundant NACK.
                self.received_ahead.clear();
            }
            self.received_ahead.insert(seq);
        }

        log::debug!(
            "[PROXY] Received DATA seq={}, low_mark={} ahead={}",
            seq,
            self.highest_received_seq,
            self.received_ahead.len()
        );
    }

    /// Record a sequence the writer declared irrelevant via GAP (RTPS v2.5
    /// Sec.8.3.7.4). It will never arrive, so for ACKNACK purposes it counts as
    /// received: the low mark may move past it and it must not be NACKed.
    pub fn on_irrelevant(&mut self, seq: i64) {
        self.on_data(seq);
    }

    /// Same for a contiguous irrelevant range `start..=end` (a GAP's
    /// `gapStart..gapList.base - 1` span).
    pub fn on_irrelevant_range(&mut self, start: i64, end: i64) {
        if end < start || end <= self.highest_received_seq {
            return;
        }

        // A malformed/hostile GAP (gapListBase near i64::MAX) would otherwise park
        // the low mark at the end of sequence space in one step. Clamp the advance
        // to MAX_RECEIVED_AHEAD per GAP instead of rejecting it outright: rejecting
        // livelocks against a writer that legitimately sends an oversized GAP (it
        // keeps resending the same GAP, we keep NACKing), whereas clamping still
        // makes bounded forward progress and converges over successive GAPs.
        let end = end.min(
            self.highest_received_seq
                .saturating_add(MAX_RECEIVED_AHEAD as i64),
        );

        if start <= self.highest_received_seq + 1 {
            // The range covers the next sequence we were waiting for: the low
            // mark can jump to its end in one step, no per-sequence bookkeeping.
            self.highest_received_seq = end;
            self.drain_received_ahead();
            return;
        }

        // There is still a real hole below the range; remember the irrelevant
        // sequences individually (bounded) so they are not NACKed.
        for seq in start..=end {
            if self.received_ahead.len() >= MAX_RECEIVED_AHEAD {
                break;
            }
            self.received_ahead.insert(seq);
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
    fn test_acknack_base_advances_past_consumed_samples() {
        let mut proxy = ReliableReaderProxy::new([0u8; 16]);

        proxy.on_data(1);
        proxy.on_data(2);
        proxy.on_data(3);

        assert_eq!(proxy.acknack_base(), 4);
        assert!(proxy.missing_up_to(3).is_empty());

        // Writer announces exactly what we have -> Final ACKNACK with base 4.
        let decision = proxy.on_heartbeat(1, 3, 1, true);
        assert!(matches!(
            decision,
            AcknackDecision::Synchronized { bitmap_base: 4 }
        ));
    }

    #[test]
    fn test_acknack_out_of_order_arrival_keeps_hole() {
        let mut proxy = ReliableReaderProxy::new([0u8; 16]);

        // seq 2 arrives before seq 1: base must stay at 1 and only 1 is missing.
        proxy.on_data(2);
        assert_eq!(proxy.acknack_base(), 1);
        assert_eq!(proxy.missing_up_to(2), vec![1]);

        // Hole filled -> low mark folds both samples in.
        proxy.on_data(1);
        assert_eq!(proxy.acknack_base(), 3);
        assert!(proxy.missing_up_to(2).is_empty());
    }

    #[test]
    fn test_acknack_base_follows_writer_first_available() {
        let mut proxy = ReliableReaderProxy::new([0u8; 16]);

        // Writer's history starts at 5 (earlier samples gone): nothing below 5
        // may be NACKed, and receiving 5..6 must fully acknowledge.
        let decision = proxy.on_heartbeat(5, 6, 1, false);
        assert!(matches!(
            decision,
            AcknackDecision::NeedData { bitmap_base: 5 }
        ));
        assert_eq!(proxy.missing_up_to(6), vec![5, 6]);

        proxy.on_data(5);
        proxy.on_data(6);
        assert_eq!(proxy.acknack_base(), 7);
        assert!(proxy.missing_up_to(6).is_empty());
    }

    #[test]
    fn test_duplicate_data_does_not_advance_base() {
        let mut proxy = ReliableReaderProxy::new([0u8; 16]);

        proxy.on_data(1);
        proxy.on_data(1);
        assert_eq!(proxy.acknack_base(), 2);
    }

    #[test]
    fn test_oversized_gap_clamps_advance() {
        let mut proxy = ReliableReaderProxy::new([0u8; 16]);
        proxy.on_data(1);
        let low_mark_before = proxy.highest_received_seq();

        // Hostile GAP claiming everything up to i64::MAX is irrelevant: accepting
        // it verbatim would jump the low mark to i64::MAX (saturating add avoids
        // overflow) and positively ack the whole sequence space. Instead the
        // advance is clamped to MAX_RECEIVED_AHEAD, making bounded progress.
        proxy.on_irrelevant_range(2, i64::MAX);
        assert_eq!(
            proxy.acknack_base(),
            low_mark_before + MAX_RECEIVED_AHEAD as i64 + 1,
            "oversized GAP must clamp to MAX_RECEIVED_AHEAD advance, not be ignored"
        );
    }

    #[test]
    fn test_sane_gap_span_applied() {
        let mut proxy = ReliableReaderProxy::new([0u8; 16]);
        proxy.on_data(1);

        // A sane span is applied in full.
        proxy.on_irrelevant_range(2, 5);
        assert_eq!(proxy.acknack_base(), 6);
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
