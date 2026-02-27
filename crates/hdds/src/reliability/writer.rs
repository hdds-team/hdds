// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Writer-side reliability protocol handlers
//!
//! Consolidates all TX (transmit) logic for Reliable QoS:
//! - HeartbeatTx: Periodic heartbeat transmission with jitter
//! - GapTx: GAP message generation for lost sequences
//! - InfoTsTx: Timestamp injection for DATA submessages
//! - InfoDstTx: Destination GUID prefix for targeted delivery
//! - WriterRetransmitHandler: NACK processing and retransmission

use std::convert::TryFrom;
use std::time::{Duration, Instant};

use super::messages::{
    EntityId, GapMsg, GuidPrefix, HeartbeatMsg, InfoDstMsg, InfoTsMsg, NackMsg, SequenceNumberSet,
    ENTITYID_UNKNOWN_READER, ENTITYID_UNKNOWN_WRITER, GUID_PREFIX_LEN,
};
use super::{HistoryCache, ReliableMetrics, RtpsRange};

// ============================================================================
// HEARTBEAT TX
// ============================================================================

/// Default heartbeat period (milliseconds).
pub const DEFAULT_PERIOD_MS: u32 = 100;
/// Default jitter percentage (0-100).
pub const DEFAULT_JITTER_PCT: u8 = 10;

/// Heartbeat transmitter (writer-side).
#[derive(Debug)]
pub struct HeartbeatTx {
    next_deadline: Instant,
    period: Duration,
    jitter_pct: u8,
    count: u32,
}

impl HeartbeatTx {
    /// Create a transmitter with the default period (100 ms +/- 10%).
    #[must_use]
    pub fn new() -> Self {
        Self::with_period_ms(DEFAULT_PERIOD_MS, DEFAULT_JITTER_PCT)
    }

    /// Create a transmitter with custom period and jitter.
    #[must_use]
    pub fn with_period_ms(period_ms: u32, jitter_pct: u8) -> Self {
        let period = Duration::from_millis(period_ms as u64);
        let next_deadline = Instant::now() + Self::apply_jitter(period, jitter_pct);

        Self {
            next_deadline,
            period,
            jitter_pct,
            count: 0,
        }
    }

    /// Next time the heartbeat should be sent.
    #[must_use]
    pub fn next_deadline(&self) -> Instant {
        self.next_deadline
    }

    /// Build a heartbeat message and schedule the next send deadline.
    pub fn build_heartbeat(&mut self, first_seq: u64, last_seq: u64) -> HeartbeatMsg {
        let hb = HeartbeatMsg::new(first_seq, last_seq, self.count);
        self.count = self.count.wrapping_add(1);
        self.next_deadline = Instant::now() + Self::apply_jitter(self.period, self.jitter_pct);
        hb
    }

    /// Monotonic heartbeat counter.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count
    }

    fn apply_jitter(period: Duration, jitter_pct: u8) -> Duration {
        if jitter_pct == 0 {
            return period;
        }

        let now_ns = Instant::now().elapsed().as_nanos();
        let jitter_seed = u32::try_from(now_ns % 200).unwrap_or(0);
        let jitter_factor = i32::try_from(jitter_seed).unwrap_or(0) - 100; // -100..=100

        let base_ms = i128::try_from(period.as_millis()).unwrap_or(i128::MAX);
        let jitter_ms = base_ms
            .saturating_mul(i128::from(jitter_pct))
            .saturating_mul(i128::from(jitter_factor))
            / 10_000;

        let adjusted_ms = base_ms.saturating_add(jitter_ms).max(1);
        let millis_u128 = u128::try_from(adjusted_ms).unwrap_or(u128::from(u64::MAX));
        let clamped_ms = millis_u128.min(u128::from(u64::MAX));

        Duration::from_millis(clamped_ms as u64)
    }
}

impl Default for HeartbeatTx {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GAP TX
// ============================================================================

/// GAP transmitter (writer-side).
#[derive(Debug)]
pub struct GapTx {
    gap_count: u64,
    total_lost: u64,
    reader_id: EntityId,
    writer_id: EntityId,
}

impl GapTx {
    /// Create transmitter with default entity identifiers.
    #[must_use]
    pub fn new() -> Self {
        Self::with_entity_ids(ENTITYID_UNKNOWN_READER, ENTITYID_UNKNOWN_WRITER)
    }

    /// Create transmitter with explicit reader/writer entity IDs.
    #[must_use]
    pub fn with_entity_ids(reader_id: EntityId, writer_id: EntityId) -> Self {
        Self {
            gap_count: 0,
            total_lost: 0,
            reader_id,
            writer_id,
        }
    }

    /// Update entity identifiers (fluent builder style).
    pub fn set_entity_ids(&mut self, reader_id: EntityId, writer_id: EntityId) {
        self.reader_id = reader_id;
        self.writer_id = writer_id;
    }

    /// Build GAP messages for the provided range.
    pub fn build_gap(&mut self, range: RtpsRange) -> Vec<GapMsg> {
        if range.start >= range.end {
            return Vec::new();
        }

        let mut messages = Vec::new();
        let mut cursor = range.start;

        while cursor < range.end {
            let chunk_end = (cursor + u64::from(SequenceNumberSet::MAX_BITS) + 1).min(range.end);
            if let Some(msg) = GapMsg::contiguous(
                self.reader_id,
                self.writer_id,
                RtpsRange::new(cursor, chunk_end),
            ) {
                self.gap_count += 1;
                self.total_lost += chunk_end - cursor;
                messages.push(msg);
            }
            cursor = chunk_end;
        }

        messages
    }

    /// Build GAP messages from explicit missing sequence numbers.
    ///
    /// Sequences must be sorted in ascending order.
    pub fn build_gap_from_sequences(&mut self, sequences: &[u64]) -> Vec<GapMsg> {
        if sequences.is_empty() {
            return Vec::new();
        }

        let mut messages = Vec::new();
        let mut idx = 0usize;

        while idx < sequences.len() {
            let gap_start = sequences[idx];
            let base = gap_start.saturating_add(1);
            let base_i64 = match i64::try_from(base) {
                Ok(value) => value,
                Err(_) => {
                    idx = idx.saturating_add(1);
                    continue;
                }
            };

            let max_seq = gap_start.saturating_add(u64::from(SequenceNumberSet::MAX_BITS));
            let mut extras = Vec::new();
            let mut j = idx.saturating_add(1);
            while j < sequences.len() {
                let seq = sequences[j];
                if seq > max_seq {
                    break;
                }
                if seq > gap_start {
                    extras.push(seq);
                }
                j += 1;
            }

            if let Some(gap_list) = SequenceNumberSet::from_sequences(base_i64, &extras) {
                self.gap_count = self.gap_count.saturating_add(1);
                let lost = 1u64.saturating_add(u64::try_from(extras.len()).unwrap_or(0));
                self.total_lost = self.total_lost.saturating_add(lost);
                messages.push(GapMsg::new(
                    self.reader_id,
                    self.writer_id,
                    gap_start,
                    gap_list,
                ));
            }

            idx = j;
        }

        messages
    }

    /// Total GAP messages emitted.
    #[must_use]
    pub fn gap_count(&self) -> u64 {
        self.gap_count
    }

    /// Total sequence numbers marked as lost.
    #[must_use]
    pub fn total_lost(&self) -> u64 {
        self.total_lost
    }
}

impl Default for GapTx {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// INFO_TS TX
// ============================================================================

/// INFO_TS transmitter (writer-side)
#[derive(Debug, Default)]
pub struct InfoTsTx {
    ts_count: u64,
}

impl InfoTsTx {
    pub fn new() -> Self {
        Self { ts_count: 0 }
    }

    pub fn build_timestamp(&mut self) -> InfoTsMsg {
        self.ts_count += 1;
        InfoTsMsg::now()
    }

    pub fn build_timestamp_at(&mut self, nanos: u64) -> InfoTsMsg {
        self.ts_count += 1;
        InfoTsMsg::from_nanos(nanos)
    }

    #[must_use]
    pub fn ts_count(&self) -> u64 {
        self.ts_count
    }
}

// ============================================================================
// INFO_DST TX
// ============================================================================

/// INFO_DST transmitter (writer-side).
#[derive(Debug, Default)]
pub struct InfoDstTx {
    dst_count: u64,
    last_prefix: Option<GuidPrefix>,
}

impl InfoDstTx {
    #[must_use]
    pub fn new() -> Self {
        Self {
            dst_count: 0,
            last_prefix: None,
        }
    }

    /// Build INFO_DST message for specific destination.
    pub fn build_info_dst(&mut self, guid_prefix: GuidPrefix) -> InfoDstMsg {
        self.dst_count += 1;
        self.last_prefix = Some(guid_prefix);
        InfoDstMsg::new(guid_prefix)
    }

    /// Build broadcast INFO_DST (all zeros).
    pub fn build_broadcast(&mut self) -> InfoDstMsg {
        self.dst_count += 1;
        self.last_prefix = Some([0; GUID_PREFIX_LEN]);
        InfoDstMsg::broadcast()
    }

    #[must_use]
    pub fn dst_count(&self) -> u64 {
        self.dst_count
    }

    #[must_use]
    pub fn last_prefix(&self) -> Option<&GuidPrefix> {
        self.last_prefix.as_ref()
    }
}

// ============================================================================
// WRITER RETRANSMIT HANDLER
// ============================================================================

/// Writer-side retransmission handler.
pub struct WriterRetransmitHandler<'a> {
    cache: &'a HistoryCache,
    gap_tx: &'a mut GapTx,
    metrics: &'a ReliableMetrics,
}

impl<'a> WriterRetransmitHandler<'a> {
    /// Create new writer retransmission handler.
    pub fn new(
        cache: &'a HistoryCache,
        gap_tx: &'a mut GapTx,
        metrics: &'a ReliableMetrics,
    ) -> Self {
        Self {
            cache,
            gap_tx,
            metrics,
        }
    }

    /// Process a NACK message and return both retransmits and GAP notifications.
    ///
    /// # NACK Processing State Machine
    ///
    /// For each sequence number range requested in the NACK:
    /// 1. **Cache Hit** → Add payload to retransmits, increment metrics
    /// 2. **Cache Miss** → Collect into `missing` list for GAP generation
    ///
    /// After processing each range, if any sequences were missing from the cache,
    /// we generate GAP messages to inform the reader those samples are irretrievably
    /// lost (expired from history cache or never existed).
    ///
    /// # Why Both Retransmits AND Gaps?
    ///
    /// A single NACK may request sequences in mixed states:
    /// - Some still available in cache → retransmit them
    /// - Some already evicted (history depth exceeded) → send GAP
    ///
    /// The reader needs BOTH responses to maintain correct state:
    /// - Retransmits fill actual data gaps
    /// - GAPs allow the reader to advance its expected sequence number without
    ///   waiting forever for samples that will never arrive
    ///
    /// # Cache Lookup and Range Iteration
    ///
    /// We iterate `range.start..range.end` (exclusive end) to match RTPS sequence
    /// number semantics. Each lookup in `self.cache` is O(1) for the typical
    /// ring-buffer implementation. Missing sequences are batched per-range to
    /// minimize the number of GAP submessages generated.
    pub fn on_nack(&mut self, nack: &NackMsg) -> (Vec<(u64, Vec<u8>)>, Vec<GapMsg>) {
        let mut retransmits = Vec::new();
        let mut gaps = Vec::new();

        // Process each requested sequence range from the NACK
        for range in &nack.ranges {
            let mut missing = Vec::new();

            // Attempt to retrieve each sequence from the writer's history cache
            for seq in range.start..range.end {
                if let Some(payload) = self.cache.get(seq) {
                    // Cache hit: queue for retransmission
                    retransmits.push((seq, payload));
                    self.metrics.increment_retransmit_sent(1);
                } else {
                    // Cache miss: sample expired or never existed
                    missing.push(seq);
                }
            }

            // Generate GAP messages for sequences we cannot retransmit
            if !missing.is_empty() {
                let gap_msgs = self.gap_tx.build_gap_from_sequences(&missing);
                for gap in &gap_msgs {
                    let gap_size = 1u64.saturating_add(gap.gap_list().iter().count() as u64);
                    self.metrics.record_gap(gap_size);
                }
                gaps.extend(gap_msgs);
            }
        }

        (retransmits, gaps)
    }
}
