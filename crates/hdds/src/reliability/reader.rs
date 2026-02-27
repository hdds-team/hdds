// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reader-side reliability protocol handlers
//!
//! Consolidates all RX (receive) logic for Reliable QoS:
//! - HeartbeatRx: Heartbeat processing and gap detection
//! - GapRx: GAP message processing for lost sequences
//! - InfoTsRx: Timestamp extraction from INFO_TS
//! - InfoDstRx: Destination validation from INFO_DST
//! - ReaderRetransmitHandler: Retransmission tracking
//! - NackScheduler: Time-windowed NACK coalescing with exponential backoff

use std::ops::Range;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::messages::{GapMsg, GuidPrefix, HeartbeatMsg, InfoDstMsg, InfoTsMsg, GUID_PREFIX_LEN};
use super::{GapTracker, ReliableMetrics, RtpsRange};

// ============================================================================
// HEARTBEAT RX
// ============================================================================

/// Heartbeat receiver (reader-side).
#[derive(Debug, Default)]
pub struct HeartbeatRx {
    last_count: Option<u32>,
}

impl HeartbeatRx {
    /// Create a new heartbeat receiver.
    #[must_use]
    pub fn new() -> Self {
        Self { last_count: None }
    }

    /// Process a heartbeat and emit missing ranges if needed.
    pub fn on_heartbeat(
        &mut self,
        hb: &HeartbeatMsg,
        reader_last_seen: u64,
    ) -> Option<Vec<Range<u64>>> {
        if let Some(last_count) = self.last_count {
            if hb.count <= last_count {
                return None;
            }
        }

        self.last_count = Some(hb.count);

        if hb.last_seq > reader_last_seen {
            let gap = RtpsRange::from_inclusive(reader_last_seen + 1, hb.last_seq).into_range();
            Some(vec![gap])
        } else {
            None
        }
    }

    /// Last heartbeat count seen.
    #[must_use]
    pub fn last_count(&self) -> Option<u32> {
        self.last_count
    }
}

// ============================================================================
// GAP RX
// ============================================================================

/// GAP receiver (reader-side).
#[derive(Debug, Default)]
pub struct GapRx {
    gap_count: u64,
    total_lost: u64,
}

impl GapRx {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Process GAP message and return ranges that should be marked as lost.
    pub fn on_gap(&mut self, gap: &GapMsg) -> Vec<Range<u64>> {
        let ranges = gap.lost_ranges();
        let lost: u64 = ranges.iter().map(|r| r.end - r.start).sum();

        self.gap_count += 1;
        self.total_lost += lost;

        ranges
    }

    #[must_use]
    pub fn gap_count(&self) -> u64 {
        self.gap_count
    }

    #[must_use]
    pub fn total_lost(&self) -> u64 {
        self.total_lost
    }
}

// ============================================================================
// INFO_TS RX
// ============================================================================

/// INFO_TS receiver (reader-side)
#[derive(Debug, Default)]
pub struct InfoTsRx {
    last_ts: Option<InfoTsMsg>,
    ts_count: u64,
}

impl InfoTsRx {
    pub fn new() -> Self {
        Self {
            last_ts: None,
            ts_count: 0,
        }
    }

    pub fn on_timestamp(&mut self, ts: &InfoTsMsg) {
        self.last_ts = Some(*ts);
        self.ts_count += 1;
    }

    #[must_use]
    pub fn last_timestamp(&self) -> Option<InfoTsMsg> {
        self.last_ts
    }

    pub fn clear(&mut self) {
        self.last_ts = None;
    }

    #[must_use]
    pub fn ts_count(&self) -> u64 {
        self.ts_count
    }
}

// ============================================================================
// INFO_DST RX
// ============================================================================

/// INFO_DST receiver (reader-side).
#[derive(Debug, Default)]
pub struct InfoDstRx {
    last_dst: Option<GuidPrefix>,
    dst_count: u64,
}

impl InfoDstRx {
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_dst: None,
            dst_count: 0,
        }
    }

    /// Process received INFO_DST message and track destination prefix.
    pub fn on_info_dst(&mut self, info_dst: &InfoDstMsg) {
        self.last_dst = Some(*info_dst.guid_prefix());
        self.dst_count += 1;
    }

    #[must_use]
    pub fn last_destination(&self) -> Option<&GuidPrefix> {
        self.last_dst.as_ref()
    }

    #[must_use]
    pub fn dst_count(&self) -> u64 {
        self.dst_count
    }

    /// Returns true when current destination matches us or broadcast.
    #[must_use]
    pub fn is_for_us(&self, our_prefix: &GuidPrefix) -> bool {
        match self.last_dst {
            None => true,
            Some(ref dst) if dst == &[0; GUID_PREFIX_LEN] => true,
            Some(ref dst) => dst == our_prefix,
        }
    }

    /// Clear last destination (start of new RTPS message).
    pub fn clear(&mut self) {
        self.last_dst = None;
    }
}

// ============================================================================
// READER RETRANSMIT HANDLER
// ============================================================================

/// Reader-side retransmission handler.
pub struct ReaderRetransmitHandler<'a> {
    tracker: &'a mut GapTracker,
    metrics: &'a ReliableMetrics,
}

impl<'a> ReaderRetransmitHandler<'a> {
    /// Create new reader retransmission handler.
    pub fn new(tracker: &'a mut GapTracker, metrics: &'a ReliableMetrics) -> Self {
        Self { tracker, metrics }
    }

    /// Mark a retransmitted sequence as filled.
    pub fn on_retransmit(&mut self, seq: u64) {
        self.tracker.mark_filled(RtpsRange::from_sequence(seq));
        self.metrics.increment_retransmit_received(1);
    }
}

// ============================================================================
// NACK SCHEDULER
// ============================================================================

/// Default NACK window (milliseconds).
pub(crate) const DEFAULT_WINDOW_MS: u32 = 20;
/// Maximum NACK retries before giving up.
pub(crate) const MAX_RETRIES: u8 = 5;
/// Initial backoff interval (milliseconds).
pub(crate) const INITIAL_BACKOFF_MS: u32 = 50;

/// NACK scheduler with time-windowed gap coalescing and exponential backoff.
#[derive(Debug)]
pub struct NackScheduler {
    tracker: GapTracker,
    next_flush: Option<Instant>,
    window: Duration,
    retry_count: u8,
    backoff: Duration,
    initial_backoff: Duration,
    metrics: Option<Arc<ReliableMetrics>>,
}

/// NackScheduler state machine:
///
/// ```text
///                    ┌──────────────────────────────────────────┐
///                    │                                          │
///                    ▼                                          │
///   ┌────────┐  gap detected   ┌─────────┐  window expires  ┌───┴───┐
///   │  IDLE  │ ───────────────▶│ PENDING │ ────────────────▶│ RETRY │
///   └────────┘                 └─────────┘                  └───────┘
///       ▲                           │                           │
///       │      all gaps filled      │     retry_count >= 5      │
///       └───────────────────────────┴───────────────────────────┘
///                              (reset)
/// ```
///
/// - **IDLE**: No gaps, `next_flush = None`, `retry_count = 0`
/// - **PENDING**: Gaps detected, waiting for coalescing window to expire
/// - **RETRY**: NACK sent, waiting with exponential backoff for retransmission
///
/// Exponential backoff: starts at 50ms, doubles after each NACK (50→100→200→400→800ms).
/// After MAX_RETRIES (5), resets to IDLE (gives up on missing data).
impl NackScheduler {
    /// Create new NACK scheduler with the default coalescing window (20ms).
    ///
    /// The coalescing window batches multiple gap detections into a single NACK,
    /// reducing network overhead when packets arrive out of order.
    pub fn new() -> Self {
        Self::with_window_ms(DEFAULT_WINDOW_MS)
    }

    /// Create new NACK scheduler with a custom coalescing window in milliseconds.
    ///
    /// Shorter windows = lower latency but more NACKs. Longer windows = fewer
    /// NACKs but higher latency for retransmissions.
    pub fn with_window_ms(window_ms: u32) -> Self {
        let initial_backoff = Duration::from_millis(INITIAL_BACKOFF_MS as u64);

        Self {
            tracker: GapTracker::new(),
            next_flush: None,
            window: Duration::from_millis(window_ms as u64),
            retry_count: 0,
            backoff: initial_backoff,
            initial_backoff,
            metrics: None,
        }
    }

    /// Attach Reliable QoS metrics collector.
    pub fn set_metrics(&mut self, metrics: Arc<ReliableMetrics>) {
        self.metrics = Some(metrics);
    }

    /// Process an incoming sequence number.
    ///
    /// State transitions:
    /// - IDLE → PENDING: First gap detected, starts coalescing window
    /// - PENDING/RETRY → IDLE: All gaps filled, reset scheduler
    ///
    /// The coalescing window allows out-of-order packets to arrive before
    /// sending a NACK, avoiding unnecessary retransmission requests.
    pub fn on_receive(&mut self, seq: u64) {
        let had_gaps_before = !self.tracker.pending_gaps().is_empty();

        self.tracker.on_receive(seq);

        let has_gaps_now = !self.tracker.pending_gaps().is_empty();

        // IDLE → PENDING: first gap detected, start coalescing window
        if !had_gaps_before && has_gaps_now && self.next_flush.is_none() {
            self.next_flush = Some(Instant::now() + self.window);
        }

        // Any state → IDLE: all gaps filled
        if !has_gaps_now {
            self.reset();
        }
    }

    /// Report a gap range explicitly (e.g., via Heartbeat notifications).
    ///
    /// Transitions IDLE → PENDING if no gaps were pending. Unlike `on_receive`,
    /// this is used when Heartbeats inform us of available data we haven't seen.
    pub fn on_gap(&mut self, _gap: RtpsRange) {
        let had_gaps = !self.tracker.pending_gaps().is_empty();

        // IDLE → PENDING: start coalescing window
        if !had_gaps && self.next_flush.is_none() {
            self.next_flush = Some(Instant::now() + self.window);
        }
    }

    /// Try to flush pending NACKs when the window expires.
    ///
    /// Returns `Some(gaps)` when:
    /// 1. The coalescing/backoff window has expired (`Instant::now() >= deadline`)
    /// 2. There are still unfilled gaps to request
    ///
    /// The caller should send the NACK and then call `on_nack_sent()`.
    pub fn try_flush(&mut self) -> Option<Vec<Range<u64>>> {
        if let Some(deadline) = self.next_flush {
            if Instant::now() >= deadline {
                let gaps: Vec<Range<u64>> = self.tracker.pending_gaps().to_vec();
                if !gaps.is_empty() {
                    return Some(gaps);
                }
            }
        }
        None
    }

    /// Notify the scheduler that a NACK has been sent.
    ///
    /// Implements exponential backoff: 50ms → 100ms → 200ms → 400ms → 800ms.
    ///
    /// After MAX_RETRIES (5) NACKs without receiving the missing data, the
    /// scheduler resets to IDLE. This prevents infinite retry loops when
    /// data is permanently lost (writer crashed, network partition, etc.).
    /// The application will see a gap in sequence numbers.
    pub fn on_nack_sent(&mut self) {
        self.retry_count += 1;

        if let Some(ref metrics) = self.metrics {
            metrics.increment_nacks_sent(1);
        }

        // Give up after MAX_RETRIES: data is considered permanently lost
        if self.retry_count >= MAX_RETRIES {
            self.reset();
        } else {
            // Exponential backoff: double the wait time
            self.backoff *= 2;
            self.next_flush = Some(Instant::now() + self.backoff);
        }
    }

    /// Mark a retransmitted sequence as received.
    ///
    /// Called when the writer responds to our NACK with the missing data.
    /// Transitions to IDLE if all gaps are now filled.
    pub fn on_data_received(&mut self, seq: u64) {
        self.tracker.mark_filled(RtpsRange::from_sequence(seq));
        if self.tracker.pending_gaps().is_empty() {
            self.reset();
        }
    }

    /// Mark sequences as lost (writer emitted GAP submessage).
    ///
    /// The writer uses GAP to indicate data it will never send (e.g., filtered
    /// out by content filter, or writer history pruned). We stop waiting for
    /// these sequences. Transitions to IDLE if no gaps remain.
    pub fn mark_lost(&mut self, range: RtpsRange) {
        self.tracker.mark_lost(range);
        if self.tracker.pending_gaps().is_empty() {
            self.reset();
        }
    }

    /// Convenience helper to consume multiple lost ranges.
    pub fn mark_lost_ranges<I>(&mut self, ranges: I)
    where
        I: IntoIterator<Item = RtpsRange>,
    {
        for range in ranges {
            self.mark_lost(range);
        }
    }

    /// Read current pending gaps.
    pub fn pending_gaps(&self) -> &[Range<u64>] {
        self.tracker.pending_gaps()
    }

    /// Retrieve the current retry count (0 to MAX_RETRIES).
    ///
    /// Useful for diagnostics. Value of 5 means the scheduler gave up.
    pub fn retry_count(&self) -> u8 {
        self.retry_count
    }

    /// Whether the scheduler currently has outstanding gaps.
    pub fn has_pending_gaps(&self) -> bool {
        !self.tracker.pending_gaps().is_empty()
    }

    /// Reset to IDLE state: clear flush deadline, retry count, and backoff.
    ///
    /// Called when:
    /// - All gaps are filled (success)
    /// - MAX_RETRIES reached (give up)
    fn reset(&mut self) {
        self.next_flush = None;
        self.retry_count = 0;
        self.backoff = self.initial_backoff;
    }
}

impl Default for NackScheduler {
    fn default() -> Self {
        Self::new()
    }
}
