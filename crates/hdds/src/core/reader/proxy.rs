// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reliable Reader Proxy -- RTPS Sec.8.4.12.2 State Machine
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
//! Per RTPS v2.5 Sec.8.4.10.4, a StatefulReader maintains:
//! - `changes_from_writer_low_mark_`: highest contiguous seq received
//! - Missing changes set for gap detection
//! - HEARTBEAT response timing
//!
//! We implement a simplified version suitable for SEDP (1-2 samples).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Minimum interval between ACKNACK responses (the reader's heartbeatResponseDelay role in RTPS)
const ACKNACK_RATE_LIMIT_MS: u64 = 10;

/// Upper bound on the number of out-of-order sequences tracked above the
/// contiguous low-mark. Out-of-order reception above this many holes is
/// bounded so a misbehaving / lossy writer cannot grow the set without limit.
/// The contiguous prefix (low_mark) is never affected by this cap.
const MAX_RECEIVED_ABOVE: usize = 4096;

/// Decision after processing a HEARTBEAT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcknackDecision {
    /// Ignore duplicate HEARTBEAT (same or lower count)
    Ignore,

    /// We have all announced data, send ACKNACK with Final=1
    /// bitmapBase = low_mark + 1 (the next contiguous seq we want)
    Synchronized { bitmap_base: i64 },

    /// Missing data, send ACKNACK with Final=0
    /// bitmapBase = low_mark + 1 (the first hole in the contiguous prefix)
    NeedData { bitmap_base: i64 },

    /// Rate-limited, don't send ACKNACK yet
    RateLimited,
}

/// Per-writer state for reliable Reader (RTPS Sec.8.4.10.4 WriterProxy)
///
/// Tracks sequence numbers received from a remote Writer to generate
/// correct ACKNACK responses with proper bitmapBase and Final flag.
#[derive(Debug, Clone)]
pub struct ReliableReaderProxy {
    /// Remote writer GUID (guid_prefix + entity_id)
    writer_guid: [u8; 16],

    /// Highest CONTIGUOUS sequence number received: every sequence in
    /// `[1 ..= low_mark]` is present (received as DATA or covered by a GAP).
    /// This is the RTPS StatefulReader `changes_from_writer_low_mark_` and is
    /// the cumulative-ack point: the ACKNACK base is `low_mark + 1`.
    ///
    /// The ACKNACK is driven strictly from this contiguous prefix, not from
    /// a high-water mark of received sequences: on a receipt of {1,3} a
    /// high-water mark would ack as if 2 were present (premature Final ACK /
    /// silent loss of 2).
    low_mark: i64,

    /// Out-of-order sequences received that sit ABOVE `low_mark + 1` (i.e. a
    /// gap exists below them). When `low_mark + 1` lands in this set the prefix
    /// advances contiguously, draining entries as it goes. Bounded by
    /// `MAX_RECEIVED_ABOVE` so a lossy stream cannot grow it without limit.
    received_above: BTreeSet<i64>,

    /// Maximum sequence number announced by writer (from last HEARTBEAT)
    /// (the writer's announced lastSN)
    expected_max_seq: i64,

    /// Last HEARTBEAT count seen (for duplicate detection)
    last_hb_count: u32,

    /// Last time we sent an ACKNACK (for rate limiting)
    last_acknack_time: Option<Instant>,

    /// Rate limit duration
    rate_limit: Duration,

    /// Arm 2 (RTPS v2.5 sec 8.3.8.4): highest sequence number the writer has
    /// declared irrelevant via the contiguous GAP implicit range. The cumulative
    /// ACKNACK base is advanced to at least (gap_floor + 1) so we never NACK a
    /// sequence the writer already purged. `note_gap` advances `low_mark` over
    /// the GAP range directly; `gap_floor` is retained as a floor that survives
    /// even when no DATA has yet arrived to seed `low_mark`.
    ///
    /// Invariants (G1/G2/G3):
    /// - Initialised to 0; `.max(gap_floor + 1)` equals `.max(1)` at seq=1 so
    ///   the no-gap path is bit-for-bit unchanged (G1).
    /// - Only advanced over the CONTIGUOUS implicit range [gap_start, gap_list_base-1]
    ///   when gap_start <= current_front (G2, no jump over a real hole).
    /// - Monotonically non-decreasing; never recedes (G3).
    gap_floor: i64,

    /// Count of the last ACKNACK built from this proxy (RTPS 2.5 8.3.8.1:
    /// incremented with each ACKNACK the reader sends to this writer).
    acknack_count: u32,
    group_heartbeat_blocked: u8,
}

impl ReliableReaderProxy {
    /// Create a new proxy for tracking a remote writer
    pub fn new(writer_guid: [u8; 16]) -> Self {
        Self {
            writer_guid,
            low_mark: 0, // Nothing contiguous received yet
            received_above: BTreeSet::new(),
            expected_max_seq: 0,
            last_hb_count: 0,
            last_acknack_time: None,
            rate_limit: Duration::from_millis(ACKNACK_RATE_LIMIT_MS),
            gap_floor: 0,
            acknack_count: 0,
            group_heartbeat_blocked: 0,
        }
    }

    /// Get the writer GUID this proxy tracks
    pub fn writer_guid(&self) -> &[u8; 16] {
        &self.writer_guid
    }

    /// Highest CONTIGUOUS sequence number received (the cumulative-ack point).
    /// The ACKNACK base is `low_mark() + 1`.
    pub fn low_mark(&self) -> i64 {
        self.low_mark
    }

    /// Compatibility accessor. The contiguous low-mark IS the highest sequence
    /// we can safely report as received without a hole, which is the semantics
    /// ACKNACK callers of `highest_received_seq` need.
    pub fn highest_received_seq(&self) -> i64 {
        self.low_mark
    }

    /// Effective cumulative front: the next sequence we still need. This folds
    /// the contiguous prefix and the GAP floor together (G1: gap_floor=0 leaves
    /// it equal to `low_mark + 1`).
    pub(super) fn next_needed(&self) -> i64 {
        (self.low_mark + 1).max(self.gap_floor + 1)
    }

    /// Advance `low_mark` contiguously over any sequences in `received_above`
    /// (and over the GAP floor). Drains consumed entries. Idempotent.
    fn advance_low_mark(&mut self) {
        // First, absorb a GAP floor that sits at or beyond the current prefix.
        if self.gap_floor > self.low_mark {
            self.low_mark = self.gap_floor;
        }
        // Then walk forward while the next sequence is already received.
        while self.received_above.remove(&(self.low_mark + 1)) {
            self.low_mark += 1;
        }
        // Drop any stale entries at or below the new low_mark (defensive: a
        // duplicate insert below the prefix should never linger).
        while let Some(&first) = self.received_above.iter().next() {
            if first <= self.low_mark {
                self.received_above.remove(&first);
            } else {
                break;
            }
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
        if self.group_heartbeat_blocked != 0 {
            return self.on_group_blocked_heartbeat(last_seq, count);
        }
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

        // RTPS v2.5 Sec.8.3.8.6: `firstSN` declares the earliest sequence the
        // writer can still supply. Anything before `firstSN` is unavailable
        // (purged / never written for a late-joiner). Advance the contiguous
        // prefix over that unavailable leading history so we never NACK a
        // sequence the writer cannot resend: a late-joiner that gets HB(first=31,last=31) immediately treats
        // [1..=30] as covered and only requests 31.
        if first_seq > self.low_mark + 1 {
            // Treat [low_mark+1 .. first_seq-1] as covered (unavailable history).
            self.low_mark = self.low_mark.max(first_seq - 1);
            self.advance_low_mark();
        }

        // If writer has no data (lastSeq < firstSeq or lastSeq = 0), nothing to request
        if last_seq < first_seq || last_seq == 0 {
            log::trace!(
                "[PROXY] Writer has no data (first={}, last={})",
                first_seq,
                last_seq
            );
            // Still synchronized (nothing to get). Factor in gap_floor so a GAP received
            // before the first HEARTBEAT is honoured (G1: gap_floor=0 => .max(1) unchanged).
            return AcknackDecision::Synchronized {
                bitmap_base: first_seq.max(1).max(self.next_needed()),
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

        // bitmapBase = first hole in the contiguous prefix = low_mark + 1.
        // Clamp to first_seq (the writer cannot resend earlier) and to the
        // GAP floor (Arm 2). G1: for an in-order no-loss stream, low_mark
        // tracks the latest sequence, so the base is the same as a plain
        // high-water mark would give.
        let bitmap_base = self.next_needed().max(first_seq);

        // Synchronized when the contiguous prefix has reached the writer's
        // announced last sequence (low_mark >= last_seq). With holes below
        // last_seq the prefix lags and we must keep requesting (Final=0).
        if self.low_mark >= last_seq {
            log::debug!(
                "[PROXY] Synchronized: low_mark={} >= expected={}, bitmapBase={}",
                self.low_mark,
                last_seq,
                bitmap_base
            );
            AcknackDecision::Synchronized { bitmap_base }
        } else {
            log::debug!(
                "[PROXY] NeedData: low_mark={} < expected={}, bitmapBase={}, holes_above={}",
                self.low_mark,
                last_seq,
                bitmap_base,
                self.received_above.len()
            );
            AcknackDecision::NeedData { bitmap_base }
        }
    }

    /// Record that we received a DATA with the given sequence number.
    ///
    /// Inserts into the out-of-order set then advances the contiguous prefix
    /// (`low_mark`) over any now-contiguous run. Out-of-order arrivals (a hole
    /// below them) are retained until the gap is filled. This is the core of
    /// the contiguous-prefix state machine: receiving {1,3} leaves low_mark=1
    /// and received_above={3}; a later DATA(2) advances low_mark to 3.
    pub fn on_data(&mut self, seq: i64) {
        // Already covered by the contiguous prefix: pure duplicate, no-op.
        if seq <= self.low_mark {
            return;
        }
        // Bound the out-of-order set. Past the cap we still take the contiguous
        // case (seq == low_mark + 1) but refuse to grow the hole-set further;
        // the writer will resend via the NACK we keep emitting from low_mark+1.
        if seq > self.low_mark + 1 && self.received_above.len() >= MAX_RECEIVED_ABOVE {
            log::debug!(
                "[PROXY] received_above at cap ({}), dropping out-of-order seq={}",
                MAX_RECEIVED_ABOVE,
                seq
            );
            return;
        }
        self.received_above.insert(seq);
        let before = self.low_mark;
        self.advance_low_mark();
        if self.low_mark != before {
            log::debug!(
                "[PROXY] DATA seq={} advanced low_mark {} -> {} (holes_above={})",
                seq,
                before,
                self.low_mark,
                self.received_above.len()
            );
        }
    }

    /// Whether `seq` is still awaited: above the contiguous prefix and not
    /// received out of order.
    pub(crate) fn awaits(&self, seq: i64) -> bool {
        seq > self.low_mark && !self.received_above.contains(&seq)
    }

    /// Owed WriterSN intervals from actual HEARTBEAT announcements.
    /// Received and declared-irrelevant changes are excluded.
    pub(super) fn announced_through(&self) -> u64 {
        u64::try_from(self.expected_max_seq).unwrap_or(0)
    }

    pub(super) fn set_group_heartbeat_blocked(&mut self, blocked: bool) {
        self.group_heartbeat_blocked = (self.group_heartbeat_blocked & !1) | u8::from(blocked);
    }

    pub(super) fn set_group_order_pending(&mut self, pending: bool) {
        self.group_heartbeat_blocked =
            (self.group_heartbeat_blocked & !2) | (u8::from(pending) << 1);
    }

    #[cold]
    #[inline(never)]
    fn on_group_blocked_heartbeat(&mut self, last_seq: i64, count: u32) -> AcknackDecision {
        if self.group_heartbeat_blocked & 2 == 0 {
            return AcknackDecision::Ignore;
        }
        if count <= self.last_hb_count && self.last_hb_count > 0 {
            return AcknackDecision::Ignore;
        }
        self.last_hb_count = count;
        self.expected_max_seq = self.expected_max_seq.max(last_seq);
        // firstSN may have passed an irrelevant change whose GROUP proof
        // still needs repair. Preserve that hole so the writer repeats its GAP.
        if self
            .last_acknack_time
            .is_some_and(|last| last.elapsed() < self.rate_limit)
        {
            return AcknackDecision::RateLimited;
        }
        AcknackDecision::NeedData {
            bitmap_base: self.next_needed(),
        }
    }

    pub(crate) fn unreceived_ranges(&self) -> Vec<(u64, u64)> {
        let first = self.low_mark.saturating_add(1).max(1);
        if self.expected_max_seq < first || self.low_mark == i64::MAX {
            return Vec::new();
        }
        let mut next = first as u64;
        let mut ranges = Vec::new();
        for &received in self.received_above.range(first..=self.expected_max_seq) {
            let received = received as u64;
            if next < received {
                ranges.push((next, received));
            }
            next = received + 1;
        }
        if next <= self.expected_max_seq as u64 {
            ranges.push((next, self.expected_max_seq as u64 + 1));
        }
        ranges
    }

    /// Compute the NACK bitmap holes in [low_mark+1 ..= last_seq] given the
    /// current contiguous prefix and out-of-order set. Returns the list of
    /// MISSING sequences (those neither in the prefix nor received out-of-order),
    /// capped to the RTPS bitmap window of 256 bits starting at `low_mark+1`.
    /// `last_seq` is the writer's announced last sequence.
    pub fn missing_holes(&self, last_seq: i64) -> Vec<i64> {
        let base = self.low_mark + 1;
        if last_seq < base {
            return Vec::new();
        }
        // RTPS ACKNACK readerSNState bitmap is at most 256 bits wide.
        let window_end = (base + 255).min(last_seq);
        let mut holes = Vec::new();
        let mut s = base;
        while s <= window_end {
            if !self.received_above.contains(&s) {
                holes.push(s);
            }
            s += 1;
        }
        holes
    }

    /// Advance the cumulative-ack floor over a writer-declared GAP implicit range.
    ///
    /// RTPS v2.5 sec 8.3.8.4: a GAP submessage declares [gap_start, gap_list_base - 1]
    /// contiguously irrelevant. By advancing gap_floor to (gap_list_base - 1) we ensure
    /// the next ACKNACK requests the first truly-needed sequence (gap_list_base or beyond)
    /// rather than NACKing already-purged sequences the writer will never retransmit.
    ///
    /// ### Guards
    /// - G1 (inert without GAP): initialised to 0; `.max(gap_floor + 1)` equals `.max(1)`
    ///   which is already satisfied, so callers that never invoke note_gap are unchanged.
    /// - G2 (real range only): advances only when `gap_start <= current_front`; a mid-stream
    ///   GAP whose start is beyond the current front would jump over a real hole (data loss).
    /// - G3 (never recede / never over-advance): `.max(...)` keeps gap_floor monotonic; the
    ///   front-guard prevents jumping past genuine missing sequences.
    pub fn note_gap(&mut self, gap_start: i64, gap_list_base: i64) {
        if gap_list_base <= gap_start {
            // Empty implicit range: nothing to settle.
            return;
        }
        // Current contiguous front: the next sequence we still need.
        let current_front = self.next_needed();
        // G2: only advance when the GAP fills the front. A mid-stream GAP (gap_start
        // beyond the front) must NOT jump the cumulative base over a real hole.
        if gap_start > current_front {
            return;
        }
        // G3: monotonic advance over [gap_start, gap_list_base - 1]. The writer
        // declared every sequence in that range irrelevant, so it counts as
        // "received" for prefix advancement.
        self.gap_floor = self.gap_floor.max(gap_list_base - 1);
        // Fold the GAP coverage into the contiguous prefix immediately so a
        // subsequent on_data above the gap can chain through it.
        self.advance_low_mark();
    }

    /// The count of the next ACKNACK to this writer (starts at 1).
    pub(crate) fn next_acknack_count(&mut self) -> u32 {
        self.acknack_count = self.acknack_count.wrapping_add(1);
        self.acknack_count
    }

    /// Record that we sent an ACKNACK (for rate limiting)
    pub fn mark_acknack_sent(&mut self) {
        self.last_acknack_time = Some(Instant::now());
    }

    /// Whether an ACKNACK was recorded as sent (the rate-limit window runs).
    #[cfg(test)]
    pub(crate) fn acknack_sent(&self) -> bool {
        self.last_acknack_time.is_some()
    }

    /// Check if we are synchronized with the writer: the contiguous prefix has
    /// reached the last sequence announced via HEARTBEAT.
    pub fn is_synchronized(&self) -> bool {
        self.low_mark >= self.expected_max_seq && self.expected_max_seq > 0
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

    // --- Arm 2 unit tests (G1 / G2 / G3) ---

    /// G1: a flow that never calls note_gap must produce bit-for-bit identical
    /// bitmap_base values to the pre-change behavior. With gap_floor=0 the term
    /// `.max(gap_floor + 1)` equals `.max(1)`, and bitmap_base is already >= 1,
    /// so no change occurs.
    #[test]
    fn inert_without_gap() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // Same scenario as test_new_proxy_needs_data (no note_gap calls)
        let decision = proxy.on_heartbeat(1, 5, 1, false);
        assert!(
            matches!(decision, AcknackDecision::NeedData { bitmap_base: 1 }),
            "expected NeedData {{ bitmap_base: 1 }}, got {:?}",
            decision
        );

        // Also verify the no-data branch (lastSeq < firstSeq)
        let mut proxy2 = ReliableReaderProxy::new(guid);
        let d2 = proxy2.on_heartbeat(5, 0, 1, false);
        // no-data branch: bitmap_base = first_seq.max(1).max(gap_floor+1) = 5.max(1).max(1) = 5
        assert!(
            matches!(d2, AcknackDecision::Synchronized { bitmap_base: 5 }),
            "no-data branch wrong: {:?}",
            d2
        );
    }

    /// G2: fresh proxy (highest_received=0); note_gap(1, 35) fills the front
    /// (gap_start=1 <= current_front=1). Subsequent on_heartbeat must return
    /// bitmap_base == 35 (the first sequence NOT in the implicit irrelevant range).
    /// A late joiner facing a purged history: GAP [1,34] then HB first=1 last=80.
    #[test]
    fn gap_from_front_advances_base() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        proxy.note_gap(1, 35);

        let decision = proxy.on_heartbeat(1, 80, 1, false);
        assert!(
            matches!(decision, AcknackDecision::NeedData { bitmap_base: 35 }),
            "expected NeedData {{ bitmap_base: 35 }}, got {:?}",
            decision
        );
    }

    /// G2 / G3: a mid-stream GAP (gap_start beyond current front) must NOT advance
    /// gap_floor, preventing a jump over a real hole. fresh proxy; note_gap(50, 60)
    /// with gap_start=50 > current_front=1 => gap_floor stays 0; bitmap_base unchanged.
    #[test]
    fn midstream_gap_does_not_advance() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        proxy.note_gap(50, 60); // gap_start=50 > current_front=1 => ignored

        let decision = proxy.on_heartbeat(1, 80, 1, false);
        // gap_floor=0 => bitmap_base = (0+1).max(1).max(0+1) = 1
        assert!(
            matches!(decision, AcknackDecision::NeedData { bitmap_base: 1 }),
            "midstream GAP must not advance base; got {:?}",
            decision
        );
    }

    /// G3: gap_floor is strictly non-decreasing. A subsequent GAP with a smaller
    /// gap_list_base must NOT lower the floor.
    #[test]
    fn gap_floor_never_recedes() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        proxy.note_gap(1, 35); // gap_floor becomes 34
        proxy.note_gap(1, 20); // smaller range: gap_floor must stay 34

        let decision = proxy.on_heartbeat(1, 80, 1, false);
        // bitmap_base = (0+1).max(1).max(34+1) = 35
        assert!(
            matches!(decision, AcknackDecision::NeedData { bitmap_base: 35 }),
            "gap_floor must not recede; got {:?}",
            decision
        );
    }

    /// GAP-first compound: a durable writer purges [1,51] via GAP(gapStart=1,
    /// gapList.base=52) and announces HEARTBEAT(first=52, last=52) in the same
    /// datagram. The listener forwards the GAP before the embedded HEARTBEAT,
    /// so the proxy folds the gap floor in first and the heartbeat must yield
    /// a NACK with bitmap_base 52 and missing set exactly {52} -- the precise
    /// ACKNACK a NACK-driven durable writer needs to release its history.
    #[test]
    fn gap_then_heartbeat_nacks_first_live_sequence() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // GAP declares [1,51] irrelevant (gapStart=1, gapList.base=52).
        proxy.note_gap(1, 52);

        // Embedded HEARTBEAT from the same datagram: first=52, last=52.
        let decision = proxy.on_heartbeat(52, 52, 1, false);
        assert!(
            matches!(decision, AcknackDecision::NeedData { bitmap_base: 52 }),
            "expected NeedData {{ bitmap_base: 52 }}, got {:?}",
            decision
        );
        // The ONLY missing sequence is 52 (nothing below is NACKed).
        assert_eq!(proxy.missing_holes(52), vec![52]);
    }

    // --- Contiguous-prefix unit tests ---

    /// Core invariant: receiving {1,3} then 2 advances the contiguous low_mark
    /// to 3; the receipt of {1,3} alone must not move it past 1 (that would
    /// silently ack 2 as present).
    #[test]
    fn out_of_order_then_fill_advances_low_mark() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        proxy.on_data(1);
        assert_eq!(proxy.low_mark(), 1, "1 contiguous");

        proxy.on_data(3); // hole at 2
        assert_eq!(
            proxy.low_mark(),
            1,
            "low_mark must NOT advance past the hole at 2"
        );

        proxy.on_data(2); // fills the hole -> prefix chains 1,2,3
        assert_eq!(proxy.low_mark(), 3, "hole filled, prefix advances to 3");
    }

    /// With a hole below last_seq the proxy is NOT synchronized and emits
    /// NeedData with base at the first hole.
    #[test]
    fn hole_below_last_is_need_data() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        proxy.on_data(1);
        proxy.on_data(3); // missing 2

        // Writer announces up to 3.
        let decision = proxy.on_heartbeat(1, 3, 1, false);
        assert!(
            matches!(decision, AcknackDecision::NeedData { bitmap_base: 2 }),
            "expected NeedData base=2 (first hole), got {:?}",
            decision
        );

        // Now fill 2: prefix reaches 3, synchronized, base = 4.
        proxy.on_data(2);
        let decision = proxy.on_heartbeat(1, 3, 2, false);
        assert!(
            matches!(decision, AcknackDecision::Synchronized { bitmap_base: 4 }),
            "expected Synchronized base=4 after fill, got {:?}",
            decision
        );
        assert!(proxy.is_synchronized());
    }

    /// missing_holes reports exactly the absent sequences in the window.
    #[test]
    fn missing_holes_lists_gaps() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // Received 1, 2, 5 -> low_mark=2, received_above={5}; missing 3,4 up to 5.
        proxy.on_data(1);
        proxy.on_data(2);
        proxy.on_data(5);
        assert_eq!(proxy.low_mark(), 2);
        assert_eq!(proxy.missing_holes(5), vec![3, 4]);

        // Nothing announced above low_mark -> no holes.
        assert_eq!(proxy.missing_holes(2), Vec::<i64>::new());
    }

    /// A GAP that fills the front advances the contiguous prefix and chains
    /// through an out-of-order sample sitting just above the gap.
    #[test]
    fn gap_advances_prefix_and_chains() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // Out-of-order receipt of 35 (writer purged 1..=34 via GAP).
        proxy.on_data(35);
        assert_eq!(proxy.low_mark(), 0, "35 is out-of-order, prefix stays 0");

        // GAP declares [1,34] irrelevant: prefix jumps to 34 then chains 35.
        proxy.note_gap(1, 35);
        assert_eq!(
            proxy.low_mark(),
            35,
            "GAP [1,34] + received 35 chains prefix to 35"
        );

        // HB(first=1,last=35): synchronized, base = 36.
        let decision = proxy.on_heartbeat(1, 35, 1, false);
        assert!(
            matches!(decision, AcknackDecision::Synchronized { bitmap_base: 36 }),
            "expected Synchronized base=36, got {:?}",
            decision
        );
    }

    /// HEARTBEAT firstSN past the prefix (late-joiner / VOLATILE writer purge)
    /// advances the contiguous prefix over the unavailable leading history.
    /// Expected: HB(first=31,last=31) -> synchronized base=32
    /// once DATA(31) lands.
    #[test]
    fn heartbeat_first_sn_advances_over_unavailable_history() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        // Late joiner: writer only offers from 31.
        let d = proxy.on_heartbeat(31, 31, 1, false);
        // [1..=30] unavailable -> low_mark=30; still need 31.
        assert_eq!(proxy.low_mark(), 30, "unavailable history [1..30] absorbed");
        assert!(
            matches!(d, AcknackDecision::NeedData { bitmap_base: 31 }),
            "expected NeedData base=31, got {:?}",
            d
        );

        // DATA(31) arrives, then HB again -> synchronized base=32.
        proxy.on_data(31);
        assert_eq!(proxy.low_mark(), 31);
        let d = proxy.on_heartbeat(31, 31, 2, false);
        assert!(
            matches!(d, AcknackDecision::Synchronized { bitmap_base: 32 }),
            "expected Synchronized base=32, got {:?}",
            d
        );
    }

    /// An in-order no-loss stream behaves like a plain high-water mark:
    /// low_mark tracks the latest sequence and base = last+1.
    #[test]
    fn in_order_no_loss_matches_high_water() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        for s in 1..=10 {
            proxy.on_data(s);
            assert_eq!(proxy.low_mark(), s, "in-order prefix == seq");
        }
        let d = proxy.on_heartbeat(1, 10, 1, false);
        assert!(
            matches!(d, AcknackDecision::Synchronized { bitmap_base: 11 }),
            "expected Synchronized base=11, got {:?}",
            d
        );
    }

    /// Duplicate DATA below the prefix is a no-op (idempotent reception).
    #[test]
    fn duplicate_data_is_noop() {
        let guid = [0u8; 16];
        let mut proxy = ReliableReaderProxy::new(guid);

        proxy.on_data(1);
        proxy.on_data(2);
        proxy.on_data(1); // duplicate retransmit
        proxy.on_data(2);
        assert_eq!(proxy.low_mark(), 2);
        assert_eq!(proxy.missing_holes(2), Vec::<i64>::new());
    }
}

#[cfg(test)]
mod departure_loss_tests {
    use super::*;

    #[test]
    fn departure_owed_ranges_exclude_unannounced_prefix_receipts_and_gaps() {
        let mut proxy = ReliableReaderProxy::new([0x51; 16]);
        assert!(proxy.unreceived_ranges().is_empty());
        proxy.on_heartbeat(31, 36, 1, false);
        proxy.on_data(31);
        proxy.on_data(33);
        proxy.note_gap(34, 35);
        // The GAP parser also lists its implicit interval above the
        // contiguous front, so the proxy records it out of order.
        proxy.on_data(34);
        assert_eq!(proxy.unreceived_ranges(), vec![(32, 33), (35, 37)]);
        proxy.on_data(36);
        assert_eq!(proxy.unreceived_ranges(), vec![(32, 33), (35, 36)]);
    }

    #[test]
    fn a_received_maximum_writer_sequence_is_not_counted_as_owed() {
        let mut proxy = ReliableReaderProxy::new([0x52; 16]);
        proxy.on_heartbeat(i64::MAX - 1, i64::MAX, 1, false);
        proxy.on_data(i64::MAX);
        assert_eq!(
            proxy.unreceived_ranges(),
            vec![(i64::MAX as u64 - 1, i64::MAX as u64)]
        );
    }
}

#[cfg(test)]
mod ordered_gap_repair_tests {
    use super::*;

    #[test]
    fn heartbeat_retains_repair_and_last_sn_while_a_group_gap_is_unconsumed() {
        let mut proxy = ReliableReaderProxy::new([7; 16]);
        proxy.on_data(1);
        proxy.set_group_order_pending(true);
        assert!(matches!(
            proxy.on_heartbeat(10, 20, 1, false),
            AcknackDecision::NeedData { bitmap_base: 2 }
        ));
        assert_eq!(
            proxy.low_mark(),
            1,
            "firstSN consumed an outstanding GROUP proof"
        );
        assert_eq!(
            proxy.announced_through(),
            20,
            "blocked ordering lost the native repair horizon"
        );
        assert!(proxy.missing_holes(20).contains(&2));
        proxy.note_gap(2, 7);
        assert!(matches!(
            proxy.on_heartbeat(10, 20, 2, false),
            AcknackDecision::NeedData { bitmap_base: 7 }
        ));
        assert_eq!(
            proxy.low_mark(),
            6,
            "one consumed GAP cleared later proof debt"
        );
        proxy.set_group_order_pending(false);
        let _ = proxy.on_heartbeat(10, 20, 3, false);
        assert_eq!(proxy.low_mark(), 9);
    }
}
