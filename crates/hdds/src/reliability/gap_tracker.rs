// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Gap detection and tracking for Reliable QoS
//!
//! Reader-side component that detects out-of-order packets and tracks missing sequences.
//! Automatically merges adjacent ranges to minimize memory overhead.

use std::ops::Range;

use super::RtpsRange;

/// Maximum number of gap ranges to track
///
/// If exceeded, oldest gaps are dropped (log warning, continue).
/// 100 ranges is sufficient for most scenarios (burst loss, reordering).
const MAX_GAP_RANGES: usize = 100;

/// Gap tracker for detecting missing sequence numbers
///
/// Tracks gaps (missing sequences) in received messages, supporting:
/// - Out-of-order packet detection
/// - Automatic range merging
/// - Bounded memory (max 100 ranges)
///
/// # Algorithm
///
/// On `on_receive(seq)`:
/// 1. If `seq == last_seen + 1` -> contiguous, no gap
/// 2. If `seq > last_seen + 1` -> gap detected: `[last_seen+1..seq)`
/// 3. If `seq <= last_seen` -> out-of-order (fill existing gap or duplicate)
///
/// # Example
///
/// ```ignore
/// let mut tracker = GapTracker::new();
///
/// tracker.on_receive(1); // last_seen = 1
/// tracker.on_receive(2); // last_seen = 2, no gap
/// tracker.on_receive(5); // last_seen = 5, gap [3..5)
/// assert_eq!(tracker.pending_gaps(), &[3..5]);
///
/// tracker.on_receive(3); // fills part of gap
/// assert_eq!(tracker.pending_gaps(), &[4..5]);
/// ```
#[derive(Debug, Clone)]
pub struct GapTracker {
    /// Highest sequence number seen so far
    ///
    /// Invariant: `last_seen >= 0` (starts at 0, first packet sets to 1+)
    last_seen: u64,

    /// List of gap ranges (missing sequences)
    ///
    /// Each range `[start..end)` represents missing sequences.
    /// Ranges are kept sorted and merged when adjacent.
    ///
    /// Capacity: max `MAX_GAP_RANGES` (100), oldest dropped if exceeded.
    gaps: Vec<Range<u64>>,
}

impl GapTracker {
    /// Create a new gap tracker
    ///
    /// Starts with `last_seen = 0` (no packets received yet).
    pub fn new() -> Self {
        Self {
            last_seen: 0,
            gaps: Vec::with_capacity(MAX_GAP_RANGES),
        }
    }

    /// Process received sequence number
    ///
    /// Updates `last_seen` and gap ranges based on received sequence.
    ///
    /// # Cases
    ///
    /// 1. **Contiguous**: `seq == last_seen + 1` -> update `last_seen`, no gap
    /// 2. **Forward jump**: `seq > last_seen + 1` -> gap `[last_seen+1..seq)`, update `last_seen`
    /// 3. **Out-of-order**: `seq <= last_seen` -> fill gap or duplicate (no update to `last_seen`)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut tracker = GapTracker::new();
    /// tracker.on_receive(1); // last_seen = 1
    /// tracker.on_receive(3); // gap [2..3), last_seen = 3
    /// tracker.on_receive(2); // fills gap [2..3), last_seen = 3
    /// ```
    pub fn on_receive(&mut self, seq: u64) {
        if seq == 0 {
            // RTPS spec: sequence numbers start at 1, ignore 0
            return;
        }

        match seq.cmp(&(self.last_seen + 1)) {
            std::cmp::Ordering::Equal => {
                // Case 1: Contiguous (no gap)
                self.last_seen = seq;
            }
            std::cmp::Ordering::Greater => {
                // Case 2: Forward jump (gap detected)
                let gap = RtpsRange::from_gap(self.last_seen, seq).into_range();
                self.gaps.push(gap);
                self.last_seen = seq;

                // Merge adjacent ranges and enforce capacity
                self.merge_and_compact();
            }
            std::cmp::Ordering::Less => {
                // Case 3: Out-of-order (fill gap or duplicate)
                self.mark_filled(RtpsRange::from_sequence(seq));
            }
        }
    }

    /// Get current pending gaps
    ///
    /// Returns slice of gap ranges (sorted, merged).
    ///
    /// # Example
    ///
    /// ```ignore
    /// tracker.on_receive(1);
    /// tracker.on_receive(5);
    /// assert_eq!(tracker.pending_gaps(), &[2..5]);
    /// ```
    pub fn pending_gaps(&self) -> &[Range<u64>] {
        &self.gaps
    }

    /// Mark a range as filled (received out-of-order)
    ///
    /// Removes or splits gap ranges that overlap with `filled`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// tracker.on_receive(1);
    /// tracker.on_receive(5); // gap [2..5)
    /// tracker.mark_filled(RtpsRange::new(3, 4)); // gap becomes [2..3) + [4..5)
    /// ```
    pub fn mark_filled(&mut self, filled: RtpsRange) {
        let mut updated_gaps = Vec::with_capacity(self.gaps.len());

        for gap in &self.gaps {
            if filled.end <= gap.start || filled.start >= gap.end {
                // No overlap, keep gap as-is
                updated_gaps.push(gap.clone());
            } else {
                // Overlap: split gap into [gap.start..filled.start) and [filled.end..gap.end)
                if gap.start < filled.start {
                    updated_gaps.push(gap.start..filled.start);
                }
                if filled.end < gap.end {
                    updated_gaps.push(filled.end..gap.end);
                }
            }
        }

        self.gaps = updated_gaps;
    }

    /// Mark a range as lost (writer sent GAP notification).
    ///
    /// Removes the range from pending gaps and updates `last_seen` to represent
    /// the highest contiguous sequence number that has been accounted for (received
    /// or declared lost).
    ///
    /// # RTPS Semantics
    ///
    /// When a GAP [start..end) is received:
    /// 1. Mark sequences [start..end) as lost (remove from pending gaps)
    /// 2. Update `last_seen` to the end of the gap minus 1 (last sequence in gap)
    /// 3. This allows the reader to stop NACK-ing those sequences
    ///
    /// Note: `last_seen` may be "downgraded" if we had received sequences beyond
    /// the gap prematurely. This is correct RTPS behavior: the gap forces us to
    /// acknowledge we've processed up to the gap range, but sequences beyond must
    /// still be considered "out of order" until contiguous.
    ///
    /// # Example
    ///
    /// ```ignore
    /// tracker.on_receive(1); // last_seen = 1
    /// tracker.on_receive(5); // gap [2..5), last_seen = 5 (premature)
    /// tracker.mark_lost(RtpsRange::new(2, 5)); // Mark 2-4 as lost
    /// // Result: last_seen = 4 (end of gap - 1)
    /// // Sequence 5 is now considered "next expected" even though received
    /// ```
    pub fn mark_lost(&mut self, lost: RtpsRange) {
        if lost.start >= lost.end {
            return;
        }

        // Remove lost range from pending gaps
        self.mark_filled(lost.clone());

        // Update last_seen to end of lost range - 1
        // This represents "highest sequence accounted for (received OR lost)"
        if lost.end > 0 {
            self.last_seen = lost.end - 1;
        }

        self.merge_and_compact();
    }

    /// Get highest sequence number seen
    ///
    /// Returns `last_seen` value (updated by `on_receive` when seq > last_seen).
    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }

    /// Get total number of missing sequences
    ///
    /// Sums the size of all gap ranges.
    ///
    /// # Example
    ///
    /// ```ignore
    /// tracker.on_receive(1);
    /// tracker.on_receive(5); // gap [2..5) = 3 missing
    /// assert_eq!(tracker.total_missing(), 3);
    /// ```
    pub fn total_missing(&self) -> u64 {
        self.gaps.iter().map(|r| r.end - r.start).sum()
    }

    /// Merge adjacent ranges and enforce capacity limit
    ///
    /// Merges ranges like `[1..3)` + `[3..5)` -> `[1..5)`.
    /// If `gaps.len() > MAX_GAP_RANGES`, drops oldest gaps (FIFO).
    fn merge_and_compact(&mut self) {
        if self.gaps.is_empty() {
            return;
        }

        // Sort gaps by start (should already be sorted, but enforce)
        self.gaps.sort_by_key(|r| r.start);

        // Merge adjacent ranges
        let mut merged = Vec::with_capacity(self.gaps.len());
        let mut current = self.gaps[0].clone();

        for gap in &self.gaps[1..] {
            if gap.start == current.end {
                // Adjacent: merge
                current.end = gap.end;
            } else {
                // Not adjacent: push current, start new
                merged.push(current.clone());
                current = gap.clone();
            }
        }
        merged.push(current);

        self.gaps = merged;

        // Enforce capacity limit (drop oldest if needed)
        if self.gaps.len() > MAX_GAP_RANGES {
            let excess = self.gaps.len() - MAX_GAP_RANGES;
            log::debug!(
                "GapTracker: capacity exceeded, dropping {} oldest gaps (total {} -> {})",
                excess,
                self.gaps.len(),
                MAX_GAP_RANGES
            );
            self.gaps.drain(0..excess);
        }
    }
}

impl Default for GapTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gap_tracker_contiguous() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(1);
        tracker.on_receive(2);
        tracker.on_receive(3);

        assert_eq!(tracker.last_seen(), 3);
        assert_eq!(tracker.pending_gaps(), &[]);
        assert_eq!(tracker.total_missing(), 0);
    }

    #[test]
    fn test_gap_tracker_detect_gap() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(1);
        tracker.on_receive(5); // gap [2..5)

        assert_eq!(tracker.last_seen(), 5);
        let expected_gap: Vec<_> = std::iter::once(2_u64..5_u64).collect();
        assert_eq!(tracker.pending_gaps(), expected_gap);
        assert_eq!(tracker.total_missing(), 3);
    }

    #[test]
    fn test_gap_tracker_fill_gap_complete() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(1);
        tracker.on_receive(5); // gap [2..5)
        tracker.on_receive(2); // fills [2..3)
        tracker.on_receive(3); // fills [3..4)
        tracker.on_receive(4); // fills [4..5)

        assert_eq!(tracker.pending_gaps(), &[]);
        assert_eq!(tracker.total_missing(), 0);
    }

    #[test]
    fn test_gap_tracker_fill_gap_partial() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(1);
        tracker.on_receive(6); // gap [2..6)
        tracker.on_receive(3); // fills [3..4), gaps become [2..3) + [4..6)

        let gaps = tracker.pending_gaps();
        assert_eq!(gaps.len(), 2);
        assert_eq!(gaps[0], 2..3);
        assert_eq!(gaps[1], 4..6);
        assert_eq!(tracker.total_missing(), 3);
    }

    #[test]
    fn test_gap_tracker_merge_adjacent() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(1);
        tracker.on_receive(3); // gap [2..3)
        tracker.on_receive(5); // gap [4..5)

        // Gaps should merge if adjacent
        tracker.mark_filled(RtpsRange::new(4, 5)); // removes [4..5)
        let expected: Vec<_> = std::iter::once(2_u64..3_u64).collect();
        assert_eq!(tracker.pending_gaps(), expected);
    }

    #[test]
    fn test_gap_tracker_out_of_order() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(1);
        tracker.on_receive(2);
        tracker.on_receive(5);
        tracker.on_receive(6);

        // Out-of-order: 3, 4
        tracker.on_receive(3);
        tracker.on_receive(4);

        assert_eq!(tracker.pending_gaps(), &[]);
    }

    #[test]
    fn test_gap_tracker_capacity_limit() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(1);

        // Create 101 gaps (exceeds MAX_GAP_RANGES = 100)
        for i in 0..101 {
            let seq = 2 + (i * 2); // Creates gaps [2..3), [4..5), ..., [202..203)
            tracker.on_receive(seq);
        }

        // Should have dropped oldest gap (capacity enforced)
        assert_eq!(tracker.pending_gaps().len(), MAX_GAP_RANGES);
    }

    #[test]
    fn test_gap_tracker_duplicate() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(1);
        tracker.on_receive(2);
        tracker.on_receive(2); // Duplicate

        assert_eq!(tracker.last_seen(), 2);
        assert_eq!(tracker.pending_gaps(), &[]);
    }

    #[test]
    fn test_gap_tracker_zero_ignored() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(0); // Should be ignored (RTPS spec)

        assert_eq!(tracker.last_seen(), 0);
        assert_eq!(tracker.pending_gaps(), &[]);
    }

    #[test]
    fn test_gap_tracker_range_merging() {
        let mut tracker = GapTracker::new();

        tracker.on_receive(1);
        tracker.on_receive(5); // gap [2..5)
        tracker.on_receive(10); // gap [6..10)

        assert_eq!(tracker.pending_gaps(), &[2..5, 6..10]);

        // Fill connecting sequence
        tracker.on_receive(6);
        tracker.on_receive(7);
        tracker.on_receive(8);
        tracker.on_receive(9);

        // Should only have gap [2..5) left
        let expected_remaining: Vec<_> = std::iter::once(2_u64..5_u64).collect();
        assert_eq!(tracker.pending_gaps(), expected_remaining);
    }
}
