// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS sequence number range abstraction
//!
//! Provides semantic constructors for `Range<u64>` that document RTPS boundary conventions
//! and eliminate clippy::range_plus_one warnings.

use std::ops::Range;

/// RTPS sequence number range (exclusive boundaries `[start, end)`)
///
/// # RTPS Semantics
///
/// DDS-RTPS v2.5 encodes sequence ranges as:
/// - **Exclusive**: `[start, end)` means "start included, end excluded"
/// - **Adjacency**: Two ranges `A` and `B` are contiguous if `A.end == B.start`
/// - **Wire Format**: Encoded as `(start: i64, end: i64)` in CDR2 little-endian
///
/// # Why Not `RangeInclusive`?
///
/// 1. **Adjacency Test**: `[1..3)` + `[3..5)` -> `[1..5)` (clean)
///    - Inclusive: `[1..=2]` + `[3..=4]` -> requires `2+1 == 3` adjacency check
///
/// 2. **Overlap Detection**: `A.end <= B.start` (standard interval overlap)
///    - Inclusive: `A.end < B.start - 1` (off-by-one prone)
///
/// 3. **CDR2 Encoding**: Wire format is exclusive (no +1/-1 on encode/decode)
///
/// # Clippy Suppression
///
/// Constructors like `from_inclusive(start, end_inclusive)` internally use
/// `start..(end_inclusive+1)`, which triggers `clippy::range_plus_one`.
/// This is **intentional** boundary transformation, not a code smell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RtpsRange {
    inner: Range<u64>,
}

impl RtpsRange {
    /// Create range from exclusive boundaries `[start, end)`
    ///
    /// # Example
    ///
    /// ```ignore
    /// let r = RtpsRange::new(10, 20); // [10..20)
    /// assert_eq!(r.start(), 10);
    /// assert_eq!(r.end(), 20);
    /// ```
    pub fn new(start: u64, end: u64) -> Self {
        assert!(start < end, "RTPS range must be non-empty");
        Self { inner: start..end }
    }

    /// Create range from inclusive boundaries `[start, end_inclusive]`
    ///
    /// Converts to exclusive range `[start, end_inclusive+1)`.
    ///
    /// # RTPS Rationale
    ///
    /// When a protocol specifies "sequences 10 through 15 inclusive",
    /// we convert to `[10..16)` for RTPS wire format compatibility.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let r = RtpsRange::from_inclusive(10, 15); // [10..=15] -> [10..16)
    /// assert_eq!(r.as_range(), &(10..16));
    /// ```
    #[allow(clippy::range_plus_one)]
    pub fn from_inclusive(start: u64, end_inclusive: u64) -> Self {
        assert!(start <= end_inclusive, "Inclusive range must be valid");
        Self {
            inner: start..(end_inclusive + 1),
        }
    }

    /// Create single-element range `[seq, seq+1)`
    ///
    /// # RTPS Rationale
    ///
    /// RTPS SequenceNumberSet bitmap represents sequences as ranges.
    /// A single sequence `seq` is encoded as range `[seq, seq+1)`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let r = RtpsRange::from_sequence(42); // [42..43)
    /// assert!(r.contains(42));
    /// assert!(!r.contains(43));
    /// ```
    #[allow(clippy::range_plus_one)]
    pub fn from_sequence(seq: u64) -> Self {
        Self {
            inner: seq..(seq + 1),
        }
    }

    /// Create gap range from last_seen to next_seq (boundary shift)
    ///
    /// # RTPS Rationale
    ///
    /// When reader has `last_seen = 10` and receives `seq = 15`,
    /// the gap is `(10+1)..15 = [11..15)` (sequences 11, 12, 13, 14).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let r = RtpsRange::from_gap(10, 15); // [11..15)
    /// assert_eq!(r.start(), 11);
    /// ```
    #[allow(clippy::range_plus_one)]
    pub fn from_gap(last_seen: u64, next_seq: u64) -> Self {
        assert!(last_seen < next_seq, "Gap range must be non-empty");
        Self {
            inner: (last_seen + 1)..next_seq,
        }
    }

    /// Start of range (inclusive)
    pub fn start(&self) -> u64 {
        self.inner.start
    }

    /// End of range (exclusive)
    pub fn end(&self) -> u64 {
        self.inner.end
    }

    /// Get as standard `Range<u64>` (for compatibility)
    pub fn as_range(&self) -> &Range<u64> {
        &self.inner
    }

    /// Convert to owned `Range<u64>`
    pub fn into_range(self) -> Range<u64> {
        self.inner
    }

    /// Check if range contains sequence
    pub fn contains(&self, seq: u64) -> bool {
        self.inner.contains(&seq)
    }

    /// Check if range is single-element
    pub fn is_single(&self) -> bool {
        self.inner.end == self.inner.start + 1
    }

    /// Iterate sequences in range
    pub fn iter_sequences(&self) -> impl Iterator<Item = u64> {
        self.inner.clone()
    }

    /// Number of sequences in range
    pub fn len(&self) -> u64 {
        self.inner.end - self.inner.start
    }

    /// Always false (range must be non-empty by construction)
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl From<Range<u64>> for RtpsRange {
    fn from(range: Range<u64>) -> Self {
        assert!(!range.is_empty(), "RTPS range must be non-empty");
        Self { inner: range }
    }
}

impl AsRef<Range<u64>> for RtpsRange {
    fn as_ref(&self) -> &Range<u64> {
        &self.inner
    }
}

impl std::ops::Deref for RtpsRange {
    type Target = Range<u64>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtps_range_new() {
        let r = RtpsRange::new(10, 20);
        assert_eq!(r.start(), 10);
        assert_eq!(r.end(), 20);
        assert_eq!(r.len(), 10);
    }

    #[test]
    fn test_rtps_range_from_inclusive() {
        let r = RtpsRange::from_inclusive(10, 15);
        assert_eq!(r.as_range(), &(10..16));
        assert_eq!(r.start(), 10);
        assert_eq!(r.end(), 16);
    }

    #[test]
    fn test_rtps_range_from_sequence() {
        let r = RtpsRange::from_sequence(42);
        assert!(r.is_single());
        assert!(r.contains(42));
        assert!(!r.contains(41));
        assert!(!r.contains(43));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_rtps_range_from_gap() {
        let r = RtpsRange::from_gap(10, 20);
        assert_eq!(r.as_range(), &(11..20));
        assert_eq!(r.start(), 11);
        assert_eq!(r.end(), 20);
    }

    #[test]
    fn test_rtps_range_adjacency() {
        let r1 = RtpsRange::new(1, 3);
        let r2 = RtpsRange::new(3, 5);
        assert_eq!(r1.end(), r2.start()); // Adjacency test (critical for gap merging)
    }

    #[test]
    fn test_rtps_range_from_range() {
        let r: RtpsRange = (10..20).into();
        assert_eq!(r.start(), 10);
        assert_eq!(r.end(), 20);
    }

    #[test]
    fn test_rtps_range_iter_sequences() {
        let r = RtpsRange::new(5, 8);
        let seqs: Vec<u64> = r.iter_sequences().collect();
        assert_eq!(seqs, vec![5, 6, 7]);
    }

    #[test]
    #[should_panic(expected = "RTPS range must be non-empty")]
    fn test_rtps_range_new_empty() {
        let _r = RtpsRange::new(10, 10);
    }

    #[test]
    #[should_panic(expected = "RTPS range must be non-empty")]
    fn test_rtps_range_new_inverted() {
        let _r = RtpsRange::new(20, 10);
    }

    #[test]
    #[should_panic(expected = "Gap range must be non-empty")]
    fn test_rtps_range_from_gap_invalid() {
        let _r = RtpsRange::from_gap(10, 10);
    }
}
