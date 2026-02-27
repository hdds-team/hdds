// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! NACK coalescer for reliable QoS.
//!
//! Coalesces multiple NACKs into batched repair requests to avoid
//! repair storms under congestion.

use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Sequence number type (matches RTPS).
pub type SequenceNumber = i64;

/// Coalesces NACKs to avoid repair storms.
///
/// When multiple readers NACK the same sequence numbers in quick succession,
/// this coalescer batches them together before triggering repairs.
#[derive(Debug)]
pub struct NackCoalescer {
    /// Pending gaps waiting to be flushed.
    pending: HashSet<SequenceNumber>,

    /// Coalescing delay (wait this long before flushing).
    coalesce_delay: Duration,

    /// Time of first NACK in current batch.
    first_nack_at: Option<Instant>,

    /// Maximum batch size (flush early if exceeded).
    max_batch_size: usize,

    /// Statistics.
    stats: NackCoalescerStats,
}

/// Statistics for NACK coalescing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NackCoalescerStats {
    /// Total NACKs received.
    pub nacks_received: u64,
    /// Total flushes performed.
    pub flushes: u64,
    /// Total unique sequences flushed.
    pub sequences_flushed: u64,
    /// NACKs that were deduplicated (same seq in same batch).
    pub duplicates_coalesced: u64,
}

impl NackCoalescer {
    /// Create a new NACK coalescer with the specified delay.
    pub fn new(coalesce_delay: Duration) -> Self {
        Self {
            pending: HashSet::new(),
            coalesce_delay,
            first_nack_at: None,
            max_batch_size: 100,
            stats: NackCoalescerStats::default(),
        }
    }

    /// Create with custom max batch size.
    pub fn with_max_batch(coalesce_delay: Duration, max_batch_size: usize) -> Self {
        Self {
            pending: HashSet::new(),
            coalesce_delay,
            first_nack_at: None,
            max_batch_size,
            stats: NackCoalescerStats::default(),
        }
    }

    /// Add gaps from a NACK message.
    ///
    /// Gaps are accumulated until `flush_if_ready` is called.
    pub fn add(&mut self, gaps: &[SequenceNumber]) {
        if gaps.is_empty() {
            return;
        }

        // Start timer on first NACK
        if self.first_nack_at.is_none() {
            self.first_nack_at = Some(Instant::now());
        }

        for &seq in gaps {
            self.stats.nacks_received += 1;
            if !self.pending.insert(seq) {
                // Already in set - duplicate
                self.stats.duplicates_coalesced += 1;
            }
        }
    }

    /// Add a single gap.
    pub fn add_one(&mut self, seq: SequenceNumber) {
        self.add(&[seq]);
    }

    /// Add a range of gaps (inclusive).
    pub fn add_range(&mut self, start: SequenceNumber, end: SequenceNumber) {
        if start > end {
            return;
        }

        if self.first_nack_at.is_none() {
            self.first_nack_at = Some(Instant::now());
        }

        for seq in start..=end {
            self.stats.nacks_received += 1;
            if !self.pending.insert(seq) {
                self.stats.duplicates_coalesced += 1;
            }
        }
    }

    /// Check if the coalescer should flush (delay elapsed or batch full).
    pub fn should_flush(&self) -> bool {
        if self.pending.is_empty() {
            return false;
        }

        // Flush if batch is full
        if self.pending.len() >= self.max_batch_size {
            return true;
        }

        // Flush if delay has elapsed
        if let Some(first) = self.first_nack_at {
            if first.elapsed() >= self.coalesce_delay {
                return true;
            }
        }

        false
    }

    /// Flush if ready (delay elapsed or batch full).
    ///
    /// Returns `Some(gaps)` if there are pending gaps ready to flush,
    /// `None` otherwise.
    pub fn flush_if_ready(&mut self) -> Option<Vec<SequenceNumber>> {
        if !self.should_flush() {
            return None;
        }

        self.flush()
    }

    /// Force flush regardless of timing.
    ///
    /// Returns `Some(gaps)` if there were pending gaps, `None` if empty.
    pub fn flush(&mut self) -> Option<Vec<SequenceNumber>> {
        if self.pending.is_empty() {
            return None;
        }

        let mut gaps: Vec<_> = self.pending.drain().collect();
        gaps.sort_unstable(); // Return in order

        self.first_nack_at = None;
        self.stats.flushes += 1;
        self.stats.sequences_flushed += gaps.len() as u64;

        Some(gaps)
    }

    /// Get the number of pending gaps.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if there are pending gaps.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get time until next flush (if any pending).
    pub fn time_until_flush(&self) -> Option<Duration> {
        let first = self.first_nack_at?;
        let elapsed = first.elapsed();

        if elapsed >= self.coalesce_delay {
            Some(Duration::ZERO)
        } else {
            Some(self.coalesce_delay - elapsed)
        }
    }

    /// Get the coalescing delay.
    pub fn coalesce_delay(&self) -> Duration {
        self.coalesce_delay
    }

    /// Set the coalescing delay.
    pub fn set_coalesce_delay(&mut self, delay: Duration) {
        self.coalesce_delay = delay;
    }

    /// Get statistics.
    pub fn stats(&self) -> NackCoalescerStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = NackCoalescerStats::default();
    }

    /// Clear all pending gaps without flushing.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.first_nack_at = None;
    }
}

impl Default for NackCoalescer {
    fn default() -> Self {
        // Default: 15ms coalescing delay (sweet spot for latency/batching)
        Self::new(Duration::from_millis(15))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new() {
        let mut nc = NackCoalescer::new(Duration::from_millis(10));
        assert_eq!(nc.pending_count(), 0);
        assert!(!nc.has_pending());
        assert!(nc.flush_if_ready().is_none());
    }

    #[test]
    fn test_default() {
        let nc = NackCoalescer::default();
        assert_eq!(nc.coalesce_delay(), Duration::from_millis(15));
    }

    #[test]
    fn test_add_gaps() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        nc.add(&[1, 2, 3]);
        assert_eq!(nc.pending_count(), 3);
        assert!(nc.has_pending());
    }

    #[test]
    fn test_add_one() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        nc.add_one(42);
        assert_eq!(nc.pending_count(), 1);
    }

    #[test]
    fn test_add_range() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        nc.add_range(10, 15);
        assert_eq!(nc.pending_count(), 6); // 10, 11, 12, 13, 14, 15
    }

    #[test]
    fn test_add_range_invalid() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        nc.add_range(15, 10); // Invalid range
        assert_eq!(nc.pending_count(), 0);
    }

    #[test]
    fn test_deduplication() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        nc.add(&[1, 2, 3]);
        nc.add(&[2, 3, 4]); // 2, 3 are duplicates

        assert_eq!(nc.pending_count(), 4); // 1, 2, 3, 4
        assert_eq!(nc.stats().duplicates_coalesced, 2);
    }

    #[test]
    fn test_flush_if_ready_not_ready() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        nc.add(&[1, 2, 3]);

        // Not ready yet (delay not elapsed)
        assert!(nc.flush_if_ready().is_none());
        assert_eq!(nc.pending_count(), 3);
    }

    #[test]
    fn test_flush_if_ready_delay_elapsed() {
        let mut nc = NackCoalescer::new(Duration::from_millis(10));

        nc.add(&[3, 1, 2]);

        // Wait for delay
        thread::sleep(Duration::from_millis(15));

        let gaps = nc.flush_if_ready();
        assert!(gaps.is_some());

        let gaps = gaps.unwrap();
        assert_eq!(gaps, vec![1, 2, 3]); // Sorted
        assert_eq!(nc.pending_count(), 0);
    }

    #[test]
    fn test_flush_if_ready_batch_full() {
        let mut nc = NackCoalescer::with_max_batch(Duration::from_secs(100), 5);

        nc.add(&[1, 2, 3, 4, 5]); // Exactly at max

        // Should flush immediately due to batch size
        assert!(nc.should_flush());
        let gaps = nc.flush_if_ready();
        assert!(gaps.is_some());
        assert_eq!(gaps.unwrap().len(), 5);
    }

    #[test]
    fn test_force_flush() {
        let mut nc = NackCoalescer::new(Duration::from_secs(100)); // Long delay

        nc.add(&[1, 2, 3]);

        // Force flush regardless of timing
        let gaps = nc.flush();
        assert!(gaps.is_some());
        assert_eq!(gaps.unwrap(), vec![1, 2, 3]);
        assert_eq!(nc.pending_count(), 0);
    }

    #[test]
    fn test_flush_empty() {
        let mut nc = NackCoalescer::new(Duration::from_millis(10));

        assert!(nc.flush().is_none());
    }

    #[test]
    fn test_time_until_flush() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        assert!(nc.time_until_flush().is_none());

        nc.add(&[1]);

        let remaining = nc.time_until_flush();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() <= Duration::from_millis(100));
    }

    #[test]
    fn test_time_until_flush_ready() {
        let mut nc = NackCoalescer::new(Duration::from_millis(5));

        nc.add(&[1]);
        thread::sleep(Duration::from_millis(10));

        let remaining = nc.time_until_flush();
        assert_eq!(remaining, Some(Duration::ZERO));
    }

    #[test]
    fn test_stats() {
        let mut nc = NackCoalescer::new(Duration::from_millis(5));

        nc.add(&[1, 2, 3]);
        nc.add(&[2, 3, 4]); // 2 duplicates

        thread::sleep(Duration::from_millis(10));
        nc.flush_if_ready();

        let stats = nc.stats();
        assert_eq!(stats.nacks_received, 6);
        assert_eq!(stats.duplicates_coalesced, 2);
        assert_eq!(stats.flushes, 1);
        assert_eq!(stats.sequences_flushed, 4);
    }

    #[test]
    fn test_reset_stats() {
        let mut nc = NackCoalescer::new(Duration::from_millis(5));

        nc.add(&[1, 2, 3]);
        thread::sleep(Duration::from_millis(10));
        nc.flush_if_ready();

        nc.reset_stats();

        let stats = nc.stats();
        assert_eq!(stats.nacks_received, 0);
        assert_eq!(stats.flushes, 0);
    }

    #[test]
    fn test_clear() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        nc.add(&[1, 2, 3]);
        nc.clear();

        assert_eq!(nc.pending_count(), 0);
        assert!(!nc.has_pending());
    }

    #[test]
    fn test_multiple_batches() {
        let mut nc = NackCoalescer::new(Duration::from_millis(5));

        // First batch
        nc.add(&[1, 2, 3]);
        thread::sleep(Duration::from_millis(10));
        let batch1 = nc.flush_if_ready();
        assert!(batch1.is_some());
        assert_eq!(batch1.unwrap(), vec![1, 2, 3]);

        // Second batch
        nc.add(&[10, 11]);
        thread::sleep(Duration::from_millis(10));
        let batch2 = nc.flush_if_ready();
        assert!(batch2.is_some());
        assert_eq!(batch2.unwrap(), vec![10, 11]);

        let stats = nc.stats();
        assert_eq!(stats.flushes, 2);
        assert_eq!(stats.sequences_flushed, 5);
    }

    #[test]
    fn test_add_empty() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        nc.add(&[]);
        assert_eq!(nc.pending_count(), 0);
        assert!(nc.first_nack_at.is_none());
    }

    #[test]
    fn test_sorted_output() {
        let mut nc = NackCoalescer::new(Duration::from_millis(5));

        nc.add(&[100, 50, 75, 25, 1]);
        thread::sleep(Duration::from_millis(10));

        let gaps = nc.flush_if_ready().unwrap();
        assert_eq!(gaps, vec![1, 25, 50, 75, 100]);
    }

    #[test]
    fn test_coalesce_delay_change() {
        let mut nc = NackCoalescer::new(Duration::from_millis(100));

        nc.set_coalesce_delay(Duration::from_millis(5));
        assert_eq!(nc.coalesce_delay(), Duration::from_millis(5));

        nc.add(&[1]);
        thread::sleep(Duration::from_millis(10));

        assert!(nc.should_flush());
    }
}
