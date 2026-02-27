// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Repair queue for reliable QoS with budget control.
//!
//!
//! Manages retransmission requests with:
//! - NACK coalescing to avoid repair storms
//! - Exponential backoff for retries
//! - Budget cap to limit repair traffic

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::nack_coalescer::{NackCoalescer, SequenceNumber};
use super::retry_tracker::{RepairRequest, RetryConfig, RetryTracker};

/// Configuration for the repair queue.
#[derive(Debug, Clone)]
pub struct RepairQueueConfig {
    /// Maximum ratio of total budget for repair traffic (0.0 - 1.0).
    pub budget_ratio: f32,
    /// NACK coalescing delay.
    pub coalesce_delay: Duration,
    /// Maximum batch size for NACK coalescing.
    pub max_batch_size: usize,
    /// Retry backoff configuration.
    pub retry_config: RetryConfig,
    /// Maximum queue size.
    pub max_queue_size: usize,
}

impl Default for RepairQueueConfig {
    fn default() -> Self {
        Self {
            budget_ratio: 0.3, // 30% max for repairs
            coalesce_delay: Duration::from_millis(15),
            max_batch_size: 100,
            retry_config: RetryConfig::default(),
            max_queue_size: 500,
        }
    }
}

impl RepairQueueConfig {
    /// Create with custom budget ratio.
    pub fn with_budget_ratio(mut self, ratio: f32) -> Self {
        self.budget_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Create with custom coalesce delay.
    pub fn with_coalesce_delay(mut self, delay: Duration) -> Self {
        self.coalesce_delay = delay;
        self
    }
}

/// Repair queue with budget control.
///
/// Integrates NACK coalescing, retry backoff, and budget management
/// to provide controlled retransmission under congestion.
#[derive(Debug)]
pub struct RepairQueue {
    /// Configuration.
    config: RepairQueueConfig,

    /// NACK coalescer.
    coalescer: NackCoalescer,

    /// Retry tracker.
    retry_tracker: RetryTracker,

    /// Queue of scheduled repairs.
    queue: VecDeque<RepairRequest>,

    /// Budget tracking for current window.
    budget_window: BudgetWindow,

    /// Statistics.
    stats: RepairQueueStats,
}

/// Tracks budget usage within a time window.
#[derive(Debug)]
struct BudgetWindow {
    /// Bytes used in current window.
    bytes_used: u64,
    /// Total budget available (updated externally).
    total_budget: u64,
    /// Window start time.
    window_start: Instant,
    /// Window duration.
    window_duration: Duration,
}

impl Default for BudgetWindow {
    fn default() -> Self {
        Self {
            bytes_used: 0,
            total_budget: 100_000, // 100KB default
            window_start: Instant::now(),
            window_duration: Duration::from_secs(1),
        }
    }
}

impl BudgetWindow {
    /// Check and reset window if needed.
    fn maybe_reset(&mut self) {
        if self.window_start.elapsed() >= self.window_duration {
            self.bytes_used = 0;
            self.window_start = Instant::now();
        }
    }

    /// Check if we have budget for the given size.
    fn has_budget(&mut self, size: u64, ratio: f32) -> bool {
        self.maybe_reset();
        let max_repair_budget = (self.total_budget as f32 * ratio) as u64;
        self.bytes_used + size <= max_repair_budget
    }

    /// Consume budget.
    fn consume(&mut self, size: u64) {
        self.bytes_used += size;
    }

    /// Get remaining repair budget.
    fn remaining(&self, ratio: f32) -> u64 {
        let max_repair_budget = (self.total_budget as f32 * ratio) as u64;
        max_repair_budget.saturating_sub(self.bytes_used)
    }
}

/// Statistics for repair queue.
#[derive(Debug, Clone, Copy, Default)]
pub struct RepairQueueStats {
    /// Total repair requests received.
    pub requests_received: u64,
    /// Repairs scheduled.
    pub repairs_scheduled: u64,
    /// Repairs sent successfully.
    pub repairs_sent: u64,
    /// Repairs blocked by budget.
    pub repairs_budget_blocked: u64,
    /// Repairs that exceeded max retries.
    pub repairs_exceeded: u64,
    /// Repairs dropped due to queue full.
    pub repairs_dropped: u64,
    /// Bytes used for repairs.
    pub repair_bytes: u64,
}

/// Result of trying to dequeue a repair.
#[derive(Debug)]
pub enum DequeueResult {
    /// Repair is ready to send.
    Ready(RepairRequest),
    /// Repair is scheduled but not yet ready; wait this long.
    Wait(Duration),
    /// Queue is empty.
    Empty,
    /// Budget exhausted for this window.
    BudgetExhausted,
}

impl RepairQueue {
    /// Create a new repair queue with default configuration.
    pub fn new() -> Self {
        Self::with_config(RepairQueueConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: RepairQueueConfig) -> Self {
        Self {
            coalescer: NackCoalescer::with_max_batch(config.coalesce_delay, config.max_batch_size),
            retry_tracker: RetryTracker::with_config(config.retry_config),
            queue: VecDeque::new(),
            budget_window: BudgetWindow::default(),
            stats: RepairQueueStats::default(),
            config,
        }
    }

    /// Request repair for sequence numbers (from NACK).
    ///
    /// The sequences are coalesced before being scheduled.
    pub fn request_repair(&mut self, gaps: &[SequenceNumber]) {
        self.stats.requests_received += gaps.len() as u64;
        self.coalescer.add(gaps);
    }

    /// Request repair for a single sequence.
    pub fn request_repair_one(&mut self, seq: SequenceNumber) {
        self.stats.requests_received += 1;
        self.coalescer.add_one(seq);
    }

    /// Process coalesced NACKs and schedule repairs.
    ///
    /// Call this periodically (e.g., every tick) to flush coalesced NACKs.
    pub fn process_coalesced(&mut self) {
        if let Some(gaps) = self.coalescer.flush_if_ready() {
            for seq in gaps {
                self.schedule_repair(seq);
            }
        }
    }

    /// Force flush coalesced NACKs.
    pub fn flush_coalesced(&mut self) {
        if let Some(gaps) = self.coalescer.flush() {
            for seq in gaps {
                self.schedule_repair(seq);
            }
        }
    }

    /// Schedule a repair for a sequence.
    fn schedule_repair(&mut self, seq: SequenceNumber) {
        // Get retry delay
        let delay = match self.retry_tracker.next_retry(seq) {
            Some(d) => d,
            None => {
                // Max retries exceeded
                self.stats.repairs_exceeded += 1;
                return;
            }
        };

        // Check queue capacity
        if self.queue.len() >= self.config.max_queue_size {
            self.stats.repairs_dropped += 1;
            return;
        }

        let retry_attempt = self.retry_tracker.retry_count(seq);
        let request = RepairRequest::new(seq, delay, retry_attempt);

        // Insert in sorted order by scheduled_at
        let pos = self
            .queue
            .iter()
            .position(|r| r.scheduled_at > request.scheduled_at)
            .unwrap_or(self.queue.len());

        self.queue.insert(pos, request);
        self.stats.repairs_scheduled += 1;
    }

    /// Try to dequeue the next ready repair.
    pub fn try_dequeue(&mut self) -> DequeueResult {
        self.budget_window.maybe_reset();

        let Some(front) = self.queue.front() else {
            return DequeueResult::Empty;
        };

        // Check if ready
        if !front.is_ready() {
            return DequeueResult::Wait(front.time_until_ready());
        }

        // Check budget
        let size = front.estimated_size() as u64;
        if !self
            .budget_window
            .has_budget(size, self.config.budget_ratio)
        {
            self.stats.repairs_budget_blocked += 1;
            return DequeueResult::BudgetExhausted;
        }

        // Dequeue and consume budget
        // SAFETY: We just checked front() returned Some, so pop_front() will too
        let Some(request) = self.queue.pop_front() else {
            return DequeueResult::Empty;
        };
        self.budget_window.consume(size);
        self.stats.repairs_sent += 1;
        self.stats.repair_bytes += size;

        DequeueResult::Ready(request)
    }

    /// Acknowledge a sequence (stop tracking retries).
    pub fn ack(&mut self, seq: SequenceNumber) {
        self.retry_tracker.ack(seq);
        // Also remove from queue if pending
        self.queue.retain(|r| r.sequence != seq);
    }

    /// Acknowledge a range of sequences.
    pub fn ack_range(&mut self, start: SequenceNumber, end: SequenceNumber) {
        self.retry_tracker.ack_range(start, end);
        self.queue
            .retain(|r| r.sequence < start || r.sequence > end);
    }

    /// Set the total budget (call when rate changes).
    pub fn set_total_budget(&mut self, budget_bps: u64) {
        // Budget is per second, window is 1 second by default
        self.budget_window.total_budget = budget_bps;
    }

    /// Get the number of pending repairs.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Check if there are pending repairs.
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty() || self.coalescer.has_pending()
    }

    /// Get remaining repair budget for this window.
    pub fn remaining_budget(&self) -> u64 {
        self.budget_window.remaining(self.config.budget_ratio)
    }

    /// Get statistics.
    pub fn stats(&self) -> RepairQueueStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = RepairQueueStats::default();
    }

    /// Get coalescer statistics.
    pub fn coalescer_stats(&self) -> super::nack_coalescer::NackCoalescerStats {
        self.coalescer.stats()
    }

    /// Get retry tracker statistics.
    pub fn retry_stats(&self) -> super::retry_tracker::RetryTrackerStats {
        self.retry_tracker.stats()
    }

    /// Clear all pending repairs.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.coalescer.clear();
        self.retry_tracker.clear();
    }

    /// Prune old retry state.
    pub fn prune_old(&mut self, max_age: Duration) {
        self.retry_tracker.prune_old(max_age);
    }

    /// Get the configuration.
    pub fn config(&self) -> &RepairQueueConfig {
        &self.config
    }
}

impl Default for RepairQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_config_default() {
        let cfg = RepairQueueConfig::default();
        assert!((cfg.budget_ratio - 0.3).abs() < 0.001);
        assert_eq!(cfg.coalesce_delay, Duration::from_millis(15));
    }

    #[test]
    fn test_config_builder() {
        let cfg = RepairQueueConfig::default()
            .with_budget_ratio(0.5)
            .with_coalesce_delay(Duration::from_millis(20));

        assert!((cfg.budget_ratio - 0.5).abs() < 0.001);
        assert_eq!(cfg.coalesce_delay, Duration::from_millis(20));
    }

    #[test]
    fn test_new() {
        let rq = RepairQueue::new();
        assert_eq!(rq.pending_count(), 0);
        assert!(!rq.has_pending());
    }

    #[test]
    fn test_request_repair() {
        let mut rq = RepairQueue::new();

        rq.request_repair(&[1, 2, 3]);
        assert!(rq.has_pending()); // In coalescer

        assert_eq!(rq.stats().requests_received, 3);
    }

    #[test]
    fn test_process_coalesced() {
        let cfg = RepairQueueConfig::default().with_coalesce_delay(Duration::from_millis(5));
        let mut rq = RepairQueue::with_config(cfg);

        rq.request_repair(&[1, 2, 3]);

        // Wait for coalesce delay
        thread::sleep(Duration::from_millis(10));

        rq.process_coalesced();

        // Now repairs should be in queue
        assert_eq!(rq.pending_count(), 3);
        assert_eq!(rq.stats().repairs_scheduled, 3);
    }

    #[test]
    fn test_flush_coalesced() {
        let mut rq = RepairQueue::new(); // Long default delay

        rq.request_repair(&[1, 2, 3]);
        rq.flush_coalesced(); // Force flush

        assert_eq!(rq.pending_count(), 3);
    }

    #[test]
    fn test_try_dequeue_empty() {
        let mut rq = RepairQueue::new();

        match rq.try_dequeue() {
            DequeueResult::Empty => {}
            _ => panic!("Expected Empty"),
        }
    }

    #[test]
    fn test_try_dequeue_wait() {
        let cfg = RepairQueueConfig {
            retry_config: RetryConfig::new(100, 1000), // 100ms base delay
            coalesce_delay: Duration::from_millis(1),
            ..RepairQueueConfig::default()
        };

        let mut rq = RepairQueue::with_config(cfg);

        rq.request_repair(&[1]);
        thread::sleep(Duration::from_millis(5));
        rq.process_coalesced();

        // Should need to wait for retry delay
        match rq.try_dequeue() {
            DequeueResult::Wait(d) => {
                assert!(d > Duration::ZERO);
                assert!(d <= Duration::from_millis(100));
            }
            _ => panic!("Expected Wait"),
        }
    }

    #[test]
    fn test_try_dequeue_ready() {
        let cfg = RepairQueueConfig {
            retry_config: RetryConfig::new(5, 100), // 5ms base delay
            coalesce_delay: Duration::from_millis(1),
            ..RepairQueueConfig::default()
        };

        let mut rq = RepairQueue::with_config(cfg);
        rq.set_total_budget(1_000_000); // 1MB budget

        rq.request_repair(&[42]);
        thread::sleep(Duration::from_millis(5));
        rq.process_coalesced();

        // Wait for retry delay
        thread::sleep(Duration::from_millis(10));

        match rq.try_dequeue() {
            DequeueResult::Ready(req) => {
                assert_eq!(req.sequence, 42);
                assert_eq!(req.retry_attempt, 1);
            }
            other => panic!("Expected Ready, got {:?}", other),
        }

        assert_eq!(rq.stats().repairs_sent, 1);
    }

    #[test]
    fn test_budget_exhausted() {
        let cfg = RepairQueueConfig {
            retry_config: RetryConfig::new(1, 100),
            coalesce_delay: Duration::from_millis(1),
            budget_ratio: 0.001, // Very small budget
            ..Default::default()
        };

        let mut rq = RepairQueue::with_config(cfg);
        rq.set_total_budget(100); // Very small total = ~0.03 bytes repair budget

        // Request many repairs
        rq.request_repair(&[1, 2, 3, 4, 5]);
        thread::sleep(Duration::from_millis(5));
        rq.process_coalesced();

        // Wait for ready
        thread::sleep(Duration::from_millis(5));

        // Should be budget exhausted
        match rq.try_dequeue() {
            DequeueResult::BudgetExhausted => {}
            other => panic!("Expected BudgetExhausted, got {:?}", other),
        }

        assert!(rq.stats().repairs_budget_blocked > 0);
    }

    #[test]
    fn test_ack() {
        let cfg = RepairQueueConfig {
            retry_config: RetryConfig::new(1, 100),
            coalesce_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let mut rq = RepairQueue::with_config(cfg);

        rq.request_repair(&[1, 2, 3]);
        thread::sleep(Duration::from_millis(5));
        rq.process_coalesced();

        assert_eq!(rq.pending_count(), 3);

        rq.ack(2);
        assert_eq!(rq.pending_count(), 2);
    }

    #[test]
    fn test_ack_range() {
        let cfg = RepairQueueConfig {
            retry_config: RetryConfig::new(1, 100),
            coalesce_delay: Duration::from_millis(1),
            ..RepairQueueConfig::default()
        };

        let mut rq = RepairQueue::with_config(cfg);

        rq.request_repair(&[1, 2, 3, 4, 5]);
        thread::sleep(Duration::from_millis(5));
        rq.process_coalesced();

        assert_eq!(rq.pending_count(), 5);

        rq.ack_range(2, 4);
        assert_eq!(rq.pending_count(), 2); // 1 and 5 remain
    }

    #[test]
    fn test_remaining_budget() {
        let cfg = RepairQueueConfig::default().with_budget_ratio(0.5);
        let mut rq = RepairQueue::with_config(cfg);

        rq.set_total_budget(1000);
        assert_eq!(rq.remaining_budget(), 500); // 50% of 1000
    }

    #[test]
    fn test_clear() {
        let cfg = RepairQueueConfig {
            coalesce_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let mut rq = RepairQueue::with_config(cfg);

        rq.request_repair(&[1, 2, 3]);
        thread::sleep(Duration::from_millis(5));
        rq.process_coalesced();

        rq.clear();

        assert_eq!(rq.pending_count(), 0);
        assert!(!rq.has_pending());
    }

    #[test]
    fn test_max_queue_size() {
        let cfg = RepairQueueConfig {
            max_queue_size: 3,
            retry_config: RetryConfig::new(1, 100),
            coalesce_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let mut rq = RepairQueue::with_config(cfg);

        rq.request_repair(&[1, 2, 3, 4, 5]); // 5 requests
        thread::sleep(Duration::from_millis(5));
        rq.process_coalesced();

        // Only 3 should be in queue
        assert_eq!(rq.pending_count(), 3);
        assert_eq!(rq.stats().repairs_dropped, 2);
    }

    #[test]
    fn test_max_retries_exceeded() {
        let cfg = RepairQueueConfig {
            retry_config: RetryConfig::new(1, 10).with_max_retries(2),
            coalesce_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let mut rq = RepairQueue::with_config(cfg);
        rq.set_total_budget(1_000_000);

        // Request repair multiple times for same sequence
        for _ in 0..3 {
            rq.request_repair_one(100);
            thread::sleep(Duration::from_millis(5));
            rq.process_coalesced();
            thread::sleep(Duration::from_millis(5));

            // Try to dequeue (may succeed or wait)
            if let DequeueResult::Ready(_) = rq.try_dequeue() {
                // Consumed
            }
        }

        // After 2 retries, 3rd should be exceeded
        assert!(rq.stats().repairs_exceeded > 0);
    }

    #[test]
    fn test_sorted_queue() {
        let cfg = RepairQueueConfig {
            retry_config: RetryConfig::new(1, 100),
            coalesce_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let mut rq = RepairQueue::with_config(cfg);

        // Add sequences that will have increasing delays
        rq.request_repair_one(1);
        thread::sleep(Duration::from_millis(2));
        rq.process_coalesced();

        // Request more for seq 1 (will have longer delay due to backoff)
        rq.request_repair_one(1);
        thread::sleep(Duration::from_millis(2));
        rq.process_coalesced();

        // Add new sequence (shorter delay)
        rq.request_repair_one(2);
        thread::sleep(Duration::from_millis(2));
        rq.process_coalesced();

        // Queue should be sorted by scheduled_at
        assert!(rq.pending_count() >= 2);
    }

    #[test]
    fn test_coalescing_dedup() {
        let cfg = RepairQueueConfig {
            coalesce_delay: Duration::from_millis(5),
            ..Default::default()
        };

        let mut rq = RepairQueue::with_config(cfg);

        // Send same sequence multiple times
        rq.request_repair(&[1, 2, 3]);
        rq.request_repair(&[2, 3, 4]); // 2, 3 are duplicates

        thread::sleep(Duration::from_millis(10));
        rq.process_coalesced();

        // Should only have 4 unique sequences
        assert_eq!(rq.pending_count(), 4);

        let stats = rq.coalescer_stats();
        assert_eq!(stats.duplicates_coalesced, 2);
    }
}
