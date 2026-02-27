// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Writer pacer with priority queues.
//!
//!
//! The `WriterPacer` manages outgoing samples with:
//! - Token bucket rate limiting
//! - Priority queues (P0 > P1 > P2)
//! - P2 coalescing (last value wins)
//! - Backpressure handling

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::coalescing::{CoalescingQueue, InstanceKey};
use super::config::{CongestionConfig, Priority};
use super::token_bucket::TokenBucket;

/// A pending sample in the priority queues.
#[derive(Clone, Debug)]
pub struct PendingSample {
    /// Sample data.
    pub data: Vec<u8>,
    /// Sample priority.
    pub priority: Priority,
    /// When enqueued.
    pub enqueued_at: Instant,
    /// Sequence number for ordering.
    pub sequence: u64,
}

impl PendingSample {
    /// Create a new pending sample.
    pub fn new(data: Vec<u8>, priority: Priority, sequence: u64) -> Self {
        Self {
            data,
            priority,
            enqueued_at: Instant::now(),
            sequence,
        }
    }

    /// Get the size in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Get the age of this sample.
    pub fn age(&self) -> Duration {
        self.enqueued_at.elapsed()
    }
}

/// Action returned by try_send.
#[derive(Debug)]
pub enum SendAction {
    /// Send this sample data.
    Send(PendingSample),
    /// No data available to send.
    Empty,
    /// Rate limited, wait for tokens.
    RateLimited {
        /// Time until tokens available.
        wait_time: Duration,
    },
}

/// Error when enqueueing samples.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnqueueError {
    /// Queue is full and backpressure policy is ReturnError.
    QueueFull,
    /// Would block but timeout expired.
    Timeout,
    /// Congestion control is disabled.
    Disabled,
}

impl std::fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnqueueError::QueueFull => write!(f, "queue full"),
            EnqueueError::Timeout => write!(f, "timeout waiting for queue space"),
            EnqueueError::Disabled => write!(f, "congestion control disabled"),
        }
    }
}

impl std::error::Error for EnqueueError {}

/// Writer pacer with priority queues and rate limiting.
pub struct WriterPacer {
    /// Configuration.
    config: CongestionConfig,

    /// Token bucket for rate limiting.
    tokens: TokenBucket,

    /// P0 queue (critical, protected).
    queue_p0: VecDeque<PendingSample>,

    /// P1 queue (normal).
    queue_p1: VecDeque<PendingSample>,

    /// P2 queue (background, coalesced).
    queue_p2: CoalescingQueue,

    /// Next sequence number.
    next_sequence: u64,

    /// Metrics.
    metrics: WriterPacerMetrics,
}

/// Metrics for the writer pacer.
#[derive(Clone, Debug, Default)]
pub struct WriterPacerMetrics {
    /// Samples enqueued to P0.
    pub enqueued_p0: u64,
    /// Samples enqueued to P1.
    pub enqueued_p1: u64,
    /// Samples enqueued to P2.
    pub enqueued_p2: u64,
    /// Samples sent from P0.
    pub sent_p0: u64,
    /// Samples sent from P1.
    pub sent_p1: u64,
    /// Samples sent from P2.
    pub sent_p2: u64,
    /// Samples dropped from P1 (queue full).
    pub dropped_p1: u64,
    /// Samples coalesced in P2.
    pub coalesced_p2: u64,
    /// Samples dropped from P2.
    pub dropped_p2: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Rate limit hits.
    pub rate_limited: u64,
    /// P0 force sends (bypassed rate limit).
    pub force_sends_p0: u64,
}

impl WriterPacer {
    /// Create a new writer pacer with the given configuration.
    pub fn new(config: CongestionConfig) -> Self {
        let initial_rate = config.max_rate_bps;
        let capacity = (initial_rate as u64) / 10; // 100ms burst

        Self {
            tokens: TokenBucket::new(initial_rate, capacity.max(1500)), // At least 1 MTU
            queue_p0: VecDeque::with_capacity(config.max_queue_p0),
            queue_p1: VecDeque::with_capacity(config.max_queue_p1),
            queue_p2: CoalescingQueue::new(config.max_queue_p2),
            next_sequence: 0,
            metrics: WriterPacerMetrics::default(),
            config,
        }
    }

    /// Create a writer pacer with custom initial rate.
    pub fn with_rate(config: CongestionConfig, initial_rate_bps: u32) -> Self {
        let capacity = (initial_rate_bps as u64) / 10;

        Self {
            tokens: TokenBucket::new(initial_rate_bps, capacity.max(1500)),
            queue_p0: VecDeque::with_capacity(config.max_queue_p0),
            queue_p1: VecDeque::with_capacity(config.max_queue_p1),
            queue_p2: CoalescingQueue::new(config.max_queue_p2),
            next_sequence: 0,
            metrics: WriterPacerMetrics::default(),
            config,
        }
    }

    /// Enqueue a sample with the given priority.
    pub fn enqueue(&mut self, data: Vec<u8>, priority: Priority) -> Result<(), EnqueueError> {
        if !self.config.enabled {
            return Err(EnqueueError::Disabled);
        }

        let seq = self.next_sequence;
        self.next_sequence += 1;

        match priority {
            Priority::P0 => self.enqueue_p0(data, seq),
            Priority::P1 => self.enqueue_p1(data, seq),
            Priority::P2 => self.enqueue_p2(data, InstanceKey::keyless("default"), seq),
        }
    }

    /// Enqueue a sample with blocking if queue is full.
    ///
    /// This method respects `max_blocking_time`:
    /// - If queue has space, enqueues immediately
    /// - If queue is full, waits up to `max_blocking_time` for space
    /// - Returns `Err(Timeout)` if timeout expires before space is available
    ///
    /// Note: This is a simple polling implementation. In production, you would
    /// typically use async/await or condition variables.
    pub fn enqueue_blocking(
        &mut self,
        data: Vec<u8>,
        priority: Priority,
        max_blocking_time: Duration,
    ) -> Result<(), EnqueueError> {
        if !self.config.enabled {
            return Err(EnqueueError::Disabled);
        }

        let deadline = Instant::now() + max_blocking_time;

        loop {
            match self.enqueue(data.clone(), priority) {
                Ok(()) => return Ok(()),
                Err(EnqueueError::QueueFull) => {
                    if Instant::now() >= deadline {
                        return Err(EnqueueError::Timeout);
                    }
                    // Small sleep before retry (polling)
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Enqueue a P2 sample with instance key for coalescing.
    pub fn enqueue_p2_keyed(
        &mut self,
        data: Vec<u8>,
        key: InstanceKey,
    ) -> Result<(), EnqueueError> {
        if !self.config.enabled {
            return Err(EnqueueError::Disabled);
        }

        let seq = self.next_sequence;
        self.next_sequence += 1;

        self.enqueue_p2(data, key, seq)
    }

    fn enqueue_p0(&mut self, data: Vec<u8>, seq: u64) -> Result<(), EnqueueError> {
        if self.queue_p0.len() >= self.config.max_queue_p0 {
            // P0 never drops - return error
            return Err(EnqueueError::QueueFull);
        }

        self.queue_p0
            .push_back(PendingSample::new(data, Priority::P0, seq));
        self.metrics.enqueued_p0 += 1;
        Ok(())
    }

    fn enqueue_p1(&mut self, data: Vec<u8>, seq: u64) -> Result<(), EnqueueError> {
        if self.queue_p1.len() >= self.config.max_queue_p1 {
            // P1 drops oldest when full
            self.queue_p1.pop_front();
            self.metrics.dropped_p1 += 1;
        }

        self.queue_p1
            .push_back(PendingSample::new(data, Priority::P1, seq));
        self.metrics.enqueued_p1 += 1;
        Ok(())
    }

    fn enqueue_p2(
        &mut self,
        data: Vec<u8>,
        key: InstanceKey,
        _seq: u64,
    ) -> Result<(), EnqueueError> {
        let old_coalesced = self.queue_p2.coalesced_count();
        let old_dropped = self.queue_p2.dropped_count();

        self.queue_p2.insert(data, key);

        // Update metrics
        if self.queue_p2.coalesced_count() > old_coalesced {
            self.metrics.coalesced_p2 += 1;
        }
        if self.queue_p2.dropped_count() > old_dropped {
            self.metrics.dropped_p2 += 1;
        }

        self.metrics.enqueued_p2 += 1;
        Ok(())
    }

    /// Try to get the next sample to send.
    ///
    /// Respects priority order: P0 > P1 > P2.
    /// Respects rate limiting (except P0 which can force-send).
    pub fn try_send(&mut self) -> SendAction {
        if !self.config.enabled {
            return SendAction::Empty;
        }

        // Try P0 first (may force-send)
        if let Some(sample) = self.try_dequeue_p0() {
            return SendAction::Send(sample);
        }

        // Try P1
        if let Some(sample) = self.try_dequeue_p1() {
            return SendAction::Send(sample);
        }

        // Try P2
        if let Some(sample) = self.try_dequeue_p2() {
            return SendAction::Send(sample);
        }

        // Check if we have pending but rate limited
        if !self.queue_p1.is_empty() || !self.queue_p2.is_empty() {
            let needed = self
                .queue_p1
                .front()
                .map(|s| s.data.len() as u64)
                .or_else(|| self.queue_p2.peek_front().map(|s| s.data.len() as u64))
                .unwrap_or(1500);

            let wait = self.tokens.time_until_available(needed);
            if !wait.is_zero() {
                self.metrics.rate_limited += 1;
                return SendAction::RateLimited { wait_time: wait };
            }
        }

        SendAction::Empty
    }

    fn try_dequeue_p0(&mut self) -> Option<PendingSample> {
        let sample = self.queue_p0.front()?;
        let size = sample.data.len() as u64;

        if self.tokens.try_consume(size) {
            let sample = self.queue_p0.pop_front()?;
            self.metrics.sent_p0 += 1;
            self.metrics.bytes_sent += size;
            Some(sample)
        } else {
            // P0 can force-send if rate limited
            self.tokens.force_consume(size);
            let sample = self.queue_p0.pop_front()?;
            self.metrics.sent_p0 += 1;
            self.metrics.force_sends_p0 += 1;
            self.metrics.bytes_sent += size;
            Some(sample)
        }
    }

    fn try_dequeue_p1(&mut self) -> Option<PendingSample> {
        let sample = self.queue_p1.front()?;
        let size = sample.data.len() as u64;

        if self.tokens.try_consume(size) {
            let sample = self.queue_p1.pop_front()?;
            self.metrics.sent_p1 += 1;
            self.metrics.bytes_sent += size;
            Some(sample)
        } else {
            None
        }
    }

    fn try_dequeue_p2(&mut self) -> Option<PendingSample> {
        let peeked = self.queue_p2.peek_front()?;
        let size = peeked.data.len() as u64;

        if self.tokens.try_consume(size) {
            let coalesced = self.queue_p2.pop_front()?;
            let sample = PendingSample::new(coalesced.data, Priority::P2, coalesced.sequence);
            self.metrics.sent_p2 += 1;
            self.metrics.bytes_sent += size;
            Some(sample)
        } else {
            None
        }
    }

    /// Update the rate limit.
    pub fn set_rate(&mut self, rate_bps: u32) {
        let clamped = rate_bps
            .max(self.config.min_rate_bps)
            .min(self.config.max_rate_bps);
        self.tokens.set_rate(clamped);

        // Update capacity to match new rate (100ms burst)
        let capacity = (clamped as u64) / 10;
        self.tokens.set_capacity(capacity.max(1500));
    }

    /// Get the current rate.
    pub fn rate(&self) -> u32 {
        self.tokens.rate()
    }

    /// Get current queue lengths.
    pub fn queue_lengths(&self) -> (usize, usize, usize) {
        (
            self.queue_p0.len(),
            self.queue_p1.len(),
            self.queue_p2.len(),
        )
    }

    /// Get total queued samples.
    pub fn total_queued(&self) -> usize {
        self.queue_p0.len() + self.queue_p1.len() + self.queue_p2.len()
    }

    /// Check if all queues are empty.
    pub fn is_empty(&self) -> bool {
        self.queue_p0.is_empty() && self.queue_p1.is_empty() && self.queue_p2.is_empty()
    }

    /// Get available tokens.
    pub fn available_tokens(&mut self) -> u64 {
        self.tokens.tokens()
    }

    /// Get token bucket fill ratio.
    pub fn token_fill_ratio(&mut self) -> f32 {
        self.tokens.fill_ratio()
    }

    /// Get a snapshot of the metrics.
    pub fn metrics(&self) -> &WriterPacerMetrics {
        &self.metrics
    }

    /// Reset the metrics.
    pub fn reset_metrics(&mut self) {
        self.metrics = WriterPacerMetrics::default();
        self.queue_p2.reset_metrics();
    }

    /// Clear all queues.
    pub fn clear(&mut self) {
        self.queue_p0.clear();
        self.queue_p1.clear();
        self.queue_p2.clear();
    }

    /// Get the configuration.
    pub fn config(&self) -> &CongestionConfig {
        &self.config
    }
}

impl WriterPacerMetrics {
    /// Get total samples enqueued.
    pub fn total_enqueued(&self) -> u64 {
        self.enqueued_p0 + self.enqueued_p1 + self.enqueued_p2
    }

    /// Get total samples sent.
    pub fn total_sent(&self) -> u64 {
        self.sent_p0 + self.sent_p1 + self.sent_p2
    }

    /// Get total samples dropped.
    pub fn total_dropped(&self) -> u64 {
        self.dropped_p1 + self.dropped_p2
    }

    /// Get send success rate (0.0 to 1.0).
    pub fn success_rate(&self) -> f32 {
        let total = self.total_enqueued();
        if total == 0 {
            return 1.0;
        }
        self.total_sent() as f32 / total as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> CongestionConfig {
        CongestionConfig {
            enabled: true,
            max_queue_p0: 10,
            max_queue_p1: 20,
            max_queue_p2: 10,
            min_rate_bps: 1000,
            max_rate_bps: 1_000_000,
            ..Default::default()
        }
    }

    #[test]
    fn test_new() {
        let pacer = WriterPacer::new(make_config());
        assert!(pacer.is_empty());
        assert_eq!(pacer.total_queued(), 0);
    }

    #[test]
    fn test_enqueue_p0() {
        let mut pacer = WriterPacer::new(make_config());

        pacer.enqueue(vec![1, 2, 3], Priority::P0).expect("ok");

        assert_eq!(pacer.queue_lengths(), (1, 0, 0));
        assert_eq!(pacer.metrics().enqueued_p0, 1);
    }

    #[test]
    fn test_enqueue_p1() {
        let mut pacer = WriterPacer::new(make_config());

        pacer.enqueue(vec![1, 2, 3], Priority::P1).expect("ok");

        assert_eq!(pacer.queue_lengths(), (0, 1, 0));
        assert_eq!(pacer.metrics().enqueued_p1, 1);
    }

    #[test]
    fn test_enqueue_p2() {
        let mut pacer = WriterPacer::new(make_config());

        pacer.enqueue(vec![1, 2, 3], Priority::P2).expect("ok");

        assert_eq!(pacer.queue_lengths(), (0, 0, 1));
        assert_eq!(pacer.metrics().enqueued_p2, 1);
    }

    #[test]
    fn test_priority_order() {
        let mut pacer = WriterPacer::new(make_config());

        // Enqueue in reverse order
        pacer.enqueue(vec![2], Priority::P2).expect("ok");
        pacer.enqueue(vec![1], Priority::P1).expect("ok");
        pacer.enqueue(vec![0], Priority::P0).expect("ok");

        // Should dequeue in priority order
        if let SendAction::Send(s) = pacer.try_send() {
            assert_eq!(s.priority, Priority::P0);
        } else {
            panic!("expected send");
        }

        if let SendAction::Send(s) = pacer.try_send() {
            assert_eq!(s.priority, Priority::P1);
        } else {
            panic!("expected send");
        }

        if let SendAction::Send(s) = pacer.try_send() {
            assert_eq!(s.priority, Priority::P2);
        } else {
            panic!("expected send");
        }

        assert!(matches!(pacer.try_send(), SendAction::Empty));
    }

    #[test]
    fn test_p0_queue_full() {
        let mut config = make_config();
        config.max_queue_p0 = 2;
        let mut pacer = WriterPacer::new(config);

        pacer.enqueue(vec![1], Priority::P0).expect("ok");
        pacer.enqueue(vec![2], Priority::P0).expect("ok");

        // Third should fail
        let result = pacer.enqueue(vec![3], Priority::P0);
        assert_eq!(result, Err(EnqueueError::QueueFull));
    }

    #[test]
    fn test_p1_drops_oldest() {
        let mut config = make_config();
        config.max_queue_p1 = 2;
        let mut pacer = WriterPacer::new(config);

        pacer.enqueue(vec![1], Priority::P1).expect("ok");
        pacer.enqueue(vec![2], Priority::P1).expect("ok");
        pacer.enqueue(vec![3], Priority::P1).expect("ok"); // Should drop [1]

        assert_eq!(pacer.queue_lengths().1, 2);
        assert_eq!(pacer.metrics().dropped_p1, 1);

        // Should get [2] first (oldest remaining)
        if let SendAction::Send(s) = pacer.try_send() {
            assert_eq!(s.data, vec![2]);
        }
    }

    #[test]
    fn test_p2_coalescing() {
        let mut pacer = WriterPacer::new(make_config());

        let key = InstanceKey::new(1, 1);
        pacer.enqueue_p2_keyed(vec![1], key.clone()).expect("ok");
        pacer.enqueue_p2_keyed(vec![2], key.clone()).expect("ok");
        pacer.enqueue_p2_keyed(vec![3], key.clone()).expect("ok");

        // Should only have 1 sample (latest)
        assert_eq!(pacer.queue_lengths().2, 1);
        assert_eq!(pacer.metrics().coalesced_p2, 2);

        if let SendAction::Send(s) = pacer.try_send() {
            assert_eq!(s.data, vec![3]);
        }
    }

    #[test]
    fn test_p0_force_send() {
        let mut config = make_config();
        config.max_rate_bps = 100; // Very low rate
        let mut pacer = WriterPacer::with_rate(config, 100);

        // Drain tokens
        pacer.tokens.drain();

        // P0 should still send (force)
        pacer.enqueue(vec![0; 1000], Priority::P0).expect("ok");

        if let SendAction::Send(s) = pacer.try_send() {
            assert_eq!(s.priority, Priority::P0);
        } else {
            panic!("P0 should force send");
        }

        assert_eq!(pacer.metrics().force_sends_p0, 1);
    }

    #[test]
    fn test_rate_limited() {
        let mut config = make_config();
        config.max_rate_bps = 100;
        let mut pacer = WriterPacer::with_rate(config, 100);

        // Drain tokens
        pacer.tokens.drain();

        // P1 should be rate limited
        pacer.enqueue(vec![0; 1000], Priority::P1).expect("ok");

        match pacer.try_send() {
            SendAction::RateLimited { wait_time } => {
                assert!(wait_time.as_secs() > 0);
            }
            _ => panic!("expected rate limited"),
        }
    }

    #[test]
    fn test_set_rate() {
        let mut pacer = WriterPacer::new(make_config());

        pacer.set_rate(50_000);
        assert_eq!(pacer.rate(), 50_000);

        // Should clamp to min
        pacer.set_rate(100);
        assert_eq!(pacer.rate(), 1000); // min_rate_bps

        // Should clamp to max
        pacer.set_rate(100_000_000);
        assert_eq!(pacer.rate(), 1_000_000); // max_rate_bps
    }

    #[test]
    fn test_metrics() {
        let mut pacer = WriterPacer::new(make_config());

        pacer.enqueue(vec![1], Priority::P0).expect("ok");
        pacer.enqueue(vec![2], Priority::P1).expect("ok");
        pacer.enqueue(vec![3], Priority::P2).expect("ok");

        pacer.try_send();
        pacer.try_send();
        pacer.try_send();

        let m = pacer.metrics();
        assert_eq!(m.total_enqueued(), 3);
        assert_eq!(m.total_sent(), 3);
        assert_eq!(m.bytes_sent, 3);
    }

    #[test]
    fn test_clear() {
        let mut pacer = WriterPacer::new(make_config());

        pacer.enqueue(vec![1], Priority::P0).expect("ok");
        pacer.enqueue(vec![2], Priority::P1).expect("ok");
        pacer.enqueue(vec![3], Priority::P2).expect("ok");

        pacer.clear();

        assert!(pacer.is_empty());
    }

    #[test]
    fn test_disabled() {
        let config = CongestionConfig::disabled();
        let mut pacer = WriterPacer::new(config);

        let result = pacer.enqueue(vec![1], Priority::P0);
        assert_eq!(result, Err(EnqueueError::Disabled));

        assert!(matches!(pacer.try_send(), SendAction::Empty));
    }

    #[test]
    fn test_pending_sample_size() {
        let sample = PendingSample::new(vec![1, 2, 3, 4, 5], Priority::P1, 0);
        assert_eq!(sample.size(), 5);
    }

    #[test]
    fn test_pending_sample_age() {
        let sample = PendingSample::new(vec![1], Priority::P1, 0);
        std::thread::sleep(Duration::from_millis(10));
        assert!(sample.age().as_millis() >= 10);
    }

    #[test]
    fn test_metrics_success_rate() {
        let mut m = WriterPacerMetrics::default();
        assert!((m.success_rate() - 1.0).abs() < 0.01); // No samples = 100%

        m.enqueued_p1 = 10;
        m.sent_p1 = 8;
        m.dropped_p1 = 2;

        assert!((m.success_rate() - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_enqueue_blocking_immediate() {
        let mut pacer = WriterPacer::new(make_config());

        // Should succeed immediately if queue has space
        let result =
            pacer.enqueue_blocking(vec![1, 2, 3], Priority::P0, Duration::from_millis(100));
        assert!(result.is_ok());
        assert_eq!(pacer.queue_lengths().0, 1);
    }

    #[test]
    fn test_enqueue_blocking_timeout() {
        let mut config = make_config();
        config.max_queue_p0 = 1;
        let mut pacer = WriterPacer::new(config);

        // Fill the queue
        pacer.enqueue(vec![1], Priority::P0).expect("ok");

        // Should timeout since queue is full
        let start = Instant::now();
        let result = pacer.enqueue_blocking(vec![2], Priority::P0, Duration::from_millis(50));
        let elapsed = start.elapsed();

        assert_eq!(result, Err(EnqueueError::Timeout));
        assert!(elapsed >= Duration::from_millis(50));
        assert!(elapsed < Duration::from_millis(100)); // Shouldn't take too long
    }

    #[test]
    fn test_enqueue_blocking_zero_timeout() {
        let mut config = make_config();
        config.max_queue_p0 = 1;
        let mut pacer = WriterPacer::new(config);

        // Fill the queue
        pacer.enqueue(vec![1], Priority::P0).expect("ok");

        // Zero timeout should fail immediately
        let result = pacer.enqueue_blocking(vec![2], Priority::P0, Duration::ZERO);
        assert_eq!(result, Err(EnqueueError::Timeout));
    }
}
