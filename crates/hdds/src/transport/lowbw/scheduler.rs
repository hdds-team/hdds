// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TX scheduler for LBW transport.
//!
//! The scheduler manages outbound frame transmission with:
//! - **Priority queues**: P0 (critical), P1 (important), P2 (droppable)
//! - **Token bucket**: Rate limiting in bytes/sec
//! - **Batching**: Combine multiple records into frames
//! - **P0 immediate flush**: Critical data bypasses batching
//!
//! # Priority Levels
//!
//! - **P0**: Commands, state sync, CONTROL messages - immediate flush, no batching
//! - **P1**: Important sensor data - batched, sent when token allows
//! - **P2**: Telemetry - batched, dropped under congestion
//!
//! # Token Bucket Algorithm
//!
//! The token bucket limits bandwidth to prevent overwhelming constrained links.
//! Tokens are added at `rate_bps / 8` bytes per second.
//! Each frame consumes tokens equal to its size.
//!
//! # Usage
//!
//! ```ignore
//! let config = SchedulerConfig {
//!     rate_bps: 9600,           // 9600 bits per second
//!     bucket_size: 512,         // Max burst
//!     batch_window_ms: 100,     // Batch for 100ms
//!     ..Default::default()
//! };
//! let mut scheduler = Scheduler::new(config);
//!
//! // Enqueue records
//! scheduler.enqueue(Priority::P0, record_bytes, stream_id); // Immediate
//! scheduler.enqueue(Priority::P1, record_bytes, stream_id); // Batched
//! scheduler.enqueue(Priority::P2, record_bytes, stream_id); // Droppable
//!
//! // In event loop:
//! while let Some(frame) = scheduler.poll_frame(session_id, frame_seq) {
//!     link.send(&frame)?;
//! }
//! ```

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::frame::{encode_frame, FrameHeader};
use super::record::Priority;

/// Scheduler configuration.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Target bandwidth in bits per second.
    pub rate_bps: u64,
    /// Token bucket capacity in bytes.
    pub bucket_size: usize,
    /// Batch window for P1/P2 in milliseconds.
    pub batch_window_ms: u64,
    /// Maximum frame size.
    pub max_frame_size: usize,
    /// P0 queue capacity (records).
    pub p0_capacity: usize,
    /// P1 queue capacity (records).
    pub p1_capacity: usize,
    /// P2 queue capacity (records).
    pub p2_capacity: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            rate_bps: 9600,       // 9600 bps default
            bucket_size: 512,     // Half second burst at 9600 bps
            batch_window_ms: 100, // 100ms batch window
            max_frame_size: 256,  // Default MTU
            p0_capacity: 32,      // P0 is critical, keep small
            p1_capacity: 64,      // P1 important data
            p2_capacity: 128,     // P2 telemetry, can be larger
        }
    }
}

impl SchedulerConfig {
    /// Create config for slow serial link (9600 bps).
    pub fn slow_serial() -> Self {
        Self {
            rate_bps: 9600,
            bucket_size: 256,
            batch_window_ms: 200,
            max_frame_size: 128,
            ..Default::default()
        }
    }

    /// Create config for tactical radio (19.2 kbps).
    pub fn tactical_radio() -> Self {
        Self {
            rate_bps: 19200,
            bucket_size: 512,
            batch_window_ms: 100,
            max_frame_size: 256,
            ..Default::default()
        }
    }

    /// Create config for satellite (400 kbps).
    pub fn satellite() -> Self {
        Self {
            rate_bps: 400_000,
            bucket_size: 4096,
            batch_window_ms: 50,
            max_frame_size: 1024,
            ..Default::default()
        }
    }
}

/// Queued record.
#[derive(Debug, Clone)]
struct QueuedRecord {
    /// Record bytes (including header).
    data: Vec<u8>,
    /// Stream ID (for tracking).
    #[allow(dead_code)] // Used for tracking/debugging purposes
    stream_id: u8,
    /// Enqueue time.
    #[allow(dead_code)] // Used for latency tracking and timeout handling
    enqueued_at: Instant,
}

/// Scheduler statistics.
#[derive(Debug, Default, Clone)]
pub struct SchedulerStats {
    /// Records enqueued (total).
    pub records_enqueued: u64,
    /// Records dropped (P2 overflow).
    pub records_dropped: u64,
    /// Frames sent.
    pub frames_sent: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// P0 flushes (immediate sends).
    pub p0_flushes: u64,
    /// Token stalls (waiting for tokens).
    pub token_stalls: u64,
    /// Current token level.
    pub current_tokens: usize,
    /// P0 queue depth.
    pub p0_depth: usize,
    /// P1 queue depth.
    pub p1_depth: usize,
    /// P2 queue depth.
    pub p2_depth: usize,
}

/// TX scheduler for LBW transport.
pub struct Scheduler {
    /// Configuration.
    config: SchedulerConfig,
    /// Token bucket - current tokens.
    tokens: usize,
    /// Last token refill time.
    last_refill: Instant,
    /// P0 queue (critical).
    p0_queue: VecDeque<QueuedRecord>,
    /// P1 queue (important).
    p1_queue: VecDeque<QueuedRecord>,
    /// P2 queue (droppable).
    p2_queue: VecDeque<QueuedRecord>,
    /// Last batch send time.
    last_batch_time: Instant,
    /// Statistics.
    stats: SchedulerStats,
    /// Frame buffer for encoding.
    frame_buf: Vec<u8>,
}

impl Scheduler {
    /// Create a new scheduler.
    pub fn new(config: SchedulerConfig) -> Self {
        let bucket_size = config.bucket_size;
        Self {
            config,
            tokens: bucket_size, // Start full
            last_refill: Instant::now(),
            p0_queue: VecDeque::new(),
            p1_queue: VecDeque::new(),
            p2_queue: VecDeque::new(),
            last_batch_time: Instant::now(),
            stats: SchedulerStats::default(),
            frame_buf: vec![0u8; 2048], // Max frame buffer
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> SchedulerStats {
        let mut stats = self.stats.clone();
        stats.current_tokens = self.tokens;
        stats.p0_depth = self.p0_queue.len();
        stats.p1_depth = self.p1_queue.len();
        stats.p2_depth = self.p2_queue.len();
        stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = SchedulerStats::default();
    }

    /// Enqueue a record for transmission.
    ///
    /// # Arguments
    /// * `priority` - Record priority (P0, P1, P2)
    /// * `data` - Record bytes (including header)
    /// * `stream_id` - Stream ID for tracking
    ///
    /// # Returns
    /// * `true` if enqueued successfully
    /// * `false` if dropped (queue full for P2)
    pub fn enqueue(&mut self, priority: Priority, data: Vec<u8>, stream_id: u8) -> bool {
        let record = QueuedRecord {
            data,
            stream_id,
            enqueued_at: Instant::now(),
        };

        let success = match priority {
            Priority::P0 => {
                // P0 always enqueued (will be flushed immediately)
                if self.p0_queue.len() < self.config.p0_capacity {
                    self.p0_queue.push_back(record);
                    true
                } else {
                    // P0 overflow is critical - drop oldest
                    self.p0_queue.pop_front();
                    self.p0_queue.push_back(record);
                    true
                }
            }
            Priority::P1 => {
                if self.p1_queue.len() < self.config.p1_capacity {
                    self.p1_queue.push_back(record);
                    true
                } else {
                    // P1 overflow - drop oldest to make room
                    self.p1_queue.pop_front();
                    self.p1_queue.push_back(record);
                    true
                }
            }
            Priority::P2 => {
                if self.p2_queue.len() < self.config.p2_capacity {
                    self.p2_queue.push_back(record);
                    true
                } else {
                    // P2 overflow - drop new record (LIFO drop)
                    self.stats.records_dropped += 1;
                    false
                }
            }
        };

        if success {
            self.stats.records_enqueued += 1;
        }

        success
    }

    /// Check if there's urgent data (P0) waiting.
    pub fn has_urgent(&self) -> bool {
        !self.p0_queue.is_empty()
    }

    /// Check if any queue has data.
    pub fn has_data(&self) -> bool {
        !self.p0_queue.is_empty() || !self.p1_queue.is_empty() || !self.p2_queue.is_empty()
    }

    /// Refill token bucket based on elapsed time.
    fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let elapsed_us = elapsed.as_micros() as u64;

        // Calculate tokens to add (rate_bps / 8 bytes per second)
        // tokens = elapsed_us * (rate_bps / 8) / 1_000_000
        let rate_bytes_per_sec = self.config.rate_bps / 8;
        let new_tokens = (elapsed_us * rate_bytes_per_sec / 1_000_000) as usize;

        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.config.bucket_size);
            self.last_refill = now;
        }
    }

    /// Try to consume tokens for sending.
    ///
    /// Returns `true` if tokens were consumed.
    fn try_consume_tokens(&mut self, bytes: usize) -> bool {
        self.refill_tokens();

        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            self.stats.token_stalls += 1;
            false
        }
    }

    /// Check if batch window has elapsed.
    fn batch_window_elapsed(&self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_batch_time);
        elapsed >= Duration::from_millis(self.config.batch_window_ms)
    }

    /// Poll for a frame to send.
    ///
    /// Returns encoded frame bytes if there's data to send and tokens available.
    ///
    /// # Arguments
    /// * `session_id` - Session ID for frame header
    /// * `frame_seq` - Frame sequence number (will be incremented)
    pub fn poll_frame(&mut self, session_id: u16, frame_seq: &mut u32) -> Option<Vec<u8>> {
        // Priority 1: P0 immediate flush
        if !self.p0_queue.is_empty() {
            return self.build_frame(Priority::P0, session_id, frame_seq);
        }

        // Priority 2: P1/P2 if batch window elapsed or queue getting full
        if self.batch_window_elapsed() || self.should_flush_batch() {
            // Try P1 first
            if !self.p1_queue.is_empty() {
                return self.build_frame(Priority::P1, session_id, frame_seq);
            }
            // Then P2
            if !self.p2_queue.is_empty() {
                return self.build_frame(Priority::P2, session_id, frame_seq);
            }
        }

        None
    }

    /// Check if we should flush batch early (queue getting full).
    fn should_flush_batch(&self) -> bool {
        // Flush if P1 is >75% full
        if self.p1_queue.len() > self.config.p1_capacity * 3 / 4 {
            return true;
        }
        // Flush if P2 is >90% full
        if self.p2_queue.len() > self.config.p2_capacity * 9 / 10 {
            return true;
        }
        false
    }

    /// Build a frame from the specified priority queue.
    fn build_frame(
        &mut self,
        priority: Priority,
        session_id: u16,
        frame_seq: &mut u32,
    ) -> Option<Vec<u8>> {
        let is_p0 = matches!(priority, Priority::P0);
        let max_payload = self.config.max_frame_size.saturating_sub(16); // Reserve for header + CRC

        // First pass: check if queue is empty
        {
            let queue = match priority {
                Priority::P0 => &self.p0_queue,
                Priority::P1 => &self.p1_queue,
                Priority::P2 => &self.p2_queue,
            };
            if queue.is_empty() {
                return None;
            }
        }

        // Collect records that fit in the frame
        let mut records_data = Vec::with_capacity(max_payload);
        let mut records_to_send = Vec::new();

        {
            let queue = match priority {
                Priority::P0 => &mut self.p0_queue,
                Priority::P1 => &mut self.p1_queue,
                Priority::P2 => &mut self.p2_queue,
            };

            while let Some(record) = queue.front() {
                if records_data.len() + record.data.len() > max_payload {
                    break;
                }
                #[allow(clippy::unwrap_used)] // front() returned Some, pop_front() cannot be None
                let record = queue.pop_front().unwrap();
                records_data.extend_from_slice(&record.data);
                records_to_send.push(record);
            }
        }

        if records_data.is_empty() {
            return None;
        }

        // Calculate frame size
        let frame_size = records_data.len() + 16; // Conservative estimate

        // Check token bucket (P0 bypasses for first frame)
        if !is_p0 && !self.try_consume_tokens(frame_size) {
            // Put records back
            let queue = match priority {
                Priority::P0 => &mut self.p0_queue,
                Priority::P1 => &mut self.p1_queue,
                Priority::P2 => &mut self.p2_queue,
            };
            for record in records_to_send.into_iter().rev() {
                queue.push_front(record);
            }
            return None;
        }

        // For P0, always send but still track token usage
        if is_p0 {
            self.refill_tokens();
            self.tokens = self.tokens.saturating_sub(frame_size);
            self.stats.p0_flushes += 1;
        }

        // Encode frame
        let header = FrameHeader::new(session_id, *frame_seq);
        *frame_seq = frame_seq.wrapping_add(1);

        match encode_frame(&header, &records_data, &mut self.frame_buf) {
            Ok(len) => {
                self.stats.frames_sent += 1;
                self.stats.bytes_sent += len as u64;
                self.last_batch_time = Instant::now();
                Some(self.frame_buf[..len].to_vec())
            }
            Err(_) => {
                // Encoding failed - put records back
                let queue = match priority {
                    Priority::P0 => &mut self.p0_queue,
                    Priority::P1 => &mut self.p1_queue,
                    Priority::P2 => &mut self.p2_queue,
                };
                for record in records_to_send.into_iter().rev() {
                    queue.push_front(record);
                }
                None
            }
        }
    }

    /// Clear all queues.
    pub fn clear(&mut self) {
        self.p0_queue.clear();
        self.p1_queue.clear();
        self.p2_queue.clear();
    }

    /// Get current token level.
    pub fn token_level(&self) -> usize {
        self.tokens
    }

    /// Get queue depths.
    pub fn queue_depths(&self) -> (usize, usize, usize) {
        (
            self.p0_queue.len(),
            self.p1_queue.len(),
            self.p2_queue.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(size: usize) -> Vec<u8> {
        vec![0u8; size]
    }

    #[test]
    fn test_enqueue_p0() {
        let mut scheduler = Scheduler::new(SchedulerConfig::default());

        assert!(scheduler.enqueue(Priority::P0, make_record(10), 1));
        assert_eq!(scheduler.stats().records_enqueued, 1);
        assert!(scheduler.has_urgent());
    }

    #[test]
    fn test_enqueue_p2_overflow() {
        let config = SchedulerConfig {
            p2_capacity: 2,
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        assert!(scheduler.enqueue(Priority::P2, make_record(10), 1));
        assert!(scheduler.enqueue(Priority::P2, make_record(10), 1));
        // Third should be dropped
        assert!(!scheduler.enqueue(Priority::P2, make_record(10), 1));

        assert_eq!(scheduler.stats().records_dropped, 1);
    }

    #[test]
    fn test_p0_immediate_flush() {
        let mut scheduler = Scheduler::new(SchedulerConfig::default());

        scheduler.enqueue(Priority::P0, make_record(10), 1);

        let mut frame_seq = 0u32;
        let frame = scheduler.poll_frame(1, &mut frame_seq);

        assert!(frame.is_some());
        assert_eq!(scheduler.stats().p0_flushes, 1);
    }

    #[test]
    fn test_p1_batching() {
        let config = SchedulerConfig {
            batch_window_ms: 100,
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        scheduler.enqueue(Priority::P1, make_record(10), 1);

        // Immediate poll should return None (batch window not elapsed)
        let mut frame_seq = 0u32;
        let frame = scheduler.poll_frame(1, &mut frame_seq);
        assert!(frame.is_none());

        // Wait for batch window
        std::thread::sleep(Duration::from_millis(110));

        let frame = scheduler.poll_frame(1, &mut frame_seq);
        assert!(frame.is_some());
    }

    #[test]
    fn test_priority_ordering() {
        let config = SchedulerConfig {
            batch_window_ms: 0, // Disable batching for test
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        // Enqueue in reverse priority order
        scheduler.enqueue(Priority::P2, make_record(10), 3);
        scheduler.enqueue(Priority::P1, make_record(10), 2);
        scheduler.enqueue(Priority::P0, make_record(10), 1);

        let mut frame_seq = 0u32;

        // P0 should be sent first
        let _ = scheduler.poll_frame(1, &mut frame_seq);
        assert!(scheduler.p0_queue.is_empty());
        assert!(!scheduler.p1_queue.is_empty());

        // P1 should be sent next
        let _ = scheduler.poll_frame(1, &mut frame_seq);
        assert!(scheduler.p1_queue.is_empty());
        assert!(!scheduler.p2_queue.is_empty());

        // P2 last
        let _ = scheduler.poll_frame(1, &mut frame_seq);
        assert!(scheduler.p2_queue.is_empty());
    }

    #[test]
    fn test_token_bucket_refill() {
        let config = SchedulerConfig {
            rate_bps: 8000,   // 1000 bytes/sec
            bucket_size: 100, // Small bucket
            batch_window_ms: 0,
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        // Drain tokens
        scheduler.tokens = 0;

        // Wait a bit for refill
        std::thread::sleep(Duration::from_millis(50));
        scheduler.refill_tokens();

        // Should have ~50 tokens (50ms * 1000 bytes/sec)
        assert!(scheduler.tokens > 30);
        assert!(scheduler.tokens < 70);
    }

    #[test]
    fn test_token_bucket_limit() {
        let config = SchedulerConfig {
            rate_bps: 8000,  // 1000 bytes/sec
            bucket_size: 50, // Small bucket
            batch_window_ms: 0,
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        // Bucket starts full
        assert_eq!(scheduler.tokens, 50);

        // Even after waiting, shouldn't exceed bucket size
        std::thread::sleep(Duration::from_millis(100));
        scheduler.refill_tokens();
        assert!(scheduler.tokens <= 50);
    }

    #[test]
    fn test_token_stall() {
        let config = SchedulerConfig {
            rate_bps: 8000,
            bucket_size: 10, // Very small bucket
            batch_window_ms: 0,
            max_frame_size: 256,
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        // Enqueue large P1 record (needs more tokens than available)
        scheduler.enqueue(Priority::P1, make_record(100), 1);

        // Drain tokens
        scheduler.tokens = 0;

        let mut frame_seq = 0u32;
        let frame = scheduler.poll_frame(1, &mut frame_seq);

        // Should stall (no tokens)
        assert!(frame.is_none());
        assert!(scheduler.stats().token_stalls > 0);
    }

    #[test]
    fn test_multiple_records_in_frame() {
        let config = SchedulerConfig {
            batch_window_ms: 0,
            max_frame_size: 256,
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        // Enqueue multiple small records
        scheduler.enqueue(Priority::P1, make_record(20), 1);
        scheduler.enqueue(Priority::P1, make_record(20), 1);
        scheduler.enqueue(Priority::P1, make_record(20), 1);

        let mut frame_seq = 0u32;
        let frame = scheduler.poll_frame(1, &mut frame_seq);

        assert!(frame.is_some());
        // All records should be in one frame
        assert!(scheduler.p1_queue.is_empty());
        assert_eq!(scheduler.stats().frames_sent, 1);
    }

    #[test]
    fn test_frame_size_limit() {
        let config = SchedulerConfig {
            batch_window_ms: 0,
            max_frame_size: 50, // Very small
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        // Enqueue records that exceed frame size
        scheduler.enqueue(Priority::P1, make_record(20), 1);
        scheduler.enqueue(Priority::P1, make_record(20), 1);
        scheduler.enqueue(Priority::P1, make_record(20), 1);

        let mut frame_seq = 0u32;

        // First frame should take some records
        let frame1 = scheduler.poll_frame(1, &mut frame_seq);
        assert!(frame1.is_some());

        // Should still have records left
        assert!(!scheduler.p1_queue.is_empty());

        // Second frame for remaining
        let frame2 = scheduler.poll_frame(1, &mut frame_seq);
        assert!(frame2.is_some());
    }

    #[test]
    fn test_clear() {
        let mut scheduler = Scheduler::new(SchedulerConfig::default());

        scheduler.enqueue(Priority::P0, make_record(10), 1);
        scheduler.enqueue(Priority::P1, make_record(10), 1);
        scheduler.enqueue(Priority::P2, make_record(10), 1);

        scheduler.clear();

        let (p0, p1, p2) = scheduler.queue_depths();
        assert_eq!((p0, p1, p2), (0, 0, 0));
    }

    #[test]
    fn test_config_presets() {
        let slow = SchedulerConfig::slow_serial();
        assert_eq!(slow.rate_bps, 9600);

        let tactical = SchedulerConfig::tactical_radio();
        assert_eq!(tactical.rate_bps, 19200);

        let satellite = SchedulerConfig::satellite();
        assert_eq!(satellite.rate_bps, 400_000);
    }

    #[test]
    fn test_frame_sequence_increment() {
        let config = SchedulerConfig {
            batch_window_ms: 0,
            max_frame_size: 50, // Small frame size to force multiple frames
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        // Enqueue records that won't fit in one frame
        scheduler.enqueue(Priority::P0, make_record(30), 1);
        scheduler.enqueue(Priority::P0, make_record(30), 1);

        let mut frame_seq = 100u32;

        scheduler.poll_frame(1, &mut frame_seq);
        assert_eq!(frame_seq, 101);

        scheduler.poll_frame(1, &mut frame_seq);
        assert_eq!(frame_seq, 102);
    }

    #[test]
    fn test_has_data() {
        let mut scheduler = Scheduler::new(SchedulerConfig::default());

        assert!(!scheduler.has_data());

        scheduler.enqueue(Priority::P2, make_record(10), 1);
        assert!(scheduler.has_data());
    }

    #[test]
    fn test_early_flush_on_queue_full() {
        let config = SchedulerConfig {
            batch_window_ms: 10000, // Long window
            p1_capacity: 4,
            ..Default::default()
        };
        let mut scheduler = Scheduler::new(config);

        // Fill P1 to >75%
        scheduler.enqueue(Priority::P1, make_record(10), 1);
        scheduler.enqueue(Priority::P1, make_record(10), 1);
        scheduler.enqueue(Priority::P1, make_record(10), 1);
        scheduler.enqueue(Priority::P1, make_record(10), 1);

        // Should flush early even though batch window hasn't elapsed
        let mut frame_seq = 0u32;
        let frame = scheduler.poll_frame(1, &mut frame_seq);
        assert!(frame.is_some());
    }
}
