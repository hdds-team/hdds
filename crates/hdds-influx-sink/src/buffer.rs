// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Batching buffer for Line Protocol lines.
//!
//! Accumulates lines and flushes either when the batch is full or
//! when the configured time interval has elapsed.

use std::time::{Duration, Instant};

/// A batching buffer that collects Line Protocol strings.
///
/// Lines are accumulated until either:
/// - The buffer reaches `max_size` (size-based flush)
/// - The configured `flush_interval` has elapsed since the last flush (time-based flush)
pub struct BatchBuffer {
    lines: Vec<String>,
    max_size: usize,
    flush_interval: Duration,
    last_flush: Instant,
}

impl BatchBuffer {
    /// Create a new batch buffer.
    ///
    /// # Arguments
    /// - `max_size` - Maximum number of lines before automatic flush
    /// - `flush_interval` - Maximum time between flushes
    pub fn new(max_size: usize, flush_interval: Duration) -> Self {
        Self {
            lines: Vec::with_capacity(max_size),
            max_size,
            flush_interval,
            last_flush: Instant::now(),
        }
    }

    /// Add a line to the buffer.
    ///
    /// Returns `Some(batch)` if the buffer is now full and should be flushed,
    /// or `None` if there is still room.
    pub fn add(&mut self, line: String) -> Option<Vec<String>> {
        self.lines.push(line);
        if self.lines.len() >= self.max_size {
            Some(self.flush())
        } else {
            None
        }
    }

    /// Check if a time-based flush is due.
    pub fn should_flush(&self) -> bool {
        !self.lines.is_empty() && self.last_flush.elapsed() >= self.flush_interval
    }

    /// Flush the buffer, returning all accumulated lines and resetting the timer.
    pub fn flush(&mut self) -> Vec<String> {
        self.last_flush = Instant::now();
        std::mem::take(&mut self.lines)
    }

    /// Get the current number of buffered lines.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_buffer_returns_none_until_full() {
        let mut buf = BatchBuffer::new(3, Duration::from_secs(60));

        assert!(buf.add("line1".to_string()).is_none());
        assert_eq!(buf.len(), 1);

        assert!(buf.add("line2".to_string()).is_none());
        assert_eq!(buf.len(), 2);

        // Not full yet
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_batch_buffer_returns_batch_when_full() {
        let mut buf = BatchBuffer::new(3, Duration::from_secs(60));

        buf.add("line1".to_string());
        buf.add("line2".to_string());

        let result = buf.add("line3".to_string());
        assert!(result.is_some());

        let batch = result.unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0], "line1");
        assert_eq!(batch[1], "line2");
        assert_eq!(batch[2], "line3");

        // Buffer should be empty after flush
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_batch_buffer_time_based_flush() {
        let mut buf = BatchBuffer::new(1000, Duration::from_millis(0));

        buf.add("line1".to_string());

        // With a zero-duration interval, should_flush is immediately true
        // (after the tiny time that elapses between construction and the check)
        assert!(buf.should_flush());

        let batch = buf.flush();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0], "line1");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_batch_buffer_no_flush_when_empty() {
        let buf = BatchBuffer::new(10, Duration::from_millis(0));
        // Even with zero interval, empty buffer should not need flush
        assert!(!buf.should_flush());
    }

    #[test]
    fn test_batch_buffer_manual_flush() {
        let mut buf = BatchBuffer::new(100, Duration::from_secs(60));

        buf.add("a".to_string());
        buf.add("b".to_string());

        let batch = buf.flush();
        assert_eq!(batch.len(), 2);
        assert!(buf.is_empty());
    }
}
