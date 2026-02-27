// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Metrics collection with atomic counters and latency histograms.
#![allow(missing_docs)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Field data type for telemetry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DType {
    U64,
    I64,
    F64,
    U32,
    Bytes,
}

/// Single telemetry field (tag + type + value)
#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub tag: u16,
    pub dtype: DType,
    pub value_u64: u64, // union, reinterpret per dtype
}

/// Telemetry frame (binary fixed-width LE)
#[derive(Debug)]
pub struct Frame {
    pub ts_ns: u64,
    pub fields: Vec<Field>,
}

impl Frame {
    pub fn new(ts_ns: u64) -> Self {
        Self {
            ts_ns,
            fields: Vec::new(),
        }
    }

    pub fn push_field(&mut self, field: Field) {
        self.fields.push(field);
    }
}

// Metric tag constants
pub const TAG_PARTICIPANT_ID: u16 = 1;
pub const TAG_MESSAGES_SENT: u16 = 10;
pub const TAG_MESSAGES_RECEIVED: u16 = 11;
pub const TAG_MESSAGES_DROPPED: u16 = 12;
pub const TAG_BYTES_SENT: u16 = 13;
pub const TAG_LATENCY_P50: u16 = 20;
pub const TAG_LATENCY_P99: u16 = 21;
pub const TAG_LATENCY_P999: u16 = 22;
pub const TAG_MERGE_FULL_COUNT: u16 = 40;
pub const TAG_WOULD_BLOCK_COUNT: u16 = 41;
pub const TAG_CACHE_INSERT_ERRORS: u16 = 42;
pub const TAG_TRANSPORT_ERRORS: u16 = 43;

/// Metrics collector with atomic counters and latency histogram
///
/// Thread-safe: counters use atomics (Relaxed ordering), latencies use Mutex.
///
/// # Performance
/// - Counter increment: < 5 ns (atomic Relaxed)
/// - Latency sample: < 500 ns (Mutex lock + push)
/// - Snapshot: < 1 us (load all counters + sort latencies)
pub struct MetricsCollector {
    /// Global counters (thread-safe atomic)
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    messages_dropped: AtomicU64,
    bytes_sent: AtomicU64,
    merge_full: AtomicU64,
    would_block: AtomicU64,
    cache_insert_errors: AtomicU64,
    transport_errors: AtomicU64,

    /// Latency histogram (ring buffer of samples)
    latency_samples: Mutex<VecDeque<u64>>,
    max_samples: usize,
}

impl MetricsCollector {
    /// Create new metrics collector
    ///
    /// # Arguments
    /// - `max_samples`: Maximum latency samples to keep (default: 10,000)
    pub fn new() -> Self {
        Self::with_capacity(10_000)
    }

    /// Create metrics collector with custom capacity
    pub fn with_capacity(max_samples: usize) -> Self {
        Self {
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            messages_dropped: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            merge_full: AtomicU64::new(0),
            would_block: AtomicU64::new(0),
            cache_insert_errors: AtomicU64::new(0),
            transport_errors: AtomicU64::new(0),
            latency_samples: Mutex::new(VecDeque::with_capacity(max_samples)),
            max_samples,
        }
    }

    /// Increment messages sent counter
    pub fn increment_sent(&self, count: u64) {
        self.messages_sent.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment messages received counter
    pub fn increment_received(&self, count: u64) {
        self.messages_received.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment messages dropped counter
    pub fn increment_dropped(&self, count: u64) {
        self.messages_dropped.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment bytes sent counter
    pub fn increment_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment merge full counter
    pub fn increment_merge_full(&self, count: u64) {
        self.merge_full.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment would block counter
    pub fn increment_would_block(&self, count: u64) {
        self.would_block.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment cache insert errors counter (Reliable QoS HistoryCache)
    pub fn increment_cache_insert_errors(&self, count: u64) {
        self.cache_insert_errors.fetch_add(count, Ordering::Relaxed);
    }

    pub fn increment_transport_errors(&self, count: u64) {
        self.transport_errors.fetch_add(count, Ordering::Relaxed);
    }

    /// Add latency sample
    ///
    /// # Arguments
    /// - `start_ns`: Start timestamp (nanoseconds)
    /// - `end_ns`: End timestamp (nanoseconds)
    ///
    /// Latency is computed as (end_ns - start_ns).
    /// If buffer is full, oldest sample is dropped (FIFO).
    pub fn add_latency_sample(&self, start_ns: u64, end_ns: u64) {
        let latency = end_ns.saturating_sub(start_ns);

        if let Ok(mut samples) = self.latency_samples.lock() {
            if samples.len() >= self.max_samples {
                samples.pop_front(); // Drop oldest if full
            }
            samples.push_back(latency);
        }
    }

    /// Snapshot current metrics into a Frame
    ///
    /// # Returns
    /// Frame with all current counters and latency percentiles.
    ///
    /// # Performance
    /// Target: < 1 us (load counters + sort latencies)
    pub fn snapshot(&self) -> Frame {
        let now = current_time_ns();
        let mut frame = Frame::new(now);

        // Snapshot all atomic counters
        snapshot_counter_fields(&mut frame, self);

        // Compute latency percentiles if samples available
        if let Ok(samples) = self.latency_samples.lock() {
            if !samples.is_empty() {
                snapshot_latency_percentiles(&mut frame, &samples);
            }
        }

        frame
    }

    /// Get messages sent count (snapshot)
    pub fn messages_sent(&self) -> u64 {
        self.messages_sent.load(Ordering::Relaxed)
    }

    /// Get messages dropped count (snapshot)
    pub fn messages_dropped(&self) -> u64 {
        self.messages_dropped.load(Ordering::Relaxed)
    }

    /// Get latency sample count
    pub fn latency_sample_count(&self) -> usize {
        self.latency_samples.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// Snapshot all atomic counters into Frame fields
fn snapshot_counter_fields(frame: &mut Frame, collector: &MetricsCollector) {
    frame.push_field(Field {
        tag: TAG_MESSAGES_SENT,
        dtype: DType::U64,
        value_u64: collector.messages_sent.load(Ordering::Relaxed),
    });

    frame.push_field(Field {
        tag: TAG_MESSAGES_RECEIVED,
        dtype: DType::U64,
        value_u64: collector.messages_received.load(Ordering::Relaxed),
    });

    frame.push_field(Field {
        tag: TAG_MESSAGES_DROPPED,
        dtype: DType::U64,
        value_u64: collector.messages_dropped.load(Ordering::Relaxed),
    });

    frame.push_field(Field {
        tag: TAG_BYTES_SENT,
        dtype: DType::U64,
        value_u64: collector.bytes_sent.load(Ordering::Relaxed),
    });

    frame.push_field(Field {
        tag: TAG_MERGE_FULL_COUNT,
        dtype: DType::U64,
        value_u64: collector.merge_full.load(Ordering::Relaxed),
    });

    frame.push_field(Field {
        tag: TAG_WOULD_BLOCK_COUNT,
        dtype: DType::U64,
        value_u64: collector.would_block.load(Ordering::Relaxed),
    });

    frame.push_field(Field {
        tag: TAG_CACHE_INSERT_ERRORS,
        dtype: DType::U64,
        value_u64: collector.cache_insert_errors.load(Ordering::Relaxed),
    });

    frame.push_field(Field {
        tag: TAG_TRANSPORT_ERRORS,
        dtype: DType::U64,
        value_u64: collector.transport_errors.load(Ordering::Relaxed),
    });
}

/// Compute and add latency percentiles to Frame
fn snapshot_latency_percentiles(frame: &mut Frame, samples: &VecDeque<u64>) {
    let mut sorted: Vec<u64> = samples.iter().copied().collect();
    sorted.sort_unstable();

    let p50_idx = (sorted.len() * 50) / 100;
    let p99_idx = (sorted.len() * 99) / 100;
    let p999_idx = (sorted.len() * 999) / 1000;

    frame.push_field(Field {
        tag: TAG_LATENCY_P50,
        dtype: DType::U64,
        value_u64: sorted[p50_idx.min(sorted.len() - 1)],
    });

    frame.push_field(Field {
        tag: TAG_LATENCY_P99,
        dtype: DType::U64,
        value_u64: sorted[p99_idx.min(sorted.len() - 1)],
    });

    frame.push_field(Field {
        tag: TAG_LATENCY_P999,
        dtype: DType::U64,
        value_u64: sorted[p999_idx.min(sorted.len() - 1)],
    });
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current time in nanoseconds since epoch
pub fn current_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_increment_sent() {
        let m = MetricsCollector::new();
        m.increment_sent(10);
        m.increment_sent(5);

        assert_eq!(m.messages_sent(), 15);
    }

    #[test]
    fn test_metrics_increment_dropped() {
        let m = MetricsCollector::new();
        m.increment_dropped(7);

        assert_eq!(m.messages_dropped(), 7);
    }

    #[test]
    fn test_metrics_snapshot_fields() {
        let m = MetricsCollector::new();
        m.increment_sent(100);
        m.increment_dropped(5);

        let frame = m.snapshot();

        // Find sent field
        let sent = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_MESSAGES_SENT)
            .map_or(0, |f| f.value_u64);

        assert_eq!(sent, 100);
    }

    #[test]
    fn test_latency_samples() {
        let m = MetricsCollector::new();

        // Add samples: 1ns, 2ns, ..., 100ns
        for i in 1..=100 {
            m.add_latency_sample(0, i);
        }

        assert_eq!(m.latency_sample_count(), 100);

        let frame = m.snapshot();

        // Find p50, p99
        let p50 = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_LATENCY_P50)
            .map_or(0, |f| f.value_u64);

        let p99 = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_LATENCY_P99)
            .map_or(0, |f| f.value_u64);

        // p50 should be around 50ns
        assert!((45..=55).contains(&p50));

        // p99 should be around 99ns
        assert!((95..=100).contains(&p99));
    }

    #[test]
    fn test_latency_buffer_overflow() {
        let m = MetricsCollector::with_capacity(10);

        // Add 15 samples (buffer max = 10)
        for i in 1..=15 {
            m.add_latency_sample(0, i);
        }

        // Should only keep last 10
        assert_eq!(m.latency_sample_count(), 10);
    }

    #[test]
    fn test_snapshot_empty_latencies() {
        let m = MetricsCollector::new();
        m.increment_sent(42);

        let frame = m.snapshot();

        // Should have counters but no latency fields
        let has_sent = frame.fields.iter().any(|f| f.tag == TAG_MESSAGES_SENT);
        let has_p50 = frame.fields.iter().any(|f| f.tag == TAG_LATENCY_P50);

        assert!(has_sent);
        assert!(!has_p50); // No latency samples -> no percentiles
    }

    #[test]
    fn test_concurrent_increments() {
        use std::sync::Arc;
        use std::thread;

        let m = Arc::new(MetricsCollector::new());
        let mut handles = vec![];

        // Spawn 10 threads, each incrementing sent by 100
        for _ in 0..10 {
            let m_clone = m.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    m_clone.increment_sent(1);
                }
            }));
        }

        for h in handles {
            h.join().expect("Thread should complete successfully");
        }

        // Total should be 10 * 100 = 1000
        assert_eq!(m.messages_sent(), 1000);
    }
}
