// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Metrics collection with atomic counters and latency histograms.
#![allow(missing_docs)]

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
#[cfg(not(unix))]
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
pub const TAG_SAMPLES_REJECTED_RING_FULL: u16 = 44;
pub const TAG_SAMPLES_REJECTED_SLAB_EXHAUSTED: u16 = 45;

/// One counter alone on its cache line.
///
/// `messages_sent` is bumped by writer threads and `messages_received` by
/// reader threads. Sharing a line, every sample of a cross-thread stream
/// would move that line between the two cores twice; padding keeps each
/// side's counter in its own line.
#[repr(align(64))]
struct PaddedCounter(AtomicU64);

impl PaddedCounter {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

/// Metrics collector with atomic counters and latency histogram
///
/// Thread-safe: counters use atomics (Relaxed ordering), latencies use a
/// lock-free atomic ring buffer.
///
/// # What each counter counts
/// Each counter is raised at the one place every path of its kind goes
/// through, so it does not depend on the transport (intra-process, shared
/// memory, UDP) or on the accessor the application uses:
///
/// - `messages_sent`: one per `DataWriter` write that succeeded (every
///   `write*` variant, typed, keyed, raw, C ABI), whether or not a reader
///   is matched. Dispose and unregister are lifecycle changes, not
///   messages.
/// - `bytes_sent`: the serialized payload bytes of those same writes (the
///   encoded sample, before RTPS framing, fragmentation or encryption),
///   so `bytes_sent / messages_sent` is the mean sample size.
/// - `messages_received`: one per sample that lands in a `DataReader`'s
///   history, from any transport, counted when it is deposited there (the
///   history cache, the first place the reader owns it as a sample), so
///   `read`, `take`, `take_batch`, `take_with_info`, ... all see the same
///   figure. A duplicate refused by the history is not a reception. The
///   deposit happens when the application next accesses the reader (the
///   ring-to-history pump runs inside the accessors), so a sample still
///   queued in the transport ring is not counted yet.
/// - `messages_dropped`: samples discarded after arriving, for want of
///   room (ring or history replaced the oldest unread sample) or because
///   the reader's content filter refused them, plus intra-process writes
///   that could not be delivered. QoS-driven expiry (lifespan,
///   TIME_BASED_FILTER, source-timestamp ordering) is not a drop.
/// - `merge_full`: a co-located reader could not take a sample for lack
///   of room (a writer's local delivery was refused or timed out).
/// - `would_block`: a writer operation (write, dispose, unregister) came
///   back `WouldBlock` (slab pool or writer history out of memory).
/// - `cache_insert_errors`: an insert into a writer's `HistoryCache` was
///   refused, whichever path made it.
/// - `transport_errors`: a writer's UDP send failed (data and
///   dispose/unregister changes).
/// - `samples_rejected_*`: every `SampleRejected` report with reason
///   `ResourceLimit` is counted in exactly one of the two.
///
/// # Performance
/// - Counter increment: < 5 ns (atomic Relaxed)
/// - Latency sample: < 10 ns (atomic fetch_add + store, no lock)
/// - Snapshot: < 1 us (load all counters + sort latencies)
pub struct MetricsCollector {
    /// Global counters (thread-safe atomic)
    messages_sent: AtomicU64,
    /// Reader side: its own cache line (see [`PaddedCounter`]).
    messages_received: PaddedCounter,
    messages_dropped: AtomicU64,
    bytes_sent: AtomicU64,
    merge_full: AtomicU64,
    would_block: AtomicU64,
    cache_insert_errors: AtomicU64,
    transport_errors: AtomicU64,
    /// A reader's own ring or history bound was full when a sample tried
    /// to land. For a RELIABLE network reader the sample was already
    /// dedup'd and control-plane-credited: it is discarded and never
    /// repaired, since the writer is never asked to resend a sequence it
    /// was already acknowledged for. A co-located reader's refusal is
    /// counted here too.
    samples_rejected_ring_full: AtomicU64,
    /// Same rejection as above, at the slab-pool-exhausted admission exit
    /// instead of the ring-full one.
    samples_rejected_slab_exhausted: AtomicU64,

    /// Latency histogram (lock-free ring of samples, oldest overwritten)
    latency_ring: Box<[AtomicU64]>,
    /// Monotonic write counter into `latency_ring`
    latency_write_idx: AtomicUsize,
    /// Fastmod magic for the ring length: ceil(2^128 / len), or 0 when
    /// the ring is empty. See [`Self::fastmod`].
    latency_mod_magic: u128,
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
            messages_received: PaddedCounter::new(),
            messages_dropped: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            merge_full: AtomicU64::new(0),
            would_block: AtomicU64::new(0),
            cache_insert_errors: AtomicU64::new(0),
            transport_errors: AtomicU64::new(0),
            samples_rejected_ring_full: AtomicU64::new(0),
            samples_rejected_slab_exhausted: AtomicU64::new(0),
            latency_ring: (0..max_samples)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            latency_write_idx: AtomicUsize::new(0),
            // ceil(2^128 / len); wraps to 0 for len == 1 (fastmod then
            // yields 0, matching i % 1).
            latency_mod_magic: if max_samples > 0 {
                (u128::MAX / (max_samples as u128)).wrapping_add(1)
            } else {
                0
            },
        }
    }

    /// Increment messages sent counter
    pub fn increment_sent(&self, count: u64) {
        self.messages_sent.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment messages received counter
    pub fn increment_received(&self, count: u64) {
        self.messages_received.0.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment messages dropped counter
    pub fn increment_dropped(&self, count: u64) {
        self.messages_dropped.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment the ring-full SAMPLE_REJECTED counter: an admitted sample
    /// (already dedup'd and control-plane-credited) found the reader's own
    /// ring full and was discarded.
    pub fn increment_samples_rejected_ring_full(&self, count: u64) {
        self.samples_rejected_ring_full
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increment the slab-pool-exhausted SAMPLE_REJECTED counter: same
    /// rejection as [`Self::increment_samples_rejected_ring_full`], at the
    /// slab-pool admission exit instead.
    pub fn increment_samples_rejected_slab_exhausted(&self, count: u64) {
        self.samples_rejected_slab_exhausted
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increment bytes sent counter by the serialized payload size of a
    /// write (see the type docs)
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

        let len = self.latency_ring.len();
        if len == 0 {
            return;
        }
        let i = self.latency_write_idx.fetch_add(1, Ordering::Relaxed);
        let slot = Self::fastmod(i as u64, self.latency_mod_magic, len as u64) as usize;
        self.latency_ring[slot].store(latency, Ordering::Relaxed);
    }

    /// Lemire fastmod (Lemire, Kaser, Kurz 2019): for `magic` =
    /// ceil(2^128 / d), `i % d` == high 128 bits of
    /// `(magic.wrapping_mul(i)) * d`, i.e.
    /// `floor((magic * i mod 2^128) * d / 2^128)`. Exact for every u64
    /// `i` and every u64 `d > 0`: the error term `e = d * magic - 2^128`
    /// satisfies `e < d <= 2^64`, so `i * e < 2^128` always holds.
    /// Avoids the hardware integer division `i % d` costs when `d` is
    /// not a power of two.
    #[inline]
    fn fastmod(i: u64, magic: u128, d: u64) -> u64 {
        let lowbits = magic.wrapping_mul(u128::from(i));
        // High 128 bits of the 256-bit product lowbits * d, computed
        // via 64-bit halves (d < 2^64 keeps every partial in range).
        let hi = (lowbits >> 64) as u64;
        let lo = lowbits as u64;
        let t = u128::from(hi) * u128::from(d) + ((u128::from(lo) * u128::from(d)) >> 64);
        (t >> 64) as u64
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
        // (per-slot reads are racy by design: telemetry-grade snapshot)
        let samples = self.collect_latency_samples();
        if !samples.is_empty() {
            snapshot_latency_percentiles(&mut frame, &samples);
        }

        frame
    }

    /// Get messages sent count (snapshot)
    pub fn messages_sent(&self) -> u64 {
        self.messages_sent.load(Ordering::Relaxed)
    }

    /// Get messages received count (snapshot)
    pub fn messages_received(&self) -> u64 {
        self.messages_received.0.load(Ordering::Relaxed)
    }

    /// Get messages dropped count (snapshot)
    pub fn messages_dropped(&self) -> u64 {
        self.messages_dropped.load(Ordering::Relaxed)
    }

    /// Get bytes sent count (snapshot)
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get merge-full (local delivery refused for lack of room) count (snapshot)
    pub fn merge_full(&self) -> u64 {
        self.merge_full.load(Ordering::Relaxed)
    }

    /// Get would-block count (snapshot)
    pub fn would_block(&self) -> u64 {
        self.would_block.load(Ordering::Relaxed)
    }

    /// Get writer history-cache insert error count (snapshot)
    pub fn cache_insert_errors(&self) -> u64 {
        self.cache_insert_errors.load(Ordering::Relaxed)
    }

    /// Get writer transport error count (snapshot)
    pub fn transport_errors(&self) -> u64 {
        self.transport_errors.load(Ordering::Relaxed)
    }

    /// Get the ring-full SAMPLE_REJECTED count (snapshot)
    pub fn samples_rejected_ring_full(&self) -> u64 {
        self.samples_rejected_ring_full.load(Ordering::Relaxed)
    }

    /// Get the slab-pool-exhausted SAMPLE_REJECTED count (snapshot)
    pub fn samples_rejected_slab_exhausted(&self) -> u64 {
        self.samples_rejected_slab_exhausted.load(Ordering::Relaxed)
    }

    /// Get latency sample count
    pub fn latency_sample_count(&self) -> usize {
        self.latency_write_idx
            .load(Ordering::Relaxed)
            .min(self.latency_ring.len())
    }

    /// Copy current ring contents into a Vec (Relaxed loads, order irrelevant
    /// for percentiles)
    fn collect_latency_samples(&self) -> Vec<u64> {
        let count = self.latency_sample_count();
        self.latency_ring[..count]
            .iter()
            .map(|s| s.load(Ordering::Relaxed))
            .collect()
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
        value_u64: collector.messages_received.0.load(Ordering::Relaxed),
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

    frame.push_field(Field {
        tag: TAG_SAMPLES_REJECTED_RING_FULL,
        dtype: DType::U64,
        value_u64: collector.samples_rejected_ring_full.load(Ordering::Relaxed),
    });

    frame.push_field(Field {
        tag: TAG_SAMPLES_REJECTED_SLAB_EXHAUSTED,
        dtype: DType::U64,
        value_u64: collector
            .samples_rejected_slab_exhausted
            .load(Ordering::Relaxed),
    });
}

/// Compute and add latency percentiles to Frame
#[allow(clippy::similar_names)] // p99_idx / p999_idx are intentionally parallel percentile indices
fn snapshot_latency_percentiles(frame: &mut Frame, samples: &[u64]) {
    let mut sorted: Vec<u64> = samples.to_vec();
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
#[cfg(unix)]
pub fn current_time_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY:
    // - CLOCK_REALTIME is a valid clock ID on all unix targets
    // - &mut ts is a valid pointer to a properly sized timespec struct
    // - clock_gettime() writes valid time data on success
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Get current time in nanoseconds since epoch
#[cfg(not(unix))]
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
    fn test_fastmod_matches_modulo() {
        fn magic(d: u64) -> u128 {
            (u128::MAX / u128::from(d)).wrapping_add(1)
        }

        let divisors: [u64; 9] = [1, 2, 3, 7, 10, 1000, 10_000, 16_384, 99_999];
        let edges: [u64; 12] = [
            u64::MAX,
            u64::MAX - 1,
            (1u64 << 32) - 1,
            1u64 << 32,
            (1u64 << 32) + 1,
            (1u64 << 48) - 1,
            1u64 << 48,
            (1u64 << 48) + 1,
            (1u64 << 63) - 1,
            1u64 << 63,
            (1u64 << 63) + 1,
            u64::MAX / 2,
        ];

        for &d in &divisors {
            let m = magic(d);
            for i in 0..10_000u64 {
                assert_eq!(
                    MetricsCollector::fastmod(i, m, d),
                    i % d,
                    "fastmod mismatch at i={i} d={d}"
                );
            }
            for &i in &edges {
                assert_eq!(
                    MetricsCollector::fastmod(i, m, d),
                    i % d,
                    "fastmod mismatch at edge i={i} d={d}"
                );
            }
        }
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
