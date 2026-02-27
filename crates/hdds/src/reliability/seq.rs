// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Sequence number generation for Reliable QoS
//!
//! Per-writer monotonic sequence numbering for RTPS DATA submessages.
//! Thread-safe via AtomicU64, safe for 1M msg/s (no wrap for ~584,942 years).

use std::sync::atomic::{AtomicU64, Ordering};

/// Sequence number generator (per-writer)
///
/// Generates monotonically increasing sequence numbers for RTPS DATA submessages.
/// Used by Reliable QoS writers to track message ordering and enable gap detection.
///
/// # Thread Safety
///
/// All methods are thread-safe via `AtomicU64`. Multiple threads can call `next()`
/// concurrently without coordination.
///
/// # Performance
///
/// - `next()`: ~1-2 ns (single atomic fetch_add)
/// - No contention: relaxed memory ordering
/// - Zero allocations
///
/// # Example
///
/// ```ignore
/// let gen = SeqNumGenerator::new();
/// let seq1 = gen.next(); // 1
/// let seq2 = gen.next(); // 2
/// assert!(seq2 > seq1);
/// ```
#[derive(Debug)]
pub struct SeqNumGenerator {
    /// Next sequence number to assign
    ///
    /// Starts at 1 (RTPS spec: sequence numbers start at 1, not 0).
    /// Incremented atomically on each call to `next()`.
    next: AtomicU64,
}

impl SeqNumGenerator {
    /// Create a new sequence number generator
    ///
    /// Starts at sequence number 1 (RTPS spec compliant).
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }

    /// Get next sequence number (monotonically increasing)
    ///
    /// # Returns
    ///
    /// Unique sequence number (never repeats, never decreases).
    ///
    /// # Thread Safety
    ///
    /// Safe to call from multiple threads concurrently.
    ///
    /// # Performance
    ///
    /// - Relaxed ordering (no synchronization overhead)
    /// - ~1-2 ns per call (single atomic operation)
    ///
    /// # Panics
    ///
    /// Never panics. If sequence number wraps (after 2^64 - 1 messages),
    /// behavior is defined by `fetch_add` wrapping semantics.
    ///
    /// Note: At 1M msg/s, wrap occurs after ~584,942 years.
    #[inline]
    pub fn next(&self) -> u64 {
        // fetch_add returns OLD value, so result is the seq we should use
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// Get current sequence number without incrementing
    ///
    /// Returns the NEXT sequence that will be assigned by `next()`.
    ///
    /// # Use Cases
    ///
    /// - Debugging: inspect current state
    /// - Heartbeat: report highest sequence written
    ///
    /// # Thread Safety
    ///
    /// Value may be stale immediately after reading (race with concurrent `next()`).
    #[inline]
    pub fn current(&self) -> u64 {
        self.next.load(Ordering::Relaxed)
    }
}

impl Default for SeqNumGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_seqgen_starts_at_one() {
        let gen = SeqNumGenerator::new();
        assert_eq!(
            gen.next(),
            1,
            "First sequence number should be 1 (RTPS spec)"
        );
    }

    #[test]
    fn test_seqgen_monotonic() {
        let gen = SeqNumGenerator::new();
        let seq1 = gen.next();
        let seq2 = gen.next();
        let seq3 = gen.next();

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);
    }

    #[test]
    fn test_seqgen_no_duplicates_1m() {
        let gen = SeqNumGenerator::new();
        let mut seen = HashSet::new();

        for _ in 0..1_000_000 {
            let seq = gen.next();
            assert!(
                seen.insert(seq),
                "Duplicate sequence number detected: {}",
                seq
            );
        }

        assert_eq!(
            seen.len(),
            1_000_000,
            "Should have exactly 1M unique sequences"
        );
    }

    #[test]
    fn test_seqgen_thread_safety() {
        let gen = Arc::new(SeqNumGenerator::new());
        let num_threads = 4;
        let seqs_per_thread = 250_000; // Total: 1M sequences

        let mut handles = vec![];

        for _ in 0..num_threads {
            let gen = Arc::clone(&gen);
            let handle = thread::spawn(move || {
                let mut local_seqs = Vec::with_capacity(seqs_per_thread);
                for _ in 0..seqs_per_thread {
                    local_seqs.push(gen.next());
                }
                local_seqs
            });
            handles.push(handle);
        }

        // Collect all sequences from all threads
        let mut all_seqs = Vec::new();
        for handle in handles {
            let seqs = handle.join().expect("Thread should complete successfully");
            all_seqs.extend(seqs);
        }

        // Verify uniqueness
        let mut seen = HashSet::new();
        for seq in &all_seqs {
            assert!(
                seen.insert(*seq),
                "Duplicate sequence number in concurrent test: {}",
                seq
            );
        }

        assert_eq!(
            all_seqs.len(),
            1_000_000,
            "Should have exactly 1M sequences total"
        );
    }

    #[test]
    fn test_seqgen_current() {
        let gen = SeqNumGenerator::new();

        // Initially, next seq is 1
        assert_eq!(gen.current(), 1);

        // After generating one, next seq is 2
        gen.next();
        assert_eq!(gen.current(), 2);

        // After generating another, next seq is 3
        gen.next();
        assert_eq!(gen.current(), 3);
    }

    #[test]
    fn test_seqgen_default() {
        let gen = SeqNumGenerator::default();
        assert_eq!(gen.next(), 1, "Default should start at 1");
    }
}
