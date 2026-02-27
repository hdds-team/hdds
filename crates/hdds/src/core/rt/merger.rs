// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fan-out dispatcher from writer to N reader rings.
//!
//!
//! `TopicMerger` clones `IndexEntry` to all registered readers. Supports
//! late-joiner delivery with TRANSIENT_LOCAL/PERSISTENT durability.
//!
//! # Performance
//!
//! - push: < 100 ns per reader (RwLock read-only in hot path)

use super::indexring::{IndexEntry, IndexRing};
use super::slabpool::SlabPool;
use crate::reliability::HistoryCache;
use std::convert::TryFrom;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Unique identifier for a reader in a merger
///
/// Based on Arc pointer address - two readers with the same ring
/// pointer are considered the same reader.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ReaderId(usize);

impl ReaderId {
    /// Create ReaderId from an IndexRing Arc pointer
    pub fn from_ring(ring: &Arc<IndexRing>) -> Self {
        Self(Arc::as_ptr(ring) as usize)
    }
}

/// Reader registration stored by the [`TopicMerger`].
///
/// Holds the reader ring together with a notification callback that is invoked
/// whenever new data becomes available. The callback is typically responsible for
/// updating the associated `StatusCondition` so higher layers (WaitSet) can wake
/// immediately without polling.
#[derive(Clone)]
pub struct MergerReader {
    id: ReaderId,
    ring: Arc<IndexRing>,
    on_data: Arc<dyn Fn() + Send + Sync>,
}

impl MergerReader {
    /// Construct a new [`MergerReader`].
    #[must_use]
    pub fn new(ring: Arc<IndexRing>, on_data: Arc<dyn Fn() + Send + Sync>) -> Self {
        let id = ReaderId::from_ring(&ring);
        Self { id, ring, on_data }
    }

    /// Get the reader's unique identifier
    #[must_use]
    pub fn id(&self) -> ReaderId {
        self.id
    }

    /// Access the underlying ring buffer.
    #[must_use]
    pub fn ring(&self) -> &Arc<IndexRing> {
        &self.ring
    }

    /// Invoke the notification callback.
    fn notify(&self) {
        (self.on_data)();
    }
}

/// TopicMerger: Fan-out from writer ring to N reader rings
///
/// Simple dispatcher that clones [`IndexEntry`] to all registered readers.
/// Non-blocking, best-effort (lossy if reader ring full).
///
/// # Performance
/// - Target: < 100 ns per push (N readers x 50 ns ring push)
/// - `RwLock` read-only in hot path (no write contention)
///
/// # Late-Joiner Support (v0.5.0+)
/// - If `durability_state` is `Some`, `add_reader()` replays historical samples
/// - Supports TRANSIENT_LOCAL and PERSISTENT durability for late-joiner delivery
pub struct TopicMerger {
    readers: RwLock<Vec<MergerReader>>,
    /// Optional history cache + slab pool for TRANSIENT_LOCAL/PERSISTENT durability
    durability_state: Option<(Arc<HistoryCache>, Arc<SlabPool>)>,
}

impl TopicMerger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            readers: RwLock::new(Vec::new()),
            durability_state: None,
        }
    }

    /// Create merger with TRANSIENT_LOCAL/PERSISTENT durability support
    ///
    /// Enables automatic historical data delivery to late-joining readers.
    #[must_use]
    pub fn with_history(cache: Arc<HistoryCache>, slab_pool: Arc<SlabPool>) -> Self {
        Self {
            readers: RwLock::new(Vec::new()),
            durability_state: Some((cache, slab_pool)),
        }
    }

    /// Register reader ring (called during matching)
    ///
    /// Takes write lock briefly (cold path).
    ///
    /// # Idempotence
    /// If a reader with the same ID is already registered, this is a no-op.
    /// Returns `true` if the reader was newly added, `false` if already present.
    ///
    /// # Late-Joiner Delivery (v0.5.0+)
    /// If TRANSIENT_LOCAL/PERSISTENT durability is enabled, automatically pushes
    /// all historical samples from the cache to the new reader's ring.
    pub fn add_reader(&self, reader: MergerReader) -> bool {
        let reader_id = reader.id();

        // Check for duplicate (idempotence)
        {
            let readers = recover_read(&self.readers, "TopicMerger::add_reader readers.read()");
            if readers.iter().any(|r| r.id() == reader_id) {
                log::debug!(
                    "[DEBUG] TopicMerger::add_reader(): Reader {:?} already registered, ignoring duplicate",
                    reader_id
                );
                return false;
            }
        }

        // Push historical samples if TRANSIENT_LOCAL durability is enabled
        if let Some((cache, _slab_pool)) = &self.durability_state {
            let all_samples = cache.get_all_samples();
            log::debug!(
                "[DEBUG] TopicMerger::add_reader(): Found {} historical samples in cache",
                all_samples.len()
            );
            for (seq, handle, size) in all_samples {
                let seq_u32 = match u32::try_from(seq) {
                    Ok(value) => value,
                    Err(_) => {
                        log::debug!(
                            "[WARN] TopicMerger::add_reader(): historical seq {} exceeds u32 range, skipping",
                            seq
                        );
                        continue;
                    }
                };
                let len_u32 = match u32::try_from(size) {
                    Ok(value) => value,
                    Err(_) => {
                        log::debug!(
                            "[WARN] TopicMerger::add_reader(): historical payload {} bytes exceeds u32 range, skipping seq {}",
                            size, seq
                        );
                        continue;
                    }
                };
                let entry = IndexEntry::new(seq_u32, handle, len_u32);
                if reader.ring().push(entry) {
                    reader.notify();
                } else {
                    log::debug!(
                        "[DEBUG] TopicMerger::add_reader(): Reader ring full while replaying seq {}, dropping historical sample",
                        seq
                    );
                }
            }
        } else {
            log::debug!(
                "[DEBUG] TopicMerger::add_reader(): No durability_state, not pushing historical samples"
            );
        }

        // Register reader for future samples
        let mut readers = recover_write(&self.readers, "TopicMerger::add_reader readers.write()");

        // Double-check after acquiring write lock (race condition protection)
        if readers.iter().any(|r| r.id() == reader_id) {
            log::debug!(
                "[DEBUG] TopicMerger::add_reader(): Reader {:?} registered by another thread, ignoring",
                reader_id
            );
            return false;
        }

        readers.push(reader);
        log::debug!(
            "[DEBUG] TopicMerger::add_reader(): Registered reader {:?}, now have {} readers",
            reader_id,
            readers.len()
        );
        true
    }

    /// Dispatch entry from writer to all readers (non-blocking, lossy)
    ///
    /// Returns true if pushed to at least one reader.
    /// If any reader full, it's OK (lossy, app will miss message).
    ///
    /// # Performance
    /// - Read lock only (no contention in hot path)
    /// - Target: < 100 ns for typical 1-3 readers
    pub fn push(&self, entry: IndexEntry) -> bool {
        let readers = recover_read(&self.readers, "TopicMerger::push readers.read()");

        let mut pushed_any = false;
        for reader in readers.iter() {
            if reader.ring().push(entry) {
                reader.notify();
                pushed_any = true;
            }
        }

        pushed_any
    }

    /// Get current number of registered readers
    #[must_use]
    pub fn reader_count(&self) -> usize {
        recover_read(&self.readers, "TopicMerger::reader_count readers.read()").len()
    }
}

impl Default for TopicMerger {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro to generate poisoned lock recovery functions (eliminates duplication)
///
/// Generates `recover_read` and `recover_write` with identical error handling.
macro_rules! impl_recover_lock {
    ($fn_name:ident, $lock_method:ident, $guard_type:ty) => {
        fn $fn_name<'a, T>(lock: &'a RwLock<T>, context: &str) -> $guard_type {
            match lock.$lock_method() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::debug!("[rt] WARNING: {} poisoned, recovering", context);
                    poisoned.into_inner()
                }
            }
        }
    };
}

impl_recover_lock!(recover_read, read, RwLockReadGuard<'a, T>);
impl_recover_lock!(recover_write, write, RwLockWriteGuard<'a, T>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rt::SlabHandle;

    fn noop_callback() -> Arc<dyn Fn() + Send + Sync> {
        Arc::new(|| {})
    }

    #[test]
    fn test_merger_add_readers() {
        let merger = TopicMerger::new();
        assert_eq!(merger.reader_count(), 0);

        let ring1 = Arc::new(IndexRing::with_capacity(16));
        let ring2 = Arc::new(IndexRing::with_capacity(16));

        let reader1 = MergerReader::new(Arc::clone(&ring1), noop_callback());
        let reader2 = MergerReader::new(Arc::clone(&ring2), noop_callback());

        assert!(merger.add_reader(reader1), "First add should succeed");
        assert!(merger.add_reader(reader2), "Second add should succeed");

        assert_eq!(merger.reader_count(), 2);
    }

    #[test]
    fn test_add_reader_idempotent_no_double_delivery() {
        let merger = TopicMerger::new();
        let ring = Arc::new(IndexRing::with_capacity(16));

        // Create two MergerReader instances with the same ring Arc
        let reader1 = MergerReader::new(Arc::clone(&ring), noop_callback());
        let reader2 = MergerReader::new(Arc::clone(&ring), noop_callback());

        // First add should succeed
        assert!(merger.add_reader(reader1), "First add should succeed");
        assert_eq!(merger.reader_count(), 1);

        // Second add with same ring should be rejected (idempotent)
        assert!(
            !merger.add_reader(reader2),
            "Duplicate add should be rejected"
        );
        assert_eq!(merger.reader_count(), 1, "Reader count should still be 1");

        // Push entry - should only be delivered once
        let entry = IndexEntry::new(1, SlabHandle(42), 100);
        assert!(merger.push(entry), "Push should succeed");

        // Only one entry in the ring (not two!)
        let e1 = ring.pop();
        assert!(e1.is_some(), "Should have one entry");
        assert_eq!(e1.unwrap().seq, 1);

        let e2 = ring.pop();
        assert!(
            e2.is_none(),
            "Should NOT have a second entry (no double delivery)"
        );
    }

    #[test]
    fn test_merger_fanout() {
        let merger = TopicMerger::new();

        let ring1 = Arc::new(IndexRing::with_capacity(16));
        let ring2 = Arc::new(IndexRing::with_capacity(16));

        let reader1 = MergerReader::new(Arc::clone(&ring1), noop_callback());
        let reader2 = MergerReader::new(Arc::clone(&ring2), noop_callback());

        merger.add_reader(reader1);
        merger.add_reader(reader2);

        // Push entry via merger
        let entry = IndexEntry::new(1, SlabHandle(42), 100);
        assert!(merger.push(entry), "Should push to at least one reader");

        // Both readers should have the entry (IndexRing now has interior mutability)
        let e1 = ring1.pop();
        let e2 = ring2.pop();

        assert!(e1.is_some(), "Reader 1 should have entry");
        assert!(e2.is_some(), "Reader 2 should have entry");

        assert_eq!(e1.expect("Entry should be present").seq, 1);
        assert_eq!(e2.expect("Entry should be present").seq, 1);
    }
}
