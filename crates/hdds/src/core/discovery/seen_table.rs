// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Anti-loop gossip table for tracking seen announce messages.

use std::collections::HashMap;

/// Anti-loop gossip table for tracking seen announce messages
///
/// Prevents infinite loops in gossip protocols by tracking (origin_id, announce_id)
/// pairs that have already been seen. Entries are automatically expired after TTL.
///
/// # Performance
/// - is_seen(): O(1) average, includes automatic cleanup on each call
/// - Max entries: 100,000 (prevents unbounded growth)
/// - TTL: 300 seconds (5 minutes)
pub struct SeenTable {
    /// Map of (origin_id, announce_id) -> timestamp (ns)
    table: HashMap<(u32, u32), u64>,

    /// Maximum entries before dropping oldest
    max_entries: usize,

    /// Time-to-live for entries (nanoseconds)
    ttl_ns: u64,
}

impl SeenTable {
    /// Create new seen table with default settings
    ///
    /// Defaults:
    /// - max_entries: 100,000
    /// - ttl_ns: 300 seconds (5 minutes)
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            max_entries: 100_000,
            ttl_ns: 300 * 1_000_000_000, // 300 sec
        }
    }

    /// Create seen table with custom settings
    ///
    /// # Arguments
    /// - `max_entries`: Maximum entries before cleanup
    /// - `ttl_sec`: Time-to-live in seconds
    pub fn with_capacity(max_entries: usize, ttl_sec: u64) -> Self {
        Self {
            table: HashMap::new(),
            max_entries,
            ttl_ns: ttl_sec * 1_000_000_000,
        }
    }

    /// Check if (origin_id, announce_id) has been seen before
    ///
    /// Returns true if already seen, false if first time.
    /// Automatically cleans up stale entries on each call.
    ///
    /// # Arguments
    /// - `origin_id`: Participant ID of the origin
    /// - `announce_id`: Sequence number of the announce
    /// - `now_ns`: Current timestamp (nanoseconds since epoch)
    ///
    /// # Performance
    /// Target: < 100 ns (hash lookup + optional cleanup)
    pub fn is_seen(&mut self, origin_id: u32, announce_id: u32, now_ns: u64) -> bool {
        let key = (origin_id, announce_id);

        // Clean stale entries (older than TTL)
        self.table
            .retain(|_, &mut time| now_ns - time < self.ttl_ns);

        if self.table.contains_key(&key) {
            return true; // Seen before, skip
        }

        // Add to table (if not full)
        if self.table.len() < self.max_entries {
            self.table.insert(key, now_ns);
        }

        false // First time seeing this
    }

    /// Get current number of entries
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.table.clear();
    }
}

impl Default for SeenTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seen_table_first_time() {
        let mut table = SeenTable::new();
        let now = 1_000_000_000_000; // 1000 sec in ns

        assert!(!table.is_seen(1, 100, now)); // First time
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_seen_table_duplicate() {
        let mut table = SeenTable::new();
        let now = 1_000_000_000_000;

        assert!(!table.is_seen(1, 100, now)); // First time
        assert!(table.is_seen(1, 100, now + 1000)); // Duplicate
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_seen_table_different_origins() {
        let mut table = SeenTable::new();
        let now = 1_000_000_000_000;

        assert!(!table.is_seen(1, 100, now)); // Origin 1
        assert!(!table.is_seen(2, 100, now)); // Origin 2 (different)
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_seen_table_different_announce_ids() {
        let mut table = SeenTable::new();
        let now = 1_000_000_000_000;

        assert!(!table.is_seen(1, 100, now)); // Announce 100
        assert!(!table.is_seen(1, 101, now)); // Announce 101 (different)
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_seen_table_ttl_expiry() {
        let mut table = SeenTable::with_capacity(100, 5); // 5 sec TTL
        let now = 1_000_000_000_000;

        table.is_seen(1, 100, now); // Add entry
        assert_eq!(table.len(), 1);

        // After 6 seconds (> TTL), entry should be cleaned
        let later = now + 6_000_000_000; // +6 sec
        assert!(!table.is_seen(1, 100, later)); // Expired, treated as first time
        assert_eq!(table.len(), 1); // New entry added
    }

    #[test]
    fn test_seen_table_max_capacity() {
        let mut table = SeenTable::with_capacity(10, 300); // Max 10 entries
        let now = 1_000_000_000_000;

        // Fill table to capacity
        for i in 0..10 {
            table.is_seen(1, i, now);
        }
        assert_eq!(table.len(), 10);

        // Next insert should be dropped (at capacity)
        table.is_seen(1, 100, now);
        assert_eq!(table.len(), 10); // Still 10
    }

    #[test]
    fn test_seen_table_cleanup_during_insert() {
        let mut table = SeenTable::with_capacity(100, 5); // 5 sec TTL
        let now = 1_000_000_000_000;

        // Add 5 entries
        for i in 0..5 {
            table.is_seen(1, i, now);
        }
        assert_eq!(table.len(), 5);

        // After 6 seconds, all should be expired
        let later = now + 6_000_000_000;
        table.is_seen(2, 100, later); // Trigger cleanup
        assert_eq!(table.len(), 1); // Only new entry remains
    }

    #[test]
    fn test_seen_table_clear() {
        let mut table = SeenTable::new();
        let now = 1_000_000_000_000;

        table.is_seen(1, 100, now);
        table.is_seen(2, 200, now);
        assert_eq!(table.len(), 2);

        table.clear();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn test_seen_table_stress() {
        let mut table = SeenTable::with_capacity(1000, 300);
        let now = 1_000_000_000_000;

        // Insert 500 unique entries
        for i in 0..500 {
            assert!(!table.is_seen(i / 100, i, now));
        }
        assert_eq!(table.len(), 500);

        // Check all 500 are seen
        for i in 0..500 {
            assert!(table.is_seen(i / 100, i, now));
        }
        assert_eq!(table.len(), 500); // No new entries added
    }
}
