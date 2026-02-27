// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Duplicate message detection cache

/// Cache entry for seen messages
#[derive(Debug, Clone, Copy, Default)]
struct SeenEntry {
    /// Message ID (src << 16 | seq)
    message_id: u32,
    /// Timestamp when seen (tick counter)
    seen_at: u32,
    /// Valid flag
    valid: bool,
}

/// Fixed-size cache for duplicate detection
///
/// Uses a simple ring buffer with LRU eviction.
pub struct SeenCache<const N: usize> {
    /// Cache entries
    entries: [SeenEntry; N],
    /// Next insertion index
    next: usize,
    /// Current tick (for expiry)
    tick: u32,
    /// Entry lifetime in ticks
    lifetime: u32,
}

impl<const N: usize> SeenCache<N> {
    /// Create a new seen cache
    ///
    /// # Arguments
    /// * `lifetime` - How many ticks before entries expire
    pub fn new(lifetime: u32) -> Self {
        Self {
            entries: [SeenEntry::default(); N],
            next: 0,
            tick: 0,
            lifetime,
        }
    }

    /// Advance the tick counter
    pub fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }

    /// Check if a message was recently seen
    ///
    /// Returns `true` if the message is a duplicate (was seen before).
    pub fn is_duplicate(&self, message_id: u32) -> bool {
        for entry in &self.entries {
            if entry.valid && entry.message_id == message_id {
                // Check if not expired
                let age = self.tick.wrapping_sub(entry.seen_at);
                if age <= self.lifetime {
                    return true;
                }
            }
        }
        false
    }

    /// Check if duplicate and mark as seen if not
    ///
    /// Returns `true` if the message is a duplicate.
    /// If not a duplicate, adds it to the cache.
    pub fn check_and_mark(&mut self, message_id: u32) -> bool {
        // First check if already seen
        for entry in &mut self.entries {
            if entry.valid && entry.message_id == message_id {
                let age = self.tick.wrapping_sub(entry.seen_at);
                if age <= self.lifetime {
                    return true; // Duplicate
                }
                // Expired, will be replaced
            }
        }

        // Not a duplicate, add to cache
        self.mark_seen(message_id);
        false
    }

    /// Mark a message as seen
    pub fn mark_seen(&mut self, message_id: u32) {
        // Try to find an expired or invalid slot first
        for entry in &mut self.entries {
            if !entry.valid {
                entry.message_id = message_id;
                entry.seen_at = self.tick;
                entry.valid = true;
                return;
            }

            let age = self.tick.wrapping_sub(entry.seen_at);
            if age > self.lifetime {
                entry.message_id = message_id;
                entry.seen_at = self.tick;
                entry.valid = true;
                return;
            }
        }

        // No free slot, use LRU (next index)
        self.entries[self.next] = SeenEntry {
            message_id,
            seen_at: self.tick,
            valid: true,
        };
        self.next = (self.next + 1) % N;
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.valid = false;
        }
        self.next = 0;
    }

    /// Get number of valid (non-expired) entries
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.valid && self.tick.wrapping_sub(e.seen_at) <= self.lifetime)
            .count()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seen_cache_basic() {
        let mut cache: SeenCache<8> = SeenCache::new(100);

        // First time should not be duplicate
        assert!(!cache.check_and_mark(0x0001_0001));

        // Second time should be duplicate
        assert!(cache.check_and_mark(0x0001_0001));

        // Different message should not be duplicate
        assert!(!cache.check_and_mark(0x0001_0002));
    }

    #[test]
    fn test_seen_cache_expiry() {
        let mut cache: SeenCache<8> = SeenCache::new(10);

        assert!(!cache.check_and_mark(0x0001_0001));
        assert!(cache.check_and_mark(0x0001_0001));

        // Advance time past lifetime
        for _ in 0..15 {
            cache.tick();
        }

        // Should no longer be duplicate (expired)
        assert!(!cache.check_and_mark(0x0001_0001));
    }

    #[test]
    fn test_seen_cache_lru() {
        let mut cache: SeenCache<4> = SeenCache::new(1000);

        // Fill cache
        for i in 0..4 {
            assert!(!cache.check_and_mark(i));
        }

        // All should still be duplicates
        for i in 0..4 {
            assert!(cache.check_and_mark(i));
        }

        // Add more (should evict oldest)
        for i in 4..8 {
            assert!(!cache.check_and_mark(i));
        }

        // Old entries should have been evicted
        assert!(!cache.check_and_mark(0)); // Re-added as new
    }

    #[test]
    fn test_seen_cache_clear() {
        let mut cache: SeenCache<8> = SeenCache::new(100);

        cache.mark_seen(0x0001_0001);
        cache.mark_seen(0x0001_0002);
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_seen_cache_len() {
        let mut cache: SeenCache<8> = SeenCache::new(5);

        assert_eq!(cache.len(), 0);

        cache.mark_seen(1);
        cache.mark_seen(2);
        cache.mark_seen(3);
        assert_eq!(cache.len(), 3);

        // Expire entries
        for _ in 0..10 {
            cache.tick();
        }
        assert_eq!(cache.len(), 0);
    }
}
