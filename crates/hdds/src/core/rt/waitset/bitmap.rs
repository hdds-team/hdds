// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::sync::atomic::{AtomicUsize, Ordering};

/// Lock-free bitmap used by the waitset driver to track which slots are active.
pub(super) struct AtomicBitset {
    words: Vec<AtomicUsize>,
    capacity: usize,
}

impl AtomicBitset {
    pub(super) fn new(capacity: usize) -> Self {
        let bits_per_word = usize::BITS as usize;
        let word_count = capacity.div_ceil(bits_per_word);
        let mut words = Vec::with_capacity(word_count);
        for _ in 0..word_count {
            words.push(AtomicUsize::new(0));
        }
        Self { words, capacity }
    }

    pub(super) fn test_and_set(&self, index: usize) -> bool {
        if index >= self.capacity {
            return false;
        }

        let bits_per_word = usize::BITS as usize;
        let word_index = index / bits_per_word;
        let bit = 1usize << (index % bits_per_word);
        let prev = self.words[word_index].fetch_or(bit, Ordering::AcqRel);
        (prev & bit) != 0
    }

    /// Clear a single bit without reporting it.
    ///
    /// The driver uses this when a slot index is handed to a new owner: a
    /// handle that outlived its registration may have set the bit after the
    /// bound dropped below its word, where `take_all` no longer visits. Left
    /// in place, that stale bit would make the new owner's first
    /// `test_and_set` report "already set" and skip the event write, a lost
    /// wakeup. The driver clears in the same critical section that raises
    /// the bound, under the mutex its waiter reads the bound through, so a
    /// bit set after the clear is in a word the next `take_all` visits.
    pub(super) fn clear(&self, index: usize) {
        if index >= self.capacity {
            return;
        }

        let bits_per_word = usize::BITS as usize;
        let word_index = index / bits_per_word;
        let bit = 1usize << (index % bits_per_word);
        self.words[word_index].fetch_and(!bit, Ordering::AcqRel);
    }

    /// Take (return and clear) every set bit whose index is below `slot_bound`.
    ///
    /// Only the words that can hold such an index are swapped, so the cost of
    /// a wakeup scales with the highest registered slot rather than with the
    /// bitmap capacity: a driver with one registration touches one word, not
    /// all 32 words (four cache lines) of a 2048-slot bitmap.
    ///
    /// The bound is word-granular: a bit at index `slot_bound..` that shares
    /// its word with a bit below the bound is taken as well, which is harmless
    /// because callers already tolerate indices of unregistered slots. A bound
    /// of `0` visits nothing; a bound at or above the capacity visits every
    /// word, which is the pre-bound behaviour.
    pub(super) fn take_all(&self, slot_bound: usize) -> Vec<usize> {
        let bits_per_word = usize::BITS as usize;
        let word_bound = slot_bound.div_ceil(bits_per_word).min(self.words.len());
        let mut indices = Vec::new();

        for (word_idx, word) in self.words[..word_bound].iter().enumerate() {
            let value = word.swap(0, Ordering::AcqRel);
            if value == 0 {
                continue;
            }

            for bit_offset in 0..bits_per_word {
                let bit = 1usize << bit_offset;
                if value & bit == 0 {
                    continue;
                }

                let index = word_idx * bits_per_word + bit_offset;
                if index < self.capacity {
                    indices.push(index);
                }
            }
        }

        indices
    }
}
