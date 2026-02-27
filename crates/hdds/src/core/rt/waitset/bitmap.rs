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

    pub(super) fn take_all(&self) -> Vec<usize> {
        let bits_per_word = usize::BITS as usize;
        let mut indices = Vec::new();

        for (word_idx, word) in self.words.iter().enumerate() {
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
