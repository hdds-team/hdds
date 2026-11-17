// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bounded exact absence proofs in Publisher GSN space.

/// A run represents `count` half-open intervals of `width` values in GSN
/// space, starting `stride` apart. It never represents the holes between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Run {
    first: u64,
    width: u64,
    stride: u64,
    count: u64,
}

impl Run {
    fn interval(first: u64, end: u64) -> Option<Self> {
        let width = end.checked_sub(first).filter(|width| *width > 0)?;
        Some(Self {
            first,
            width,
            stride: width,
            count: 1,
        })
    }

    fn new(first: u64, width: u64, stride: u64, count: u64) -> Option<Self> {
        if width == 0 || count == 0 || stride < width {
            return None;
        }
        let last = first.checked_add(stride.checked_mul(count - 1)?)?;
        last.checked_add(width)?;
        if stride == width {
            return Self::interval(first, last.checked_add(width)?);
        }
        Some(Self {
            first,
            width,
            stride,
            count,
        })
    }

    fn last_start(self) -> u64 {
        // Construction and every mutation preserve this checked span.
        self.first + self.stride * (self.count - 1)
    }

    fn end(self) -> u64 {
        self.last_start() + self.width
    }

    fn through(self, gsn: u64) -> Option<u64> {
        let offset = gsn.checked_sub(self.first)?;
        let interval = offset / self.stride;
        (interval < self.count && offset % self.stride < self.width)
            .then(|| self.first + interval * self.stride + self.width)
    }

    fn contains(self, other: Self) -> bool {
        if self.first > other.first || self.end() < other.end() {
            return false;
        }
        if self.count == 1 {
            return true;
        }
        if other.count == 1 {
            return self
                .through(other.first)
                .is_some_and(|end| end >= other.end());
        }
        let offset = (other.first - self.first) % self.stride;
        other.stride.is_multiple_of(self.stride)
            && offset
                .checked_add(other.width)
                .is_some_and(|end| end <= self.width)
    }

    fn merge(self, other: Self) -> Option<Self> {
        if self.contains(other) {
            return Some(self);
        }
        if other.contains(self) {
            return Some(other);
        }
        if self.count == 1 && other.count == 1 {
            if self.first <= other.end() && other.first <= self.end() {
                return Self::interval(self.first.min(other.first), self.end().max(other.end()));
            }
            if self.width == other.width {
                let first = self.first.min(other.first);
                let stride = self.first.max(other.first) - first;
                return Self::new(first, self.width, stride, 2);
            }
            return None;
        }
        let (earlier, later) = if self.first <= other.first {
            (self, other)
        } else {
            (other, self)
        };
        // A contiguous proof can bridge every hole of an existing run. The
        // two edge intervals supply only their own already proved GSNs.
        for (interval, run) in [(self, other), (other, self)] {
            if interval.count == 1
                && interval.first <= run.first.checked_add(run.width)?
                && interval.end() >= run.last_start()
            {
                return Self::interval(
                    interval.first.min(run.first),
                    interval.end().max(run.end()),
                );
            }
        }
        if self.width != other.width {
            return None;
        }
        if earlier.count == 1 {
            if earlier.first.checked_add(later.stride) == Some(later.first) {
                return Self::new(
                    earlier.first,
                    later.width,
                    later.stride,
                    later.count.checked_add(1)?,
                );
            }
            return None;
        }
        if later.count == 1 {
            if earlier.last_start().checked_add(earlier.stride) == Some(later.first) {
                return Self::new(
                    earlier.first,
                    earlier.width,
                    earlier.stride,
                    earlier.count.checked_add(1)?,
                );
            }
            return None;
        }
        if earlier.stride != later.stride {
            return None;
        }
        let difference = later.first - earlier.first;
        if difference % earlier.stride == 0 {
            let index = difference / earlier.stride;
            if index <= earlier.count {
                return Self::new(
                    earlier.first,
                    earlier.width,
                    earlier.stride,
                    earlier.count.max(index.checked_add(later.count)?),
                );
            }
        }
        // Two interleaved equal runs form one exact denser run, never their
        // convex hull. An extra final interval is allowed only on the first.
        if earlier.stride % 2 == 0
            && difference == earlier.stride / 2
            && (earlier.count == later.count || earlier.count == later.count.checked_add(1)?)
        {
            return Self::new(
                earlier.first,
                earlier.width,
                earlier.stride / 2,
                earlier.count.checked_add(later.count)?,
            );
        }
        None
    }

    fn prune(&mut self, next: u64) -> bool {
        if self.end() <= next {
            return false;
        }
        if next <= self.first {
            return true;
        }
        if self.count == 1 {
            self.width = self.end() - next;
            self.first = next;
            self.stride = self.width;
            return true;
        }
        let mut skip = (next - self.first) / self.stride;
        let start = self.first + skip * self.stride;
        if start + self.width <= next {
            skip += 1;
        }
        if skip >= self.count {
            return false;
        }
        self.first += skip * self.stride;
        self.count -= skip;
        true
    }
}

/// At most 512 descriptors (16 KiB of run data per writer/reader pair),
/// independent of the number and distance of regularly spaced GAPs. If exact
/// compression is impossible at that bound, retain the lowest-starting descriptors;
/// the uncovered future prefix must wait for an actual HEARTBEAT/GAP proof.
#[derive(Clone, Debug, Default)]
pub(super) struct GapProofs {
    runs: Vec<Run>,
    overflow_end: Option<u64>,
}

impl GapProofs {
    const LIMIT: usize = 512;

    pub fn insert(&mut self, start: u64, end: u64) -> bool {
        let Some(mut candidate) = Run::interval(start, end) else {
            return false;
        };
        let mut i = 0;
        while i < self.runs.len() {
            if let Some(merged) = candidate.merge(self.runs[i]) {
                candidate = merged;
                self.runs.remove(i);
                i = 0;
            } else {
                i += 1;
            }
        }
        let index = self.runs.partition_point(|run| run.first < candidate.first);
        if self.runs.len() == Self::LIMIT {
            if index == self.runs.len() {
                self.note_overflow(candidate.end());
                return false;
            }
            // Pop before insertion: the Vec never grows to a 1024-element
            // allocation just to trim its length afterwards. The length is
            // LIMIT here, so the pop always yields the run it omits.
            let omitted = self.runs.pop();
            debug_assert!(omitted.is_some(), "a full proof set has a run to omit");
            match omitted {
                Some(omitted) => self.note_overflow(omitted.end()),
                None => log::error!("gap proof overflow with no run to omit"),
            }
        }
        self.runs.insert(index, candidate);
        true
    }

    fn note_overflow(&mut self, end: u64) {
        self.overflow_end = Some(self.overflow_end.map_or(end, |old| old.max(end)));
    }

    pub fn prune(&mut self, next: u64) {
        self.runs.retain_mut(|run| run.prune(next));
        self.runs.sort_unstable_by_key(|run| run.first);
        if self.overflow_end.is_some_and(|end| end <= next) {
            self.overflow_end = None;
        }
    }

    /// An exclusive end supported by an exact stored interval. Never expand
    /// a strided run, including when the queried GSN is near u64::MAX.
    pub fn through(&self, gsn: u64) -> Option<u64> {
        self.runs.iter().filter_map(|run| run.through(gsn)).max()
    }

    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    #[cfg(test)]
    pub fn descriptor_count(&self) -> usize {
        self.runs.len()
    }

    #[cfg(test)]
    pub fn overflowed(&self) -> bool {
        self.overflow_end.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_union_never_fills_an_unproved_hole() {
        let mut proofs = GapProofs::default();
        for (start, end) in [(2, 5), (5, 7), (1, 3), (4, 6)] {
            proofs.insert(start, end);
        }
        assert_eq!(proofs.descriptor_count(), 1);
        for gsn in 1..7 {
            assert_eq!(proofs.through(gsn), Some(7));
        }
        assert_eq!(proofs.through(0), None);
        assert_eq!(proofs.through(7), None);
        proofs.insert(9, 10);
        assert_eq!(proofs.through(8), None);
    }

    #[test]
    fn regularly_spaced_proofs_remain_exact_after_more_than_512_intervals() {
        for (width, stride) in [(1, 2), (2, 5), (3, 11)] {
            let mut proofs = GapProofs::default();
            for i in 0..2048 {
                assert!(proofs.insert(1 + i * stride, 1 + i * stride + width));
            }
            assert_eq!(proofs.descriptor_count(), 1);
            for i in [0, 1, 511, 512, 1024, 2047] {
                let start = 1 + i * stride;
                assert_eq!(proofs.through(start), Some(start + width));
                assert_eq!(
                    proofs.through(start + width),
                    None,
                    "stride holes are not absence proof"
                );
            }
            assert!(proofs.runs.capacity() <= GapProofs::LIMIT);
        }
    }

    #[test]
    fn complementary_runs_merge_only_when_their_intervals_cover_the_period() {
        let mut proofs = GapProofs::default();
        for i in 0..1024 {
            proofs.insert(1 + 4 * i, 2 + 4 * i);
        }
        for i in 0..1024 {
            proofs.insert(3 + 4 * i, 4 + 4 * i);
        }
        assert_eq!(proofs.descriptor_count(), 1);
        assert_eq!(proofs.through(2), None);
        for i in 0..2048 {
            proofs.insert(2 + 2 * i, 3 + 2 * i);
        }
        assert_eq!(proofs.descriptor_count(), 1);
        assert_eq!(proofs.through(1), Some(4097));
    }

    #[test]
    fn sparse_irregular_proofs_keep_the_lowest_bounded_descriptors() {
        let mut proofs = GapProofs::default();
        let mut start = 1;
        let mut omitted = 0;
        for width in 1..=600 {
            if width == 513 {
                omitted = start;
            }
            proofs.insert(start, start + width);
            start += width + 1024;
            assert!(proofs.runs.len() <= GapProofs::LIMIT);
            assert!(proofs.runs.capacity() <= GapProofs::LIMIT);
        }
        assert_eq!(proofs.descriptor_count(), 512);
        assert!(proofs.overflowed());
        assert_eq!(proofs.through(1), Some(2));
        assert_eq!(proofs.through(2), None);
        assert_eq!(proofs.through(omitted), None, "overflow invented absence");
        assert!(proofs.insert(3, 704));
        assert_eq!(proofs.through(3), Some(704));
        assert_eq!(proofs.descriptor_count(), 512);
        assert!(proofs.runs.capacity() <= GapProofs::LIMIT);
        proofs.insert(0, 1);
        assert_eq!(proofs.through(0), Some(2));
        assert!(proofs.runs.capacity() <= GapProofs::LIMIT);
        proofs.prune(start);
        assert!(proofs.is_empty());
        assert!(!proofs.overflowed());
    }

    #[test]
    fn exact_queries_match_a_finite_reference_union_after_insert_and_prune() {
        let mut proofs = GapProofs::default();
        let mut expected = [false; 256];
        let mut state = 0x5ea1_u64;
        let mut next = 0;
        for turn in 0..512 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let start = ((state >> 32) as usize % 255).max(next);
            let width = ((state >> 16) as usize % 11) + 1;
            let end = (start + width).min(256);
            if start < end {
                assert!(proofs.insert(start as u64, end as u64));
                expected[start..end].fill(true);
            }
            if turn % 29 == 0 && next < 200 {
                next += 3;
                proofs.prune(next as u64);
            }
            for (gsn, known) in expected.iter().enumerate().skip(next) {
                let through = proofs.through(gsn as u64);
                assert_eq!(through.is_some(), *known, "query at {gsn}");
                if let Some(end) = through {
                    assert!(expected[gsn..end as usize].iter().all(|known| *known));
                }
            }
            assert!(proofs.runs.capacity() <= GapProofs::LIMIT);
        }
    }

    #[test]
    fn every_compressed_union_matches_its_actual_finite_intervals() {
        let mut state = 0x51ca_u64;
        let mut draw = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            state >> 32
        };
        for _ in 0..8192 {
            let mut build = || {
                let first = draw() % 13;
                let width = 1 + draw() % 4;
                let stride = width + draw() % 6;
                let count = 1 + draw() % 8;
                Run::new(first, width, stride, count).unwrap()
            };
            let a = build();
            let b = build();
            if let Some(merged) = a.merge(b) {
                for gsn in 0..100 {
                    assert_eq!(
                        merged.through(gsn).is_some(),
                        a.through(gsn).is_some() || b.through(gsn).is_some(),
                        "compression changed the proved union: {a:?}, {b:?}, at {gsn}"
                    );
                }
            }
            for next in [0, 1, 9, 17, 33, 65, 99] {
                let mut pruned = a;
                let alive = pruned.prune(next);
                for gsn in next..100 {
                    assert_eq!(
                        alive && pruned.through(gsn).is_some(),
                        a.through(gsn).is_some()
                    );
                }
            }
        }
    }

    #[test]
    fn pruning_and_large_gsns_use_checked_arithmetic_without_expansion() {
        let mut proofs = GapProofs::default();
        let count = (u64::MAX - 2) / 2;
        let run = Run::new(1, 1, 2, count).unwrap();
        proofs.runs.push(run);
        let last = run.last_start();
        assert_eq!(proofs.through(last), Some(last + 1));
        assert_eq!(proofs.through(last - 1), None);
        proofs.prune(last);
        assert_eq!(proofs.descriptor_count(), 1);
        assert_eq!(proofs.through(last), Some(last + 1));
        proofs.prune(last + 1);
        assert!(proofs.is_empty());
        assert!(Run::new(1, 1, u64::MAX, 2).is_none());
        assert!(Run::new(u64::MAX, 1, 1, 1).is_none());
        assert!(Run::new(0, 1, 1, 0).is_none());
        assert!(Run::new(0, 2, 1, 2).is_none());
        assert!(!proofs.insert(5, 5));
        assert_eq!(std::mem::size_of::<Run>(), 32);
    }
}
