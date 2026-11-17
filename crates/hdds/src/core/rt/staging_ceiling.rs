// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The process-wide ceiling on what coherent readers stage
//! (`MemoryPolicy::max_staging_bytes`), kept by the slab pool every reader
//! of the process stores in.
//!
//! Each coherent reader stages its sets in a budget of its own (the
//! reader's `staging_budget` module states the rule); the budgets of one
//! process together are held within this ceiling, each reader that stages
//! entitled to a fair share of it. A member that would take the process
//! past it makes room by rejecting sets whole, only of the readers above
//! their share (the youngest first); nothing waits for room here. The
//! budgets register as [`StagedSets`], so that one reader's member can
//! reject another reader's set.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// A reader's staged sets, as the ceiling sees them: each by the stamp of
/// its first member's arrival ([`StagingCeiling::next_arrival`]).
pub(crate) trait StagedSets: Send + Sync {
    /// What the reader stages now, in bytes (its charges together).
    fn used(&self) -> usize;

    /// The stamp of the youngest set staged here that can be rejected
    /// from outside the reader: of the sets in order when `in_order`, of
    /// the others otherwise. `None` when there is none, or when the reader
    /// cannot be reached.
    fn youngest(&self, in_order: bool) -> Option<u64>;

    /// Reject the set staged with stamp `arrival` whole, its storage given
    /// back before this returns. Whether a set was found to reject.
    fn reject(&self, arrival: u64) -> bool;
}

/// The process-wide staging ceiling (see the module documentation).
pub(crate) struct StagingCeiling {
    /// `MemoryPolicy::max_staging_bytes`.
    limit: usize,
    /// What every registered budget has charged, together (bytes as
    /// stored).
    total: AtomicUsize,
    /// The next set's arrival stamp.
    arrivals: AtomicU64,
    /// Charged loss markers that cannot be reclaimed without their unit.
    pinned_sets: AtomicUsize,
    /// The budgets of the process, as long as they live.
    budgets: Mutex<Vec<Weak<dyn StagedSets>>>,
}

impl std::fmt::Debug for StagingCeiling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagingCeiling")
            .field("limit", &self.limit)
            .field("total", &self.total.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl StagingCeiling {
    /// A ceiling of `limit` bytes.
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            total: AtomicUsize::new(0),
            arrivals: AtomicU64::new(0),
            pinned_sets: AtomicUsize::new(0),
            budgets: Mutex::new(Vec::new()),
        })
    }

    /// The ceiling, in bytes.
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// What the process's coherent readers stage now, in bytes.
    #[cfg(test)]
    pub(crate) fn total(&self) -> usize {
        self.total.load(Ordering::Acquire)
    }

    /// `len` bytes charged by a budget if the process stays within the
    /// ceiling with them: whether they are. Atomic: members admitted
    /// concurrently never take the process past it together.
    pub(crate) fn try_charge(&self, len: usize) -> bool {
        self.total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |total| {
                total
                    .checked_add(len)
                    .filter(|&charged| charged <= self.limit)
            })
            .is_ok()
    }

    /// `len` bytes a budget charged given back.
    pub(crate) fn discharge(&self, len: usize) {
        // Never below zero: every discharge follows its charge.
        let _ = self
            .total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |total| {
                Some(total.saturating_sub(len))
            });
    }

    /// A charged set acquired its first retained loss marker.
    pub(crate) fn pin_set(&self) {
        self.pinned_sets.fetch_add(1, Ordering::AcqRel);
    }

    /// The final charge of a pinned set was released.
    pub(crate) fn unpin_set(&self) {
        let old = self.pinned_sets.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(old > 0, "pinned set released twice");
    }

    /// Called only after the process ceiling refused an admission.
    pub(crate) fn has_pinned_sets(&self) -> bool {
        self.pinned_sets.load(Ordering::Acquire) != 0
    }

    /// A stamp later than every one given before.
    pub(crate) fn next_arrival(&self) -> u64 {
        self.arrivals.fetch_add(1, Ordering::AcqRel)
    }

    /// `budget` takes part in the ceiling for as long as it lives.
    pub(crate) fn register(&self, budget: Weak<dyn StagedSets>) {
        let mut budgets = self.budgets.lock().unwrap_or_else(|e| e.into_inner());
        budgets.retain(|b| b.strong_count() > 0);
        budgets.push(budget);
    }

    /// The budgets of the process other than `own`, as long as they live.
    /// The registry's lock is released on return.
    pub(crate) fn others(&self, own: *const ()) -> Vec<Arc<dyn StagedSets>> {
        self.budgets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|b| !std::ptr::eq(Arc::as_ptr(b).cast::<()>(), own))
            .collect()
    }

    /// A reader's fair share of the ceiling when `staging` readers stage
    /// (at least one): the ceiling split evenly among them.
    pub(crate) fn share(&self, staging: usize) -> usize {
        self.limit / staging.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct One(std::sync::Mutex<Option<u64>>);

    impl StagedSets for One {
        fn used(&self) -> usize {
            usize::from(self.0.lock().expect("one").is_some())
        }
        fn youngest(&self, _in_order: bool) -> Option<u64> {
            *self.0.lock().expect("one")
        }
        fn reject(&self, arrival: u64) -> bool {
            let mut set = self.0.lock().expect("one");
            if *set == Some(arrival) {
                *set = None;
                return true;
            }
            false
        }
    }

    #[test]
    fn the_others_skip_their_own_budget_and_the_dead() {
        let ceiling = StagingCeiling::new(100);
        let a: Arc<dyn StagedSets> = Arc::new(One(std::sync::Mutex::new(Some(3))));
        let b: Arc<dyn StagedSets> = Arc::new(One(std::sync::Mutex::new(Some(7))));
        ceiling.register(Arc::downgrade(&a));
        ceiling.register(Arc::downgrade(&b));
        let own = Arc::as_ptr(&b).cast::<()>();
        let others = ceiling.others(own);
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].youngest(false), Some(3));
        drop(others);
        drop(a);
        assert!(ceiling.others(own).is_empty());
        ceiling.register(Arc::downgrade(&b));
        assert_eq!(ceiling.budgets.lock().expect("budgets").len(), 2);
        assert_eq!(ceiling.share(0), 100);
        assert_eq!(ceiling.share(3), 33);
        assert!(ceiling.try_charge(10));
        assert!(!ceiling.try_charge(91), "past the ceiling");
        assert!(ceiling.try_charge(90), "up to it");
        ceiling.discharge(130);
        assert_eq!(ceiling.total(), 0);
    }
}
