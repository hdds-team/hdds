// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Runtime primitives for lock-free data structures and event handling.

pub mod indexring;
pub mod merger;
pub(crate) mod shutdown;
pub mod slabpool;
pub mod slabpool_metrics;
pub(crate) mod staging_ceiling;
pub mod waitset;

pub use indexring::{IndexEntry, IndexRing};
pub(crate) use merger::DeliveryObserver;
pub(crate) use merger::LocalDeliveryOrder;
pub(crate) use merger::{
    lock_replay_cohort, CoherentMember, CoherentReplay, CoherentReplayIdentity, CoherentResult,
};
pub(crate) use merger::{
    mergers_freed, MergerWriter, NoRoom, ReaderDoor, ReaderId, RoomTimeout, SampleGate,
    WriteDeadline, WriterInstances,
};
pub use merger::{MergerReader, SampleFilter, TopicMerger};
pub(crate) use slabpool::Claim;
pub use slabpool::{SlabHandle, SlabPool, SlabRef};
pub use slabpool_metrics::SlabPoolMetrics;
pub use waitset::{
    WaitsetDriver, WaitsetRegistration, WaitsetSignal, WaitsetWaitError, WAITSET_DEFAULT_MAX_SLOTS,
};

// Re-export of the hub, which lives in engine/hub.rs, for backwards compatibility
pub use crate::engine::hub::{Event, Hub};

use crate::qos::MemoryPolicy;
use std::sync::{Arc, OnceLock};

/// The process-wide pool together with the [`MemoryPolicy`] that actually
/// built it, so a later caller asking for a different policy can be told
/// its request had no effect (see [`init_slab_pool_with_policy`]) instead
/// of the divergence staying invisible.
struct GlobalPool {
    pool: Arc<SlabPool>,
    policy: MemoryPolicy,
}

static GLOBAL_SLAB_POOL: OnceLock<GlobalPool> = OnceLock::new();

/// Get a reference to the global slab pool (creates it with the default
/// `MemoryPolicy` if not initialized).
///
/// Hot-path accessor: no `Arc` clone/drop per call. All accessors share
/// this single `get_or_init` construction path, so exactly one pool is
/// ever built and every caller observes the global instance.
#[inline]
pub fn get_slab_pool_ref() -> &'static Arc<SlabPool> {
    #[cfg(test)]
    if let Some(pool) = THREAD_SLAB_POOL_FOR_TEST.with(std::cell::Cell::get) {
        return pool;
    }
    &GLOBAL_SLAB_POOL
        .get_or_init(|| GlobalPool {
            pool: Arc::new(SlabPool::new()),
            policy: MemoryPolicy::default(),
        })
        .pool
}

#[cfg(test)]
thread_local! {
    /// Test-only: a slab pool that replaces the process-wide one for every
    /// accessor called on THIS thread (see [`private_slab_pool_for_test`]).
    static THREAD_SLAB_POOL_FOR_TEST: std::cell::Cell<Option<&'static Arc<SlabPool>>> =
        const { std::cell::Cell::new(None) };
}

/// A value a test hands out as `&'static` (the accessors the tests
/// replace return `&'static`) that is nevertheless freed: the owner holds
/// the allocation and releases it when dropped, instead of leaving it to
/// the process (which a leak checker reports).
///
/// The `&'static` it gives is a lie bounded by the owner: it must not be
/// used once the owner is dropped. Every use in this crate keeps the owner
/// in the guard that installs the reference (`PrivateSlabPoolGuard`,
/// `telemetry::PrivateMetricsGuard`), which removes the reference from the
/// thread before the owner drops.
#[cfg(test)]
pub(crate) struct TestOwned<T: 'static>(std::ptr::NonNull<T>);

// SAFETY: `TestOwned<T>` is a `Box<T>` held by raw pointer; it is as
// `Send`/`Sync` as the `T` it owns.
#[cfg(test)]
unsafe impl<T: Send + 'static> Send for TestOwned<T> {}
#[cfg(test)]
unsafe impl<T: Sync + 'static> Sync for TestOwned<T> {}

#[cfg(test)]
impl<T: 'static> TestOwned<T> {
    pub(crate) fn new(value: T) -> Self {
        // Freed by `drop`, the one place it is turned back into a `Box`.
        let raw = Box::into_raw(Box::new(value));
        // SAFETY: `Box::into_raw` never returns null.
        Self(unsafe { std::ptr::NonNull::new_unchecked(raw) })
    }

    /// The value as `&'static`, valid until this owner is dropped.
    pub(crate) fn get(&self) -> &'static T {
        // SAFETY: the pointer comes from `Box::into_raw` in `new` and is freed
        // only by `drop`; callers keep to the contract of the type.
        unsafe { &*self.0.as_ptr() }
    }
}

#[cfg(test)]
impl<T: 'static> Drop for TestOwned<T> {
    fn drop(&mut self) {
        // SAFETY: allocated by `Box::into_raw` in `new`, freed exactly once here.
        drop(unsafe { Box::from_raw(self.0.as_ptr()) });
    }
}

/// Restores the calling thread's previous slab pool when dropped.
#[cfg(test)]
pub(crate) struct PrivateSlabPoolGuard {
    previous: Option<&'static Arc<SlabPool>>,
    /// The pool this guard made (`owned_private_slab_pool_for_test`), freed
    /// after the thread's pool is restored (a field drops after the body of
    /// `Drop::drop`).
    _owned: Option<TestOwned<Arc<SlabPool>>>,
}

#[cfg(test)]
impl Drop for PrivateSlabPoolGuard {
    fn drop(&mut self) {
        THREAD_SLAB_POOL_FOR_TEST.with(|cell| cell.set(self.previous));
    }
}

/// Test-only: route every slab-pool accessor called on the CURRENT thread
/// to `pool` until the guard is dropped.
///
/// The process-wide pool is one byte budget shared by every test of the
/// `--lib` binary running at once: a test that exhausts it for real makes
/// every concurrent test's reservations fail (samples silently refused,
/// local writes returning `WouldBlock`). A test that needs an exhausted
/// pool exhausts a private one instead. Only sound when every handle the
/// test reserves is reserved, read and released on this thread: a handle
/// carries no pool identity.
#[cfg(test)]
pub(crate) fn private_slab_pool_for_test(pool: &'static Arc<SlabPool>) -> PrivateSlabPoolGuard {
    let previous = THREAD_SLAB_POOL_FOR_TEST.with(|cell| cell.replace(Some(pool)));
    PrivateSlabPoolGuard {
        previous,
        _owned: None,
    }
}

/// [`private_slab_pool_for_test`] for a pool built from `policy` that the
/// returned guard owns and frees when it is dropped (the pool itself is
/// shared by every `Arc` clone taken of it, and lives as long as the last):
/// no allocation is left behind for the process to leak. The `&'static`
/// reference is valid for as long as the guard is.
#[cfg(test)]
pub(crate) fn owned_private_slab_pool_for_test(
    policy: &MemoryPolicy,
) -> (&'static Arc<SlabPool>, PrivateSlabPoolGuard) {
    let owned = TestOwned::new(Arc::new(SlabPool::with_policy(policy)));
    let pool = owned.get();
    let mut guard = private_slab_pool_for_test(pool);
    guard._owned = Some(owned);
    (pool, guard)
}

/// Initialize global slab pool (default `MemoryPolicy`).
pub fn init_slab_pool() -> Arc<SlabPool> {
    get_slab_pool_ref().clone()
}

/// Whether a participant's requested [`MemoryPolicy`] differs from the one
/// that already built the process-wide pool, i.e. whether
/// [`init_slab_pool_with_policy`] must warn instead of staying quiet. Split
/// out as a pure function (no access to `GLOBAL_SLAB_POOL`) so this
/// decision has a unit test that cannot touch -- and so cannot leak a
/// non-default policy into -- the real, process-wide, shared-by-every-test
/// singleton; see that function's own doc comment for why calling IT
/// directly from a test is exactly the hazard
/// [`private_slab_pool_for_test`] exists to avoid.
fn policy_diverges(active: &MemoryPolicy, requested: &MemoryPolicy) -> bool {
    active != requested
}

/// Build (or reuse) the process-wide slab pool with `policy`.
///
/// There is exactly one slab pool per process (it is `rt`'s global, not a
/// per-`Participant` resource): the FIRST participant built in a process
/// decides it, like any other `OnceLock`. A later participant that asks
/// for a DIFFERENT policy does not get a second pool to itself -- it gets
/// the same shared one, unchanged -- so that divergence is logged instead
/// of a policy that silently never took effect. A later call with the SAME
/// policy (or the first call of all) logs nothing.
///
/// Called by `ParticipantBuilder::build()` with the builder's
/// `MemoryPolicy` (`MemoryPolicy::default()` if the application never set
/// one), so every participant creation goes through this comparison, not
/// only the ones that customize memory policy.
///
/// # Not test-safe to call with a non-default policy
///
/// Unlike [`get_slab_pool_ref`], this does NOT consult
/// `THREAD_SLAB_POOL_FOR_TEST`: it exists to touch the real
/// `GLOBAL_SLAB_POOL` at genuine participant start. A `--lib` test binary
/// runs thousands of tests in one process sharing that same `OnceLock` (see
/// [`private_slab_pool_for_test`]'s doc comment), so a test that calls this
/// with a policy other than [`MemoryPolicy::default`] risks LOCKING IN that
/// policy for every other test in the binary if it happens to run first.
/// [`policy_diverges`] carries this function's test coverage instead.
pub fn init_slab_pool_with_policy(policy: &MemoryPolicy) -> Arc<SlabPool> {
    let global = GLOBAL_SLAB_POOL.get_or_init(|| GlobalPool {
        pool: Arc::new(SlabPool::with_policy(policy)),
        policy: policy.clone(),
    });
    if policy_diverges(&global.policy, policy) {
        log::warn!(
            "[hdds] MemoryPolicy {policy:?} has no effect for this participant: the \
             process-wide slab pool was already built by an earlier participant with a \
             different policy ({:?}), and HDDS has one pool per process, configured once by \
             whichever participant starts first.",
            global.policy
        );
    }
    Arc::clone(&global.pool)
}

/// Get global slab pool (creates if not initialized)
pub fn get_slab_pool() -> Arc<SlabPool> {
    get_slab_pool_ref().clone()
}

#[cfg(test)]
mod memory_policy_tests {
    use super::*;

    #[test]
    fn identical_policies_do_not_diverge() {
        let a = MemoryPolicy::default();
        let b = MemoryPolicy::default();
        assert!(!policy_diverges(&a, &b));
        assert!(!policy_diverges(&b, &a));
    }

    #[test]
    fn a_different_heap_ceiling_diverges() {
        let a = MemoryPolicy::default();
        let b = MemoryPolicy {
            max_heap_bytes: a.max_heap_bytes + 1,
            ..a.clone()
        };
        assert!(
            policy_diverges(&a, &b),
            "a later participant's different max_heap_bytes must be detected, not ignored"
        );
    }

    #[test]
    fn different_large_pool_classes_diverge() {
        let a = MemoryPolicy::default();
        let b = MemoryPolicy {
            large_pool: crate::qos::LargePoolConfig::typical_large_data(),
            ..a.clone()
        };
        assert!(
            policy_diverges(&a, &b),
            "a later participant's different large_pool classes must be detected, not ignored"
        );
    }
}
