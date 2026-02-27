// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Runtime primitives for lock-free data structures and event handling.

pub mod indexring;
pub mod merger;
pub mod slabpool;
pub mod waitset;

pub use indexring::{IndexEntry, IndexRing};
pub use merger::{MergerReader, TopicMerger};
pub use slabpool::{SlabHandle, SlabPool};
pub use waitset::{
    WaitsetDriver, WaitsetRegistration, WaitsetSignal, WaitsetWaitError, WAITSET_DEFAULT_MAX_SLOTS,
};

// Hub has been moved to engine/hub.rs
// Legacy re-export for backwards compatibility
pub use crate::engine::hub::{Event, Hub};

use std::sync::{Arc, OnceLock};

static GLOBAL_SLAB_POOL: OnceLock<Arc<SlabPool>> = OnceLock::new();

/// Initialize global slab pool
pub fn init_slab_pool() -> Arc<SlabPool> {
    GLOBAL_SLAB_POOL
        .get_or_init(|| Arc::new(SlabPool::new()))
        .clone()
}

/// Get global slab pool (creates if not initialized)
pub fn get_slab_pool() -> Arc<SlabPool> {
    GLOBAL_SLAB_POOL
        .get()
        .cloned()
        .unwrap_or_else(init_slab_pool)
}
