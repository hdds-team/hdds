// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Lock recovery utilities for poisoned RwLocks.

use std::sync::{RwLock, RwLockWriteGuard};

/// Recover from a poisoned RwLock write guard while logging the context.
pub(crate) fn recover_write<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[admin] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}
