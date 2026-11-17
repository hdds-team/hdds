// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Waitset bridge exposing HDDS waitset primitives to the C FFI.
//!
//! ## Ownership and destruction order
//!
//! Every condition kind (Status, Guard, Read, Query) is handed to
//! `ForeignWaitSet` as an `Arc` clone, never a borrow of the C-side handle.
//! The C-visible pointer (from `hdds_*_create`/`hdds_reader_get_status_condition`)
//! is itself the address of an `Arc::into_raw` allocation, refcounted a
//! second time by a per-kind registry in `lib.rs`/`condition_ffi.rs` that
//! tracks how many outstanding C handles point at it.
//!
//! Attaching a condition to a waitset clones that `Arc` again and stores the
//! clone in this module's `ConditionRegistry`. That clone is independent of
//! the C-side handle's refcount:
//! - If the C caller releases/deletes its condition handle while it is still
//!   attached, the `Arc` allocation is NOT freed (the waitset's clone keeps
//!   the strong count above zero); the condition simply becomes owned solely
//!   by the waitset until it is detached or the waitset is destroyed.
//! - If the waitset is destroyed (or the condition is detached) while the
//!   condition is still owned by C, the waitset's `ConditionRegistry` is
//!   dropped, releasing its `Arc` clone; the condition stays alive as long
//!   as the C handle's own reference is outstanding.
//!
//! Either destruction order is therefore safe: no side ever holds a raw
//! pointer into memory the other side has freed, because both sides hold a
//! real `Arc` strong reference rather than a borrowed pointer.

use hdds::api::{Condition, Error as ApiError, GuardCondition, StatusCondition, WaitSet};
use hdds::dds::{QueryCondition, ReadCondition};
use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::HddsError;

/// Internal error type for waitset operations.
#[derive(Debug)]
pub(crate) enum WaitsetError {
    InvalidArgument,
    DuplicateCondition,
    NotFound,
    WaitFailed,
}

impl From<WaitsetError> for HddsError {
    fn from(err: WaitsetError) -> Self {
        match err {
            WaitsetError::InvalidArgument => HddsError::HddsInvalidArgument,
            WaitsetError::DuplicateCondition => HddsError::HddsInvalidArgument,
            WaitsetError::NotFound => HddsError::HddsNotFound,
            WaitsetError::WaitFailed => HddsError::HddsOperationFailed,
        }
    }
}

/// Tracks waitset registrations and keeps conditions alive across FFI.
pub(crate) struct ForeignWaitSet {
    waitset: WaitSet,
    registry: Mutex<ConditionRegistry>,
}

struct ConditionRegistry {
    /// Map raw pointer (as usize) to condition entry.
    by_ptr: HashMap<usize, ConditionEntry>,
    /// Map condition id to raw pointer key.
    by_id: HashMap<u64, usize>,
}

struct ConditionEntry {
    id: u64,
    raw_ptr: *const c_void,
    kind: ConditionKind,
}

enum ConditionKind {
    Status(Arc<StatusCondition>),
    Guard(Arc<GuardCondition>),
    Read(Arc<ReadCondition>),
    Query(Arc<QueryCondition>),
}

impl ConditionKind {
    fn as_dyn(&self) -> Arc<dyn Condition> {
        match self {
            ConditionKind::Status(cond) => cond.clone(),
            ConditionKind::Guard(cond) => cond.clone(),
            ConditionKind::Read(cond) => cond.clone(),
            ConditionKind::Query(cond) => cond.clone(),
        }
    }
}

impl ForeignWaitSet {
    pub fn new() -> Self {
        Self {
            waitset: WaitSet::new(),
            registry: Mutex::new(ConditionRegistry {
                by_ptr: HashMap::new(),
                by_id: HashMap::new(),
            }),
        }
    }

    pub fn attach_status(
        &self,
        condition: Arc<StatusCondition>,
        raw_ptr: *const c_void,
    ) -> Result<(), WaitsetError> {
        self.attach_condition(ConditionKind::Status(condition), raw_ptr)
    }

    pub fn attach_guard(
        &self,
        condition: Arc<GuardCondition>,
        raw_ptr: *const c_void,
    ) -> Result<(), WaitsetError> {
        self.attach_condition(ConditionKind::Guard(condition), raw_ptr)
    }

    /// Attach a ReadCondition, mirroring `attach_status`/`attach_guard`: the
    /// `Arc` clone lives in the registry so the WaitSet's hook (installed
    /// through the same `Condition::add_waitset_signal` path StatusCondition
    /// and GuardCondition use) keeps the condition alive independently of
    /// the C-side handle. See the module doc comment on ownership.
    pub fn attach_read(
        &self,
        condition: Arc<ReadCondition>,
        raw_ptr: *const c_void,
    ) -> Result<(), WaitsetError> {
        self.attach_condition(ConditionKind::Read(condition), raw_ptr)
    }

    /// Attach a QueryCondition. See `attach_read`.
    pub fn attach_query(
        &self,
        condition: Arc<QueryCondition>,
        raw_ptr: *const c_void,
    ) -> Result<(), WaitsetError> {
        self.attach_condition(ConditionKind::Query(condition), raw_ptr)
    }

    pub fn detach(&self, raw_ptr: *const c_void) -> Result<(), WaitsetError> {
        if raw_ptr.is_null() {
            return Err(WaitsetError::InvalidArgument);
        }

        let ptr_key = raw_ptr as usize;

        let mut registry = self.registry.lock().expect("waitset registry poisoned");

        let Some(entry) = registry.by_ptr.remove(&ptr_key) else {
            return Err(WaitsetError::NotFound);
        };

        registry.by_id.remove(&entry.id);

        self.waitset
            .detach_condition(entry.kind.as_dyn())
            .map_err(|_| WaitsetError::WaitFailed)
    }

    pub fn wait(&self, timeout: Option<Duration>) -> Result<Vec<*const c_void>, WaitsetError> {
        let triggered = match self.waitset.wait(timeout) {
            Ok(list) => list,
            Err(ApiError::WouldBlock) => Vec::new(),
            Err(_) => return Err(WaitsetError::WaitFailed),
        };

        let registry = self.registry.lock().expect("waitset registry poisoned");

        let mut pointers = Vec::with_capacity(triggered.len());
        for condition in triggered {
            let id = condition.condition_id();
            let Some(ptr_key) = registry.by_id.get(&id) else {
                return Err(WaitsetError::WaitFailed);
            };
            if let Some(entry) = registry.by_ptr.get(ptr_key) {
                pointers.push(entry.raw_ptr);
            }
        }

        Ok(pointers)
    }

    fn attach_condition(
        &self,
        kind: ConditionKind,
        raw_ptr: *const c_void,
    ) -> Result<(), WaitsetError> {
        if raw_ptr.is_null() {
            return Err(WaitsetError::InvalidArgument);
        }

        let ptr_key = raw_ptr as usize;
        let id = kind.as_dyn().condition_id();

        let mut registry = self.registry.lock().expect("waitset registry poisoned");

        if registry.by_ptr.contains_key(&ptr_key) || registry.by_id.contains_key(&id) {
            return Err(WaitsetError::DuplicateCondition);
        }

        self.waitset
            .attach_condition(kind.as_dyn())
            .map_err(|_| WaitsetError::WaitFailed)?;

        registry
            .by_ptr
            .insert(ptr_key, ConditionEntry { id, raw_ptr, kind });
        registry.by_id.insert(id, ptr_key);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdds::api::GuardCondition;
    use std::ptr;

    #[test]
    fn attach_and_wait_guard_condition() {
        let waitset = ForeignWaitSet::new();
        let guard = Arc::new(GuardCondition::new());
        let raw = Arc::into_raw(guard.clone()) as *const c_void;

        waitset
            .attach_guard(guard.clone(), raw)
            .expect("attach guard");

        guard.set_trigger_value(true);
        let triggered = waitset.wait(Some(Duration::from_millis(10))).expect("wait");
        assert_eq!(triggered.len(), 1);
        assert_eq!(triggered[0], raw);

        waitset.detach(raw).expect("detach");
        unsafe {
            Arc::from_raw(raw.cast::<GuardCondition>());
        }
    }

    #[test]
    fn wait_timeout_empty() {
        let waitset = ForeignWaitSet::new();
        let result = waitset.wait(Some(Duration::from_millis(1))).expect("wait");
        assert!(result.is_empty());
    }

    #[test]
    fn detach_unknown_returns_error() {
        let waitset = ForeignWaitSet::new();
        let err = waitset.detach(ptr::null()).expect_err("err");
        assert!(matches!(err, WaitsetError::InvalidArgument));
    }
}
