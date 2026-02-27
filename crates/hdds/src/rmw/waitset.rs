// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ROS 2 waitset wrapper built on top of the core HDDS WaitSet.
//!
//! The RMW adapter needs deterministic attach/detach semantics and must keep
//! conditions alive while they are registered with a waitset. This module
//! provides a thin wrapper around [`crate::dds::WaitSet`] that tracks every
//! attached condition, assigns a stable `ConditionKey` and exposes helpers
//! for mapping the triggered handles back to the underlying guard/status
//! conditions.

use crate::dds::WaitSet;
use crate::dds::{
    Condition, DataReader, Error as ApiError, GuardCondition, Participant, Result as ApiResult,
    StatusCondition, DDS,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Identifier associated with a registered condition (stable across clones).
pub type ConditionKey = u64;

/// Thin wrapper around [`WaitSet`] that keeps conditions alive and provides
/// deterministic detach semantics for the rmw layer.
#[derive(Default)]
pub struct RmwWaitSet {
    inner: Arc<WaitSetInner>,
}

struct WaitSetInner {
    waitset: WaitSet,
    registry: Mutex<HashMap<ConditionKey, Arc<dyn Condition>>>,
}

impl Default for WaitSetInner {
    fn default() -> Self {
        Self {
            waitset: WaitSet::new(),
            registry: Mutex::new(HashMap::new()),
        }
    }
}

impl RmwWaitSet {
    /// Create a new rmw waitset wrapper.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(WaitSetInner::default()),
        }
    }

    /// Attach the participant discovery guard condition.
    pub fn attach_participant(&self, participant: &Participant) -> ApiResult<ConditionHandle> {
        let guard = participant.graph_guard();
        self.attach_guard(&guard)
    }

    /// Attach a guard condition (used for custom events such as shutdown).
    pub fn attach_guard(&self, guard: &Arc<GuardCondition>) -> ApiResult<ConditionHandle> {
        self.attach_condition(Arc::clone(guard) as Arc<dyn Condition>)
    }

    /// Attach an explicit status condition (helper for future rmw handles).
    pub fn attach_status(&self, status: Arc<StatusCondition>) -> ApiResult<ConditionHandle> {
        self.attach_condition(status as Arc<dyn Condition>)
    }

    /// Attach a reader's status condition.
    pub fn attach_reader<T: DDS>(&self, reader: &DataReader<T>) -> ApiResult<ConditionHandle> {
        let status = reader.get_status_condition();
        self.attach_status(status)
    }

    /// Wait for any attached condition to become active.
    pub fn wait(&self, timeout: Option<Duration>) -> ApiResult<Vec<ConditionKey>> {
        let triggered = match self.inner.waitset.wait(timeout) {
            Ok(list) => list,
            Err(ApiError::WouldBlock) => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };

        let registry = self
            .inner
            .registry
            .lock()
            .map_err(|_| ApiError::WouldBlock)?;

        let mut keys = Vec::with_capacity(triggered.len());
        for condition in triggered {
            let key = condition.condition_id();
            if registry.contains_key(&key) {
                keys.push(key);
            } else {
                return Err(ApiError::Config);
            }
        }

        Ok(keys)
    }

    /// Retrieve the registered condition associated with a key.
    #[must_use]
    pub fn condition(&self, key: ConditionKey) -> Option<Arc<dyn Condition>> {
        self.inner
            .registry
            .lock()
            .ok()
            .and_then(|registry| registry.get(&key).cloned())
    }

    fn attach_condition(&self, condition: Arc<dyn Condition>) -> ApiResult<ConditionHandle> {
        let key = condition.condition_id();

        let mut registry = self
            .inner
            .registry
            .lock()
            .map_err(|_| ApiError::WouldBlock)?;

        if registry.contains_key(&key) {
            return Err(ApiError::Config);
        }

        self.inner
            .waitset
            .attach_condition(Arc::clone(&condition))?;
        registry.insert(key, condition);

        Ok(ConditionHandle {
            inner: Arc::clone(&self.inner),
            key,
            active: true,
        })
    }
}

/// Handle returned when a condition is attached to the waitset.
/// Detaches automatically when dropped.
pub struct ConditionHandle {
    inner: Arc<WaitSetInner>,
    key: ConditionKey,
    active: bool,
}

impl ConditionHandle {
    /// Identifier associated with the registered condition.
    #[must_use]
    pub fn key(&self) -> ConditionKey {
        self.key
    }

    /// Explicitly detach the condition.
    pub fn detach(mut self) -> ApiResult<()> {
        if self.active {
            self.detach_inner()?;
            self.active = false;
        }
        Ok(())
    }

    fn detach_inner(&self) -> ApiResult<()> {
        let mut registry = self
            .inner
            .registry
            .lock()
            .map_err(|_| ApiError::WouldBlock)?;

        let Some(condition) = registry.remove(&self.key) else {
            return Err(ApiError::Config);
        };

        self.inner
            .waitset
            .detach_condition(condition)
            .map_err(|_| ApiError::Config)
    }
}

impl Drop for ConditionHandle {
    fn drop(&mut self) {
        if self.active && self.detach_inner().is_ok() {
            self.active = false;
        }
    }
}

#[cfg(test)]
mod tests;
