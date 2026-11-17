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
    StatusCondition, StatusMask, DDS,
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
    /// One drain per attached reader, run after every `wait`.
    ///
    /// ROS 2 has no dispose-event API, so a node built on this adapter can
    /// never call `DataReader::get_dispose_events` and the queue behind it
    /// would grow for the lifetime of the node. Since a queued dispose also
    /// keeps its condition true - a DDS status is level-triggered and stays
    /// raised until the application reads it - an undrained queue would also
    /// wake this waitset continuously. Draining here is what makes the rmw
    /// layer a reader of that status rather than an application that ignores
    /// it. The events themselves are discarded: nothing in the ROS 2 API can
    /// carry them.
    reader_drains: Mutex<HashMap<ConditionKey, Box<dyn Fn() + Send + Sync>>>,
}

impl Default for WaitSetInner {
    fn default() -> Self {
        Self {
            waitset: WaitSet::new(),
            registry: Mutex::new(HashMap::new()),
            reader_drains: Mutex::new(HashMap::new()),
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
    ///
    /// Automatically enables `DATA_AVAILABLE` on the reader's `StatusCondition`
    /// so the waitset wakes when intra-process or network data arrives.
    pub fn attach_reader<T: DDS>(&self, reader: &DataReader<T>) -> ApiResult<ConditionHandle> {
        let status = reader.get_status_condition();
        status.set_enabled_statuses(status.get_enabled_statuses().or(StatusMask::DATA_AVAILABLE));
        let key = status.condition_id();
        let handle = self.attach_status(status)?;

        // See `reader_drains`. Registered only once the attach succeeded, so
        // a failed attach leaves nothing behind.
        if let Ok(mut drains) = self.inner.reader_drains.lock() {
            drains.insert(key, Box::new(reader.dispose_drain_hook()));
        }
        Ok(handle)
    }

    /// Wait for any attached condition to become active.
    pub fn wait(&self, timeout: Option<Duration>) -> ApiResult<Vec<ConditionKey>> {
        let triggered = match self.inner.waitset.wait(timeout) {
            Ok(list) => list,
            Err(ApiError::WouldBlock) => {
                self.drain_reader_events();
                return Ok(Vec::new());
            }
            Err(err) => return Err(err),
        };
        self.drain_reader_events();

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
                return Err(ApiError::Config(
                    "triggered condition is not registered in this WaitSet".to_string(),
                ));
            }
        }

        Ok(keys)
    }

    /// Take and discard every attached reader's dispose events. See
    /// `WaitSetInner::reader_drains` for why this belongs in the wait cycle.
    fn drain_reader_events(&self) {
        let Ok(drains) = self.inner.reader_drains.lock() else {
            return;
        };
        for drain in drains.values() {
            drain();
        }
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
            return Err(ApiError::Config(
                "condition is already attached to this WaitSet".to_string(),
            ));
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
            return Err(ApiError::Config(
                "condition handle key not found during detach".to_string(),
            ));
        };

        self.inner
            .waitset
            .detach_condition(condition)
            .map_err(|e| ApiError::Config(format!("WaitSet detach_condition failed: {}", e)))
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
