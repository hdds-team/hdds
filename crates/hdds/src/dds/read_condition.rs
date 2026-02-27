// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ReadCondition and QueryCondition for DataReader event filtering
//!

use super::condition::Condition;
use crate::core::rt::waitset::WaitsetSignal;
use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Sample state mask for ReadCondition
///
/// Per DDS v1.4 spec section 2.2.2.5.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleStateMask(u32);

impl SampleStateMask {
    /// Sample has been read
    pub const READ: SampleStateMask = SampleStateMask(1 << 0);

    /// Sample has not been read
    pub const NOT_READ: SampleStateMask = SampleStateMask(1 << 1);

    /// Any sample state
    pub const ANY: SampleStateMask = SampleStateMask(Self::READ.0 | Self::NOT_READ.0);

    /// Create from raw bits
    pub const fn from_bits(bits: u32) -> Self {
        SampleStateMask(bits)
    }

    /// Get raw bits
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if contains state
    pub const fn contains(&self, other: SampleStateMask) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for SampleStateMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        SampleStateMask(self.0 | rhs.0)
    }
}

/// View state mask for ReadCondition
///
/// Per DDS v1.4 spec section 2.2.2.5.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewStateMask(u32);

impl ViewStateMask {
    /// Instance is new (first sample)
    pub const NEW: ViewStateMask = ViewStateMask(1 << 0);

    /// Instance is not new (subsequent samples)
    pub const NOT_NEW: ViewStateMask = ViewStateMask(1 << 1);

    /// Any view state
    pub const ANY: ViewStateMask = ViewStateMask(Self::NEW.0 | Self::NOT_NEW.0);

    /// Create from raw bits
    pub const fn from_bits(bits: u32) -> Self {
        ViewStateMask(bits)
    }

    /// Get raw bits
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if contains state
    pub const fn contains(&self, other: ViewStateMask) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for ViewStateMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        ViewStateMask(self.0 | rhs.0)
    }
}

/// Instance state mask for ReadCondition
///
/// Per DDS v1.4 spec section 2.2.2.5.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceStateMask(u32);

impl InstanceStateMask {
    /// Instance is alive (writer exists)
    pub const ALIVE: InstanceStateMask = InstanceStateMask(1 << 0);

    /// Instance writer has disposed
    pub const NOT_ALIVE_DISPOSED: InstanceStateMask = InstanceStateMask(1 << 1);

    /// Instance writer has lost liveliness
    pub const NOT_ALIVE_NO_WRITERS: InstanceStateMask = InstanceStateMask(1 << 2);

    /// Any instance state
    pub const ANY: InstanceStateMask = InstanceStateMask(
        Self::ALIVE.0 | Self::NOT_ALIVE_DISPOSED.0 | Self::NOT_ALIVE_NO_WRITERS.0,
    );

    /// Create from raw bits
    pub const fn from_bits(bits: u32) -> Self {
        InstanceStateMask(bits)
    }

    /// Get raw bits
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if contains state
    pub const fn contains(&self, other: InstanceStateMask) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for InstanceStateMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        InstanceStateMask(self.0 | rhs.0)
    }
}

/// ReadCondition - condition based on DataReader sample states
///
/// Per DDS v1.4 spec section 2.2.4.1.6:
/// "A ReadCondition is a Condition associated with a DataReader. The trigger_value
/// depends on the presence of samples in the DataReader that match the specified states."
pub struct ReadCondition {
    /// Unique identifier
    id: u64,

    /// Sample state mask
    sample_state_mask: SampleStateMask,

    /// View state mask
    view_state_mask: ViewStateMask,

    /// Instance state mask
    instance_state_mask: InstanceStateMask,

    /// Trigger value (updated by DataReader)
    trigger_value: AtomicBool,

    /// Waitset hooks to notify on trigger change
    waitset_signals: Mutex<Vec<ReadConditionHook>>,
}

impl ReadCondition {
    /// Create a new ReadCondition
    ///
    /// # Arguments
    ///
    /// * `sample_state_mask` - Which sample states to match
    /// * `view_state_mask` - Which view states to match
    /// * `instance_state_mask` - Which instance states to match
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Match only unread samples
    /// let cond = ReadCondition::new(
    ///     SampleStateMask::NOT_READ,
    ///     ViewStateMask::ANY,
    ///     InstanceStateMask::ALIVE
    /// );
    /// ```
    pub fn new(
        sample_state_mask: SampleStateMask,
        view_state_mask: ViewStateMask,
        instance_state_mask: InstanceStateMask,
    ) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(2_000_000);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        Self {
            id,
            sample_state_mask,
            view_state_mask,
            instance_state_mask,
            trigger_value: AtomicBool::new(false),
            waitset_signals: Mutex::new(Vec::new()),
        }
    }

    /// Get the sample state mask
    pub fn get_sample_state_mask(&self) -> SampleStateMask {
        self.sample_state_mask
    }

    /// Get the view state mask
    pub fn get_view_state_mask(&self) -> ViewStateMask {
        self.view_state_mask
    }

    /// Get the instance state mask
    pub fn get_instance_state_mask(&self) -> InstanceStateMask {
        self.instance_state_mask
    }

    /// Set trigger value (called by DataReader when matching samples available)
    #[allow(dead_code)] // Will be used by DataReader in future
    pub(crate) fn set_trigger_value(&self, value: bool) {
        self.trigger_value.store(value, Ordering::Release);
        if value {
            self.notify_waitsets();
        }
    }

    fn notify_waitsets(&self) {
        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] ReadCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        hooks.retain(|hook| {
            if let Some(signal) = hook.signal.upgrade() {
                signal.signal();
                true
            } else {
                false
            }
        });
    }
}

struct ReadConditionHook {
    id: u64,
    signal: Weak<dyn WaitsetSignal>,
}

impl Condition for ReadCondition {
    fn get_trigger_value(&self) -> bool {
        self.trigger_value.load(Ordering::Acquire)
    }

    fn condition_id(&self) -> u64 {
        self.id
    }

    fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>) {
        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] ReadCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        hooks.retain(|hook| hook.signal.upgrade().is_some());
        hooks.push(ReadConditionHook {
            id: signal.id(),
            signal: Arc::downgrade(&signal),
        });

        if self.get_trigger_value() {
            signal.signal();
        }
    }

    fn remove_waitset_signal(&self, signal_id: u64) {
        if let Ok(mut hooks) = self.waitset_signals.lock() {
            hooks.retain(|hook| hook.id != signal_id);
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// QueryCondition - ReadCondition with SQL-like query expression
///
/// Per DDS v1.4 spec section 2.2.4.1.7:
/// "A QueryCondition is a specialization of ReadCondition that allows specifying
/// a filter on the content of the data."
pub struct QueryCondition {
    /// Base ReadCondition
    base: ReadCondition,

    /// Query expression (SQL-like subset)
    query_expression: String,

    /// Query parameters
    query_parameters: Arc<Mutex<Vec<String>>>,
}

impl QueryCondition {
    /// Create a new QueryCondition
    ///
    /// # Arguments
    ///
    /// * `sample_state_mask` - Which sample states to match
    /// * `view_state_mask` - Which view states to match
    /// * `instance_state_mask` - Which instance states to match
    /// * `query_expression` - SQL-like filter expression (e.g., "temperature > %0")
    /// * `query_parameters` - Parameters to substitute in expression (e.g., `["25.0"]`)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cond = QueryCondition::new(
    ///     SampleStateMask::NOT_READ,
    ///     ViewStateMask::ANY,
    ///     InstanceStateMask::ALIVE,
    ///     "temperature > %0 AND pressure < %1",
    ///     vec!["25.0".to_string(), "100.0".to_string()]
    /// );
    /// ```
    pub fn new(
        sample_state_mask: SampleStateMask,
        view_state_mask: ViewStateMask,
        instance_state_mask: InstanceStateMask,
        query_expression: String,
        query_parameters: Vec<String>,
    ) -> Self {
        Self {
            base: ReadCondition::new(sample_state_mask, view_state_mask, instance_state_mask),
            query_expression,
            query_parameters: Arc::new(Mutex::new(query_parameters)),
        }
    }

    /// Get the query expression
    pub fn get_query_expression(&self) -> &str {
        &self.query_expression
    }

    /// Get the query parameters
    pub fn get_query_parameters(&self) -> Vec<String> {
        self.query_parameters
            .lock()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    /// Set new query parameters
    pub fn set_query_parameters(&self, parameters: Vec<String>) {
        if let Ok(mut params) = self.query_parameters.lock() {
            *params = parameters;
        }
    }

    /// Set trigger value (called by DataReader when matching samples available)
    #[allow(dead_code)] // Will be used by DataReader in future
    pub(crate) fn set_trigger_value(&self, value: bool) {
        self.base.set_trigger_value(value);
    }
}

impl Condition for QueryCondition {
    fn get_trigger_value(&self) -> bool {
        self.base.get_trigger_value()
    }

    fn condition_id(&self) -> u64 {
        self.base.condition_id()
    }

    fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>) {
        self.base.add_waitset_signal(signal);
    }

    fn remove_waitset_signal(&self, signal_id: u64) {
        self.base.remove_waitset_signal(signal_id);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests;
