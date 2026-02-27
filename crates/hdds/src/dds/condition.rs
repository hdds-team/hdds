// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Conditions - event notification predicates for WaitSets
//!
//! Per DDS v1.4 specification, Conditions are predicates that can be attached
//! to WaitSets to enable event-driven blocking wait patterns.
//!

use crate::core::rt::waitset::WaitsetSignal;
use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Condition trait - base interface for all DDS conditions
///
/// A Condition is a boolean-valued predicate that can be evaluated.
/// Conditions are attached to WaitSets to enable blocking waits.
pub trait Condition: Send + Sync {
    /// Get the current trigger value of this condition
    ///
    /// Returns `true` if the condition is satisfied, `false` otherwise.
    fn get_trigger_value(&self) -> bool;

    /// Get a unique identifier for this condition (for comparison)
    fn condition_id(&self) -> u64;

    /// Register a waitset signal so this condition can wake blocked waiters.
    fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>);

    /// Remove a previously registered waitset signal.
    fn remove_waitset_signal(&self, signal_id: u64);

    /// Downcast support for dynamic condition handling.
    fn as_any(&self) -> &dyn Any;
}

/// Status mask bits for StatusCondition
///
/// Per DDS v1.4 spec section 2.2.4.1 - Communication Status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusMask(u32);

impl StatusMask {
    /// No status enabled
    pub const NONE: StatusMask = StatusMask(0);

    /// All statuses enabled
    pub const ALL: StatusMask = StatusMask(0xFFFFFFFF);

    /// Data available to read (DataReader)
    pub const DATA_AVAILABLE: StatusMask = StatusMask(1 << 0);

    /// Sample lost (DataReader)
    pub const SAMPLE_LOST: StatusMask = StatusMask(1 << 1);

    /// Sample rejected (DataReader)
    pub const SAMPLE_REJECTED: StatusMask = StatusMask(1 << 2);

    /// Liveliness changed (DataReader)
    pub const LIVELINESS_CHANGED: StatusMask = StatusMask(1 << 3);

    /// Requested deadline missed (DataReader)
    pub const REQUESTED_DEADLINE_MISSED: StatusMask = StatusMask(1 << 4);

    /// Requested incompatible QoS (DataReader)
    pub const REQUESTED_INCOMPATIBLE_QOS: StatusMask = StatusMask(1 << 5);

    /// Subscription matched (DataReader)
    pub const SUBSCRIPTION_MATCHED: StatusMask = StatusMask(1 << 6);

    /// Liveliness lost (DataWriter)
    pub const LIVELINESS_LOST: StatusMask = StatusMask(1 << 7);

    /// Offered deadline missed (DataWriter)
    pub const OFFERED_DEADLINE_MISSED: StatusMask = StatusMask(1 << 8);

    /// Offered incompatible QoS (DataWriter)
    pub const OFFERED_INCOMPATIBLE_QOS: StatusMask = StatusMask(1 << 9);

    /// Publication matched (DataWriter)
    pub const PUBLICATION_MATCHED: StatusMask = StatusMask(1 << 10);

    /// Create a new StatusMask from raw bits
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        StatusMask(bits)
    }

    /// Get the raw bits value
    #[must_use]
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if this mask contains the given status
    #[must_use]
    pub const fn contains(&self, other: StatusMask) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two masks with bitwise OR
    #[must_use]
    pub const fn or(self, other: StatusMask) -> Self {
        StatusMask(self.0 | other.0)
    }

    /// Intersect two masks with bitwise AND
    #[must_use]
    pub const fn and(self, other: StatusMask) -> Self {
        StatusMask(self.0 & other.0)
    }
}

impl std::ops::BitOr for StatusMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.or(rhs)
    }
}

impl std::ops::BitAnd for StatusMask {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        self.and(rhs)
    }
}

/// StatusCondition - condition based on Entity communication status
///
/// Per DDS v1.4 spec section 2.2.4.1.4:
/// "A StatusCondition object is associated with each Entity. The trigger_value
/// is determined by the communication statuses of that Entity."
pub struct StatusCondition {
    /// Unique identifier for this condition
    id: u64,

    /// Enabled status mask - which statuses to monitor
    enabled_statuses: Arc<Mutex<StatusMask>>,

    /// Current active statuses (set by entity when status changes)
    active_statuses: Arc<Mutex<StatusMask>>,

    /// Waitset hooks to notify when trigger value changes
    waitset_signals: Mutex<Vec<WaitsetHook>>,
}

impl StatusCondition {
    /// Create a new StatusCondition
    ///
    /// By default, no statuses are enabled (must call `set_enabled_statuses`)
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        Self {
            id,
            enabled_statuses: Arc::new(Mutex::new(StatusMask::NONE)),
            active_statuses: Arc::new(Mutex::new(StatusMask::NONE)),
            waitset_signals: Mutex::new(Vec::new()),
        }
    }

    /// Set which statuses this condition should monitor
    ///
    /// # Example
    ///
    /// ```ignore
    /// let condition = StatusCondition::new();
    /// condition.set_enabled_statuses(
    ///     StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED
    /// );
    /// ```
    pub fn set_enabled_statuses(&self, mask: StatusMask) {
        if let Ok(mut enabled) = self.enabled_statuses.lock() {
            *enabled = mask;
        }

        if self.get_trigger_value() {
            self.notify_waitsets();
        }
    }

    /// Get the currently enabled statuses
    pub fn get_enabled_statuses(&self) -> StatusMask {
        self.enabled_statuses
            .lock()
            .map(|m| *m)
            .unwrap_or(StatusMask::NONE)
    }

    /// Set active statuses (called by Entity when status changes)
    ///
    /// This is an internal method used by DataReader/DataWriter to signal
    /// status changes.
    pub(crate) fn set_active_statuses(&self, mask: StatusMask) {
        let enabled = self.get_enabled_statuses();
        if let Ok(mut active) = self.active_statuses.lock() {
            *active = mask;
        }

        if enabled.and(mask).bits() != 0 {
            self.notify_waitsets();
        }
    }

    /// Get the currently active statuses
    pub fn get_active_statuses(&self) -> StatusMask {
        self.active_statuses
            .lock()
            .map(|m| *m)
            .unwrap_or(StatusMask::NONE)
    }

    /// Clear active statuses (called after read)
    pub(crate) fn clear_active_statuses(&self) {
        if let Ok(mut active) = self.active_statuses.lock() {
            *active = StatusMask::NONE;
        }
    }
}

impl Condition for StatusCondition {
    fn get_trigger_value(&self) -> bool {
        let enabled = self.get_enabled_statuses();
        let active = self.get_active_statuses();

        // Trigger is true if any enabled status is active
        enabled.and(active).bits() != 0
    }

    fn condition_id(&self) -> u64 {
        self.id
    }

    fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>) {
        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] StatusCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        hooks.retain(|hook| hook.signal.upgrade().is_some());
        log::debug!(
            "[STATUS-CONDITION] attach signal id={} cond_id={}",
            signal.id(),
            self.id
        );
        hooks.push(WaitsetHook {
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

impl Default for StatusCondition {
    fn default() -> Self {
        Self::new()
    }
}

struct WaitsetHook {
    id: u64,
    signal: Weak<dyn WaitsetSignal>,
}

impl StatusCondition {
    fn notify_waitsets(&self) {
        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] StatusCondition waitset_signals poisoned, recovering");
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

/// GuardCondition - manually-triggered condition
///
/// Per DDS v1.4 spec section 2.2.4.1.5:
/// "A GuardCondition is a Condition whose trigger_value is under the control
/// of the application."
pub struct GuardCondition {
    /// Unique identifier for this condition
    id: u64,

    /// Trigger value (controlled by application)
    trigger_value: AtomicBool,

    /// Waitset hooks to notify when trigger value flips true
    waitset_signals: Mutex<Vec<WaitsetHook>>,
}

impl GuardCondition {
    /// Create a new GuardCondition with trigger_value = false
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(1_000_000);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        Self {
            id,
            trigger_value: AtomicBool::new(false),
            waitset_signals: Mutex::new(Vec::new()),
        }
    }

    /// Set the trigger value
    ///
    /// When set to `true`, any WaitSet waiting on this condition will wake up.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let guard = GuardCondition::new();
    /// guard.set_trigger_value(true);  // Wake up WaitSet
    /// ```
    pub fn set_trigger_value(&self, value: bool) {
        self.trigger_value.store(value, Ordering::Release);
        if value {
            self.notify_waitsets();
        }
    }

    fn notify_waitsets(&self) {
        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] GuardCondition waitset_signals poisoned, recovering");
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

impl Condition for GuardCondition {
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
                log::debug!("[condition] GuardCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        hooks.retain(|hook| hook.signal.upgrade().is_some());
        hooks.push(WaitsetHook {
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

impl Default for GuardCondition {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for entities that have a StatusCondition (DataReader, DataWriter).
///
/// This trait enables the convenience method `WaitSet::attach(&entity)`.
///
/// # Example
/// ```ignore
/// let reader = participant.create_reader::<MyType>("topic", QoS::default())?;
/// let waitset = WaitSet::new();
/// waitset.attach(&reader)?;  // Convenience - calls get_status_condition() internally
/// ```
pub trait HasStatusCondition {
    /// Get the StatusCondition associated with this entity.
    fn get_status_condition(&self) -> Arc<StatusCondition>;
}

#[cfg(test)]
mod tests;
