// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! WaitSet - blocking wait for Condition triggers
//!
//! Backed by the runtime waitset driver (`core::rt::waitset`) which uses
//! coalesced `eventfd` notifications. Conditions register a waitset signal when
//! attached so they can wake blocked waiters immediately when their trigger
//! value flips to `true`.

use super::condition::{Condition, HasStatusCondition};
use crate::core::rt::{WaitsetDriver, WaitsetSignal, WaitsetWaitError, WAITSET_DEFAULT_MAX_SLOTS};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// WaitSet - wait for multiple conditions
///
/// A WaitSet allows blocking until at least one attached Condition has
/// `trigger_value == true`. Uses a coalesced eventfd-driven driver to avoid
/// polling and minimise file descriptor usage.
pub struct WaitSet {
    driver: Arc<WaitsetDriver>,
    entries: Mutex<Vec<Option<ConditionEntry>>>,
}

struct ConditionEntry {
    condition: Arc<dyn Condition>,
    slot_index: usize,
    slot_id: u64,
    signal: Arc<dyn WaitsetSignal>,
}

impl WaitSet {
    /// Create a new WaitSet
    #[must_use]
    pub fn new() -> Self {
        #[allow(clippy::expect_used)]
        // waitset driver creation is infallible on supported platforms
        let driver = WaitsetDriver::new(WAITSET_DEFAULT_MAX_SLOTS)
            .expect("waitset driver creation must succeed on supported platforms");

        Self {
            driver: Arc::new(driver),
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Attach a Condition to this WaitSet
    pub fn attach_condition(&self, condition: Arc<dyn Condition>) -> super::Result<()> {
        let condition_id = condition.condition_id();

        // Prevent duplicate attachments
        {
            let entries = self.entries.lock().map_err(|_| super::Error::WouldBlock)?;
            if entries
                .iter()
                .flatten()
                .any(|entry| entry.condition.condition_id() == condition_id)
            {
                return Err(super::Error::Config);
            }
        }

        let registration = self.driver.register_slot().map_err(super::Error::IoError)?;
        let (slot_index, slot_id, signal) = registration.into_trait();

        condition.add_waitset_signal(Arc::clone(&signal));

        let mut entries = self.entries.lock().map_err(|_| super::Error::WouldBlock)?;

        if slot_index >= entries.len() {
            entries.resize_with(slot_index + 1, || None);
        }

        entries[slot_index] = Some(ConditionEntry {
            condition,
            slot_index,
            slot_id,
            signal,
        });

        Ok(())
    }

    /// Attach an entity's StatusCondition to this WaitSet (convenience method).
    ///
    /// This is a convenience wrapper around `attach_condition()` for entities
    /// that implement `HasStatusCondition` (like `DataReader` and `DataWriter`).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use hdds::{Participant, QoS, WaitSet};
    /// # fn main() -> hdds::Result<()> {
    /// # let participant = Participant::builder("test").build()?;
    /// # let reader = participant.create_reader::<MyType>("topic", QoS::default())?;
    /// let waitset = WaitSet::new();
    /// waitset.attach(&reader)?;  // Convenience
    /// // Equivalent to: waitset.attach_condition(reader.get_status_condition())?;
    /// # Ok(())
    /// # }
    /// # #[derive(hdds::DDS)] struct MyType { x: i32 }
    /// ```
    pub fn attach<E: HasStatusCondition>(&self, entity: &E) -> super::Result<()> {
        self.attach_condition(entity.get_status_condition())
    }

    /// Detach a Condition from this WaitSet
    pub fn detach_condition(&self, condition: Arc<dyn Condition>) -> super::Result<()> {
        let condition_id = condition.condition_id();

        let mut entries = self.entries.lock().map_err(|_| super::Error::WouldBlock)?;

        let (slot_index, slot_id) = {
            let mut result = None;
            for entry in entries.iter_mut().flatten() {
                if entry.condition.condition_id() == condition_id {
                    let slot_index = entry.slot_index;
                    let slot_id = entry.slot_id;
                    let signal_id = entry.signal.id();
                    entry.condition.remove_waitset_signal(signal_id);
                    result = Some((slot_index, slot_id));
                    break;
                }
            }
            result.ok_or(super::Error::Config)?
        };

        if let Some(entry) = entries.get_mut(slot_index) {
            *entry = None;
        }

        drop(entries);
        self.driver.unregister_slot(slot_index, slot_id);

        Ok(())
    }

    /// Get all attached Conditions
    #[must_use]
    pub fn get_conditions(&self) -> Vec<Arc<dyn Condition>> {
        self.entries
            .lock()
            .map(|entries| {
                entries
                    .iter()
                    .flatten()
                    .map(|entry| Arc::clone(&entry.condition))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Wait until at least one Condition is triggered
    pub fn wait(&self, timeout: Option<Duration>) -> super::Result<Vec<Arc<dyn Condition>>> {
        log::debug!("[RUST-WAITSET] wait called timeout={:?}", timeout);
        if let Some(mut triggered) = self.collect_triggered(None) {
            triggered.retain(|cond| cond.get_trigger_value());
            if !triggered.is_empty() {
                return Ok(triggered);
            }
        }

        let start = timeout.map(|_| Instant::now());

        loop {
            let remaining = match (timeout, start) {
                (Some(total), Some(begin)) => {
                    let elapsed = begin.elapsed();
                    if elapsed >= total {
                        return Err(super::Error::WouldBlock);
                    }
                    Some(total.saturating_sub(elapsed))
                }
                _ => timeout,
            };

            match self.driver.wait(remaining) {
                Ok(indices) => {
                    let candidates = if indices.is_empty() {
                        self.collect_triggered(None)
                    } else {
                        self.collect_triggered(Some(&indices))
                    };

                    if let Some(mut triggered) = candidates {
                        triggered.retain(|cond| cond.get_trigger_value());
                        if !triggered.is_empty() {
                            log::debug!(
                                "[RUST-WAITSET] wait returning triggered_len={}",
                                triggered.len()
                            );
                            return Ok(triggered);
                        }
                    }
                }
                Err(WaitsetWaitError::Timeout) => return Err(super::Error::WouldBlock),
                Err(WaitsetWaitError::Io(err)) => return Err(super::Error::IoError(err)),
            }
        }
    }

    /// Notify the WaitSet to wake up from `wait()`.
    ///
    /// Wakes a blocked `wait()` call from another thread without triggering
    /// any condition. Used for graceful shutdown or external event injection.
    pub fn notify(&self) {
        self.driver.manual_notify();
    }

    fn collect_triggered(&self, indices: Option<&[usize]>) -> Option<Vec<Arc<dyn Condition>>> {
        let entries = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[waitset] entries mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };

        let mut triggered = Vec::new();

        match indices {
            Some(slots) => {
                for &slot in slots {
                    if let Some(Some(entry)) = entries.get(slot) {
                        triggered.push(Arc::clone(&entry.condition));
                    }
                }
            }
            None => {
                for entry in entries.iter().flatten() {
                    triggered.push(Arc::clone(&entry.condition));
                }
            }
        }

        Some(triggered)
    }
}

impl Default for WaitSet {
    fn default() -> Self {
        Self::new()
    }
}

// WaitSet is thread-safe (driver + mutex protected)
unsafe impl Send for WaitSet {}
unsafe impl Sync for WaitSet {}

impl Drop for WaitSet {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.entries.lock() {
            for entry_opt in entries.iter_mut() {
                if let Some(entry) = entry_opt.take() {
                    entry.condition.remove_waitset_signal(entry.signal.id());
                    self.driver.unregister_slot(entry.slot_index, entry.slot_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::condition::{GuardCondition, StatusCondition, StatusMask};
    use std::thread;

    #[test]
    fn test_waitset_new() {
        let ws = WaitSet::new();
        assert_eq!(ws.get_conditions().len(), 0);
    }

    #[test]
    fn test_waitset_attach_condition() {
        let ws = WaitSet::new();
        let guard = Arc::new(GuardCondition::new());

        assert!(ws.attach_condition(guard.clone()).is_ok());
        assert_eq!(ws.get_conditions().len(), 1);
    }

    #[test]
    fn test_waitset_attach_duplicate() {
        let ws = WaitSet::new();
        let guard = Arc::new(GuardCondition::new());

        assert!(ws.attach_condition(guard.clone()).is_ok());
        assert!(ws.attach_condition(guard).is_err());
    }

    #[test]
    fn test_waitset_detach_condition() {
        let ws = WaitSet::new();
        let guard = Arc::new(GuardCondition::new());

        ws.attach_condition(guard.clone())
            .expect("condition attachment should succeed");
        assert!(ws.detach_condition(guard).is_ok());
        assert_eq!(ws.get_conditions().len(), 0);
    }

    #[test]
    fn test_waitset_detach_not_attached() {
        let ws = WaitSet::new();
        let guard = Arc::new(GuardCondition::new());

        assert!(ws.detach_condition(guard).is_err());
    }

    #[test]
    fn test_waitset_wait_immediate_trigger() {
        let ws = WaitSet::new();
        let guard = Arc::new(GuardCondition::new());

        guard.set_trigger_value(true);
        ws.attach_condition(guard.clone())
            .expect("condition attachment should succeed");

        let result = ws.wait(Some(Duration::from_millis(100)));
        assert!(result.is_ok());
        let triggered = result.expect("wait should succeed");
        assert_eq!(triggered.len(), 1);
        assert_eq!(triggered[0].condition_id(), guard.condition_id());
    }

    #[test]
    fn test_waitset_wait_timeout() {
        let ws = WaitSet::new();
        let guard = Arc::new(GuardCondition::new());

        ws.attach_condition(guard)
            .expect("condition attachment should succeed");

        let start = Instant::now();
        let result = ws.wait(Some(Duration::from_millis(100)));
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(elapsed >= Duration::from_millis(80));
    }

    #[test]
    fn test_waitset_wait_async_trigger() {
        let ws = Arc::new(WaitSet::new());
        let guard = Arc::new(GuardCondition::new());

        ws.attach_condition(guard.clone())
            .expect("condition attachment should succeed");

        let guard_clone = Arc::clone(&guard);

        thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            guard_clone.set_trigger_value(true);
        });

        let start = Instant::now();
        let result = ws.wait(Some(Duration::from_secs(1)));
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        let triggered = result.expect("wait should succeed");
        assert_eq!(triggered.len(), 1);
        assert!(elapsed >= Duration::from_millis(50));
    }

    #[test]
    fn test_waitset_multiple_conditions() {
        let ws = WaitSet::new();
        let guard1 = Arc::new(GuardCondition::new());
        let guard2 = Arc::new(GuardCondition::new());
        let status = Arc::new(StatusCondition::new());

        status.set_enabled_statuses(StatusMask::DATA_AVAILABLE);

        ws.attach_condition(guard1.clone())
            .expect("guard1 attachment should succeed");
        ws.attach_condition(guard2.clone())
            .expect("guard2 attachment should succeed");
        ws.attach_condition(status.clone())
            .expect("status attachment should succeed");

        status.set_active_statuses(StatusMask::DATA_AVAILABLE);

        let triggered = ws
            .wait(Some(Duration::from_millis(100)))
            .expect("wait should succeed");
        assert_eq!(triggered.len(), 1);
        assert_eq!(triggered[0].condition_id(), status.condition_id());

        guard1.set_trigger_value(true);
        let triggered = ws
            .wait(Some(Duration::from_millis(100)))
            .expect("wait should succeed");
        assert_eq!(triggered[0].condition_id(), guard1.condition_id());
    }
}
