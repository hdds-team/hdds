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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// WaitSet - wait for multiple conditions
///
/// A WaitSet allows blocking until at least one attached Condition has
/// `trigger_value == true`. Uses a coalesced eventfd-driven driver to avoid
/// polling and minimise file descriptor usage.
pub struct WaitSet {
    driver: Arc<WaitsetDriver>,
    entries: Mutex<Vec<Option<ConditionEntry>>>,
    /// Set for the duration of a `wait()` call, so a second concurrent one
    /// can be refused. See `wait()` for why this is a correctness device and
    /// not a convenience.
    waiter_present: AtomicBool,
    /// A pending `notify()`. Level-triggered, so a request that lands before
    /// anyone is inside `wait()` is honoured by the next call rather than
    /// lost - which is the whole point on a shutdown path, where the race
    /// between raising the flag and entering the wait is unwinnable.
    manual_wake: AtomicBool,
    /// Test-only handoff after the false condition scan, before driver wait.
    #[cfg(any(test, feature = "test-support"))]
    before_wait_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Test-only: runs once, inside the next `attach_condition`, right
    /// after the condition has been handed its signal (so after the signal
    /// an already-triggered condition sends), with `entries` released.
    /// Lets a test park attach there and watch what a waiter makes of that
    /// signal.
    #[cfg(test)]
    attach_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// Releases the single-waiter slot when `wait()` leaves, however it leaves.
struct WaiterSlot<'a> {
    flag: &'a AtomicBool,
}

impl Drop for WaiterSlot<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

struct ConditionEntry {
    condition: Arc<dyn Condition>,
    /// Cached so that lookups under `entries` do not call into the
    /// condition, which is trait code (see `attach_condition`).
    condition_id: u64,
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
            waiter_present: AtomicBool::new(false),
            manual_wake: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            before_wait_hook: Mutex::new(None),
            #[cfg(test)]
            attach_hook: Mutex::new(None),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn before_next_driver_wait(&self, hook: Box<dyn FnOnce() + Send>) {
        *self
            .before_wait_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(hook);
    }

    /// Attach a Condition to this WaitSet
    ///
    /// Two rules hold for every path in this file.
    ///
    /// No `Condition` method runs under `entries`. `Condition` is a public
    /// trait, so `add_waitset_signal` and `remove_waitset_signal` are user
    /// code: a condition that called back into this WaitSet from there
    /// (`get_conditions`, say) would deadlock on the non-reentrant mutex,
    /// and every waiter would sit on `entries` past its deadline for as
    /// long as that call took. So the guard covers the duplicate check,
    /// the slot registration and the publication of the entry, and is
    /// released before the condition is handed its signal; detach takes
    /// the entry out under the guard and tells the condition afterwards;
    /// `Drop` has exclusive access and takes no lock at all. Even
    /// `condition_id` is cached in the entry rather than called.
    ///
    /// The entry is published before the condition gets its signal.
    /// `add_waitset_signal` signals at once when the condition is already
    /// triggered, and that is the only signal an already-true condition
    /// ever sends: a waiter that drains that event and takes the slot
    /// index must find the entry, and it does, because the entry was there
    /// before the signal could exist. Signalling first would let a waiter
    /// that looked the index up in between find nothing, wait again and
    /// never be woken.
    ///
    /// Lock order: `entries`, then the driver's slot table (`register_slot`
    /// here). `wait` takes the slot table inside the driver and `entries`
    /// only after the driver has returned; detach releases `entries`
    /// before `unregister_slot`. Condition locks nest with neither.
    pub fn attach_condition(&self, condition: Arc<dyn Condition>) -> super::Result<()> {
        let condition_id = condition.condition_id();

        let (slot_index, slot_id, signal) = {
            let mut entries = self.entries.lock().map_err(|_| super::Error::WouldBlock)?;
            if entries
                .iter()
                .flatten()
                .any(|entry| entry.condition_id == condition_id)
            {
                return Err(super::Error::Config(
                    "condition is already attached to this WaitSet".to_string(),
                ));
            }

            let registration = self.driver.register_slot().map_err(super::Error::IoError)?;
            let (slot_index, slot_id, signal) = registration.into_trait();

            if slot_index >= entries.len() {
                entries.resize_with(slot_index + 1, || None);
            }
            entries[slot_index] = Some(ConditionEntry {
                condition: Arc::clone(&condition),
                condition_id,
                slot_index,
                slot_id,
                signal: Arc::clone(&signal),
            });
            (slot_index, slot_id, signal)
        };

        self.install_hook(condition.as_ref(), Arc::clone(&signal));

        // A detach can run between the publication above and the hook
        // installation: it finds the entry, removes a hook that is not
        // installed yet (a no-op), drops the entry and releases the slot.
        // The hook would then outlive its registration and signal a slot
        // this WaitSet no longer owns. The driver tolerates that (a stale
        // bit is cleared when the index is reused, so at most one empty
        // wake, never a lost one), but the condition would carry a dead
        // hook until it pruned it. So the entry is checked again, by slot
        // id since the index may already have a new owner, and the hook is
        // taken back out if the entry is gone. Detach does its three steps
        // under one guard, so either all of them ran before this check and
        // the hook is removed here, or all of them run after
        // `add_waitset_signal` and detach removes it.
        let still_attached = {
            let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
            matches!(entries.get(slot_index), Some(Some(entry)) if entry.slot_id == slot_id)
        };
        if !still_attached {
            condition.remove_waitset_signal(signal.id());
        }

        Ok(())
    }

    /// Hand the condition its signal. This is trait code, so it runs with
    /// `entries` released, and the condition signals at once if it is
    /// already triggered, so it runs after the entry is published (see
    /// `attach_condition`). The test hook fires right after, so a test can
    /// park attach with that signal sent; moving this call moves the hook.
    fn install_hook(&self, condition: &dyn Condition, signal: Arc<dyn WaitsetSignal>) {
        condition.add_waitset_signal(signal);
        #[cfg(test)]
        self.fire_attach_hook();
    }

    #[cfg(test)]
    fn fire_attach_hook(&self) {
        // Taken out before it runs, so it fires once.
        let hook = self
            .attach_hook
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Run `hook` once, inside the next `attach_condition`, right after the
    /// condition has been handed its signal, with `entries` released.
    #[cfg(test)]
    fn set_attach_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        if let Ok(mut slot) = self.attach_hook.lock() {
            *slot = Some(hook);
        }
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
    ///
    /// The entry comes out under the guard, so the slot index stops
    /// resolving first; the condition is told with the guard released
    /// (trait code, see `attach_condition`); the slot is released last, so
    /// that no signal through this hook can reach a slot the driver has
    /// already handed to someone else. A signal that lands in between
    /// sets the bit of a registered slot whose entry is gone: an empty
    /// wake, nothing more.
    pub fn detach_condition(&self, condition: Arc<dyn Condition>) -> super::Result<()> {
        let condition_id = condition.condition_id();

        let entry = {
            let mut entries = self.entries.lock().map_err(|_| super::Error::WouldBlock)?;
            entries
                .iter_mut()
                .find(|slot| matches!(slot, Some(entry) if entry.condition_id == condition_id))
                .and_then(Option::take)
                .ok_or_else(|| {
                    super::Error::Config("condition not found in WaitSet during detach".to_string())
                })?
        };

        entry.condition.remove_waitset_signal(entry.signal.id());
        self.driver.unregister_slot(entry.slot_index, entry.slot_id);

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
    ///
    /// With `Some(timeout)`, returns `Err(WouldBlock)` only once the full
    /// timeout has elapsed on this call's own clock; a sub-millisecond timeout
    /// blocks for that duration rather than returning at once. With `None`,
    /// blocks until a condition triggers.
    ///
    /// # One waiter at a time
    ///
    /// Returns `Err(InvalidState)` if another thread is already blocked in
    /// `wait()` on this same WaitSet. DDS v1.4 section 2.2.2.4.2.1 mandates
    /// that refusal (`RETCODE_PRECONDITION_NOT_MET`), and this implementation
    /// needs it: the driver's readiness is a level that the first waiter
    /// CONSUMES. A second waiter parked in the driver after the first drained
    /// the event gets no further wake-up, and the only full re-scan of the
    /// conditions happens on entry, before the loop, so it can sleep to its
    /// timeout with its condition true the whole time.
    ///
    /// Sharing one WaitSet across threads is still fine; what is refused is
    /// two threads *blocking on it at once*.
    pub fn wait(&self, timeout: Option<Duration>) -> super::Result<Vec<Arc<dyn Condition>>> {
        log::debug!("[RUST-WAITSET] wait called timeout={:?}", timeout);
        if self
            .waiter_present
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(super::Error::InvalidState(
                "WaitSet::wait: another thread is already blocked on this WaitSet".to_string(),
            ));
        }
        // Clears the flag on every exit path, including the early returns and
        // an unwind out of trait code called while scanning conditions.
        let _waiter = WaiterSlot {
            flag: &self.waiter_present,
        };
        // Taken before the first scan so the deadline is measured from the
        // call, not from the start of the blocking phase.
        let start = timeout.map(|_| Instant::now());

        // An explicit wake-up request beats a condition scan: the caller asked
        // for this wait to end, and on the shutdown path there is no condition
        // for it to raise.
        if self.take_manual_wake() {
            return Ok(Vec::new());
        }

        if let Some(mut triggered) = self.collect_triggered(None) {
            triggered.retain(|cond| cond.get_trigger_value());
            if !triggered.is_empty() {
                return Ok(triggered);
            }
        }

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

            if self.take_manual_wake() {
                return Ok(Vec::new());
            }

            #[cfg(any(test, feature = "test-support"))]
            {
                let hook = self
                    .before_wait_hook
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            match self.driver.wait(remaining) {
                Ok(indices) => {
                    if self.take_manual_wake() {
                        return Ok(Vec::new());
                    }
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
                // The driver's timeout is a hint, not the deadline: the OS
                // wait primitive has its own granularity (whole milliseconds
                // on some platforms) and its own clock. The check at the top
                // of the loop is the only place that returns WouldBlock, so a
                // Timeout that lands before our deadline simply waits again
                // for the remainder. The driver never times out on a None
                // timeout, so this cannot spin on an unbounded wait.
                Err(WaitsetWaitError::Timeout) => {}
                Err(WaitsetWaitError::Io(err)) => return Err(super::Error::IoError(err)),
            }
        }
    }

    /// Notify the WaitSet to wake up from `wait()`.
    ///
    /// Wakes a blocked `wait()` from another thread without triggering any
    /// condition, and that `wait()` returns an EMPTY list: woken, nothing
    /// triggered. Meant for graceful shutdown, where the waiter has no
    /// condition to raise and `wait(None)` would otherwise never return.
    ///
    /// Level-triggered, not edge: a notify that lands before anyone is inside
    /// `wait()` is honoured by the next call rather than lost. Shutdown is
    /// exactly the case where the race between "set the flag" and "enter the
    /// wait" is real and unwinnable by the caller.
    ///
    /// It must wake the waiter AND make the next scan report a trigger: a
    /// wakeup that only wrote the driver's event would leave the waiter
    /// re-scanning, finding nothing triggered and going straight back to
    /// sleep, so with `wait(None)` the thread would never return.
    pub fn notify(&self) {
        // Flag BEFORE the wake, so a waiter that the event wakes is guaranteed
        // to find it. `SeqCst` on both sides: this is the same store-buffering
        // shape as the hook count and the status words, and it is cold enough
        // that the total order costs nothing worth counting.
        self.manual_wake.store(true, Ordering::SeqCst);
        self.driver.manual_notify();
    }

    /// Consume a pending manual wake, if any.
    fn take_manual_wake(&self) -> bool {
        self.manual_wake.swap(false, Ordering::SeqCst)
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
        // Exclusive access: the entries are taken without locking, and no
        // lock is held while the conditions are told (trait code).
        let entries = std::mem::take(
            self.entries
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for entry in entries.into_iter().flatten() {
            entry.condition.remove_waitset_signal(entry.signal.id());
            self.driver.unregister_slot(entry.slot_index, entry.slot_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::condition::{GuardCondition, StatusCondition, StatusMask};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;

    /// Upper bound on how late a short timed wait may return. The lower
    /// bound is the assertion that matters; this one only tells a wait
    /// that returned from one that hung, so it is deliberately loose: a
    /// loaded CI box can pause a process for hundreds of milliseconds, and
    /// a tight bound (100 ms, say) would turn such a pause into a red test.
    const GENEROUS_OVERSHOOT: Duration = Duration::from_secs(2);

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

    /// A timeout with a sub-millisecond remainder must not return early: the
    /// driver must not hand poll(2) a truncated whole number of milliseconds,
    /// or 1.5 ms would wait 1 ms and WaitSet would report WouldBlock before its
    /// own deadline.
    #[test]
    fn test_waitset_wait_sub_millisecond_remainder_honours_deadline() {
        let ws = WaitSet::new();
        let guard = Arc::new(GuardCondition::new());
        ws.attach_condition(guard)
            .expect("condition attachment should succeed");

        let timeout = Duration::from_micros(1500);
        let start = Instant::now();
        let result = ws.wait(Some(timeout));
        let elapsed = start.elapsed();

        assert!(matches!(result, Err(crate::dds::Error::WouldBlock)));
        assert!(
            elapsed >= timeout,
            "wait returned after {elapsed:?}, before the {timeout:?} deadline"
        );
        assert!(
            elapsed < GENEROUS_OVERSHOOT,
            "wait overshot the {timeout:?} deadline by too much: {elapsed:?}"
        );
    }

    /// A timeout under 1 ms must block for that long, not become
    /// poll(..., 0) and return at once.
    #[test]
    fn test_waitset_wait_below_one_millisecond_blocks() {
        let ws = WaitSet::new();
        let guard = Arc::new(GuardCondition::new());
        ws.attach_condition(guard)
            .expect("condition attachment should succeed");

        let timeout = Duration::from_micros(300);
        let start = Instant::now();
        let result = ws.wait(Some(timeout));
        let elapsed = start.elapsed();

        assert!(matches!(result, Err(crate::dds::Error::WouldBlock)));
        assert!(
            elapsed >= timeout,
            "wait returned after {elapsed:?}, before the {timeout:?} deadline"
        );
        assert!(
            elapsed < GENEROUS_OVERSHOOT,
            "wait overshot the {timeout:?} deadline by too much: {elapsed:?}"
        );
    }

    /// A zero timeout is a non-blocking probe: it reports WouldBlock at once
    /// when nothing is triggered, and it reports a triggered condition.
    #[test]
    fn test_waitset_wait_zero_timeout_is_a_probe() {
        let ws = WaitSet::new();
        let guard = Arc::new(GuardCondition::new());
        ws.attach_condition(guard.clone())
            .expect("condition attachment should succeed");

        let start = Instant::now();
        let result = ws.wait(Some(Duration::ZERO));
        assert!(matches!(result, Err(crate::dds::Error::WouldBlock)));
        assert!(start.elapsed() < GENEROUS_OVERSHOOT);

        guard.set_trigger_value(true);
        let triggered = ws
            .wait(Some(Duration::ZERO))
            .expect("triggered condition must be reported by a zero-timeout probe");
        assert_eq!(triggered.len(), 1);
    }

    /// Attaching an already-triggered condition sends exactly one signal,
    /// from inside `add_waitset_signal`. A waiter that is already blocked
    /// must be able to resolve that signal's slot index to the condition:
    /// attach must publish the entry before it installs the hook (and so
    /// sends the signal): otherwise a waiter that drained the event and
    /// looked the index up in that window finds nothing, waits again, and is
    /// never signalled a second time. The hook parks attach right after
    /// the signal is sent and waits there for the waiter's report: with
    /// the entry published first, the waiter resolves the index (or, if it
    /// arrives late, finds the entry in its first scan) and reports the
    /// condition while attach is still parked. With the hook installed
    /// first, the waiter could not resolve the index until attach moved on,
    /// so the report does not come and the park times out, which is the
    /// failure.
    /// The head start only makes the waiter likely to be inside the driver
    /// when the signal is sent; it is not needed for the pass.
    #[test]
    fn test_attach_of_triggered_condition_wakes_a_waiter_parked_across_attach() {
        let ws = Arc::new(WaitSet::new());
        let guard = Arc::new(GuardCondition::new());
        guard.set_trigger_value(true);

        let (seen_tx, seen_rx) = mpsc::channel();
        let waiter = {
            let ws = Arc::clone(&ws);
            thread::spawn(move || {
                let seen = ws.wait(Some(Duration::from_secs(5)));
                // The hook has given up on the receiver if the report is
                // late; the join below still tells a panic from a return.
                let _ = seen_tx.send(seen);
            })
        };
        thread::sleep(Duration::from_millis(50));

        // What the waiter reported while attach was parked after the
        // signal; None if it reported nothing in time.
        let seen_in_window = Arc::new(Mutex::new(None));
        ws.set_attach_hook({
            let seen_in_window = Arc::clone(&seen_in_window);
            Box::new(move || {
                *seen_in_window.lock().expect("test mutex") =
                    Some(seen_rx.recv_timeout(Duration::from_secs(2)).ok());
            })
        });
        ws.attach_condition(guard.clone())
            .expect("condition attachment should succeed");
        waiter.join().expect("waiter thread panicked");

        let seen = seen_in_window
            .lock()
            .expect("test mutex")
            .take()
            .expect("the attach hook must have run")
            .expect("the waiter must resolve the attach signal while attach is parked after it");
        let triggered =
            seen.expect("a waiter parked across attach must see the triggered condition");
        assert_eq!(triggered.len(), 1);
        assert_eq!(triggered[0].condition_id(), guard.condition_id());
    }

    /// A condition whose hooks call back into the WaitSet. `Condition` is a
    /// public trait, so this is a legal implementation, and attach, detach
    /// and drop must all survive it: they run no trait method under
    /// `entries`. Each step runs on its own thread and is given a bounded
    /// time, so a failure is a red test, not a hung suite.
    #[test]
    fn test_condition_may_call_back_into_the_waitset_from_its_hooks() {
        use std::sync::Weak;

        struct Reentrant {
            inner: GuardCondition,
            ws: Weak<WaitSet>,
        }

        impl Reentrant {
            fn look_back(&self) {
                if let Some(ws) = self.ws.upgrade() {
                    // get_conditions takes `entries`: a deadlock if the
                    // caller holds it.
                    let _ = ws.get_conditions();
                }
            }
        }

        impl Condition for Reentrant {
            fn get_trigger_value(&self) -> bool {
                self.inner.get_trigger_value()
            }
            fn condition_id(&self) -> u64 {
                self.inner.condition_id()
            }
            fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>) {
                self.look_back();
                self.inner.add_waitset_signal(signal);
            }
            fn remove_waitset_signal(&self, signal_id: u64) {
                self.look_back();
                self.inner.remove_waitset_signal(signal_id);
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        fn within(limit: Duration, step: impl FnOnce() + Send + 'static) -> bool {
            let (done_tx, done_rx) = mpsc::channel();
            thread::spawn(move || {
                step();
                let _ = done_tx.send(());
            });
            done_rx.recv_timeout(limit).is_ok()
        }

        const LIMIT: Duration = Duration::from_secs(2);

        let ws = Arc::new(WaitSet::new());
        let condition: Arc<dyn Condition> = Arc::new(Reentrant {
            inner: GuardCondition::new(),
            ws: Arc::downgrade(&ws),
        });

        let attached = {
            let (ws, condition) = (Arc::clone(&ws), Arc::clone(&condition));
            within(LIMIT, move || {
                ws.attach_condition(condition)
                    .expect("condition attachment should succeed");
            })
        };
        assert!(attached, "attach ran the condition's hook under `entries`");
        assert_eq!(ws.get_conditions().len(), 1);

        let detached = {
            let (ws, condition) = (Arc::clone(&ws), Arc::clone(&condition));
            within(LIMIT, move || {
                ws.detach_condition(condition)
                    .expect("condition detach should succeed");
            })
        };
        assert!(detached, "detach ran the condition's hook under `entries`");
        assert_eq!(ws.get_conditions().len(), 0);

        ws.attach_condition(Arc::clone(&condition))
            .expect("re-attachment should succeed");
        // Drop runs on the last owner; the condition's look_back fails to
        // upgrade by then, so this only checks that drop does not lock.
        let dropped = within(LIMIT, move || drop(ws));
        assert!(dropped, "drop deadlocked");
    }

    /// The same race without a hook: an already-triggered condition is
    /// attached and detached in a loop while a waiter loops on `wait`. The
    /// condition ends attached, so every wait must return it and none may
    /// time out. Timing-dependent as a detector, deterministic as a pass.
    #[test]
    fn test_attach_of_triggered_condition_under_a_looping_waiter() {
        const ROUNDS: usize = 300;

        let ws = Arc::new(WaitSet::new());
        let guard = Arc::new(GuardCondition::new());
        guard.set_trigger_value(true);

        let stop = Arc::new(AtomicBool::new(false));
        let waiter = {
            let ws = Arc::clone(&ws);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut timeouts = 0usize;
                while !stop.load(Ordering::Acquire) {
                    match ws.wait(Some(Duration::from_secs(5))) {
                        Ok(_) => {}
                        Err(crate::dds::Error::WouldBlock) => timeouts += 1,
                        Err(err) => panic!("wait failed: {err:?}"),
                    }
                }
                timeouts
            })
        };

        for _ in 0..ROUNDS {
            ws.attach_condition(guard.clone())
                .expect("condition attachment should succeed");
            ws.detach_condition(guard.clone())
                .expect("condition detach should succeed");
        }
        ws.attach_condition(guard.clone())
            .expect("final attachment should succeed");
        stop.store(true, Ordering::Release);

        let timeouts = waiter.join().expect("waiter thread panicked");
        assert_eq!(
            timeouts, 0,
            "a triggered condition was attached at every wait's end, none may time out"
        );
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

    #[test]
    fn a_second_concurrent_waiter_is_refused_instead_of_sleeping_forever() {
        use std::sync::mpsc;

        let waitset = Arc::new(WaitSet::new());
        let guard = Arc::new(GuardCondition::new());
        waitset
            .attach_condition(guard.clone())
            .expect("attach should succeed");

        // First waiter parks in the driver with nothing triggered.
        let (entered_tx, entered_rx) = mpsc::channel();
        let first = {
            let waitset = Arc::clone(&waitset);
            std::thread::spawn(move || {
                entered_tx.send(()).expect("handshake send");
                waitset.wait(Some(Duration::from_secs(2)))
            })
        };
        entered_rx.recv().expect("handshake recv");
        // The handshake only proves the thread started; give it time to park.
        std::thread::sleep(Duration::from_millis(100));

        // DDS v1.4 2.2.2.4.2.1: the second one must be told no, not queued
        // behind a level the first waiter is going to consume.
        match waitset.wait(Some(Duration::from_millis(50))) {
            Err(super::super::Error::InvalidState(_)) => {}
            other => panic!(
                "expected InvalidState for a second waiter, got {:?}",
                other.is_ok()
            ),
        }

        guard.set_trigger_value(true);
        let triggered = first
            .join()
            .expect("first waiter thread")
            .expect("first waiter should be woken");
        assert_eq!(triggered[0].condition_id(), guard.condition_id());

        // And the slot is released once the first waiter is done.
        guard.set_trigger_value(true);
        waitset
            .wait(Some(Duration::from_millis(100)))
            .expect("a later wait must be accepted again");
    }
}
