// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The wake of a parked TIME_BASED_FILTER sample (DDS v1.4 Sec.2.2.3.12).
//!
//! A sample that arrives before its instance's window ends is parked in the
//! reader's cache and enters the history at the first access at or after
//! the window's end. An application that polls finds it there. One that
//! waits on a WaitSet or a listener must be told: the participant's
//! liveliness scheduler fires an entry at the window's end, which queues a
//! [`FilterWaker`] notice, run on the notices thread (never on the
//! scheduler), that raises DATA_AVAILABLE as an arrival does.
//!
//! The wake carries no sample and owns nothing: losing it (a participant
//! torn down first, a refused thread) only means the sample is shown at the
//! next access instead of being announced.

use super::notices::{Notice, Ordered};
use super::subscriber::ReaderSubscriber;
use crate::dds::liveliness::{FilterWakeSink, Shared};
use crate::dds::reader::InstanceHandle;
use crate::dds::DDS;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Instant;

/// The reader's link to its participant's liveliness scheduler: the clock
/// that arms a wake, and the notices queue the wake is told on.
pub(super) struct FilterWaker<T: DDS> {
    clock: Arc<Shared>,
    notices: Arc<Ordered>,
    reader: OnceLock<Weak<ReaderSubscriber<T>>>,
    /// How many samples the reader's cache holds parked: a wake that finds
    /// none (the application already took them) has nothing to announce.
    parked: OnceLock<Arc<AtomicUsize>>,
}

impl<T: DDS> FilterWaker<T> {
    pub(super) fn new(clock: Arc<Shared>) -> Self {
        Self {
            clock,
            notices: Arc::new(Ordered::default()),
            reader: OnceLock::new(),
            parked: OnceLock::new(),
        }
    }

    /// Set once the reader's `Arc` exists (the wake holds a `Weak`, so the
    /// scheduler never keeps a dropped reader alive).
    pub(super) fn set_reader(&self, reader: Weak<ReaderSubscriber<T>>) {
        let _ = self.reader.set(reader);
    }

    pub(super) fn set_parked(&self, parked: Arc<AtomicUsize>) {
        let _ = self.parked.set(parked);
    }

    /// Wake the application at `at` for `handle`'s parked sample.
    pub(super) fn arm(self: &Arc<Self>, handle: InstanceHandle, at: Instant) {
        let remaining = at.saturating_duration_since(Instant::now());
        let nanos = u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX);
        let when = self.clock.now().saturating_add(nanos);
        let weak: Weak<FilterWaker<T>> = Arc::downgrade(self);
        let sink: Weak<dyn FilterWakeSink> = weak;
        let _ = self.clock.arm_filter_wake(sink, handle, when);
    }
}

impl<T: DDS> FilterWakeSink for FilterWaker<T> {
    fn wake(&self, _handle: InstanceHandle) -> Option<Arc<Ordered>> {
        if self
            .parked
            .get()
            .is_some_and(|parked| parked.load(Ordering::Acquire) == 0)
        {
            return None;
        }
        let reader = self.reader.get()?.clone();
        let notice: Notice = Box::new(move || {
            if let Some(reader) = reader.upgrade() {
                reader.filter_window_ended();
            }
        });
        match self.notices.push(notice) {
            Ok(()) => Some(Arc::clone(&self.notices)),
            Err(notice) => {
                // A full queue: told on a thread of its own, as the
                // DEADLINE notices are.
                if let Err(e) = std::thread::Builder::new()
                    .name("hdds-notices".to_string())
                    .spawn(notice)
                {
                    log::error!("[reader] a TIME_BASED_FILTER wake is lost: no thread ({e})");
                }
                None
            }
        }
    }
}

impl<T: DDS> Drop for FilterWaker<T> {
    fn drop(&mut self) {
        self.notices.close();
    }
}
