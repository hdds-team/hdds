// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A writer's own LIVELINESS_LOST (DDS v1.4 Sec.2.2.4.1): MANUAL_BY_PARTICIPANT
//! and MANUAL_BY_TOPIC only -- AUTOMATIC's liveliness is the participant's
//! to keep, never the application's to miss.
//!
//! One watch per writer (`WriterAssert`'s renewal, watched by
//! `Shared::watch`), on the scheduler thread; the status update and the
//! listener queue happen there, the listener itself on a thread of its own
//! (see the module doc on `ReaderLiveliness` for why).

use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use super::leases::{LivelinessSink, Renewal, WatchKey};
use super::scheduler::Shared;
use crate::dds::listener::LivelinessLostStatus;
use crate::dds::reader::notices::{Notice, Ordered};
use crate::dds::{StatusCondition, StatusMask};

/// The listener call reporting `status`, when a listener covers
/// LIVELINESS_LOST now.
pub(crate) type LivelinessLostListener =
    Box<dyn Fn(LivelinessLostStatus) -> Option<Notice> + Send + Sync>;

struct State {
    status: LivelinessLostStatus,
}

/// One writer's own liveliness lease (DDS v1.4 Sec.2.2.3.11
/// MANUAL_BY_PARTICIPANT, MANUAL_BY_TOPIC): raises LIVELINESS_LOST when the
/// writer (or, for MANUAL_BY_PARTICIPANT, any writer of its participant)
/// stops renewing its lease in time. Owns its watch (`Shared::watch`),
/// unwatched on drop: a leaked watch on a shared MANUAL_BY_PARTICIPANT
/// renewal would wrongly keep pulling in that renewal's threshold forever
/// after this writer is gone.
pub(crate) struct WriterLiveliness {
    shared: Arc<Shared>,
    key: WatchKey,
    state: Mutex<State>,
    condition: Arc<StatusCondition>,
    listener: LivelinessLostListener,
    /// Its application calls, in the order they were decided.
    notices: Arc<Ordered>,
}

impl WriterLiveliness {
    /// Watches `renewal` with `lease` from now (`shared.watch`): `renewal`
    /// is what the writer's own `write()`/`assert_liveliness()` renews
    /// (`WriterAssert`), the exact same one for both to agree.
    pub(crate) fn new(
        shared: Arc<Shared>,
        renewal: Arc<Renewal>,
        lease: Duration,
        condition: Arc<StatusCondition>,
        listener: LivelinessLostListener,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me: &Weak<WriterLiveliness>| {
            let sink: Weak<dyn LivelinessSink> = me.clone();
            let key = shared.watch(renewal, lease, sink);
            Self {
                shared,
                key,
                state: Mutex::new(State {
                    status: LivelinessLostStatus::default(),
                }),
                condition,
                listener,
                notices: Arc::default(),
            }
        })
    }

    /// The LIVELINESS_LOST status; reading it resets its change (DDS v1.4
    /// Sec.2.2.4.2.1).
    pub(crate) fn status(&self) -> LivelinessLostStatus {
        let mut state = self.state();
        let snapshot = state.status.clone();
        state.status.total_count_change = 0;
        self.condition
            .clear_active_status(StatusMask::LIVELINESS_LOST);
        snapshot
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Count one more loss, under the state lock: queued for the listener
    /// (and its change reset) or raised on the condition. The notice a
    /// full queue gives back is returned, for the caller to tell.
    fn report(&self, state: &mut State) -> Option<Notice> {
        state.status.total_count = state.status.total_count.saturating_add(1);
        state.status.total_count_change = state.status.total_count_change.saturating_add(1);
        let notice = match (self.listener)(state.status.clone()) {
            Some(call) => {
                state.status.total_count_change = 0;
                self.condition
                    .clear_active_status(StatusMask::LIVELINESS_LOST);
                call
            }
            None => {
                self.condition
                    .raise_active_statuses(StatusMask::LIVELINESS_LOST);
                let condition = Arc::clone(&self.condition);
                Box::new(move || condition.notify_waitsets_for(StatusMask::LIVELINESS_LOST))
            }
        };
        self.notices.push(notice).err()
    }

    /// Nothing more is watched (the writer is deleted), and nothing more
    /// reaches its listener.
    pub(crate) fn close(&self) {
        self.shared.unwatch(self.key);
        self.notices.close();
    }
}

impl LivelinessSink for WriterLiveliness {
    fn transition(&self, _key: WatchKey, alive: bool) -> Option<Arc<Ordered>> {
        if !alive {
            let mut state = self.state();
            if let Some(own) = self.report(&mut state) {
                // A full queue: told on a thread of its own all the same.
                drop(state);
                let spawned = std::thread::Builder::new()
                    .name("hdds-notices".to_string())
                    .spawn(own);
                if let Err(e) = spawned {
                    log::error!("[liveliness] a LIVELINESS_LOST call is lost: no thread ({e})");
                }
            }
        }
        // A resumption (`alive == true`) raised nothing new: LIVELINESS_LOST
        // has no "regained" counterpart (DDS v1.4 Sec.2.2.4.1), the loss was
        // already counted when the writer went not alive, even if the
        // scheduler only saw it on the resumption path (`Core::resumed`'s
        // "expired then resumed before the timer ran").
        Some(Arc::clone(&self.notices))
    }
}

impl Drop for WriterLiveliness {
    fn drop(&mut self) {
        self.close();
    }
}
