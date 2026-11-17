// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The liveliness of the writers a reader matches (DDS v1.4
//! Sec.2.2.3.11): one lease per matched remote writer, alive or not.
//!
//! What renews a remote writer's lease depends on its kind:
//! - AUTOMATIC: any traffic of its participant (`Shared::heard_from`);
//! - MANUAL_BY_PARTICIPANT: its participant's manual assertions
//!   (`Shared::manual_from`) and the data of any of its
//!   MANUAL_BY_PARTICIPANT writers;
//! - MANUAL_BY_TOPIC: the writer's own data.
//!
//! A writer of this reader's participant is alive while it exists; so is
//! one with an infinite lease. Neither has a lease to watch.
//!
//! The reader's LIVELINESS_CHANGED status (DDS v1.4 Sec.2.2.4.1) counts the
//! matched writers alive and not alive. Each change is reported as the
//! reader's other statuses are: with a listener for it, a snapshot is
//! queued for `on_liveliness_changed` and the changes reset; without one,
//! the StatusCondition bit is raised. Application code (the listener, a
//! WaitSet's signal) is told through the reader's queue of listener calls
//! (`notices::Ordered`): after the match entry's dispatch for a match, on a
//! thread of its own for a transition the scheduler found, never on the
//! scheduler's thread.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use super::leases::{LivelinessSink, Renewal, WatchKey};
use super::scheduler::Shared;
use crate::core::discovery::GUID;
use crate::dds::listener::LivelinessChangedStatus;
use crate::dds::qos::{Liveliness, LivelinessKind};
use crate::dds::reader::notices::{Notice, Ordered};
use crate::dds::{StatusCondition, StatusMask};

/// The listener call reporting `status`, when a listener covers
/// LIVELINESS_CHANGED now.
pub(crate) type LivelinessListener =
    Box<dyn Fn(LivelinessChangedStatus) -> Option<Notice> + Send + Sync>;

/// Told a matched writer's LIVELINESS changed: `guid`, alive from now or
/// not (DDS v1.4 Sec.2.2.3.11). Drives the instance-state side of a
/// liveliness loss (Sec.2.2.3.23.2 NOT_ALIVE_NO_WRITERS, Sec.2.2.3.23.1.2
/// EXCLUSIVE ownership transfer), through the reader's writer
/// registrations and dispose queue - the same mechanism a writer's
/// departure or an explicit unregister already drives. Called on the
/// liveliness scheduler thread: it must only update that state and queue
/// what the application is told, never call a listener directly (see the
/// module doc).
pub(crate) type OnWriterAlive = Box<dyn Fn(GUID, bool) + Send + Sync>;

struct Tracked {
    key: Option<WatchKey>,
    alive: bool,
    /// The writer's own LIVELINESS kind: a HEARTBEAT's Liveliness flag
    /// (RTPS v2.5 Sec.8.3.7.5) only ever renews a MANUAL_BY_TOPIC writer's
    /// lease, never a MANUAL_BY_PARTICIPANT one (that kind renews only on
    /// its participant's ParticipantMessage).
    kind: LivelinessKind,
    /// What a DATA of the writer renews (MANUAL kinds).
    on_data: Option<Arc<Renewal>>,
    /// The remote participant held for the watch.
    participant: Option<[u8; 12]>,
}

#[derive(Default)]
struct State {
    writers: HashMap<GUID, Tracked>,
    keys: HashMap<WatchKey, GUID>,
    status: LivelinessChangedStatus,
}

impl State {
    /// Count `alive` (or not alive) one writer more (`by` 1) or less (-1).
    fn count(&mut self, alive: bool, by: i32) {
        let status = &mut self.status;
        let (count, change) = if alive {
            (&mut status.alive_count, &mut status.alive_count_change)
        } else {
            (
                &mut status.not_alive_count,
                &mut status.not_alive_count_change,
            )
        };
        *count = count.saturating_add_signed(by);
        *change = change.saturating_add(by);
    }
}

/// The liveliness of the writers one reader matches.
pub(crate) struct ReaderLiveliness {
    shared: Arc<Shared>,
    me: Weak<ReaderLiveliness>,
    state: Mutex<State>,
    /// Some matched writer is renewed by its data (`on_data`).
    renews_on_data: AtomicBool,
    condition: Arc<StatusCondition>,
    listener: LivelinessListener,
    /// Its application calls, in the order they were decided.
    notices: Arc<Ordered>,
    /// Told every writer-alive transition this tracks (see
    /// [`OnWriterAlive`]).
    on_writer_alive: OnWriterAlive,
}

impl ReaderLiveliness {
    pub(crate) fn new(
        shared: Arc<Shared>,
        condition: Arc<StatusCondition>,
        listener: LivelinessListener,
        on_writer_alive: OnWriterAlive,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            shared,
            me: me.clone(),
            state: Mutex::new(State::default()),
            renews_on_data: AtomicBool::new(false),
            condition,
            listener,
            notices: Arc::default(),
            on_writer_alive,
        })
    }

    /// Report the status as it is now, `guid` the writer that changed it,
    /// under the state lock: queued for the listener (and its changes
    /// reset) or raised on the condition. The notice a full queue gives
    /// back is returned, for the caller to tell.
    fn report(&self, state: &mut State, guid: GUID) -> Option<Notice> {
        state.status.last_publication_handle = Some(guid);
        let notice = match (self.listener)(state.status.clone()) {
            Some(call) => {
                state.status.alive_count_change = 0;
                state.status.not_alive_count_change = 0;
                self.condition
                    .clear_active_status(StatusMask::LIVELINESS_CHANGED);
                call
            }
            None => {
                self.condition
                    .raise_active_statuses(StatusMask::LIVELINESS_CHANGED);
                let condition = Arc::clone(&self.condition);
                Box::new(move || condition.notify_waitsets_for(StatusMask::LIVELINESS_CHANGED))
            }
        };
        self.notices.push(notice).err()
    }

    /// Tell what `report` queued, from a match dispatch.
    fn tell(&self, own: Option<Notice>) {
        if let Some(own) = own {
            crate::dds::reader::notices::notify(own);
        }
        let notices = Arc::clone(&self.notices);
        crate::dds::reader::notices::notify(move || notices.tell());
    }

    /// The LIVELINESS_CHANGED status; reading it resets its changes (DDS
    /// v1.4 Sec.2.2.4.2.1).
    pub(crate) fn status(&self) -> LivelinessChangedStatus {
        let mut state = self.state();
        let snapshot = state.status.clone();
        state.status.alive_count_change = 0;
        state.status.not_alive_count_change = 0;
        self.condition
            .clear_active_status(StatusMask::LIVELINESS_CHANGED);
        snapshot
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sink(&self) -> Weak<dyn LivelinessSink> {
        let me: Weak<dyn LivelinessSink> = self.me.clone();
        me
    }

    /// The writer `guid` matched, offering `liveliness`; `local`: a writer
    /// of this reader's participant. Alive from now.
    pub(crate) fn matched(&self, guid: GUID, liveliness: Liveliness, local: bool) {
        // Under the state lock: a transition of the new watch finds it.
        let mut state = self.state();
        if let Some(old) = state.writers.remove(&guid) {
            if let Some(key) = old.key {
                state.keys.remove(&key);
            }
            state.count(old.alive, -1);
            self.forget(old);
        }
        let infinite = liveliness.is_infinite()
            || super::clock::lease_nanos(liveliness.lease_duration) == super::clock::INFINITE;
        let mut tracked = Tracked {
            key: None,
            alive: true,
            kind: liveliness.kind,
            on_data: None,
            participant: None,
        };
        if !local && !infinite {
            let (automatic, manual) = self.shared.remote(guid.prefix);
            tracked.participant = Some(guid.prefix);
            let renewal = match liveliness.kind {
                LivelinessKind::Automatic => automatic,
                LivelinessKind::ManualByParticipant => {
                    tracked.on_data = Some(Arc::clone(&manual));
                    manual
                }
                LivelinessKind::ManualByTopic => {
                    let own = self.shared.renewal();
                    tracked.on_data = Some(Arc::clone(&own));
                    own
                }
            };
            if tracked.on_data.is_some() {
                self.renews_on_data.store(true, Ordering::Relaxed);
            }
            let key = self
                .shared
                .watch(renewal, liveliness.lease_duration, self.sink());
            tracked.key = Some(key);
            state.keys.insert(key, guid);
        }
        state.writers.insert(guid, tracked);
        state.count(true, 1);
        let own = self.report(&mut state, guid);
        drop(state);
        self.tell(own);
    }

    /// The writer `guid` no longer matches.
    pub(crate) fn unmatched(&self, guid: GUID) {
        let mut state = self.state();
        let Some(tracked) = state.writers.remove(&guid) else {
            return;
        };
        if let Some(key) = tracked.key {
            state.keys.remove(&key);
        }
        state.count(tracked.alive, -1);
        let own = self.report(&mut state, guid);
        drop(state);
        self.forget(tracked);
        self.tell(own);
    }

    fn forget(&self, tracked: Tracked) {
        if let Some(key) = tracked.key {
            self.shared.unwatch(key);
        }
        if let Some(prefix) = tracked.participant {
            self.shared.release(&prefix);
        }
    }

    /// A DATA (or dispose, unregister) of `writer` was received: it renews
    /// a MANUAL writer's lease. One relaxed load while no matched writer
    /// is MANUAL.
    #[inline]
    pub(crate) fn on_data(&self, writer: &[u8; 16]) {
        if !self.renews_on_data.load(Ordering::Relaxed) {
            return;
        }
        let renewal = self
            .state()
            .writers
            .get(&GUID::from_bytes(*writer))
            .and_then(|t| t.on_data.clone());
        if let Some(renewal) = renewal {
            self.shared.renew(&renewal);
        }
    }

    /// A HEARTBEAT with the Liveliness flag set was received from
    /// `writer` (RTPS v2.5 Sec.8.3.7.5): renews its lease, but only
    /// when `writer` matched as MANUAL_BY_TOPIC -- the flag never renews
    /// a MANUAL_BY_PARTICIPANT writer's lease (that kind renews only on a
    /// ParticipantMessage of kind MANUAL). One relaxed load while no
    /// matched writer is MANUAL.
    #[inline]
    pub(crate) fn on_heartbeat_liveliness(&self, writer: &[u8; 16]) {
        if !self.renews_on_data.load(Ordering::Relaxed) {
            return;
        }
        let renewal = {
            let state = self.state();
            state
                .writers
                .get(&GUID::from_bytes(*writer))
                .filter(|t| t.kind == LivelinessKind::ManualByTopic)
                .and_then(|t| t.on_data.clone())
        };
        if let Some(renewal) = renewal {
            self.shared.renew(&renewal);
        }
    }

    /// Nothing more is watched (the reader is deleted), and nothing more
    /// reaches its listener.
    pub(crate) fn close(&self) {
        self.notices.close();
        let writers: Vec<Tracked> = {
            let mut state = self.state();
            state.keys.clear();
            state.writers.drain().map(|(_, t)| t).collect()
        };
        for tracked in writers {
            self.forget(tracked);
        }
    }

    /// Whether the matched writer `guid` is alive.
    pub(crate) fn is_alive(&self, guid: &GUID) -> Option<bool> {
        self.state().writers.get(guid).map(|t| t.alive)
    }
}

impl LivelinessSink for ReaderLiveliness {
    fn transition(&self, key: WatchKey, alive: bool) -> Option<Arc<Ordered>> {
        let mut state = self.state();
        let guid = *state.keys.get(&key)?;
        let tracked = state.writers.get_mut(&guid)?;
        if tracked.alive == alive {
            return None;
        }
        tracked.alive = alive;
        state.count(alive, 1);
        state.count(!alive, -1);
        (self.on_writer_alive)(guid, alive);
        if let Some(own) = self.report(&mut state, guid) {
            // A full queue: told on a thread of its own all the same.
            let spawned = std::thread::Builder::new()
                .name("hdds-notices".to_string())
                .spawn(own);
            if let Err(e) = spawned {
                log::error!("[liveliness] a LIVELINESS_CHANGED call is lost: no thread ({e})");
            }
        }
        Some(Arc::clone(&self.notices))
    }
}

impl Drop for ReaderLiveliness {
    fn drop(&mut self) {
        self.close();
    }
}
