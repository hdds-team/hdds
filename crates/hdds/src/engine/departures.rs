// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The departures of remote DataWriters, routed behind their data.
//!
//! A writer's data reaches the readers through the participant's receive
//! ring and the Router thread; its departure (its participant's SPDP
//! dispose or lease expiry, its own SEDP dispose) is detected by the
//! discovery thread. If it were announced to the readers at once, data still
//! queued, in the receive ring or in the writer's shared-memory ring not yet
//! drained, would arrive after the departure: the writer would have left,
//! and its last coherent sets would be discarded as the staging of a writer
//! that left. A best-effort publisher that exits right after its last
//! `end_coherent_changes` would lose its last set on every co-located reader.
//!
//! A departure therefore takes the data's path. It is queued here
//! (`DepartureRoute::fence`), and a FENCE takes its place in the receive
//! ring, behind every datagram already queued; the Router applies the
//! departure when it pops the fence (`TopicRegistry::apply_next_departure`).
//! With a shared-memory receive leg, the departure goes first to its poller
//! (`DepartureRoute::post`), which drains every attached writer's ring into
//! the receive ring, then fences it. A datagram of the writer still in a
//! socket buffer, read after the fence, is late data from a writer that
//! left (the readers' `has_left`).
//!
//! A departure is never dropped: the fence waits for a place in a full
//! receive ring (the Router drains it), and a ring that stays full past
//! `FENCE_WAIT` (a Router stopped) has the departure applied at once.

use crate::core::discovery::multicast::{Origin, PacketKind, RxMeta};
use crossbeam::queue::ArrayQueue;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::subscriber::{DisposeKind, WriterDeparture};
use super::WakeNotifier;

/// How long a fence waits for a place in a full receive ring before its
/// departure is applied at once. The Router drains the ring continuously:
/// only a stopped Router leaves it full that long.
const FENCE_WAIT: Duration = Duration::from_secs(1);

/// A remote DataWriter, or all those of a participant, gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Departure {
    /// Every writer of the participant of this GUID prefix.
    Participant {
        prefix: [u8; 12],
        cause: WriterDeparture,
    },
    /// One writer.
    Writer {
        guid: [u8; 16],
        kind: DisposeKind,
        cause: WriterDeparture,
    },
    /// A departure with admission-scoped GROUP evidence.
    TerminalParticipant {
        prefix: [u8; 12],
        proof: u64,
        cause: WriterDeparture,
    },
    /// A writer departure with admission-scoped GROUP evidence.
    TerminalWriter {
        guid: [u8; 16],
        kind: DisposeKind,
        proof: u64,
        cause: WriterDeparture,
    },
}

/// The receive ring item that holds a departure's place: no buffer.
pub(crate) fn fence_item() -> (RxMeta, u8) {
    (
        RxMeta::new(
            Origin::direct(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
            0,
            PacketKind::Departure,
        ),
        0,
    )
}

/// The route of the departures of one participant's remote writers through
/// its receive ring (module docs).
pub(crate) struct DepartureRoute {
    ring: Arc<ArrayQueue<(RxMeta, u8)>>,
    notifier: Option<Arc<WakeNotifier>>,
    /// The departures fenced, in the order of their fences in the ring.
    fenced: Mutex<VecDeque<Departure>>,
    /// Held by the fence waiting for a place (`fence`): one at a time, so
    /// the departures stay in their fences' order. The Router never takes
    /// it; `fenced` is held only to push or pop, never across a wait.
    fencing: Mutex<()>,
    /// The shared-memory poller's inbox, while it runs (`attach_shm`).
    shm_inbox: Mutex<Option<Arc<Mutex<Vec<Departure>>>>>,
    /// A departure the fence gave up on (`FENCE_WAIT`), applied at once by
    /// whoever fenced it: the registry applies those.
    overflow: Mutex<Vec<Departure>>,
    gave_up: AtomicBool,
    /// How many departures were posted, and applied (`settled`).
    posted: AtomicU64,
    applied: AtomicU64,
}

impl DepartureRoute {
    pub(crate) fn new(
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        notifier: Option<Arc<WakeNotifier>>,
    ) -> Self {
        Self {
            ring,
            notifier,
            fenced: Mutex::new(VecDeque::new()),
            fencing: Mutex::new(()),
            shm_inbox: Mutex::new(None),
            overflow: Mutex::new(Vec::new()),
            gave_up: AtomicBool::new(false),
            posted: AtomicU64::new(0),
            applied: AtomicU64::new(0),
        }
    }

    /// The shared-memory poller drains its rings, then fences what `inbox`
    /// holds (`ShmReceiver`); `None` when it stops, which then fences what
    /// is left itself.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn attach_shm(&self, inbox: Option<Arc<Mutex<Vec<Departure>>>>) {
        *self.shm_inbox.lock().unwrap_or_else(|e| e.into_inner()) = inbox;
    }

    /// Route `departure`: through the shared-memory poller when one runs,
    /// else fenced at once.
    pub(crate) fn post(&self, departure: Departure) {
        self.posted.fetch_add(1, Ordering::AcqRel);
        {
            let inbox = self.shm_inbox.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(inbox) = inbox.as_ref() {
                inbox
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(departure);
                return;
            }
        }
        self.fence(departure);
    }

    /// Queue `departure` and put its fence in the receive ring, behind every
    /// datagram already queued. Returns false when the ring stayed full past
    /// `FENCE_WAIT`: the departure is then the caller's to apply at once.
    pub(crate) fn fence(&self, departure: Departure) -> bool {
        let _fencing = self.fencing.lock().unwrap_or_else(|e| e.into_inner());
        // Queued before its fence is in the ring: the Router, popping the
        // fence, finds it. No other fence is placed meanwhile (`fencing`),
        // so the departure stays last until its fence is.
        self.fenced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(departure);
        let deadline = Instant::now() + FENCE_WAIT;
        let mut item = fence_item();
        let mut tries: u32 = 0;
        loop {
            match self.ring.push(item) {
                Ok(()) => break,
                Err(back) => {
                    if Instant::now() >= deadline {
                        self.fenced
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .pop_back();
                        log::warn!(
                            "[departures] the receive ring stayed full {:?}: {:?} applied \
                             without waiting for the data queued before it",
                            FENCE_WAIT,
                            departure
                        );
                        self.overflow
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(departure);
                        self.gave_up.store(true, Ordering::Release);
                        return false;
                    }
                    item = back;
                    // A place the Router frees goes to whoever pushes first:
                    // a ring kept full by a receive thread is raced for, not
                    // waited for. Spin a while, yield a while, then sleep,
                    // longer each time up to a millisecond: a Router that
                    // stopped leaves the ring full for good, and the fence
                    // must not burn a core until FENCE_WAIT.
                    tries = tries.saturating_add(1);
                    if tries < 1024 {
                        std::hint::spin_loop();
                    } else if tries < 1024 + 256 {
                        std::thread::yield_now();
                    } else {
                        let step = (tries - 1024 - 256).min(5);
                        std::thread::sleep(Duration::from_micros(32 << step));
                    }
                }
            }
        }
        if let Some(notifier) = self.notifier.as_ref() {
            notifier.notify();
        }
        true
    }

    /// A departure posted here was applied (`TopicRegistry::apply_departure`).
    pub(crate) fn note_applied(&self) {
        self.applied.fetch_add(1, Ordering::AcqRel);
    }

    /// Whether every departure posted so far was applied.
    #[cfg(test)]
    pub(crate) fn settled(&self) -> bool {
        self.applied.load(Ordering::Acquire) >= self.posted.load(Ordering::Acquire)
    }

    /// The departure of the fence the Router popped.
    pub(crate) fn next(&self) -> Option<Departure> {
        self.fenced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    /// The departures the fence gave up on, to apply at once.
    pub(crate) fn take_overflow(&self) -> Vec<Departure> {
        if !self.gave_up.load(Ordering::Acquire) || !self.gave_up.swap(false, Ordering::AcqRel) {
            return Vec::new();
        }
        std::mem::take(&mut *self.overflow.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participant(byte: u8) -> Departure {
        Departure::Participant {
            prefix: [byte; 12],
            cause: WriterDeparture::Deleted,
        }
    }

    /// A departure's fence takes its place behind what the ring holds, and
    /// the Router finds the departures in their fences' order.
    #[test]
    fn a_departure_is_fenced_behind_the_queued_data() {
        let ring = Arc::new(ArrayQueue::new(8));
        let route = DepartureRoute::new(Arc::clone(&ring), None);
        let data = (
            RxMeta::new(
                Origin::direct(std::net::SocketAddr::from(([127, 0, 0, 1], 1))),
                4,
                PacketKind::Data,
            ),
            3u8,
        );
        ring.push(data).expect("room");
        route.post(participant(1));
        route.post(participant(2));
        let kinds: Vec<PacketKind> =
            std::iter::from_fn(|| ring.pop().map(|(m, _)| m.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                PacketKind::Data,
                PacketKind::Departure,
                PacketKind::Departure
            ]
        );
        assert_eq!(route.next(), Some(participant(1)));
        assert_eq!(route.next(), Some(participant(2)));
        assert_eq!(route.next(), None);
    }

    /// A fence never drops its departure: it waits for a place, and a ring
    /// that stays full past `FENCE_WAIT` hands the departure back to be
    /// applied at once.
    #[test]
    fn a_departure_is_never_dropped() {
        let ring = Arc::new(ArrayQueue::new(1));
        let route = Arc::new(DepartureRoute::new(Arc::clone(&ring), None));
        ring.push(fence_item()).expect("room");
        // Room comes back while it waits.
        let drainer = {
            let ring = Arc::clone(&ring);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                ring.pop();
            })
        };
        assert!(route.fence(participant(1)), "fenced once room came back");
        drainer.join().expect("drainer");
        assert_eq!(route.next(), Some(participant(1)));
        // No room ever: handed back.
        assert!(!route.fence(participant(2)));
        assert_eq!(route.take_overflow(), vec![participant(2)]);
        assert_eq!(route.next(), None, "no fence of it in the ring");
    }
}
