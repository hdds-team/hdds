// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Periodic Heartbeat Scheduler for RTPS Reliable QoS
//!
//! This module implements a dedicated thread that sends HEARTBEAT messages
//! at regular intervals, independent of write() calls. This is required for
//! RTPS 2.5 conformance (Section 8.4.7.2) to enable recovery after bursts.
//!
//! ## Problem Solved
//!
//! Without periodic heartbeats, a writer that bursts data and then goes idle
//! will never trigger ACKNACK responses from readers, causing permanent loss.
//!
//! ## Protocol Flow
//!
//! ```text
//! Writer                              Reader
//!   +--DATA(1-10000) burst------------>  (some lost)
//!   |                                   |
//!   |  (writer idle, thread continues)  |
//!   |                                   |
//!   +--HEARTBEAT(first=1,last=10000)-->  (every 100ms)
//!   |                                   |
//!   <----------ACKNACK(missing=[...])--+
//!   |                                   |
//!   +--DATA retransmit---------------->
//! ```

use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::EndpointRegistry;
use crate::core::discovery::GUID;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::protocol::builder::{self, RtpsEndpointContext};
use crate::protocol::dialect::sequence_window::ClassicPairing;
use crate::reliability::HistoryCache;
use crate::transport::udp::BestEffortUnicastTarget;
use crate::transport::UdpTransport;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Default heartbeat period in milliseconds (RTPS recommendation: 100ms)
pub const DEFAULT_HEARTBEAT_PERIOD_MS: u64 = 100;

/// Shared state between the writer and the heartbeat scheduler thread.
#[derive(Debug)]
pub struct HeartbeatSchedulerState {
    /// Highest sequence number of a change the writer's own thread made
    /// (sample, dispose, unregister). Read through `announced_last_seq`.
    pub last_seq: AtomicU64,
    /// Highest sequence number of an end-of-set marker, taken from whichever
    /// thread closes a coherent set (`end_coherent_changes`), not the
    /// writer's. Read through `announced_last_seq`.
    pub end_of_set_seq: AtomicU64,
    /// Stop flag to terminate the thread
    pub stop: AtomicBool,
    /// Heartbeat counter (monotonically increasing per RTPS spec)
    pub count: AtomicU32,
    /// For VOLATILE writers, sequence number snapshotted at the time the
    /// first reader matched via SEDP (for a RELIABLE reader: its discovery
    /// pairing, with the watermark its ReaderProxy took then, so that the
    /// floor never hides what that reader is owed), encoded as
    /// `sequence + 1`. Subsequent
    /// HEARTBEATs use `max(cache.oldest, sequence + 1)` as `firstSN` so the
    /// matched reader never NACKs for samples that existed before it subscribed.
    /// 0 means "not yet set"; encoding the value makes a floor at sequence 0
    /// sticky instead of allowing a later match to move it.
    ///
    /// This floor is writer-wide: a VOLATILE reader matched after the first
    /// one may NACK samples written between the two matches. It is never
    /// sent them: each reader proxy records what it is owed at match time
    /// (`nack.rs`, `track_reader_proxy`) and a NACK at or below that mark is
    /// answered with a GAP (`split_at_watermark`). The cost is one NACK/GAP
    /// round; see `tests/a_second_volatile_reader_receives_no_history.rs`.
    pub first_eligible_seq: AtomicU64,
    /// For a GROUP Publisher's writer: the GSN of a change taken and not
    /// yet made (0: none), set under the Publisher's lock
    /// (`PublisherCore::take_sn_and_gsn`). This thread must not announce
    /// it as absent (`group_heartbeat_info_of`).
    pub pending_gsn: AtomicU64,
    /// The deletion barrier's actual guarantee. A one-shot
    /// `should_stop()` check in `fire()` is insufficient on its own, and
    /// so is a per-call check-then-release of THIS lock (a send already
    /// past its check would be free to transmit after drop returns); but
    /// holding this lock across the periodic origin's entire fanout,
    /// including discovery/registry lookups and window-table translation,
    /// would let `revoke_sends` wait, unboundedly, on whatever unrelated
    /// thread happened to be holding one of THOSE locks, the opposite of
    /// "bounded". So `send_heartbeat_best_effort` does all of that
    /// lookup/resolution work with NO gate held at all, and takes this
    /// lock (`with_send_gate_held`) only around the already-resolved,
    /// non-blocking transmits themselves -- a handful of syscalls, not a
    /// fanout that can wait on arbitrary other locks. `revoke_sends`
    /// takes the SAME lock, under the SAME mutex, from
    /// `HeartbeatPeriodic::drop`: it cannot return while one of those
    /// already-resolved transmits is still running, so no periodic
    /// HEARTBEAT this writer's sink builds can reach the wire after that
    /// -- but it also cannot be made to wait on anything BUT that, since
    /// nothing else is done while the lock is held. The non-periodic
    /// origins (piggyback, MANUAL_BY_TOPIC assert) still use the cheaper
    /// per-call `sends_revoked` check, never holding this lock across
    /// their own (still blocking) socket send.
    send_gate: Mutex<bool>,
    /// Per-writer allocate-then-transmit serialization (RTPS v2.5
    /// Sec.8.3.8.6: one monotonic count per writer, on the WIRE, not
    /// only in allocation order): held from `next_count()` through the
    /// matching `send_heartbeat_to_readers` call for every origin
    /// (periodic, piggyback, MANUAL_BY_TOPIC assert) of this ONE writer,
    /// via `with_next_count` / `try_with_next_count`. Without it, two
    /// origins could allocate N then N+1, and send N+1 before N (one
    /// paused, slow, or just reordered by the scheduler), so a reader
    /// sees the higher count first and discards N as stale when it
    /// finally arrives -- the atomic `count` field alone only orders
    /// *allocation*. The periodic origin uses `try_lock` and skips its
    /// tick entirely on contention (never blocks the shared
    /// `hdds-hb-sender` worker on a lock a DIFFERENT thread holds); the
    /// others block briefly, on their own thread, for this one writer's
    /// own lock only -- never another writer's, each has its own.
    send_serial: Mutex<()>,
    /// Set when the durable-writer first-match announce HEARTBEAT
    /// (`dds::writer::builder`'s match callback) could not go through
    /// `try_with_next_count` because `send_serial` was contended at the
    /// moment discovery tried -- a call that bypassed serialization
    /// entirely would be wrong, so the announcement must never block the
    /// discovery thread AND never be lost. Checked and
    /// retried by `fire_heartbeat_tick` on this writer's own next due
    /// tick (`take_announce_pending`), re-armed if that retry is ALSO
    /// contended (`mark_announce_pending`) -- so it keeps retrying,
    /// never silently drops, until a tick finds `send_serial` free.
    announce_pending: AtomicBool,
    /// Tests only: a one-shot signal fired from `with_next_count`
    /// immediately BEFORE it attempts `send_serial.lock()`, so a test
    /// pausing this writer's periodic tick while holding that lock
    /// (`test_pause::arm`) can confirm a blocking piggyback/manual-assert
    /// call actually reached the contested acquisition, instead of
    /// inferring that from a fixed sleep.
    #[cfg(test)]
    send_serial_contention_hook: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    /// Tests only: a one-shot signal fired from `with_next_count` right
    /// AFTER `send_serial.lock()` actually returns a guard -- never
    /// before it, and tied to that guard by parameter, so a mutant that
    /// deletes the `lock()` call cannot keep this call compiling by
    /// accident. The contention-attempt signal above, used ALONE to
    /// decide when to release a paused periodic
    /// tick, is not enough: a mutant removing just the lock lets the releaser wake
    /// periodic transmission before this writer's piggyback send, which
    /// can then race ahead on the wire anyway and pass by luck. This
    /// signal proves genuine acquisition happened at all, independent of
    /// wire-arrival timing.
    #[cfg(test)]
    send_serial_acquired_hook: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

impl HeartbeatSchedulerState {
    /// Create new shared state.
    pub fn new() -> Self {
        Self {
            last_seq: AtomicU64::new(0),
            end_of_set_seq: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            count: AtomicU32::new(1),
            first_eligible_seq: AtomicU64::new(0),
            pending_gsn: AtomicU64::new(0),
            send_gate: Mutex::new(false),
            send_serial: Mutex::new(()),
            announce_pending: AtomicBool::new(false),
            #[cfg(test)]
            send_serial_contention_hook: Mutex::new(None),
            #[cfg(test)]
            send_serial_acquired_hook: Mutex::new(None),
        }
    }

    /// Tests only: arms a one-shot signal on `entering`, fired the next
    /// time `with_next_count` reaches its `send_serial.lock()` call
    /// site, right before attempting the lock.
    #[cfg(test)]
    pub(crate) fn arm_send_serial_contention_signal(&self, entering: std::sync::mpsc::Sender<()>) {
        *self
            .send_serial_contention_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(entering);
    }

    #[cfg(test)]
    fn note_send_serial_lock_attempt(&self) {
        if let Some(entering) = self
            .send_serial_contention_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = entering.send(());
        }
    }

    /// Tests only: arms a one-shot signal on `acquired`, fired the next
    /// time `with_next_count` genuinely holds `send_serial` -- see
    /// `send_serial_acquired_hook`'s doc.
    #[cfg(test)]
    pub(crate) fn arm_send_serial_acquired_signal(&self, acquired: std::sync::mpsc::Sender<()>) {
        *self
            .send_serial_acquired_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(acquired);
    }

    /// Takes `_guard` so this call cannot exist in code that deleted the
    /// `lock()` call that produced it.
    #[cfg(test)]
    fn note_send_serial_acquired(&self, _guard: &std::sync::MutexGuard<'_, ()>) {
        if let Some(acquired) = self
            .send_serial_acquired_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = acquired.send(());
        }
    }

    /// Record that the durable-writer first-match announce could not
    /// send (`send_serial` contended): retried on this writer's next
    /// due periodic tick.
    pub(crate) fn mark_announce_pending(&self) {
        self.announce_pending.store(true, Ordering::Release);
    }

    /// Consume the pending-announce flag: `true` at most once per
    /// `mark_announce_pending` call, so a tick that finds it set is the
    /// ONE tick responsible for retrying (or re-arming it on another
    /// contended try).
    pub(crate) fn take_announce_pending(&self) -> bool {
        self.announce_pending.swap(false, Ordering::AcqRel)
    }

    /// Revoke this writer's periodic HEARTBEAT send permission,
    /// unconditionally: see the `send_gate` field doc for why this, not
    /// `signal_stop`, is the actual "no HEARTBEAT after drop returns"
    /// guarantee. May block briefly if a periodic send is mid-transmit
    /// right now (see `with_send_gate_held`) -- bounded, because nothing
    /// but the already-resolved, non-blocking transmits themselves ever
    /// runs while that lock is held.
    pub fn revoke_sends(&self) {
        *self.send_gate.lock().unwrap_or_else(|e| e.into_inner()) = true;
    }

    /// The non-periodic send path's own check, taken immediately before
    /// each real socket transmission: `true` means drop the packet, this
    /// writer's periodic HEARTBEAT origin has been revoked. The periodic
    /// origin does not use this: it holds the gate for its transmit
    /// instead (`with_send_gate_held`).
    pub fn sends_revoked(&self) -> bool {
        *self.send_gate.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The periodic origin's hold of `send_gate` around its already-
    /// resolved transmits (see the field doc and `send_heartbeat_
    /// best_effort`'s doc for why ONLY the transmits, never the lookup
    /// work that produces them): `None` without running `body` at all if
    /// already revoked; otherwise runs `body`, which must perform ONLY
    /// the non-blocking transmit syscalls with the lock held, nothing
    /// that can itself wait on an unrelated lock. `body` must never
    /// itself try to take this same lock (via `sends_revoked`/
    /// `revoke_sends`): this mutex is not reentrant.
    #[cfg(not(windows))]
    pub(crate) fn with_send_gate_held<R>(&self, body: impl FnOnce() -> R) -> Option<R> {
        let guard = self.send_gate.lock().unwrap_or_else(|e| e.into_inner());
        if *guard {
            return None;
        }
        Some(body())
    }

    /// Allocate this writer's next HEARTBEAT count and run `send` with
    /// it, holding `send_serial` for the whole call: see the field doc.
    /// Blocking -- for the on-write ("piggyback") and MANUAL_BY_TOPIC
    /// `assert_liveliness()` origins, which run on the writer's own
    /// thread and may wait briefly for this SAME writer's own periodic
    /// tick to finish.
    pub(crate) fn with_next_count<R>(&self, send: impl FnOnce(u32) -> R) -> R {
        #[cfg(test)]
        self.note_send_serial_lock_attempt();
        let _guard = self.send_serial.lock().unwrap_or_else(|e| e.into_inner());
        #[cfg(test)]
        self.note_send_serial_acquired(&_guard);
        send(self.next_count())
    }

    /// Same guarantee, for the periodic scheduler/worker ONLY: `try_lock`
    /// instead of `lock`. `None` on genuine contention -- this writer's
    /// own piggyback or manual-assert origin is mid-send right now --
    /// skips the tick entirely (no count allocated, nothing built or
    /// sent) rather than making the single `hdds-hb-sender` worker wait
    /// on a lock a DIFFERENT thread holds. Legal to skip: a HEARTBEAT for
    /// this writer is either about to reach the wire or just did.
    ///
    /// The naive `self.send_serial.try_lock().ok()?` would treat
    /// `TryLockError::Poisoned` exactly like `WouldBlock`: a
    /// single caught panic while holding this lock (the worker's own
    /// `catch_unwind` around `sink.fire()` keeps the WORKER alive, but
    /// does nothing about the lock it was holding) would poison it
    /// forever, and every later tick for THIS writer would silently skip
    /// -- an idle reliable writer stops announcing unacknowledged data,
    /// permanently, with nothing in the logs to say why. `Poisoned` is
    /// recovered here (`into_inner`, same as every other lock in this
    /// crate), exactly like `with_next_count` above already does for the
    /// plain blocking `lock()`; only a genuine `WouldBlock` skips the tick.
    pub(crate) fn try_with_next_count<R>(&self, send: impl FnOnce(u32) -> R) -> Option<R> {
        let guard = match self.send_serial.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return None,
        };
        let _guard = guard;
        Some(send(self.next_count()))
    }

    /// Record a change the writer's thread made: `seq` is announced as
    /// lastSN from the next HEARTBEAT on. A plain store: that thread is the
    /// only one to write this field, in the order it takes its numbers, so
    /// the value only rises (this is on every reliable write).
    pub fn update_seq(&self, seq: u64) {
        self.last_seq.store(seq, Ordering::Release);
    }

    /// Record an end-of-set marker `seq`, from the thread closing the set,
    /// which may race the writer's own changes: kept apart from them, and
    /// only raised, so neither producer can hide the other's higher number.
    pub fn record_end_of_set(&self, seq: u64) {
        self.end_of_set_seq.fetch_max(seq, Ordering::AcqRel);
    }

    /// The lastSN to announce: the highest number any change took, whichever
    /// thread made it (RTPS v2.5 Sec.8.3.8.6).
    pub fn announced_last_seq(&self) -> u64 {
        self.last_seq
            .load(Ordering::Acquire)
            .max(self.end_of_set_seq.load(Ordering::Acquire))
    }

    /// Signal the thread to stop.
    pub fn signal_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Check if stop was signaled.
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Get and increment the heartbeat counter.
    pub fn next_count(&self) -> u32 {
        self.count.fetch_add(1, Ordering::Relaxed)
    }

    /// CAS-set the encoded floor on the first call only. Subsequent
    /// calls are no-ops, so the floor is captured at the moment of the
    /// *first* reader match event and never slides further. Returns `true`
    /// if this call installed the value.
    pub fn bump_first_eligible(&self, value: u64) -> bool {
        let Some(encoded) = value.checked_add(1) else {
            return false;
        };
        self.first_eligible_seq
            .compare_exchange(0, encoded, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Compute the `firstSN` to advertise in HEARTBEAT, respecting the
    /// VOLATILE floor when present. When `first_eligible_seq` is 0 (never
    /// set), returns `cache_oldest` unchanged (VOLATILE writers pre-match, or
    /// non-VOLATILE writers). Otherwise returns `max(cache_oldest,
    /// first_eligible + 1)` so the reader never sees historical seqs.
    pub fn heartbeat_first_seq(&self, cache_oldest: u64) -> u64 {
        self.first_eligible_seq
            .load(Ordering::Acquire)
            .checked_sub(1)
            .map_or(cache_oldest, |floor| cache_oldest.max(floor + 1))
    }
}

impl Default for HeartbeatSchedulerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle to the heartbeat scheduler thread.
///
/// When dropped, signals the thread to stop and waits for it to join.
pub struct HeartbeatSchedulerHandle {
    state: Arc<HeartbeatSchedulerState>,
    thread: Option<JoinHandle<()>>,
}

impl HeartbeatSchedulerHandle {
    /// Get a reference to the shared state (for updating last_seq from writer).
    pub fn state(&self) -> &Arc<HeartbeatSchedulerState> {
        &self.state
    }
}

impl Drop for HeartbeatSchedulerHandle {
    fn drop(&mut self) {
        // Signal stop
        self.state.signal_stop();

        // Wait for thread to finish
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// The HEARTBEAT firstSN for a history whose oldest change is
/// `cache_oldest`, the writer having written up to `last_seq`. An empty
/// history advertises `lastSN + 1`: "a Writer [...] that has no samples
/// available at the time of the Heartbeat will send a Heartbeat with
/// firstSN.value = 11, lastSN.value = 10" (RTPS 2.5 8.3.8.6). Empty is not
/// only "nothing written yet": a VOLATILE writer removes what every reader
/// acknowledged, and advertising 1 would then invite NACKs for all of it.
pub(super) fn advertised_first_seq(cache_oldest: Option<u64>, last_seq: u64) -> u64 {
    cache_oldest.unwrap_or(last_seq.saturating_add(1))
}

/// The GroupInfo `[currentGSN, firstGSN, lastGSN]` of a HEARTBEAT of a
/// GROUP Publisher's writer (RTPS v2.5 Sec.8.3.8.6, Sec.9.4.5.7, D4, D15),
/// from the Publisher's last GSN `current_gsn`, the GSN of a change the
/// writer took and has not made yet (`pending_gsn`, 0: none), and what its
/// history holds of the announced changes (`window`).
///
/// A reader takes a GSN below currentGSN and outside [firstGSN, lastGSN]
/// as one this writer does not have (Sec.8.7.5), so currentGSN stops at
/// the first GSN of this writer the HEARTBEAT does not announce: one
/// pending, or one made above lastSN. It never stops below lastGSN: every
/// GSN of this writer below that one is made. It may exceed lastGSN, the
/// Publisher's other writers taking GSNs too (D3). With nothing of the
/// range in the history, the interval is empty: [currentGSN,
/// currentGSN - 1]. `None` before the Publisher's first GSN (currentGSN
/// must be positive): the HEARTBEAT goes without GroupInfo.
pub(crate) fn group_heartbeat_info(
    current_gsn: u64,
    pending_gsn: u64,
    window: crate::reliability::GroupWindow,
) -> Option<[u64; 3]> {
    let mut current = current_gsn;
    if pending_gsn != 0 {
        current = current.min(pending_gsn);
    }
    if let Some(unannounced) = window.unannounced_gsn {
        current = current.min(unannounced);
    }
    match (window.first_gsn, window.last_gsn) {
        (Some(first), Some(last)) => Some([current.max(last), first, last]),
        _ => (current > 0).then(|| [current, current, current - 1]),
    }
}

/// `group_heartbeat_info` of the writer of `cache`, read in the one order
/// that keeps it true while the writer writes: currentGSN first, then the
/// pending GSN, then the history. A currentGSN read above a GSN this writer
/// took implies the pending GSN read after it is that one (stored before
/// it, under the Publisher's lock), or the change is in the history read
/// after that.
pub(crate) fn group_heartbeat_info_of(
    publisher: &crate::dds::publisher::PublisherCore,
    pending_gsn: Option<&AtomicU64>,
    cache: &HistoryCache,
    first_seq: u64,
    last_seq: u64,
) -> Option<[u64; 3]> {
    let current = publisher.current_gsn();
    let pending = pending_gsn.map_or(0, |pending| pending.load(Ordering::Acquire));
    group_heartbeat_info(current, pending, cache.group_window(first_seq, last_seq))
}

/// Send a writer's HEARTBEAT to its readers: `group_packet` (the GROUP
/// form, D4) to the readers of the spec class, `packet` to the others
/// (D18), per reader by unicast; `packet` to the user-data multicast group
/// when no reader was reached, but not for a topic whose multicast fallback
/// is closed (`runtime::multicast_fallback_closed`). Readers of the participant `local_prefix`
/// are skipped. Returns whether a unicast send succeeded.
///
/// `best_effort` picks which transport call every transmit makes (the
/// ordinary blocking send, or the non-blocking twin a full kernel send
/// buffer cannot stall). The ONLY caller that passes `true` is the
/// periodic scheduler (`fire_heartbeat_tick`): a single blocking send
/// there must never be allowed to starve the `hdds-hb-sender` worker's
/// OTHER queued writers (`dds::liveliness::scheduler`'s module doc).
/// DATA, the on-write ("piggyback") HEARTBEAT and MANUAL_BY_TOPIC
/// `assert_liveliness()` HEARTBEAT pass `false` and keep the ordinary
/// blocking send, unchanged -- they run on the writer's own thread,
/// never the shared worker, so there is nothing here for them to starve.
/// `best_effort` also picks an entirely different function below:
/// [`send_heartbeat_best_effort`]'s doc explains why.
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_heartbeat_to_readers(
    transport: &UdpTransport,
    state: Option<&HeartbeatSchedulerState>,
    discovery_fsm: Option<&DiscoveryFsm>,
    endpoint_registry: Option<&EndpointRegistry>,
    topic: &str,
    local_prefix: Option<[u8; 12]>,
    packet: &[u8],
    group_packet: Option<&[u8]>,
    windows: &crate::protocol::dialect::sequence_window::WriterWindows,
    best_effort: bool,
) -> bool {
    if best_effort {
        // `.delivered` only: this wrapper's historical contract is
        // "whether a unicast send succeeded", unchanged for every
        // existing caller. The durable-announce retry, the only
        // caller that needs the fuller outcome (including a
        // successful MULTICAST fallback), calls
        // `send_heartbeat_best_effort` directly instead of through
        // here -- see its own call site.
        return send_heartbeat_best_effort(
            transport,
            state,
            discovery_fsm,
            endpoint_registry,
            topic,
            local_prefix,
            packet,
            group_packet,
            windows,
        )
        .delivered;
    }
    send_heartbeat_fanout(
        transport,
        state,
        discovery_fsm,
        endpoint_registry,
        topic,
        local_prefix,
        packet,
        group_packet,
        windows,
    )
}

/// The ordinary (non-periodic) fanout: per-call `sends_revoked()` check,
/// the plain blocking send. Used by DATA, piggyback and MANUAL_BY_TOPIC
/// assert-liveliness, on their own thread -- never the shared worker, so
/// an early exit mid-loop on revoke is a harmless optimization, not a
/// correctness requirement the way it is for the periodic origin below.
#[allow(clippy::too_many_arguments)]
fn send_heartbeat_fanout(
    transport: &UdpTransport,
    state: Option<&HeartbeatSchedulerState>,
    discovery_fsm: Option<&DiscoveryFsm>,
    endpoint_registry: Option<&EndpointRegistry>,
    topic: &str,
    local_prefix: Option<[u8; 12]>,
    packet: &[u8],
    group_packet: Option<&[u8]>,
    windows: &crate::protocol::dialect::sequence_window::WriterWindows,
) -> bool {
    let revoked = || state.is_some_and(HeartbeatSchedulerState::sends_revoked);
    let mut delivered = false;
    if let (Some(fsm), Some(reg)) = (discovery_fsm, endpoint_registry) {
        let readers = fsm.find_readers_for_topic(topic);
        for reader in &readers {
            let classic_window =
                windows.is_group() && fsm.requires_group_window(&reader.endpoint_guid.prefix);
            if classic_window && !windows.contains(reader.endpoint_guid) {
                continue;
            }
            let mut prefix = [0u8; 12];
            prefix.copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
            if local_prefix == Some(prefix) {
                continue;
            }
            let mut pguid_bytes = [0u8; 16];
            pguid_bytes[..12].copy_from_slice(&prefix);
            pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
            let participant_key = GUID::from_bytes(pguid_bytes);
            let dest = reg
                .get_reader_locator(&reader.endpoint_guid)
                .or_else(|| reg.get(&participant_key));
            let Some(endpoint) = dest else {
                continue;
            };
            let form = match group_packet {
                Some(group) if fsm.speaks_spec_group(&prefix) => group,
                _ => packet,
            };
            if revoked() {
                return delivered;
            }
            if windows
                .send_classed(
                    transport,
                    form,
                    &endpoint,
                    reader.endpoint_guid,
                    classic_window,
                )
                .is_ok()
            {
                delivered = true;
            }
        }
    }
    // Not to a group anyone may listen on, for a protected topic: a
    // HEARTBEAT names the writer and the changes it holds, and invites
    // whoever hears it to ask (`runtime::multicast_fallback_closed`).
    if !delivered
        && !windows.is_group()
        && !super::runtime::multicast_fallback_closed(discovery_fsm, topic)
    {
        if revoked() {
            return delivered;
        }
        if let Err(e) = transport.send_user_data_multicast(packet) {
            log::debug!("[heartbeat] Failed to send HEARTBEAT: {}", e);
        }
    }
    delivered
}

/// What one periodic-style best-effort fanout actually did.
///
/// `delivered` is this function's HISTORICAL meaning, unchanged: at
/// least one PER-READER UNICAST transmit succeeded -- every existing
/// caller of `send_heartbeat_to_readers` reads (or discards) exactly
/// that `bool`, per its own doc ("Returns whether a unicast send
/// succeeded"), and this struct does not touch that contract.
///
/// `multicast_delivered` is whether the multicast FALLBACK itself
/// succeeded. The durable-announce retry (the only caller that actually
/// BRANCHES on the outcome) must not treat `delivered == false` as
/// "nothing was accepted this tick", or it would re-arm the pending flag
/// forever even after a genuinely successful multicast send. The retry
/// checks `delivered || multicast_delivered`; no other caller inspects
/// this field, and it defaults to `false`.
#[derive(Clone, Copy, Default)]
pub(crate) struct HeartbeatSendOutcome {
    pub(crate) delivered: bool,
    pub(crate) multicast_delivered: bool,
}

impl HeartbeatSendOutcome {
    /// Whether ANYTHING reached the wire this tick, unicast or
    /// multicast -- what the durable-announce retry actually needs to
    /// know, never `delivered` alone.
    pub(crate) fn transmitted(&self) -> bool {
        self.delivered || self.multicast_delivered
    }
}

/// One per-reader unicast send the periodic origin has fully resolved
/// AHEAD of taking any gate: a destination (direct socket, or an
/// already-identified relay peer -- `UdpTransport::
/// resolve_best_effort_unicast` did that lookup), the final bytes, and,
/// for a classic/translated packet only, the pairing it was translated
/// against (`WriterWindows::pairing_unchanged` revalidates this
/// immediately before the transmit it guards).
struct PreparedUnicast<'a> {
    target: BestEffortUnicastTarget,
    packet: std::borrow::Cow<'a, [u8]>,
    pairing: Option<ClassicPairing>,
}

/// The periodic origin's own path. `send_gate` must not be held across
/// the WHOLE fanout (discovery snapshots, registry lookups, window-table
/// translation), which would let `revoke_sends()` wait on whatever
/// unrelated thread held one of THOSE locks; nor may it enclose
/// `trace_fn!`/debug logging inside the transport methods or the relay
/// peer lookup's `RwLock` read, both application-adjacent or
/// potentially-blocking work the gate must never be able to wait on.
///
/// This version does ALL lookup/resolution work first -- discovery,
/// registry, window-table translation AND relay peer resolution
/// (`UdpTransport::resolve_best_effort_unicast`) -- with no gate held at
/// all, producing `PreparedUnicast` entries. `HeartbeatSchedulerState::
/// send_gate` is then taken ONLY around: the one revoke check, a cheap
/// pairing revalidation (a lock, but a plain integer comparison, no
/// re-translation -- see `ClassicPairing`'s doc for the concrete
/// staleness scenario it closes), and the raw non-blocking syscalls
/// themselves (`UdpTransport::transmit_best_effort_resolved` /
/// `transmit_best_effort_multicast_resolved`, which do no logging and no
/// lookup of their own). Diagnostics (the multicast-fallback failure
/// log) run AFTER the gate releases.
#[allow(clippy::too_many_arguments)]
fn send_heartbeat_best_effort(
    transport: &UdpTransport,
    state: Option<&HeartbeatSchedulerState>,
    discovery_fsm: Option<&DiscoveryFsm>,
    endpoint_registry: Option<&EndpointRegistry>,
    topic: &str,
    local_prefix: Option<[u8; 12]>,
    packet: &[u8],
    group_packet: Option<&[u8]>,
    windows: &crate::protocol::dialect::sequence_window::WriterWindows,
) -> HeartbeatSendOutcome {
    // ----- Prepare: discovery, registry, window table, relay lookup. No gate held. -----
    let mut prepared: Vec<PreparedUnicast<'_>> = Vec::new();
    if let (Some(fsm), Some(reg)) = (discovery_fsm, endpoint_registry) {
        let readers = fsm.find_readers_for_topic(topic);
        for reader in &readers {
            let classic_window =
                windows.is_group() && fsm.requires_group_window(&reader.endpoint_guid.prefix);
            if classic_window && !windows.contains(reader.endpoint_guid) {
                continue;
            }
            let mut prefix = [0u8; 12];
            prefix.copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
            if local_prefix == Some(prefix) {
                continue;
            }
            let mut pguid_bytes = [0u8; 16];
            pguid_bytes[..12].copy_from_slice(&prefix);
            pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
            let participant_key = GUID::from_bytes(pguid_bytes);
            let dest = reg
                .get_reader_locator(&reader.endpoint_guid)
                .or_else(|| reg.get(&participant_key));
            let Some(endpoint) = dest else {
                continue;
            };
            let form = match group_packet {
                Some(group) if fsm.speaks_spec_group(&prefix) => group,
                _ => packet,
            };
            let Some(resolved) =
                windows.resolve_classed(form, &endpoint, reader.endpoint_guid, classic_window)
            else {
                continue;
            };
            let Some(target) = transport.resolve_best_effort_unicast(&resolved.endpoint) else {
                continue; // relay range, no peer this participant relays to
            };
            prepared.push(PreparedUnicast {
                target,
                packet: resolved.packet,
                pairing: resolved.pairing,
            });
        }
    }
    // Whether the multicast fallback ROUTE is even open (routing/
    // security policy): no side effects, resolved outside the gate
    // same as everything above.
    let multicast_route_open =
        !windows.is_group() && !super::runtime::multicast_fallback_closed(discovery_fsm, topic);
    // Whether `MulticastMode` permits it at all: read with NO side
    // effect here (`UdpTransport::multicast_send_allowed`). Calling the
    // side-effecting `multicast_send_refused` unconditionally in THIS
    // prepare phase would count and log a refusal on every tick whose
    // policy disables multicast -- even when unicast delivery succeeded
    // and no fallback was ever needed, or the tick was revoked before
    // reaching one. The actual count+log, gated on this tick having
    // genuinely needed and been refused the fallback, happens after
    // the gate releases, below -- the same place every other
    // diagnostic in this function already runs.
    let multicast_mode_allows = transport.multicast_send_allowed();
    let multicast_allowed = multicast_route_open && multicast_mode_allows;

    // Explicit platform policy: on every target where the transmits
    // below are genuinely non-blocking, hold the gate for them, giving
    // the real unconditional "no HEARTBEAT after drop returns"
    // guarantee. On Windows there is no per-call non-blocking flag in
    // Winsock (see `transport::udp::best_effort_send_to`), so holding
    // the gate across them there would reintroduce exactly the
    // unbounded wait the gate exists to avoid, just on a different
    // platform -- the gate is skipped entirely there, relying on the
    // older, already-existing, bounded `HeartbeatPeriodic::drop`'s
    // `wait_idle` instead. The cheap, never-blocking per-call revocation
    // check must survive there too: without it, a tick stalled in
    // preparation, with drop having revoked and given up after its
    // bound, would transmit anyway on resuming, having never re-checked.
    // The loop below checks before EVERY transmit, so a
    // revoke landing mid-loop (or before it, from a stall this function
    // cannot see) stops the rest of this tick's sends, on every platform.
    #[cfg(not(windows))]
    let (delivered, multicast_delivered, multicast_err) = {
        let transmit =
            || transmit_prepared(transport, windows, &prepared, multicast_allowed, packet);
        state.map_or_else(transmit, |state| {
            state
                .with_send_gate_held(transmit)
                .unwrap_or((false, false, None))
        })
    };
    #[cfg(windows)]
    let (delivered, multicast_delivered, multicast_err) =
        transmit_prepared_with_per_call_revocation(
            transport,
            state,
            windows,
            &prepared,
            multicast_allowed,
            packet,
        );

    // ----- Diagnostics: outside the gate. -----
    if let Some(e) = multicast_err {
        log::debug!("[heartbeat] Failed to send HEARTBEAT: {}", e);
    }
    // This tick genuinely needed the fallback (unicast did not deliver,
    // and nothing else -- GROUP/security policy -- closed the route)
    // and `MulticastMode` is what refused it: count and log it exactly
    // where an ordinary multicast send would, at the moment it would
    // actually be used, never on a tick that never needed it.
    if !delivered && multicast_route_open && !multicast_mode_allows {
        let _ = transport.multicast_send_refused("periodic HEARTBEAT fallback");
    }
    // `transmit_best_effort_resolved`'s relay branch must not log
    // synchronously from inside the gate (the relay sink's own
    // failed-wake/oversized diagnostics). The sink only COLLECTS those;
    // log them here, same as the multicast error
    // above, only after the gate has released.
    if let Some(egress) = transport.relay() {
        let diag = egress.drain_pending_diagnostics();
        if let Some(len) = diag.oversized_len {
            log::error!(
                "[relay] refused a {len}-byte periodic HEARTBEAT relay datagram: too large for \
                 a UDP payload. Further occurrences are counted, not logged."
            );
        }
        if diag.wake_failed {
            log::warn!(
                "[relay] the Discovery Server session could not be woken for a periodic \
                 HEARTBEAT relay datagram; it will wait for its poll timeout instead"
            );
        }
    }
    HeartbeatSendOutcome {
        delivered,
        multicast_delivered,
    }
}

/// The non-Windows transmit body: every per-reader send and the
/// multicast fallback, meant to run entirely inside `HeartbeatScheduler
/// State::send_gate` (see `send_heartbeat_best_effort`'s doc). Each
/// entry's pairing (if any) is revalidated right here, under the gate,
/// against the window table -- cheap (a lock and an integer compare,
/// never a re-translation), but still a genuine lock acquisition; see
/// `ClassicPairing`'s doc for why this one, specifically, is accepted
/// inside the gate where the full resolution work above is not.
#[cfg(not(windows))]
fn transmit_prepared(
    transport: &UdpTransport,
    windows: &crate::protocol::dialect::sequence_window::WriterWindows,
    prepared: &[PreparedUnicast<'_>],
    multicast_allowed: bool,
    packet: &[u8],
) -> (bool, bool, Option<std::io::Error>) {
    let mut delivered = false;
    for p in prepared {
        if let Some(pairing) = &p.pairing {
            if !windows.pairing_unchanged(pairing) {
                continue; // stale: this reader's pairing changed since prepare
            }
        }
        if transport
            .transmit_best_effort_resolved(&p.target, &p.packet)
            .is_ok()
        {
            delivered = true;
        }
    }
    let mut multicast_delivered = false;
    let multicast_err = if !delivered && multicast_allowed {
        match transport.transmit_best_effort_multicast_resolved(packet) {
            Ok(_) => {
                multicast_delivered = true;
                None
            }
            Err(e) => Some(e),
        }
    } else {
        None
    };
    (delivered, multicast_delivered, multicast_err)
}

/// Windows only: the same transmit body as [`transmit_prepared`], but
/// with no gate (that platform's transmits are still the ordinary
/// blocking send) and an explicit `sends_revoked()` check -- never
/// blocking, just an atomic-cheap flag read under a lock held for an
/// instant -- before EVERY single transmit, so a revoke that lands
/// between this tick's preparation and its transmit, or mid-transmit,
/// stops the rest of it rather than sending anyway.
#[cfg(windows)]
fn transmit_prepared_with_per_call_revocation(
    transport: &UdpTransport,
    state: Option<&HeartbeatSchedulerState>,
    windows: &crate::protocol::dialect::sequence_window::WriterWindows,
    prepared: &[PreparedUnicast<'_>],
    multicast_allowed: bool,
    packet: &[u8],
) -> (bool, bool, Option<std::io::Error>) {
    let revoked = || state.is_some_and(HeartbeatSchedulerState::sends_revoked);
    let mut delivered = false;
    for p in prepared {
        if revoked() {
            return (delivered, false, None);
        }
        if let Some(pairing) = &p.pairing {
            if !windows.pairing_unchanged(pairing) {
                continue;
            }
        }
        // Revalidation above can still leave a gap:
        // revocation landing while `pairing_unchanged` contended `peers`
        // (or simply while this loop iterated) would otherwise reach the
        // syscall unchecked. Re-check immediately before the submission
        // itself, not just once per entry at the top of the loop.
        if revoked() {
            return (delivered, false, None);
        }
        if transport
            .transmit_best_effort_resolved(&p.target, &p.packet)
            .is_ok()
        {
            delivered = true;
        }
    }
    if delivered || !multicast_allowed || revoked() {
        return (delivered, false, None);
    }
    match transport.transmit_best_effort_multicast_resolved(packet) {
        Ok(_) => (delivered, true, None),
        Err(e) => (delivered, false, Some(e)),
    }
}

/// Spawn a periodic heartbeat scheduler thread.
///
/// Returns a handle that manages the thread lifecycle. The thread will
/// send HEARTBEAT messages every `period_ms` milliseconds until the
/// handle is dropped.
///
/// # Arguments
///
/// * `transport` - UDP transport for sending heartbeats
/// * `history_cache` - History cache to get first_seq
/// * `rtps_endpoint` - RTPS context for building packets
/// * `period_ms` - Heartbeat period in milliseconds
///
/// # Returns
///
/// A handle that owns the thread. Drop the handle to stop the thread.
#[allow(clippy::too_many_arguments)]
pub fn spawn_heartbeat_scheduler(
    transport: Arc<UdpTransport>,
    history_cache: Arc<HistoryCache>,
    rtps_endpoint: RtpsEndpointContext,
    period_ms: u64,
    topic: String,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    endpoint_registry: Option<EndpointRegistry>,
    group_publisher: Option<Arc<crate::dds::publisher::PublisherCore>>,
) -> HeartbeatSchedulerHandle {
    let state = Arc::new(HeartbeatSchedulerState::new());
    let state_clone = Arc::clone(&state);
    let period = Duration::from_millis(period_ms);

    #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
    let thread = thread::Builder::new()
        .name("hdds-heartbeat".into())
        .spawn(move || {
            heartbeat_loop(
                transport,
                history_cache,
                rtps_endpoint,
                state_clone,
                period,
                topic,
                discovery_fsm,
                endpoint_registry,
                group_publisher,
            );
        })
        .expect("failed to spawn heartbeat thread");

    HeartbeatSchedulerHandle {
        state,
        thread: Some(thread),
    }
}

/// Main heartbeat loop - runs until stop is signaled.
#[allow(clippy::too_many_arguments)]
fn heartbeat_loop(
    transport: Arc<UdpTransport>,
    history_cache: Arc<HistoryCache>,
    ctx: RtpsEndpointContext,
    state: Arc<HeartbeatSchedulerState>,
    period: Duration,
    topic: String,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    endpoint_registry: Option<EndpointRegistry>,
    group_publisher: Option<Arc<crate::dds::publisher::PublisherCore>>,
) {
    log::debug!(
        "[heartbeat] Starting periodic heartbeat thread (period={:?})",
        period
    );

    while !state.should_stop() {
        thread::sleep(period);

        if state.should_stop() {
            break;
        }

        fire_heartbeat_tick(
            &transport,
            &history_cache,
            &ctx,
            &state,
            &topic,
            discovery_fsm.as_deref(),
            endpoint_registry.as_ref(),
            group_publisher.as_deref(),
        );
    }

    log::debug!("[heartbeat] Heartbeat thread stopped");
}

/// One periodic HEARTBEAT tick for a reliable writer (RTPS v2.5
/// Sec.8.4.7.2): builds and sends it from `state`'s current counters, or
/// does nothing when the writer has never written (`last_seq == 0`). The
/// shared body of the dedicated per-writer thread above (`heartbeat_loop`,
/// used for a writer built with no participant) and of
/// [`WriterHeartbeatSink::fire`] (an entry on the participant's liveliness
/// scheduler, `crate::dds::liveliness`) -- one evaluation, whichever
/// origin calls it.
///
/// Count allocation and the transmit it names run inside
/// `state.try_with_next_count`: `try_lock`, so this call -- on the
/// shared `hdds-hb-sender` worker -- never blocks waiting for THIS
/// writer's own piggyback or MANUAL_BY_TOPIC assert-liveliness HEARTBEAT
/// to finish sending on a DIFFERENT thread. On contention the whole tick
/// is skipped: no count allocated, nothing built or sent (legal -- a
/// HEARTBEAT for this writer is either about to reach the wire or just
/// did, from the origin holding the lock).
#[allow(clippy::too_many_arguments)]
pub(crate) fn fire_heartbeat_tick(
    transport: &UdpTransport,
    history_cache: &HistoryCache,
    ctx: &RtpsEndpointContext,
    state: &HeartbeatSchedulerState,
    topic: &str,
    discovery_fsm: Option<&DiscoveryFsm>,
    endpoint_registry: Option<&EndpointRegistry>,
    group_publisher: Option<&crate::dds::publisher::PublisherCore>,
) {
    // Get sequence range
    let last_seq = state.announced_last_seq();
    if last_seq == 0 {
        // No data written yet: normally nothing to announce, EXCEPT a
        // durable writer's first-match announce HEARTBEAT
        // (`dds::writer::builder`'s match callback) that could not send
        // because `send_serial` was contended at the moment discovery
        // tried, on a thread that must never block. Retried here, on
        // this writer's own next due tick, with the exact same
        // firstSN=1/lastSN=0 shape.
        //
        // The retry must not call the plain, blocking
        // `UdpTransport::send` -- to the metatraffic multicast address,
        // unconditionally, on the SHARED worker: that has no per-reader
        // locators, no relay routing (a relay-only peer could never see
        // it), no send-gate revocation, and a real block if that
        // socket's kernel buffer were ever full, stalling every OTHER
        // writer's tick queued behind it on `hdds-hb-sender`. It goes
        // through the exact same prepare + gated non-blocking transmit path as an
        // ordinary periodic tick, calling `send_heartbeat_best_effort`
        // DIRECTLY (not through `send_heartbeat_to_readers`, whose
        // `bool` return keeps its historical "unicast succeeded" sense
        // unchanged) so this retry can read the FULL outcome:
        // `send_heartbeat_to_readers`' `bool` is true only on a
        // successful UNICAST send -- a successful MULTICAST fallback
        // leaves it `false`, so the retry would re-arm `announce_pending`
        // forever even after the announcement genuinely reached the
        // wire. Re-armed on an actual send failure too (neither unicast
        // nor multicast delivered), not only on `send_serial`
        // contention -- a transient failure must not silently drop the
        // announcement any more than contention does.
        if state.take_announce_pending() {
            let fired = state.try_with_next_count(|count| {
                let packet = builder::build_heartbeat_packet_with_context(ctx, 1, 0, count);
                send_heartbeat_best_effort(
                    transport,
                    Some(state),
                    discovery_fsm,
                    endpoint_registry,
                    topic,
                    Some(ctx.guid_prefix),
                    &packet,
                    None,
                    &history_cache.wire_windows,
                )
            });
            match fired {
                Some(outcome) => {
                    if !outcome.transmitted() {
                        state.mark_announce_pending();
                    }
                }
                None => state.mark_announce_pending(),
            }
        }
        return;
    }

    let cache_oldest = advertised_first_seq(history_cache.oldest_seq(), last_seq);
    // Apply VOLATILE firstSN floor captured at first match (if any).
    let first_seq = state.heartbeat_first_seq(cache_oldest);

    let fired = state.try_with_next_count(|count| {
        #[cfg(test)]
        test_pause::maybe_panic_once(topic);
        #[cfg(test)]
        test_pause::maybe_pause(topic, count);

        // Build and send HEARTBEAT
        let packet = builder::build_heartbeat_packet_with_context(ctx, first_seq, last_seq, count);
        // A GROUP Publisher's writer's HEARTBEAT carries its GroupInfo for
        // the readers of the spec class (D4, D18).
        let group_packet = group_publisher.and_then(|publisher| {
            let info = group_heartbeat_info_of(
                publisher,
                Some(&state.pending_gsn),
                history_cache,
                first_seq,
                last_seq,
            )?;
            Some(builder::build_heartbeat_packet_group(
                ctx, first_seq, last_seq, count, info,
            ))
            .filter(|packet| !packet.is_empty())
        });

        // Same destinations as the on-write emitter (`maybe_send_heartbeat`):
        // per-reader user unicast, user-data multicast as fallback. A reader
        // receiving two streams for the same writer applies the RTPS
        // per-writer count-monotonicity rule and discards whichever stream is
        // behind -- most of our user HEARTBEATs were then discarded, no
        // ACKNACK/NACK_FRAG flowed and fragmented samples never recovered
        // their holes. One writer = one count sequence (shared with
        // `maybe_send_heartbeat`) over the SAME locator set.
        send_heartbeat_to_readers(
            transport,
            Some(state),
            discovery_fsm,
            endpoint_registry,
            topic,
            Some(ctx.guid_prefix),
            &packet,
            group_packet.as_deref(),
            &history_cache.wire_windows,
            true,
        );
        log::trace!(
            "[heartbeat] Sent HEARTBEAT first={} last={} count={}",
            first_seq,
            last_seq,
            count
        );
    });

    if fired.is_none() {
        log::trace!(
            "[heartbeat] periodic tick for {topic} skipped: this writer's own \
             piggyback/manual-assert HEARTBEAT is in flight"
        );
    }
}

/// Tests only: a one-shot hook to pause a specific topic's tick right
/// after its count is allocated, reproducing a slow/blocking send
/// deterministically (this shape catches concurrent fires of one
/// writer, and a writer delete that does not wait for one already in
/// flight). Armed by `arm`, consumed at most
/// once by `maybe_pause` -- a second tick for the same topic runs
/// unpaused unless re-armed. Keyed by topic in a map, not a single
/// slot: several tests in this binary use this hook on their own,
/// distinct topics, and the default test runner runs them concurrently
/// -- a single slot would have one `arm` call silently clobber
/// another's (dropping its `entered` sender, which then reads as
/// `Disconnected`).
#[cfg(test)]
pub(crate) mod test_pause {
    use std::collections::HashMap;
    use std::sync::mpsc::Sender;
    use std::sync::{Arc, Condvar, Mutex};

    struct Pause {
        entered: Sender<u32>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    static PAUSE: Mutex<Option<HashMap<String, Pause>>> = Mutex::new(None);

    /// Arms the pause: the next `fire_heartbeat_tick` for `topic` sends
    /// its allocated count on `entered`, then blocks until `release`'s
    /// flag is set `true` and its condvar notified.
    pub(crate) fn arm(topic: &str, entered: Sender<u32>, release: Arc<(Mutex<bool>, Condvar)>) {
        let mut slot = PAUSE.lock().unwrap_or_else(|e| e.into_inner());
        slot.get_or_insert_with(HashMap::new)
            .insert(topic.to_string(), Pause { entered, release });
    }

    pub(super) fn maybe_pause(topic: &str, count: u32) {
        let armed = {
            let mut slot = PAUSE.lock().unwrap_or_else(|e| e.into_inner());
            slot.as_mut().and_then(|map| map.remove(topic))
        };
        let Some(pause) = armed else { return };
        let _ = pause.entered.send(count);
        let (lock, cv) = &*pause.release;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = cv
            .wait_while(guard, |ready| !*ready)
            .unwrap_or_else(|e| e.into_inner());
    }

    /// A one-shot hook that PANICS the next `fire_heartbeat_tick` for
    /// `topic`, from INSIDE `try_with_next_count`'s closure -- i.e.
    /// while holding `send_serial` -- simulating a panic there (a bug
    /// anywhere in packet building or the send path) to prove the lock
    /// RECOVERS from the resulting poisoning instead of starving this
    /// writer's periodic HEARTBEAT forever (item 2's fix in
    /// `try_with_next_count`: see `participant_heartbeat_tests::
    /// a_panicked_tick_does_not_starve_this_writers_next_one`). The
    /// worker's own `catch_unwind` around `sink.fire()` keeps the WORKER
    /// alive either way; this hook is about the LOCK the panic unwinds
    /// through, not the worker thread.
    static PANIC_ONCE: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);

    /// Arms a one-shot panic for `topic`'s next tick.
    pub(crate) fn arm_panic_once(topic: &str) {
        let mut slot = PANIC_ONCE.lock().unwrap_or_else(|e| e.into_inner());
        slot.get_or_insert_with(std::collections::HashSet::new)
            .insert(topic.to_string());
    }

    pub(super) fn maybe_panic_once(topic: &str) {
        let armed = {
            let mut slot = PANIC_ONCE.lock().unwrap_or_else(|e| e.into_inner());
            slot.as_mut().is_some_and(|set| set.remove(topic))
        };
        if armed {
            panic!("test_pause::maybe_panic_once armed for topic {topic}");
        }
    }

    /// A one-shot hook that reports when `WriterHeartbeatSink::fire` for
    /// `topic` has actually RETURNED from `fire_heartbeat_tick` -- i.e. the
    /// worker finished that job, not merely that the scheduler dispatched
    /// it (`Shared::settle` only confirms the latter). Backed by a
    /// `Sender<()>` fired from `Drop`, so it still signals if the tick
    /// panics: the worker's own `catch_unwind` around `sink.fire()` is
    /// further up the call stack, and `Drop` runs during that unwind.
    /// Replaces fixed sleeps/timeouts in tests that need to know a specific
    /// tick has completed before asserting on its effects.
    static COMPLETION: Mutex<Option<HashMap<String, Sender<()>>>> = Mutex::new(None);

    /// Arms a one-shot completion signal for `topic`'s next tick.
    pub(crate) fn arm_completion(topic: &str, done: Sender<()>) {
        let mut slot = COMPLETION.lock().unwrap_or_else(|e| e.into_inner());
        slot.get_or_insert_with(HashMap::new)
            .insert(topic.to_string(), done);
    }

    /// RAII guard held across one `fire_heartbeat_tick` call: on drop (tick
    /// returned normally OR panicked), sends on the armed sender for this
    /// topic, if any. A topic with no armed sender is a no-op cost (one
    /// lock + map lookup).
    pub(crate) struct CompletionGuard {
        topic: String,
    }

    impl CompletionGuard {
        pub(crate) fn new(topic: &str) -> Self {
            Self {
                topic: topic.to_string(),
            }
        }
    }

    impl Drop for CompletionGuard {
        fn drop(&mut self) {
            let armed = {
                let mut slot = COMPLETION.lock().unwrap_or_else(|e| e.into_inner());
                slot.as_mut().and_then(|map| map.remove(&self.topic))
            };
            if let Some(done) = armed {
                let _ = done.send(());
            }
        }
    }
}

/// This writer's periodic HEARTBEAT (RTPS v2.5 Sec.8.4.7.2) as an entry on
/// its participant's liveliness scheduler (`crate::dds::liveliness`),
/// instead of a dedicated thread:
/// `fire` runs [`fire_heartbeat_tick`] with this writer's own context, on
/// a thread that is never the scheduler's own
/// (`crate::dds::liveliness::scheduler::deliver`). Used only when the
/// writer has a participant; a standalone writer (built with no
/// participant, so no scheduler to join) still gets its own
/// `spawn_heartbeat_scheduler` thread, unchanged.
pub(crate) struct WriterHeartbeatSink {
    transport: Arc<UdpTransport>,
    history_cache: Arc<HistoryCache>,
    ctx: RtpsEndpointContext,
    state: Arc<HeartbeatSchedulerState>,
    topic: String,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    endpoint_registry: Option<EndpointRegistry>,
    group_publisher: Option<Arc<crate::dds::publisher::PublisherCore>>,
}

impl WriterHeartbeatSink {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        transport: Arc<UdpTransport>,
        history_cache: Arc<HistoryCache>,
        ctx: RtpsEndpointContext,
        topic: String,
        discovery_fsm: Option<Arc<DiscoveryFsm>>,
        endpoint_registry: Option<EndpointRegistry>,
        group_publisher: Option<Arc<crate::dds::publisher::PublisherCore>>,
    ) -> Self {
        Self {
            transport,
            history_cache,
            ctx,
            state: Arc::new(HeartbeatSchedulerState::new()),
            topic,
            discovery_fsm,
            endpoint_registry,
            group_publisher,
        }
    }

    /// The counters shared with the on-write ("piggyback") HEARTBEAT path
    /// (`DataWriter::maybe_send_heartbeat`): one monotonic count per
    /// writer, whichever emitter sends (RTPS v2.5 Sec.8.3.8.6).
    pub(crate) fn state(&self) -> &Arc<HeartbeatSchedulerState> {
        &self.state
    }
}

impl crate::dds::liveliness::HeartbeatSink for WriterHeartbeatSink {
    fn fire(&self) {
        // `HeartbeatPeriodic::drop` signals this before the scheduler
        // watch is unwatched (belt and suspenders: the watch alone
        // already stops any FUTURE fire). A fire already handed to the
        // scheduler's worker thread before that signal lands still
        // checks it here, so nothing reaches the wire once the writer
        // considers its periodic HEARTBEAT stopped.
        if self.state.should_stop() {
            return;
        }
        // Test-only: signals (via Drop, so it fires even if
        // fire_heartbeat_tick panics -- the worker's own catch_unwind
        // is further up the call stack, in `heartbeat_worker`) that
        // THIS fire() call has fully returned. `Shared::settle()` only
        // confirms the scheduler DISPATCHED the job to the worker's
        // queue, never that the worker finished running it -- a test relying on
        // `settle()` alone, then a real sleep or a receive timeout, to
        // stand in for that can be defeated by a sufficiently delayed
        // worker.
        #[cfg(test)]
        let _completion = test_pause::CompletionGuard::new(&self.topic);
        fire_heartbeat_tick(
            &self.transport,
            &self.history_cache,
            &self.ctx,
            &self.state,
            &self.topic,
            self.discovery_fsm.as_deref(),
            self.endpoint_registry.as_ref(),
            self.group_publisher.as_deref(),
        );
    }
}

/// This writer's share of its periodic HEARTBEAT (RTPS v2.5
/// Sec.8.4.7.2): an entry on its participant's liveliness scheduler
/// (`Participant`) when it has one, or, for a writer built with no
/// participant, its own dedicated thread (`Standalone` -- see `WriterBuilder::build`'s spawn site
/// for which one a given writer gets). Both share the exact same
/// `HeartbeatSchedulerState` the on-write HEARTBEAT path writes through
/// too, so the two emitters never drift apart (one monotonic count per
/// writer, RTPS v2.5 Sec.8.3.8.6).
pub(crate) enum HeartbeatPeriodic {
    Participant {
        // Read in this type's own `Drop` (the deletion barrier) before
        // the field drop that follows unwatches it, so a `sink` not yet
        // dropped is still there for the sender to upgrade and no new
        // HEARTBEAT is admitted for it in between.
        watch: crate::dds::liveliness::HeartbeatWatchHandle,
        sink: Arc<WriterHeartbeatSink>,
    },
    Standalone(HeartbeatSchedulerHandle),
}

/// The writer-side stop check alone does not stop an ALREADY-dispatched
/// send: drop would signal stop but return before a job already handed
/// to the sender had run, so its HEARTBEAT would reach the wire after
/// both the writer's and the participant's drop had returned -- a
/// dedicated thread's `join` never has that gap. This is the deletion
/// barrier that closes it: how long `Drop for
/// HeartbeatPeriodic` waits for an in-flight send before giving up and
/// proceeding anyway (logged), same shape as `core::rt::shutdown`'s
/// `JOIN_WARN_AFTER`/`JOIN_GIVE_UP_AFTER` it otherwise mirrors.
const DELETE_BARRIER_BOUND: std::time::Duration = std::time::Duration::from_secs(2);

impl HeartbeatPeriodic {
    pub(crate) fn state(&self) -> &Arc<HeartbeatSchedulerState> {
        match self {
            Self::Participant { sink, .. } => sink.state(),
            Self::Standalone(handle) => handle.state(),
        }
    }
}

impl Drop for HeartbeatPeriodic {
    /// `Standalone`'s own `Drop` (on `HeartbeatSchedulerHandle`) already
    /// signals and joins its thread: a send in progress there finishes
    /// before the join returns, same as every other thread this crate
    /// joins on teardown. `Participant` has no thread of its own to
    /// join, so this reproduces the guarantee by hand, in two parts that
    /// do different jobs (the first one alone is not enough):
    ///
    /// 1. `revoke_sends()`: an "unconditional and immediate, never
    ///    blocked on a send in progress" version of this step would
    ///    still let a send already past its own per-call check transmit
    ///    after `wait_idle` below gave up and this whole function had
    ///    returned. `revoke_sends()` therefore takes the SAME lock the periodic
    ///    origin's `with_send_gate_held` holds for its entire transmit
    ///    (`send_gate` field doc on `HeartbeatSchedulerState`), so it CAN
    ///    block here now -- bounded, because that transmit is the
    ///    non-blocking, best-effort send. Once it returns, no periodic
    ///    send -- in flight or later -- can still reach the wire,
    ///    regardless of how long a paused/slow job takes to get there:
    ///    the real, unconditional "no HEARTBEAT after drop returns"
    ///    guarantee, not contingent on the bounded wait below.
    ///    `signal_stop()` alongside it is the cheap short-circuit at the
    ///    top of `fire` that skips building a packet at all in the
    ///    common case.
    /// 2. `wait_idle`, bounded (`DELETE_BARRIER_BOUND`): best-effort --
    ///    in the ordinary case (a send finishes in micro/milliseconds)
    ///    this returns almost at once and teardown proceeds cleanly
    ///    with nothing logged. By the time it runs, (1) already closed
    ///    the wire; this step is about the scheduler's own
    ///    `HeartbeatPending` admission bookkeeping, a separate concern
    ///    from the send gate.
    ///
    /// There is a further case (2) must never run
    /// in: a writer destroyed by code running ON the participant's own
    /// scheduler or HEARTBEAT sender thread (e.g. a sink callback
    /// `deliver` invokes inline, which can end up owning and dropping
    /// the last reference to a writer) would wait on work that very
    /// thread has to do, stalling every timer on it for up to the
    /// bound. (1) alone already gives the real guarantee (bounded, see
    /// above) with no further wait needed, so on those threads this
    /// skips (2) entirely. (1) itself staying reachable on the SENDER
    /// thread specifically (not deadlocking on its own `send_gate`
    /// lock) rests on `fire()`'s call stack never dropping a `DataWriter`
    /// -- it only ever reaches the sink's own fields (transport, history
    /// cache, state, ...), never the writer, and invokes no application
    /// callback, unlike the scheduler thread's `Transition`/
    /// `DeadlineMissed` delivery.
    fn drop(&mut self) {
        if let Self::Participant { sink, watch } = self {
            sink.state().revoke_sends();
            sink.state().signal_stop();
            if watch.is_on_its_own_scheduler_or_sender_thread() {
                log::debug!(
                    "[heartbeat] writer delete on its own scheduler/sender thread: skipping \
                     the deletion barrier's wait (its send gate is already revoked)"
                );
                return;
            }
            if !watch.pending().wait_idle(DELETE_BARRIER_BOUND) {
                log::warn!(
                    "[heartbeat] writer delete: an in-flight periodic HEARTBEAT send did not \
                     finish within {DELETE_BARRIER_BOUND:?}; proceeding without it (its send \
                     gate is already revoked, so nothing more reaches the wire for it)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_update_seq() {
        let state = HeartbeatSchedulerState::new();
        assert_eq!(state.last_seq.load(Ordering::Relaxed), 0);

        state.update_seq(42);
        assert_eq!(state.last_seq.load(Ordering::Relaxed), 42);

        state.update_seq(100);
        assert_eq!(state.last_seq.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn test_state_stop_signal() {
        let state = HeartbeatSchedulerState::new();
        assert!(!state.should_stop());

        state.signal_stop();
        assert!(state.should_stop());
    }

    #[test]
    fn test_state_count_increment() {
        let state = HeartbeatSchedulerState::new();

        assert_eq!(state.next_count(), 1);
        assert_eq!(state.next_count(), 2);
        assert_eq!(state.next_count(), 3);
    }

    /// `bump_first_eligible` installs the VOLATILE floor on the first
    /// call only; subsequent bumps must not slide the value.
    #[test]
    fn bump_first_eligible_is_first_match_wins() {
        let state = HeartbeatSchedulerState::new();
        assert_eq!(state.first_eligible_seq.load(Ordering::Acquire), 0);

        assert!(state.bump_first_eligible(32), "first bump must install");
        assert_eq!(state.first_eligible_seq.load(Ordering::Acquire), 33);

        assert!(
            !state.bump_first_eligible(100),
            "second bump must be a no-op even with a larger value"
        );
        assert_eq!(
            state.first_eligible_seq.load(Ordering::Acquire),
            33,
            "floor must stay at the first-match snapshot"
        );

        assert!(
            !state.bump_first_eligible(5),
            "third bump must be a no-op too"
        );
        assert_eq!(state.first_eligible_seq.load(Ordering::Acquire), 33);

        let zero_state = HeartbeatSchedulerState::new();
        assert!(zero_state.bump_first_eligible(0), "zero floor must install");
        assert!(
            !zero_state.bump_first_eligible(7),
            "a later match must not slide a zero floor"
        );
        assert_eq!(zero_state.first_eligible_seq.load(Ordering::Acquire), 1);
        assert_eq!(zero_state.heartbeat_first_seq(1), 1);
    }

    /// without a floor, `heartbeat_first_seq` passes `cache_oldest`
    /// through; with a floor, it returns `max(cache_oldest, floor + 1)`.
    #[test]
    fn heartbeat_first_seq_applies_volatile_floor() {
        let state = HeartbeatSchedulerState::new();
        // No floor yet: identity on cache_oldest.
        assert_eq!(state.heartbeat_first_seq(1), 1);
        assert_eq!(state.heartbeat_first_seq(50), 50);

        // Floor installed at 32 -> first advertised seq must be 33 at minimum.
        state.bump_first_eligible(32);
        assert_eq!(
            state.heartbeat_first_seq(1),
            33,
            "cache_oldest=1 must be lifted to floor+1"
        );
        assert_eq!(
            state.heartbeat_first_seq(33),
            33,
            "cache_oldest=33 must stay at 33 (tied with floor+1)"
        );
        assert_eq!(
            state.heartbeat_first_seq(50),
            50,
            "cache_oldest=50 must stay at 50 (already above floor+1)"
        );
    }
}
