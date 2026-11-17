// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Intra-process (local merger) delivery of coherent sets (DDS v1.4
//! Sec.2.2.3.6 PRESENTATION coherent_access, RTPS v2.5 Sec.8.7.5/8.7.6).
//!
//! A member of an open coherent set must reach a co-located coherent-access
//! reader together with the rest of its set, never ahead of it. Its local
//! delivery is therefore held back here, per writer, and released once the
//! set is complete.
//!
//! This mirrors what the wire leg does. A remote reader holds a set until
//! it has received the end of set AND every change up to that boundary,
//! each one either received or declared irrelevant by a GAP. Locally:
//!
//! * a write STAMPED into the open set (`DataWriter::coherent_context_held`,
//!   under the Publisher's `set_lock`) registers one outstanding member
//!   ([`IntraCoherentSets::stamp`]);
//! * that write later either stages its encoded sample
//!   ([`CoherentStamp::stage`]) or fails before emission, in which case
//!   dropping the stamp withdraws it: the application got an error, so the
//!   change was never part of the set, exactly like a GAP on the wire;
//! * the outermost `end_coherent_changes` marks the set closed
//!   ([`IntraCoherentSets::close_open_set`], under `set_lock`) and never
//!   waits for anything.
//!
//! A set is delivered when it is both closed and has no outstanding member,
//! by whichever of those events comes last: the close, the last stage, or
//! the last withdrawal ("last one out delivers"). Delivery itself
//! ([`IntraCoherentSets::deliver_ready`]) runs with no lock held: not
//! `set_lock` (the closer calls it after releasing it), and not this
//! queue's own mutex (released around every merger push). The merger push
//! runs the co-located readers' listeners on the delivering thread, so a
//! listener may itself write, or begin and end a set on the same Publisher.
//!
//! Sets are delivered strictly in order: a later set that completes first
//! waits for the earlier one, and only one thread delivers a given writer's
//! sets at a time (`SetsState::delivering`); a completion that finds a
//! delivery already running leaves its set to that thread.
//!
//! Which changes belong to a set is decided once, by the stamp, the same
//! call that tags the change's `coherent_sn` for the wire and the history.
//! The late-joiner replay (`HistoryCache::snapshot_for_local_replay`) reads
//! those tags and the journaled end of set; this queue reads the stamp.
//! Neither re-derives membership.

use super::local_group::GroupPart;
use crate::core::rt;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// One local delivery held back while its coherent set is incomplete:
/// already encoded and holding its slab claim, exactly as on the immediate
/// delivery path, just not pushed to the merger yet.
pub(super) struct StagedIntraSample {
    payload: LocalPayload,
    pub(super) key_hash: [u8; 16],
    pub(super) gsn: Option<u64>,
    pending: rt::merger::PendingOrders,
}

enum DeferredBody {
    Data(Vec<u8>),
    Key([u8; 16]),
}

struct DeferredSample {
    body: DeferredBody,
    seq: u64,
    source_ts_ns: u64,
    reception_prefix: bool,
    version: crate::dds::CdrVersion,
    lifecycle: u8,
    materialized: std::sync::OnceLock<rt::IndexEntry>,
}

enum LocalPayload {
    Ready(Option<rt::IndexEntry>),
    Deferred(DeferredSample),
}

impl Drop for LocalPayload {
    fn drop(&mut self) {
        let entry = match self {
            Self::Ready(entry) => *entry,
            Self::Deferred(sample) => sample.materialized.get().copied(),
        };
        if let Some(entry) = entry {
            rt::get_slab_pool_ref().release(entry.handle);
        }
    }
}

impl StagedIntraSample {
    pub(super) fn ready(entry: rt::IndexEntry, key_hash: [u8; 16], gsn: Option<u64>) -> Self {
        Self {
            payload: LocalPayload::Ready(Some(entry)),
            key_hash,
            gsn,
            pending: rt::merger::PendingOrders::default(),
        }
    }

    pub(super) fn with_pending(mut self, pending: rt::merger::PendingOrders) -> Self {
        self.pending = pending;
        self
    }

    pub(super) fn encoded(
        seq: u64,
        bytes: &[u8],
        source_ts_ns: u64,
        reception_ts: Option<u64>,
        version: crate::dds::CdrVersion,
        key_hash: [u8; 16],
    ) -> Self {
        let mut payload = Vec::with_capacity(bytes.len() + usize::from(reception_ts.is_some()) * 8);
        if let Some(at) = reception_ts {
            payload.extend_from_slice(&at.to_le_bytes());
        }
        payload.extend_from_slice(bytes);
        Self {
            payload: LocalPayload::Deferred(DeferredSample {
                body: DeferredBody::Data(payload),
                seq,
                source_ts_ns,
                reception_prefix: reception_ts.is_some(),
                version,
                lifecycle: 0,
                materialized: std::sync::OnceLock::new(),
            }),
            key_hash,
            gsn: None,
            pending: rt::merger::PendingOrders::default(),
        }
    }

    pub(super) fn lifecycle(
        seq: u64,
        key_hash: [u8; 16],
        lifecycle: u8,
        source_ts_ns: u64,
    ) -> Self {
        Self {
            payload: LocalPayload::Deferred(DeferredSample {
                body: DeferredBody::Key(key_hash),
                seq,
                source_ts_ns,
                reception_prefix: false,
                version: crate::dds::CdrVersion::Xcdr2,
                lifecycle,
                materialized: std::sync::OnceLock::new(),
            }),
            key_hash,
            gsn: None,
            pending: rt::merger::PendingOrders::default(),
        }
    }

    /// The key hash of a sample (not a lifecycle change), the reader-side
    /// refusal of a set that cannot be stored locally counts those only.
    pub(super) fn sample_key(&self) -> Option<[u8; 16]> {
        let is_sample = match &self.payload {
            LocalPayload::Ready(Some(entry)) => entry.lifecycle_bits() == 0,
            LocalPayload::Ready(None) => false,
            LocalPayload::Deferred(sample) => sample.lifecycle == 0,
        };
        is_sample.then_some(self.key_hash)
    }

    /// Only the frozen publication cohort may request local materialization.
    /// An absent local destination never reserves a slab or narrows its SN.
    pub(super) fn local_entry(&self) -> Option<rt::IndexEntry> {
        #[cfg(test)]
        super::run_local_prepare_hook();
        match &self.payload {
            LocalPayload::Ready(entry) => *entry,
            LocalPayload::Deferred(sample) => {
                if let Some(entry) = sample.materialized.get() {
                    return Some(*entry);
                }
                let seq = u32::try_from(sample.seq).ok()?;
                let bytes = match &sample.body {
                    DeferredBody::Data(bytes) => bytes.as_slice(),
                    DeferredBody::Key(key) => key.as_slice(),
                };
                let len = u32::try_from(bytes.len()).ok()?;
                let pool = rt::get_slab_pool_ref();
                let (handle, _) = pool.reserve_and_write(bytes, rt::Claim::Writer)?;
                let mut entry = rt::IndexEntry::with_cdr_version(
                    seq,
                    handle,
                    len,
                    sample.source_ts_ns,
                    sample.version,
                );
                entry.mark_source_ts();
                entry.mark_lifecycle(sample.lifecycle);
                if sample.reception_prefix {
                    entry.mark_reception_ts_prefix();
                }
                if let Err(extra) = sample.materialized.set(entry) {
                    pool.release(extra.handle);
                }
                sample.materialized.get().copied()
            }
        }
    }

    /// The owned entry of an ordinary tail, taken once; `None` once it has
    /// been taken or for a tail that holds no local entry.
    fn transfer_entry(mut self) -> Option<(rt::IndexEntry, [u8; 16])> {
        match &mut self.payload {
            LocalPayload::Ready(entry) => entry.take().map(|entry| (entry, self.key_hash)),
            _ => None,
        }
    }
}

/// One coherent set of one writer, as its local delivery sees it.
struct StagedSet {
    /// Identity of this set within the writer's queue (never reused, unlike
    /// a sequence number a failed write may give back).
    epoch: u64,
    /// The Publisher's GROUP set identity (the GSN `begin_coherent_changes`
    /// took), `None` under another access scope: a GROUP set is delivered by
    /// the Publisher's coordinator (`super::local_group`) with its siblings,
    /// not by this writer alone.
    group_sn: Option<u64>,
    /// Stamped writes of this set that have neither staged nor withdrawn.
    outstanding: usize,
    /// The outermost `end_coherent_changes` has closed this set.
    closed: bool,
    members: Vec<StagedIntraSample>,
    reported: bool,
    ordinary: Option<OrdinaryChange>,
}

struct OrdinaryChange {
    targets: Vec<rt::ReaderId>,
    ordering: Option<(u64, u64)>,
    _pending: rt::merger::PendingOrders,
}

impl StagedSet {
    fn complete(&self) -> bool {
        self.closed && self.outstanding == 0
    }
}

/// What the next delivery pass takes from the queue.
enum Next {
    /// A set this writer ended with no change of its own.
    EmptyPart(u64),
    Set(StagedSet),
    Group {
        epoch: u64,
        generation: u64,
        members: Vec<StagedIntraSample>,
    },
}

#[derive(Default)]
struct SetsState {
    /// Oldest first. At most one set is open (not closed), and it is the
    /// last: stamps and closes are both serialized by the Publisher's
    /// `set_lock`, and a Publisher has one open set at a time.
    sets: VecDeque<StagedSet>,
    /// GROUP set identities this writer ends with no change of its own: an
    /// empty part, still owed to the Publisher (RTPS v2.5 Sec.8.7.6, every
    /// writer ends every set), reported by the next delivery with no lock
    /// held.
    ended_empty: Vec<u64>,
    /// The part of the oldest set a reader's access bracket (or a replay)
    /// held back: delivered again, before any later set, by the next delivery
    /// (see `deliver_ready`). `None` when nothing is held.
    held: Option<GroupPart>,
    next_epoch: u64,
    /// A thread is delivering this writer's complete sets.
    delivering: bool,
    retry_due: bool,
    room_waiting: bool,
}

/// A writer's coherent sets awaiting local delivery. Shared (`Arc`) by the
/// `DataWriter`, which stamps and stages, and its `WriterCoherentBridge`,
/// which closes and delivers at `end_coherent_changes`.
pub(super) struct IntraCoherentSets {
    state: Mutex<SetsState>,
    merger: Arc<rt::TopicMerger>,
    /// The writer's `max_blocking_time`: one deadline per delivered set.
    max_blocking_time: Duration,
    /// A RELIABLE writer's delivery waits for room in a reader's history up
    /// to that deadline, as a live write would; a BEST_EFFORT one drops.
    reliable: bool,
    /// The Publisher's coordinator, which delivers a GROUP set as one whole
    /// across its writers (`super::local_group`); `None` under any other
    /// access scope, and for a writer without a Publisher.
    group: Option<std::sync::Weak<super::local_group::LocalGroupSets>>,
    /// This writer's identity within that coordinator.
    slot: u64,
    retry_lane: std::sync::OnceLock<Arc<crate::dds::reader::local_retries::Lane>>,
    /// This queue's bracket-end wake, kept alive here while the merger holds
    /// it weakly (`follow_brackets`).
    wake: std::sync::OnceLock<Arc<dyn Fn() + Send + Sync>>,
}

/// A stamped write's obligation to its set: [`stage`](Self::stage) its
/// sample, or drop the stamp to withdraw it. Must never be dropped while
/// the Publisher's `set_lock` is held: a withdrawal can complete the set
/// and deliver it on this thread.
pub(super) struct CoherentStamp {
    sets: Arc<IntraCoherentSets>,
    epoch: u64,
    settled: bool,
    /// The change's PID_COHERENT_SET (the writer's first SN in the set).
    coherent_sn: u64,
    /// Its group set, under GROUP access scope.
    group_sn: Option<u64>,
    gsn: Option<u64>,
}

impl CoherentStamp {
    /// The set markers of the stamped change, `(coherent_sn, group_sn)`,
    /// as its wire DATA and its journal entry carry them.
    pub(super) fn markers(&self) -> (Option<u64>, Option<u64>) {
        (Some(self.coherent_sn), self.group_sn)
    }

    /// Stage the encoded sample of this stamped write: delivered with its
    /// set, at once if the set is already closed and this was its last
    /// outstanding member.
    #[cfg(test)]
    pub(super) fn stage(self, entry: rt::IndexEntry, key_hash: [u8; 16]) {
        self.stage_sample(StagedIntraSample::ready(entry, key_hash, None));
    }

    pub(super) fn stage_sample(mut self, mut sample: StagedIntraSample) {
        self.settled = true;
        sample.gsn = self.gsn;
        self.sets.settle(self.epoch, Some(sample));
    }
}

impl Drop for CoherentStamp {
    /// The write did not stage: it failed before emission, or took a path
    /// that delivers locally on its own. Either way its set no longer waits
    /// for it.
    fn drop(&mut self) {
        if !self.settled {
            self.sets.settle(self.epoch, None);
        }
    }
}

/// Clears `SetsState::delivering` if a delivery unwinds, so a later
/// completion can still deliver. Never dropped with the queue's mutex
/// held (see `deliver_ready`).
struct DeliveringReset<'a>(&'a IntraCoherentSets);

impl Drop for DeliveringReset<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.lock().delivering = false;
        }
    }
}

impl IntraCoherentSets {
    pub(super) fn new(
        _topic: String,
        merger: Arc<rt::TopicMerger>,
        max_blocking_time: Duration,
        reliable: bool,
        group: Option<Arc<super::local_group::LocalGroupSets>>,
    ) -> Self {
        let slot = group
            .as_ref()
            .map(|group| group.writer_slot())
            .unwrap_or_default();
        Self {
            state: Mutex::new(SetsState::default()),
            merger,
            max_blocking_time,
            reliable,
            group: group.as_ref().map(Arc::downgrade),
            slot,
            retry_lane: std::sync::OnceLock::new(),
            wake: std::sync::OnceLock::new(),
        }
    }

    /// This writer's slot in its Publisher's coordinator, `None` when its
    /// sets are delivered per writer (no GROUP access scope).
    pub(super) fn group_slot(&self) -> Option<u64> {
        self.group.as_ref().map(|_| self.slot)
    }

    /// Deliver what a reader's access bracket holds back when that bracket
    /// ends: the merger calls this wake from `wake_local_group`. A GROUP
    /// Publisher's coordinator does the same for its sets, so only writers
    /// outside one register.
    pub(super) fn follow_brackets(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            if let Some(sets) = weak.upgrade() {
                sets.deliver_ready();
            }
        });
        self.merger.register_local_wake(&wake);
        let _ = self.wake.set(wake);
    }

    pub(super) fn acknowledge_control(&self, seq: u64) {
        self.merger.acknowledge_control(seq);
    }

    fn lock(&self) -> MutexGuard<'_, SetsState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register one more member of the Publisher's open set. Called under
    /// `set_lock`, in the critical section that tags the change as a member
    /// (lock order: `set_lock`, then this queue's mutex; nothing takes them
    /// the other way round).
    pub(super) fn stamp(
        self: &Arc<Self>,
        coherent_sn: u64,
        group_sn: Option<u64>,
        gsn: Option<u64>,
    ) -> CoherentStamp {
        let mut state = self.lock();
        let epoch = match state.sets.back_mut() {
            Some(open) if !open.closed => {
                open.outstanding += 1;
                open.epoch
            }
            _ => {
                let epoch = state.next_epoch;
                state.next_epoch += 1;
                state.sets.push_back(StagedSet {
                    epoch,
                    group_sn,
                    outstanding: 1,
                    closed: false,
                    members: Vec::new(),
                    reported: false,
                    ordinary: None,
                });
                epoch
            }
        };
        CoherentStamp {
            sets: Arc::clone(self),
            epoch,
            settled: false,
            coherent_sn,
            group_sn,
            gsn,
        }
    }

    /// Close this writer's part of the Publisher's set, if it has one.
    /// Called under `set_lock` by the outermost `end_coherent_changes`, for
    /// every writer of the set: never waits, never delivers (the closer
    /// calls [`deliver_ready`](Self::deliver_ready) once `set_lock` is
    /// released).
    pub(super) fn close_open_set(&self, generation: Option<u64>) {
        let mut state = self.lock();
        match state.sets.back_mut() {
            Some(open) if !open.closed => {
                open.closed = true;
                return;
            }
            _ => {}
        }
        // No change of this writer in the set: its empty part is still owed
        // to the Publisher, which waits for every writer of the set to end
        // it (RTPS v2.5 Sec.8.7.6).
        if let (Some(generation), Some(_)) = (generation, self.group.as_ref()) {
            state.ended_empty.push(generation);
        }
    }

    /// A stamped write of set `epoch` staged `member`, or (`None`) withdrew.
    fn settle(self: &Arc<Self>, epoch: u64, member: Option<StagedIntraSample>) {
        let ready = {
            let mut state = self.lock();
            let Some(set) = state.sets.iter_mut().find(|s| s.epoch == epoch) else {
                // No such set: nothing will ever deliver it, so give its
                // claim back.
                drop(state);
                drop(member);
                return;
            };
            if let Some(member) = member {
                set.members.push(member);
            }
            set.outstanding -= 1;
            state.sets.front().is_some_and(StagedSet::complete) && !state.delivering
        };
        if ready {
            self.deliver_ready();
        }
    }

    /// Deliver every complete set at the head of the queue, oldest first.
    /// Returns at once if another call (another thread, or this thread
    /// further up its stack, from a listener) is already delivering: that
    /// call picks up what completed meanwhile before it stops. Must be
    /// called with no lock held.
    pub(super) fn deliver_ready(self: &Arc<Self>) {
        {
            let mut state = self.lock();
            if state.delivering {
                state.retry_due = true;
                return;
            }
            // Only the armed room callback retries a blocked head. Access
            // transitions must not accumulate duplicate waiter ownership.
            if state.room_waiting {
                return;
            }
            state.retry_due = false;
            state.delivering = true;
        }
        // Declared before any later guard of the mutex, so it drops after
        // it on an unwind.
        let _reset = DeliveringReset(self);
        loop {
            // A part a bracket held back is the oldest undelivered one: it
            // goes first, and no later set is taken while it is held.
            let held = self.lock().held.take();
            if let Some(part) = held {
                match Self::deliver_part(part) {
                    None => continue,
                    Some(part) => {
                        if self.hold(part) {
                            continue;
                        }
                        return;
                    }
                }
            }
            let next = {
                let mut state = self.lock();
                let next = match state.ended_empty.first().copied() {
                    Some(generation) => {
                        state.ended_empty.remove(0);
                        Some(Next::EmptyPart(generation))
                    }
                    None if !self.merger.has_any_pending_replay() => match state.sets.front_mut() {
                        Some(set) if set.complete() && !set.reported => {
                            match set.group_sn.filter(|_| self.group.is_some()) {
                                Some(generation) => {
                                    set.reported = true;
                                    Some(Next::Group {
                                        epoch: set.epoch,
                                        generation,
                                        members: std::mem::take(&mut set.members),
                                    })
                                }
                                None => {
                                    let popped = state.sets.pop_front().map(Next::Set);
                                    debug_assert!(
                                        popped.is_some(),
                                        "a complete front set can be popped"
                                    );
                                    popped
                                }
                            }
                        }
                        _ => None,
                    },
                    None => None,
                };
                match next {
                    Some(next) => next,
                    None => {
                        // Cleared under the same lock as the check: a set
                        // that completes after this point finds no delivery
                        // running and delivers itself.
                        state.delivering = false;
                        drop(state);
                        self.retain_pending();
                        return;
                    }
                }
            };
            match next {
                Next::EmptyPart(generation) => self.report(generation, Vec::new(), None),
                Next::Group {
                    epoch,
                    generation,
                    members,
                } => self.report(generation, members, Some(epoch)),
                Next::Set(mut set) => {
                    if let Some(ordinary) = &set.ordinary {
                        // An ordinary set holds exactly one change; nothing
                        // to hand on for an empty one.
                        let popped = set.members.pop();
                        debug_assert!(popped.is_some(), "an ordinary set holds one change");
                        let Some(member) = popped else {
                            continue;
                        };
                        let transferred = member.transfer_entry();
                        debug_assert!(
                            transferred.is_some(),
                            "an ordinary tail holds its local entry"
                        );
                        let Some((entry, key_hash)) = transferred else {
                            continue;
                        };
                        if let Err(blocked) = self.merger.push_staged(
                            entry,
                            key_hash,
                            &ordinary.targets,
                            self.reliable,
                            ordinary.ordering,
                        ) {
                            set.members
                                .push(StagedIntraSample::ready(entry, key_hash, None));
                            {
                                let mut state = self.lock();
                                state.sets.push_front(set);
                                state.room_waiting = true;
                            }
                            self.retain_pending();
                            let stream = Arc::clone(self);
                            let retry: crate::dds::reader::LocalRetry = Arc::new(move || {
                                stream.lock().room_waiting = false;
                                stream.deliver_ready();
                            });
                            let lane = Arc::clone(self.retry_lane.get_or_init(|| {
                                Arc::new(crate::dds::reader::local_retries::Lane::default())
                            }));
                            blocked.retry_when_room(
                                entry,
                                key_hash,
                                Arc::new(move || {
                                    crate::dds::reader::local_retries::schedule(
                                        &lane,
                                        Arc::clone(&retry),
                                    );
                                }),
                            );
                            let due = {
                                let mut state = self.lock();
                                let due = state.retry_due && !state.room_waiting;
                                state.delivering = due;
                                state.retry_due = false;
                                due
                            };
                            if due {
                                continue;
                            }
                            return;
                        }
                    } else if let Some(part) = self.push(set.members) {
                        if self.hold(part) {
                            continue;
                        }
                        return;
                    }
                }
            }
        }
    }

    /// Hand one part of a GROUP set to the Publisher's coordinator, which
    /// delivers it with the other writers' parts. Runs with no lock held:
    /// the part delivered last delivers the whole set, readers' listeners
    /// included.
    fn report(
        self: &Arc<Self>,
        generation: u64,
        members: Vec<StagedIntraSample>,
        epoch: Option<u64>,
    ) {
        let Some(group) = self.group.as_ref().and_then(std::sync::Weak::upgrade) else {
            drop(members);
            if let Some(epoch) = epoch {
                self.finish(epoch);
            }
            return;
        };
        group.report(
            generation,
            self.slot,
            super::local_group::GroupPart {
                merger: Arc::clone(&self.merger),
                members,
                max_blocking_time: self.max_blocking_time,
                reliable: self.reliable,
                completion: epoch.map(|epoch| super::local_group::GroupCompletion {
                    stream: Arc::clone(self),
                    epoch,
                }),
            },
        );
    }

    pub(super) fn finish(self: &Arc<Self>, epoch: u64) {
        let ready = {
            let mut state = self.lock();
            if state.sets.front().is_some_and(|set| set.epoch == epoch) {
                state.sets.pop_front();
            }
            !state.delivering
        };
        if ready {
            self.retain_pending();
        }
    }

    fn retain_pending(self: &Arc<Self>) {
        if let Some(group) = self.group.as_ref().and_then(std::sync::Weak::upgrade) {
            group.update_stream(Arc::clone(self));
        }
    }

    /// Whether the registry of the Publisher's coordinator must keep this
    /// queue. A delivery in flight counts: its end prunes the queue through
    /// `retain_pending`, and until then a held or new set is never left
    /// unregistered (a stale registration only costs one empty delivery).
    pub(super) fn has_queued_changes(&self) -> bool {
        let state = self.lock();
        state.delivering || !state.sets.is_empty() || state.held.is_some()
    }

    /// Keep the part a bracket held back as the next thing to deliver, and
    /// say whether a completion that asked for a retry meanwhile means to
    /// deliver it now (`true`: the caller goes on, `false`: it stops).
    fn hold(self: &Arc<Self>, part: GroupPart) -> bool {
        let due = {
            let mut state = self.lock();
            state.held = Some(part);
            let due = state.retry_due && !state.room_waiting;
            state.retry_due = false;
            state.delivering = due;
            due
        };
        self.retain_pending();
        due
    }

    /// One attempt to deliver `part` as a whole: `None` once it is delivered
    /// (or refused whole, reported), `Some` when a reader's access bracket or
    /// a replay holds it back, handed back intact for a later attempt.
    fn deliver_part(part: GroupPart) -> Option<GroupPart> {
        let (_, mut remaining) = super::local_group::deliver_parts(vec![part], 0);
        remaining.pop()
    }

    /// Push one complete set to the merger, in the order its members
    /// staged, which is their SN order: a `DataWriter` is not `Sync`, so one
    /// writer's writes take their SNs and stage one after the other.
    ///
    /// Admission takes the whole set, or none of it, before any push. A
    /// capacity wait releases every reservation and producer turn first.
    /// `Some`: a bracket or a replay held the set back; the caller keeps it.
    fn push(&self, members: Vec<StagedIntraSample>) -> Option<GroupPart> {
        if members.is_empty() {
            return None;
        }
        let part = super::local_group::GroupPart {
            merger: Arc::clone(&self.merger),
            members,
            max_blocking_time: self.max_blocking_time,
            reliable: self.reliable,
            completion: None,
        };
        Self::deliver_part(part)
    }
}

impl rt::LocalDeliveryOrder for IntraCoherentSets {
    fn try_enter(&self) -> bool {
        let mut state = self.lock();
        if state.delivering
            || !state.sets.is_empty()
            || !state.ended_empty.is_empty()
            || state.held.is_some()
            || self.merger.has_any_pending_replay()
        {
            return false;
        }
        state.delivering = true;
        true
    }

    fn defer(
        self: Arc<Self>,
        entry: rt::IndexEntry,
        key_hash: [u8; 16],
        targets: Vec<rt::ReaderId>,
        ordering: Option<(u64, u64)>,
        pending: rt::merger::PendingOrders,
    ) {
        if targets.is_empty() {
            rt::get_slab_pool_ref().release(entry.handle);
            return;
        }
        {
            let mut state = self.lock();
            let epoch = state.next_epoch;
            state.next_epoch += 1;
            state.sets.push_back(StagedSet {
                epoch,
                group_sn: None,
                outstanding: 0,
                closed: true,
                members: vec![StagedIntraSample::ready(entry, key_hash, None)],
                reported: false,
                ordinary: Some(OrdinaryChange {
                    targets,
                    ordering,
                    _pending: pending,
                }),
            });
        }
        self.retain_pending();
        self.deliver_ready();
    }

    fn leave(self: Arc<Self>) {
        let pending = {
            let mut state = self.lock();
            state.delivering = false;
            !state.sets.is_empty() || !state.ended_empty.is_empty() || state.held.is_some()
        };
        if pending {
            // Older notifications drain before later work can wait for
            // capacity; failed admissions also wait for their write guards.
            crate::dds::notify_local(move || self.deliver_ready());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sets() -> Arc<IntraCoherentSets> {
        Arc::new(IntraCoherentSets::new(
            "intra-coherent-unit".to_string(),
            Arc::new(rt::TopicMerger::new()),
            Duration::from_millis(50),
            true,
            None,
        ))
    }

    fn member(seq: u32) -> (rt::IndexEntry, [u8; 16]) {
        let (handle, _metric) = rt::get_slab_pool_ref()
            .reserve_and_write(b"member", rt::Claim::Writer)
            .expect("slab reservation");
        (
            rt::IndexEntry::with_cdr_version(seq, handle, 6, 0, crate::dds::CdrVersion::Xcdr2),
            [0u8; 16],
        )
    }

    fn queued(sets: &IntraCoherentSets) -> Vec<(usize, bool, usize)> {
        sets.lock()
            .sets
            .iter()
            .map(|s| (s.outstanding, s.closed, s.members.len()))
            .collect()
    }

    /// The close of a set whose member has not staged yet returns at once
    /// and delivers nothing; the member's own stage delivers the set.
    #[test]
    fn a_close_before_the_last_stage_leaves_delivery_to_the_stage() {
        let sets = sets();
        let first = sets.stamp(1, None, None);
        let second = sets.stamp(1, None, None);
        let (e, k) = member(1);
        first.stage(e, k);
        sets.close_open_set(None);
        sets.deliver_ready();
        assert_eq!(queued(&sets), vec![(1, true, 1)], "held for the straggler");
        let (e, k) = member(2);
        second.stage(e, k);
        assert!(queued(&sets).is_empty(), "the last stage delivered the set");
    }

    /// A stamped write that fails is withdrawn: the set is delivered
    /// without it, by the withdrawal itself when it comes last.
    #[test]
    fn a_withdrawn_member_completes_its_set() {
        let sets = sets();
        let first = sets.stamp(1, None, None);
        let failed = sets.stamp(1, None, None);
        let third = sets.stamp(1, None, None);
        let (e, k) = member(1);
        first.stage(e, k);
        let (e, k) = member(3);
        third.stage(e, k);
        sets.close_open_set(None);
        sets.deliver_ready();
        assert_eq!(queued(&sets), vec![(1, true, 2)]);
        drop(failed);
        assert!(queued(&sets).is_empty(), "the withdrawal delivered the set");
    }

    /// A later set that completes first waits for the earlier one, and both
    /// go out, in order, when the earlier one completes.
    #[test]
    fn sets_are_delivered_in_order() {
        let sets = sets();
        let slow = sets.stamp(1, None, None);
        sets.close_open_set(None);
        let next = sets.stamp(1, None, None);
        let (e, k) = member(2);
        next.stage(e, k);
        sets.close_open_set(None);
        sets.deliver_ready();
        assert_eq!(queued(&sets), vec![(1, true, 0), (0, true, 1)]);
        let (e, k) = member(1);
        slow.stage(e, k);
        assert!(queued(&sets).is_empty());
    }

    /// A completion that finds a delivery running leaves its set to that
    /// delivery, which picks it up before it stops (the listener case: a
    /// listener run by the push completes another set on the same thread).
    #[test]
    fn a_completion_during_a_delivery_is_picked_up_by_it() {
        let sets = sets();
        sets.lock().delivering = true;
        let stamp = sets.stamp(1, None, None);
        sets.close_open_set(None);
        drop(stamp);
        assert_eq!(
            queued(&sets),
            vec![(0, true, 0)],
            "left to the running delivery"
        );
        sets.deliver_ready();
        assert_eq!(
            queued(&sets),
            vec![(0, true, 0)],
            "a second delivery does not run beside the first"
        );
        sets.lock().delivering = false;
        sets.deliver_ready();
        assert!(queued(&sets).is_empty());
    }

    /// A close with no set of the writer open closes nothing: an earlier,
    /// closed set still waiting for a straggler stays as it is, and a stamp
    /// after it opens a new set rather than joining the closed one.
    #[test]
    fn an_idle_close_does_not_touch_an_earlier_set() {
        let sets = sets();
        let straggler = sets.stamp(1, None, None);
        sets.close_open_set(None);
        sets.close_open_set(None);
        let later = sets.stamp(1, None, None);
        assert_eq!(queued(&sets), vec![(1, true, 0), (1, false, 0)]);
        drop(straggler);
        drop(later);
        assert_eq!(queued(&sets), vec![(0, false, 0)], "the open set stays");
    }

    /// A queue whose delivery is in flight stays registered with its
    /// Publisher's coordinator (`has_queued_changes`).
    #[test]
    fn a_delivery_in_flight_keeps_the_queue_registered() {
        let sets = sets();
        assert!(!sets.has_queued_changes());
        sets.lock().delivering = true;
        assert!(
            sets.has_queued_changes(),
            "a delivery in flight counts as queued"
        );
        sets.lock().delivering = false;
        assert!(!sets.has_queued_changes());
    }
}
