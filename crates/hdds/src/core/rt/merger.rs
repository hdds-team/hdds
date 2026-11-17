// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fan-out dispatcher from writer to N reader rings.
//!
//!
//! `TopicMerger` clones `IndexEntry` to all registered readers. Supports
//! late-joiner delivery with TRANSIENT_LOCAL/PERSISTENT durability.
//!
//! # Performance
//!
//! - Untracked mergers scan inline slots without a registration lock.
//! - Reliable DDS bindings serialize matching with admission and commit.

mod coherent;
pub(crate) use coherent::{
    lock_replay_cohort, CoherentMember, CoherentReplay, CoherentReplayIdentity, CoherentResult,
};

use super::indexring::{IndexEntry, IndexRing};
use super::slabpool::{Claim, SlabPool};
use crate::dds::CdrVersion;
use crate::reliability::local_ack::{LocalAckWriter, LocalReaderAck};
use crate::reliability::HistoryCache;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(test)]
type DeliveryHook = Arc<dyn Fn(u32) + Send + Sync>;

/// Number of lock-free inline reader slots scanned by the hot push path.
const INLINE_READERS: usize = 16;

/// Unique identifier for a reader in a merger
///
/// Based on Arc pointer address - two readers with the same ring
/// pointer are considered the same reader.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ReaderId(usize);

impl ReaderId {
    /// Create ReaderId from an IndexRing Arc pointer
    pub fn from_ring(ring: &Arc<IndexRing>) -> Self {
        Self(Arc::as_ptr(ring) as usize)
    }
}

/// Content filter a reader registers together with its ring.
///
/// Called on the WRITER's thread with the encoded sample bytes and their
/// CDR version, before the entry is pushed into that reader's ring.
/// `false` skips the reader for this sample: no ring slot, no slab
/// reference, no DATA_AVAILABLE. This is the intra-process twin of the
/// network path, where `ReaderSubscriber::process_admitted` evaluates the
/// same filter before its own ring insertion; a ContentFilteredTopic reader
/// gets one of these from its builder, every other reader registers `None`.
///
/// # Contract for the closure
///
/// It runs on whichever thread calls `write()` on a bound writer, from
/// several writers at once, and the same underlying filter is evaluated on
/// the receive thread for the reader's network leg. It must not block, do
/// I/O, or create or drop DDS entities: for readers beyond the inline
/// slots it runs under the merger's registration read lock, so a closure
/// that registers or removes a reader on the same writer deadlocks. A
/// panic inside it is caught by the merger and counted as a rejection.
pub type SampleFilter = Arc<dyn Fn(&[u8], CdrVersion) -> bool + Send + Sync>;

/// Ownership gate a reader registers together with its ring, for one
/// writer: the EXCLUSIVE arbitration of DDS v1.4 Sec.2.2.3.9.2 applied to an
/// intra-process delivery. Called on the WRITER's thread, after the content
/// filter, with the entry (its writer sequence number and, for a lifecycle
/// change, its kind), its bytes (the encoded sample, or the 16-octet key
/// hash of a lifecycle change) and, for a sample, its instance key hash when
/// the pushing writer supplied it ([`TopicMerger::push_keyed`]; `None` for a
/// history replay, which the gate then derives from the bytes). `false`
/// skips the reader for this entry, exactly like a filter. Same contract as
/// [`SampleFilter`]; a panic is a rejection.
pub(crate) type SampleGate =
    Arc<dyn Fn(&IndexEntry, &[u8], Option<[u8; 16]>) -> bool + Send + Sync>;

/// The instance key hash of the sample being pushed, computed at most once
/// and only if a gated registration asks for it.
type KeyOnDemand<'a> = &'a dyn Fn() -> Option<[u8; 16]>;

/// What a [`DeliveryObserver`] calls with a delivered sample's bytes.
pub(crate) type ObserveFn = Box<dyn Fn(&[u8], CdrVersion) + Send + Sync>;

/// Observer of the samples a registration is delivered: the reader's
/// `on_data_available` listener for an intra-process delivery, which never
/// passes through the reader's network subscriber.
///
/// Armed while `hint & bit != 0` (the reader's listener slot hint, see
/// `dds::listener::ListenerSlot::hint`), so an unarmed observer costs the
/// push one relaxed load. Called on the WRITER's thread right after the
/// entry is in the reader's ring and the reader is notified, with the
/// sample's encoded bytes, and with no merger lock held. Lifecycle entries
/// (a local dispose or unregister) carry a key hash, not a sample, and are
/// not observed. The closure is application-facing: it must catch its own
/// panics (the reader's closure does).
pub(crate) struct DeliveryObserver {
    hint: Arc<AtomicU32>,
    bit: u32,
    observe: ObserveFn,
    /// A payload-less arrival notice, coalesced across a replay batch.
    notification: Option<Arc<dyn Fn() + Send + Sync>>,
    needs_payload: bool,
    /// Where `observe_later` hands its call (`deferring`); at once when
    /// none was given.
    defer: Option<DeferFn>,
}

/// Takes a call to make once the caller's locks are released.
pub(crate) type DeferFn = fn(Box<dyn FnOnce() + Send>);

impl DeliveryObserver {
    /// An observer armed while `hint & bit != 0`.
    #[must_use]
    pub(crate) fn new(hint: Arc<AtomicU32>, bit: u32, observe: ObserveFn) -> Self {
        Self {
            hint,
            bit,
            observe,
            notification: None,
            needs_payload: true,
            defer: None,
        }
    }

    /// The same observer, its `observe_later` calls handed to `defer`.
    #[must_use]
    pub(crate) fn deferring(self, defer: DeferFn) -> Self {
        Self {
            defer: Some(defer),
            ..self
        }
    }

    /// Split a payload-less listener notice from per-sample observation
    /// (such as DEADLINE). Replay defers the notice once per batch.
    pub(crate) fn notifying(
        self,
        notification: Arc<dyn Fn() + Send + Sync>,
        needs_payload: bool,
    ) -> Self {
        Self {
            notification: Some(notification),
            needs_payload,
            ..self
        }
    }

    fn notify_later(&self) {
        let Some(notification) = self.notification.clone() else {
            return;
        };
        let call: Box<dyn FnOnce() + Send> = Box::new(move || notification());
        self.defer.unwrap_or(crate::dds::notify_local)(call);
    }

    #[inline]
    fn armed(&self) -> bool {
        self.hint.load(Ordering::Relaxed) & self.bit != 0
    }

    /// [`observe`](Self::observe) for one member of a coherent group: both
    /// the payload callback and the payload-less notice are deferred to the
    /// end of the group's delivery (`notices::Delivering`), so a listener
    /// runs once every member of every writer's part is in its ring (DDS
    /// v1.4 Sec.2.2.3.6, `TopicMerger::deliver_grouped`).
    fn observe_grouped(self: &Arc<Self>, entry: &IndexEntry, pool: &SlabPool) {
        self.notify_later();
        self.observe_later(entry, pool);
    }

    /// [`observe`](Self::observe), told later: the payload is copied and
    /// the call handed to the observer's `defer` (the reader notices, told
    /// once the delivery of this thread ends, every lock it took released).
    /// For the history replay of `TopicMerger::add_reader`, which runs under
    /// the binding locks of the reader and of the domain: the listener
    /// called there could not create or delete an entity. Cold: replay only.
    #[inline(never)]
    fn observe_later(self: &Arc<Self>, entry: &IndexEntry, pool: &SlabPool) {
        if !self.needs_payload {
            return;
        }
        let data_len = entry.len as usize;
        let payload_start = entry.payload_offset();
        let bytes = match pool.try_borrow(entry.handle) {
            Some(buf) => buf.get(payload_start..data_len).map(<[u8]>::to_vec),
            None => pool
                .get_buffer(entry.handle)
                .get(payload_start..data_len)
                .map(<[u8]>::to_vec),
        };
        let Some(bytes) = bytes else {
            return;
        };
        let observer = Arc::clone(self);
        let version = entry.cdr_version;
        let call: Box<dyn FnOnce() + Send> = Box::new(move || (observer.observe)(&bytes, version));
        self.defer.unwrap_or(crate::dds::notify_local)(call);
    }

    /// Hand `entry`'s payload to the observer. The caller holds a live
    /// reference on `entry.handle`.
    #[inline(never)]
    fn observe(&self, entry: &IndexEntry, pool: &SlabPool) {
        if let Some(notification) = &self.notification {
            notification();
        }
        if !self.needs_payload {
            return;
        }
        let data_len = entry.len as usize;
        let payload_start = entry.payload_offset();
        let call = |buf: &[u8]| {
            if let Some(bytes) = buf.get(payload_start..data_len) {
                (self.observe)(bytes, entry.cdr_version);
            }
        };
        match pool.try_borrow(entry.handle) {
            Some(buf) => call(buf),
            None => call(&pool.get_buffer(entry.handle)),
        }
    }
}

/// No key supplied.
fn no_key() -> Option<[u8; 16]> {
    None
}

/// The pushed sample's instance key hash, asked of the writer at most once
/// (see [`KeyOnDemand`]), and the instance a door took room for.
struct ResolvedKey<'a> {
    supply: KeyOnDemand<'a>,
    asked: Option<Option<[u8; 16]>>,
    /// What the doors' `reserve` returned: the same for every reader of the
    /// sample, all of one type.
    used: [u8; 16],
}

impl<'a> ResolvedKey<'a> {
    fn new(supply: KeyOnDemand<'a>) -> Self {
        Self {
            supply,
            asked: None,
            used: [0; 16],
        }
    }

    fn get(&mut self) -> Option<[u8; 16]> {
        *self.asked.get_or_insert_with(|| (self.supply)())
    }
}

/// What [`MergerReader::admit`] decided for one registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Push it: there is room, taken in the reader's history if `reserved`.
    Admit { reserved: bool },
    /// No room and the reader does not wait for any.
    Skip,
    /// Excluded by the content filter; settle only after emission commits.
    Irrelevant,
    /// No room, and the writer waits for this reader to make some.
    Blocked,
}

/// Why a reader's history has no room for a sample (DDS v1.4 Sec.2.2.3.19),
/// as the SAMPLE_REJECTED reason it is reported with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoRoom {
    /// `max_samples`, or the reader's ring.
    Samples,
    /// A new instance with `max_instances` already managed.
    Instances,
    /// `max_samples_per_instance` samples of the instance already held.
    SamplesPerInstance,
}

/// What a reader needs from a DataWriter of the same process for its
/// HISTORY and RESOURCE_LIMITS (DDS v1.4 Sec.2.2.3.18, Sec.2.2.3.19): the
/// reader's side of the merger's push. A `DataReader` registers one with
/// every merger it binds to; a registration without one keeps the lossy
/// push (a full ring skips the entry).
///
/// Called on the WRITER's thread, with no merger lock held. A reader whose
/// door [`counts`](Self::counts) is asked for every sample; otherwise the
/// door is asked only when the ring is full.
pub(crate) trait ReaderDoor: Send + Sync {
    /// Teardown can close a door before its merger registration is retired.
    fn is_closed(&self) -> bool {
        false
    }

    /// `ring`, this reader's ring of the calling merger, is full: drop from
    /// it what the reader's history no longer keeps, counting `incoming`,
    /// about to be pushed (a sample, or a lifecycle change, which is none),
    /// whose instance is `key` when the writer supplied it. Returns whether a
    /// push now finds room.
    ///
    /// The caller is the ring's only producer, so room seen here stays until
    /// its push.
    fn make_room(&self, ring: &IndexRing, incoming: &IndexEntry, key: Option<[u8; 16]>) -> bool;

    /// Prepare enough ring positions for an entire coherent set.
    fn make_room_for_set(
        &self,
        _ring: &IndexRing,
        _members: &[(IndexEntry, [u8; 16])],
        _commit: bool,
    ) -> bool {
        false
    }

    /// A bound exceeded even in an empty history.
    fn never_holds_set(&self, _members: &[(IndexEntry, [u8; 16])]) -> Option<NoRoom> {
        None
    }

    /// Reserve a GROUP change's order before another writer can take a GSN.
    fn reserve_order(&self, _publisher: u64, _gsn: u64) -> Option<u64> {
        None
    }

    /// Cancel only a reservation not yet attached to a visible ring entry.
    fn cancel_pending_order(&self, _token: u64) {
        // Readers without ordered GROUP presentation reserve no token.
    }

    /// Register a GROUP member before publishing its ring entry.
    fn record_order(&self, _entry: &IndexEntry, _publisher: u64, _gsn: u64) -> Option<u64> {
        // Readers without ordered GROUP presentation have no order to record.
        None
    }

    /// Undo an order registration whose ring delivery failed.
    fn cancel_order(&self, _token: u64) {
        // Readers without ordered GROUP presentation have nothing to cancel.
    }

    /// Subscriber identity for GROUP coherence, shared across its readers.
    fn coherent_subscriber(&self) -> Option<usize> {
        None
    }

    /// Whether every sample takes room in the reader's history before it is
    /// pushed ([`reserve`](Self::reserve)). Fixed for the door's life.
    fn counts(&self) -> bool;

    /// Whether the reader's instance of a sample must be known to
    /// [`reserve`](Self::reserve) it. Fixed for the door's life.
    fn needs_instance(&self) -> bool;

    /// Take room in the reader's history for `entry`, a sample about to be
    /// pushed, whose instance is `key` when the writer supplied it and the
    /// door [`needs_instance`](Self::needs_instance) (the door decodes it
    /// otherwise). The ring entry carries the room until the application
    /// takes the sample. Returns the instance the room was taken for, to
    /// give it back with. Only for a door that [`counts`](Self::counts).
    fn reserve(&self, entry: &IndexEntry, key: Option<[u8; 16]>) -> Result<[u8; 16], NoRoom>;

    fn reserve_ordered(
        &self,
        entry: &IndexEntry,
        key: Option<[u8; 16]>,
        _publisher: u64,
        _gsn: u64,
    ) -> Result<[u8; 16], NoRoom> {
        self.reserve(entry, key)
    }

    fn has_room_ordered(
        &self,
        entry: &IndexEntry,
        key: Option<[u8; 16]>,
        _publisher: u64,
        _gsn: u64,
    ) -> bool {
        self.has_room(entry, key)
    }

    /// Give back a [`reserve`](Self::reserve) whose sample is not pushed,
    /// with the instance it returned.
    fn cancel(&self, key: [u8; 16]);

    /// Whether [`reserve`](Self::reserve) would find room now for a sample
    /// of instance `key` (as passed to `reserve`), without taking any: the
    /// condition a waiting writer re-checks under the door's wait lock,
    /// which a reservation given back would try to take again to wake it.
    fn has_room(&self, entry: &IndexEntry, key: Option<[u8; 16]>) -> bool;

    /// A sample of instance `key` (when known) found no room and will not
    /// be pushed to this reader, which does not wait for room: account for
    /// it as the reader's history refusing it (DDS v1.4 Sec.2.2.3.19).
    fn rejected(&self, why: NoRoom, key: Option<[u8; 16]>);

    /// Whether a writer waits for room rather than skip this reader: a
    /// RELIABLE reader, which nothing would repair a skipped sample for
    /// (DDS v1.4 Sec.2.2.3.14, Sec.2.2.3.19).
    fn waits(&self) -> bool;

    /// Wait until `blocked()` is false or `deadline`, woken by the reader
    /// as it frees room. Returns false on a timeout with `blocked()` still
    /// true. `blocked` must not take the reader's consumer gate.
    fn wait_while(&self, deadline: std::time::Instant, blocked: &mut dyn FnMut() -> bool) -> bool;

    /// Schedule a one-shot retry after returning all tentative room.
    /// The callback only queues work, never delivers on the freeing thread.
    fn retry_when_room(
        &self,
        _retry: Arc<dyn Fn() + Send + Sync>,
        _blocked: &mut dyn FnMut() -> bool,
    ) {
    }

    /// The depth of the reader's open coherent-access bracket, when it is a
    /// reader of a GROUP-scope Subscriber: a local coherent set must reach
    /// its ring only while no bracket is open, so that a bracketed read
    /// never sees part of a set (DDS v1.4 Sec.2.2.2.5.2.8, GROUP access
    /// scope). `None` otherwise: the reader has no bracket to wait for.
    fn bracket_depth(&self) -> Option<u32> {
        None
    }
}

/// The deadline of one `write()`: at most `max_blocking_time` after the
/// first time the write blocks, whatever it blocks for (DDS v1.4
/// Sec.2.2.3.14: "the maximum duration the write operation may block").
/// Every wait of the write shares it. The clock is read only when something
/// first waits: a write that never blocks never reads it.
pub(crate) struct WriteDeadline {
    max_blocking_time: std::time::Duration,
    at: std::cell::Cell<Option<std::time::Instant>>,
}

impl WriteDeadline {
    /// The deadline of a write that may block `max_blocking_time`.
    #[inline]
    pub(crate) fn new(max_blocking_time: std::time::Duration) -> Self {
        Self {
            max_blocking_time,
            at: std::cell::Cell::new(None),
        }
    }

    /// What is left of the wait, fixing the deadline if no wait did yet.
    pub(crate) fn remaining(&self) -> std::time::Duration {
        self.instant()
            .saturating_duration_since(std::time::Instant::now())
    }

    /// The instant the write stops waiting, fixed by the first call.
    pub(crate) fn instant(&self) -> std::time::Instant {
        match self.at.get() {
            Some(at) => at,
            None => {
                let now = std::time::Instant::now();
                let at = now.checked_add(self.max_blocking_time).unwrap_or_else(|| {
                    now + std::time::Duration::from_secs(60 * 60 * 24 * 365 * 100)
                });
                self.at.set(Some(at));
                at
            }
        }
    }
}

/// The writer did not find room in a RELIABLE reader's history within its
/// `max_blocking_time` (see [`TopicMerger::admit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoomTimeout;

/// A coherent writer's local stream, including ordinary changes queued
/// behind retained sets. No queue lock crosses admission or delivery.
pub(crate) trait LocalDeliveryOrder: Send + Sync {
    fn try_enter(&self) -> bool;
    fn defer(
        self: Arc<Self>,
        entry: IndexEntry,
        key: [u8; 16],
        targets: Vec<ReaderId>,
        ordering: Option<(u64, u64)>,
        pending: PendingOrders,
    );
    fn leave(self: Arc<Self>);
}

#[derive(Default)]
struct LocalProducer {
    turn: OnceLock<parking_lot::ReentrantMutex<()>>,
    order: OnceLock<std::sync::Weak<dyn LocalDeliveryOrder>>,
    publisher: OnceLock<u64>,
    pending: std::sync::Mutex<Vec<std::sync::Weak<PendingOrderLease>>>,
}

#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    // @audit-ok: one-shot test-only thread-local hook, never shared.
    static BEFORE_ROOM_WAIT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn before_next_room_wait(hook: Box<dyn FnOnce()>) {
    BEFORE_ROOM_WAIT.with(|pending| *pending.borrow_mut() = Some(hook));
}

#[cfg(any(test, feature = "test-support"))]
fn run_room_wait_hook() {
    let hook = BEFORE_ROOM_WAIT.with(|pending| pending.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

struct PendingOrderReservation {
    door: Arc<dyn ReaderDoor>,
    token: u64,
}

impl Drop for PendingOrderReservation {
    fn drop(&mut self) {
        self.door.cancel_pending_order(self.token);
    }
}

#[derive(Default)]
struct PendingOrderState {
    closed: bool,
    committed: bool,
    reservations: Vec<PendingOrderReservation>,
}

struct PendingOrderLease {
    publisher: u64,
    gsn: u64,
    seq: u64,
    coherent: bool,
    state: std::sync::Mutex<PendingOrderState>,
}

impl PendingOrderLease {
    fn extend(&self, door: Arc<dyn ReaderDoor>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed
            || (state.committed && !self.coherent)
            || state
                .reservations
                .iter()
                .any(|existing| Arc::ptr_eq(&existing.door, &door))
        {
            return;
        }
        if let Some(token) = door.reserve_order(self.publisher, self.gsn) {
            state
                .reservations
                .push(PendingOrderReservation { door, token });
        }
    }
}

/// Positions of a GROUP change, including readers that pair while the
/// change is still being prepared or its coherent set remains retained.
#[derive(Default)]
pub(crate) struct PendingOrders(Option<Arc<PendingOrderLease>>);

impl PendingOrders {
    pub(crate) fn finish(&self) {
        let Some(lease) = self.0.as_ref() else { return };
        let _notices = crate::dds::LocalDelivery::enter();
        let reservations = {
            let mut state = lease.state.lock().unwrap_or_else(|e| e.into_inner());
            state.closed = true;
            std::mem::take(&mut state.reservations)
        };
        // Cancellation may wake a reader. No lease or registry lock reaches it.
        drop(reservations);
    }
}

impl Drop for PendingOrders {
    fn drop(&mut self) {
        self.finish();
    }
}

struct OrderReservation<'a> {
    door: &'a dyn ReaderDoor,
    token: u64,
    committed: bool,
}

impl Drop for OrderReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.door.cancel_order(self.token);
        }
    }
}

struct OrderedAdmission {
    order: Arc<dyn LocalDeliveryOrder>,
    direct: bool,
    targets: Vec<ReaderId>,
}

pub(crate) struct AdmissionControl<'m> {
    producer: Option<parking_lot::ReentrantMutexGuard<'m, ()>>,
    order: Option<OrderedAdmission>,
}

/// Cleanup operations erase completely for an ordinary admission.
pub(crate) trait AdmissionCleanup {
    const CONTROLLED: bool;
    fn release_producer(&mut self);
    fn release_order(&mut self);
}

impl AdmissionCleanup for () {
    const CONTROLLED: bool = false;
    // @audit-ok: the ordinary policy owns no producer guard to release.
    #[inline]
    fn release_producer(&mut self) {}
    // @audit-ok: the ordinary policy owns no logical delivery lease.
    #[inline]
    fn release_order(&mut self) {}
}

impl AdmissionCleanup for Option<AdmissionControl<'_>> {
    const CONTROLLED: bool = true;
    fn release_producer(&mut self) {
        if let Some(control) = self.as_mut() {
            drop(control.producer.take());
        }
    }
    fn release_order(&mut self) {
        drop(self.take());
    }
}

pub(crate) type PlainAdmission<'m> = Admission<'m, ()>;

impl Drop for OrderedAdmission {
    fn drop(&mut self) {
        if self.direct {
            Arc::clone(&self.order).leave();
        }
    }
}

/// Which registrations of a merger a sample was admitted to by
/// [`TopicMerger::admit`], to be pushed by [`TopicMerger::deliver`]. Dropped
/// without being delivered, it gives back the room it took.
#[must_use]
pub(crate) struct Admission<'m, C: AdmissionCleanup = Option<AdmissionControl<'m>>> {
    merger: &'m TopicMerger,
    pairing: Option<parking_lot::RwLockReadGuard<'m, ()>>,
    notices: Option<crate::dds::LocalDelivery>,
    /// Inline slot + 1 of the sole active reader when the sample took the
    /// single-reader path, 0 otherwise.
    sole: usize,
    /// Inline slots admitted (bit i: slot i).
    inline: u32,
    /// Inline slots whose door took room for the sample.
    reserved: u32,
    irrelevant_inline: u32,
    irrelevant_overflow: Vec<MergerReader>,
    /// Overflow registrations admitted, and whether their door took room.
    overflow: Vec<(MergerReader, bool)>,
    /// The sample's instance, when a door needed it.
    key: [u8; 16],
    /// The producer turn of a GROUP Publisher's merger (see
    /// `TopicMerger::group_producer`), held from admission to the end of the
    /// push: its rings are single-producer, and the Publisher's coordinator
    /// pushes from whichever thread completed the set.
    control: C,
}

/// The instances a DataWriter holds registered/// The instances a DataWriter holds registered, key hash to serialized key
/// (`DataWriter::written_instances`): written, and not unregistered since.
/// The instances a writer has written: key hash -> the serialized key, with
/// the CDR version it was encoded at (the one its K payload must announce).
pub(crate) type WriterInstances =
    std::sync::Mutex<std::collections::HashMap<[u8; 16], (crate::dds::CdrVersion, Vec<u8>)>>;

/// The writer a [`TopicMerger`] belongs to, as a reader in this process
/// sees it: its identity and OWNERSHIP_STRENGTH, which an EXCLUSIVE reader
/// arbitrates, and the instances it holds, which every reader asks before
/// it declares an instance without writers.
#[derive(Clone, Debug)]
pub(crate) struct MergerWriter {
    pub(crate) guid: [u8; 16],
    pub(crate) strength: i32,
    pub(crate) instances: std::sync::Weak<WriterInstances>,
}

/// How many [`TopicMerger`]s were ever freed in this process. A writer's
/// merger lives exactly as long as the writer, so a reader that tracks local
/// writers compares this to the value it last swept at, one atomic load per
/// admission, instead of asking each writer whether it is still alive.
static MERGERS_FREED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// See [`MERGERS_FREED`].
#[must_use]
pub(crate) fn mergers_freed() -> u64 {
    MERGERS_FREED.load(Ordering::Acquire)
}

/// Reader registration stored by the [`TopicMerger`].
///
/// Holds the reader ring together with a notification callback that is invoked
/// whenever new data becomes available. The callback is typically responsible for
/// updating the associated `StatusCondition` so higher layers (WaitSet) can wake
/// immediately without polling.
pub struct MergerReader {
    coherent: Arc<CoherentReaderState>,
    ring: Arc<IndexRing>,
    on_data: Arc<dyn Fn() + Send + Sync>,
    /// Per-registration content filter, `None` for a reader without a
    /// ContentFilteredTopic. Consulted by `push()` and by the late-joiner
    /// replay before any ring push; the unfiltered case costs the push
    /// path one branch per active registration.
    filter: Option<SampleFilter>,
    /// Per-registration ownership gate, `None` unless the reader is
    /// EXCLUSIVE (see [`SampleGate`]).
    gate: Option<SampleGate>,
    /// `filter.is_some() || gate.is_some() || counting`, so the unchecked
    /// case stays one branch on the push path.
    checked: bool,
    /// Delivery observer (the reader's `on_data_available` for this
    /// intra-process path), `None` for a registration nobody observes.
    observer: Option<Arc<DeliveryObserver>>,
    /// The reader's history (see [`ReaderDoor`]); `None` keeps the lossy
    /// push.
    door: Option<Arc<dyn ReaderDoor>>,
    /// `door` takes room for every sample ([`ReaderDoor::counts`]).
    counting: bool,
    /// `door` needs each sample's instance ([`ReaderDoor::needs_instance`]).
    needs_instance: bool,
    /// `counting` with no content filter and no ownership gate: a sample
    /// goes to this reader once its door took room for it.
    counting_only: bool,
    /// Tombstone flag. Inline `OnceLock` slots cannot be vacated, so a
    /// dropped reader is deactivated in place: `push()` skips it with a
    /// single Relaxed load and `reader_count()` no longer counts it.
    active: AtomicBool,
    /// Reliable local pairing, settled only after committed admission.
    ack: Option<Arc<LocalReaderAck>>,
    ack_identity: Option<([u8; 16], bool)>,
}

/// Shared tracking for cloned registrations and deferred coherent replay.
/// Keeping the identity here leaves the inline registration's hot layout
/// unchanged; ordinary inline delivery never dereferences this state.
struct CoherentReaderState {
    id: ReaderId,
    active: AtomicBool,
    /// Last coherent writer SN delivered, plus one.
    through: std::sync::atomic::AtomicU64,
    /// Snapshots that must precede newer live data.
    replay_pending: AtomicUsize,
}

impl Clone for MergerReader {
    fn clone(&self) -> Self {
        Self {
            coherent: Arc::clone(&self.coherent),
            ring: Arc::clone(&self.ring),
            on_data: Arc::clone(&self.on_data),
            filter: self.filter.clone(),
            gate: self.gate.clone(),
            checked: self.checked,
            observer: self.observer.clone(),
            door: self.door.clone(),
            counting: self.counting,
            needs_instance: self.needs_instance,
            counting_only: self.counting_only,
            active: AtomicBool::new(self.active.load(Ordering::Relaxed)),
            ack: self.ack.clone(),
            ack_identity: self.ack_identity,
        }
    }
}

/// Only the state needed while waiting for reader room. Keeping this by
/// value makes ordinary backpressure allocation-free.
pub(crate) struct BlockedReader {
    ring: Arc<IndexRing>,
    door: Option<Arc<dyn ReaderDoor>>,
    active: Arc<CoherentReaderState>,
    counting: bool,
    needs_instance: bool,
    ordering: Option<(u64, u64)>,
}

impl BlockedReader {
    fn new(reader: &MergerReader, ordering: Option<(u64, u64)>) -> Self {
        Self {
            ring: Arc::clone(&reader.ring),
            door: reader.door.clone(),
            active: Arc::clone(&reader.coherent),
            counting: reader.counting,
            needs_instance: reader.needs_instance,
            ordering,
        }
    }

    pub(crate) fn retry_when_room(
        self,
        entry: IndexEntry,
        key: [u8; 16],
        retry: Arc<dyn Fn() + Send + Sync>,
    ) {
        if let Some(door) = &self.door {
            let supply = || Some(key);
            let mut resolved = ResolvedKey::new(&supply);
            door.retry_when_room(retry, &mut || self.still_blocked(&entry, &mut resolved));
        }
    }

    fn still_blocked(&self, entry: &IndexEntry, key: &mut ResolvedKey<'_>) -> bool {
        if !self.active.active.load(Ordering::Acquire) {
            return false;
        }
        if self.counting && entry.lifecycle_bits() == 0 {
            if let Some(door) = &self.door {
                let instance = if self.needs_instance { key.get() } else { None };
                let room = match self.ordering {
                    Some((publisher, gsn)) => {
                        door.has_room_ordered(entry, instance, publisher, gsn)
                    }
                    None => door.has_room(entry, instance),
                };
                if !room {
                    return true;
                }
            }
        }
        self.ring.is_full()
    }
}

impl MergerReader {
    /// Construct a new [`MergerReader`] that takes every sample.
    #[must_use]
    pub fn new(ring: Arc<IndexRing>, on_data: Arc<dyn Fn() + Send + Sync>) -> Self {
        let id = ReaderId::from_ring(&ring);
        Self {
            coherent: Arc::new(CoherentReaderState {
                id,
                active: AtomicBool::new(true),
                through: std::sync::atomic::AtomicU64::new(0),
                replay_pending: AtomicUsize::new(0),
            }),
            ring,
            on_data,
            filter: None,
            gate: None,
            checked: false,
            observer: None,
            door: None,
            counting: false,
            needs_instance: false,
            counting_only: false,
            active: AtomicBool::new(true),
            ack: None,
            ack_identity: None,
        }
    }

    /// Construct a registration whose deliveries are gated by `filter`
    /// (`None` behaves exactly like [`MergerReader::new`]).
    #[must_use]
    pub fn with_filter(
        ring: Arc<IndexRing>,
        on_data: Arc<dyn Fn() + Send + Sync>,
        filter: Option<SampleFilter>,
    ) -> Self {
        Self {
            checked: filter.is_some(),
            filter,
            ..Self::new(ring, on_data)
        }
    }

    /// The same registration, its deliveries also gated by `gate` (`None`
    /// leaves it as it is).
    #[must_use]
    pub(crate) fn gated(self, gate: Option<SampleGate>) -> Self {
        Self {
            checked: self.checked || gate.is_some(),
            gate,
            ..self
        }
    }

    /// The same registration, its deliveries also observed by `observer`.
    #[must_use]
    pub(crate) fn observed(self, observer: Option<Arc<DeliveryObserver>>) -> Self {
        Self { observer, ..self }
    }

    /// The same registration, its HISTORY and RESOURCE_LIMITS kept by the
    /// reader's `door` (see [`ReaderDoor`]) instead of a lossy push.
    #[must_use]
    pub(crate) fn with_door(self, door: Option<Arc<dyn ReaderDoor>>) -> Self {
        let counting = door.as_ref().is_some_and(|door| door.counts());
        let needs_instance = door.as_ref().is_some_and(|door| door.needs_instance());
        Self {
            checked: self.checked || counting,
            counting_only: counting && self.filter.is_none() && self.gate.is_none(),
            door,
            counting,
            needs_instance,
            ..self
        }
    }

    pub(crate) fn with_ack_identity(self, identity: Option<([u8; 16], bool)>) -> Self {
        Self {
            ack_identity: identity,
            ..self
        }
    }

    #[cfg(test)]
    pub(crate) fn acknowledging(self, ack: Option<Arc<LocalReaderAck>>) -> Self {
        Self { ack, ..self }
    }

    #[inline]
    fn acknowledge(&self, seq: u32) {
        if let Some(ack) = &self.ack {
            ack.acknowledge(u64::from(seq));
        }
    }

    /// The observation of this registration, `None` when it takes no part
    /// in a GROUP access bracket (see [`ReaderDoor::bracket_depth`]).
    fn bracket_depth(&self) -> Option<u32> {
        self.door.as_ref().and_then(|door| door.bracket_depth())
    }

    /// The observer to call for `entry` once it is delivered, if one is
    /// armed and `entry` is a sample (not a lifecycle change).
    #[inline]
    fn armed_observer(&self, entry: &IndexEntry) -> Option<&Arc<DeliveryObserver>> {
        match &self.observer {
            Some(observer) if observer.armed() && entry.lifecycle_bits() == 0 => Some(observer),
            _ => None,
        }
    }

    /// The first step of a delivery to this registration, before anything
    /// is pushed anywhere (see [`TopicMerger::admit`]): the content filter,
    /// room in the reader's history, room in the ring.
    ///
    /// The hot path (no filter, no door that counts, room in the ring)
    /// is two flag tests and the ring's room check.
    #[inline]
    fn admit<const SELECTED: bool, const CONTROLLED: bool>(
        &self,
        entry: &IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        may_wait: bool,
        ordering: Option<(u64, u64)>,
    ) -> Step {
        if !SELECTED && self.checked && !self.passes_filter(entry, pool) {
            return Step::Irrelevant;
        }
        let reserved = self.counting && entry.lifecycle_bits() == 0;
        if reserved {
            if let Err(step) = self.reserve::<CONTROLLED>(entry, key, may_wait, ordering) {
                return step;
            }
        }
        if !self.ring.is_full() {
            return Step::Admit { reserved };
        }
        self.admit_into_full_ring::<SELECTED>(entry, key, may_wait, reserved)
    }

    /// Room in the reader's history for one more sample (a door that
    /// counts), or what to do without it.
    #[cold]
    #[inline(never)]
    fn reserve<const CONTROLLED: bool>(
        &self,
        entry: &IndexEntry,
        key: &mut ResolvedKey<'_>,
        may_wait: bool,
        ordering: Option<(u64, u64)>,
    ) -> Result<(), Step> {
        let Some(door) = self.door.as_ref() else {
            return Ok(());
        };
        let instance = if self.needs_instance { key.get() } else { None };
        let reserved = if CONTROLLED {
            match ordering {
                Some((publisher, gsn)) => door.reserve_ordered(entry, instance, publisher, gsn),
                None => door.reserve(entry, instance),
            }
        } else {
            door.reserve(entry, instance)
        };
        match reserved {
            Ok(used) => {
                if self.needs_instance {
                    key.used = used;
                }
                Ok(())
            }
            Err(why) if may_wait && door.waits() => {
                let _ = why;
                Err(Step::Blocked)
            }
            Err(why) => {
                door.rejected(why, instance);
                Err(Step::Skip)
            }
        }
    }

    /// [`admit`](Self::admit) into a full ring: the reader's history drops
    /// what it no longer keeps; a ring still full makes a RELIABLE reader's
    /// writer wait, and is a lost sample for any other.
    #[cold]
    #[inline(never)]
    fn admit_into_full_ring<const SELECTED: bool>(
        &self,
        entry: &IndexEntry,
        key: &mut ResolvedKey<'_>,
        may_wait: bool,
        reserved: bool,
    ) -> Step {
        let Some(door) = self.door.as_ref() else {
            return Step::Skip;
        };
        let instance = if entry.lifecycle_bits() == 0 {
            key.get()
        } else {
            None
        };
        if door.make_room(&self.ring, entry, instance) {
            return Step::Admit { reserved };
        }
        if reserved {
            door.cancel(key.used);
        }
        if may_wait && door.waits() && (SELECTED || entry.lifecycle_bits() == 0) {
            Step::Blocked
        } else {
            if entry.lifecycle_bits() == 0 {
                door.rejected(NoRoom::Samples, instance);
            }
            Step::Skip
        }
    }

    /// Whether a writer blocked on this registration must keep waiting: no
    /// room in the reader's history or none in the ring. Runs under the
    /// door's wait lock: no consumer gate is taken here, and nothing is
    /// given back (which would wake under that lock).
    fn still_blocked(
        &self,
        entry: &IndexEntry,
        key: &mut ResolvedKey<'_>,
        ordering: Option<(u64, u64)>,
    ) -> bool {
        if !self.is_active() {
            return false;
        }
        if self.counting && entry.lifecycle_bits() == 0 {
            if let Some(door) = self.door.as_ref() {
                let instance = if self.needs_instance { key.get() } else { None };
                let room = match ordering {
                    Some((publisher, floor)) => {
                        door.has_room_ordered(entry, instance, publisher, floor)
                    }
                    None => door.has_room(entry, instance),
                };
                if !room {
                    return true;
                }
            }
        }
        self.ring.is_full()
    }

    /// Give back the room [`admit`](Self::admit) took in the reader's
    /// history for a sample that is not pushed.
    #[cold]
    fn cancel(&self, key: [u8; 16]) {
        if let Some(door) = self.door.as_ref() {
            door.cancel(key);
        }
    }

    /// The content filter's verdict (`checked` registrations only). A
    /// lifecycle change (a local dispose or unregister) carries a key hash,
    /// not a sample: there is nothing for a content filter to test, and
    /// running it over the key bytes as if they were one dropped the
    /// transition. The network path queues transitions unfiltered too.
    fn passes_filter(&self, entry: &IndexEntry, pool: &SlabPool) -> bool {
        match &self.filter {
            Some(filter) if entry.lifecycle_bits() == 0 => {
                self.with_payload(entry, pool, |bytes| filter(bytes, entry.cdr_version))
            }
            _ => true,
        }
    }

    /// The ownership gate's verdict, asked once the push that follows
    /// cannot fail (see [`TopicMerger::deliver`]).
    ///
    /// The ownership gate RECORDS what it admits: an EXCLUSIVE reader's
    /// registrations (who holds each instance, who owns it). So it is asked
    /// only when the push that follows cannot fail: an admitted entry has
    /// room in the ring, and the ring has one producer, the push after this
    /// call. Otherwise an unregister the ring refused would be recorded as
    /// delivered, and the writer's deletion, which leaves without writers
    /// only the instances it still holds, would announce nothing for it. Under
    /// EXCLUSIVE ownership only the owner's dispose moves the instance: the
    /// gate sees lifecycle changes too.
    #[inline]
    fn passes_gate(&self, entry: &IndexEntry, pool: &SlabPool, key: &mut ResolvedKey<'_>) -> bool {
        match &self.gate {
            None => true,
            Some(gate) => {
                let key = if entry.lifecycle_bits() == 0 {
                    key.get()
                } else {
                    None
                };
                self.with_payload(entry, pool, |bytes| gate(entry, bytes, key))
            }
        }
    }

    /// Run `check` (the content filter or the ownership gate) over the
    /// entry's payload bytes.
    ///
    /// The caller must hold a live reference on `entry.handle` (the
    /// push guard, or the replay reference), which is what makes the slab
    /// read sound. `try_borrow` is `None` only for the Heap tier, whose
    /// storage lives behind the pool mutex and is copied out through
    /// `get_buffer`, the same split the reader pump uses to decode.
    ///
    /// Merger entries carry no GUID prefix, but the same prefix split as
    /// the reader pump is applied (a write with an explicit source
    /// timestamp carries a reception-time prefix); a prefixed entry too
    /// short to hold its prefix is rejected rather than handed to the
    /// check as sample bytes.
    ///
    /// The check is caller-supplied code running on the WRITER's thread:
    /// a panic inside it is caught and counts as a rejection, so no
    /// unwind can escape `push()` or the replay loop with a slab
    /// reference still owed.
    #[inline(never)]
    fn with_payload(
        &self,
        entry: &IndexEntry,
        pool: &SlabPool,
        check: impl Fn(&[u8]) -> bool,
    ) -> bool {
        let data_len = entry.len as usize;
        let payload_start = entry.payload_offset();
        if data_len < payload_start {
            return false;
        }
        // An entry whose `len` overruns its slot is malformed: reject it
        // instead of indexing past the buffer.
        let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match pool.try_borrow(entry.handle) {
                Some(buf) => buf.get(payload_start..data_len).is_some_and(&check),
                None => {
                    let buf = pool.get_buffer(entry.handle);
                    buf.get(payload_start..data_len).is_some_and(&check)
                }
            }
        }));
        verdict.unwrap_or_else(|_| {
            log::error!(
                "[TopicMerger] content filter or ownership gate panicked for reader {:?}; \
                 entry rejected",
                self.coherent.id
            );
            false
        })
    }

    /// Get the reader's unique identifier
    #[must_use]
    pub fn id(&self) -> ReaderId {
        self.coherent.id
    }

    /// Access the underlying ring buffer.
    #[must_use]
    pub fn ring(&self) -> &Arc<IndexRing> {
        &self.ring
    }

    /// Whether this registration is live (not tombstoned).
    ///
    /// Relaxed load: the flag carries no data dependency; a push racing
    /// a concurrent tombstone at worst delivers one extra entry to the
    /// dead ring, as if it had landed just before the tombstone.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Tombstone this registration (only under the merger write guard).
    fn deactivate(&self) {
        self.active.store(false, Ordering::Relaxed);
        self.coherent.active.store(false, Ordering::Release);
        if let Some(ack) = &self.ack {
            ack.depart();
        }
    }

    /// Invoke the notification callback.
    fn notify(&self) {
        (self.on_data)();
    }
}

/// TopicMerger: Fan-out from writer ring to N reader rings
///
/// Simple dispatcher that clones [`IndexEntry`] to all registered readers.
/// Non-blocking. A full reader ring asks the reader's history to drop what
/// it no longer keeps ([`ReaderDoor`]); a ring that still has no room, or
/// that of a registration without a door, skips the entry.
///
/// # Performance
/// - Target: < 100 ns per push (N readers x 50 ns ring push)
/// - First `INLINE_READERS` readers dispatched lock-free (no RwLock in hot path)
///
/// # Late-Joiner Support (v0.5.0+)
/// - If `durability_state` is `Some`, `add_reader()` replays historical samples
/// - Supports TRANSIENT_LOCAL and PERSISTENT durability for late-joiner delivery
pub struct TopicMerger {
    /// Lock-free inline slots for the first `INLINE_READERS` readers.
    /// Append-only: slots are set once under the `overflow_readers` write
    /// guard and never vacated. A removed reader is tombstoned in place
    /// (`MergerReader::active = false`) and its slot is never reused; a
    /// re-registration goes to the next free slot or overflow.
    inline_readers: [OnceLock<MergerReader>; INLINE_READERS],
    /// Number of fully initialized inline slots, tombstones included
    /// (Release-published after each slot set; Acquire-loaded by the
    /// fan-out push path).
    inline_published: AtomicUsize,
    /// Readers beyond the inline capacity (rare). The write guard also
    /// serializes ALL mutations, including inline slot registration and
    /// tombstoning.
    overflow_readers: RwLock<Vec<MergerReader>>,
    /// Cached ACTIVE reader count (inline + overflow, tombstones
    /// excluded), updated under the write guard at every mutation. Lets
    /// `reader_count()` answer with a single atomic load instead of
    /// taking the RwLock read guard.
    reader_count_cache: AtomicUsize,
    /// Number of ACTIVE overflow readers, updated under the write guard.
    /// Gates the overflow read-lock excursion in `push()`:
    /// `reader_count_cache` counts active readers while `inline_published`
    /// includes tombstones, so comparing those two can no longer detect
    /// live overflow readers once an inline slot is tombstoned.
    overflow_active: AtomicUsize,
    /// Sole-active-reader designation: inline slot index + 1 when
    /// EXACTLY one registration is active (inline + overflow, tombstones
    /// excluded) and it lives in an inline slot; 0 otherwise. Written
    /// under the write guard at every mutation (Release), read with one
    /// Acquire load by `push()` to select the EXCLUSIVE transfer path.
    ///
    /// Keyed on ACTIVE registrations rather than on `inline_published`
    /// because tombstoned slots are never reused: gating the fast path
    /// on the published count would lose it forever after the first
    /// reader churn on a writer (drop + re-create is normal operation
    /// for rmw layers), and every later sample would pay the fan-out
    /// refcount round trip for a single live reader.
    sole_reader: AtomicUsize,
    /// Optional history cache + slab pool for TRANSIENT_LOCAL/PERSISTENT durability
    durability_state: Option<(Arc<HistoryCache>, Arc<SlabPool>)>,
    /// The writer this merger belongs to, set once by the writer's builder
    /// before any reader binds (see [`MergerWriter`]).
    writer: OnceLock<MergerWriter>,
    /// Wakes the coherent group coordinator of the writer's Publisher (see
    /// [`TopicMerger::set_local_group_wake`]) when a bound reader's access
    /// bracket ends. It holds the coordinator weakly: the coordinator holds
    /// the merger.
    local_group: OnceLock<Arc<dyn Fn() + Send + Sync>>,
    /// Further bracket-end wakes, one per writer whose queue holds back a
    /// set of this topic (`IntraCoherentSets::follow_brackets`). Held weakly:
    /// the writer's queue owns its wake, and a dropped writer's wake is pruned.
    local_wakes: std::sync::Mutex<Vec<std::sync::Weak<dyn Fn() + Send + Sync>>>,
    /// Producer turn for a coherent Publisher's merger: ordinary writes
    /// and set publication may run on different threads. Never armed for
    /// non-coherent writers, whose hot path only checks this OnceLock.
    /// No application callback runs while the turn is held.
    group_producer: OnceLock<LocalProducer>,
    ordered_pairing: bool,
    coherent_replay: std::sync::Mutex<Vec<CoherentReplay>>,
    acknowledgments: OnceLock<LocalAckWriter>,
    pairing: parking_lot::RwLock<()>,
    #[cfg(test)]
    before_reader_publish: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    before_local_delivery: std::sync::Mutex<Option<DeliveryHook>>,
}

impl TopicMerger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inline_readers: [const { OnceLock::new() }; INLINE_READERS],
            inline_published: AtomicUsize::new(0),
            overflow_readers: RwLock::new(Vec::new()),
            reader_count_cache: AtomicUsize::new(0),
            overflow_active: AtomicUsize::new(0),
            sole_reader: AtomicUsize::new(0),
            durability_state: None,
            writer: OnceLock::new(),
            local_group: OnceLock::new(),
            local_wakes: std::sync::Mutex::new(Vec::new()),
            group_producer: OnceLock::new(),
            ordered_pairing: false,
            coherent_replay: std::sync::Mutex::new(Vec::new()),
            acknowledgments: OnceLock::new(),
            pairing: parking_lot::RwLock::new(()),
            #[cfg(test)]
            before_reader_publish: std::sync::Mutex::new(None),
            #[cfg(test)]
            before_local_delivery: std::sync::Mutex::new(None),
        }
    }

    /// Create merger with TRANSIENT_LOCAL/PERSISTENT durability support
    ///
    /// Enables automatic historical data delivery to late-joining readers.
    #[must_use]
    pub fn with_history(cache: Arc<HistoryCache>, slab_pool: Arc<SlabPool>) -> Self {
        Self {
            inline_readers: [const { OnceLock::new() }; INLINE_READERS],
            inline_published: AtomicUsize::new(0),
            overflow_readers: RwLock::new(Vec::new()),
            reader_count_cache: AtomicUsize::new(0),
            overflow_active: AtomicUsize::new(0),
            sole_reader: AtomicUsize::new(0),
            durability_state: Some((cache, slab_pool)),
            writer: OnceLock::new(),
            local_group: OnceLock::new(),
            local_wakes: std::sync::Mutex::new(Vec::new()),
            group_producer: OnceLock::new(),
            ordered_pairing: false,
            coherent_replay: std::sync::Mutex::new(Vec::new()),
            acknowledgments: OnceLock::new(),
            pairing: parking_lot::RwLock::new(()),
            #[cfg(test)]
            before_reader_publish: std::sync::Mutex::new(None),
            #[cfg(test)]
            before_local_delivery: std::sync::Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn pause_local_delivery(&self, hook: DeliveryHook) {
        *self
            .before_local_delivery
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(hook);
    }

    #[cfg(test)]
    fn before_delivery(&self, seq: u32) {
        let hook = self
            .before_local_delivery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(hook) = hook {
            hook(seq);
        }
    }

    pub(crate) fn set_acknowledgments(&self, writer: LocalAckWriter) {
        let _ = self.acknowledgments.set(writer);
    }

    /// Pairing captures the committed watermark and publishes membership
    /// atomically against a write's admission and commit. Recursive reads
    /// let a Publisher finish its control while a writer already holds an
    /// admission, even when a new pairing is waiting for the write lock.
    #[inline]
    pub(crate) fn pairing_plain(&self) -> Option<parking_lot::RwLockReadGuard<'_, ()>> {
        self.acknowledgments
            .get()
            .map(|_| self.pairing.read_recursive())
    }

    pub(crate) fn pairing(&self) -> Option<parking_lot::RwLockReadGuard<'_, ()>> {
        (self.acknowledgments.get().is_some() || self.ordered_pairing)
            .then(|| self.pairing.read_recursive())
    }

    pub(crate) fn with_ordered_pairing(mut self, enabled: bool) -> Self {
        self.ordered_pairing = enabled;
        self
    }

    pub(crate) fn set_local_publisher(&self, publisher: u64) {
        let _ = self
            .group_producer
            .get_or_init(LocalProducer::default)
            .publisher
            .set(publisher);
    }

    pub(crate) fn reserve_order(
        &self,
        publisher: u64,
        gsn: u64,
        seq: u64,
        coherent: bool,
    ) -> PendingOrders {
        let producer = self.group_producer.get_or_init(LocalProducer::default);
        let lease = Arc::new(PendingOrderLease {
            publisher,
            gsn,
            seq,
            coherent,
            state: Default::default(),
        });
        // Registration takes this registry before its overflow publication.
        // Either its door is already visible here, or it extends this lease
        // before publishing that door. No pairing read occurs under the
        // Publisher's set lock.
        let mut pending = producer.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|weak| {
            weak.upgrade()
                .is_some_and(|lease| !lease.state.lock().unwrap_or_else(|e| e.into_inner()).closed)
        });
        pending.push(Arc::downgrade(&lease));
        for reader in self.readers_snapshot() {
            if let Some(door) = reader.door {
                lease.extend(door);
            }
        }
        drop(pending);
        PendingOrders(Some(lease))
    }

    pub(crate) fn commit_order(&self, seq: u64) {
        let Some(producer) = self.group_producer.get() else {
            return;
        };
        let mut pending = producer.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|weak| {
            let Some(lease) = weak.upgrade() else {
                return false;
            };
            let mut state = lease.state.lock().unwrap_or_else(|e| e.into_inner());
            if lease.seq == seq {
                state.committed = true;
            }
            !state.closed
        });
    }

    #[cfg(test)]
    pub(crate) fn with_pending_orders_locked_for_test<R>(&self, inspect: impl FnOnce() -> R) -> R {
        let producer = self.group_producer.get_or_init(LocalProducer::default);
        let _pending = producer.pending.lock().unwrap_or_else(|e| e.into_inner());
        inspect()
    }

    pub(crate) fn set_local_order(&self, order: std::sync::Weak<dyn LocalDeliveryOrder>) {
        let _ = self
            .group_producer
            .get_or_init(LocalProducer::default)
            .order
            .set(order);
    }

    #[cfg(test)]
    pub(crate) fn pause_reader_publication(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .before_reader_publish
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(hook);
    }

    /// A wire-only control completes locally without a ring entry. The
    /// pairing retains holes for any earlier data still awaiting admission.
    pub(crate) fn acknowledge_control(&self, seq: u64) {
        let Some(writer) = self.acknowledgments.get() else {
            return;
        };
        // The consumed control is complete locally even if its optional
        // wire replay journal could not retain it. Late matches skip it.
        writer.cache.record_local_commit(seq);
        let _pairing = self.pairing();
        let overflow = recover_read(&self.overflow_readers, "TopicMerger::acknowledge_control");
        let n = self
            .inline_published
            .load(Ordering::Acquire)
            .min(INLINE_READERS);
        for reader in self.inline_readers[..n]
            .iter()
            .filter_map(OnceLock::get)
            .chain(overflow.iter())
        {
            if reader.is_active() {
                if let Some(ack) = &reader.ack {
                    ack.acknowledge(seq);
                }
            }
        }
    }

    /// Name the writer this merger belongs to. The first call wins.
    pub(crate) fn set_writer(&self, writer: MergerWriter) {
        let _ = self.writer.set(writer);
    }

    /// Name the coherent group coordinator of the writer's Publisher (see
    /// `dds::writer::local_group`): it is woken when a reader's access
    /// bracket ends, so a group it held back reaches the reader before the
    /// next bracket's first read. Set once, before any reader binds.
    pub(crate) fn set_local_group_wake(&self, wake: Arc<dyn Fn() + Send + Sync>) {
        let _ = self.local_group.set(wake);
        self.enable_coherent_producer();
    }

    #[inline]
    pub(crate) fn has_local_delivery_control(&self) -> bool {
        self.group_producer.get().is_some()
    }

    pub(crate) fn enable_coherent_producer(&self) {
        self.group_producer
            .get_or_init(LocalProducer::default)
            .turn
            .get_or_init(|| parking_lot::ReentrantMutex::new(()));
    }

    #[cfg(test)]
    pub(crate) fn coherent_producer_enabled(&self) -> bool {
        self.group_producer
            .get()
            .is_some_and(|control| control.turn.get().is_some())
    }

    /// The producer turn of a coherent Publisher's merger. Taken by
    /// [`admit`](Self::admit) and held to the end of the push.
    #[inline]
    fn producer_turn(&self) -> Option<parking_lot::ReentrantMutexGuard<'_, ()>> {
        self.group_producer
            .get()?
            .turn
            .get()
            .map(parking_lot::ReentrantMutex::lock)
    }

    /// A reader bound to this merger left a coherent-access bracket: let
    /// the writer's Publisher deliver what it held back.
    pub(crate) fn wake_local_group(&self) {
        if let Some(wake) = self.local_group.get() {
            wake();
        }
        let wakes: Vec<_> = {
            let mut wakes = self.local_wakes.lock().unwrap_or_else(|e| e.into_inner());
            wakes.retain(|wake| wake.strong_count() > 0);
            wakes.iter().filter_map(std::sync::Weak::upgrade).collect()
        };
        for wake in wakes {
            wake();
        }
    }

    /// Register a writer's bracket-end wake (held weakly, see `local_wakes`).
    pub(crate) fn register_local_wake(&self, wake: &Arc<dyn Fn() + Send + Sync>) {
        self.local_wakes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::downgrade(wake));
    }

    pub(crate) fn has_pending_replay(&self, id: ReaderId) -> bool {
        let pending = |reader: &MergerReader| {
            reader.id() == id && reader.coherent.replay_pending.load(Ordering::Acquire) != 0
        };
        let n = self
            .inline_published
            .load(Ordering::Acquire)
            .min(INLINE_READERS);
        if self.inline_readers[..n]
            .iter()
            .filter_map(OnceLock::get)
            .any(pending)
        {
            return true;
        }
        self.overflow_active.load(Ordering::Acquire) != 0
            && recover_read(&self.overflow_readers, "pending local replay")
                .iter()
                .any(pending)
    }

    pub(crate) fn has_any_pending_replay(&self) -> bool {
        let pending = |reader: &MergerReader| {
            reader.is_active() && reader.coherent.replay_pending.load(Ordering::Acquire) != 0
        };
        let n = self
            .inline_published
            .load(Ordering::Acquire)
            .min(INLINE_READERS);
        self.inline_readers[..n]
            .iter()
            .filter_map(OnceLock::get)
            .any(pending)
            || (self.overflow_active.load(Ordering::Acquire) != 0
                && recover_read(&self.overflow_readers, "pending local stream replay")
                    .iter()
                    .any(pending))
    }

    /// Whether any active registration reads under a coherent-access
    /// bracket, and whether one of them is inside a bracket now.
    #[must_use]
    pub(crate) fn coherent_brackets(&self) -> (bool, bool) {
        let overflow = recover_read(&self.overflow_readers, "TopicMerger::coherent_brackets");
        let n = self
            .inline_published
            .load(Ordering::Acquire)
            .min(INLINE_READERS);
        let mut gated = false;
        let mut held = false;
        for reader in self.inline_readers[..n]
            .iter()
            .filter_map(OnceLock::get)
            .chain(overflow.iter())
        {
            if !reader.is_active() {
                continue;
            }
            if let Some(depth) = reader.bracket_depth() {
                gated = true;
                held |= depth > 0;
            }
        }
        (gated, held)
    }

    /// The writer this merger belongs to, if its builder named it.
    #[must_use]
    pub(crate) fn writer(&self) -> Option<MergerWriter> {
        self.writer.get().cloned()
    }

    /// Inline slot index of the cached sole-active-reader designation,
    /// `None` when the fast path is disabled (zero, several, or an
    /// overflow-only active reader). Test hook for pinning the
    /// designation state machine; `push()` reads the raw atomic.
    #[cfg(test)]
    fn sole_inline_slot(&self) -> Option<usize> {
        self.sole_reader.load(Ordering::Acquire).checked_sub(1)
    }

    /// Scan the published inline slots for an ACTIVE `reader_id`
    /// (lock-free). Tombstoned registrations are treated as absent so a
    /// reader that re-registers the same ring after removal is accepted
    /// again (its previous slot stays inactive, so delivery is single).
    fn inline_contains(&self, reader_id: ReaderId) -> bool {
        let n = self
            .inline_published
            .load(Ordering::Acquire)
            .min(INLINE_READERS);
        self.inline_readers[..n]
            .iter()
            .filter_map(OnceLock::get)
            .any(|r| r.is_active() && r.id() == reader_id)
    }

    /// Recompute the active-count caches and the sole-active-reader
    /// designation from the current registration state. Must be called
    /// under the `overflow_readers` write guard.
    fn refresh_counts(&self, overflow: &[MergerReader]) {
        let n = self
            .inline_published
            .load(Ordering::Relaxed)
            .min(INLINE_READERS);
        let mut inline_active = 0usize;
        let mut last_active_slot = 0usize;
        for (idx, slot) in self.inline_readers[..n].iter().enumerate() {
            if slot.get().is_some_and(MergerReader::is_active) {
                inline_active += 1;
                last_active_slot = idx + 1;
            }
        }
        let overflow_active = overflow.iter().filter(|r| r.is_active()).count();
        // Overflow readers stay on the fan-out path: the designation
        // names an inline slot only, so a lone overflow reader (16
        // tombstones ahead of it) is refcounted, never EXCLUSIVE.
        let sole = if inline_active == 1 && overflow_active == 0 {
            last_active_slot
        } else {
            0
        };
        self.overflow_active
            .store(overflow_active, Ordering::Release);
        self.reader_count_cache
            .store(inline_active + overflow_active, Ordering::Release);
        self.sole_reader.store(sole, Ordering::Release);
    }

    /// Register reader ring (called during matching)
    ///
    /// Takes write lock briefly (cold path).
    ///
    /// # Idempotence
    /// If an ACTIVE reader with the same ID is already registered, this is
    /// a no-op. Returns `true` if the reader was newly added, `false` if
    /// already present. Tombstoned registrations do not count as present:
    /// a reader that re-registers the same ring after removal gets a fresh
    /// slot (tombstoned slots are never reused).
    ///
    /// # Late-Joiner Delivery (v0.5.0+)
    /// If TRANSIENT_LOCAL/PERSISTENT durability is enabled, automatically pushes
    /// all historical samples from the cache to the new reader's ring.
    pub fn add_reader(&self, mut reader: MergerReader) -> bool {
        let _notices = crate::dds::LocalDelivery::enter();
        let _pairing = (self.acknowledgments.get().is_some() || self.ordered_pairing)
            .then(|| self.pairing.write());
        let reader_id = reader.id();

        // Check for duplicate (idempotence)
        {
            let overflow = recover_read(
                &self.overflow_readers,
                "TopicMerger::add_reader overflow_readers.read()",
            );
            if self.inline_contains(reader_id)
                || overflow
                    .iter()
                    .any(|r| r.is_active() && r.id() == reader_id)
            {
                log::debug!(
                    "[DEBUG] TopicMerger::add_reader(): Reader {:?} already registered, ignoring duplicate",
                    reader_id
                );
                return false;
            }
        }

        if let (Some(writer), Some((guid, volatile))) =
            (self.acknowledgments.get(), reader.ack_identity)
        {
            reader.ack = Some(writer.reader(guid, volatile));
        }
        #[cfg(test)]
        {
            let hook = self
                .before_reader_publish
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(hook) = hook {
                hook();
            }
        }

        // Match the history snapshot and registration against live set
        // destination snapshots. A stamped write completing meanwhile
        // must either include this registration or precede its snapshot.
        let _cohort = lock_replay_cohort();
        let mut pending_coherent_replay = Vec::new();
        // Push historical samples if TRANSIENT_LOCAL durability is enabled.
        //
        // Replay refcounting: the snapshot below takes one reference per
        // returned handle UNDER the cache lock (while the cache's own
        // persistent reference is provably live, closing the window
        // where a concurrent eviction frees the slot between snapshot
        // and increment). Each pushed entry hands its pre-taken ref to
        // the reader; every skip/drop path must release it.
        if let Some((cache, slab_pool)) = &self.durability_state {
            let all_samples = cache.snapshot_for_local_replay();
            log::debug!(
                "[DEBUG] TopicMerger::add_reader(): Found {} historical samples in cache",
                all_samples.len()
            );
            let mut replay_observer = None;
            let mut coherent_replay: std::collections::BTreeMap<
                CoherentReplayIdentity,
                CoherentReplay,
            > = std::collections::BTreeMap::new();
            for change in all_samples {
                let (seq, handle, size, cdr_version) =
                    (change.seq, change.slab, change.len, change.cdr_version);
                let seq_u32 = match u32::try_from(seq) {
                    Ok(value) => value,
                    Err(_) => {
                        log::debug!(
                            "[WARN] TopicMerger::add_reader(): historical seq {} exceeds u32 range, skipping",
                            seq
                        );
                        slab_pool.release(handle);
                        continue;
                    }
                };
                let len_u32 = match u32::try_from(size) {
                    Ok(value) => value,
                    Err(_) => {
                        log::debug!(
                            "[WARN] TopicMerger::add_reader(): historical payload {} bytes exceeds u32 range, skipping seq {}",
                            size, seq
                        );
                        slab_pool.release(handle);
                        continue;
                    }
                };
                // The replayed entry must decode the way the live one did:
                // the cache journaled the CDR version the writer encoded
                // with, and a reader (or the content filter below) that
                // honours the version would misread a non-default payload
                // rebuilt with `IndexEntry::new`'s default. Source order
                // and lifespan also require the journaled INFO_TS and its
                // validity, including a genuine epoch timestamp.
                // A lifecycle change in the history (a dispose, an
                // unregister) replays in the form it has live: a ring entry
                // flagged as such that carries the key hash, not the
                // key-only DATA payload the history keeps for the wire.
                // Source time lives beside the shared retained slab in the
                // entry. Replay needs no second payload-sized allocation.
                let (handle, len_u32, lifecycle) = match change.lifecycle {
                    None => (handle, len_u32, 0),
                    Some((status, key_hash)) => {
                        slab_pool.release(handle);
                        let key_bytes = key_hash;
                        let Some((key_slab, _metric)) =
                            slab_pool.reserve_and_write(&key_bytes, Claim::Writer)
                        else {
                            log::debug!(
                                "[WARN] TopicMerger::add_reader(): slab pool exhausted replaying lifecycle seq {}",
                                seq
                            );
                            continue;
                        };
                        (key_slab, 16, u8::from(status))
                    }
                };
                let mut entry = IndexEntry::with_cdr_version(
                    seq_u32,
                    handle,
                    len_u32,
                    change.source_timestamp_ns.unwrap_or(0),
                    cdr_version,
                );
                if change.source_timestamp_ns.is_some() {
                    entry.mark_source_ts();
                }
                entry.mark_local_replay();
                entry.mark_lifecycle(lifecycle);
                // GROUP replay joins all readers already attached at the
                // next access transition, outside the binding locks.
                if reader.bracket_depth().is_some() && self.local_group.get().is_some() {
                    if let Some(identity) = change
                        .group_sn
                        .filter(|_| change.coherent_sn.is_some())
                        .map(CoherentReplayIdentity::Set)
                        .or_else(|| change.gsn.map(CoherentReplayIdentity::Change))
                    {
                        coherent_replay
                            .entry(identity)
                            .or_insert_with(|| CoherentReplay::new(&reader, identity))
                            .members
                            .push(coherent::ReplayMember {
                                _pending_order: self
                                    .group_producer
                                    .get()
                                    .and_then(|producer| producer.publisher.get())
                                    .zip(change.gsn)
                                    .and_then(|(&publisher, gsn)| {
                                        let door = reader.door.as_ref()?;
                                        let token = door.reserve_order(publisher, gsn)?;
                                        Some(PendingOrderReservation {
                                            door: Arc::clone(door),
                                            token,
                                        })
                                    }),
                                coherent_replay_valid: change.coherent_replay_valid,
                                coherent_replay_admission: change.coherent_replay_admission,
                                entry,
                                key: change.key_hash.unwrap_or([0; 16]),
                                gsn: change.gsn,
                            });
                        continue;
                    }
                }
                // A ContentFilteredTopic late joiner is owed only the history
                // that passes its filter; the skipped entry's replay ref goes
                // back like every other skip on this path.
                if reader.checked && !reader.passes_filter(&entry, slab_pool) {
                    reader.acknowledge(entry.seq);
                    slab_pool.release(handle);
                    continue;
                }
                // The history replays into the reader's history like a live
                // sample: it takes room there first. No room is made in a
                // full ring here and no writer waits: the reader binds under
                // its binding table's lock, which a take holds inside its
                // consumer gate, and nothing waits under that lock.
                let replay_key = || change.key_hash;
                let mut key = ResolvedKey::new(&replay_key);
                let reserved = reader.counting && entry.lifecycle_bits() == 0;
                if reserved
                    && reader
                        .reserve::<false>(&entry, &mut key, false, None)
                        .is_err()
                {
                    log::debug!(
                        "[DEBUG] TopicMerger::add_reader(): no room in the reader's history for historical seq {}, dropping it",
                        seq
                    );
                    slab_pool.release(handle);
                    continue;
                }
                // Announced like a live delivery (`DeliveryObserver`), once
                // the binding's locks are released (`observe_later`): its own
                // reference keeps the payload readable past the push.
                let observer = reader.armed_observer(&entry).cloned();
                if observer.is_some() {
                    slab_pool.add_ref(handle);
                }
                // Room seen by the only producer stays until its push.
                let allowed = reader.passes_gate(&entry, slab_pool, &mut key);
                if !allowed {
                    reader.acknowledge(entry.seq);
                }
                if !reader.ring.is_full() && allowed && reader.ring().push(entry) {
                    reader.acknowledge(entry.seq);
                    let on_data = Arc::clone(&reader.on_data);
                    crate::dds::notify_local(move || on_data());
                    if let Some(observer) = observer {
                        observer.observe_later(&entry, slab_pool);
                        replay_observer = Some(observer);
                        slab_pool.release(handle);
                    }
                } else {
                    if observer.is_some() {
                        slab_pool.release(handle);
                    }
                    log::debug!(
                        "[DEBUG] TopicMerger::add_reader(): Reader ring full while replaying seq {}, dropping historical sample",
                        seq
                    );
                    if reserved {
                        reader.cancel(key.used);
                    }
                    slab_pool.release(handle);
                }
            }
            pending_coherent_replay.extend(coherent_replay.into_values());
            if let Some(observer) = replay_observer {
                observer.notify_later();
            }
        } else {
            log::debug!(
                "[DEBUG] TopicMerger::add_reader(): No durability_state, not pushing historical samples"
            );
        }

        let replay_notice =
            (!pending_coherent_replay.is_empty()).then(|| Arc::clone(&reader.on_data));
        // All replay decoding and filtering is finished. Registry then
        // overflow matches reserve_order; tokens precede visible membership.
        let mut order_registry = self
            .group_producer
            .get()
            .map(|producer| producer.pending.lock().unwrap_or_else(|e| e.into_inner()));
        // Register reader for future samples. The overflow write guard
        // serializes ALL mutations, including inline slot registration.
        let mut overflow = recover_write(
            &self.overflow_readers,
            "TopicMerger::add_reader overflow_readers.write()",
        );

        // Double-check after acquiring write lock (race condition protection)
        if self.inline_contains(reader_id)
            || overflow
                .iter()
                .any(|r| r.is_active() && r.id() == reader_id)
        {
            log::debug!(
                "[DEBUG] TopicMerger::add_reader(): Reader {:?} registered by another thread, ignoring",
                reader_id
            );
            return false;
        }

        if let Some(pending) = order_registry.as_mut() {
            pending.retain(|weak| {
                let Some(lease) = weak.upgrade() else {
                    return false;
                };
                if let Some(door) = &reader.door {
                    lease.extend(Arc::clone(door));
                }
                let alive = !lease.state.lock().unwrap_or_else(|e| e.into_inner()).closed;
                alive
            });
        }

        let published = self.inline_published.load(Ordering::Relaxed);
        if published < INLINE_READERS {
            match self.inline_readers[published].set(reader) {
                Ok(()) => {
                    self.inline_published
                        .store(published + 1, Ordering::Release);
                }
                Err(reader) => {
                    // Cannot happen: slot writes are serialized by the write guard.
                    log::debug!(
                        "[WARN] TopicMerger::add_reader(): inline slot {} unexpectedly occupied, using overflow",
                        published
                    );
                    overflow.push(reader);
                }
            }
        } else {
            overflow.push(reader);
        }

        self.refresh_counts(&overflow);
        drop(overflow);
        drop(order_registry);
        // Publish replay only after its target registration is visible.
        self.coherent_replay
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(pending_coherent_replay);

        if let Some(on_data) = replay_notice {
            // Registration and replay debt are published first. The outer
            // delivery scope tells WaitSets after binding/cohort guards go.
            crate::dds::notify_local(move || on_data());
        }

        log::debug!(
            "[DEBUG] TopicMerger::add_reader(): Registered reader {:?}, now have {} active readers",
            reader_id,
            self.reader_count_cache.load(Ordering::Relaxed)
        );
        true
    }

    /// Tombstone a reader registration (called when a `DataReader` drops).
    ///
    /// Inline `OnceLock` slots cannot be vacated, so removal deactivates
    /// the registration in place: `push()` skips it and `reader_count()`
    /// no longer counts it. Tombstoned slots are never reused; a later
    /// `add_reader` with the same or a new id takes the next free inline
    /// slot or overflow as usual.
    ///
    /// Entries still sitting in the tombstoned ring are drained and
    /// their slab references released (each entry carries its own
    /// fan-out reference under the refcount side-table, so this cannot
    /// free slots other readers still reference). The caller
    /// must be (or act for) the ring's consumer: the ring is SPSC and
    /// the pump of a dropping `DataReader` is already dead. A push
    /// in flight past its `is_active` check can still land one entry
    /// after this drain; that single-entry residue is the tombstone race
    /// window (bounded, one entry per racing push).
    ///
    /// The sole-reader designation does not widen that residue: it is
    /// cleared right after the tombstone, under this same guard and
    /// BEFORE the drain, so a push can only reach the dead ring through
    /// the fast path if it loaded the designation before the clear,
    /// which is the same in-flight push the `is_active` window already
    /// admits. Inline `OnceLock` slots are never vacated, so a stale
    /// designation always names a live (tombstoned) registration, never
    /// a dangling one.
    ///
    /// Returns `true` if an active registration was deactivated, `false`
    /// if no active reader with this id exists (idempotent).
    pub fn remove_reader(&self, reader_id: ReaderId, pool: &SlabPool) -> bool {
        // The overflow write guard serializes ALL mutations (same
        // protocol as add_reader), so the count recompute cannot
        // interleave with a concurrent registration.
        let overflow = recover_write(
            &self.overflow_readers,
            "TopicMerger::remove_reader overflow_readers.write()",
        );

        let n = self
            .inline_published
            .load(Ordering::Relaxed)
            .min(INLINE_READERS);
        let target = self.inline_readers[..n]
            .iter()
            .filter_map(OnceLock::get)
            .chain(overflow.iter())
            .find(|r| r.is_active() && r.id() == reader_id);

        let Some(reader) = target else {
            return false;
        };
        reader.deactivate();
        // Drop the fast-path designation together with the tombstone,
        // before the drain below. Between this store and the
        // `refresh_counts` at the end of this call, every push takes
        // the fan-out path (which re-checks `is_active` per slot), so
        // the drain can only be trailed by pushes that were already
        // past their designation load. `refresh_counts` may then
        // designate a remaining single active reader as the new sole;
        // that names a live slot, never the ring drained here.
        self.sole_reader.store(0, Ordering::Release);

        // Return the dead ring's slab references (safe under refcounts).
        // Event entries carry the EMPTY sentinel and no reference.
        while let Some(entry) = reader.ring().pop() {
            if !entry.handle.is_empty() {
                pool.release(entry.handle);
            }
        }

        self.refresh_counts(&overflow);
        log::debug!(
            "[DEBUG] TopicMerger::remove_reader(): Tombstoned reader {:?}, now have {} active readers",
            reader_id,
            self.reader_count_cache.load(Ordering::Relaxed)
        );
        true
    }

    /// Dispatch entry from writer to all readers (non-blocking, lossy).
    ///
    /// CONSUMES the caller's slab reference on `entry.handle` in every
    /// outcome (the caller must hold exactly one, fresh from
    /// `reserve`/`reserve_and_write`, and must NOT release it again):
    ///
    /// * single ACTIVE inline reader (the crown 1w1r topology, with or
    ///   without tombstones ahead of it): the ref transfers to the
    ///   reader on a successful push -- zero refcount traffic on the
    ///   fast path; a failed push frees the slot here (the caller does not
    ///   release on a failed push);
    /// * several registered readers: the caller's ref is held as a
    ///   GUARD for the whole fan-out; each ring takes its own
    ///   `add_ref` BEFORE the push attempt (a fast reader may pop and
    ///   release while the loop is still running -- the guard keeps
    ///   the count above zero, and incrementing after the push would
    ///   race that release into a premature free, loom-verified
    ///   unsound), undone on a full-ring drop; the guard is dropped
    ///   after the loop, so zero successful deliveries free the slot
    ///   immediately (net count == successful deliveries).
    ///
    /// Returns true if pushed to at least one reader.
    /// A reader whose ring is full and whose history keeps everything in it
    /// misses the entry.
    ///
    /// # Content filters
    ///
    /// A registration carrying a [`SampleFilter`] is consulted BEFORE its
    /// reference is taken and its ring is pushed, on both the sole-reader
    /// and the fan-out path. A rejected sample is therefore invisible to
    /// that reader: no ring slot, no reference, no notification. With the
    /// sole reader rejecting, this returns `false` exactly like a full
    /// ring (zero deliveries, the caller's ref freed here): the return
    /// value means "delivered to at least one reader", never "lost", and a
    /// caller must not count `false` as loss. Both writer call sites only
    /// log it today.
    ///
    /// # Performance
    ///
    /// These fast paths describe mergers without reliable DDS tracking.
    /// Tracked bindings serialize pairing and record each admission.
    ///
    /// - Sole active reader: one Acquire load selects the slot, no scan
    /// - Lock-free inline slot scan otherwise (read lock only for
    ///   overflow readers, rare)
    /// - Tombstoned readers cost one Relaxed load + branch per slot
    /// - Unfiltered readers cost one `Option` branch per active slot
    /// - Each FILTERED registration costs one decode + one filter
    ///   evaluation on the writer's thread per push, so N filtered readers
    ///   on one topic cost N decodes per sample (overflow ones under the
    ///   overflow read lock). The < 100 ns target below is for unfiltered
    ///   registrations only
    /// - Single-reader topology: no refcount RMW added by this function
    /// - Target: < 100 ns for typical 1-3 readers
    ///
    /// Iteration order is registration order: inline slots first, then overflow.
    pub fn push(&self, entry: IndexEntry, pool: &SlabPool) -> bool {
        self.push_keyed(entry, pool, &no_key)
    }

    /// [`push`](Self::push) with the sample's instance key hash on demand:
    /// `key` is called at most once, and only if a registration's ownership
    /// gate or its reader's history asks for it, so a writer passes the key
    /// it computed (or will compute) instead of every gated reader decoding
    /// the sample again. Never waits for room: [`admit`](Self::admit) then
    /// [`deliver`](Self::deliver) with no `max_blocking_time`.
    pub(crate) fn push_keyed(
        &self,
        entry: IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
    ) -> bool {
        // Unreachable without a wait: the push never times out.
        self.push_waiting(entry, pool, key, || None)
            .unwrap_or(false)
    }

    /// [`admit`](Self::admit) then [`deliver`](Self::deliver) in one call,
    /// for a writer that emits the sample nowhere else in between, waiting
    /// at most `wait` for room in a RELIABLE reader's history. CONSUMES the
    /// caller's slab reference in every outcome, `Err` included.
    ///
    /// The crown topology (one active reader, no filter, no gate, no door
    /// that counts) takes the push it always took: the ring's room check is
    /// the push itself, its single reader has the sample or none does, and
    /// only a full ring goes the general way.
    ///
    /// `wait` gives the `max_blocking_time` when a reader has no room.
    #[inline(never)]
    pub(crate) fn push_waiting(
        &self,
        entry: IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
        wait: impl FnOnce() -> Option<std::time::Duration>,
    ) -> Result<bool, RoomTimeout> {
        self.push_waiting_mode::<true>(entry, pool, key, wait)
    }

    #[inline]
    pub(crate) fn push_waiting_plain(
        &self,
        entry: IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
        wait: impl FnOnce() -> Option<std::time::Duration>,
    ) -> Result<bool, RoomTimeout> {
        self.push_waiting_mode::<false>(entry, pool, key, wait)
    }

    #[inline(never)]
    fn push_waiting_mode<const CONTROLLED: bool>(
        &self,
        entry: IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
        wait: impl FnOnce() -> Option<std::time::Duration>,
    ) -> Result<bool, RoomTimeout> {
        #[cfg(test)]
        self.before_delivery(entry.seq);
        if self.acknowledgments.get().is_some()
            || (CONTROLLED && self.group_producer.get().is_some())
        {
            let deadline = wait().map(WriteDeadline::new);
            return if CONTROLLED {
                self.push_admitting(entry, pool, key, deadline.as_ref())
            } else {
                self.push_admitting_plain(entry, pool, key, deadline.as_ref())
            };
        }
        let sole = self.sole_reader.load(Ordering::Acquire);
        if sole != 0 {
            if let Some(reader) = self.inline_readers.get(sole - 1).and_then(OnceLock::get) {
                if reader.is_active() && !reader.checked {
                    // As in `deliver_sole`: the transferred reference is the
                    // only one, unless an armed observer holds its own.
                    let tagged = entry;
                    let observer = reader.armed_observer(&tagged);
                    if observer.is_some() {
                        pool.add_ref(tagged.handle);
                    }
                    if reader.ring().push_tagged(tagged, observer.is_none()) {
                        reader.acknowledge(entry.seq);
                        reader.notify();
                        if let Some(observer) = observer {
                            observer.observe(&tagged, pool);
                            pool.release(tagged.handle);
                        }
                        return Ok(true);
                    }
                    if observer.is_some() {
                        pool.release(tagged.handle);
                    }
                } else if reader.counting_only && entry.lifecycle_bits() == 0 && reader.is_active()
                {
                    if let Some(pushed) = Self::push_counted(reader, entry, pool, key) {
                        return Ok(pushed);
                    }
                }
            }
        }
        let deadline = wait().map(WriteDeadline::new);
        if CONTROLLED {
            self.push_admitting(entry, pool, key, deadline.as_ref())
        } else {
            self.push_admitting_plain(entry, pool, key, deadline.as_ref())
        }
    }

    /// The one-reader push for a reader whose door counts (a RELIABLE
    /// KEEP_ALL reader, or one whose limits bound instances): room in its
    /// history, then the push. `None` when there is no room in either
    /// (whatever was taken given back): the general path decides then.
    #[inline]
    fn push_counted(
        reader: &MergerReader,
        entry: IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
    ) -> Option<bool> {
        let door = reader.door.as_ref()?;
        let instance = if reader.needs_instance { key() } else { None };
        let used = door.reserve(&entry, instance).ok()?;
        let tagged = entry;
        let observer = reader.armed_observer(&tagged);
        if observer.is_some() {
            pool.add_ref(tagged.handle);
        }
        if reader.ring().push_tagged(tagged, observer.is_none()) {
            reader.acknowledge(entry.seq);
            reader.notify();
            if let Some(observer) = observer {
                observer.observe(&tagged, pool);
                pool.release(tagged.handle);
            }
            return Some(true);
        }
        if observer.is_some() {
            pool.release(tagged.handle);
        }
        door.cancel(used);
        None
    }

    /// The general half of [`push_waiting`](Self::push_waiting).
    #[inline(never)]
    fn push_admitting(
        &self,
        entry: IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
        wait: Option<&WriteDeadline>,
    ) -> Result<bool, RoomTimeout> {
        let mut resolved = ResolvedKey::new(key);
        match self.admit_resolved(&entry, pool, &mut resolved, wait) {
            Ok(admission) => Ok(self.deliver_resolved(
                admission,
                entry,
                pool,
                &mut resolved,
                false,
                None,
                PendingOrders::default(),
            )),
            Err(timeout) => {
                pool.release(entry.handle);
                Err(timeout)
            }
        }
    }

    #[inline(never)]
    fn push_admitting_plain(
        &self,
        entry: IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
        wait: Option<&WriteDeadline>,
    ) -> Result<bool, RoomTimeout> {
        let mut resolved = ResolvedKey::new(key);
        match self.admit_plain_resolved(&entry, pool, &mut resolved, wait) {
            Ok(admission) => {
                Ok(self.deliver_body::<false>(admission, entry, pool, &mut resolved, None))
            }
            Err(timeout) => {
                pool.release(entry.handle);
                Err(timeout)
            }
        }
    }

    /// The first half of a delivery: decide, for every active registration,
    /// whether `entry` goes to it, and take the room it needs there, before
    /// anything is pushed anywhere (the caller may emit the sample on other
    /// legs in between). Nothing is pushed and no slab reference is taken
    /// or consumed; [`deliver`](Self::deliver) pushes.
    ///
    /// A RELIABLE reader with no room (its history at a RESOURCE_LIMITS
    /// bound, or its ring full of samples the history keeps) makes the
    /// writer wait until `wait`, its write's deadline: DDS v1.4
    /// Sec.2.2.3.14 and Sec.2.2.3.18 ("If reliability is RELIABLE, then the
    /// Service will block the DataWriter until it can deliver the necessary
    /// old values to all subscribers"). A local reader has no repair path,
    /// so a sample skipped would be lost. The sample goes to every reader or
    /// to none: the room taken in the others is given back while the writer
    /// waits (no writer holds room while it waits for another reader, so two
    /// writers cannot each hold what the other waits for), and admission
    /// starts over once the blocking reader made room. `Err(RoomTimeout)`
    /// when the deadline passes first: nothing was taken and the writer's
    /// `write` returns TIMEOUT. `wait == None` never waits: a reader with no
    /// room is skipped.
    ///
    /// Clock reads and the waiting itself happen only when a reader has no
    /// room.
    pub(crate) fn admit<'m>(
        &'m self,
        entry: &IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
        wait: Option<&WriteDeadline>,
    ) -> Result<Admission<'m>, RoomTimeout> {
        self.admit_resolved(entry, pool, &mut ResolvedKey::new(key), wait)
    }

    pub(crate) fn admit_ordered<'m>(
        &'m self,
        entry: &IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
        wait: Option<&WriteDeadline>,
        ordering: Option<(u64, u64)>,
    ) -> Result<Admission<'m>, RoomTimeout> {
        self.admit_targeted::<false>(entry, pool, &mut ResolvedKey::new(key), wait, &[], ordering)
    }

    fn admit_resolved<'m>(
        &'m self,
        entry: &IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        wait: Option<&WriteDeadline>,
    ) -> Result<Admission<'m>, RoomTimeout> {
        self.admit_targeted::<false>(entry, pool, key, wait, &[], None)
    }

    fn admit_targeted<'m, const SELECTED: bool>(
        &'m self,
        entry: &IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        wait: Option<&WriteDeadline>,
        targets: &[ReaderId],
        ordering: Option<(u64, u64)>,
    ) -> Result<Admission<'m>, RoomTimeout> {
        // Merger rings carry data entries only (event entries with the
        // EMPTY sentinel travel on the hub rings, never through here).
        debug_assert!(
            !entry.handle.is_empty(),
            "TopicMerger::push requires a real slab handle"
        );
        loop {
            let blocked = match self.admit_once::<SELECTED>(
                entry,
                pool,
                key,
                wait.is_some(),
                targets,
                ordering,
            ) {
                Ok(admission) => return Ok(admission),
                Err(blocked) => blocked,
            };
            Self::wait_for_room(blocked, entry, key, wait)?;
        }
    }

    #[inline]
    pub(crate) fn admit_plain<'m>(
        &'m self,
        entry: &IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
        wait: Option<&WriteDeadline>,
    ) -> Result<PlainAdmission<'m>, RoomTimeout> {
        self.admit_plain_resolved(entry, pool, &mut ResolvedKey::new(key), wait)
    }

    fn admit_plain_resolved<'m>(
        &'m self,
        entry: &IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        wait: Option<&WriteDeadline>,
    ) -> Result<PlainAdmission<'m>, RoomTimeout> {
        loop {
            match self.admit_readers::<false, false, _>(
                self.empty_admission::<()>(),
                entry,
                pool,
                key,
                wait.is_some(),
                &[],
                None,
            ) {
                Ok(admission) => return Ok(admission),
                Err(blocked) => Self::wait_for_room(blocked, entry, key, wait)?,
            }
        }
    }

    fn wait_for_room(
        blocked: BlockedReader,
        entry: &IndexEntry,
        key: &mut ResolvedKey<'_>,
        wait: Option<&WriteDeadline>,
    ) -> Result<(), RoomTimeout> {
        #[cfg(any(test, feature = "test-support"))]
        run_room_wait_hook();
        let Some(wait) = wait else {
            // `admit_once` blocks only when it may wait.
            return Err(RoomTimeout);
        };
        let deadline = wait.instant();
        let now = std::time::Instant::now();
        // Checked here too: room seen by the wait can be taken by
        // another writer before this one's next pass.
        let timed_out = now >= deadline
            || !blocked.door.as_ref().is_some_and(|door| {
                door.wait_while(deadline, &mut || blocked.still_blocked(entry, key))
            });
        if timed_out {
            if let Some(m) = crate::telemetry::get_metrics_opt() {
                m.increment_merge_full(1);
            }
            return Err(RoomTimeout);
        }
        Ok(())
    }

    /// One pass of [`admit`](Self::admit) over the active registrations.
    /// `Err` with the registration that blocked, every room taken by this
    /// pass given back.
    #[inline(always)]
    fn empty_admission<'m, C: AdmissionCleanup + Default>(&'m self) -> Admission<'m, C> {
        Admission {
            merger: self,
            pairing: if C::CONTROLLED {
                self.pairing()
            } else {
                self.pairing_plain()
            },
            notices: Some(crate::dds::LocalDelivery::enter()),
            sole: 0,
            inline: 0,
            reserved: 0,
            irrelevant_inline: 0,
            irrelevant_overflow: Vec::new(),
            overflow: Vec::new(),
            key: [0; 16],
            // One producer at a time on this merger's rings (`admit` to
            // `deliver`): see `producer_turn`.
            control: C::default(),
        }
    }

    fn admit_once<'m, const SELECTED: bool>(
        &'m self,
        entry: &IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        may_wait: bool,
        targets: &[ReaderId],
        ordering: Option<(u64, u64)>,
    ) -> Result<Admission<'m>, BlockedReader> {
        let mut admission = self.empty_admission();
        if let Some(control) = self.group_producer.get() {
            let mut local = AdmissionControl {
                producer: None,
                order: None,
            };
            if !SELECTED {
                local.order = control
                    .order
                    .get()
                    .and_then(std::sync::Weak::upgrade)
                    .map(|order| {
                        let direct = order.try_enter();
                        OrderedAdmission {
                            order,
                            direct,
                            targets: Vec::new(),
                        }
                    });
            }
            if let Some(order) = local.order.as_mut().filter(|order| !order.direct) {
                for reader in self.readers_snapshot() {
                    if !reader.checked || reader.passes_filter(entry, pool) {
                        order.targets.push(reader.id());
                    } else {
                        admission.irrelevant_overflow.push(reader);
                    }
                }
                admission.control = Some(local);
                return Ok(admission);
            }
            local.producer = control.turn.get().map(parking_lot::ReentrantMutex::lock);
            admission.control = Some(local);
        }
        self.admit_readers::<SELECTED, true, _>(
            admission, entry, pool, key, may_wait, targets, ordering,
        )
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn admit_readers<'m, const SELECTED: bool, const CONTROLLED: bool, C: AdmissionCleanup>(
        &'m self,
        mut admission: Admission<'m, C>,
        entry: &IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        may_wait: bool,
        targets: &[ReaderId],
        ordering: Option<(u64, u64)>,
    ) -> Result<Admission<'m, C>, BlockedReader> {
        let sole = self.sole_reader.load(Ordering::Acquire);
        if sole != 0 {
            // Exactly one active reader as of the designation store. A
            // reader registered concurrently with this load misses this
            // sample, which is the same registration-race window the
            // fan-out path has.
            if let Some(reader) = self.inline_readers.get(sole - 1).and_then(OnceLock::get) {
                if reader.is_active() && (!SELECTED || targets.contains(&reader.id())) {
                    match reader.admit::<SELECTED, CONTROLLED>(entry, pool, key, may_wait, ordering)
                    {
                        Step::Admit { reserved } => {
                            admission.sole = sole;
                            admission.reserved = u32::from(reserved);
                            admission.key = key.used;
                        }
                        Step::Irrelevant => admission.irrelevant_inline |= 1 << (sole - 1),
                        Step::Skip => {}
                        Step::Blocked => return Err(BlockedReader::new(reader, ordering)),
                    }
                }
            }
            return Ok(admission);
        }

        // Zero, several, or overflow-resident active readers.
        let n = self
            .inline_published
            .load(Ordering::Acquire)
            .min(INLINE_READERS);
        for (i, slot) in self.inline_readers[..n].iter().enumerate() {
            let Some(reader) = slot.get() else {
                continue;
            };
            if !reader.is_active() || (SELECTED && !targets.contains(&reader.id())) {
                continue;
            }
            match reader.admit::<SELECTED, CONTROLLED>(entry, pool, key, may_wait, ordering) {
                Step::Admit { reserved } => {
                    admission.inline |= 1 << i;
                    admission.reserved |= u32::from(reserved) << i;
                    admission.key = key.used;
                }
                Step::Irrelevant => admission.irrelevant_inline |= 1 << i,
                Step::Skip => {}
                Step::Blocked => {
                    let blocked = BlockedReader::new(reader, ordering);
                    drop(admission);
                    return Err(blocked);
                }
            }
        }
        if self.overflow_active.load(Ordering::Acquire) > 0 {
            // The registrations are asked outside the overflow read guard:
            // a reader's history may make room in its ring under its
            // consumer gate, which the reader's teardown holds while it
            // takes the write guard.
            let overflow: Vec<MergerReader> = recover_read(
                &self.overflow_readers,
                "TopicMerger::admit overflow_readers.read()",
            )
            .iter()
            .filter(|reader| reader.is_active())
            .cloned()
            .collect();
            for reader in overflow {
                if SELECTED && !targets.contains(&reader.id()) {
                    continue;
                }
                match reader.admit::<SELECTED, CONTROLLED>(entry, pool, key, may_wait, ordering) {
                    Step::Admit { reserved } => {
                        admission.key = key.used;
                        admission.overflow.push((reader, reserved));
                    }
                    Step::Irrelevant => admission.irrelevant_overflow.push(reader),
                    Step::Skip => {}
                    Step::Blocked => {
                        drop(admission);
                        return Err(BlockedReader::new(&reader, ordering));
                    }
                }
            }
        }
        Ok(admission)
    }

    /// The second half of a delivery: push `entry` into the rings
    /// [`admit`](Self::admit) admitted it to. Every admitted ring has room,
    /// and its door already holds the room the sample takes in the reader's
    /// history.
    ///
    /// CONSUMES the caller's slab reference on `entry.handle` in every
    /// outcome (the caller must hold exactly one, fresh from
    /// `reserve`/`reserve_and_write`, and must NOT release it again):
    ///
    /// * single ACTIVE inline reader (the crown 1w1r topology, with or
    ///   without tombstones ahead of it): the ref transfers to the
    ///   reader on a successful push -- zero refcount traffic on the
    ///   fast path; a failed push frees the slot here;
    /// * several registered readers: the caller's ref is held as a
    ///   GUARD for the whole fan-out; each ring takes its own
    ///   `add_ref` BEFORE the push attempt (a fast reader may pop and
    ///   release while the loop is still running -- the guard keeps
    ///   the count above zero, and incrementing after the push would
    ///   race that release into a premature free, loom-verified
    ///   unsound), undone on a failed push; the guard is dropped
    ///   after the loop, so zero successful deliveries free the slot
    ///   immediately (net count == successful deliveries).
    ///
    /// Returns true if pushed to at least one reader.
    /// Publish an ordinary GROUP change with its Publisher order.
    pub(crate) fn deliver(
        &self,
        admission: Admission<'_>,
        entry: IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
        ordering: Option<(u64, u64)>,
        pending: PendingOrders,
    ) -> bool {
        self.deliver_resolved(
            admission,
            entry,
            pool,
            &mut ResolvedKey::new(key),
            false,
            ordering,
            pending,
        )
    }

    /// Attempt an already accepted ordinary tail once. A blocked RELIABLE
    /// destination keeps the caller's slab claim and retries when it frees
    /// room; the write has committed, so no delivery timeout can discard it.
    pub(crate) fn push_staged(
        &self,
        entry: IndexEntry,
        key: [u8; 16],
        targets: &[ReaderId],
        reliable: bool,
        ordering: Option<(u64, u64)>,
    ) -> Result<(), BlockedReader> {
        let pool = super::get_slab_pool_ref();
        let supply = || Some(key);
        let mut resolved = ResolvedKey::new(&supply);
        let admission =
            self.admit_once::<true>(&entry, pool, &mut resolved, reliable, targets, ordering)?;
        self.deliver_resolved(
            admission,
            entry,
            pool,
            &mut resolved,
            true,
            ordering,
            PendingOrders::default(),
        );
        Ok(())
    }

    #[inline]
    pub(crate) fn deliver_plain(
        &self,
        admission: PlainAdmission<'_>,
        entry: IndexEntry,
        pool: &SlabPool,
        key: KeyOnDemand<'_>,
    ) -> bool {
        self.deliver_body::<false>(admission, entry, pool, &mut ResolvedKey::new(key), None)
    }

    #[allow(clippy::too_many_arguments)]
    fn deliver_resolved(
        &self,
        mut admission: Admission<'_>,
        entry: IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        grouped: bool,
        ordering: Option<(u64, u64)>,
        pending: PendingOrders,
    ) -> bool {
        // Declared first: unwinding releases every producer and logical
        // owner before this scope drains application notifications.
        let notices = admission.notices.take();
        let (producer, order, grouped) = match admission.control.take() {
            None => (None, None, grouped),
            Some(mut control) => {
                // `take_if` leaves a direct order in place, as the fall-through
                // below expects.
                if let Some(mut ordered) = control.order.take_if(|order| !order.direct) {
                    let targets = std::mem::take(&mut ordered.targets);
                    let order = Arc::clone(&ordered.order);
                    for reader in std::mem::take(&mut admission.irrelevant_overflow) {
                        reader.acknowledge(entry.seq);
                    }
                    drop(ordered);
                    drop(control);
                    drop(admission);
                    order.defer(
                        entry,
                        key.get().unwrap_or([0; 16]),
                        targets,
                        ordering,
                        pending,
                    );
                    return true;
                }
                (control.producer.take(), control.order.take(), true)
            }
        };
        let plain = admission.take_plain();
        drop(admission);
        let pushed = if grouped {
            self.deliver_body::<true>(plain, entry, pool, key, ordering)
        } else {
            self.deliver_body::<false>(plain, entry, pool, key, None)
        };
        drop(pending);
        drop(producer);
        drop(order);
        drop(notices);
        pushed
    }

    fn deliver_body<const GROUPED: bool>(
        &self,
        admission: PlainAdmission<'_>,
        entry: IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        ordering: Option<(u64, u64)>,
    ) -> bool {
        debug_assert!(std::ptr::eq(admission.merger, self));
        // From here on this function gives back what is not pushed.
        let mut admission = std::mem::ManuallyDrop::new(admission);
        // The writer committed before delivery. A new binding may now take
        // that watermark; no registration lock reaches application code.
        drop(admission.pairing.take());
        let _notices = admission.notices.take();

        let mut irrelevant = admission.irrelevant_inline;
        while irrelevant != 0 {
            let i = irrelevant.trailing_zeros() as usize;
            irrelevant &= irrelevant - 1;
            if let Some(reader) = self.inline_readers[i].get() {
                reader.acknowledge(entry.seq);
            }
        }
        for reader in std::mem::take(&mut admission.irrelevant_overflow) {
            reader.acknowledge(entry.seq);
        }
        let overflow = std::mem::take(&mut admission.overflow);
        let (sole, inline, reserved, used) = (
            admission.sole,
            admission.inline,
            admission.reserved,
            admission.key,
        );
        if sole != 0 {
            let pushed =
                self.deliver_sole::<GROUPED>(sole, reserved != 0, used, entry, pool, key, ordering);
            return pushed;
        }

        let mut pushed_any = false;
        let mut bits = inline;
        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            let Some(reader) = self.inline_readers[i].get() else {
                continue;
            };
            let took = reserved & (1 << i) != 0;
            pushed_any |=
                Self::deliver_one::<GROUPED>(reader, took, used, entry, pool, key, ordering);
        }
        if !overflow.is_empty() {
            // Observers are application code: they run after every push,
            // still under the fan-out guard that keeps the payload readable.
            let mut observers: Vec<Arc<DeliveryObserver>> = Vec::new();
            for (reader, took) in &overflow {
                if Self::deliver_one_deferring::<GROUPED>(
                    reader, *took, used, entry, pool, key, ordering,
                ) {
                    pushed_any = true;
                    if let Some(observer) = reader.armed_observer(&entry) {
                        observers.push(Arc::clone(observer));
                    }
                }
            }
            for observer in &observers {
                if GROUPED {
                    observer.observe_grouped(&entry, pool);
                } else {
                    observer.observe(&entry, pool);
                }
            }
        }

        // Drop the fan-out guard (the caller's claim ref). With zero
        // successful deliveries this is the 1 -> 0 transition that
        // frees the slot.
        pool.release(entry.handle);

        pushed_any
    }

    /// Push `entry` to one fan-out registration and observe it there.
    #[inline]
    fn deliver_one<const GROUPED: bool>(
        reader: &MergerReader,
        took: bool,
        used: [u8; 16],
        entry: IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        ordering: Option<(u64, u64)>,
    ) -> bool {
        let pushed =
            Self::deliver_one_deferring::<GROUPED>(reader, took, used, entry, pool, key, ordering);
        if pushed {
            // The fan-out guard (released by the caller) keeps the payload
            // readable for the observer.
            if let Some(observer) = reader.armed_observer(&entry) {
                if GROUPED {
                    observer.observe_grouped(&entry, pool);
                } else {
                    observer.observe(&entry, pool);
                }
            }
        }
        pushed
    }

    /// [`deliver_one`](Self::deliver_one) leaving the observer to the
    /// caller.
    #[inline]
    fn deliver_one_deferring<const GROUPED: bool>(
        reader: &MergerReader,
        took: bool,
        used: [u8; 16],
        entry: IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        ordering: Option<(u64, u64)>,
    ) -> bool {
        // A reader tombstoned since its admission, or whose ownership gate
        // refuses, owns no reference: nothing is owed back but its room.
        if !reader.is_active() || (reader.checked && !reader.passes_gate(&entry, pool, key)) {
            if reader.is_active() {
                reader.acknowledge(entry.seq);
            }
            if took {
                reader.cancel(used);
            }
            return false;
        }
        // Increment BEFORE the push: the entry copy must never be visible
        // to a consumer it is not yet accounted for.
        let mut order = if GROUPED {
            ordering.and_then(|(publisher, gsn)| {
                let door = reader.door.as_ref()?;
                let token = door.record_order(&entry, publisher, gsn)?;
                Some(OrderReservation {
                    door: door.as_ref(),
                    token,
                    committed: false,
                })
            })
        } else {
            None
        };
        pool.add_ref(entry.handle);
        if reader.ring().push(entry) {
            if let Some(order) = order.as_mut() {
                order.committed = true;
            }
            reader.acknowledge(entry.seq);
            if GROUPED {
                let on_data = Arc::clone(&reader.on_data);
                crate::dds::notify_local(move || on_data());
            } else {
                reader.notify();
            }
            true
        } else {
            // Admitted with room by the ring's only producer: not reached.
            pool.release(entry.handle);
            if took {
                reader.cancel(used);
            }
            false
        }
    }

    /// [`deliver`](Self::deliver) on the single-reader path.
    // Mirrors the fan-out path argument for argument; gathering them in a
    // struct would put it on the 100 ns push path.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn deliver_sole<const GROUPED: bool>(
        &self,
        sole: usize,
        took: bool,
        used: [u8; 16],
        entry: IndexEntry,
        pool: &SlabPool,
        key: &mut ResolvedKey<'_>,
        ordering: Option<(u64, u64)>,
    ) -> bool {
        // At most ONE push attempt, so the caller's ref can transfer
        // without the guard dance.
        //
        // The entry is tagged EXCLUSIVE before the push: the transferred
        // ref is provably the only one (no fan-out duplicate is possible on
        // this branch, and merger-pushed handles never alias HistoryCache
        // retention -- the cache reserves its own slot, and replay entries
        // are built with fresh flags in add_reader). The reader pump then
        // frees the slot directly and never touches the refcount side-table
        // line, keeping the crown 1w1r release at one RMW (loom:
        // exclusive-transfer + mixed-generation models).
        //
        // The `is_active` re-check keeps the tombstone race at its
        // documented one-entry bound: a designation loaded before
        // `remove_reader` cleared it names a slot that is being tombstoned,
        // and the slot itself is never vacated, so the `get()` below cannot
        // dangle.
        if let Some(reader) = self.inline_readers.get(sole - 1).and_then(OnceLock::get) {
            let live = reader.is_active();
            let allowed = live && (!reader.checked || reader.passes_gate(&entry, pool, key));
            if live && !allowed {
                reader.acknowledge(entry.seq);
            }
            if allowed {
                // An armed observer reads the payload AFTER the push, when
                // the ring may already have consumed and freed the
                // transferred reference: it holds one of its own across the
                // push, so the entry is not exclusive.
                let observer = reader.armed_observer(&entry);
                if observer.is_some() {
                    pool.add_ref(entry.handle);
                }
                let mut order = if GROUPED {
                    ordering.and_then(|(publisher, gsn)| {
                        let door = reader.door.as_ref()?;
                        let token = door.record_order(&entry, publisher, gsn)?;
                        Some(OrderReservation {
                            door: door.as_ref(),
                            token,
                            committed: false,
                        })
                    })
                } else {
                    None
                };
                if reader.ring().push_tagged(entry, observer.is_none()) {
                    if let Some(order) = order.as_mut() {
                        order.committed = true;
                    }
                    reader.acknowledge(entry.seq);
                    if GROUPED {
                        let on_data = Arc::clone(&reader.on_data);
                        crate::dds::notify_local(move || on_data());
                    } else {
                        reader.notify();
                    }
                    if let Some(observer) = observer {
                        if GROUPED {
                            observer.observe_grouped(&entry, pool);
                        } else {
                            observer.observe(&entry, pool);
                        }
                        pool.release(entry.handle);
                    }
                    return true;
                }
                if observer.is_some() {
                    pool.release(entry.handle);
                }
            }
            if took {
                reader.cancel(used);
            }
        }
        // Zero deliveries (the ownership gate refused, or the sole reader
        // is being tombstoned under us): drop the caller's ref (frees the
        // slot).
        pool.release(entry.handle);
        false
    }

    /// Get current number of ACTIVE registered readers (tombstoned
    /// registrations excluded).
    #[must_use]
    pub fn reader_count(&self) -> usize {
        self.reader_count_cache.load(Ordering::Acquire)
    }
}

impl Drop for TopicMerger {
    fn drop(&mut self) {
        MERGERS_FREED.fetch_add(1, Ordering::Release);
    }
}

impl<C: AdmissionCleanup> Admission<'_, C> {
    /// An admission not delivered gives back the room its doors took.
    fn cancel_reservations(&mut self) {
        if self.reserved == 0 && self.overflow.iter().all(|(_, took)| !took) {
            return;
        }
        if self.sole != 0 {
            if let Some(reader) = self
                .merger
                .inline_readers
                .get(self.sole - 1)
                .and_then(OnceLock::get)
            {
                reader.cancel(self.key);
            }
            return;
        }
        let mut bits = self.reserved;
        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            if let Some(reader) = self.merger.inline_readers[i].get() {
                reader.cancel(self.key);
            }
        }
        for (reader, took) in &self.overflow {
            if *took {
                reader.cancel(self.key);
            }
        }
    }
}

impl<C: AdmissionCleanup> Drop for Admission<'_, C> {
    fn drop(&mut self) {
        self.cancel_reservations();
        self.control.release_producer();
        drop(self.pairing.take());
        self.control.release_order();
        drop(self.notices.take());
    }
}

impl<'m> Admission<'m> {
    fn take_plain(&mut self) -> PlainAdmission<'m> {
        debug_assert!(self.control.is_none());
        PlainAdmission {
            merger: self.merger,
            pairing: self.pairing.take(),
            notices: self.notices.take(),
            sole: std::mem::take(&mut self.sole),
            inline: std::mem::take(&mut self.inline),
            reserved: std::mem::take(&mut self.reserved),
            irrelevant_inline: std::mem::take(&mut self.irrelevant_inline),
            irrelevant_overflow: std::mem::take(&mut self.irrelevant_overflow),
            overflow: std::mem::take(&mut self.overflow),
            key: self.key,
            control: (),
        }
    }
}

impl Default for TopicMerger {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro to generate poisoned lock recovery functions (eliminates duplication)
///
/// Generates `recover_read` and `recover_write` with identical error handling.
macro_rules! impl_recover_lock {
    ($fn_name:ident, $lock_method:ident, $guard_type:ty) => {
        #[inline]
        fn $fn_name<'a, T>(lock: &'a RwLock<T>, context: &str) -> $guard_type {
            match lock.$lock_method() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::debug!("[rt] WARNING: {} poisoned, recovering", context);
                    poisoned.into_inner()
                }
            }
        }
    };
}

impl_recover_lock!(recover_read, read, RwLockReadGuard<'a, T>);
impl_recover_lock!(recover_write, write, RwLockWriteGuard<'a, T>);

#[cfg(test)]
#[path = "merger_test.rs"]
mod tests;

#[cfg(test)]
mod pending_order_lease_tests {
    use super::*;

    #[test]
    fn completed_order_lease_registry_is_pruned_on_writes_and_pairing() {
        let merger = TopicMerger::new();
        for seq in 1..=128 {
            let lease = merger.reserve_order(1, seq, seq, false);
            assert_eq!(
                merger
                    .group_producer
                    .get()
                    .unwrap()
                    .pending
                    .lock()
                    .unwrap()
                    .len(),
                1
            );
            lease.finish();
        }
        merger.add_reader(MergerReader::new(
            Arc::new(IndexRing::with_capacity(4)),
            Arc::new(|| {}),
        ));
        assert!(merger
            .group_producer
            .get()
            .unwrap()
            .pending
            .lock()
            .unwrap()
            .is_empty());
    }
}
