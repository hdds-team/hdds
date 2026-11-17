// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::cache::{
    never, CachedSample, InstanceHandle, InstanceState, InstanceTable, SampleCache, SampleInfo,
    ViewState,
};
use super::coherent_barrier::CoherentPresentationBarrier;
use super::consumer_gate::ConsumerGate;
use super::subscriber::{DisposeEvent, DisposeQueue};
use crate::core::rt;
use crate::core::rt::merger::ReaderId;
use crate::dds::listener::{
    DataReaderListener, ReaderListenerSlot, RequestedDeadlineMissedStatus,
    RequestedIncompatibleQosStatus, SampleRejectedStatus,
};
use crate::dds::{
    qos::History, BindToken, QoS, Result, StatusCondition, StatusMask, DDS, WAKE_WORDS,
};
use crate::engine::subscriber::DisposeKind;
use crate::engine::{SubscriberToken, TopicRegistry};
use crate::qos::time_based_filter::TimeBasedFilterChecker;
use crate::telemetry::metrics::current_time_ns;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

type LocalKeys = Arc<Mutex<std::collections::HashMap<rt::SlabHandle, LocalCapture>>>;

#[derive(Clone, Copy)]
struct LocalCapture {
    key: [u8; 16],
    writer_guid: Option<[u8; 16]>,
}

/// Which DATA_AVAILABLE wake word each of the reader's producers raises
/// (`StatusCondition::wake_words`, see `WakeWords` for the argument).
/// A word whose raises all come from one thread is raised with a plain
/// store (the primary ring's merger; the dispose queue, under its
/// lock). A word whose raises can come from several threads is raised
/// with a read-modify-write: the extra binding rings (unbounded, one
/// merger thread each) and the network ring (the router thread, and the
/// application thread when a coherent barrier delivers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(super) enum WakeWord {
    /// The primary local ring: the first bound writer's merger fan-out
    /// (the crown 1w1r topology has this producer only).
    Primary = 0,
    /// The dedicated network ring: `ReaderSubscriber::process_admitted`,
    /// reached from the router thread and, behind a coherent barrier,
    /// from the application thread (shared word; the push site says
    /// why).
    Network = 1,
    /// Every non-primary local binding ring, raised by each of their
    /// mergers (shared word).
    Extra = 2,
    /// The dispose queue: `ReaderSubscriber::on_dispose` through
    /// `DisposeQueue::push`, which owns the word's writes.
    Dispose = 3,
}

impl WakeWord {
    /// The words a ring re-check covers, primary first.
    const RINGS: [WakeWord; 3] = [WakeWord::Primary, WakeWord::Network, WakeWord::Extra];

    #[inline]
    pub(super) const fn index(self) -> usize {
        self as usize
    }
}

// Every producer has a word and the condition carries no spare.
const _: () = assert!(WakeWord::Dispose.index() + 1 == WAKE_WORDS);

/// One intra-process binding: the writer merger this reader registered
/// with and the dedicated SPSC ring that merger fans into.
struct RingBinding {
    /// Weak: a merger dies with its writer; `Drop` tombstones this
    /// reader in each still-alive one.
    merger: Weak<rt::TopicMerger>,
    /// The ring registered with `merger`. The first binding reuses the
    /// reader's primary ring; every later binding gets a fresh ring.
    ring: Arc<rt::IndexRing>,
    /// The writer's identity, captured ONCE at [`bind`](ReaderBindings::bind)
    /// time from the live `merger`, `None` for the rare merger with no
    /// writer yet. A GUID is a fixed property of the writer, established
    /// at its creation and never reassigned, so this never goes stale --
    /// unlike re-deriving it by upgrading `merger` on every pump, which
    /// loses the identity the moment the writer is dropped (DDS v1.4 Sec.2.2.3.17 tie-break): a ring this
    /// binding already queued entries into can still be draining after
    /// its writer is gone, and those entries' tie-break must not change
    /// depending on how fast the application happens to drain them.
    writer_guid: Option<[u8; 16]>,
}

/// Per-(writer, reader) ring table.
///
/// `IndexRing` is a single-producer ring: registering the reader's one
/// ring with N writer mergers put N concurrent producers on it (silent
/// loss, UB). Here every binding owns its own ring, so each ring
/// keeps exactly one producer -- that writer's merger fan-out -- and
/// the reader drains K rings. Ring identity doubles as writer identity
/// (`IndexEntry` carries no writer id).
///
/// The FIRST binding reuses the reader's primary ring: the 1w1r
/// topology (crown latency path, every single-writer test) keeps today's
/// exact pump loop and merger registration (same `ReaderId` = primary
/// ring address), and `extra_rings` stays 0 so the pump never takes
/// the table mutex.
pub(super) struct ReaderBindings {
    /// The reader's primary local-delivery ring.
    primary: Arc<rt::IndexRing>,
    local_ack_identity: std::sync::OnceLock<([u8; 16], bool)>,
    /// Dedicated network-producer ring. Keeping it separate from every
    /// merger registration preserves the SPSC contract in mixed
    /// topologies. The ring is single-producer; the threads that deliver
    /// the reader (router, control, TCP/QUIC routing, and the application
    /// thread behind a coherent barrier) push into it one at a time under
    /// `ReaderSubscriber`'s push lock (see `process_admitted`).
    network: Option<Arc<rt::IndexRing>>,
    /// The history places of the reader's network arrivals
    /// (`admission::HistoryRoom`): every entry of `network` carries one. For
    /// a KEEP_ALL reader the pump hands it to the cached sample it becomes;
    /// a KEEP_LAST reader's cache has no room, and the place is given back
    /// as the entry leaves the ring.
    history_room: Option<Arc<super::admission::HistoryRoom>>,
    /// Capacity for fresh per-binding rings -- same policy as the
    /// primary ring (builder: max(history depth, READER_HISTORY_RING_SIZE)).
    ring_capacity: usize,
    /// DATA_AVAILABLE notification for the merger bound to the primary
    /// ring: raises `WakeWord::Primary`, a plain store (that merger is
    /// the ring's single producer, so it is the word's single producer).
    notify_primary: Arc<dyn Fn() + Send + Sync>,
    /// DATA_AVAILABLE notification shared by every other merger
    /// registration: raises `WakeWord::Extra` with a read-modify-write
    /// (several writer threads on one word).
    notify_extra: Arc<dyn Fn() + Send + Sync>,
    /// Registered bindings, append-only until reader drop. The mutex
    /// also serializes the K>1 pump drain (single consumer per ring).
    entries: Mutex<Vec<RingBinding>>,
    /// Non-primary local rings, plus one permanent merge token for an
    /// ordered GROUP reader. Selecting that token at creation keeps order
    /// bookkeeping off the ordinary single-ring take and decode paths.
    /// New bindings are Release-published; an idle network source alone
    /// does not force the ordinary reader through the merge path.
    extra_rings: AtomicUsize,
    /// Content filter handed to every merger registration, `None` for a
    /// reader without a ContentFilteredTopic. The WRITER's merger runs it
    /// before the ring push, so a rejected sample never reaches any of this
    /// reader's rings or its DATA_AVAILABLE words -- the placement the
    /// network path already has in `ReaderSubscriber::process_admitted`.
    filter: Option<rt::SampleFilter>,
    /// The reader's writer registrations, shared with its network
    /// subscriber, and, for an EXCLUSIVE reader, what its bindings need to
    /// arbitrate the local writers (see [`LocalOwnership`]).
    ownership: LocalOwnership,
    /// The reader's `on_data_available` for intra-process deliveries,
    /// handed to every merger registration (see `rt::DeliveryObserver`).
    observer: Option<Arc<rt::DeliveryObserver>>,
    /// The reader's history as the writers' mergers see it when one of its
    /// local rings is full (`local_door::LocalDoor`), handed to every merger
    /// registration; `None` keeps the lossy push.
    door: Option<Arc<dyn rt::ReaderDoor>>,
    /// Opaque local captures retain the key and writer GUID for each live slab slot.
    /// Slots are reused only after all samples referencing them are released,
    /// so the map is bounded by the pool's slot high-water mark.
    local_keys: Option<LocalKeys>,
    /// The reader's ring consumer gate. The rings are single-consumer,
    /// and with the conditions (`conditions.rs`) the consumer is not
    /// one thread by construction: a WaitSet evaluating a
    /// ReadCondition pumps the rings from its own thread while the
    /// application thread drains with `take()`, the ordinary DDS pattern,
    /// and several WaitSets may hold conditions of one reader (DDS v1.4
    /// Sec.2.2.4.5). A writer that finds a local ring full pops it too,
    /// to drop what the reader's history no longer keeps (`door`). Every
    /// ring pop, from the first pop to the cache push of what it popped,
    /// runs with this held, so N threads are one consumer and the cache
    /// sees arrivals in ring order. The condition accessors hold it across
    /// pump and cache access; the ordinary accessors hold it across the
    /// pump only. A reader drained by one thread enters with plain stores
    /// and loads; the first other thread that consumes engages it, and
    /// from then on every acquisition is one CAS and one store (see
    /// `consumer_gate`).
    consumer_gate: ConsumerGate,
    /// Set, under `consumer_gate`, when the reader is torn down: from then
    /// on its rings are drained by the teardown only, and a writer's door
    /// leaves them alone.
    closed: std::sync::atomic::AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    after_order_forget: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Where the local writers of a RELIABLE reader wait for room in its
    /// history (`admission::RoomWait`): woken when the reader pops a full
    /// local ring or gives places back, closed when it is torn down.
    room_wait: Arc<super::admission::RoomWait>,
    /// What every sample of a local ring holds in the reader's history,
    /// taken by its writer's door before the push (`cache::HELD_PLACE` for
    /// a RELIABLE KEEP_ALL reader); 0 when the door takes nothing.
    local_hold: u8,
    /// The Subscriber's coherent presentation barrier, when this reader is
    /// attached to a Subscriber entity: its access brackets hold the
    /// delivery of a local coherent set (`coherent_publication`), and its
    /// `end_access` is what retries a set that found one open.
    access_gate: Option<Arc<super::coherent_barrier::CoherentPresentationBarrier>>,
    group_replay: bool,
    order_status: Option<std::sync::Weak<StatusCondition>>,
    order_registered: std::sync::OnceLock<()>,
}

/// The instance key of an encoded sample, `None` when it does not decode.
pub(super) type KeyOf =
    Arc<dyn Fn(&[u8], crate::dds::CdrVersion) -> Option<[u8; 16]> + Send + Sync>;

/// What an EXCLUSIVE reader's intra-process bindings need to arbitrate the
/// local writers (DDS v1.4 Sec.2.2.3.9.2): the reader's registration table,
/// shared with its network subscriber so local and remote writers contend
/// in one place, and the instance key of an encoded sample
/// (`T::decode(..).compute_key()`, `None` when it does not decode).
pub(super) struct LocalOwnership {
    pub(super) registrations: Arc<super::registrations::ReaderRegistrations>,
    /// `Some` for EXCLUSIVE ownership or a finite DEADLINE. A SHARED
    /// reader with an infinite deadline installs no gate.
    pub(super) key_of: Option<KeyOf>,
    pub(super) deadlines: Option<std::sync::Weak<crate::dds::liveliness::ReaderDeadlines>>,
    /// DESTINATION_ORDER BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17),
    /// resolved at reader creation: a dispose ends the instance's deadline
    /// watch only once the reader admits it (`DisposeQueue::push`), never
    /// here, ahead of an ordering that may refuse it.
    pub(super) by_source_timestamp: bool,
}

impl LocalOwnership {
    /// The ownership gate of one binding: arbitrate `writer`'s samples and
    /// lifecycle changes in the shared table, on the writer's thread, before
    /// the ring push, as the network path does in `process_admitted` and
    /// `on_dispose_from_writer`.
    fn gate_for(&self, writer: [u8; 16], key_of: &KeyOf) -> rt::SampleGate {
        // Weak: the gate lives in the WRITER's merger, as long as the writer;
        // the reader's table must not live that long after the reader. A
        // dropped reader's registration is tombstoned and its gate no longer
        // asked; `true` for the window in between.
        let registrations = Arc::downgrade(&self.registrations);
        let key_of = Arc::clone(key_of);
        let deadlines = self.deadlines.clone().filter(|_| !self.by_source_timestamp);
        Arc::new(
            move |entry: &rt::IndexEntry, bytes: &[u8], key: Option<[u8; 16]>| -> bool {
                let Some(registrations) = registrations.upgrade() else {
                    return true;
                };
                let seq = u64::from(entry.seq);
                let kind = match entry.lifecycle_bits() {
                    0 => {
                        // The writer's own key hash when it supplied one; the
                        // bytes otherwise (a history replay).
                        return match key.or_else(|| key_of(bytes, entry.cdr_version)) {
                            Some(key) => registrations.admit_sample(writer, key, seq),
                            // The reader cannot decode it either: nothing to
                            // arbitrate.
                            None => true,
                        };
                    }
                    1 => DisposeKind::Disposed,
                    2 => DisposeKind::Unregistered,
                    _ => DisposeKind::DisposedUnregistered,
                };
                match bytes.get(..16).and_then(|b| <[u8; 16]>::try_from(b).ok()) {
                    Some(key) => {
                        let visible = registrations.admit_lifecycle(writer, key, seq, kind);
                        if visible && kind != DisposeKind::Unregistered {
                            if let Some(deadlines) =
                                deadlines.as_ref().and_then(std::sync::Weak::upgrade)
                            {
                                deadlines.remove_instance(InstanceHandle::new(key));
                            }
                        }
                        visible
                    }
                    None => true,
                }
            },
        )
    }
}

impl ReaderBindings {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        primary: Arc<rt::IndexRing>,
        network: Option<Arc<rt::IndexRing>>,
        history_room: Option<Arc<super::admission::HistoryRoom>>,
        ring_capacity: usize,
        status_condition: &Arc<StatusCondition>,
        filter: Option<rt::SampleFilter>,
        ownership: LocalOwnership,
        observer: Option<Arc<rt::DeliveryObserver>>,
        door: Option<Arc<dyn rt::ReaderDoor>>,
        room_wait: Arc<super::admission::RoomWait>,
        local_hold: u8,
        capture_identity: bool,
        access_gate: Option<Arc<super::coherent_barrier::CoherentPresentationBarrier>>,
    ) -> Self {
        let ordered_merge = access_gate
            .as_ref()
            .is_some_and(|gate| gate.local_order().is_some());
        let notify_primary: Arc<dyn Fn() + Send + Sync> = {
            let status = Arc::clone(status_condition);
            Arc::new(move || status.raise_data_available(WakeWord::Primary.index()))
        };
        let notify_extra: Arc<dyn Fn() + Send + Sync> = {
            let status = Arc::clone(status_condition);
            Arc::new(move || status.raise_data_available_shared(WakeWord::Extra.index()))
        };
        Self {
            primary,
            local_ack_identity: std::sync::OnceLock::new(),
            network,
            history_room,
            ring_capacity,
            notify_primary,
            notify_extra,
            entries: Mutex::new(Vec::new()),
            extra_rings: AtomicUsize::new(usize::from(ordered_merge)),
            filter,
            ownership,
            observer,
            door,
            consumer_gate: ConsumerGate::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            after_order_forget: Mutex::new(None),
            room_wait,
            local_hold,
            local_keys: capture_identity
                .then(|| Arc::new(Mutex::new(std::collections::HashMap::new()))),
            order_status: ordered_merge.then(|| Arc::downgrade(status_condition)),
            order_registered: std::sync::OnceLock::new(),
            group_replay: access_gate.as_ref().is_some_and(|gate| gate.group_scope()),
            access_gate,
        }
    }

    pub(super) fn coherent_subscriber(&self) -> Option<usize> {
        let gate = self.access_gate.as_ref()?;
        gate.group_scope().then_some(Arc::as_ptr(gate) as usize)
    }

    pub(super) fn local_read_order(&self) -> Option<&super::local_order::LocalReadOrder> {
        let order = self.access_gate.as_ref()?.local_order()?;
        self.order_registered.get_or_init(|| {
            if let Some(status) = &self.order_status {
                order.register_reader(
                    self as *const Self as usize,
                    status.clone(),
                    Arc::downgrade(&self.room_wait),
                );
            }
        });
        Some(order)
    }

    /// The depth of the access bracket an incoming local coherent set must
    /// wait for, `None` when this reader's Subscriber does not hold
    /// publication (no Subscriber, or an access scope other than GROUP).
    /// Read by the writer's coordinator through `ReaderDoor::bracket_depth`.
    pub(super) fn coherent_bracket_depth(&self) -> Option<u32> {
        let gate = self.access_gate.as_ref()?;
        gate.group_scope().then(|| gate.access_depth())
    }

    /// A local coherent set is waiting for this reader's access bracket to
    /// close: ask the writers' coordinators to deliver again. Called by the
    /// barrier once the bracket's `end_access` is over (`publish`).
    pub(super) fn retry_local_groups(&self) {
        let mergers: Vec<_> = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|binding| binding.merger.upgrade())
            .collect();
        for merger in mergers {
            merger.wake_local_group();
        }
    }

    #[inline]
    fn has_pending_local_replay(&self) -> bool {
        self.group_replay && self.pending_group_replay()
    }

    #[cold]
    #[inline(never)]
    fn pending_group_replay(&self) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|binding| {
                binding.merger.upgrade().is_some_and(|merger| {
                    merger.has_pending_replay(ReaderId::from_ring(&binding.ring))
                })
            })
    }

    fn local_capture(&self, entry: &rt::IndexEntry) -> Option<LocalCapture> {
        self.local_keys.as_ref().and_then(|keys| {
            keys.lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&entry.handle)
                .copied()
        })
    }

    pub(super) fn local_key(&self, entry: &rt::IndexEntry) -> Option<[u8; 16]> {
        self.local_capture(entry).map(|capture| capture.key)
    }

    /// The reader's ring consumer gate (see the field).
    #[inline]
    pub(super) fn consumer_gate(&self) -> &ConsumerGate {
        &self.consumer_gate
    }

    /// Whether the reader is being torn down (see `closed`). Read under the
    /// consumer gate.
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(super) fn set_ack_identity(&self, guid: [u8; 16], volatile: bool) {
        let _ = self.local_ack_identity.set((guid, volatile));
    }

    /// Register this reader with `merger`, creating the binding's ring.
    ///
    /// Idempotent per merger: the ring-pointer dedup inside
    /// `TopicMerger::add_reader` cannot catch re-binds anymore (every
    /// bind would present a fresh ring), so binding identity lives
    /// here. The dedup only counts bindings whose merger is still
    /// alive: a dead writer's merger address can be reused by a new
    /// allocation, and matching it would silently skip the new writer.
    pub(super) fn bind(&self, merger: &Arc<rt::TopicMerger>) {
        let _notices = super::notices::Delivering::enter();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        if entries
            .iter()
            .any(|b| b.merger.upgrade().is_some_and(|m| Arc::ptr_eq(&m, merger)))
        {
            log::debug!("[ReaderBindings] merger already bound, ignoring duplicate bind");
            return;
        }

        let primary_taken = entries.iter().any(|b| Arc::ptr_eq(&b.ring, &self.primary));
        // The ring decides the wake word: the primary ring's merger is
        // alone on `WakeWord::Primary`, every other merger shares
        // `WakeWord::Extra`.
        let (ring, notify) = if primary_taken {
            (
                Arc::new(rt::IndexRing::with_capacity(self.ring_capacity)),
                &self.notify_extra,
            )
        } else {
            (Arc::clone(&self.primary), &self.notify_primary)
        };

        entries.push(RingBinding {
            merger: Arc::downgrade(merger),
            ring: Arc::clone(&ring),
            writer_guid: merger.writer().map(|w| w.guid),
        });
        // Publish the extra ring BEFORE add_reader: the TRANSIENT_LOCAL
        // history replay inside add_reader pushes into this ring, and
        // the pump must already route through the merge path when those
        // entries land.
        if primary_taken {
            self.extra_rings.fetch_add(1, Ordering::Release);
        }

        // An EXCLUSIVE reader arbitrates the writer behind this merger like
        // a remote one, under the identity and strength its builder gave
        // the merger.
        // Every reader learns the instances the writer holds, which it asks
        // before declaring one without writers; an EXCLUSIVE reader also
        // arbitrates the writer through a gate.
        let gate = merger.writer().and_then(|writer| {
            let registrations = &self.ownership.registrations;
            registrations.add_local_holder(writer.instances.clone());
            let key_of = self.ownership.key_of.as_ref()?;
            registrations
                .lock()
                .add_local_writer(writer.guid, writer.strength, merger);
            Some(self.ownership.gate_for(writer.guid, key_of))
        });
        let gate = if let Some(keys) = self.local_keys.as_ref() {
            let keys = Arc::clone(keys);
            let deadlines = self.ownership.deadlines.clone();
            let writer_guid = merger.writer().map(|writer| writer.guid);
            Some(Arc::new(
                move |entry: &rt::IndexEntry, bytes: &[u8], key: Option<[u8; 16]>| {
                    if gate.as_ref().is_some_and(|gate| !gate(entry, bytes, key)) {
                        return false;
                    }
                    if entry.lifecycle_bits() == 0 {
                        let mut keys = keys.lock().unwrap_or_else(|e| e.into_inner());
                        let key = key.unwrap_or([0; 16]);
                        keys.insert(entry.handle, LocalCapture { key, writer_guid });
                        drop(keys);
                        if let Some(watch) = deadlines.as_ref().and_then(Weak::upgrade) {
                            watch.on_sample(InstanceHandle::new(key));
                        }
                    }
                    true
                },
            ) as rt::SampleGate)
        } else {
            gate
        };
        let registration = rt::MergerReader::with_filter(
            Arc::clone(&ring),
            Arc::clone(notify),
            self.filter.clone(),
        )
        .gated(gate)
        .observed(self.observer.clone())
        .with_door(self.door.clone())
        .with_ack_identity(self.local_ack_identity.get().copied());
        if !merger.add_reader(registration) {
            // Merger already had this exact ring (only reachable for
            // the primary ring via an out-of-band registration); roll
            // the binding back so Drop does not double-tombstone. Every
            // registration of a reader ring in the tree goes through this
            // function, so a pre-existing one carries this reader's own
            // filter; an unfiltered registration of a filtered reader's
            // ring cannot arise here.
            entries.pop();
            if primary_taken {
                self.extra_rings.fetch_sub(1, Ordering::Release);
            }
        }
    }

    /// The writer identity of the PRIMARY ring's one merger registration
    /// (DDS v1.4 Sec.2.2.3.17 tie-break, BY_SOURCE_TIMESTAMP only): `None`
    /// before any local writer has bound to it, or once that writer has
    /// died. The primary ring carries at most one local writer at a time
    /// (the first `bind` claims it; every later one gets its own fresh
    /// ring, see `bind`'s doc), so this is unambiguous for the crown
    /// single-ring (K==1) fast path and `pump_pending_gated`'s unmerged
    /// loop, both of which call it once per pump: without it, a local
    /// sample decoded there would report `writer_guid: None`
    /// (`prepare_sample_dropping`), so two different writers tied on
    /// source timestamp -- one local, one remote, or two local ones on
    /// different readers -- would NOT resolve the tie the same way on
    /// every reader. Looked up fresh each call (one lock, one Weak
    /// upgrade): callers gate this behind BY_SOURCE_TIMESTAMP, so
    /// BY_RECEPTION_TIMESTAMP never pays for it.
    ///
    /// The K>1 merge path (`pump_merge_locked`) does the same lookup
    /// itself, widened to every ring it drains (its own `writer_guids`,
    /// aligned index-for-index with its `rings`), rather than calling this
    /// method: a K>1 drain can carry more than one local writer at once,
    /// which this method -- scoped to the ONE primary ring -- cannot name.
    /// Both paths feed `admit_lifecycle_entry`'s local dispose/unregister
    /// construction the same looked-up identity as the ordinary samples
    /// around it, so a local writer's dispose/unregister ties the same way
    /// on every reader too.
    pub(super) fn primary_writer_guid(&self) -> Option<[u8; 16]> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .first()
            .and_then(|binding| binding.writer_guid)
    }

    /// True when at least one binding drains a non-primary ring.
    #[inline]
    fn has_extra_rings(&self) -> bool {
        self.extra_rings.load(Ordering::Acquire) != 0
    }

    #[inline]
    fn network_ready(&self) -> bool {
        self.network.as_ref().is_some_and(|ring| !ring.is_empty())
    }

    #[inline]
    fn needs_merge(&self) -> bool {
        self.has_extra_rings() || self.network_ready()
    }
}

/// Static projection policy for the shared reader take path. Keeping the
/// policy generic lets LLVM monomorphize the data-only path back to its
/// pre-SampleInfo cache operations while the metadata path retains the full
/// sample.
trait CacheTakeProjection<T> {
    type Output;

    /// Whether an accessor using this projection is STRUCTURALLY unable to
    /// report an instance-state change, and must therefore announce the
    /// queued transitions when it observes the reader idle.
    ///
    /// A projection that yields `T` has no field for an instance state, so
    /// leaving the transitions unannounced keeps DATA_AVAILABLE raised with
    /// nothing its caller can do about it - a 100% CPU wait/take loop. A
    /// projection that yields the full sample CAN report it and must not
    /// announce, or it would settle a wake-up it is about to honour.
    ///
    /// Compile-time so the crown path carries no runtime test for it.
    const ANNOUNCES_TRANSITIONS: bool;

    fn project(sample: CachedSample<T>) -> Self::Output;

    // The takes below hand out the front sample unless `fits` refuses its
    // data; a refused sample stays in the cache, and the refusal is the
    // error. An accessor that refuses nothing passes an `Infallible` gate.
    fn take<E, G>(cache: &SampleCache<T>, fits: &G) -> std::result::Result<Option<Self::Output>, E>
    where
        G: Fn(&T) -> std::result::Result<(), E>;
    fn push_and_take<E, G>(
        cache: &SampleCache<T>,
        sample: CachedSample<T>,
        fits: &G,
    ) -> std::result::Result<Option<Self::Output>, E>
    where
        G: Fn(&T) -> std::result::Result<(), E>;
    fn push_all_and_take<E, G>(
        cache: &SampleCache<T>,
        first: CachedSample<T>,
        rest: Vec<CachedSample<T>>,
        fits: &G,
    ) -> std::result::Result<Option<Self::Output>, E>
    where
        G: Fn(&T) -> std::result::Result<(), E>;
}

struct DataProjection;

impl<T> CacheTakeProjection<T> for DataProjection {
    type Output = T;
    fn project(sample: CachedSample<T>) -> T {
        sample.data
    }

    /// `take() -> Option<T>` has nowhere to put an instance state.
    const ANNOUNCES_TRANSITIONS: bool = true;

    #[inline(always)]
    fn take<E, G>(cache: &SampleCache<T>, fits: &G) -> std::result::Result<Option<T>, E>
    where
        G: Fn(&T) -> std::result::Result<(), E>,
    {
        cache.take_if_with(fits, |sample| sample.data)
    }

    #[inline(always)]
    fn push_and_take<E, G>(
        cache: &SampleCache<T>,
        sample: CachedSample<T>,
        fits: &G,
    ) -> std::result::Result<Option<T>, E>
    where
        G: Fn(&T) -> std::result::Result<(), E>,
    {
        cache.push_and_take_if_with(sample, fits, |taken| taken.data)
    }

    #[inline(always)]
    fn push_all_and_take<E, G>(
        cache: &SampleCache<T>,
        first: CachedSample<T>,
        rest: Vec<CachedSample<T>>,
        fits: &G,
    ) -> std::result::Result<Option<T>, E>
    where
        G: Fn(&T) -> std::result::Result<(), E>,
    {
        cache.push_all_and_take_if_with(first, rest, fits, |taken| taken.data)
    }
}

struct FullSampleProjection;

impl<T> CacheTakeProjection<T> for FullSampleProjection {
    type Output = CachedSample<T>;
    fn project(sample: CachedSample<T>) -> CachedSample<T> {
        sample
    }

    /// `take_with_info()` RETURNS the transition, so announcing it here
    /// would settle a wake-up the very next line honours.
    const ANNOUNCES_TRANSITIONS: bool = false;

    #[inline(always)]
    fn take<E, G>(
        cache: &SampleCache<T>,
        fits: &G,
    ) -> std::result::Result<Option<CachedSample<T>>, E>
    where
        G: Fn(&T) -> std::result::Result<(), E>,
    {
        cache.take_if_with(fits, |sample| sample)
    }

    #[inline(always)]
    fn push_and_take<E, G>(
        cache: &SampleCache<T>,
        sample: CachedSample<T>,
        fits: &G,
    ) -> std::result::Result<Option<CachedSample<T>>, E>
    where
        G: Fn(&T) -> std::result::Result<(), E>,
    {
        cache.push_and_take_if_with(sample, fits, |taken| taken)
    }

    #[inline(always)]
    fn push_all_and_take<E, G>(
        cache: &SampleCache<T>,
        first: CachedSample<T>,
        rest: Vec<CachedSample<T>>,
        fits: &G,
    ) -> std::result::Result<Option<CachedSample<T>>, E>
    where
        G: Fn(&T) -> std::result::Result<(), E>,
    {
        cache.push_all_and_take_if_with(first, rest, fits, |taken| taken)
    }
}

/// A typed DDS DataReader that subscribes to samples on a topic.
///
/// `DataReader<T>` receives data samples of type `T` from matching [`DataWriter<T>`](crate::DataWriter)
/// instances. It deserializes incoming CDR-encoded data and provides access via `try_take()`.
///
/// # Type Parameter
///
/// * `T` - The data type, must implement [`DDS`](crate::dds::DDS) (derive with `#[derive(hdds::DDS)]`)
///
/// # Example
///
/// ```rust,no_run
/// use hdds::{Participant, QoS, Result, DDS};
///
/// #[derive(DDS, Debug)]
/// struct Temperature {
///     sensor_id: u32,
///     value: f32,
/// }
///
/// fn main() -> Result<()> {
///     let participant = Participant::builder("temp_monitor")
///         .domain_id(0)
///         .build()?;
///
///     let reader = participant.create_reader::<Temperature>(
///         "sensors/temp",
///         QoS::reliable(),
///     )?;
///
///     loop {
///         if let Some(sample) = reader.try_take()? {
///             println!("Sensor {} = {} degC", sample.sensor_id, sample.value);
///         }
///     }
/// }
/// ```
///
/// # Thread Safety
///
/// `DataReader<T>` is `Send + Sync` when `T` is `Send + Sync`.
///
/// # See Also
///
/// - `ReaderBuilder` - For advanced configuration
/// - [`DataWriter`](crate::DataWriter) - Publishing counterpart
pub struct DataReader<T: DDS> {
    topic: String,
    qos: QoS,
    ring: Arc<rt::IndexRing>,
    /// Sample cache for read/take operations (DDS standard API).
    cache: SampleCache<T>,
    #[allow(dead_code)]
    registry: Option<Arc<TopicRegistry>>,
    status_condition: Arc<StatusCondition>,
    /// Cumulative SAMPLE_REJECTED status, the same `Arc` the
    /// `ReaderSubscriber` writes to in `report_sample_rejected`: wired up
    /// once in `ReaderBuilder::build` exactly like `status_condition`, so
    /// `get_sample_rejected_status` reads the subscriber's own writes.
    sample_rejected: Arc<Mutex<SampleRejectedStatus>>,
    /// SAMPLE_LOST, shared with the subscriber like `sample_rejected`: the
    /// samples of a coherent set it discards because the set can never be
    /// whole (`ReaderSubscriber::report_sample_lost`).
    sample_lost: Arc<Mutex<crate::dds::listener::SampleLostStatus>>,
    /// The network subscriber's and the local doors' share of
    /// `ReaderStats::drops` (the history's own is `SampleCache::dropped`).
    dropped: Arc<AtomicU64>,
    /// The subscriber whose `report_sample_lost` this reader's own
    /// SAMPLE_LOST report (`report_parked_heads_lost`) calls into, so a
    /// loss the K>1 merge finds has the one door: the count, the
    /// condition AND the listener, never a second, listener-less copy of
    /// them. A strong `Arc`, not `Weak`: a participant-less (pure
    /// intra-process) reader registers nowhere that would otherwise keep
    /// its subscriber alive, so a `Weak` here would already be dead by
    /// the time a merge failure needs it (confirmed by
    /// `a_sibling_that_also_fails_to_decode_is_the_one_thing_sample_lost_counts`
    /// going silent with one). No cycle: `ReaderSubscriber` holds no
    /// reference back to this reader.
    ///
    /// `Option`, cleared explicitly by `Drop` alongside `_subscriber_token`
    /// (before the cache/ring teardown that follows): a room's places
    /// given back there schedules its own weak-subscriber retry
    /// (`HistoryRoom::came_back`, off this thread), and this strong `Arc`
    /// kept alive past that point let it upgrade and commit a waiting
    /// coherent set after the reader's own ring had already been drained
    /// -- a leaked slab handle in a ring with no remaining consumer.
    /// Clearing this first gives the same dead-weak-upgrade safety as the
    /// retry closure's weak reference.
    subscriber_for_sample_lost: Option<Arc<super::subscriber::ReaderSubscriber<T>>>,
    /// Cumulative SUBSCRIPTION_MATCHED status, the same `Arc` the match
    /// callback (`ReaderBuilder::build`) writes to on every match/unmatch,
    /// from either source that can report one for this reader (the SEDP
    /// registry or `domain_registry::LocalMatchStatus`): wired up once at
    /// build time exactly like `sample_rejected`, so
    /// `get_subscription_matched_status` reads the callback's own writes.
    subscription_matched: Arc<Mutex<crate::dds::listener::SubscriptionMatchedStatus>>,
    /// REQUESTED_INCOMPATIBLE_QOS, shared with the incompatible-QoS
    /// callback like `subscription_matched`.
    requested_incompatible_qos: Arc<Mutex<RequestedIncompatibleQosStatus>>,
    /// BindToken for intra-process auto-binding (unregisters on drop)
    _bind_token: Option<BindToken>,
    /// Engine fanout registration (unregisters this exact reader on drop).
    _subscriber_token: Option<SubscriberToken>,
    /// RELIABLE-only heartbeat handler registration (unregisters this
    /// exact handler from `TopicRegistry::heartbeat_handlers` on drop).
    /// `None` for VOLATILE readers.
    _heartbeat_token: Option<crate::engine::HeartbeatHandlerToken>,
    /// Security plugin suite for decryption (DDS Security v1.1)
    #[cfg(feature = "security")]
    #[allow(dead_code)]
    security: Option<Arc<crate::security::SecurityPluginSuite>>,
    /// The reader's listener slot, shared with its subscriber, its
    /// intra-process delivery observers and its match callbacks
    /// (deadline missed, etc. here). See [`DataReader::set_listener`].
    listener: Arc<ReaderListenerSlot<T>>,
    /// Match notification token (fires on_subscription_matched; unregisters on drop)
    _match_token: Option<crate::dds::match_notification::MatchToken>,
    /// This reader's SUBSCRIPTION_MATCHED bookkeeping for a peer
    /// `_match_token` cannot see -- a peer with no wire path on either
    /// side, matched only through `domain_registry::LocalMatchStatus`.
    /// `get_matched_publications` reads both; `None` for a reader with no
    /// participant.
    _match_status: Option<Arc<crate::dds::domain_registry::LocalMatchStatus>>,
    /// The retirement of this reader's SEDP announcement, run by `Drop`
    /// (`SedpRetirement`). `None` for a reader with no participant.
    sedp_retirement: Option<crate::dds::participant::SedpRetirement>,
    /// Retires this reader's WriterProxies from the participant's registry
    /// on drop. Declared after `_match_token` so the match entry, whose
    /// peer callback creates those proxies, is gone first.
    _proxy_lease: Option<crate::core::reader::ReaderProxyLease>,
    /// This reader's per-instance DEADLINE watches (DDS v1.4 Sec.2.2.3.7),
    /// on the participant's liveliness scheduler: `None` with an infinite
    /// deadline (the default) -- zero cost, nothing allocated, nothing
    /// touched on the sample-arrival hot path. See
    /// `crate::dds::liveliness::deadline` for the design.
    deadlines: Option<Arc<crate::dds::liveliness::ReaderDeadlines>>,
    /// Per-instance TIME_BASED_FILTER enforcement (DDS spec 2.2.2.4.2.11),
    /// for a reader ordering by source timestamp (every other reader's filter
    /// is the cache's stage).
    pub(super) time_filter_checkers: Arc<Mutex<HashMap<InstanceHandle, TimeBasedFilterChecker>>>,
    /// Effective lifespan for sample expiration (DDS spec 2.2.2.4.2.20).
    ///
    /// Stored as nanoseconds in an `Arc<AtomicU64>`; `u64::MAX` means
    /// "infinite / disabled". Initialized from the reader's own QoS, then
    /// tightened to `min(self, writer_lifespan)` whenever a writer matches
    /// so that writer-announced lifespans filter samples even when the
    /// reader did not request a lifespan of its own. The `Arc` is shared
    /// with the match-notification registry which performs the tightening.
    lifespan_nanos: Arc<AtomicU64>,
    /// This reader's own lifespan (ns, `u64::MAX` = infinite), from its QoS
    /// and nothing else: immutable, and independent of `lifespan_nanos`,
    /// which writers tighten.
    ///
    /// A sample whose writer is known expires by `min(this, that writer's
    /// lifespan)` (`lifespan_of`): LIFESPAN is a DataWriter QoS (DDS v1.4
    /// Sec.2.2.3.16), and one writer's lifespan must not expire another
    /// writer's samples. `lifespan_nanos`, the smallest over every matched
    /// writer, stays for the samples whose writer is not known.
    own_lifespan_nanos: u64,
    /// Registry epoch observed at the last writer-lifespan probe
    /// (perf epoch-gate for the hot take() path).
    ///
    /// While `lifespan_nanos` is still `u64::MAX`, `pump_ring_to_cache`
    /// must keep checking the registry for a late-registered writer
    /// Lifespan (startup-race close, DDS v1.4 2.2.3.16). Doing the probe
    /// on every take costs an RwLock read + topic-string hash + map
    /// lookup. Instead we record `TopicRegistry::writer_lifespan_epoch()`
    /// at each probe; while the epoch is unchanged the map cannot have
    /// changed, so the previous answer (including "no finite lifespan
    /// known") is still valid and the probe is skipped -- steady state is
    /// one Acquire load + compare. `u64::MAX` = "never probed" sentinel
    /// (registry epochs start at 0 and only increment). Same pattern as
    /// the writer-side negotiated-CdrVersion generation cache.
    lifespan_probe_epoch: AtomicU64,
    /// The lifespans of the remote writers that left while samples of
    /// theirs may still be in the network ring (`DepartedLifespans`): the
    /// participant's record of a writer goes with the writer, these samples
    /// still expire by it.
    departed_lifespans: Arc<super::subscriber::DepartedLifespans>,
    /// Shared dispose event queue from ReaderSubscriber. It owns the
    /// writes of `WakeWord::Dispose`, the dispose producer's part of the
    /// idle re-check in `clear_data_available_if_idle`.
    dispose_events: Arc<DisposeQueue>,
    /// Per-writer ring bindings (intra-process fan-out), recorded at
    /// bind time by both `bind_to_writer` and the domain auto-bind
    /// callback (which shares this handle and can fire for writers
    /// created after build). Each binding owns its own SPSC ring
    /// (the first binding reuses `ring`); `Drop` tombstones every binding in
    /// its still-alive merger.
    bindings: Arc<ReaderBindings>,
    /// The presentation barrier of the Subscriber this reader was built
    /// with (`ReaderBuilder::subscriber`), coherent or not: the reader asks
    /// it only whether the Subscriber's access scope is GROUP and an access
    /// bracket is open (`consume`).
    access_gate: Option<Arc<CoherentPresentationBarrier>>,
    /// The queues of this reader's ordered listener calls (SAMPLE_REJECTED
    /// of the network and local paths, SAMPLE_LOST): closed when it is
    /// dropped, so nothing queued then reaches its listener.
    listener_queues: Vec<Arc<super::notices::Ordered>>,
    /// The liveliness of the writers it matches (DDS v1.4 Sec.2.2.3.11);
    /// None without a participant liveliness.
    liveliness: Option<Arc<crate::dds::liveliness::ReaderLiveliness>>,
    /// `bindings.local_hold`, read once per local sample on the take path
    /// without the indirection.
    local_hold: u8,
    /// A RELIABLE reader: its local writers may wait for room, and a pop of
    /// a full local ring wakes them (`slot_freed`).
    wakes_writers: bool,
    /// Test seam: runs ONCE, inside the window between "every source
    /// observed empty" and the DATA_AVAILABLE clear that follows
    /// (`clear_data_available_if_idle`). A test interposes a concurrent
    /// write there deterministically instead of racing a thread against
    /// a window a few dozen nanoseconds wide. One-shot so the take() that
    /// later drains the interposed sample does not re-fire it.
    #[cfg(test)]
    idle_clear_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Test seam: runs ONCE, inside `pump_merge` between the pop of the
    /// entry about to be deposited and the deposit itself, so a test
    /// can replay another thread's clear while that entry is in flight
    /// (out of its ring, not yet in the cache). One-shot for the same
    /// reason as `idle_clear_hook`.
    #[cfg(test)]
    pump_deposit_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    _phantom: core::marker::PhantomData<T>,
}

/// The lifespan (ns, `u64::MAX` for none) a sample of `writer_guid` expires
/// by: this reader's own and that writer's (`own`); without a known writer,
/// the smallest over every matched writer (`matched`).
fn effective_lifespan(
    registry: Option<&TopicRegistry>,
    departed: &super::subscriber::DepartedLifespans,
    own: u64,
    matched: &AtomicU64,
    writer_guid: Option<&[u8; 16]>,
) -> u64 {
    let Some(writer_guid) = writer_guid else {
        return matched.load(Ordering::Relaxed);
    };
    let writer = registry
        .and_then(|registry| registry.writer_lifespan(writer_guid))
        .or_else(|| departed.lifespan_of(writer_guid))
        .unwrap_or(u64::MAX);
    own.min(writer)
}

impl<T: DDS> DataReader<T> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        topic: String,
        qos: QoS,
        ring: Arc<rt::IndexRing>,
        registry: Option<Arc<TopicRegistry>>,
        status_condition: Arc<StatusCondition>,
        sample_rejected: Arc<Mutex<SampleRejectedStatus>>,
        sample_lost: Arc<Mutex<crate::dds::listener::SampleLostStatus>>,
        dropped: Arc<AtomicU64>,
        subscriber_for_sample_lost: Arc<super::subscriber::ReaderSubscriber<T>>,
        subscription_matched: Arc<Mutex<crate::dds::listener::SubscriptionMatchedStatus>>,
        requested_incompatible_qos: Arc<Mutex<RequestedIncompatibleQosStatus>>,
        bind_token: Option<BindToken>,
        subscriber_token: Option<SubscriberToken>,
        heartbeat_token: Option<crate::engine::HeartbeatHandlerToken>,
        listener: Arc<ReaderListenerSlot<T>>,
        match_token: Option<crate::dds::match_notification::MatchToken>,
        match_status: Option<Arc<crate::dds::domain_registry::LocalMatchStatus>>,
        proxy_lease: Option<crate::core::reader::ReaderProxyLease>,
        #[cfg(feature = "security")] security: Option<Arc<crate::security::SecurityPluginSuite>>,
        dispose_events: Arc<DisposeQueue>,
        instances: Arc<InstanceTable>,
        lifespan_nanos: Arc<AtomicU64>,
        departed_lifespans: Arc<super::subscriber::DepartedLifespans>,
        bindings: Arc<ReaderBindings>,
        access_gate: Option<Arc<CoherentPresentationBarrier>>,
        listener_queues: Vec<Arc<super::notices::Ordered>>,
        sedp_retirement: Option<crate::dds::participant::SedpRetirement>,
        liveliness: Option<Arc<crate::dds::liveliness::ReaderLiveliness>>,
        deadlines: Option<Arc<crate::dds::liveliness::ReaderDeadlines>>,
    ) -> Self {
        // From this reader's QoS, never from `lifespan_nanos`: the match
        // registry's catch-up runs before this constructor and may already
        // have tightened that cell to a matched writer's lifespan.
        let own_lifespan_nanos = if qos.lifespan.is_infinite() {
            u64::MAX
        } else {
            u64::try_from(qos.lifespan.duration.as_nanos()).unwrap_or(u64::MAX)
        };

        // Determine cache size from history QoS
        // A BEST_EFFORT KEEP_ALL history discards its old values at its
        // RESOURCE_LIMITS (DDS v1.4 Sec.2.2.3.18): its cache keeps the newest
        // `max_samples_per_instance` of each instance and the newest
        // `max_samples` across them. A RELIABLE one holds places for what it
        // keeps and evicts none of them.
        let (cache_size, cache_total) = match qos.history {
            History::KeepLast(depth) => (depth as usize, usize::MAX),
            History::KeepAll if super::admission::HistoryRoom::discards_old_values(&qos) => (
                qos.resource_limits.max_samples_per_instance,
                qos.resource_limits.max_samples,
            ),
            History::KeepAll => (1024, usize::MAX), // Default for KeepAll
        };

        // A KEEP_LAST cache keeps the newest samples rather than refuse
        // them: it holds no place of the network room. It still counts the
        // samples of each instance it holds when the room bounds instances.
        let cache_room = bindings
            .history_room
            .as_ref()
            .filter(|room| matches!(qos.history, History::KeepAll) || room.counts_instances())
            .map(Arc::clone);
        let local_hold = bindings.local_hold;
        let wakes_writers = matches!(qos.reliability, crate::dds::qos::Reliability::Reliable);
        let time_filter_checkers = Arc::clone(&subscriber_for_sample_lost.time_filter_checkers);
        let filter_waker = subscriber_for_sample_lost.filter_waker.clone();
        let time_based_filter = qos.time_based_filter;
        // A reader that presents its samples in an order (ordered access) or
        // in sets (coherent access) cannot let one wait and show it apart
        // from the rest: the order is told its place when the sample is
        // pumped, and a set is presented whole (DDS v1.4 Sec.2.2.3.6). It
        // shows what finds its instance's window open and drops what finds
        // it closed, as the strict rule does; nothing is shown late, outside
        // its set or its place.
        let park_blocked = qos.presentation.ordered_access || qos.presentation.coherent_access;
        let lifespan_registry = registry.clone();
        let lifespan_departed = Arc::clone(&departed_lifespans);
        let lifespan_matched = Arc::clone(&lifespan_nanos);
        let cache = SampleCache::with_instances(cache_size, instances)
            .with_total(cache_total)
            .with_room(cache_room)
            .with_time_based_filter(
                time_based_filter,
                !park_blocked,
                filter_waker.clone().map(|waker| {
                    Arc::new(move |handle, at| waker.arm(handle, at))
                        as Arc<dyn Fn(InstanceHandle, std::time::Instant) + Send + Sync>
                }),
                Some(Arc::new(move |writer: Option<&[u8; 16]>| {
                    effective_lifespan(
                        lifespan_registry.as_deref(),
                        &lifespan_departed,
                        own_lifespan_nanos,
                        &lifespan_matched,
                        writer,
                    )
                })),
            );
        if let (Some(waker), Some(parked)) = (filter_waker.as_ref(), cache.parked_probe()) {
            waker.set_parked(parked);
        }
        Self {
            local_hold,
            wakes_writers,
            topic,
            qos,
            ring,
            cache,
            time_filter_checkers,
            registry,
            status_condition,
            sample_rejected,
            sample_lost,
            dropped,
            subscriber_for_sample_lost: Some(subscriber_for_sample_lost),
            subscription_matched,
            requested_incompatible_qos,
            _bind_token: bind_token,
            _subscriber_token: subscriber_token,
            _heartbeat_token: heartbeat_token,
            #[cfg(feature = "security")]
            security,
            listener,
            _match_token: match_token,
            _match_status: match_status,
            sedp_retirement,
            _proxy_lease: proxy_lease,
            deadlines,
            own_lifespan_nanos,
            lifespan_nanos,
            lifespan_probe_epoch: AtomicU64::new(u64::MAX),
            departed_lifespans,
            dispose_events,
            bindings,
            access_gate,
            listener_queues,
            liveliness,
            #[cfg(test)]
            idle_clear_hook: Mutex::new(None),
            #[cfg(test)]
            pump_deposit_hook: Mutex::new(None),
            _phantom: core::marker::PhantomData,
        }
    }

    #[must_use]
    pub fn qos(&self) -> &QoS {
        &self.qos
    }

    /// The lifespan this reader keeps for `writer`, which left with samples
    /// possibly still in its ring.
    #[cfg(test)]
    pub(crate) fn departed_lifespan_of(&self, writer: &[u8; 16]) -> Option<u64> {
        self.departed_lifespans.lifespan_of(writer)
    }

    #[must_use]
    pub fn topic_name(&self) -> &str {
        &self.topic
    }

    /// Check if requested deadline was missed and fire listener callback.
    ///
    /// Called at the start of each take()/read(): re-evaluate every
    /// instance this reader currently watches for DEADLINE, right now
    /// (DDS v1.4 Sec.2.2.3.7, Sec.2.2.4.1 REQUESTED_DEADLINE_MISSED).
    ///
    /// The participant's liveliness scheduler runs this same
    /// per-instance evaluation continuously (`crate::dds::liveliness::deadline`),
    /// so an application that never calls take()/read() at all, or that
    /// only waits on a WaitSet or a listener, is told too -- this lazy
    /// call only shortens the window on the thread that is making the
    /// call right now, and shares the scheduler's exact evaluation
    /// function and lock, so the two never double-count the same miss.
    pub(super) fn check_requested_deadline(&self) {
        let Some(deadlines) = self.deadlines.as_ref() else {
            return;
        };
        deadlines.check_now();
    }

    /// Install `listener` for the statuses in `mask`, replacing the
    /// current one, or remove it (`None`) -- DDS v1.4 Sec.2.2.2.1.1
    /// `set_listener`.
    ///
    /// Takes effect for every callback of this reader, including those
    /// whose source was registered when the reader was built (match
    /// notifications, intra-process deliveries from writers already bound).
    /// A status outside `mask` is not reported to the listener; for
    /// SAMPLE_REJECTED that also means the status is not consumed by the
    /// listener and stays readable through the StatusCondition.
    ///
    /// Callbacks run on HDDS threads: the router or control thread for
    /// network deliveries and discovery events, and the WRITER's thread
    /// for a sample written by a DataWriter of this process (intra-process
    /// delivery runs inside that `write()`). No lock that this reader's
    /// take / read path takes is held across a callback, so a callback may
    /// `take()` / `read()` this reader. `on_sample_rejected` runs under the
    /// reader's re-entrant rejection-dispatch lock, which serializes
    /// rejection reports: it must not wait for another thread's callback of
    /// this reader.
    ///
    /// Does not wait for callbacks already running: a callback that loaded
    /// the previous listener before this call keeps its own reference and
    /// finishes.
    pub fn set_listener(&self, listener: Option<Arc<dyn DataReaderListener<T>>>, mask: StatusMask) {
        self.listener.set(listener, mask);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn before_next_order_registration(&self, hook: Box<dyn FnOnce() + Send>) {
        let order = self.bindings.local_read_order();
        debug_assert!(
            order.is_some(),
            "only an ordered GROUP reader has a registration to hook"
        );
        match order {
            Some(order) => {
                order.before_next_registration(Arc::as_ptr(&self.bindings) as usize, hook);
            }
            None => log::error!(
                "registration hook dropped: the reader has no ordered GROUP registration"
            ),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn after_next_order_forget(&self, hook: Box<dyn FnOnce() + Send>) {
        *self
            .bindings
            .after_order_forget
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(hook);
    }

    #[must_use]
    pub fn get_status_condition(&self) -> Arc<StatusCondition> {
        Arc::clone(&self.status_condition)
    }

    /// Read this reader's cumulative SAMPLE_REJECTED status (DDS v1.4
    /// Sec.2.2.4.1.9): a ring-full or slab-exhausted admission drop on
    /// this reader's own resource limit, `REJECTED_BY_SAMPLES_LIMIT`.
    ///
    /// Per DDS v1.4 Sec.2.2.4.2.1, reading the status is itself a
    /// "delivery": `total_count_change` in the RETURNED snapshot is the
    /// count since the previous read or listener call, and it resets to 0
    /// internally the moment this call returns, so an immediate second
    /// read reports 0 until the next rejection. `StatusMask::SAMPLE_REJECTED`
    /// on the status condition is cleared in the same critical section as
    /// the snapshot: a rejection that lands after this call's snapshot
    /// takes the state lock after this call's clear and so leaves its bit
    /// raised, never cleared by a read that did not return it. Safe to
    /// call from inside `DataReaderListener::on_sample_rejected` (does not
    /// take the dispatch lock `report_sample_rejected` holds across that
    /// callback).
    #[must_use]
    pub fn get_sample_rejected_status(&self) -> SampleRejectedStatus {
        let mut status = match self.sample_rejected.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let snapshot = status.clone();
        status.total_count_change = 0;
        self.status_condition
            .clear_active_status(StatusMask::SAMPLE_REJECTED);
        snapshot
    }

    /// The LIVELINESS_CHANGED status (DDS v1.4 Sec.2.2.4.1): how many of
    /// the writers this reader matches are alive (`alive_count`) and how
    /// many are not (`not_alive_count`), the changes of both since the last
    /// read or listener call, and the writer that changed it last
    /// (`last_publication_handle`).
    ///
    /// A writer is alive from its match, and stays alive while its lease
    /// is renewed (DDS v1.4 Sec.2.2.3.11): by any traffic of its
    /// participant for AUTOMATIC, by its participant's manual assertions or
    /// data for MANUAL_BY_PARTICIPANT, by its own data for MANUAL_BY_TOPIC.
    /// A writer that leaves the match (deleted, or its participant gone)
    /// is no longer counted. The changes reset to 0 when this returns, and
    /// `StatusMask::LIVELINESS_CHANGED` is cleared on the status condition
    /// (DDS v1.4 Sec.2.2.4.2.1). A reader of no participant (intra-process
    /// transport) reports the default status.
    #[must_use]
    pub fn get_liveliness_changed_status(&self) -> crate::dds::listener::LivelinessChangedStatus {
        self.liveliness
            .as_ref()
            .map(|l| l.status())
            .unwrap_or_default()
    }

    /// The SAMPLE_LOST status (DDS v1.4 Sec.2.2.4.1): the samples of
    /// coherent sets this reader discarded because they can never be whole
    /// (a member a best-effort writer lost, or one a GAP declared
    /// irrelevant, or its writer gone). `total_count_change` resets to 0
    /// when this returns, as for `get_sample_rejected_status`.
    #[must_use]
    pub fn get_sample_lost_status(&self) -> crate::dds::listener::SampleLostStatus {
        let mut status = match self.sample_lost.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let snapshot = status.clone();
        status.total_count_change = 0;
        self.status_condition
            .clear_active_status(StatusMask::SAMPLE_LOST);
        snapshot
    }

    /// Test seam: the shared `Arc` behind `get_sample_lost_status`.
    #[cfg(test)]
    pub(super) fn sample_lost_for_test(
        &self,
    ) -> Arc<Mutex<crate::dds::listener::SampleLostStatus>> {
        Arc::clone(&self.sample_lost)
    }

    /// Test seam: the shared `Arc` behind `get_sample_rejected_status`, so
    /// a test can hand it to a standalone `ReaderSubscriber` (constructed
    /// outside the builder, the way network-admission tests drive a
    /// reader's ring) and observe this reader's getter see that
    /// subscriber's rejections.
    #[cfg(test)]
    pub(super) fn sample_rejected_for_test(&self) -> Arc<Mutex<SampleRejectedStatus>> {
        Arc::clone(&self.sample_rejected)
    }

    /// The REQUESTED_DEADLINE_MISSED status (DDS v1.4 Sec.2.2.2.5.3.22): how
    /// many times no sample was received on an instance within the
    /// requested `deadline` period, piggybacked on `check_requested_deadline`
    /// at the start of each take()/read(). `total_count_change` resets to 0
    /// and `StatusMask::REQUESTED_DEADLINE_MISSED` clears on the status
    /// condition when this returns, as for `get_sample_rejected_status`.
    #[must_use]
    pub fn get_requested_deadline_missed_status(&self) -> RequestedDeadlineMissedStatus {
        self.deadlines
            .as_ref()
            .map_or_else(RequestedDeadlineMissedStatus::default, |d| d.status())
    }

    /// The REQUESTED_INCOMPATIBLE_QOS status (DDS v1.4 Sec.2.2.2.5.3.23): how
    /// many matched writers this reader refused for an incompatible QoS
    /// policy, and the last such policy. Shared with the match registry's
    /// incompatible-QoS callback (`ReaderBuilder::build`) exactly like
    /// `subscription_matched`. Read-and-reset like `get_sample_rejected_status`.
    #[must_use]
    pub fn get_requested_incompatible_qos_status(&self) -> RequestedIncompatibleQosStatus {
        let mut status = self
            .requested_incompatible_qos
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let snapshot = status.clone();
        status.total_count_change = 0;
        self.status_condition
            .clear_active_status(StatusMask::REQUESTED_INCOMPATIBLE_QOS);
        snapshot
    }

    /// The SUBSCRIPTION_MATCHED status (DDS v1.4 Sec.2.2.2.5.3.26): how many
    /// writers this reader has matched, the changes since the last read or
    /// listener call, and the last writer that changed it. Shared with the
    /// match callback (`ReaderBuilder::build`), fed by either source that
    /// can report a match for this reader (the SEDP registry or
    /// `domain_registry::LocalMatchStatus`, for a peer with no wire path on
    /// either side). Read-and-reset like `get_sample_rejected_status`.
    #[must_use]
    pub fn get_subscription_matched_status(
        &self,
    ) -> crate::dds::listener::SubscriptionMatchedStatus {
        let mut status = self
            .subscription_matched
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let snapshot = status.clone();
        status.total_count_change = 0;
        status.current_count_change = 0;
        self.status_condition
            .clear_active_status(StatusMask::SUBSCRIPTION_MATCHED);
        snapshot
    }

    /// GUIDs of the writers currently matched with this reader (DDS v1.4
    /// Sec.2.2.2.5.3.34 `get_matched_publications`). Not a status (no
    /// read-and-reset, no StatusCondition involvement): a live snapshot of
    /// the match registry's and `domain_registry::LocalMatchStatus`'s
    /// matched-peer sets, which are disjoint by construction (see
    /// `ReaderBuilder::build`).
    #[must_use]
    pub fn get_matched_publications(&self) -> Vec<crate::core::discovery::GUID> {
        let mut guids = self
            ._match_token
            .as_ref()
            .map(crate::dds::match_notification::MatchToken::matched_remote_guids)
            .unwrap_or_default();
        if let Some(ref status) = self._match_status {
            guids.extend(status.matched_guids());
        }
        guids
    }

    pub fn bind_to_writer(&self, writer_merger: Arc<rt::TopicMerger>) {
        // A history replayed as it binds is announced once the binding's
        // locks are released (`DeliveryObserver::observe_later`).
        let _replay_notices = super::notices::Delivering::enter();
        self.bindings.bind(&writer_merger);
    }

    /// Take a sample from the reader (legacy API).
    ///
    /// # Deprecated
    /// Use [`take()`](Self::take) instead, which uses the new cache-based
    /// architecture supporting both `read()` and `take()` semantics.
    #[deprecated(since = "0.9.0", note = "use take() instead")]
    pub fn try_take(&self) -> Result<Option<T>> {
        // The same history as every other accessor: the cache keeps the
        // newest `depth` samples of EACH instance (DDS v1.4 Sec.2.2.3.18),
        // and lifespan and TIME_BASED_FILTER apply. Popping the rings
        // directly trimmed them to `depth` entries across all instances.
        // `messages_received` is counted where a sample lands in the
        // history (`SampleCache`), not by the accessor.
        self.take()
    }

    /// Drop DATA_AVAILABLE after this reader observed every source
    /// empty, without losing a push that raced the observation.
    ///
    /// The caller has just seen "nothing pending" (ring pop returned
    /// None and the cache pop returned None, or every ring is empty
    /// after a drain). Clearing DATA_AVAILABLE on that observation is a
    /// check-then-act against every producer, whose sequence is a push
    /// into its source (`IndexRing::push`, head.store Release; or
    /// `DisposeQueue::push`), then a store of its own wake word
    /// (`StatusCondition::raise_data_available`, Release), then the
    /// WaitSet signal. A push that lands between the reader's
    /// observation and its clear would leave a sample in the ring with
    /// DATA_AVAILABLE cleared; `WaitSet::wait` then consumes the driver
    /// bit, sees the condition untriggered, and blocks until the NEXT
    /// write or the timeout. With KeepLast(1) the next write evicts the
    /// stalled sample, so the wake-up is not late, the sample is lost.
    ///
    /// The clear is therefore one `swap` per wake word, each returning
    /// the word's previous value, followed, for the words that were
    /// non-zero, by a re-check of the places that word's producer can
    /// leave work: the rings and then the cache for a ring word, the
    /// owed wake-up for the dispose word. A re-check that finds work
    /// puts the trigger back through
    /// `StatusCondition::re_raise_data_available`, which also re-signals
    /// the WaitSet: a waiter on another thread can have consumed the
    /// producer's driver bit and read the cleared trigger between the
    /// swap and the re-raise, and would otherwise sleep until the next
    /// raise.
    ///
    /// Happens-before argument, per word (`WakeWords` states the same
    /// argument from the condition's side). Producer `i` is the only
    /// writer of RAISED on word `i`; its push P_i is sequenced before
    /// its store D_i = store(RAISED, Release). This reader's clear is
    /// C_i = swap(0, AcqRel) and its re-raise X_i = fetch_or(RERAISED,
    /// AcqRel). If C_i returns a value with RAISED set, that value was
    /// written either by D_i itself or by an X_i that read a value with
    /// RAISED set, hence (by induction along the modification order) an
    /// RMW in the release sequence headed by the latest D_i before it:
    /// every write between D_i and that X_i is a swap or a fetch_or,
    /// and a release sequence continues through read-modify-writes
    /// (C++20 [intro.races]/5). C_i therefore takes its value from D_i
    /// or from a side effect in D_i's release sequence and
    /// synchronizes-with D_i ([atomics.order]/2). P_i happens-before
    /// the re-check R, and R's loads of ring `i`'s head return P_i's
    /// store or a later one (write-read coherence, so the Relaxed loads
    /// in `IndexRing::is_empty` suffice). Earlier pushes by producer `i`
    /// are sequenced before D_i on its side and visible the same way.
    /// If C_i returns zero, producer `i` has not stored since the
    /// previous clear: a D_i later in the modification order overwrites
    /// the zero, the word ends non-zero, and the next trigger read sees
    /// it; nothing to re-raise. The Relaxed pre-load in
    /// `WakeWords::clear` that skips the swap on an already-zero word
    /// reads a zero written by an earlier clear (or the dispose drain);
    /// a D_i it did not see is later than that zero and leaves the word
    /// non-zero by the same argument, and one before it was returned by
    /// the swap that wrote the zero and re-checked then. Nothing here
    /// depends on which producer stored last: each word carries its own
    /// producer's edge, which is what lets that producer use a plain
    /// store. The words with several producers, `WakeWord::Extra` (one
    /// per extra binding, unbounded) and `WakeWord::Network` (the router
    /// thread and, under a coherent presentation barrier, the
    /// application thread), are raised with `fetch_or`, so every write
    /// to them is an RMW and the release sequence headed by any of their
    /// raises reaches the value C reads; that is the argument the shared
    /// status word needed from every producer, confined to the two words
    /// that need it.
    ///
    /// The re-check for a ring word walks EVERY ring, not only ring
    /// `i`: the walk is one function and its cost is Relaxed loads.
    /// Seeing ring `j` non-empty while word `j` was zero is harmless
    /// (producer `j`'s store is in flight and lands on its own); the
    /// re-raise goes to the words that were non-zero, which is the
    /// attribution the next clear needs. A word that reads RERAISED
    /// alone is re-checked too: `DataReader` is `Sync`, and on the K>1
    /// path a second thread's clear can swap this thread's re-raise
    /// away before the take that would have drained the work, so the
    /// second clear must look for that work rather than trust the
    /// first's bookkeeping. On one thread the re-check after a
    /// RERAISED finds nothing (the take that drained it did not clear)
    /// and the word settles.
    ///
    /// The dispose producer (`ReaderSubscriber::on_dispose`) pushes to
    /// no ring, so its word is re-checked against the debt it stands
    /// for: RAISED in `prev` means a dispose was queued since the last
    /// drain and its wake-up was swapped away, so it is re-raised once;
    /// RERAISED alone means that wake-up was delivered, and the word
    /// settles. `DisposeQueue` says why a level-triggered "queue
    /// non-empty" would spin a wait/take loop, and states the one
    /// interleaving this does not cover: two threads clearing at once
    /// can erase the single re-raise before a waiter observed it. A
    /// dispose racing the same clear as a push is re-raised in the same
    /// clear: one wake-up covers both.
    ///
    /// The cache is the third place. Where two threads may drain this
    /// reader at once (K>1 local bindings; a network ring with no local
    /// producer), a pump on another thread can move a ring entry into
    /// the cache and leave it there (`take_instance` with a handle that
    /// matches nothing, `read`, a drain with a backlog) between this
    /// thread's cache pop and its swap: the ring walk then finds
    /// nothing and the sample would sit in the cache with the status
    /// cleared. The re-check therefore looks at the cache, under its
    /// lock, after the ring walk. For the extra rings that is complete
    /// on this side alone: such a pump pops AND deposits under the
    /// binding-table mutex (`pump_merge`) and the ring walk takes that
    /// same mutex whenever extra rings exist, so the pump is wholly
    /// before the walk, and its deposit is visible to the cache check
    /// (mutex ordering), or wholly after it, and the walk saw the entry
    /// still in its ring. The network ring is walked without that
    /// mutex (taking it here would put a lock on the blocking loop's
    /// empty take of every participant-built reader), so an entry
    /// popped from it and not yet deposited is invisible to both
    /// checks; the deposit side closes that window by re-raising when
    /// it finds every ring word zero (`cover_deposit` states the
    /// argument). A reader whose primary ring has a producer admits one
    /// draining thread by contract (a second popper is a data race on
    /// the SPSC ring, not a lost wake-up). Only a clear that swapped a
    /// ring word pays the cache lock: a polling reader's empty takes
    /// after the first clear read zero words Relaxed and return before
    /// it.
    ///
    /// Cost. Producers pay one plain Release store per notification (on
    /// the intra-process path that is the writer's post-commit notify;
    /// the extra-binding mergers pay a `fetch_or`). The reader pays one
    /// Relaxed load per word on every clear, one swap per raised word
    /// (once per delivered sample in a blocking loop, on one word), then
    /// Relaxed ring head/tail loads and one uncontended cache lock on
    /// that same path, and one more RMW per re-raised word.
    ///
    /// `announce_transitions` says whether the accessor that reached here can
    /// carry an instance-state change. When it cannot, the queued transitions
    /// are announced HERE, before the words are swapped, so that a transition
    /// pushed after the announce still raises its word and is re-raised by the
    /// check below. Announcing after the swap instead would let this clear
    /// erase that raise. One transition can still be announced without its own
    /// wake-up - the one pushed between the accessor entering and this
    /// announce taking the lock - which costs a bounded delay, never the
    /// transition itself.
    #[inline]
    fn clear_data_available_if_idle(&self, announce_transitions: bool) {
        #[cfg(test)]
        self.run_idle_clear_hook();

        // Before the swap, deliberately: see the note above.
        if announce_transitions {
            self.dispose_events.announce();
        }

        let status = &self.status_condition;
        let words = status.wake_words();
        let mut prev = [0u32; WAKE_WORDS];
        for (word, slot) in prev.iter_mut().enumerate() {
            *slot = words.clear(word);
        }
        // Only DATA_AVAILABLE leaves with the words (a bit a test raised
        // through the mask included): DDS v1.4 Sec.2.2.4.2.2 lets a read
        // or take reset that status and no other. A SAMPLE_REJECTED the
        // admission path raised stays up for its WaitSet until its own
        // consumer (the listener call or `get_sample_rejected_status`)
        // lowers it, Sec.2.2.4.2.1.
        status.clear_active_status(StatusMask::DATA_AVAILABLE);

        let ring_words_raised = WakeWord::RINGS.iter().any(|word| prev[word.index()] != 0);
        // The cache after the rings: its check takes a lock.
        if ring_words_raised
            && (!self.all_rings_empty()
                || !self.cache.is_empty()
                || self.bindings.has_pending_local_replay())
        {
            for word in WakeWord::RINGS {
                if prev[word.index()] != 0 {
                    status.re_raise_data_available(word.index());
                }
            }
        }
        // Same shape as the rings above: re-raise on ANY non-zero previous
        // value, and let the queue itself - not this clearer's bookkeeping -
        // decide whether anything is still owed.
        //
        // Testing `& WAKE_RAISED` instead lost the notification outright.
        // WAKE_RERAISED alone was read as "already delivered", so with two
        // threads clearing the same reader (K>1 local bindings, or a network
        // ring with no local producer, both legal for a Sync DataReader) the
        // second clearer swallowed the first's re-raise before any waiter had
        // observed it: the WaitSet woke, read a false trigger, filtered the
        // condition out and blocked again, and the event stayed in the queue
        // with every status word clear. The application was never told the
        // instance had been disposed, with no error and no log.
        //
        // The cost of closing it is that the word is effectively
        // level-triggered, so an application that blocks for DATA_AVAILABLE
        // and never calls get_dispose_events() is woken for as long as it
        // ignores the queue. That is inherent to the design: DDS
        // statuses ARE level-triggered, and a status that stays true until
        // the application reads it is the specified behaviour. Only
        // DisposeQueue::drain settles the word, under the queue's own lock.
        if prev[WakeWord::Dispose.index()] != 0 && self.dispose_events.has_unannounced() {
            status.re_raise_data_available(WakeWord::Dispose.index());
        }
    }

    #[cfg(test)]
    fn run_idle_clear_hook(&self) {
        let hook = self
            .idle_clear_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Install the one-shot seam run by `clear_data_available_if_idle`
    /// right before the clear (see the field docs).
    #[cfg(test)]
    pub(super) fn set_idle_clear_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .idle_clear_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn run_pump_deposit_hook(&self) {
        let hook = self
            .pump_deposit_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Install the one-shot seam run by `pump_merge` between the pop
    /// and the deposit of an entry (see the field docs).
    #[cfg(test)]
    pub(super) fn set_pump_deposit_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .pump_deposit_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(hook));
    }

    /// Deposit side of the idle re-check (`clear_data_available_if_idle`
    /// is the clear side): after this thread moved entries from the
    /// rings into the cache, put the trigger back if every ring word is
    /// zero, because a clear on another thread may have observed the
    /// rings empty while those entries were in flight.
    ///
    /// The window. `pump_merge` pops an entry and deposits it in the
    /// cache under the binding-table mutex, but the clear side walks
    /// the network ring without that mutex: its emptiness is two
    /// Relaxed loads on a field outside the table, and taking the mutex
    /// there would put a lock on the blocking loop's empty take of
    /// every participant-built reader. So with a network ring and no
    /// extra binding, thread B pops entry E; thread A then swaps the
    /// network word (reads RAISED), finds the network ring empty, finds
    /// the cache empty, and re-raises nothing; B deposits E with every
    /// word zero, and E sits in the cache while the WaitSet sleeps. The
    /// extra rings do not have the window (the walk takes the mutex
    /// when they exist), but the rule below covers every `pump_merge`
    /// deposit the same way, so it is stated once.
    ///
    /// The rule: after the deposit D, read every ring word; if all read
    /// zero, re-raise. Argument, with K1 a clear's cache check (under
    /// the cache mutex, as D is):
    /// - Every ring word reads zero: re-raise, so the next clear reads
    ///   RERAISED and re-checks the rings and the cache (a word that
    ///   reads RERAISED alone is re-checked; clear side). The trigger is
    ///   up until then. If a take drained the deposit in between, the
    ///   wake-up is spurious: one empty take, which clears for good.
    /// - Some ring word W reads a non-zero value V. Let C1 be the first
    ///   clear whose swap of W is after V in W's modification order. It
    ///   reads V or a later non-zero value (only a swap writes zero to
    ///   a ring word), so it re-checks: if its ring walk finds a ring
    ///   non-empty it re-raises at once; otherwise it runs K1, and K1
    ///   is after D in cache-mutex order. Were K1 before D, C1's swap
    ///   (sequenced before K1's unlock) would happen-before this
    ///   thread's read of W (sequenced after D's lock), and that read
    ///   would return the swap's zero or a later value (write-read
    ///   coherence), not V. So K1 sees the deposit and C1 re-raises. If
    ///   no clear ever swaps W after V, W stays non-zero and the
    ///   trigger stays up. Nothing here needs an ordering on this
    ///   thread's reads beyond coherence; they are Acquire because
    ///   every read of a word on the reader side is, not because the
    ///   argument needs it.
    ///
    /// Cost: three Acquire loads after a `pump_merge` that deposited,
    /// which is the K>1 and network path, never the fused single-ring
    /// take. The re-raise is one RMW and happens only when a clear on
    /// another thread swapped the producer's raise away, or when the
    /// producer's raise is still in flight behind its push. The word
    /// re-raised is the primary one: any ring word makes the next clear
    /// re-check, and the primary word exists on every reader.
    ///
    /// The fused single-ring take path deposits nothing this rule must
    /// cover: on a reader whose primary ring has a producer, a second
    /// draining thread would be a second consumer on that SPSC ring,
    /// which the contract excludes, and on a reader whose only producer
    /// is the network ring that path never deposits (the primary ring
    /// is empty).
    fn cover_deposit(&self) {
        let words = self.status_condition.wake_words();
        if WakeWord::RINGS
            .iter()
            .all(|word| words.load(word.index()) == 0)
        {
            self.status_condition
                .re_raise_data_available(WakeWord::Primary.index());
        }
    }

    /// Emptiness across the primary ring and every extra binding ring.
    fn all_rings_empty(&self) -> bool {
        if !self.ring.is_empty() {
            return false;
        }
        if self
            .bindings
            .network
            .as_ref()
            .is_some_and(|ring| !ring.is_empty())
        {
            return false;
        }
        if !self.bindings.has_extra_rings() {
            return true;
        }
        let entries = self
            .bindings
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        entries.iter().all(|b| b.ring.is_empty())
    }

    pub fn take_batch(&self, max: usize) -> Result<Vec<T>> {
        let mut messages = Vec::with_capacity(max);
        for _ in 0..max {
            match self.take()? {
                Some(sample) => messages.push(sample),
                None => break,
            }
        }
        Ok(messages)
    }

    // =========================================================================
    // DDS Standard API (v0.9+)
    // =========================================================================

    /// [`take()`](Self::take), unless `fits` refuses the data of the sample
    /// it would return. A refused take removes nothing and the refusal comes
    /// back as `Ok(Err(refusal))`; a later take returns the head of the reader
    /// at that time, normally the refused sample (another taker, or a newer
    /// sample evicting it under KEEP_LAST, can change that). Same pump,
    /// ordering and status rules as `take()`, under the same consumer gate.
    ///
    /// Doc-hidden: the C ABI's sized take is its caller.
    #[doc(hidden)]
    pub fn take_if<E>(
        &self,
        fits: impl Fn(&T) -> std::result::Result<(), E>,
    ) -> Result<std::result::Result<Option<T>, E>> {
        // Every take shares this path, the C ABI's included, so the
        // transitions below are announced for all of them:
        // No data left. ANNOUNCE any pending instance-state transitions
        // without consuming them.
        //
        // This accessor returns `T` and has no field in which to report an
        // instance state, so leaving the transitions queued would keep
        // DATA_AVAILABLE raised with nothing the caller of THIS method could
        // do about it - a busy loop.
        // Popping them instead, as the first cut did, settles the word by
        // DESTROYING what another accessor was about to return: our own
        // `examples/shape_main.rs` drains with `take()` and reads
        // `get_dispose_events()` on the very next line, so the OMG conformance
        // binary silently stopped reporting instance states.
        //
        // Announcing settles the wake-up debt and leaves the transition owed.
        // `take_with_info()` and `get_dispose_events()` still return it; a
        // later transition on the same instance re-arms the wake-up.
        //
        // The announce itself happens in `clear_data_available_if_idle`, which
        // this path has already reached (`DataProjection::ANNOUNCES_TRANSITIONS`),
        // so that it is ordered BEFORE the wake-word swap rather than after it.
        // Every other accessor that returns a `T`-shaped value - `take_all`,
        // `take_instance*`, `read*`, `try_take` - goes through the same point
        // and is covered by the same flag.
        self.take_projected::<DataProjection, E, _>(&fits)
    }

    /// Take a single sample, removing it from the cache (DDS take semantics).
    ///
    /// This is the DDS-standard `take()` operation. It:
    /// 1. Pumps any pending samples from the network ring to the cache
    /// 2. Removes and returns the oldest sample from the cache
    ///
    /// # Returns
    /// - `Ok(Some(sample))` if a sample was available
    /// - `Ok(None)` if no samples available
    /// - `Err(_)` if decoding failed
    ///
    /// # Example
    /// ```rust,no_run
    /// # use hdds::{Participant, QoS, Result};
    /// # fn main() -> Result<()> {
    /// # let participant = Participant::builder("test").build()?;
    /// # let reader = participant.create_reader::<MyType>("topic", QoS::default())?;
    /// while let Some(sample) = reader.take()? {
    ///     println!("Got: {:?}", sample);
    /// }
    /// # Ok(())
    /// # }
    /// # #[derive(hdds::DDS, Debug)] struct MyType { x: i32 }
    /// ```
    pub fn take(&self) -> Result<Option<T>> {
        Ok(never(self.take_if(|_: &T| Ok::<(), Infallible>(()))?))
    }

    /// Take a single sample together with its [`SampleInfo`] metadata.
    ///
    /// Sibling of [`take()`](Self::take) sharing the exact same pop
    /// path (same pump, same cache front-pop, same status handling):
    /// the two calls are interchangeable sample-for-sample, this one
    /// just keeps the per-sample metadata that `take()` discards.
    ///
    /// Returns `(Some(data), info)` for an ordinary sample and
    /// `(None, info)` for an instance-state change, where `info.valid_data`
    /// is `false` and `info.instance_state` says what happened. That is the
    /// shape every DDS implementation uses: the accessor RETURNS the
    /// notification rather than skipping it, and the application branches on
    /// `valid_data`.
    ///
    /// v1 metadata limits (see the [`SampleInfo`] field docs):
    /// - `writer_guid` is `None` for intra-process samples (ring
    ///   identity is not mapped back to a GUID) and for network paths
    ///   that did not resolve the writer, and always `None` on an
    ///   instance-state change, which the engine does not attribute to a
    ///   writer today.
    /// - the key itself is not reconstructible: `info.instance_handle` is a
    ///   16-byte hash and there is no `get_key_value` yet, so an application
    ///   can tell THAT an instance changed state but not WHICH business
    ///   entity it was unless it kept the mapping.
    ///
    /// Like `take()`, this drains the same SPSC ring: the documented
    /// single-consumer contract of the reader applies to the UNION of
    /// both entry points, not to each individually.
    ///
    /// # Returns
    /// - `Ok(Some((sample, info)))` if a sample was available
    /// - `Ok(None)` if no samples available
    /// - `Err(_)` if decoding failed
    pub fn take_with_info(&self) -> Result<Option<(Option<T>, SampleInfo)>> {
        // Nothing queued is the overwhelmingly common case - instance-state
        // transitions are network-only and rare - so it keeps the fused
        // single-lock pump+pop.
        // Several rings are merged by pumping them all before taking, which
        // would put a sample written after a local dispose ahead of it: that
        // (cold) shape takes the ordering path too.
        if !self.dispose_events.is_empty() || self.bindings.needs_merge() {
            return self.take_with_info_interleaved();
        }
        let unconditional = |_: &T| Ok::<(), Infallible>(());
        if let Some(cached) =
            never(self.take_projected::<FullSampleProjection, Infallible, _>(&unconditional)?)
        {
            let (data, mut info) = cached.into_data_and_info();
            self.stamp_single_rank(&mut info);
            return Ok(Some((Some(data), info)));
        }
        Ok(self
            .dispose_events
            .pop_one()
            .map(|event| (None, self.instance_notification_info(&event))))
    }

    /// `take_with_info` with a transition waiting: place it among the data
    /// instead of behind all of it.
    ///
    /// Two defects come from treating the transition as a fallback consulted
    /// only once the cache runs dry. It is delivered after data that arrived
    /// AFTER it, which on one instance reports it dead just after it was
    /// resurrected; and on a topic that keeps producing, the cache never runs
    /// dry, so it is not delayed but withheld for as long as the traffic
    /// lasts.
    ///
    /// Both close the same way: pump the ring into the cache without popping,
    /// then ask the queue whether its oldest transition belongs ahead of the
    /// sample now at the front (`DisposeQueue::pop_if_before` holds the rule).
    /// The pump must not announce here - this accessor CAN report the
    /// transition, and announcing would settle a wake-up for one it may not
    /// return on this call.
    fn take_with_info_interleaved(&self) -> Result<Option<(Option<T>, SampleInfo)>> {
        self.check_requested_deadline();
        self.pump_ring_to_cache(false)?;

        // BY_SOURCE_TIMESTAMP: also behind an older sample of its instance
        // from any writer (`DisposeQueue::pop_if_before`).
        let by_source = if self.cache.instances().by_source_timestamp() {
            self.cache.pending_source_order_from(0, |_, _, _| true)
        } else {
            Vec::new()
        };
        if let Some(event) = self
            .dispose_events
            .pop_if_before(&self.cache.pending_origins(), &by_source)
        {
            return Ok(Some((None, self.instance_notification_info(&event))));
        }

        let cached =
            if self.qos.presentation.ordered_access && self.bindings.local_read_order().is_some() {
                self.ordered_reconcile();
                let cached = self
                    .cache
                    .take_first_matching(|sample, _, _| self.ordered_allows(sample));
                if let Some(sample) = &cached {
                    self.ordered_accessed(sample);
                    self.cache.note_viewed(sample.instance_handle);
                }
                cached
            } else {
                self.cache.take_full()
            };
        if let Some(cached) = cached {
            let (data, mut info) = cached.into_data_and_info();
            self.stamp_single_rank(&mut info);
            return Ok(Some((Some(data), info)));
        }

        if !self.cache.is_empty() {
            return Ok(None);
        }
        // The cache is dry, so whatever is left has nothing to be ordered
        // against and comes out now.
        Ok(self
            .dispose_events
            .pop_one()
            .map(|event| (None, self.instance_notification_info(&event))))
    }

    /// Shared pump body of [`take()`](Self::take) and
    /// [`take_with_info()`](Self::take_with_info). The projection policy
    /// selects the cache's data-only or full-sample operations at compile
    /// time, preserving one source of ordering/status logic without moving
    /// the full sample out of the cache lock on the crown data-only path.
    fn take_projected<P, E, G>(&self, fits: &G) -> Result<std::result::Result<Option<P::Output>, E>>
    where
        P: CacheTakeProjection<T>,
        G: Fn(&T) -> std::result::Result<(), E>,
    {
        // Check requested deadline before reading (DDS spec: fire callback on miss)
        self.check_requested_deadline();

        // Startup-race lifespan probe (epoch-gated), shared with pump_ring_to_cache.
        self.probe_writer_lifespan();

        let slab_pool = rt::get_slab_pool_ref();

        // Declared before `_gate`, so it drops after: a notice the merge
        // raises while the gate (and, for K>1, the bindings mutex and the
        // network consumer guard) is held -- a mid-merge SAMPLE_LOST, for
        // one -- is held for this thread and told only once every lock
        // this call took has released, never inline while a reentrant
        // listener (one that calls take() of its own) could deadlock on
        // them (`notices::Delivering`).
        let _delivering = super::notices::Delivering::enter();
        // One ring consumer at a time (see `consumer_gate`): held from
        // the first pop to the end, so that a condition evaluation
        // pumping on another thread and this take never pop the
        // single-consumer ring concurrently, the cache receives the
        // popped entries in ring order, and no other consumer's pump
        // lands between this take's empty observation and its idle
        // clear (a writer's push still can; the re-raise covers it).
        let _gate = self.consume()?;

        // K>1 cold path: the timestamp merge across the primary + extra
        // binding rings pushes per entry (unchanged), then a separate
        // cache pop. Fusing the merge into a single lock is not worth the
        // structural risk on this already-cold path.
        if self.bindings.needs_merge() {
            let mut pushed: usize = 0;
            self.pump_merge(slab_pool, &mut pushed)?;
            // Same single-lock shape as the fast path below: the pop's
            // None is the emptiness proof, taken under the lock the pop
            // already holds, so the separate `is_empty` probe (a second
            // acquisition) is gone. With `pushed == 0` the cache was
            // untouched this round, so "pop returned None" and "cache
            // was empty before the pop" are the same fact.
            if self.bindings.local_read_order().is_some() {
                self.ordered_reconcile();
                let taken = match self
                    .cache
                    .take_first_matching_if(|sample, _, _| self.ordered_allows(sample), fits)
                {
                    Ok(taken) => taken,
                    Err(refused) => return Ok(Err(refused)),
                };
                if let Some(sample) = &taken {
                    self.ordered_accessed(sample);
                    self.cache.note_viewed(sample.instance_handle);
                } else if pushed == 0 {
                    self.clear_data_available_if_idle(P::ANNOUNCES_TRANSITIONS);
                }
                return Ok(Ok(taken.map(P::project)));
            }
            let taken = match P::take(&self.cache, fits) {
                Ok(taken) => taken,
                Err(refused) => return Ok(Err(refused)),
            };
            if pushed == 0 && taken.is_none() {
                self.clear_data_available_if_idle(P::ANNOUNCES_TRANSITIONS);
            }
            return Ok(Ok(taken));
        }

        // K==1 single-ring fast path (crown 1w1r roundtrip). Decode the
        // pending ring entries OUTSIDE the cache lock, then perform the
        // push(es) + front-pop under ONE cache-mutex acquisition instead
        // of the pre-fusion two (one per push, one for the take). The
        // roundtrip pumps exactly one sample per take(), so the common
        // case is a single prepared sample and a single fused lock.
        // A local writer's dispose or unregister rides this ring between
        // its samples. Met BEFORE any sample, the pump STOPS at it: this path
        // returns the first sample it pops without consulting the
        // transitions, so pumping past it would hand out data written after
        // the transition ahead of it. What follows stays in the ring for the
        // next call, which sees the queued transition and orders the rest.
        // Met after the first sample (the backlog loop below), it is simply
        // queued by `prepare_sample`: the sample returned precedes it, and
        // `DisposeQueue::pop_if_before` orders what was pumped behind it.
        //
        // `freed`: a pop found the ring full, and a writer may wait for the
        // slot it freed (`slot_freed`). Computed from the indices the pop
        // loads anyway.
        let mut first: Option<CachedSample<T>> = None;
        let mut freed = false;
        // BY_SOURCE_TIMESTAMP tie-break (DDS v1.4 Sec.2.2.3.17): a local
        // sample decodes with `writer_guid: None` (no GUID prefix in the
        // payload), which is fine for BY_RECEPTION_TIMESTAMP but breaks
        // the deterministic tie-break `SourceOrderKey` needs when this
        // writer ties another on source timestamp (see
        // `ReaderBindings::primary_writer_guid`'s doc for the exact
        // scope: the crown single-ring path only). Resolved once per
        // pump, not per sample; `None` whenever the policy is not
        // requested, which is the only cost the default path pays here.
        let local_writer_guid = self
            .qos
            .destination_order
            .uses_source_timestamp()
            .then(|| self.bindings.primary_writer_guid())
            .flatten();
        while let Some(entry) = self.ring.pop_noting_full(&mut freed) {
            if self.admit_lifecycle_entry(entry, slab_pool, local_writer_guid) {
                break;
            }
            if let Some(cached) =
                self.prepare_sample(entry, 0, self.local_hold, slab_pool, local_writer_guid)?
            {
                first = Some(cached);
                break;
            }
        }

        let Some(first) = first else {
            if freed {
                self.slot_freed();
            }
            // Nothing new pumped this round (ring empty or every entry
            // filtered). Pop whatever the cache already held; a None
            // from that pop is the emptiness proof, established under
            // the same lock acquisition, so the status clear is derived
            // from it instead of from a separate `is_empty` probe that
            // would take the cache mutex a second time on every idle
            // poll. The clear itself then moves after the pop; nothing
            // between the two touches the status, so the observable
            // behaviour is the pre-existing one at half the lock cost.
            let taken = match P::take(&self.cache, fits) {
                Ok(taken) => taken,
                Err(refused) => return Ok(Err(refused)),
            };
            if taken.is_none() {
                self.clear_data_available_if_idle(P::ANNOUNCES_TRANSITIONS);
            }
            return Ok(Ok(taken));
        };

        // Rare backlog case: more entries were queued behind the first.
        // The crown path leaves this empty; `Vec::new()` does not
        // allocate until the first push, so the single-sample path stays
        // allocation-free. Draining the whole ring here preserves the
        // pre-fusion "pump all pending, then take front" ordering.
        let mut rest: Vec<CachedSample<T>> = Vec::new();
        while let Some(entry) = self.ring.pop_noting_full(&mut freed) {
            if let Some(cached) =
                self.prepare_sample(entry, 0, self.local_hold, slab_pool, local_writer_guid)?
            {
                rest.push(cached);
            }
        }
        if freed {
            self.slot_freed();
        }

        if rest.is_empty() {
            Ok(P::push_and_take(&self.cache, first, fits))
        } else {
            Ok(P::push_all_and_take(&self.cache, first, rest, fits))
        }
    }

    /// Build the `SampleInfo` of an instance-state change.
    ///
    /// `valid_data: false` is the contract: the data half is absent and every
    /// fact about the event is in here. `writer_guid` is `None` regardless of
    /// what `DisposeEvent::writer_guid` holds -- the reader-facing
    /// `SampleInfo` has never surfaced it for a transition, same as a data
    /// sample's own `writer_guid` on the intra-process path.
    /// `source_timestamp_ns`, unlike `writer_guid`, IS carried from the
    /// event (DDS v1.4 Sec.2.2.2.5.5, Sec.2.2.2.4.2.13 `dispose_w_timestamp`
    /// / Sec.2.2.2.4.2.8 `unregister_instance_w_timestamp`): `None` only for
    /// a transition this reader never received with one (see
    /// `DisposeEvent::source_timestamp_ns`).
    ///
    /// Accessing the transition is an access to its instance, so the
    /// instance turns NOT_NEW the way it does for a data sample (DDS v1.4
    /// Sec.2.2.2.5.3.8/9); the `view_state` reported is the one before this
    /// access, the `sample_state` says whether a `read_w_condition` already
    /// returned it in place.
    pub(super) fn instance_notification_info(&self, event: &DisposeEvent) -> SampleInfo {
        let handle = InstanceHandle::new(event.key_hash);
        let view_state = self.cache.note_viewed(handle);
        let mut info = Self::transition_info(event, view_state);
        self.stamp_single_rank(&mut info);
        info
    }

    /// Ranks for a one-sample collection (DDS v1.4 Sec.2.2.2.5.1.6).
    fn stamp_single_rank(&self, info: &mut SampleInfo) {
        let (disposed, no_writers) = self
            .cache
            .instances()
            .generation_counts(info.instance_handle);
        info.absolute_generation_rank = disposed.wrapping_add(no_writers).wrapping_sub(
            info.disposed_generation_count
                .wrapping_add(info.no_writers_generation_count),
        );
    }

    /// Ranks are relative to this returned collection, while the absolute
    /// rank uses the latest received generation even when a condition or
    /// max_samples excluded its sample (DDS v1.4 Sec.2.2.2.5.1.6).
    pub(super) fn stamp_collection_ranks(&self, samples: &mut [(Option<T>, SampleInfo)]) {
        let mut instances = HashMap::new();
        for (_, info) in samples.iter() {
            let generation = info
                .disposed_generation_count
                .wrapping_add(info.no_writers_generation_count);
            let (_, newest, _) = instances.entry(info.instance_handle).or_insert_with(|| {
                let (disposed, no_writers) = self
                    .cache
                    .instances()
                    .generation_counts(info.instance_handle);
                (0u32, generation, disposed.wrapping_add(no_writers))
            });
            // PRESENTATION need not impose reception order on the collection.
            // The newest generation can precede an older returned sample.
            *newest = (*newest).max(generation);
        }
        for (_, info) in samples.iter_mut().rev() {
            let generation = info
                .disposed_generation_count
                .wrapping_add(info.no_writers_generation_count);
            let slot = instances.get_mut(&info.instance_handle);
            debug_assert!(slot.is_some(), "every returned instance was collected");
            let Some((later, newest, absolute)) = slot else {
                log::error!("instance rank skipped: its collection entry is missing");
                continue;
            };
            info.sample_rank = *later;
            info.generation_rank = newest.wrapping_sub(generation);
            info.absolute_generation_rank = absolute.wrapping_sub(generation);
            *later = later.saturating_add(1);
        }
    }

    /// The `SampleInfo` of a transition with a caller-supplied view state:
    /// for the conditional accessors, which record the access once their
    /// whole collection is selected (one snapshot per instance,
    /// Sec.2.2.2.5.1.8).
    ///
    /// `no_writers_generation_count` comes straight from `event` - stamped
    /// by `DisposeQueue::push` at the time this transition was queued
    /// (DDS v1.4 Sec.2.2.2.5.1.5), never re-read from the instance table
    /// here, which could already reflect a later revival.
    pub(super) fn transition_info(event: &DisposeEvent, view_state: ViewState) -> SampleInfo {
        let now = current_time_ns();
        let instance_handle = InstanceHandle::new(event.key_hash);
        SampleInfo {
            source_timestamp_ns: event.source_timestamp_ns,
            reception_timestamp_ns: now,
            writer_guid: None,
            sequence_number: if event.writer_guid.is_some() {
                event.order_seq
            } else {
                event.seq & 0xFFFF_FFFF
            },
            instance_handle,
            instance_state: Self::transition_instance_state(event.kind),
            valid_data: false,
            sample_state: if event.read {
                super::cache::SampleState::Read
            } else {
                super::cache::SampleState::NotRead
            },
            view_state,
            no_writers_generation_count: event.no_writers_generation_count,
            disposed_generation_count: event.disposed_generation_count,
            sample_rank: 0,
            generation_rank: 0,
            absolute_generation_rank: 0,
        }
    }

    /// The `InstanceState` a queued transition stands for. DDS has three
    /// instance states, so "disposed and unregistered" collapses to
    /// DISPOSED (see `get_dispose_events` for the exact kind).
    pub(super) fn transition_instance_state(kind: DisposeKind) -> InstanceState {
        super::cache::transition_state(kind)
    }

    /// Take the next sample (DDS standard alias).
    ///
    /// Equivalent to [`take()`](Self::take).
    #[inline]
    pub fn take_next_sample(&self) -> Result<Option<T>> {
        self.take()
    }

    /// Atomically drain every sample currently in the cache in a SINGLE
    /// cache-lock acquisition (DDS take, batch form).
    ///
    /// Unlike [`take_batch`](Self::take_batch) (which loops
    /// [`take()`](Self::take) and releases the cache lock between samples),
    /// this pumps the network ring(s) into the cache and then removes the
    /// whole cache under one lock. That atomicity matters for coherent-set
    /// reads: a coherent commit delivered by the control/router thread
    /// (`commit_writer_coherent_set` -> `deliver_released`) pushes a
    /// complete set into this reader's ring atomically; a per-sample drain
    /// loop can interleave with that push and observe a PARTIAL set,
    /// violating the all-or-nothing presentation contract of
    /// `Presentation.coherent_access` (DDS v1.4 sec. 2.2.3.6 + RTPS v2.5
    /// sec. 8.7.5). Draining under one cache lock observes a commit either
    /// entirely before or entirely after, never mid-commit.
    pub fn take_all(&self) -> Result<Vec<T>> {
        if self.qos.presentation.ordered_access && self.bindings.local_read_order().is_some() {
            let mut samples = Vec::new();
            while samples.len() < usize::MAX {
                match self.access_ordered(None)? {
                    Some(sample) => samples.push(sample.data),
                    None => break,
                }
            }
            return Ok(samples);
        }
        self.check_requested_deadline();
        // Cross-topic coherent presentation: pull at most ONE aligned
        // generation from the Subscriber's barrier into this reader's ring
        // before draining, so a read cycle exposes 0 or exactly one
        // complete cross-topic group. The barrier only releases a
        // generation once every group member fed by the same remote
        // publisher has one ready (see the coherent_barrier module docs).
        // No-op for readers without a barrier (non-coherent, or not
        // attached to a Subscriber), so their behaviour is unchanged.
        // (At the consumer door, `consume`.)
        self.pump_ring_to_cache(true)?;
        let drained = self.cache.take_batch(usize::MAX);
        if self.all_rings_empty() {
            self.clear_data_available_if_idle(true);
        }
        Ok(drained)
    }

    /// Take a single sample for a specific instance (DDS take_instance).
    ///
    /// Returns and removes the oldest sample matching the given instance handle.
    /// For keyless topics, use `InstanceHandle::nil()`.
    ///
    /// # Arguments
    /// * `handle` - The instance handle (key hash) to filter by
    ///
    /// # Returns
    /// - `Ok(Some(sample))` if a matching sample was found and removed
    /// - `Ok(None)` if no matching sample exists
    /// - `Err(_)` if decoding failed while pumping
    pub fn take_instance(&self, handle: InstanceHandle) -> Result<Option<T>> {
        if self.qos.presentation.ordered_access && self.bindings.local_read_order().is_some() {
            return Ok(self.access_ordered(Some(handle))?.map(|sample| sample.data));
        }
        self.pump_ring_to_cache(true)?;
        Ok(self.cache.take_instance(handle))
    }

    /// Take up to `max` samples for a specific instance, removing them.
    ///
    /// Returns and removes samples matching the given instance handle.
    ///
    /// # Arguments
    /// * `handle` - The instance handle (key hash) to filter by
    /// * `max` - Maximum number of samples to take
    pub fn take_instance_batch(&self, handle: InstanceHandle, max: usize) -> Result<Vec<T>> {
        if self.qos.presentation.ordered_access && self.bindings.local_read_order().is_some() {
            let mut samples = Vec::new();
            while samples.len() < max {
                match self.access_ordered(Some(handle))? {
                    Some(sample) => samples.push(sample.data),
                    None => break,
                }
            }
            return Ok(samples);
        }
        self.pump_ring_to_cache(true)?;
        Ok(self.cache.take_instance_batch(handle, max))
    }
}

// Read operations require T: Clone (samples are copied, not moved)
impl<T: DDS + Clone> DataReader<T> {
    /// Read a single sample without removing it (DDS read semantics).
    ///
    /// This is the DDS-standard `read()` operation. It:
    /// 1. Pumps any pending samples from the network ring to the cache
    /// 2. Returns a clone of the next unread sample (marks it as READ)
    ///
    /// Unlike [`take()`](Self::take), `read()` does not remove the sample from
    /// the cache. The same sample can be taken later with `take()`.
    ///
    /// # Returns
    /// - `Ok(Some(sample))` if an unread sample was available
    /// - `Ok(None)` if no unread samples available
    /// - `Err(_)` if decoding failed
    ///
    /// # Example
    /// ```rust,no_run
    /// # use hdds::{Participant, QoS, Result};
    /// # fn main() -> Result<()> {
    /// # let participant = Participant::builder("test").build()?;
    /// # let reader = participant.create_reader::<MyType>("topic", QoS::default())?;
    /// // Read samples (non-destructive)
    /// while let Some(sample) = reader.read()? {
    ///     println!("Peeked: {:?}", sample);
    /// }
    /// // Samples still in cache, can be taken later
    /// while let Some(sample) = reader.take()? {
    ///     println!("Took: {:?}", sample);
    /// }
    /// # Ok(())
    /// # }
    /// # #[derive(hdds::DDS, Debug, Clone)] struct MyType { x: i32 }
    /// ```
    pub fn read(&self) -> Result<Option<T>> {
        if self.qos.presentation.ordered_access && self.bindings.local_read_order().is_some() {
            return Ok(self.read_ordered(None)?.map(|sample| sample.data));
        }
        // Check requested deadline before reading (DDS spec: fire callback on miss)
        self.check_requested_deadline();

        // Pump pending samples from ring to cache
        self.pump_ring_to_cache(true)?;

        // Read from cache (non-destructive)
        Ok(self.cache.read())
    }

    /// Read up to `max` samples without removing them.
    ///
    /// Returns clones of unread samples and marks them as READ.
    pub fn read_batch(&self, max: usize) -> Result<Vec<T>> {
        if self.qos.presentation.ordered_access && self.bindings.local_read_order().is_some() {
            let mut samples = Vec::new();
            while samples.len() < max {
                match self.read_ordered(None)? {
                    Some(sample) => samples.push(sample.data),
                    None => break,
                }
            }
            return Ok(samples);
        }
        self.pump_ring_to_cache(true)?;
        Ok(self.cache.read_batch(max))
    }

    /// Read the next sample (DDS standard alias).
    ///
    /// Equivalent to [`read()`](Self::read).
    #[inline]
    pub fn read_next_sample(&self) -> Result<Option<T>> {
        self.read()
    }

    /// Read a single sample for a specific instance (DDS read_instance).
    ///
    /// Returns a clone of the first unread sample matching the given instance handle.
    /// The sample is marked as READ but remains in the cache.
    ///
    /// # Arguments
    /// * `handle` - The instance handle (key hash) to filter by
    ///
    /// # Returns
    /// - `Ok(Some(sample))` if a matching unread sample was found
    /// - `Ok(None)` if no matching unread sample exists
    /// - `Err(_)` if decoding failed while pumping
    pub fn read_instance(&self, handle: InstanceHandle) -> Result<Option<T>> {
        if self.qos.presentation.ordered_access && self.bindings.local_read_order().is_some() {
            return Ok(self.read_ordered(Some(handle))?.map(|sample| sample.data));
        }
        self.pump_ring_to_cache(true)?;
        Ok(self.cache.read_instance(handle))
    }

    /// Read up to `max` samples for a specific instance without removing them.
    ///
    /// Returns clones of unread samples matching the given instance handle.
    ///
    /// # Arguments
    /// * `handle` - The instance handle (key hash) to filter by
    /// * `max` - Maximum number of samples to read
    pub fn read_instance_batch(&self, handle: InstanceHandle, max: usize) -> Result<Vec<T>> {
        if self.qos.presentation.ordered_access && self.bindings.local_read_order().is_some() {
            let mut samples = Vec::new();
            while samples.len() < max {
                match self.read_ordered(Some(handle))? {
                    Some(sample) => samples.push(sample.data),
                    None => break,
                }
            }
            return Ok(samples);
        }
        self.pump_ring_to_cache(true)?;
        Ok(self.cache.read_instance_batch(handle, max))
    }
    #[cold]
    fn read_ordered(&self, instance: Option<InstanceHandle>) -> Result<Option<CachedSample<T>>> {
        let _notices = super::notices::Delivering::enter();
        let _consumer = self.consume()?;
        self.pump_pending_gated()?;
        self.ordered_reconcile();
        let mut matches = |sample: &CachedSample<T>, _: ViewState, _: InstanceState| {
            sample.sample_state() == super::cache::SampleState::NotRead
                && instance.is_none_or(|handle| sample.instance_handle == handle)
                && self.ordered_allows(sample)
        };
        let result = self
            .cache
            .read_first_matching_from(0, &mut matches)
            .map(|(_, sample)| sample);
        if let Some(sample) = &result {
            self.ordered_accessed(sample);
            self.cache.note_viewed(sample.instance_handle);
        } else {
            self.clear_data_available_if_idle(true);
        }
        Ok(result)
    }
}

impl<T: DDS> DataReader<T> {
    pub(super) fn ordered_reconcile(&self) {
        if let Some(order) = self.bindings.local_read_order() {
            order.reconcile(
                Arc::as_ptr(&self.bindings) as usize,
                &self.cache.local_order_keys(),
            );
        }
    }

    pub(super) fn ordered_allows(&self, sample: &CachedSample<T>) -> bool {
        self.bindings.local_read_order().is_none_or(|order| {
            order.allows(
                Arc::as_ptr(&self.bindings) as usize,
                (sample.writer_guid, sample.seq),
            )
        })
    }

    pub(super) fn ordered_transition_allows(&self, event: &DisposeEvent) -> bool {
        self.bindings.local_read_order().is_none_or(|order| {
            order.allows(
                Arc::as_ptr(&self.bindings) as usize,
                (event.writer_guid, event.seq),
            )
        })
    }

    pub(super) fn ordered_accessed(&self, sample: &CachedSample<T>) {
        if let Some(order) = self.bindings.local_read_order() {
            order.accessed(
                Arc::as_ptr(&self.bindings) as usize,
                (sample.writer_guid, sample.seq),
            );
        }
    }

    #[cold]
    fn access_ordered(&self, instance: Option<InstanceHandle>) -> Result<Option<CachedSample<T>>> {
        let _notices = super::notices::Delivering::enter();
        let _consumer = self.consume()?;
        self.pump_pending_gated()?;
        self.ordered_reconcile();
        let mut matches = |sample: &CachedSample<T>, _: ViewState, _: InstanceState| {
            instance.is_none_or(|handle| sample.instance_handle == handle)
                && self.ordered_allows(sample)
        };
        let result = self.cache.take_first_matching(&mut matches);
        if let Some(sample) = &result {
            self.ordered_accessed(sample);
            self.cache.note_viewed(sample.instance_handle);
        } else {
            self.clear_data_available_if_idle(true);
        }
        Ok(result)
    }

    /// Startup-race lifespan probe, shared by `take()` (fused path) and
    /// `pump_ring_to_cache` (read/take_instance/etc.).
    ///
    /// Close the startup race: if our effective lifespan has not been
    /// tightened yet (still infinite) but a matched writer on this topic
    /// announced a finite Lifespan via SEDP, adopt it now so the first
    /// catch-up burst is expired by source time rather than slipping
    /// through with lifespan = infinite (DDS v1.4 sec. 2.2.3.16). The async
    /// match-notification still tightens via the same Arc; this only races
    /// ahead of it for the first read after discovery.
    ///
    /// Perf epoch-gate: the registry probe (RwLock read + topic-string
    /// hash + map lookup) only runs when the registry's lifespan map has
    /// mutated since our last probe. `writer_lifespan_epoch()` is an
    /// Acquire load pairing with the Release bump in
    /// `register_writer_lifespan`; observing an unchanged epoch proves
    /// the map is unchanged, so the cached "no finite lifespan known"
    /// answer still holds. The epoch is loaded BEFORE the probe, so a
    /// registration racing the probe is re-checked on the next take --
    /// convergence is identical to the un-gated code (registration bumps
    /// the epoch, the very next take re-probes), minus the per-take cost.
    /// The lifespan a sample of `writer_guid` expires by: this reader's own
    /// and that writer's (see `own_lifespan_nanos`). Without a known writer,
    /// the smallest over every matched writer, as before.
    #[inline]
    fn lifespan_of(&self, writer_guid: Option<&[u8; 16]>) -> u64 {
        effective_lifespan(
            self.registry.as_deref(),
            &self.departed_lifespans,
            self.own_lifespan_nanos,
            &self.lifespan_nanos,
            writer_guid,
        )
    }

    #[inline]
    fn probe_writer_lifespan(&self) {
        // NOT gated on the CACHED value being `u64::MAX`: a registry
        // minimum a writer's departure raised (or removed entirely, DDS
        // v1.4 Sec.2.2.3.16: a sample expires by ITS OWN writer's
        // lifespan, never a departed one's) must still be followed once
        // this reader's own cache has already gone finite -- gating on
        // it stopped the epoch check from ever running again past that
        // point, for the life of the reader. The epoch load itself is
        // the cheap half of this probe either way (an extra Relaxed
        // load, same order as the one it replaces); the RwLock read +
        // topic-hash lookup below stays gated on the epoch actually
        // having moved, which is the expensive half the comment above
        // this function describes.
        let Some(ref reg) = self.registry else {
            return;
        };
        let epoch = reg.writer_lifespan_epoch();
        if epoch != self.lifespan_probe_epoch.load(Ordering::Relaxed) {
            let ns = reg
                .min_writer_lifespan_for_topic(&self.topic)
                .unwrap_or(u64::MAX);
            self.lifespan_nanos.store(ns, Ordering::Relaxed);
            self.lifespan_probe_epoch.store(epoch, Ordering::Relaxed);
        }
    }

    /// Tests only: the cached lifespan `probe_writer_lifespan` last set,
    /// without triggering a probe of its own.
    #[cfg(test)]
    pub(super) fn lifespan_nanos_for_test(&self) -> u64 {
        self.lifespan_nanos.load(Ordering::Relaxed)
    }

    /// Tests only: a weak reference to this reader's subscriber, the same
    /// one the room's own retry closure (`ReaderBuilder::build`) holds --
    /// upgradeable exactly as long as `subscriber_for_sample_lost` (or any
    /// other strong hold this reader owns) still exists.
    #[cfg(test)]
    pub(super) fn subscriber_weak_for_test(
        &self,
    ) -> std::sync::Weak<super::subscriber::ReaderSubscriber<T>> {
        self.subscriber_for_sample_lost
            .as_ref()
            .map(Arc::downgrade)
            .unwrap_or_default()
    }

    /// Pump samples from network ring to cache.
    ///
    /// Decodes all pending samples and stores them in the cache.
    fn pump_ring_to_cache(&self, announce_transitions: bool) -> Result<()> {
        let pushed = self.pump_pending()?;

        // Update status condition. When this pump pushed at least one
        // sample the cache cannot have been empty at push time, so the
        // (inherently racy) emptiness probe and its cache mutex cycle
        // are skipped -- an equivalent legal execution. This pump has
        // no pop of its own to derive emptiness from (read() and the
        // instance helpers pop afterwards, under their own lock), so
        // the probe stays; it is not on the take() path.
        if pushed == 0 && self.cache.is_empty() {
            self.clear_data_available_if_idle(announce_transitions);
        }

        Ok(())
    }

    /// The pump alone: move every pending ring entry into the cache and
    /// return how many were deposited, WITHOUT touching DATA_AVAILABLE.
    ///
    /// `pump_ring_to_cache` is this plus the idle clear. The split exists
    /// for the ReadCondition evaluation (`conditions.rs`): evaluating a
    /// condition's trigger has to see the samples the rings hold, but it
    /// is neither a read nor a take, and DDS v1.4 Sec.2.2.4.2.2 lets only
    /// those two reset DATA_AVAILABLE.
    pub(super) fn pump_pending(&self) -> Result<usize> {
        // See `take_projected`'s `_delivering`.
        let _delivering = super::notices::Delivering::enter();
        let _gate = self.consume()?;
        self.pump_pending_gated()
    }

    /// The one door of every sample-accessing operation: the consumer gate,
    /// after the check DDS v1.4 Sec.2.2.2.5.2.8 makes of a reader of a
    /// Subscriber of GROUP access scope: read and take (and their
    /// `_w_condition` forms) are called inside a `begin_access` bracket,
    /// "otherwise the sample-accessing operations will return the error
    /// PRECONDITION_NOT_MET". The scope is the Subscriber's PRESENTATION
    /// ("PRESENTATION QosPolicy of the Subscriber to which the DataReader
    /// belongs"), whatever the reader's own coherent or ordered access.
    pub(super) fn consume(&self) -> Result<super::consumer_gate::ConsumerGuard<'_>> {
        if let Some(gate) = self.access_gate.as_ref() {
            if gate.group_scope() && gate.access_depth() == 0 {
                return Err(crate::dds::Error::InvalidState(
                    "PRECONDITION_NOT_MET: a reader of a GROUP-scope Subscriber is read inside \
                     Subscriber::begin_access/end_access (DDS v1.4 Sec.2.2.2.5.2.8)"
                        .to_string(),
                ));
            }
        }
        Ok(self.bindings.consumer_gate().lock())
    }

    /// The consumer gate alone, for what is not a sample access (a
    /// condition's evaluation).
    pub(super) fn gate(&self) -> super::consumer_gate::ConsumerGuard<'_> {
        self.bindings.consumer_gate().lock()
    }

    /// [`pump_pending`](Self::pump_pending) for a caller that already
    /// holds the [`consumer_gate`](Self::consumer_gate) (the condition
    /// accessors, which keep it across the cache access that follows).
    pub(super) fn pump_pending_gated(&self) -> Result<usize> {
        let slab_pool = rt::get_slab_pool_ref();

        self.probe_writer_lifespan();

        let mut pushed: usize = 0;
        if !self.bindings.needs_merge() {
            // Only the primary source is ready: keep the exact local loop.
            // `pump_entry` is inline(always) with a constant 0 source tag.
            // BY_SOURCE_TIMESTAMP tie-break (DDS v1.4 Sec.2.2.3.17): same
            // one-lookup-per-pump as the fused crown path above, see
            // `ReaderBindings::primary_writer_guid`'s doc.
            let local_writer_guid = self
                .qos
                .destination_order
                .uses_source_timestamp()
                .then(|| self.bindings.primary_writer_guid())
                .flatten();
            let mut freed = false;
            while let Some(entry) = self.ring.pop_noting_full(&mut freed) {
                self.pump_entry(entry, 0, slab_pool, &mut pushed, local_writer_guid)?;
            }
            if freed {
                self.slot_freed();
            }
        } else {
            self.pump_merge(slab_pool, &mut pushed)?;
        }
        Ok(pushed)
    }

    /// Decode one ring entry and feed it through lifespan /
    /// time-based-filter / cache / deadline / NACK bookkeeping. Shared
    /// per-entry body of the single-ring fast path and the K>1 merge
    /// path; `inline(always)` so the K==1 loop keeps the single-ring
    /// straight-line instruction path.
    ///
    /// `seq_tag` distinguishes anonymous local writers in the cache's
    /// dedup key: 0 for the primary ring, `ring_index << 32` for extra
    /// bindings. Known writers use their GUID and full writer SN instead.
    /// Writers have independent sequence spaces; both forms distinguish
    /// different writers' same-SN samples while still deduplicating a
    /// replay from the same writer.
    #[inline(always)]
    fn pump_entry(
        &self,
        entry: rt::IndexEntry,
        seq_tag: u64,
        slab_pool: &Arc<rt::SlabPool>,
        pushed: &mut usize,
        local_writer_guid: Option<[u8; 16]>,
    ) -> Result<()> {
        if let Some(cached) = self.prepare_sample(
            entry,
            seq_tag,
            self.local_hold,
            slab_pool,
            local_writer_guid,
        )? {
            self.cache.push(cached);
            *pushed += 1;
        }
        Ok(())
    }

    /// A pop found a local ring full: wake the writers waiting for its slot
    /// (`RoomWait`), which only a RELIABLE reader has.
    #[cold]
    #[inline(never)]
    fn slot_freed(&self) {
        if self.wakes_writers {
            self.bindings.room_wait.freed_slot();
        }
    }

    /// What a local sample whose entry `hold` says holds in the reader's
    /// history goes back, the sample not reaching the cache: its place and,
    /// when known, its instance count.
    #[cold]
    #[inline(never)]
    fn release_local_hold(&self, hold: u8, instance: Option<&InstanceHandle>) {
        let Some(room) = self.bindings.history_room.as_ref() else {
            return;
        };
        if hold & super::cache::HELD_PLACE != 0 {
            room.give_back(1);
        }
        if hold & super::cache::HELD_INSTANCE != 0 {
            match instance {
                Some(instance) => room.release_instance(instance.as_bytes()),
                None => log::error!(
                    "[READER] topic='{}': a local sample that does not decode, \
                     its instance count cannot be given back",
                    self.topic
                ),
            }
        }
    }

    #[cold]
    #[allow(clippy::too_many_arguments)]
    fn prepare_merged_sample(
        &self,
        entry: rt::IndexEntry,
        seq_tag: u64,
        hold: u8,
        slab_pool: &Arc<rt::SlabPool>,
        dropped: &mut Option<InstanceHandle>,
        local_writer_guid: Option<[u8; 16]>,
    ) -> Result<Option<CachedSample<T>>> {
        if self.qos.presentation.ordered_access && self.bindings.local_read_order().is_some() {
            let token = self
                .bindings
                .local_read_order()
                .and_then(|order| order.claim(Arc::as_ptr(&self.bindings) as usize, entry.handle));
            let prepared = self.prepare_sample_dropping(
                entry,
                seq_tag,
                hold,
                slab_pool,
                dropped,
                local_writer_guid,
            );
            let key = prepared
                .as_ref()
                .ok()
                .and_then(|s| s.as_ref())
                .map(|s| (s.writer_guid, s.seq));
            if let (Some(order), Some(token)) = (self.bindings.local_read_order(), token) {
                order.decoded_token(token, key);
            }
            return prepared;
        }
        self.prepare_sample_dropping(entry, seq_tag, hold, slab_pool, dropped, local_writer_guid)
    }

    /// [`pump_entry`](Self::pump_entry) for an entry that carries a place in
    /// the reader's history (the merge path, which alone pumps the
    /// network ring). The place goes with the cached sample (the cache gives
    /// it back when the sample leaves), or is given back here when the entry
    /// does not become one. The single-ring fast
    /// path never sees such an entry and keeps `pump_entry`.
    ///
    /// `counted`: the entry is counted for its instance in the network room
    /// (`HistoryRoom::reserve_for`). The count goes with the cached sample,
    /// or back to the room when the entry does not become one.
    #[allow(clippy::too_many_arguments)]
    fn pump_entry_holding(
        &self,
        entry: rt::IndexEntry,
        seq_tag: u64,
        slab_pool: &Arc<rt::SlabPool>,
        pushed: &mut usize,
        place: Option<super::admission::HistorySlot>,
        counted: bool,
        hold: u8,
        local_writer_guid: Option<[u8; 16]>,
    ) -> Result<()> {
        let mut dropped = None;
        if !counted {
            if let Some(cached) = self.prepare_merged_sample(
                entry,
                seq_tag,
                hold,
                slab_pool,
                &mut dropped,
                local_writer_guid,
            )? {
                self.cache.push_holding(cached, place, false);
                *pushed += 1;
            }
            return Ok(());
        }
        let prepared = self.prepare_merged_sample(
            entry,
            seq_tag,
            0,
            slab_pool,
            &mut dropped,
            local_writer_guid,
        );
        match prepared {
            Ok(Some(cached)) => {
                self.cache.push_holding(cached, place, true);
                *pushed += 1;
            }
            Ok(None) => {
                if let (Some(room), Some(dropped)) = (self.bindings.history_room.as_ref(), dropped)
                {
                    room.release_instance(dropped.as_bytes());
                }
            }
            Err(err) => {
                // Bytes this reader encoded itself (the subscriber re-encodes
                // every sample it stores) that no longer decode: the instance
                // they were counted for is unknown, and its count stays.
                log::error!(
                    "[READER] topic='{}' seq={}: a stored sample does not decode, \
                     its instance count cannot be given back",
                    self.topic,
                    entry.seq
                );
                return Err(err);
            }
        }
        Ok(())
    }

    /// A ring entry that is an instance lifecycle change (a local writer's
    /// dispose or unregister, see `IndexEntry::mark_lifecycle`) becomes the
    /// transition the network path queues for a key-only DATA. Returns
    /// false, touching nothing, for an ordinary sample.
    ///
    /// `local_writer_guid` (DDS v1.4 Sec.2.2.3.17 tie-break, BY_SOURCE_TIMESTAMP
    /// only): the identity of the local writer bound to the ring this entry
    /// came from, looked up once per pump by the caller
    /// (`ReaderBindings::primary_writer_guid`'s doc has the exact scope); it
    /// rides the queued [`DisposeEvent`] exactly as a local DATA sample's own
    /// `writer_guid` does, so a local dispose/unregister tied on source
    /// timestamp with another writer's change resolves identically on every
    /// reader. `None` whenever the policy is not requested, which is the
    /// only cost the default path pays here. The writer sequence number
    /// orders it among its own writer's other changes regardless
    /// (`DisposeQueue::pop_if_before`).
    #[inline(always)]
    fn admit_lifecycle_entry(
        &self,
        entry: rt::IndexEntry,
        slab_pool: &Arc<rt::SlabPool>,
        local_writer_guid: Option<[u8; 16]>,
    ) -> bool {
        let kind = match entry.lifecycle_bits() {
            0 => return false,
            1 => DisposeKind::Disposed,
            2 => DisposeKind::Unregistered,
            _ => DisposeKind::DisposedUnregistered,
        };
        let mut key_hash = [0u8; 16];
        {
            let buf = slab_pool.get_buffer(entry.handle);
            let len = (entry.len as usize).min(buf.len());
            let start = entry.payload_offset();
            if len >= start + 16 {
                key_hash.copy_from_slice(&buf[start..start + 16]);
            }
        }
        if entry.is_exclusive() {
            slab_pool.release_exclusive(entry.handle);
        } else {
            slab_pool.release(entry.handle);
        }
        // An unregister leaves the instance without writers only if no other
        // ALIVE writer, remote or local, still holds it (DDS v1.4
        // Sec.2.2.2.4.2.7, Sec.2.2.3.23.2). The sender forgot the instance
        // before emitting the change. A remote writer whose LIVELINESS
        // lease expired keeps its registration recorded but must not mask
        // this: `is_held_alive` excludes it, `is_held` would not.
        if kind == DisposeKind::Unregistered
            && self
                .bindings
                .ownership
                .registrations
                .is_held_alive(&key_hash)
        {
            return true;
        }
        let seq = u64::from(entry.seq);
        self.dispose_events.push(DisposeEvent {
            key_hash,
            kind,
            seq,
            writer_guid: local_writer_guid,
            order_seq: seq,
            announced: false,
            read: false,
            from_local_writer: true,
            disposed_generation_count: 0,
            no_writers_generation_count: 0, // overwritten by `push`
            // The local writer's own clock reading at `dispose`/
            // `unregister_instance` time (or its `_w_timestamp` override,
            // `DataWriter::stamp_source_ts`): the same field a local DATA
            // entry's lifespan check reads, always a genuine source
            // timestamp for an intra-process write.
            source_timestamp_ns: Some(entry.timestamp_ns),
        });
        true
    }

    /// Decode one ring entry, release its slab reference, and run the
    /// lifespan / time-based-filter / deadline / NACK bookkeeping,
    /// returning the [`CachedSample`] ready to be pushed into the cache
    /// (or `None` when the sample is filtered out).
    ///
    /// This is the whole per-entry body of `pump_entry` MINUS
    /// the terminal `cache.push`. Splitting it out lets the fused crown
    /// take() path (`take` on the single-ring topology) decode OUTSIDE
    /// the cache lock and then perform the push + front-pop under one
    /// lock acquisition, while `pump_entry` (the K>1 merge path and the
    /// read()/take_instance()/etc. helpers) keeps pushing per entry.
    ///
    /// The deadline/NACK side effects fire here, immediately after a
    /// sample passes both filters (i.e. only for accepted samples). They
    /// run just BEFORE the cache push; both touch state disjoint from the
    /// cache mutex, so their order relative to the push is not
    /// observable.
    #[inline(always)]
    fn prepare_sample(
        &self,
        entry: rt::IndexEntry,
        seq_tag: u64,
        hold: u8,
        slab_pool: &Arc<rt::SlabPool>,
        local_writer_guid: Option<[u8; 16]>,
    ) -> Result<Option<CachedSample<T>>> {
        let mut dropped = None;
        self.prepare_sample_dropping(
            entry,
            seq_tag,
            hold,
            slab_pool,
            &mut dropped,
            local_writer_guid,
        )
    }

    /// [`prepare_sample`](Self::prepare_sample) that also says, in
    /// `dropped`, the instance of a sample it decoded and then dropped
    /// (lifespan, TIME_BASED_FILTER): the network pump gives back the count
    /// such a sample held for its instance.
    #[inline(always)]
    ///
    /// `hold`: what a sample of a local ring holds in the reader's history
    /// (`local_hold`; 0 for the network ring, whose pump hands its place
    /// over itself). The cached sample carries it; a sample dropped here
    /// gives it back.
    #[allow(clippy::too_many_arguments)]
    fn prepare_sample_dropping(
        &self,
        entry: rt::IndexEntry,
        seq_tag: u64,
        hold: u8,
        slab_pool: &Arc<rt::SlabPool>,
        dropped: &mut Option<InstanceHandle>,
        local_writer_guid: Option<[u8; 16]>,
    ) -> Result<Option<CachedSample<T>>> {
        if self.admit_lifecycle_entry(entry, slab_pool, local_writer_guid) {
            return Ok(None);
        }
        let data_len = entry.len as usize;

        // GUID-prefixed entries (network path) carry the 16-byte writer
        // GUID ahead of the encoded sample and `len` covers both; split
        // the prefix off before decoding. A BY_SOURCE_TIMESTAMP reader's
        // network entries also carry the writer's full sequence number
        // after it, and an intra-process write with an explicit source
        // timestamp its write-time clock (`IndexEntry::payload_offset`).
        // The length guard keeps a malformed entry on the decode-error
        // path instead of panicking on the slice.
        let prefix = entry.payload_offset();
        let payload_start = if prefix != 0 && data_len >= prefix {
            prefix
        } else {
            0
        };
        // A local entry may have a reception-time prefix but still needs
        // opaque identity capture. Network entries were captured at receipt.
        let local_entry = !(entry.has_guid_prefix()
            || seq_tag == (1u64 << 32) && self.bindings.network.is_some());
        let local_capture = local_entry
            .then(|| self.bindings.local_capture(&entry))
            .flatten();
        let mut writer_guid = local_capture.and_then(|capture| capture.writer_guid);
        let mut writer_sn: Option<u64> = None;

        // Pool tiers decode straight from the slab slot (no Cow
        // wrapper on the hot path); the rare Heap tier copies out
        // from behind the pool mutex via get_buffer.
        // Copy metadata while this entry still owns its slab. The release
        // after decoding can immediately make that slot available for reuse.
        let received_counts = entry
            .has_generation_counts()
            .then(|| slab_pool.generation_counts(entry.handle));
        let decode_result = match slab_pool.try_borrow(entry.handle) {
            Some(buf) => {
                if payload_start >= 16 && entry.has_guid_prefix() {
                    let mut guid = [0u8; 16];
                    guid.copy_from_slice(&buf[..16]);
                    writer_guid = Some(guid);
                    writer_sn = entry.writer_sn_in(buf);
                }
                {
                    let bytes = &buf[payload_start..data_len];
                    let captured;
                    let bytes = if local_entry {
                        captured =
                            T::capture_wire_data(bytes, local_capture.map(|capture| capture.key));
                        captured.as_ref()
                    } else {
                        bytes
                    };
                    T::decode(bytes, entry.cdr_version)
                }
            }
            None => {
                let buf = slab_pool.get_buffer(entry.handle);
                if payload_start >= 16 && entry.has_guid_prefix() {
                    let mut guid = [0u8; 16];
                    guid.copy_from_slice(&buf[..16]);
                    writer_guid = Some(guid);
                    writer_sn = entry.writer_sn_in(&buf);
                }
                {
                    let bytes = &buf[payload_start..data_len];
                    let captured;
                    let bytes = if local_entry {
                        captured =
                            T::capture_wire_data(bytes, local_capture.map(|capture| capture.key));
                        captured.as_ref()
                    } else {
                        bytes
                    };
                    T::decode(bytes, entry.cdr_version)
                }
            }
        };

        // EXCLUSIVE entries (single-registered-reader push) transferred
        // sole ownership: free the slot directly, never touching the
        // refcount side-table line (crown 1w1r stays at one release
        // RMW). Everything else drops its reference through the
        // refcounted path.
        if entry.is_exclusive() {
            slab_pool.release_exclusive(entry.handle);
        } else {
            slab_pool.release(entry.handle);
        }

        match decode_result {
            Ok(data) => {
                // Compute instance handle from @key fields
                let instance_handle = InstanceHandle::new(data.compute_key());

                // Lifespan check: discard samples older than the effective
                // lifespan (`min(self_qos, any matched writer QoS)`).
                // `entry.timestamp_ns` is the writer's source timestamp
                // (INFO_TS) when present, else reception time, so a
                // reliable catch-up burst expires by write time per
                // DDS v1.4 sec. 2.2.3.16 / RTPS v2.5 sec. 8.7.7.
                let lifespan_nanos = self.lifespan_of(writer_guid.as_ref());
                if lifespan_nanos != u64::MAX {
                    let age_ns = current_time_ns().saturating_sub(entry.timestamp_ns);
                    if age_ns > lifespan_nanos {
                        log::debug!(
                            "[READER] lifespan expired topic='{}' seq={}",
                            self.topic,
                            entry.seq
                        );
                        *dropped = Some(instance_handle);
                        if hold != 0 {
                            self.release_local_hold(hold, Some(&instance_handle));
                        }
                        return Ok(None);
                    }
                }

                let by_source = self.cache.instances().by_source_timestamp();
                // TIME_BASED_FILTER (DDS v1.4 Sec.2.2.3.12): a reader that does
                // not order by source timestamp shows its samples through the
                // cache (`SampleCache::with_time_based_filter`), on the instant
                // they enter it. One that does asks the filter inside its
                // admission below, so that a sample the ordering refuses
                // consumes no interval.

                let mut cached = CachedSample::with_meta(
                    data,
                    seq_tag | u64::from(entry.seq),
                    entry.timestamp_ns,
                    instance_handle,
                    writer_guid,
                    entry.has_source_ts(),
                );
                // DDS v1.4 Sec.2.2.3.17 tie-break: a local sample's entry
                // never carried a GUID prefix (no network wire framing), so
                // `writer_guid` decoded above is always `None` for one.
                // `local_writer_guid` (the caller's one lookup per pump,
                // `None` unless BY_SOURCE_TIMESTAMP is requested) supplies
                // the identity `SourceOrderKey` needs; a remote sample's
                // real, decoded GUID is never overwritten.
                if cached.writer_guid.is_none() {
                    cached.writer_guid = local_writer_guid;
                }
                // A known writer's GUID already distinguishes its dedup
                // domain: reuse `seq` for its full writer SN, including
                // presentation against lifecycle changes. Only anonymous
                // local samples need the ring tag in the upper bits.
                if cached.writer_guid.is_some() {
                    cached.seq = writer_sn.unwrap_or(u64::from(entry.seq));
                }
                if let Some(counts) = received_counts {
                    cached.stamp_received(counts);
                }
                if by_source
                    && !cached.receipt_stamped()
                    && !self.admit_by_source(&entry, &mut cached, writer_sn)
                {
                    log::debug!(
                        "[READER] source-order stale topic='{}' seq={}",
                        self.topic,
                        entry.seq
                    );
                    *dropped = Some(instance_handle);
                    if hold != 0 {
                        self.release_local_hold(hold, Some(&instance_handle));
                    }
                    return Ok(None);
                }
                if hold != 0 {
                    cached.set_held(hold);
                }

                // NACK bookkeeping happens at admission in
                // ReaderSubscriber::process_admitted, not here at pop time.
                Ok(Some(cached))
            }
            Err(e) => {
                log::error!(
                    "[READER] decode failed topic='{}' seq={} len={}: {}",
                    self.topic,
                    entry.seq,
                    data_len,
                    e
                );
                if hold != 0 {
                    self.release_local_hold(hold, None);
                }
                Err(e)
            }
        }
    }

    /// BY_SOURCE_TIMESTAMP admission (DDS v1.4 Sec.2.2.3.17) of a local
    /// sample. Network entries arrive already admitted and stamped; its key
    /// is the entry's source timestamp (none when the entry carries only a
    /// reception time), the writer `cached` names and that writer's full
    /// sequence number (`writer_sn`, from a network entry's prefix; a
    /// local entry's own `seq` is the writer's full number, which an
    /// intra-process write keeps below 2^32). The revive rule compares
    /// that same full number with a transition's (`Origin`). Writer presence
    /// (Sec.2.2.2.5.1.3) and TIME_BASED_FILTER (Sec.2.2.3.12) are decided
    /// under the same instance lock (`InstanceTable::admit_by_source`), so
    /// a sample the ordering refuses still revives a writerless instance
    /// its writer holds, and consumes no filter interval. Returns whether
    /// the sample is admitted.
    fn admit_by_source(
        &self,
        entry: &rt::IndexEntry,
        cached: &mut CachedSample<T>,
        writer_sn: Option<u64>,
    ) -> bool {
        let sn = writer_sn.unwrap_or(u64::from(entry.seq));
        let key = entry
            .has_source_ts()
            .then_some(super::cache::SourceOrderKey(
                entry.timestamp_ns,
                cached.writer_guid,
                sn,
            ));
        let origin = (cached.writer_guid, sn);
        let handle = cached.instance_handle;
        let registrations = &self.bindings.ownership.registrations;
        let held = || registrations.is_held_alive(&handle.0);
        let filter = || {
            if self.qos.time_based_filter.is_disabled() {
                return true;
            }
            let mut checkers = self
                .time_filter_checkers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let checker = checkers
                .entry(handle)
                .or_insert_with(|| TimeBasedFilterChecker::new(self.qos.time_based_filter));
            if !checker.should_accept() {
                return false;
            }
            checker.mark_accepted();
            true
        };
        self.cache
            .admit_by_source(cached, key, origin, held, filter)
    }

    /// K>1 drain: merge the primary ring and every extra binding ring
    /// by each head's `merge_key` (when it was written, for the default
    /// BY_RECEPTION_TIMESTAMP; its source timestamp for
    /// BY_SOURCE_TIMESTAMP). Per-writer FIFO is
    /// preserved by construction -- one lookahead slot per ring, ring
    /// order is FIFO -- while cross-writer order is best-effort only:
    /// total order under concurrent pushes is impossible.
    ///
    /// `IndexRing` has no non-destructive peek (pop-only consumer
    /// API), so each ring gets a one-entry lookahead slot: a popped
    /// head is parked until it wins the timestamp race. Ties keep the
    /// lowest ring index (primary first). An entry whose decode fails
    /// cannot be pushed back into its SPSC ring (producer-side op), but
    /// the drain does not stop there: every other ring's parked head,
    /// and whatever that ring's own next entry turns out to be, is
    /// still merged in by the same timestamp order a fully successful
    /// drain would have used -- a later entry from any ring is never
    /// deposited ahead of an earlier one still queued behind the one
    /// that failed. This call's own `Err` carries the FIRST decode
    /// failure met; a later one in the same drain has no Err channel of
    /// its own and counts toward SAMPLE_LOST instead
    /// (`report_parked_heads_lost`).
    ///
    /// The binding-table mutex is held for the whole drain: it makes
    /// this reader the single consumer of every binding ring even
    /// under concurrent `take()` callers, and binds are cold-path.
    ///
    /// A drain that deposited runs the deposit side of the idle
    /// re-check (`cover_deposit`) once the mutex is released: the
    /// argument does not need the mutex, and the re-raise's WaitSet
    /// signal takes the condition's hook mutex. It runs on the error
    /// path too, for the entries deposited before the failing one.
    #[cold]
    fn pump_merge(&self, slab_pool: &Arc<rt::SlabPool>, pushed: &mut usize) -> Result<()> {
        let before = *pushed;
        let result = self.pump_merge_locked(slab_pool, pushed);
        if *pushed > before {
            self.cover_deposit();
        }
        result
    }

    /// The drain itself, under the binding-table mutex (`pump_merge`).
    fn pump_merge_locked(&self, slab_pool: &Arc<rt::SlabPool>, pushed: &mut usize) -> Result<()> {
        let entries = self
            .bindings
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Ring set: primary first (index 0 = seq tag 0, the same dedup
        // domain as the fast path), then the dedicated network source,
        // then local extras in registration order.
        // Indices are stable across pumps: the binding list is
        // append-only until reader drop.
        let mut rings: Vec<&Arc<rt::IndexRing>> =
            Vec::with_capacity(entries.len() + 1 + usize::from(self.bindings.network.is_some()));
        rings.push(&self.ring);
        if let Some(network) = self.bindings.network.as_ref() {
            rings.push(network);
        }
        for binding in entries.iter() {
            if !Arc::ptr_eq(&binding.ring, &self.ring) {
                rings.push(&binding.ring);
            }
        }

        // BY_SOURCE_TIMESTAMP tie-break (DDS v1.4 Sec.2.2.3.17): one writer
        // identity lookup per ring, built in the EXACT same order as
        // `rings` above (primary, network, then local extras) so
        // `writer_guids[idx]` names the right writer for whichever ring
        // `idx` drained from this pass -- the same per-ring lookup
        // `primary_writer_guid` does for the crown path, widened here to
        // every ring this merge drains. `None` for the network ring
        // (always remote) and an empty vector whenever the policy is not
        // requested, which is the only cost the default path pays here
        // (see `ReaderBindings::primary_writer_guid`'s doc for the scope).
        let writer_guids: Vec<Option<[u8; 16]>> =
            if self.qos.destination_order.uses_source_timestamp() {
                let mut guids = Vec::with_capacity(rings.len());
                guids.push(entries.first().and_then(|binding| binding.writer_guid));
                if self.bindings.network.is_some() {
                    guids.push(None);
                }
                for binding in entries.iter() {
                    if !Arc::ptr_eq(&binding.ring, &self.ring) {
                        guids.push(binding.writer_guid);
                    }
                }
                guids
            } else {
                Vec::new()
            };

        // The network ring's consumer side, for the whole drain: a KEEP_LAST
        // producer that finds it full pops it too (`HistoryRoom::consume`).
        let _network_consumer = self
            .bindings
            .history_room
            .as_ref()
            .map(|room| room.consume());
        let mut heads: Vec<Option<rt::IndexEntry>> = vec![None; rings.len()];
        let by_source = self.cache.instances().by_source_timestamp();
        // The history place each parked network entry carries (index 1 is
        // the network ring when there is one): adopted as the entry leaves
        // its ring, handed to the cached sample, given back if the entry is
        // dropped on the way.
        let network_index = self.bindings.network.as_ref().map(|_| 1usize);
        let mut places: Vec<Option<super::admission::HistorySlot>> =
            std::iter::repeat_with(|| None).take(rings.len()).collect();
        // A local ring popped while full: a writer may wait for the slot.
        let mut freed = false;
        // The first decode failure this drain meets: returned as this
        // call's own `Err`, exactly as a K==1 pump's would be. A SECOND
        // (or later) failure in the same drain has no such channel of
        // its own -- `lost` counts it instead (a dispose/unregister
        // marker is not a sample, `lifecycle_bits() == 0` excludes it).
        let mut first_err = None;
        let mut lost: u64 = 0;
        loop {
            // Refill empty lookahead slots, then pick the smallest
            // timestamp among the parked heads. A ring whose last pop
            // failed to decode is refilled here exactly like any other:
            // its next entry (if any) competes on its own timestamp, the
            // same as a normal pass would have ordered it, never ahead of
            // nor behind a sibling ring's still-parked head by anything
            // other than timestamp.
            let mut best: Option<(usize, u64)> = None;
            for (i, ring) in rings.iter().enumerate() {
                if heads[i].is_none() {
                    let mut was_full = false;
                    heads[i] = ring.pop_noting_full(&mut was_full);
                    freed |= was_full && Some(i) != network_index;
                    if heads[i].is_some() && Some(i) == network_index {
                        places[i] = self
                            .bindings
                            .history_room
                            .as_ref()
                            .map(super::admission::HistoryRoom::adopt);
                    }
                }
                if let Some(head) = heads[i].as_ref() {
                    let key = Self::merge_key(head, by_source, slab_pool);
                    if best.is_none_or(|(_, best_key)| key < best_key) {
                        best = Some((i, key));
                    }
                }
            }
            let Some((idx, _)) = best else {
                break; // every ring drained
            };
            if let Some(entry) = heads[idx].take() {
                let seq_tag = (idx as u64) << 32;
                // The entry is out of its ring and not yet in the cache.
                #[cfg(test)]
                self.run_pump_deposit_hook();
                let place = places[idx].take();
                let counted = Some(idx) == network_index
                    && self
                        .bindings
                        .history_room
                        .as_ref()
                        .is_some_and(|room| room.counts_instances());
                // A local ring's sample holds what its writer's door took
                // in the reader's history (`local_hold`); the network
                // ring's place travels as `place`.
                let hold = if Some(idx) == network_index {
                    0
                } else {
                    self.local_hold
                };
                let is_sample = entry.lifecycle_bits() == 0;
                let local_writer_guid = writer_guids.get(idx).copied().flatten();
                if let Err(err) = self.pump_entry_holding(
                    entry,
                    seq_tag,
                    slab_pool,
                    pushed,
                    place,
                    counted,
                    hold,
                    local_writer_guid,
                ) {
                    // DDS v1.4 Sec.2.2.3.19 footnote 28 / RTPS v2.5
                    // Sec.8.4.12.2.8: a change already added to reader
                    // history (for a RELIABLE reader, already credited to
                    // its writer proxy, RTPS v2.5 Sec.8.4.12) is kept, or
                    // its writer is allowed to retransmit it; an ACK does
                    // not license discarding it. This entry cannot go
                    // back into its ring (no safe SPSC push from the
                    // consumer side) and its own decode failed, so
                    // nothing can keep IT -- but every sibling ring's
                    // already-parked head, and whatever that ring's own
                    // next entry turns out to be, still goes through this
                    // same loop, in the same timestamp order a fully
                    // successful drain would have used.
                    if first_err.is_none() {
                        first_err = Some(err);
                    } else if is_sample {
                        lost += 1;
                    }
                }
            }
        }
        if lost > 0 {
            self.report_parked_heads_lost(lost);
        }
        if freed {
            self.slot_freed();
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// What the K>1 merge orders a ring's head by. BY_SOURCE_TIMESTAMP
    /// (DDS v1.4 Sec.2.2.3.17): its source timestamp, the order the
    /// reader's admission keeps. BY_RECEPTION_TIMESTAMP: when it was
    /// written, which is the entry's own timestamp unless the write
    /// carried an application-supplied source timestamp, whose write time
    /// then rides the slab payload (`IndexEntry::reception_ts_in`): an
    /// application's timestamp never reorders a default reader's writers.
    /// Local history replay retains its zero reception key while the entry
    /// carries source time beside the shared, unprefixed retained slab.
    #[inline]
    fn merge_key(head: &rt::IndexEntry, by_source: bool, slab_pool: &rt::SlabPool) -> u64 {
        if !by_source && head.is_local_replay() {
            return 0;
        }
        if by_source || !head.has_reception_ts_prefix() {
            return head.timestamp_ns;
        }
        slab_pool
            .read_array::<8>(head.handle, head.payload_offset() - 8)
            .map(u64::from_le_bytes)
            .unwrap_or(head.timestamp_ns)
    }

    /// Account `count` parked DATA samples a mid-merge failure
    /// (`pump_merge_locked`) dropped with no other record: DDS v1.4
    /// Sec.2.2.4.1 SAMPLE_LOST, bumping the same cumulative status
    /// `get_sample_lost_status` reads back. A no-op for `count == 0`, the
    /// common case: the entry whose decode actually failed is reported
    /// through its own `Err`, never counted here.
    #[cold]
    fn report_parked_heads_lost(&self, count: u64) {
        if count == 0 {
            return;
        }
        // One door: `ReaderSubscriber::report_sample_lost` already updates
        // this same (shared) status, clears/raises the same
        // StatusCondition, and calls the same listener -- a second
        // counter here would move the count without ever reaching the
        // listener or the WaitSet it owes a notification. `None` only
        // once `Drop` has already cleared it (teardown in progress): no
        // one is left to tell.
        if let Some(subscriber) = self.subscriber_for_sample_lost.as_ref() {
            subscriber.report_sample_lost(count);
        }
    }

    /// Per-reader figures. `messages_received` and `drops` are the same
    /// counts the process telemetry carries, raised at the same doors, so
    /// they are per-reader and independent of whether telemetry is on.
    /// A sample still queued in the transport ring is not yet counted
    /// (the ring-to-history pump runs when the application next accesses
    /// the reader), so call this after `take`/`read` for a settled figure.
    #[must_use]
    pub fn stats(&self) -> ReaderStats {
        ReaderStats {
            messages_received: self.cache.total_received() as u64,
            bytes_received: 0,
            drops: self.cache.dropped() + self.dropped.load(Ordering::Relaxed),
        }
    }

    /// Drain all pending dispose/unregister lifecycle events.
    ///
    /// Returns events in the order they were received from the network.
    /// Each event indicates an instance that was disposed or unregistered
    /// by a remote writer.
    ///
    /// # Deprecated since 1.5.0
    ///
    /// Instance-state changes are delivered through the ordinary read
    /// path: `take_with_info()` returns them as `(None, info)` with
    /// `info.valid_data == false` and `info.instance_state` set, which is the
    /// shape every DDS implementation uses and the only one a non-Rust binding
    /// can reach.
    ///
    /// The method still works and still drains the SAME store - there is not a
    /// second queue - so whichever consumer is called first wins and the other
    /// sees nothing.
    ///
    /// It is NOT redundant, and that is a property of DDS rather than of this
    /// implementation. The standard defines exactly three instance states
    /// (ALIVE, NOT_ALIVE_DISPOSED, NOT_ALIVE_NO_WRITERS), so an instance that
    /// was disposed AND unregistered is simply reported as DISPOSED: the two
    /// facts are not simultaneously representable in `SampleInfo`. An
    /// implementation may close that gap with a QoS extension rather than a
    /// fourth state. This
    /// accessor carries the precise `DisposeKind`, which is why the OMG
    /// conformance binary in `examples/shape_main.rs` still uses it: it has to
    /// render both transitions for the combined case.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use hdds::{Participant, QoS, Result};
    /// # fn main() -> Result<()> {
    /// # let participant = Participant::builder("test").build()?;
    /// # let reader = participant.create_reader::<MyType>("topic", QoS::default())?;
    /// for event in reader.get_dispose_events() {
    ///     println!("Instance {:02x?} was {:?}", &event.key_hash[..4], event.kind);
    /// }
    /// # Ok(())
    /// # }
    /// # #[derive(hdds::DDS, Debug)] struct MyType { x: i32 }
    /// ```
    /// A type-erased drain for this reader's dispose queue.
    ///
    /// For adapters whose own API cannot carry an instance-state change and
    /// that would therefore never call `get_dispose_events` - the rmw layer
    /// is one. An undrained queue grows for the life of the reader AND keeps
    /// the dispose status true, because a DDS status is level-triggered and
    /// only a read settles it. The closure holds the queue, not the reader,
    /// so it does not keep the reader alive.
    pub(crate) fn dispose_drain_hook(&self) -> impl Fn() + Send + Sync + 'static {
        let queue = Arc::clone(&self.dispose_events);
        move || {
            let _discarded = queue.drain();
        }
    }

    #[deprecated(
        since = "1.5.0",
        note = "read instance state through take_with_info(), which returns it as a sample \
                with valid_data = false. This remains the only accessor carrying the exact \
                transition, including disposed AND unregistered, which the three states of \
                SampleInfo cannot express. Both drain the same store, so whichever is called \
                first wins."
    )]
    pub fn get_dispose_events(&self) -> Vec<InstanceDisposeEvent> {
        self.dispose_events
            .drain()
            .into_iter()
            .map(|e| InstanceDisposeEvent {
                key_hash: e.key_hash,
                kind: e.kind,
                seq: e.seq,
            })
            .collect()
    }

    /// The sample cache, for the condition evaluation in `conditions.rs`.
    #[inline]
    pub(super) fn cache(&self) -> &SampleCache<T> {
        &self.cache
    }

    /// The dispose queue, for the condition evaluation in `conditions.rs`.
    #[inline]
    pub(super) fn dispose_events(&self) -> &Arc<DisposeQueue> {
        &self.dispose_events
    }

    /// Emptiness across every ring, for `take_w_condition`'s idle clear.
    #[inline]
    pub(super) fn rings_idle(&self) -> bool {
        self.all_rings_empty()
    }

    /// DATA_AVAILABLE clear after a take variant observed the reader idle
    /// (`conditions.rs`); see `clear_data_available_if_idle`.
    #[inline]
    pub(super) fn clear_data_available_after_take(&self, announce_transitions: bool) {
        self.clear_data_available_if_idle(announce_transitions);
    }

    #[cfg(test)]
    pub(super) fn ring_for_test(&self) -> &Arc<rt::IndexRing> {
        &self.ring
    }

    #[cfg(test)]
    pub(super) fn dispose_queue_for_test(&self) -> &Arc<DisposeQueue> {
        &self.dispose_events
    }

    /// Tests only: the registration table an EXCLUSIVE reader's local
    /// bindings arbitrate in, to share with a hand-built subscriber.
    #[cfg(test)]
    pub(super) fn registrations_for_test(&self) -> &Arc<super::registrations::ReaderRegistrations> {
        &self.bindings.ownership.registrations
    }

    /// Tests only: the reader's per-instance DEADLINE watches, `None`
    /// with an infinite deadline.
    #[cfg(test)]
    pub(super) fn deadlines_for_test(
        &self,
    ) -> Option<&Arc<crate::dds::liveliness::ReaderDeadlines>> {
        self.deadlines.as_ref()
    }

    #[cfg(test)]
    pub(super) fn network_ring_for_test(&self) -> Option<&Arc<rt::IndexRing>> {
        self.bindings.network.as_ref()
    }

    #[cfg(test)]
    pub(super) fn network_room_for_test(&self) -> Option<&Arc<super::admission::HistoryRoom>> {
        self.bindings.history_room.as_ref()
    }
}

impl<T: DDS> DataReader<T> {
    /// Tests only: the liveliness of the writers it matches.
    #[cfg(test)]
    pub(crate) fn liveliness_for_test(
        &self,
    ) -> Option<Arc<crate::dds::liveliness::ReaderLiveliness>> {
        self.liveliness.clone()
    }

    /// Tests only: the queues of its ordered listener calls.
    #[cfg(test)]
    pub(super) fn listener_queues_for_test(&self) -> Vec<Arc<super::notices::Ordered>> {
        self.listener_queues.clone()
    }
}

impl<T: DDS> Drop for DataReader<T> {
    fn drop(&mut self) {
        let _ordered_notices = self
            .bindings
            .local_read_order()
            .map(|_| super::notices::Delivering::enter());
        // Retire this reader from SEDP: the dispose of its announcement goes
        // to the peers already known (DDS v1.4 Sec.2.2.2.5.2.6
        // delete_datareader, RTPS v2.5 Sec.8.5.4.4). Its place in this body
        // is a reading choice, not an order a peer can observe (unlike the
        // DataWriter's, after its unregisters): nothing else in this body
        // sends a message.
        drop(self.sedp_retirement.take());

        // Nothing more reaches its listener.
        for queue in &self.listener_queues {
            queue.close();
        }
        if let Some(deadlines) = self.deadlines.as_ref() {
            deadlines.close();
        }
        // No lease of its writers is watched any more.
        if let Some(ref liveliness) = self.liveliness {
            liveliness.close();
        }

        // Stop network fanout before releasing the reader's ring and callback
        // state. The token identifies this reader, not merely its topic.
        self._subscriber_token = None;

        // Drop this reader's own strong hold on its subscriber before the
        // cache/ring teardown below: giving a room's places back
        // (`HistoryRoom::came_back`) schedules that subscriber's
        // weak-reference retry of any coherent set still waiting for room,
        // off this thread. With this field still alive past that point,
        // the retry's upgrade could succeed and commit a set into a ring
        // this drop is about to drain (or has already drained), leaving a
        // slab handle in a ring with no consumer left to pop it. Cleared
        // here, the retry's upgrade sees the same dead weak reference it
        // would have seen had this field never existed.
        self.subscriber_for_sample_lost = None;

        // Unregister this reader's heartbeat handler (RELIABLE only; a
        // no-op field for VOLATILE). Independent of the ring/bindings
        // teardown below, but cleared here alongside the other
        // registry-facing tokens rather than left to the implicit
        // end-of-drop field order.
        self._heartbeat_token = None;

        // Unregister from the domain first: register_writer invokes the
        // auto-bind callback under the domain endpoints write lock, so
        // once the token is gone no new merger registration can be
        // recorded for this reader behind our back.
        self._bind_token = None;

        // Tombstone every binding in its still-alive writer merger so
        // push() stops feeding the dead rings and reader_count()
        // reflects active readers only. Each binding is removed with
        // ITS ring's id: ids are ring addresses and rings differ per
        // binding. remove_reader also drains the dead ring
        // and returns its slab references (safe under the refcount
        // side-table). Bindings whose merger already died (writer
        // dropped first) are drained here directly: the sole fan-out
        // producer is gone, and this Drop owns the consumer side.
        //
        // The consumer gate is held for the whole teardown: a writer that
        // found a ring full pops it under the gate (`ReaderBindings::door`),
        // and once `closed` is set it leaves the rings alone.
        let _consumer = self.bindings.consumer_gate().lock();
        self.bindings.closed.store(true, Ordering::Release);
        if let Some(order) = self.bindings.local_read_order() {
            order.forget_reader(Arc::as_ptr(&self.bindings) as usize);
        }
        #[cfg(any(test, feature = "test-support"))]
        {
            let hook = self
                .bindings
                .after_order_forget
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
        // A writer waiting for room in this reader's history waits no more:
        // its registration is tombstoned below, and it re-checks that.
        self.bindings.room_wait.close();
        let slab_pool = rt::get_slab_pool_ref();
        let bound = std::mem::take(
            &mut *self
                .bindings
                .entries
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for binding in &bound {
            if let Some(merger) = binding.merger.upgrade() {
                merger.remove_reader(rt::merger::ReaderId::from_ring(&binding.ring), slab_pool);
            } else {
                while let Some(entry) = binding.ring.pop() {
                    if !entry.handle.is_empty() {
                        slab_pool.release(entry.handle);
                    }
                }
            }
        }
        if let Some(network) = self.bindings.network.as_ref() {
            let _consumer = self
                .bindings
                .history_room
                .as_ref()
                .map(|room| room.consume());
            while let Some(entry) = network.pop() {
                drop(
                    self.bindings
                        .history_room
                        .as_ref()
                        .map(super::admission::HistoryRoom::adopt),
                );
                if !entry.handle.is_empty() {
                    slab_pool.release(entry.handle);
                }
            }
        }
    }
}

/// Information about a dispose/unregister instance lifecycle event.
///
/// Returned by [`DataReader::get_dispose_events()`] when a remote writer
/// disposes or unregisters an instance.
#[derive(Debug, Clone)]
pub struct InstanceDisposeEvent {
    /// 16-byte key hash identifying the disposed/unregistered instance.
    pub key_hash: [u8; 16],
    /// The kind of lifecycle change.
    pub kind: DisposeKind,
    /// RTPS writer sequence number.
    pub seq: u64,
}

/// Per-`DataReader` figures. Each counter is raised at the door the process
/// telemetry counter of the same meaning is raised at.
#[derive(Default, Debug, Clone, Copy)]
pub struct ReaderStats {
    /// Samples that landed in this reader's history, from any transport.
    /// Counted where the history takes the sample, so `read`, `take`,
    /// `take_batch`, ... report the same figure. A duplicate refused by the
    /// history is not a reception.
    pub messages_received: u64,
    /// Not counted: always 0. The reception doors hand the history a decoded
    /// sample, not its wire length, and the telemetry has no reader-side
    /// byte counter either. Wiring it means carrying the length through
    /// `CachedSample` to the history door.
    pub bytes_received: u64,
    /// Samples of this reader discarded after arrival: pushed out of a full
    /// ring or history before the application read them, or refused by the
    /// reader's content filter. Resource-limit rejections are not drops
    /// (they are reported through `DataReader::get_sample_rejected_status`),
    /// and QoS expiry (lifespan, time-based filter) is not a drop either.
    pub drops: u64,
}

#[cfg(test)]
mod network_ring_tests {
    use super::*;

    #[test]
    fn network_source_is_distinct_from_the_first_local_binding() {
        let primary = Arc::new(rt::IndexRing::with_capacity(16));
        let network = Arc::new(rt::IndexRing::with_capacity(16));
        let status = Arc::new(StatusCondition::new());
        let bindings = ReaderBindings::new(
            Arc::clone(&primary),
            Some(Arc::clone(&network)),
            None,
            16,
            &status,
            None,
            LocalOwnership {
                deadlines: None,
                by_source_timestamp: false,
                registrations: Arc::new(super::super::registrations::ReaderRegistrations::new(
                    false, None, None,
                )),
                key_of: None,
            },
            None,
            None,
            Arc::new(super::super::admission::RoomWait::new()),
            0,
            false,
            None,
        );

        assert!(bindings.network.is_some());
        assert!(!bindings.has_extra_rings());
        assert!(!bindings.needs_merge());

        assert!(network.push(rt::IndexEntry::new_event(1, 0)));
        assert!(bindings.needs_merge());
        assert!(network.pop().is_some());
        assert!(!bindings.needs_merge());

        let merger = Arc::new(rt::TopicMerger::new());
        bindings.bind(&merger);

        let entries = bindings.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(Arc::ptr_eq(&entries[0].ring, &primary));
        assert!(!Arc::ptr_eq(&entries[0].ring, &network));
    }
}

#[cfg(test)]
mod replay_notification_tests {
    use super::*;
    use crate::dds::Condition;

    #[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
    struct Value {
        value: i32,
    }

    #[test]
    fn an_idle_clear_preserves_data_available_for_pending_group_replay() {
        let qos = crate::QoS::reliable()
            .transient_local()
            .keep_all()
            .presentation_group_coherent();
        let participant = crate::Participant::builder("pending_replay_idle_clear")
            .with_transport(crate::TransportMode::IntraProcess)
            .build()
            .unwrap();
        let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
        let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
        let topic = participant
            .topic::<Value>("pending_replay_idle_clear")
            .unwrap();
        let writer = topic
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        publisher.begin_coherent_changes().unwrap();
        writer.write(&Value { value: 1 }).unwrap();
        publisher.end_coherent_changes().unwrap();
        // Keep every replay off the rings while testing its availability:
        // a background binding retry may otherwise publish it concurrently.
        subscriber.begin_access().unwrap();
        let reader = topic
            .reader()
            .qos(qos)
            .subscriber(&subscriber)
            .build()
            .unwrap();
        let status = reader.get_status_condition();
        status.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
        assert!(
            status.get_trigger_value(),
            "queued durable replay is available"
        );
        assert!(
            reader.all_rings_empty(),
            "replay is still behind the bracket"
        );
        assert!(reader.bindings.has_pending_local_replay());
        reader.clear_data_available_if_idle(false);
        assert!(
            status.get_trigger_value(),
            "an empty ring does not settle pending replay"
        );
        subscriber.end_access().unwrap();
    }
}
