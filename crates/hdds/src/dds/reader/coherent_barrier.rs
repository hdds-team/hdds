// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cross-reader coherent presentation barrier.
//!
//! # Problem
//!
//! A publisher that opens a coherent set spanning several topics (DDS v1.4
//! sec. 2.2.3.6 `Presentation.coherent_access`) expects the subscribing side to
//! present the whole cross-topic group consistently. In HDDS each topic is
//! served by an independent [`DataReader`](super::runtime::DataReader) with
//! its own ring, and each per-topic coherent set commits independently on
//! the RX/router thread when that topic's set-completion signal arrives
//! (ECS marker, explicit END, or implicit close -- RTPS v2.5 sec. 8.7.5). With
//! nothing between them, a read cycle can observe topic A's set N while
//! topic B's completion is still in flight: the application sees a torn
//! cross-topic group.
//!
//! # Semantics and spec grounding
//!
//! For GROUP access scope, cross-topic (subscriber-wide) coherent and
//! aligned presentation is spec-mandated (DDS v1.4 sec. 2.2.3.6: the scope of
//! the coherent changes spans all instances belonging to DataWriter
//! entities within the same Publisher). For INSTANCE and TOPIC scope the
//! specification only requires per-instance / per-topic atomicity; this
//! barrier applies the same cross-topic alignment there as well. That is a
//! conforming-but-stricter delivery timing: no spec rule is violated
//! (samples are still delivered complete, in writer order, per topic), the
//! reader merely defers exposing a completed per-topic set until the peer
//! topics of the same remote publisher have also completed one. Reference
//! implementations exhibit the same aligned behaviour through their
//! subscriber-wide presentation caches, so aligning all scopes maximises
//! interoperability of mixed-vendor coherent systems; the cost is bounded
//! extra latency (one peer-topic completion), never data loss.
//!
//! # Mechanism
//!
//! The barrier is a reader-side delivery-ordering coordinator (the wire is
//! untouched, so the HDDS-to-HDDS byte path stays spec-pure). It is owned
//! by the [`Subscriber`](crate::dds::Subscriber) entity and shared by every
//! coherent-access reader attached to that Subscriber at build time. A
//! completed per-topic set is DEPOSITED whole (atomically) instead of being
//! pushed to the reader's ring sample-by-sample. The barrier releases a
//! generation once every member it needs holds its part, and publishes what
//! it released into the readers' rings itself: on the Subscriber's
//! publishing thread while no access bracket is open, at the outermost
//! `begin_access` otherwise (`publish`), never on the thread that
//! deposited. No accessor pulls: a read, a take, a condition's evaluation
//! only read the ring. Inside a bracket the readers hold what the
//! bracket's `begin_access` published, every complete generation of every
//! publisher, and nothing more until the outermost `end_access`.
//!
//! # Per-remote-publisher keying
//!
//! Alignment is scoped per remote publisher: deposits are keyed by the
//! originating DataWriter's GUID prefix (the remote participant identity,
//! RTPS v2.5 sec. 8.2.4.2), and a reader participates in key `K` only when it
//! has a matched writer from `K`. Membership is resolved on the cold path,
//! never by per-message parsing: the SEDP match / writer-dispose hooks
//! register and unregister writers, and a deposit registers the set's
//! writers itself (per-set, on the already-extracted GUIDs). The deposit
//! side matters because the match NOTIFICATION is bookkeeping that can lag
//! the data path by whole read cycles: a committed coherent set from `K`
//! is ground-truth proof of a matched writer from `K`, and a member that
//! has deposited must never be treated as optional by a release round
//! (releasing its peers without it leaves its ring empty in that read
//! cycle: a torn cross-topic group). The release rule for `K` is: once
//! every member with a matched writer from `K` holds at least one complete
//! pending set from `K`, one generation is released for all of them
//! together. Two independent remote publishers therefore never block each
//! other, while the readers fed by the same publisher stay aligned.
//!
//! # Generation alignment and the discovery seam
//!
//! Discovery does not match every reader of the group at the same instant.
//! Under VOLATILE durability the writer sends a reader data from its match
//! point onward only (DDS v1.4 sec. 2.2.3.4), so a member matched N
//! generations later than its peers can never receive those N generations:
//! the peers' held backlog and the late member's first live set belong to
//! DIFFERENT publisher generations, and pairing queue fronts by position
//! would present generation A alongside generation B != A (a torn GROUP
//! presentation) and leave the late member permanently offset from its
//! peers -- the offset later surfaces as read cycles where some members
//! deliver and one has nothing.
//!
//! GROUP-scope sets carry the publisher's group sequence number
//! (RTPS v2.5 sec. 8.7.5, monotonic per publisher), giving the barrier a
//! cross-member generation identity. The release round for a key aligns on
//! it: all generation-tagged queue fronts must sit on the SAME generation;
//! fronts older than the newest front are uncompletable when the
//! newest-front member is VOLATILE (it joined mid-stream and no replay
//! exists) and are discarded until the fronts agree. Durability RxO
//! (DDS v1.4 sec. 2.2.3.4) grounds the discard rule: a replaying
//! (TRANSIENT_LOCAL+) reader only matches retaining writers, so its stream
//! is gap-free from the first retained generation and its fronts never
//! sit permanently ahead of a peer's -- if the newest front nevertheless
//! belongs to a non-VOLATILE member, the barrier waits instead of
//! discarding. A retry count is not proof of unavailable retained data;
//! non-volatile fronts wait until alignment or an explicit loss proof.
//! The one front that never aligns is a generation the other members
//! already presented: a reader created after that presentation receives
//! its part from the writer's retained history, and that part is presented
//! on its own (`release_past_generation`) instead of holding every later
//! generation behind it.
//! Sets
//! without a generation tag (TOPIC/INSTANCE scope,
//! classic marker-less dialects, gate-rescued strays) are wildcards: they
//! neither drive nor block alignment and fill their member's slot in
//! whichever round fires; a real generation displaced by a wildcard is
//! discarded at the next alignment (bounded, self-limiting seam impurity
//! instead of a permanent shift). For TOPIC/INSTANCE scope the
//! specification mandates no cross-topic pairing at all, so the wildcard
//! FIFO behaviour there remains the conforming-but-stricter alignment
//! described above.
//!
//! Two additional rules keep the group safe at the edges:
//!
//! * Startup coherence: no key releases while any active member is still
//!   unresolved (no matched writer registered and nothing deposited yet).
//!   Discovery does not resolve all members at the same instant; without
//!   this rule an early-matched reader would expose its first sets while a
//!   peer destined for the same publisher is still matching, recreating the
//!   torn group during startup.
//! * Departure drain: when a publisher no longer has matched writers on any
//!   member (endpoints disposed), its residual complete generations release
//!   aligned across whichever members still hold them, so a publisher
//!   shutdown never strands delivered-but-unread sets.
//!
//! # Scope
//!
//! Coherent readers and ordered GROUP readers explicitly attached to a
//! Subscriber share this barrier. Other readers never construct or touch it. A single-member
//! group (one coherent reader) releases as soon as a set is deposited:
//! single-topic coherent delivery keeps its pre-barrier behaviour. A member
//! whose reader is torn down is deactivated (see
//! [`forget_member`](CoherentPresentationBarrier::forget_member)) so a dead
//! reader cannot stall its peers.

use super::reorder::PendingPayload;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// Opaque handle identifying a member (one coherent reader) within a
/// barrier.
pub(crate) type MemberId = usize;

/// Remote publisher identity: the Publisher's GUID, the writer's GUID
/// prefix (its participant, RTPS v2.5 Sec.8.2.4.2) and the Publisher's
/// EntityId (its group, Sec.9.3.2.1, PID_GROUP_ENTITY_ID). Two Publishers of
/// one participant are two keys: their sets and generations never mix. A
/// writer whose Publisher is not known (a peer announcing none) is keyed by
/// its participant (`[0; 4]`); an HDDS 1.4.x peer announces one fixed
/// Publisher id for all its writers, one key per participant again.
/// Resolved on the discovery cold path (`Member::resolver`) and memoized
/// per writer: the data path looks the writer up, it does not ask discovery.
pub(crate) type PublisherKey = [u8; 16];

/// The key of Publisher `publisher` of participant `prefix`.
pub(crate) fn publisher_key(prefix: [u8; 12], publisher: [u8; 4]) -> PublisherKey {
    let mut key = [0u8; 16];
    key[..12].copy_from_slice(&prefix);
    key[12..].copy_from_slice(&publisher);
    key
}

/// What discovery knows of a remote writer's Publisher (its EntityId).
pub(crate) type PublisherResolver = Arc<dyn Fn(&[u8; 16]) -> Option<[u8; 4]> + Send + Sync>;

/// A complete per-topic coherent set queued for aligned delivery.
///
/// `writers` groups the set's payloads by originating DataWriter GUID so
/// the delivery closure can preserve per-writer FIFO order (a GROUP-scope
/// reader may aggregate several writers of the same Publisher into one set;
/// TOPIC/INSTANCE scope always has a single writer entry).
pub(crate) struct CoherentSet {
    pub writers: Vec<([u8; 16], Vec<PendingPayload>)>,
    /// Publisher-level generation identity: the group sequence number the
    /// set was closed under (RTPS v2.5 8.7.5), when the dialect carries
    /// one. `None` for TOPIC/INSTANCE-scope sets, classic (marker-less)
    /// dialects and rescue sets whose identity was lost: such sets are
    /// alignment wildcards (see the module docs).
    pub gsn: Option<u64>,
    /// The member's part of a GROUP set of the spec dialect it could not
    /// make whole (`gsn` is the set's): the set is incomplete for the
    /// Subscriber, and every member's part of it is discarded, reported
    /// lost, never delivered (RTPS v2.5 Sec.8.7.6).
    pub lost: bool,
}

impl CoherentSet {
    /// One set from a single writer (TOPIC / INSTANCE scope, and the common
    /// single-writer GROUP case). No generation identity.
    pub fn single(writer_guid: [u8; 16], payloads: Vec<PendingPayload>) -> Self {
        Self {
            writers: vec![(writer_guid, payloads)],
            gsn: None,
            lost: false,
        }
    }

    /// A member's part of the GROUP set `gsn` of the spec dialect: possibly
    /// empty (the member's writers wrote nothing in it, D6), possibly
    /// `lost`. Deposited all the same, so every member holds every
    /// generation and the round aligns on it.
    pub fn spec_part(writers: Vec<([u8; 16], Vec<PendingPayload>)>, gsn: u64, lost: bool) -> Self {
        Self {
            writers,
            gsn: Some(gsn),
            lost,
        }
    }

    /// Total sample count across all writer entries (test diagnostics).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.writers.iter().map(|(_, p)| p.len()).sum()
    }

    /// Whether the set carries no samples (a completed-but-empty commit,
    /// which the deposit path skips).
    pub fn is_empty(&self) -> bool {
        self.writers.iter().all(|(_, p)| p.is_empty())
    }
}

/// Closure that hands an aligned set to its reader's ring. Registered as an
/// `Arc` capturing a `Weak` reference to the reader subscriber so the
/// barrier never keeps a matched reader alive (no Arc cycle): a dropped
/// reader makes the closure a no-op. Cloned out from under the lock before
/// it runs, so a user listener callback is never invoked while the barrier
/// mutex is held.
type DeliverFn = Arc<dyn Fn(CoherentSet) + Send + Sync>;

struct Member {
    /// Topic name, for diagnostics only.
    #[allow(dead_code)]
    topic: String,
    /// Completed sets deposited by the commit paths, awaiting alignment,
    /// keyed by remote publisher.
    ready: HashMap<PublisherKey, VecDeque<CoherentSet>>,
    /// Aligned sets awaiting their publication into this member's ring.
    released: VecDeque<CoherentSet>,
    /// Matched remote writers (SEDP cold path), each with its Publisher's
    /// key: the ground truth for `key_counts`. Tracking GUIDs keeps
    /// register/unregister idempotent.
    writers: HashMap<[u8; 16], PublisherKey>,
    /// A writer's Publisher, from discovery (`attach_resolver`).
    resolver: Option<PublisherResolver>,
    /// Number of matched writers per remote publisher. A member is
    /// required for key `K` while `key_counts[K] > 0`.
    key_counts: HashMap<PublisherKey, usize>,
    /// Ring-delivery closure, attached after the reader's `Arc` exists.
    deliver: Option<DeliverFn>,
    /// Whether this member still participates in the alignment barrier. A
    /// reader that is torn down is deactivated (the safety valve) so its
    /// peers resume aligned delivery instead of waiting forever for a set
    /// it will never send.
    active: bool,
    /// Sticky flag: true once the member has registered a matched writer or
    /// deposited a set. While any active member is unresolved, no key
    /// releases (startup coherence, see the module docs). Never reset --
    /// losing every writer later must not re-freeze unrelated publishers.
    resolved: bool,
    /// Whether this member's reader is VOLATILE (DDS v1.4 2.2.3.4). A
    /// VOLATILE reader receives no history on match, so generations
    /// published before its match point can never reach it: the alignment
    /// rule may discard them (see the module docs). A TRANSIENT_LOCAL or
    /// stronger reader replays history (durability RxO guarantees the
    /// writer retains it), so nothing may be discarded on its account.
    volatile: bool,
    /// The newest generation of each remote publisher whose release round
    /// this member took part in (its own part, or an untagged set filling
    /// its slot): what it has already presented of that publisher's stream.
    presented: HashMap<PublisherKey, u64>,
}

impl Member {
    fn new(topic: String, volatile: bool) -> Self {
        Self {
            topic,
            ready: HashMap::new(),
            released: VecDeque::new(),
            writers: HashMap::new(),
            resolver: None,
            key_counts: HashMap::new(),
            deliver: None,
            active: true,
            resolved: false,
            volatile,
            presented: HashMap::new(),
        }
    }

    fn has_ready(&self, key: &PublisherKey) -> bool {
        self.ready.get(key).is_some_and(|q| !q.is_empty())
    }
}

/// Shared cross-reader coherent presentation barrier for one Subscriber.
///
/// Members register once at reader build (cold path); `deposit` (RX/router
/// thread) and `publish` (the publishing thread, or the outermost
/// `begin_access`) are the only recurring operations and each holds the
/// mutex only for O(members) queue shuffling. Ring delivery runs OUTSIDE
/// the lock.
pub(crate) struct CoherentPresentationBarrier {
    inner: Mutex<BarrierState>,
    /// How many `begin_access` brackets are open (DDS v1.4 Sec.2.2.2.5.2.8:
    /// they nest). While one is open nothing new reaches the readers: what
    /// the application accesses inside it is what the outermost
    /// `begin_access` published. An atomic: every access of a GROUP reader
    /// reads it (`DataReader::consume`), with no lock. A publication reads
    /// it under `publishing`, which an opening bracket waits for.
    depth: AtomicU32,
    /// Whether the Subscriber's PRESENTATION access scope is GROUP: only
    /// then do its access brackets hold publication and its readers' reads
    /// (DDS v1.4 Sec.2.2.2.5.2.8: for any other scope begin_access/end_access
    /// "has no effect").
    group_scope: AtomicBool,
    /// Held while released sets are delivered into the readers' rings
    /// (`publish`): one publisher at a time, and an access bracket opening
    /// waits for a delivery in progress to end.
    publishing: Mutex<()>,
    local_order: std::sync::OnceLock<super::local_order::LocalReadOrder>,
    wire_order: super::wire_order::WireOrder,
    #[cfg(test)]
    reservation_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// The Subscriber's publishing thread, spawned on the first change
    /// (`changed`): it delivers what is released while no access bracket is
    /// open.
    worker: Mutex<Option<Arc<WorkerSignal>>>,
    /// This barrier, for its publishing thread (`new_shared`); unset, as in a
    /// barrier built by `new` for a test, nothing publishes on its own.
    this: std::sync::OnceLock<std::sync::Weak<Self>>,
    /// The readers attached to this Subscriber, so that closing a bracket
    /// asks the writers' coordinators to deliver the local coherent sets
    /// that waited for it (`Retry`). Weak: a torn-down reader is dropped
    /// from its writers' mergers, which is where the wake goes.
    local_retries: Mutex<Vec<std::sync::Weak<super::runtime::ReaderBindings>>>,
}

/// Wakes the publishing thread (`CoherentPresentationBarrier::changed`), or
/// tells it its barrier is gone (`closed`).
struct WorkerSignal {
    state: Mutex<WorkerState>,
    wake: std::sync::Condvar,
}

#[derive(Default)]
struct WorkerState {
    pending: bool,
    closed: bool,
}

/// The publishing thread's name: fifteen bytes at most, the length Linux
/// keeps.
const PUBLISHING_THREAD: &str = "hdds-present";

/// Locked state: the member table and publisher generation queues.
struct BarrierState {
    members: Vec<Member>,
    /// Each remote writer's Publisher key, one for every member: resolved
    /// through discovery once (`key_of`); `true` while it is only its
    /// participant's, discovery not knowing its Publisher (yet).
    writer_keys: HashMap<[u8; 16], (PublisherKey, bool)>,
}

impl Default for CoherentPresentationBarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl CoherentPresentationBarrier {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(BarrierState {
                members: Vec::new(),
                writer_keys: HashMap::new(),
            }),
            depth: AtomicU32::new(0),
            group_scope: AtomicBool::new(true),
            publishing: Mutex::new(()),
            local_order: std::sync::OnceLock::new(),
            wire_order: super::wire_order::WireOrder::default(),
            #[cfg(test)]
            reservation_hook: Mutex::new(None),
            worker: Mutex::new(None),
            this: std::sync::OnceLock::new(),
            local_retries: Mutex::new(Vec::new()),
        }
    }

    /// A barrier that publishes on its own (`changed`): a Subscriber's.
    pub fn new_shared() -> Arc<Self> {
        let barrier = Arc::new(Self::new());
        let _ = barrier.this.set(Arc::downgrade(&barrier));
        barrier
    }

    /// How many access brackets are open.
    pub fn access_depth(&self) -> u32 {
        self.depth.load(Ordering::SeqCst)
    }

    /// The Subscriber's access scope (`group_scope`), set at its creation
    /// and with its QoS.
    pub fn set_group_scope(&self, group: bool) {
        self.group_scope.store(group, Ordering::SeqCst);
        if !group {
            self.changed();
        }
    }

    /// Whether the Subscriber's access scope is GROUP.
    pub fn group_scope(&self) -> bool {
        self.group_scope.load(Ordering::SeqCst)
    }

    /// Whether an access bracket holds publication: one is open on a
    /// Subscriber of GROUP access scope.
    fn held(&self) -> bool {
        self.group_scope() && self.depth.load(Ordering::SeqCst) > 0
    }

    /// Something changed that may complete a generation (a set deposited, a
    /// writer matched or gone, a member resolved or forgotten): its
    /// publishing thread delivers what is complete, unless an access bracket
    /// is open (then the bracket's end does). Never delivers on the calling
    /// thread, which may hold a reader's locks.
    fn changed(&self) {
        if self.held() && !self.wire_order.has_members() {
            return;
        }
        let Some(this) = self.this.get() else {
            return;
        };
        let signal = {
            let mut worker = self.worker.lock().unwrap_or_else(|e| e.into_inner());
            if worker.is_none() {
                let signal = Arc::new(WorkerSignal {
                    state: Mutex::new(WorkerState::default()),
                    wake: std::sync::Condvar::new(),
                });
                let thread_signal = Arc::clone(&signal);
                let weak = this.clone();
                let spawned = std::thread::Builder::new()
                    .name(PUBLISHING_THREAD.to_string())
                    .spawn(move || publishing_loop(&weak, &thread_signal));
                if spawned.is_err() {
                    log::error!("[COHERENT-BARRIER] the publishing thread could not be spawned");
                    return;
                }
                *worker = Some(Arc::clone(&signal));
            }
            worker.clone()
        };
        if let Some(signal) = signal {
            signal
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pending = true;
            signal.wake.notify_one();
        }
    }

    /// Deliver every set released so far into its reader's ring, with no
    /// barrier state lock held; then, `publishing` released, tell the
    /// readers' listeners and wake the readers (`notices`): once every part
    /// of every generation published is in its reader's ring. A listener
    /// told of its part found the other readers' parts missing, and a
    /// bracket it opened (DDS v1.4 Sec.2.2.2.5, pattern 1) read them torn.
    /// `in_bracket`: the outermost `begin_access` publishes; the publishing
    /// thread does not while a bracket is open.
    ///
    /// A local coherent set that waited for a bracket is retried by that
    /// bracket's `end_access`, on the thread that closes it, never here: the
    /// set is then in before the next bracket's first read.
    fn publish(&self, in_bracket: bool) {
        // Dropped last: the listeners are told after `publishing` is.
        let _delivering = super::notices::Delivering::enter();
        {
            let _publishing = self.publishing.lock().unwrap_or_else(|e| e.into_inner());
            if self.wire_order.has_members() {
                for (deliver, writer, payload) in self.wire_order.expire_lifespans() {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        deliver(writer, payload)
                    }))
                    .is_err()
                    {
                        log::error!("[PRESENTATION] expired wire delivery panicked");
                    }
                }
            }
            if !in_bracket && self.held() {
                return;
            }
            let deliveries = release_ready(&mut self.lock());
            // Released, the sets are out of the barrier: one delivery that
            // panics does not drop the others of the publication (nor leave
            // the readers it delivered unwoken: they wake as they are pushed).
            for (deliver, set) in deliveries {
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| deliver(set))).is_err()
                {
                    log::error!(
                        "[COHERENT-BARRIER] the delivery of a released set panicked; the \
                         publication goes on with the others"
                    );
                }
            }
            for (deliver, writer, payload) in self.wire_order.release() {
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    deliver(writer, payload)
                }))
                .is_err()
                {
                    log::error!("[PRESENTATION] ordered wire delivery panicked");
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn forget_wire_order_for_test(&self, member: MemberId) {
        self.wire_order.forget(member);
    }

    #[cfg(test)]
    pub(super) fn attach_wire_order(
        &self,
        id: MemberId,
        deliver: super::wire_order::Deliver,
        roster: super::wire_order::Roster,
        reliable: bool,
        durable: bool,
        bindings: std::sync::Weak<super::runtime::ReaderBindings>,
    ) {
        self.wire_order
            .attach_reader(id, deliver, roster, reliable, durable, bindings);
        self.changed();
    }

    pub(super) fn attach_wire_order_pending(
        &self,
        id: MemberId,
        deliver: super::wire_order::Deliver,
        roster: super::wire_order::Roster,
        reliable: bool,
        durable: bool,
        bindings: std::sync::Weak<super::runtime::ReaderBindings>,
    ) {
        self.wire_order
            .attach_pending_reader(id, deliver, roster, reliable, durable, bindings);
        self.changed();
    }

    #[cfg(test)]
    pub(super) fn set_wire_reservation_hook_for_test(&self, hook: Box<dyn FnOnce() + Send>) {
        *self
            .reservation_hook
            .lock()
            .expect("reservation test hook mutex") = Some(hook);
    }

    #[cfg(test)]
    pub(super) fn run_wire_reservation_hook_for_test(&self) {
        let hook = self
            .reservation_hook
            .lock()
            .expect("reservation test hook mutex")
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    #[cfg(test)]
    pub(super) fn wire_loss_marker_counts_for_test(
        &self,
        member: MemberId,
        key: PublisherKey,
    ) -> (usize, usize) {
        let state = self.lock();
        let Some(member) = state.members.get(member) else {
            return (0, 0);
        };
        let markers: Vec<_> = member
            .ready
            .get(&key)
            .into_iter()
            .flatten()
            .filter(|set| set.lost)
            .collect();
        let charged = markers
            .iter()
            .filter(|set| {
                set.writers
                    .iter()
                    .flat_map(|(_, payloads)| payloads)
                    .any(|payload| payload.staged.is_some())
            })
            .count();
        (markers.len(), charged)
    }

    #[cfg(test)]
    pub(super) fn diagnostic_alignment_for_test(&self, key: PublisherKey) -> String {
        let state = self.lock();
        format!(
            "{:?}",
            state
                .members
                .iter()
                .enumerate()
                .map(|(id, member)| (
                    id,
                    member.active,
                    member.resolved,
                    member.key_counts.get(&key),
                    member.ready.get(&key).map(|sets| sets
                        .iter()
                        .map(|set| (set.gsn, set.lost, set.len()))
                        .collect::<Vec<_>>()),
                    member.released.len(),
                ))
                .collect::<Vec<_>>()
        )
    }

    #[cfg(test)]
    pub(super) fn diagnostic_wire_for_test(&self, key: PublisherKey) -> String {
        self.wire_order.diagnostic(key)
    }

    #[cfg(test)]
    pub(super) fn set_wire_clock_for_test(
        &self,
        clock: Arc<dyn crate::dds::liveliness::LivelinessClock>,
    ) {
        self.wire_order.set_clock(clock);
    }

    #[cfg(test)]
    pub(super) fn pump_wire_history_for_test(&self) {
        self.publish(false);
    }

    /// An identified expired owner makes its entire coherent generation
    /// unavailable. Every captured part is retired whole, outside the lock.
    pub(super) fn retire_wire_owner(&self, member: MemberId, owner_token: u64) -> bool {
        let target = {
            let state = self.lock();
            state.members.get(member).and_then(|member| {
                member.ready.iter().find_map(|(key, sets)| {
                    sets.iter()
                        .find(|set| {
                            set.writers
                                .iter()
                                .flat_map(|(_, payloads)| payloads)
                                .any(|payload| {
                                    payload
                                        .order_token
                                        .as_ref()
                                        .is_some_and(|token| token.owner_id() == owner_token)
                                })
                        })
                        .and_then(|set| set.gsn.map(|gsn| (*key, gsn)))
                })
            })
        };
        if let Some((key, generation)) = target {
            self.retire_wire_generation(key, generation);
            true
        } else {
            false
        }
    }

    pub(super) fn wire_unit_lost(&self, key: PublisherKey, first: u64) -> bool {
        let state = self.lock();
        state
            .members
            .iter()
            .filter(|member| member.active)
            .any(|member| {
                member
                    .ready
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .any(|set| set.gsn == Some(first) && set.lost)
            })
    }

    pub(super) fn wire_proofs_changed(&self) {
        self.changed();
    }

    pub(super) fn wire_discarded_copy(
        &self,
        member: MemberId,
        change: crate::engine::router::OrderedGroupChange,
    ) {
        self.wire_order.discarded_copy(member, change);
        self.changed();
    }

    pub(super) fn pin_wire_loss_marker(
        &self,
        member: MemberId,
        key: PublisherKey,
        generation: u64,
        charge: super::staging_budget::StagedCharge,
    ) {
        let mut charge = Some(charge);
        {
            let mut state = self.lock();
            if let Some(member) = state.members.get_mut(member).filter(|member| member.active) {
                let queue = member.ready.entry(key).or_default();
                let marker = queue
                    .iter_mut()
                    .find(|set| set.gsn == Some(generation) && set.lost);
                if let Some(marker) = marker {
                    if !marker
                        .writers
                        .iter()
                        .flat_map(|(_, payloads)| payloads)
                        .any(|payload| payload.staged.is_some())
                    {
                        let mut placeholder = PendingPayload::nothing(0);
                        placeholder.staged = charge.take();
                        marker.writers.push(([0; 16], vec![placeholder]));
                    }
                } else {
                    let mut placeholder = PendingPayload::nothing(0);
                    placeholder.staged = charge.take();
                    let at = queue
                        .iter()
                        .position(|set| set.gsn.is_some_and(|gsn| gsn > generation))
                        .unwrap_or(queue.len());
                    queue.insert(
                        at,
                        CoherentSet::spec_part(
                            vec![([0; 16], vec![placeholder])],
                            generation,
                            true,
                        ),
                    );
                    member.resolved = true;
                }
            }
        }
        // A redundant pin or a departed reader returns the charge outside
        // the alignment lock. The placeholder has no value, token or receipt.
        drop(charge);
    }

    pub(super) fn retire_wire_generation(&self, key: PublisherKey, generation: u64) {
        let _delivering = super::notices::Delivering::enter();
        let mut retired = Vec::new();
        let mut discarded = Vec::new();
        {
            let mut state = self.lock();
            for member in state.members.iter_mut().filter(|member| member.active) {
                let Some(queue) = member.ready.get_mut(&key) else {
                    continue;
                };
                let mut keep = VecDeque::new();
                for mut set in std::mem::take(queue) {
                    let marker_only =
                        set.lost
                            && set.writers.iter().flat_map(|(_, payloads)| payloads).all(
                                |payload| {
                                    payload.order_token.is_none()
                                        && payload.slot.is_none()
                                        && matches!(
                                            payload.prepared,
                                            super::admission::Prepared::Discard
                                        )
                                },
                            );
                    if set.gsn != Some(generation) || set.is_empty() || marker_only {
                        keep.push_back(set);
                        continue;
                    }
                    let charge = set
                        .writers
                        .iter_mut()
                        .flat_map(|(_, payloads)| payloads)
                        .find_map(|payload| payload.staged.take())
                        .map(super::staging_budget::StagedCharge::pin_loss_marker);
                    let mut marker = CoherentSet::spec_part(Vec::new(), generation, true);
                    if let Some(charge) = charge {
                        let mut placeholder = PendingPayload::nothing(0);
                        placeholder.staged = Some(charge);
                        marker.writers.push(([0; 16], vec![placeholder]));
                    }
                    keep.push_back(marker);
                    set.lost = true;
                    if let Some(deliver) = member.deliver.clone() {
                        retired.push((deliver, set));
                    } else {
                        discarded.push(set);
                    }
                }
                *queue = keep;
                if queue.is_empty() {
                    member.ready.remove(&key);
                }
            }
        }
        drop(discarded);
        for (deliver, set) in retired {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| deliver(set))).is_err() {
                log::error!("[PRESENTATION] a lost coherent generation callback panicked");
            }
        }
    }

    pub(super) fn attach_wire_history(
        &self,
        id: MemberId,
        maintenance: Arc<dyn Fn(super::wire_order::HistoryProof) -> bool + Send + Sync>,
    ) {
        self.wire_order.attach_history(id, maintenance);
    }

    pub(super) fn attach_wire_snapshot(
        &self,
        id: MemberId,
        snapshot: super::wire_order::DepartureSnapshot,
    ) {
        self.wire_order.attach_snapshot(id, snapshot);
    }

    pub(super) fn wire_departure(&self, publisher: PublisherKey, writer: [u8; 16]) {
        self.wire_order.departure(publisher, writer);
        self.changed();
    }

    pub(super) fn wire_may_stage_unit(
        &self,
        writer: [u8; 16],
        change: crate::engine::router::OrderedGroupChange,
        member: MemberId,
        first: u64,
    ) -> bool {
        self.wire_order
            .may_stage_unit(writer, change, member, first)
    }

    pub(super) fn attach_wire_terminal(
        &self,
        id: MemberId,
        watch: super::wire_order::TerminalWatch,
    ) {
        self.wire_order.attach_terminal(id, watch);
    }

    pub(super) fn deposit_wire_order(
        &self,
        id: MemberId,
        writer: [u8; 16],
        change: crate::engine::router::OrderedGroupChange,
        payload: super::wire_order::OrderedPayload,
    ) {
        self.wire_order.deposit(id, writer, change, payload);
        self.changed();
    }

    pub(super) fn wire_lifespan_deadline(&self, remaining: std::time::Duration) -> u64 {
        self.wire_order.lifespan_deadline(remaining)
    }

    pub(super) fn reserve_wire_lifespan(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        token: u64,
        member: MemberId,
        at: u64,
    ) {
        self.wire_order.reserve_lifespan(change, token, member, at);
    }

    pub(super) fn activate_wire_lifespan(&self, owner_token: u64) {
        self.wire_order.activate_lifespan(owner_token);
        self.changed();
    }

    pub(super) fn wire_owner_lost(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        owner_token: u64,
    ) {
        self.wire_order.owner_lost(change, owner_token);
        self.changed();
    }

    pub(super) fn reserve_wire_sample(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        token: u64,
        member: MemberId,
        first: Option<u64>,
        repair: Option<super::wire_order::CoherentRepair>,
        loss: &super::wire_order::LossContext,
    ) -> bool {
        self.wire_order
            .reserve_sample(change, token, member, first, repair, loss)
    }

    pub(super) fn attach_wire_loss_watch(
        &self,
        id: MemberId,
        watch: super::wire_order::LossWatch,
    ) -> bool {
        let ready = self.wire_order.attach_loss_watch(id, watch);
        if ready {
            self.changed();
        }
        ready
    }

    pub(super) fn reserve_wire_order(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        token: u64,
        member: MemberId,
    ) -> bool {
        self.wire_order.reserve(change, token, member)
    }

    pub(super) fn reserve_wire_coherent(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        token: u64,
        member: MemberId,
        first: u64,
        repair: Option<super::wire_order::CoherentRepair>,
    ) -> bool {
        self.wire_order
            .reserve_coherent(change, token, member, first, repair)
    }

    pub(super) fn wire_history_repair(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        member: MemberId,
        first: u64,
    ) -> Option<super::wire_order::CoherentRepair> {
        self.wire_order.repair_context(change, member, first)
    }

    pub(super) fn wire_is_stale(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        member: MemberId,
    ) -> bool {
        self.wire_order.stale(change, member)
    }

    pub(super) fn release_wire_order(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        token: u64,
    ) {
        self.wire_order.release_reservation(change, token);
        self.changed();
    }

    pub(super) fn wire_needs_predecessor_room(
        &self,
        writer: [u8; 16],
        change: crate::engine::router::OrderedGroupChange,
        member: MemberId,
    ) -> usize {
        self.wire_order
            .needs_predecessor_room(writer, change, member)
    }

    pub(super) fn wire_heartbeat(
        &self,
        publisher: PublisherKey,
        writer: [u8; 16],
        info: [u64; 3],
        digest: Option<[u8; 4]>,
    ) {
        self.wire_order.heartbeat(publisher, writer, info, digest);
        self.changed();
    }

    pub(super) fn wire_gap(
        &self,
        publisher: PublisherKey,
        writer: [u8; 16],
        start: u64,
        end: u64,
        member: MemberId,
    ) {
        self.wire_order.gap(publisher, writer, start, end, member);
        self.changed();
    }

    pub(super) fn wire_gap_consumed(
        &self,
        publisher: PublisherKey,
        member: MemberId,
        end: u64,
    ) -> bool {
        self.wire_order.gap_consumed(publisher, member, end)
    }

    pub(super) fn wire_control_prefix(
        &self,
        member: MemberId,
        writer: [u8; 16],
        change: crate::engine::router::OrderedGroupChange,
    ) {
        self.wire_order.control_prefix(member, writer, change);
        self.changed();
    }

    pub(super) fn wire_settled(
        &self,
        member: MemberId,
        writer: [u8; 16],
        change: crate::engine::router::OrderedGroupChange,
    ) {
        self.wire_order.settled(member, writer, change);
        self.changed();
    }

    pub(super) fn wire_accounted(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        member: MemberId,
    ) -> bool {
        let admitted = self.wire_order.accounted(member, change);
        if admitted {
            self.changed();
        }
        admitted
    }

    pub(crate) fn set_local_order(&self, ordered: bool) {
        if ordered {
            let _ = self
                .local_order
                .set(super::local_order::LocalReadOrder::default());
        }
    }

    pub(super) fn local_order(&self) -> Option<&super::local_order::LocalReadOrder> {
        self.local_order.get()
    }

    /// The readers of this Subscriber follow this barrier's brackets: their
    /// writers' coordinators hold a local coherent set while one is open.
    pub(super) fn attach_local_retry(
        &self,
        bindings: std::sync::Weak<super::runtime::ReaderBindings>,
    ) {
        self.local_retries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(bindings);
    }

    /// Ask every coordinator feeding this Subscriber to deliver what its
    /// local coherent sets are waiting for, and forget the readers that are
    /// gone.
    fn retry_local_groups(&self) {
        let bindings: Vec<_> = {
            let mut retries = self.local_retries.lock().unwrap_or_else(|e| e.into_inner());
            retries.retain(|binding| binding.strong_count() > 0);
            retries
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .collect()
        };
        for bindings in bindings {
            bindings.retry_local_groups();
        }
    }

    /// Open a coherent-access bracket (DDS v1.4 sec 2.2.2.2.1
    /// `begin_access`, GROUP presentation): run one release round per
    /// known publisher so the whole cross-reader generation becomes
    /// drainable atomically, then suppress further release rounds until
    /// [`end_access`](Self::end_access). Without this bracketing a round
    /// can fire mid read-cycle (triggered by whichever reader's take
    /// aligns last) and the readers polled earlier in the cycle only see
    /// their part of the generation on the NEXT cycle -- a torn GROUP
    /// presentation.
    ///
    /// The outermost bracket publishes, on the calling thread, every
    /// generation complete so far, all of them, into the readers' rings;
    /// nothing new reaches them until the outermost `end_access`. Its
    /// listeners are told once every part is in (`publish`).
    pub fn begin_access(&self) {
        if !self.held() {
            self.retry_local_groups();
        }
        // The increment against a local coherent set's own decision
        // (`coherent_publication`): a set already being pushed into the
        // rings finishes before this bracket's first read.
        let first = {
            let _publication = crate::dds::coherent_publication::lock();
            self.depth.fetch_add(1, Ordering::SeqCst) == 0
        };
        if first {
            self.publish(true);
        }
    }

    /// Close the coherent-access bracket opened by
    /// [`begin_access`](Self::begin_access); the outermost one lets what
    /// completed meanwhile be published.
    pub fn end_access(&self) {
        let last = {
            let _publication = crate::dds::coherent_publication::lock();
            self.depth
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |d| d.checked_sub(1))
                == Ok(1)
        };
        if last {
            // Locally, on this thread, before the next bracket's first
            // read: a coherent set of a co-located Publisher waited for
            // this bracket, and the application may open the next one (and
            // read) before any other thread runs.
            self.retry_local_groups();
            self.changed();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BarrierState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserve a member slot for a coherent reader on `topic`. `volatile`
    /// is the reader's Durability kind (VOLATILE vs replaying), consulted
    /// by the alignment rule (see the module docs). The delivery closure is
    /// attached later via [`attach_deliver`](Self::attach_deliver) once the
    /// reader's `Arc` exists.
    pub fn reserve(&self, topic: String, volatile: bool) -> MemberId {
        let mut state = self.lock();
        state.members.push(Member::new(topic, volatile));
        state.members.len() - 1
    }

    /// Attach the ring-delivery closure for a previously reserved member.
    pub fn attach_deliver(&self, id: MemberId, deliver: DeliverFn) {
        let mut state = self.lock();
        if let Some(m) = state.members.get_mut(id) {
            m.deliver = Some(deliver);
        }
    }

    /// Record a matched remote writer for `id` (discovery cold path, fired
    /// from the SEDP match notification). Makes the member required for the
    /// writer's publisher key and marks it resolved. Idempotent per GUID,
    /// so the deposit-side registration (see [`deposit`](Self::deposit))
    /// and this notification can arrive in either order.
    pub fn register_matched_writer(&self, id: MemberId, writer_guid: [u8; 16]) {
        let key = self.key_of(id, &writer_guid);
        let mut state = self.lock();
        if let Some(m) = state.members.get_mut(id) {
            if !m.active {
                // A torn-down reader must never become required again.
                return;
            }
            if let std::collections::hash_map::Entry::Vacant(slot) = m.writers.entry(writer_guid) {
                slot.insert(key);
                *m.key_counts.entry(key).or_insert(0) += 1;
            }
            m.resolved = true;
        }
        drop(state);
        self.changed();
    }

    /// Tests only: the key member `id` registered `writer_guid` under.
    #[cfg(test)]
    pub(crate) fn registered_key(
        &self,
        id: MemberId,
        writer_guid: &[u8; 16],
    ) -> Option<PublisherKey> {
        self.lock()
            .members
            .get(id)
            .and_then(|m| m.writers.get(writer_guid).copied())
    }

    /// Attach member `id`'s view of discovery: a remote writer's Publisher
    /// (cold path, at reader build).
    pub fn attach_resolver(&self, id: MemberId, resolver: PublisherResolver) {
        if let Some(m) = self.lock().members.get_mut(id) {
            m.resolver = Some(resolver);
        }
    }

    /// The key of `writer_guid`'s Publisher for member `id`: the one it was
    /// registered under, else discovery's answer, else its participant's.
    /// Discovery is asked with no barrier lock held.
    fn key_of(&self, id: MemberId, writer_guid: &[u8; 16]) -> PublisherKey {
        let resolver = {
            let state = self.lock();
            if let Some(&(key, false)) = state.writer_keys.get(writer_guid) {
                return key;
            }
            // Any member's view of discovery answers for the writer.
            state
                .members
                .get(id)
                .and_then(|m| m.resolver.clone())
                .or_else(|| {
                    state
                        .members
                        .iter()
                        .filter(|m| m.writers.contains_key(writer_guid))
                        .find_map(|m| m.resolver.clone())
                })
        };
        let resolved = resolver.and_then(|r| r(writer_guid));
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&writer_guid[..12]);
        let key = publisher_key(prefix, resolved.unwrap_or([0; 4]));
        let mut state = self.lock();
        match resolved {
            Some(_) => {
                let before = state.writer_keys.insert(*writer_guid, (key, false));
                if let Some((was, true)) = before {
                    if was != key {
                        migrate_writer(&mut state, writer_guid, was, key);
                    }
                }
                key
            }
            // Not known (yet): the participant's key, asked again next time.
            None => {
                state
                    .writer_keys
                    .entry(*writer_guid)
                    .or_insert((key, true))
                    .0
            }
        }
    }

    /// Remove a matched remote writer for `id` (discovery cold path, fired
    /// from the writer-dispose notification). When the last writer of a
    /// publisher unmatches, the member stops being required for that key so
    /// the remaining members can drain the publisher's residual
    /// generations. No-op for a GUID that was never registered.
    pub fn unregister_matched_writer(&self, id: MemberId, writer_guid: [u8; 16]) {
        let mut state = self.lock();
        if let Some(m) = state.members.get_mut(id) {
            if let Some(key) = m.writers.remove(&writer_guid) {
                if let Some(count) = m.key_counts.get_mut(&key) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        m.key_counts.remove(&key);
                    }
                }
            }
        }
        drop(state);
        self.changed();
    }

    /// Deposit a completed per-topic coherent set for remote publisher
    /// `key` (RX/router thread). The set is queued whole; alignment,
    /// release and publication happen on the publishing thread
    /// (`changed`), so a deposit never blocks on ring delivery.
    ///
    /// Data implies membership: receiving a committed coherent set from
    /// publisher `key` is ground-truth evidence of a matched writer, so
    /// the set's writers are registered exactly as the SEDP notification
    /// would register them. The notification path can lag the data path
    /// by whole read cycles (it is a separate bookkeeping channel); a
    /// release round must never treat a deposited-but-not-yet-notified
    /// member as optional, or it would release its peers and leave this
    /// member's ring empty in the same read cycle (a torn cross-topic
    /// group). Registration here is idempotent per GUID, and the
    /// writer-dispose path unregisters the same GUIDs, so departure
    /// bookkeeping is unaffected by which side registered first.
    ///
    /// The set is queued under its writers' Publisher (all of one, a set
    /// spanning one Publisher's writers): `key` names it only for a set with
    /// no writer (an empty or lost spec part).
    pub fn deposit(&self, id: MemberId, key: PublisherKey, mut set: CoherentSet) {
        // An empty set is no generation, but for a spec part (`spec_part`),
        // tagged: its member holds the generation, empty or lost.
        if set.is_empty() && set.gsn.is_none() {
            return;
        }
        let owners: Vec<_> = if self.wire_order.has_members() {
            set.writers
                .iter()
                .flat_map(|(_, payloads)| payloads)
                .filter_map(|payload| payload.order_token.as_ref().map(|token| token.owner_id()))
                .collect()
        } else {
            Vec::new()
        };
        let keyed: Vec<([u8; 16], PublisherKey)> = set
            .writers
            .iter()
            .filter(|(_, payloads)| !payloads.is_empty())
            .map(|(writer, _)| (*writer, self.key_of(id, writer)))
            .collect();
        let mut state = self.lock();
        // Keyed outside the lock (the resolver asks discovery): discovery
        // may have learnt a writer's Publisher meanwhile, and moved it
        // (`migrate_writer`). Its key is the one it has now, under the
        // lock: queued under the key it had, the set sat under a key no
        // member was required for any more, and was released alone.
        let keyed: Vec<([u8; 16], PublisherKey)> = keyed
            .into_iter()
            .map(|(writer, key)| {
                (
                    writer,
                    state.writer_keys.get(&writer).map_or(key, |&(now, _)| now),
                )
            })
            .collect();
        // A set with no sample (an empty or lost spec part) names its
        // Publisher from the wire: the key its writers are known by, the
        // participant's when discovery does not know the Publisher.
        let key = keyed.first().map_or_else(
            || {
                state.members.get(id).map_or(key, |m| {
                    let known = |k: &PublisherKey| m.writers.values().any(|w| w == k);
                    let participant =
                        publisher_key(key[..12].try_into().unwrap_or([0; 12]), [0; 4]);
                    if known(&key) || !known(&participant) {
                        key
                    } else {
                        participant
                    }
                })
            },
            |(_, key)| *key,
        );
        if let Some(generation) = set.gsn {
            // A member racing a whole-unit loss cannot restore a partial unit.
            set.lost |= state.members.iter().any(|member| {
                member
                    .ready
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .any(|queued| queued.gsn == Some(generation) && queued.lost)
            });
        }
        if let Some(m) = state.members.get_mut(id) {
            if !m.active {
                // Reader torn down: the set is undeliverable. Dropping it
                // here keeps a dead slot from pinning memory or becoming
                // required for a key again.
                return;
            }
            if set.lost && set.gsn.is_some() {
                for payload in set.writers.iter_mut().flat_map(|(_, payloads)| payloads) {
                    if let Some(charge) = payload.staged.take() {
                        payload.staged = Some(charge.pin_loss_marker());
                        break;
                    }
                }
            }
            for (writer_guid, writer_key) in keyed {
                if let std::collections::hash_map::Entry::Vacant(slot) =
                    m.writers.entry(writer_guid)
                {
                    slot.insert(writer_key);
                    *m.key_counts.entry(writer_key).or_insert(0) += 1;
                }
            }
            if set.lost && set.is_empty() {
                if let Some(existing) = m
                    .ready
                    .get_mut(&key)
                    .and_then(|queue| queue.iter_mut().find(|queued| queued.gsn == set.gsn))
                {
                    // Terminal copies carry no new payload or charge. One
                    // marker per member/unit survives arbitrary retransmits.
                    existing.lost = true;
                    for payload in existing
                        .writers
                        .iter_mut()
                        .flat_map(|(_, payloads)| payloads)
                    {
                        if let Some(charge) = payload.staged.take() {
                            payload.staged = Some(charge.pin_loss_marker());
                            break;
                        }
                    }
                    drop(state);
                    self.changed();
                    return;
                }
            }
            log::debug!(
                "[COHERENT-BARRIER] deposit topic='{}' gsn={:?} key={:02x?} depth={}",
                m.topic,
                set.gsn,
                &key[..4],
                m.ready.get(&key).map_or(0, |q| q.len()) + 1,
            );
            m.ready.entry(key).or_default().push_back(set);
            m.resolved = true;
        }
        drop(state);
        for owner in owners {
            self.wire_order.activate_lifespan(owner);
        }
        self.changed();
    }

    /// Tests only: deliver this member's next aligned set to its ring, if
    /// a full generation is available for one of its publishers, as one
    /// read cycle of the model the barrier's unit tests drive. Returns
    /// `true` when a set was delivered.
    ///
    /// The release round + queue
    /// bookkeeping happen under the lock; the actual ring delivery (the
    /// `deliver` closure -> decode/re-encode/push) runs AFTER the lock is
    /// dropped so a user listener callback can never be invoked while the
    /// barrier is held.
    #[cfg(test)]
    pub fn take_one_aligned(&self, id: MemberId) -> bool {
        let taken = {
            let mut state = self.lock();
            // Only advance a generation when this member has nothing
            // already aligned: keeps the `released` queues equal length
            // across members when each is drained once per read cycle.
            // Inside a begin/end_access bracket the round already ran at
            // begin_access; takes only drain (see `begin_access`).
            let need_release = self.depth.load(Ordering::SeqCst) == 0
                && state.members.get(id).is_none_or(|m| m.released.is_empty());
            if need_release {
                // Candidate keys for this member, in deterministic (sorted)
                // order: publishers it is required for, plus publishers it
                // holds residual sets from (departure drain).
                let mut keys: Vec<PublisherKey> = match state.members.get(id) {
                    Some(m) => m.key_counts.keys().chain(m.ready.keys()).copied().collect(),
                    None => Vec::new(),
                };
                keys.sort_unstable();
                keys.dedup();
                for key in keys {
                    try_release_one_generation(&mut state, &key);
                    if state
                        .members
                        .get(id)
                        .is_some_and(|m| !m.released.is_empty())
                    {
                        break;
                    }
                }
            }
            match state.members.get_mut(id) {
                // Leave sets queued if the delivery closure is not attached
                // yet (cannot happen once wired; defensive so nothing is
                // dropped).
                Some(m) if m.deliver.is_some() => {
                    m.released.pop_front().map(|set| (m.deliver.clone(), set))
                }
                _ => None,
            }
        };
        match taken {
            Some((Some(deliver), set)) => {
                deliver(set);
                true
            }
            _ => false,
        }
    }

    /// Number of reserved member slots (test introspection for the
    /// Subscriber attach path).
    #[cfg(test)]
    pub fn member_count(&self) -> usize {
        self.lock().members.len()
    }

    /// Deactivate a member whose reader is going away (the safety valve):
    /// its queues are cleared and it is removed from every alignment
    /// requirement so a torn-down coherent reader cannot pin the barrier
    /// and stall its peers forever. The slot is retained (member ids stay
    /// stable).
    pub fn forget_member(&self, id: MemberId) {
        self.wire_order.forget(id);
        let mut state = self.lock();
        if let Some(m) = state.members.get_mut(id) {
            m.ready.clear();
            m.released.clear();
            m.writers.clear();
            m.key_counts.clear();
            m.presented.clear();
            m.deliver = None;
            m.active = false;
        }
        drop(state);
        self.changed();
    }
}

/// The publishing thread of a Subscriber's barrier: delivers what is
/// released whenever told (`changed`), and leaves when its barrier is
/// dropped (`closed`). Nothing that panics in a publication stops it: the
/// listeners' panics are caught where they are called (`notices`), a
/// delivery that panics where it is called (`publish`), and anything else
/// here.
fn publishing_loop(barrier: &std::sync::Weak<CoherentPresentationBarrier>, signal: &WorkerSignal) {
    let mut deadline: Option<super::wire_order::LifespanWake> = None;
    loop {
        {
            let mut state = signal.state.lock().unwrap_or_else(|e| e.into_inner());
            while !state.pending && !state.closed {
                if let Some(wait) = deadline.as_ref().and_then(|wake| wake.sleep_for()) {
                    if wait.is_zero() {
                        break;
                    }
                    let (next, result) = signal
                        .wake
                        .wait_timeout(state, wait)
                        .unwrap_or_else(|e| e.into_inner());
                    state = next;
                    if result.timed_out() {
                        break;
                    }
                } else {
                    state = signal.wake.wait(state).unwrap_or_else(|e| e.into_inner());
                }
            }
            if state.closed {
                return;
            }
            state.pending = false;
        }
        let Some(barrier) = barrier.upgrade() else {
            return;
        };
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| barrier.publish(false)))
            .is_err()
        {
            log::error!("[COHERENT-BARRIER] a publication panicked; the publishing thread goes on");
        }
        deadline = barrier.wire_order.next_lifespan_wake();
        // No strong barrier reference crosses the worker's sleep.
    }
}

impl Drop for CoherentPresentationBarrier {
    fn drop(&mut self) {
        // Its publishing thread leaves.
        let worker = self
            .worker
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(signal) = worker {
            signal
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .closed = true;
            signal.wake.notify_one();
        }
    }
}

/// Run the release rounds of every publisher until none releases more, then
/// take every member's released sets with its delivery closure, in order.
fn release_ready(state: &mut BarrierState) -> Vec<(DeliverFn, CoherentSet)> {
    let mut keys: Vec<PublisherKey> = state
        .members
        .iter()
        .filter(|m| m.active)
        .flat_map(|m| m.key_counts.keys().chain(m.ready.keys()).copied())
        .collect();
    keys.sort_unstable();
    keys.dedup();
    for key in keys {
        // Each round that releases takes a set from every member holding
        // one: bounded by what is queued.
        loop {
            let queued = |state: &BarrierState| -> usize {
                state
                    .members
                    .iter()
                    .map(|m| m.ready.get(&key).map_or(0, VecDeque::len))
                    .sum()
            };
            let before = queued(state);
            try_release_one_generation(state, &key);
            if queued(state) >= before {
                break;
            }
        }
    }
    let mut deliveries = Vec::new();
    for m in state.members.iter_mut().filter(|m| m.active) {
        if let Some(deliver) = m.deliver.clone() {
            deliveries.extend(m.released.drain(..).map(|set| (Arc::clone(&deliver), set)));
        }
    }
    deliveries
}

/// `writer_guid`, registered under its participant's key `from` while
/// discovery did not know its Publisher, is of Publisher `to`: every member
/// moves it there, with its count and its queued sets.
fn migrate_writer(
    state: &mut BarrierState,
    writer_guid: &[u8; 16],
    from: PublisherKey,
    to: PublisherKey,
) {
    for m in state.members.iter_mut() {
        if m.writers.get(writer_guid) != Some(&from) {
            continue;
        }
        m.writers.insert(*writer_guid, to);
        if let Some(count) = m.key_counts.get_mut(&from) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                m.key_counts.remove(&from);
            }
        }
        *m.key_counts.entry(to).or_insert(0) += 1;
        if let Some(&presented) = m.presented.get(&from) {
            let moved = m.presented.entry(to).or_insert(presented);
            *moved = (*moved).max(presented);
        }
        if let Some(queue) = m.ready.get_mut(&from) {
            let (moved, kept): (VecDeque<CoherentSet>, VecDeque<CoherentSet>) =
                std::mem::take(queue)
                    .into_iter()
                    .partition(|set| set.writers.iter().any(|(w, _)| w == writer_guid));
            *queue = kept;
            if queue.is_empty() {
                m.ready.remove(&from);
            }
            if !moved.is_empty() {
                m.ready.entry(to).or_default().extend(moved);
            }
        }
    }
}

/// Move one set from every participating member's `ready[key]` queue into
/// its `released` queue, but only when the generation is aligned for `key`:
///
/// 1. No active member may still be unresolved (startup coherence: the
///    group's discovery is not complete, so releasing now could tear the
///    very first generations).
/// 2. Every active member REQUIRED for `key` (>= 1 matched writer from that
///    publisher, registered by discovery or by deposit) must have at least
///    one ready set from `key`. When no member is required any more
///    (publisher departed), the members still holding residual sets from
///    `key` release together instead (departure drain).
/// 3. Generation identity, when the sets carry one (GROUP scope GSN,
///    RTPS v2.5 8.7.5): the round's queue fronts must all sit on the SAME
///    publisher generation. Unequal fronts only arise at a discovery seam
///    (a member matched mid-stream missed the generations published before
///    its match point); the older fronts can never be completed by the
///    mid-stream member when it is VOLATILE (no history replay, DDS v1.4
///    2.2.3.4), so they are discarded until the fronts agree. Pairing them
///    by queue position instead would present generation N alongside
///    generation M != N (a torn GROUP presentation) and leave the
///    mid-stream member permanently offset from its peers. Sets without a
///    generation tag are wildcards: they neither drive nor block the
///    alignment and simply fill their member's slot in whichever round
///    fires. If the maximum front belongs to a NON-volatile member the
///    barrier waits instead of discarding (its peers' replay must
///    eventually catch up; unreachable in practice for HDDS self replay
///    because durability RxO guarantees a gap-free stream, but waiting is
///    the safe default and the departure drain still unblocks a dead
///    publisher). Only alignment or an explicit loss proof ends that wait.
///
/// The round then pops one set from every active member holding a ready set
/// for `key` -- required members by rule 2, plus members draining residual
/// sets of a publisher they are no longer matched to. Inactive members
/// (torn-down readers) never block and never receive.
fn try_release_one_generation(state: &mut BarrierState, key: &PublisherKey) {
    if state.members.iter().any(|m| m.active && !m.resolved) {
        return;
    }
    if release_past_generation(state, key) {
        return;
    }
    let mut any_ready = false;
    for m in state.members.iter() {
        if !m.active {
            continue;
        }
        if m.key_counts.contains_key(key) && !m.has_ready(key) {
            return;
        }
        if m.has_ready(key) {
            any_ready = true;
        }
    }
    if !any_ready {
        return;
    }
    // Rule 3: align the round on one publisher generation. Each pass
    // discards at least one uncompletable set, so the loop terminates.
    loop {
        let front_gsn = |m: &Member| {
            m.ready
                .get(key)
                .and_then(|q| q.front())
                .and_then(|set| set.gsn)
        };
        let mut round: Option<u64> = None;
        for m in state.members.iter().filter(|m| m.active) {
            if let Some(g) = front_gsn(m) {
                round = Some(round.map_or(g, |r| r.max(g)));
            }
        }
        // No generation-tagged front: plain FIFO round (TOPIC/INSTANCE
        // scope and classic dialects), exactly the pre-alignment behavior.
        let Some(round) = round else { break };
        let mut any_lagging = false;
        let mut max_front_all_volatile = true;
        for m in state.members.iter().filter(|m| m.active) {
            match front_gsn(m) {
                Some(g) if g < round => any_lagging = true,
                Some(g) if g == round && !m.volatile => max_front_all_volatile = false,
                _ => {}
            }
        }
        if !any_lagging {
            break;
        }
        if !max_front_all_volatile {
            // Durable retained changes may arrive on any later retry. A
            // counter cannot establish that a coherent unit is unavailable.
            return;
        }
        for m in state.members.iter_mut().filter(|m| m.active) {
            let Some(queue) = m.ready.get_mut(key) else {
                continue;
            };
            while queue
                .front()
                .is_some_and(|set| set.gsn.is_some_and(|g| g < round))
            {
                log::debug!(
                    "[COHERENT-BARRIER] topic='{}' discarding generation {:?} < {} \
                     (unreachable for a mid-stream VOLATILE peer, cannot align)",
                    m.topic,
                    queue.front().and_then(|s| s.gsn),
                    round,
                );
                queue.pop_front();
            }
            if queue.is_empty() {
                m.ready.remove(key);
            }
        }
        // Discarding may have emptied a required member's queue: the
        // aligned generation is not complete yet, wait for its set.
        for m in state.members.iter().filter(|m| m.active) {
            if m.key_counts.contains_key(key) && !m.has_ready(key) {
                return;
            }
        }
    }
    // A generation one member could not make whole is lost for every
    // member: no part of it is delivered (RTPS v2.5 Sec.8.7.6).
    let lost_round: Option<u64> = state
        .members
        .iter()
        .filter(|m| m.active)
        .filter_map(|m| m.ready.get(key).and_then(|q| q.front()))
        .find(|set| set.lost)
        .and_then(|set| set.gsn);
    // The round's generation, aligned above: a member whose slot an
    // untagged set fills presents it too.
    let round_gsn: Option<u64> = state
        .members
        .iter()
        .filter(|m| m.active)
        .filter_map(|m| m.ready.get(key).and_then(|q| q.front()))
        .filter_map(|set| set.gsn)
        .max();
    for m in state.members.iter_mut() {
        if m.active {
            if let Some(queue) = m.ready.get_mut(key) {
                if let Some(mut set) = queue.pop_front() {
                    if lost_round.is_some() && set.gsn == lost_round {
                        set.lost = true;
                    }
                    log::debug!(
                        "[COHERENT-BARRIER] release topic='{}' gsn={:?} key={:02x?} lost={}",
                        m.topic,
                        set.gsn,
                        &key[..4],
                        set.lost,
                    );
                    note_presented(&mut m.presented, key, round_gsn.or(set.gsn));
                    // An empty part that is not lost delivers nothing: it
                    // only held the generation's place in the round.
                    if set.lost || !set.is_empty() {
                        m.released.push_back(set);
                    }
                }
                if queue.is_empty() {
                    m.ready.remove(key);
                }
            }
        }
    }
}

/// Record in a member's `presented` that it presented generation `gsn` of
/// publisher `key`.
fn note_presented(
    presented: &mut HashMap<PublisherKey, u64>,
    key: &PublisherKey,
    gsn: Option<u64>,
) {
    if let Some(gsn) = gsn {
        let newest = presented.entry(*key).or_insert(gsn);
        *newest = (*newest).max(gsn);
    }
}

/// Release the oldest queued generation of `key` to the members holding it
/// when every other member already presented that generation or a later
/// one. A reader created after its peers presented generation `g` gets its
/// part of `g` from the writer's retained history (TRANSIENT_LOCAL and
/// stronger, DDS v1.4 Sec.2.2.3.4) after `g` was made available to the
/// Subscriber (Sec.2.2.3.6): no round can ever pair it with the parts
/// already presented, so it is presented whole on its own instead of
/// holding every later generation behind it. A member whose own stream
/// already passed `g` is not served this way: its presentation order never
/// goes back. Returns whether a set was released.
fn release_past_generation(state: &mut BarrierState, key: &PublisherKey) -> bool {
    let front_gsn = |m: &Member| {
        m.ready
            .get(key)
            .and_then(|q| q.front())
            .and_then(|set| set.gsn)
    };
    let Some(oldest) = state
        .members
        .iter()
        .filter(|m| m.active)
        .filter_map(front_gsn)
        .min()
    else {
        return false;
    };
    let presented_at_least = |m: &Member| {
        m.presented
            .get(key)
            .is_some_and(|&presented| presented >= oldest)
    };
    let mut presented_elsewhere = false;
    for m in state.members.iter().filter(|m| m.active) {
        let holds_oldest = front_gsn(m) == Some(oldest);
        if holds_oldest == presented_at_least(m) {
            // A holder already past it, or a member yet to present it.
            if m.key_counts.contains_key(key) || m.has_ready(key) {
                return false;
            }
        } else if !holds_oldest {
            presented_elsewhere = true;
        }
    }
    // Nobody presented it yet: an ordinary round, aligned by the caller.
    if !presented_elsewhere {
        return false;
    }
    let lost = state
        .members
        .iter()
        .filter(|m| m.active && front_gsn(m) == Some(oldest))
        .filter_map(|m| m.ready.get(key).and_then(|q| q.front()))
        .any(|set| set.lost);
    for m in state.members.iter_mut().filter(|m| m.active) {
        let Some(queue) = m.ready.get_mut(key) else {
            continue;
        };
        if queue.front().and_then(|set| set.gsn) != Some(oldest) {
            continue;
        }
        if let Some(mut set) = queue.pop_front() {
            set.lost |= lost;
            log::debug!(
                "[COHERENT-BARRIER] release presented generation topic='{}' gsn={} key={:02x?} lost={}",
                m.topic,
                oldest,
                &key[..4],
                set.lost,
            );
            if queue.is_empty() {
                m.ready.remove(key);
            }
            note_presented(&mut m.presented, key, set.gsn);
            if set.lost || !set.is_empty() {
                m.released.push_back(set);
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn payload(seq: u64) -> PendingPayload {
        PendingPayload {
            order: None,
            order_token: None,
            version: crate::dds::CdrVersion::Xcdr2,
            remote_seq: seq,
            source_ts_ns: None,
            slot: None,
            prepared: crate::dds::reader::admission::Prepared::Discard,
            staged: None,
        }
    }

    /// A writer GUID under publisher prefix `[p; 12]` with a distinct
    /// entity id, so several writers of the same remote publisher can be
    /// modelled.
    fn wguid(p: u8, entity: u8) -> [u8; 16] {
        let mut g = [p; 16];
        g[12] = 0;
        g[13] = 0;
        g[14] = 0;
        g[15] = entity;
        g
    }

    fn key(p: u8) -> PublisherKey {
        publisher_key([p; 12], [0; 4])
    }

    /// A per-topic set of `n` samples from one writer.
    fn set_of(writer: [u8; 16], n: u64) -> CoherentSet {
        CoherentSet::single(writer, (0..n).map(payload).collect())
    }

    /// Wire a barrier of `topics` members, each delivering into a shared
    /// counter so a test can observe exactly what reached each member's
    /// "ring".
    fn build(topics: usize) -> (Arc<CoherentPresentationBarrier>, Vec<Arc<AtomicUsize>>) {
        let barrier = Arc::new(CoherentPresentationBarrier::new());
        let mut sinks = Vec::new();
        for t in 0..topics {
            let id = barrier.reserve(format!("topic{t}"), true);
            assert_eq!(id, t);
            let sink = Arc::new(AtomicUsize::new(0));
            let sink_c = Arc::clone(&sink);
            barrier.attach_deliver(
                id,
                Arc::new(move |set: CoherentSet| {
                    sink_c.fetch_add(set.len(), Ordering::SeqCst);
                }),
            );
            sinks.push(sink);
        }
        assert_eq!(barrier.member_count(), topics);
        (barrier, sinks)
    }

    /// Register one matched writer of publisher `p` per member (the SEDP
    /// cold-path step ReaderBuilder wires through the match notification).
    fn match_all(barrier: &CoherentPresentationBarrier, members: usize, p: u8) {
        for (id, entity) in (0..members).zip(1u8..) {
            barrier.register_matched_writer(id, wguid(p, entity));
        }
    }

    /// Per-topic set of `n` samples from one writer, tagged with the
    /// publisher generation it was closed under (GROUP scope).
    fn gsn_set(writer: [u8; 16], gsn: u64, n: u64) -> CoherentSet {
        CoherentSet {
            writers: vec![(writer, (0..n).map(payload).collect())],
            gsn: Some(gsn),
            lost: false,
        }
    }

    /// Recording sink variant of `build`: logs every delivered set as
    /// `(gsn, sample_count)` so a test can assert exactly WHICH generation
    /// reached each member's "ring", not just how many samples.
    type DeliveryLog = Arc<std::sync::Mutex<Vec<(Option<u64>, usize)>>>;
    fn build_recording(
        topics: usize,
        volatile: bool,
    ) -> (Arc<CoherentPresentationBarrier>, Vec<DeliveryLog>) {
        let barrier = Arc::new(CoherentPresentationBarrier::new());
        let mut sinks = Vec::new();
        for t in 0..topics {
            let id = barrier.reserve(format!("topic{t}"), volatile);
            assert_eq!(id, t);
            let sink: DeliveryLog = Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink_c = Arc::clone(&sink);
            barrier.attach_deliver(
                id,
                Arc::new(move |set: CoherentSet| {
                    let n: usize = set.writers.iter().map(|(_, p)| p.len()).sum();
                    sink_c
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((set.gsn, n));
                }),
            );
            sinks.push(sink);
        }
        (barrier, sinks)
    }

    fn log_of(sink: &DeliveryLog) -> Vec<(Option<u64>, usize)> {
        sink.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// One full subscriber read cycle: every member takes once (the
    /// `take_all` drive). Returns how many members delivered a set.
    fn cycle(barrier: &CoherentPresentationBarrier, members: usize) -> usize {
        (0..members)
            .filter(|&id| barrier.take_one_aligned(id))
            .count()
    }

    #[test]
    fn expired_best_effort_ready_units_keep_their_physical_marker_charge() {
        use super::super::staging_budget::{Admission, StagedCharge, StagedSet, StagingBudget};
        let policy = crate::qos::MemoryPolicy {
            max_staging_bytes: 200,
            ..Default::default()
        };
        let (_, _pool) = crate::core::rt::owned_private_slab_pool_for_test(&policy);
        let (barrier, _) = build_recording(2, false);
        match_all(&barrier, 2, 31);
        let live = Arc::new(AtomicUsize::new(0));
        for member in 0..2 {
            let live = live.clone();
            barrier.attach_deliver(
                member,
                Arc::new(move |set| {
                    if !set.lost {
                        live.fetch_add(set.len(), Ordering::SeqCst);
                    }
                }),
            );
        }
        let owner = StagingBudget::new(4);
        let incoming = StagingBudget::new(4);
        for generation in [1, 3] {
            let staged = StagedSet::Group(([31; 12], [0; 4], generation));
            assert_eq!(owner.admit(staged, 100, true, &|_| {}), Admission::Admitted);
            let mut item = payload(generation);
            item.staged = Some(StagedCharge::new(&owner, staged, 100));
            barrier.deposit(
                0,
                key(31),
                CoherentSet::spec_part(vec![(wguid(31, 1), vec![item])], generation, false),
            );
            barrier.retire_wire_generation(key(31), generation);
        }
        for _ in 0..1000 {
            barrier.deposit(0, key(31), CoherentSet::spec_part(Vec::new(), 1, true));
            assert_eq!(
                barrier.wire_loss_marker_counts_for_test(0, key(31)),
                (2, 2),
                "terminal retransmissions created uncharged ready records"
            );
        }
        for generation in 5..1005 {
            let staged = StagedSet::Group(([31; 12], [0; 4], generation));
            assert_eq!(
                incoming.admit(staged, 100, true, &|_| {}),
                Admission::Refused
            );
            assert_eq!(barrier.wire_loss_marker_counts_for_test(0, key(31)), (2, 2));
        }
        assert_eq!(owner.used(), 200);
        for generation in [1, 3] {
            barrier.deposit(1, key(31), gsn_set(wguid(31, 2), generation, 1));
            assert_eq!(cycle(&barrier, 2), 2);
            assert_eq!(cycle(&barrier, 2), 0);
        }
        assert_eq!(barrier.wire_loss_marker_counts_for_test(0, key(31)), (0, 0));
        assert_eq!(
            owner.used(),
            0,
            "ordered retirement leaked a pinned marker charge"
        );
        assert_eq!(
            live.load(Ordering::SeqCst),
            0,
            "the late peer presented part of a lost unit"
        );
    }

    /// Discovery-lag seam, part 1 (release-round skip): SEDP match
    /// notifications can lag the data path by whole read cycles, so members
    /// may deposit sets while none of them has a registered writer yet. A
    /// release round must then never advance some members while skipping a
    /// member that has already deposited for the same publisher: the
    /// skipped reader's ring stays empty while its peers deliver, and the
    /// application observes a partial cross-topic group in that read cycle
    /// (a torn GROUP presentation, DDS v1.4 2.2.3.6). Receiving a committed
    /// coherent set from publisher K is itself proof of a matched writer
    /// from K, ahead of the discovery callback.
    #[test]
    fn release_round_never_skips_a_deposited_member() {
        let (barrier, sinks) = build_recording(3, true);
        // No register_matched_writer at all: data outruns discovery.
        for (id, entity) in (0..3usize).zip(1u8..) {
            barrier.deposit(id, key(0xAA), set_of(wguid(0xAA, entity), 12));
        }
        // Cycle 1: the generation is complete on all three -> all deliver.
        assert_eq!(cycle(&barrier, 3), 3);
        // Members 0 and 1 complete their next set; member 2's completion
        // signal is still in flight on the RX thread.
        barrier.deposit(0, key(0xAA), set_of(wguid(0xAA, 1), 12));
        barrier.deposit(1, key(0xAA), set_of(wguid(0xAA, 2), 12));
        // Cycle 2: nothing may release. Member 2 already deposited for this
        // publisher, so it is a required group member even though discovery
        // has not fired yet; releasing members 0 and 1 without it would
        // tear the group (some-but-not-all members deliver in one cycle).
        assert_eq!(
            cycle(&barrier, 3),
            0,
            "a round released while a deposited member had nothing ready"
        );
        // Member 2 completes -> the generation releases for all three.
        barrier.deposit(2, key(0xAA), set_of(wguid(0xAA, 3), 12));
        assert_eq!(cycle(&barrier, 3), 3);
        for (t, sink) in sinks.iter().enumerate() {
            assert_eq!(
                log_of(sink),
                vec![(None, 12), (None, 12)],
                "member {t} must see exactly two aligned generations"
            );
        }
    }

    /// Discovery-lag seam, part 2 (cross-epoch pairing): while a
    /// late-matched member has never deposited, its peers accumulate held
    /// generations under the startup hold. Under VOLATILE durability the
    /// late member can never receive those generations (the writer only
    /// sends it data from its match point onward, DDS v1.4 2.2.3.4), so
    /// when its first live set arrives they must be discarded -- pairing
    /// by queue position would present publisher generation N alongside
    /// generation M != N and leave the late member one generation ahead
    /// of its peers for the rest of the stream.
    #[test]
    fn late_member_seam_discards_unpairable_backlog() {
        let (barrier, sinks) = build_recording(3, true);
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 11, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 11, 12));
        // Startup coherence: member 2 unresolved -> nothing releases.
        assert_eq!(cycle(&barrier, 3), 0);
        // Member 2 deposits its first live set: generation 12.
        barrier.deposit(2, key(0xAA), gsn_set(wguid(0xAA, 3), 12, 12));
        // Generation 11 is uncompletable and must not pair with 12.
        assert_eq!(
            cycle(&barrier, 3),
            0,
            "generation 11 must never pair with generation 12"
        );
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 12, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 12, 12));
        assert_eq!(cycle(&barrier, 3), 3);
        for (t, sink) in sinks.iter().enumerate() {
            assert_eq!(
                log_of(sink),
                vec![(Some(12), 12)],
                "member {t} must deliver exactly one aligned generation-12 set"
            );
        }
    }

    /// Symmetric seam: the late member's own deposits may START with a
    /// stale set from before its live window (observed on the wire as a
    /// VOLATILE late-join retransmit artifact). That backlog predates the
    /// peers' oldest held generation and can never be completed by them:
    /// it must be discarded rather than consume a release slot, which
    /// would shift the member one generation behind its peers for the
    /// rest of the stream.
    #[test]
    fn late_member_stale_backlog_is_discarded_not_paired() {
        let (barrier, sinks) = build_recording(3, true);
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 12, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 12, 12));
        // The late member deposits a stale pre-match set, then its live one.
        barrier.deposit(2, key(0xAA), gsn_set(wguid(0xAA, 3), 1, 12));
        barrier.deposit(2, key(0xAA), gsn_set(wguid(0xAA, 3), 12, 12));
        assert_eq!(cycle(&barrier, 3), 3);
        for (t, sink) in sinks.iter().enumerate() {
            assert_eq!(
                log_of(sink),
                vec![(Some(12), 12)],
                "member {t}: generation 12 releases aligned, the stale set never surfaces"
            );
        }
        assert_eq!(cycle(&barrier, 3), 0, "nothing may be left over");
    }

    /// TRANSIENT_LOCAL members replay history from the writer, so a
    /// late-matched member's queue starts at the same first generation as
    /// its peers: queue-position pairing is exact and nothing may be
    /// discarded on its account (durability RxO guarantees the replay: a
    /// TRANSIENT_LOCAL reader only matches TRANSIENT_LOCAL-or-stronger
    /// writers, DDS v1.4 2.2.3.4).
    #[test]
    fn transient_local_replay_keeps_every_generation() {
        let (barrier, sinks) = build_recording(2, false);
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 1, 12));
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 2, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 1, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 2, 12));
        assert_eq!(cycle(&barrier, 2), 2);
        assert_eq!(cycle(&barrier, 2), 2);
        for (t, sink) in sinks.iter().enumerate() {
            assert_eq!(
                log_of(sink),
                vec![(Some(1), 12), (Some(2), 12)],
                "member {t} must deliver the full replayed stream in order"
            );
        }
    }

    /// Cross-vendor discovery seam BOUND: when the round-front is held by a
    /// NON-volatile (TRANSIENT_LOCAL) member, rule 3 normally just waits
    /// Durable coherent fronts never become unavailable merely through retries.
    #[test]
    fn nonvolatile_retries_never_discard_retained_coherent_fronts() {
        let (barrier, sinks) = build_recording(2, false);
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 12, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 5, 5));
        for _ in 0..64 {
            assert_eq!(cycle(&barrier, 2), 0);
        }
        for sink in &sinks {
            assert!(
                log_of(sink).is_empty(),
                "retry attempts discarded retained coherent data"
            );
        }
        let state = barrier.lock();
        assert_eq!(
            state.members[1].ready[&key(0xAA)].front().unwrap().gsn,
            Some(5)
        );
    }

    /// DDS v1.4 Sec.2.2.3.4 and Sec.2.2.3.6: a TRANSIENT_LOCAL reader
    /// created after generation 79 was made available to the Subscriber
    /// receives its part of 79 from the writer's retained history. That
    /// part can never be paired with the part its peer already presented:
    /// it is presented whole on its own, and the next generation is
    /// presented aligned across every reader.
    #[test]
    fn a_reader_created_after_a_presented_generation_receives_its_part() {
        let barrier = Arc::new(CoherentPresentationBarrier::new());
        let mut sinks: Vec<DeliveryLog> = Vec::new();
        add_durable_member(&barrier, &mut sinks);
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 79, 12));
        assert_eq!(cycle(&barrier, 1), 1, "a lone reader presents 79");

        add_durable_member(&barrier, &mut sinks);
        add_durable_member(&barrier, &mut sinks);
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 79, 12));
        barrier.deposit(2, key(0xAA), gsn_set(wguid(0xAA, 3), 79, 12));
        assert_eq!(
            cycle(&barrier, 3),
            2,
            "the late readers present their part of 79 without waiting for the reader that presented it"
        );
        for id in 0..3 {
            barrier.deposit(id, key(0xAA), gsn_set(wguid(0xAA, id as u8 + 1), 118, 12));
        }
        assert_eq!(cycle(&barrier, 3), 3, "118 is presented aligned");
        assert_eq!(cycle(&barrier, 3), 0);
        for (t, sink) in sinks.iter().enumerate() {
            assert_eq!(
                log_of(sink),
                vec![(Some(79), 12), (Some(118), 12)],
                "member {t} presents every generation it received, in order"
            );
        }
    }

    /// A TRANSIENT_LOCAL member reserved after its peer joined the
    /// barrier, as a reader the application creates after another one.
    fn add_durable_member(barrier: &CoherentPresentationBarrier, sinks: &mut Vec<DeliveryLog>) {
        let id = barrier.reserve(format!("topic{}", sinks.len()), false);
        assert_eq!(id, sinks.len());
        let sink: DeliveryLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_c = Arc::clone(&sink);
        barrier.attach_deliver(
            id,
            Arc::new(move |set: CoherentSet| {
                let n: usize = set.writers.iter().map(|(_, p)| p.len()).sum();
                sink_c
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((set.gsn, n));
            }),
        );
        sinks.push(sink);
    }

    /// The same seam when the reader that presented 79 already holds 118:
    /// the late part of 79 is presented, then 118 aligned, nothing is left
    /// waiting.
    #[test]
    fn a_presented_generation_does_not_hold_the_next_one_behind_it() {
        let barrier = Arc::new(CoherentPresentationBarrier::new());
        let mut sinks: Vec<DeliveryLog> = Vec::new();
        add_durable_member(&barrier, &mut sinks);
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 79, 12));
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 118, 12));
        assert_eq!(cycle(&barrier, 1), 1, "a lone reader presents 79");
        add_durable_member(&barrier, &mut sinks);
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 79, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 118, 12));
        assert_eq!(cycle(&barrier, 2), 1, "member 1 presents its part of 79");
        assert_eq!(cycle(&barrier, 2), 2, "118 is presented aligned");
        assert_eq!(cycle(&barrier, 2), 0);
        assert_eq!(log_of(&sinks[0]), vec![(Some(79), 12), (Some(118), 12)]);
        assert_eq!(log_of(&sinks[1]), vec![(Some(79), 12), (Some(118), 12)]);
    }

    /// A reader's presentation never goes back: once a member presented
    /// 12, a set of generation 11 it completes later is not presented
    /// after it, and it does not pair with a peer's 13 either.
    #[test]
    fn a_member_never_presents_a_generation_older_than_one_it_presented() {
        let (barrier, sinks) = build_recording(2, false);
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 12, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 12, 12));
        assert_eq!(cycle(&barrier, 2), 2);
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 11, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 13, 12));
        assert_eq!(cycle(&barrier, 2), 0);
        assert_eq!(log_of(&sinks[0]), vec![(Some(12), 12)]);
        assert_eq!(log_of(&sinks[1]), vec![(Some(12), 12)]);
    }

    /// A set with unknown generation identity (classic marker-less
    /// dialects and rescue sets carry no GSN) is an alignment wildcard: it
    /// neither drives nor blocks alignment, it fills its member's slot in
    /// whichever round fires. A real generation it displaces becomes
    /// unpairable afterwards (its peers advanced past it) and is discarded
    /// by the alignment rule: bounded, self-limiting seam impurity instead
    /// of a permanently shifted member.
    #[test]
    fn unknown_generation_set_is_wildcard_and_self_limiting() {
        let (barrier, sinks) = build_recording(3, true);
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 5, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 5, 12));
        barrier.deposit(
            2,
            key(0xAA),
            CoherentSet::single(wguid(0xAA, 3), (0..12).map(payload).collect()),
        );
        barrier.deposit(2, key(0xAA), gsn_set(wguid(0xAA, 3), 5, 12));
        // Round 5 fires: the wildcard fills member 2's slot.
        assert_eq!(cycle(&barrier, 3), 3);
        // Member 2's displaced generation 5 is now behind its peers: it is
        // discarded at the next alignment, never presented as a second
        // helping of member 2 in a later cycle.
        barrier.deposit(0, key(0xAA), gsn_set(wguid(0xAA, 1), 6, 12));
        barrier.deposit(1, key(0xAA), gsn_set(wguid(0xAA, 2), 6, 12));
        assert_eq!(
            cycle(&barrier, 3),
            0,
            "generation 6 must wait for member 2's own generation 6"
        );
        barrier.deposit(2, key(0xAA), gsn_set(wguid(0xAA, 3), 6, 12));
        assert_eq!(cycle(&barrier, 3), 3);
        assert_eq!(
            log_of(&sinks[2]),
            vec![(None, 12), (Some(6), 12)],
            "the wildcard then generation 6; the displaced generation 5 never surfaces"
        );
    }

    /// THE REPRO INVARIANT (cross-topic desync): depositing a set on only
    /// some topics must expose NOTHING to any reader. Without the barrier
    /// the engine pushes topic 0's set straight to its ring, so a read
    /// cycle sees a partial cross-topic group. With the barrier, draining
    /// all three readers yields 0 until every topic fed by the same remote
    /// publisher has produced its set.
    #[test]
    fn partial_group_is_held_until_all_topics_ready() {
        let (barrier, sinks) = build(3);
        match_all(&barrier, 3, 0xAA);

        // Only topic 0 completed set 1 (topics 1 and 2 still in flight).
        barrier.deposit(0, key(0xAA), set_of(wguid(0xAA, 1), 12));

        // A full subscriber read cycle drains all three readers.
        for id in 0..3 {
            assert!(
                !barrier.take_one_aligned(id),
                "no reader may deliver a partial cross-topic group"
            );
        }
        for (t, sink) in sinks.iter().enumerate() {
            assert_eq!(
                sink.load(Ordering::SeqCst),
                0,
                "topic {t} leaked a partial set"
            );
        }
    }

    /// Once every topic has a set, one read cycle delivers exactly one
    /// aligned generation: 12 per topic, and nothing left over.
    #[test]
    fn full_group_releases_exactly_one_aligned_generation() {
        let (barrier, sinks) = build(3);
        match_all(&barrier, 3, 0xAA);
        for (id, entity) in (0..3usize).zip(1u8..) {
            barrier.deposit(id, key(0xAA), set_of(wguid(0xAA, entity), 12));
        }
        // Read cycle 1: every reader delivers its aligned set.
        for id in 0..3 {
            assert!(barrier.take_one_aligned(id), "reader {id} should deliver");
        }
        for sink in &sinks {
            assert_eq!(sink.load(Ordering::SeqCst), 12);
        }
        // Read cycle 2: nothing new was deposited -> all readers empty.
        for id in 0..3 {
            assert!(!barrier.take_one_aligned(id));
        }
        for sink in &sinks {
            assert_eq!(
                sink.load(Ordering::SeqCst),
                12,
                "no second generation exists"
            );
        }
    }

    /// Two generations arriving before any read must NOT merge into one
    /// read cycle: each cycle delivers exactly one generation per topic.
    #[test]
    fn two_generations_do_not_merge_in_one_cycle() {
        let (barrier, sinks) = build(3);
        match_all(&barrier, 3, 0xAA);
        for _generation in 0..2 {
            for (id, entity) in (0..3usize).zip(1u8..) {
                barrier.deposit(id, key(0xAA), set_of(wguid(0xAA, entity), 12));
            }
        }
        // Cycle 1: each reader takes exactly one set (12), not both (24).
        for id in 0..3 {
            assert!(barrier.take_one_aligned(id));
        }
        for sink in &sinks {
            assert_eq!(
                sink.load(Ordering::SeqCst),
                12,
                "cycle 1 must be one generation"
            );
        }
        // Cycle 2: the second generation, also aligned.
        for id in 0..3 {
            assert!(barrier.take_one_aligned(id));
        }
        for sink in &sinks {
            assert_eq!(sink.load(Ordering::SeqCst), 24);
        }
    }

    /// A single-member group (a lone coherent reader) is pure pass-through:
    /// each deposited set is delivered on the next take, preserving the
    /// pre-barrier single-topic behaviour with zero regression.
    #[test]
    fn single_member_group_is_passthrough() {
        let (barrier, sinks) = build(1);
        match_all(&barrier, 1, 0xAA);
        barrier.deposit(0, key(0xAA), set_of(wguid(0xAA, 1), 12));
        assert!(barrier.take_one_aligned(0));
        assert_eq!(sinks[0].load(Ordering::SeqCst), 12);
        assert!(!barrier.take_one_aligned(0));
    }

    /// A member whose reader is torn down is forgotten so its peers can
    /// resume aligned delivery instead of stalling forever (safety valve).
    #[test]
    fn forgotten_member_unblocks_peers() {
        let (barrier, sinks) = build(3);
        match_all(&barrier, 3, 0xAA);
        barrier.deposit(0, key(0xAA), set_of(wguid(0xAA, 1), 12));
        barrier.deposit(1, key(0xAA), set_of(wguid(0xAA, 2), 12));
        // Topic 2 never produces; the group is stuck (no partial leaks).
        for id in 0..3 {
            assert!(!barrier.take_one_aligned(id));
        }
        for sink in &sinks {
            assert_eq!(sink.load(Ordering::SeqCst), 0);
        }
        // Topic 2's reader goes away -> forget it -> the remaining two align.
        barrier.forget_member(2);
        assert!(barrier.take_one_aligned(0));
        assert!(barrier.take_one_aligned(1));
        assert!(
            !barrier.take_one_aligned(2),
            "forgotten member delivers nothing"
        );
        assert_eq!(sinks[0].load(Ordering::SeqCst), 12);
        assert_eq!(sinks[1].load(Ordering::SeqCst), 12);
        assert_eq!(sinks[2].load(Ordering::SeqCst), 0);
    }

    /// Per-remote-publisher keying: readers fed by publisher A must never
    /// be blocked by a reader that is only matched to publisher B, and vice
    /// versa. Alignment applies within each publisher's member set only.
    #[test]
    fn independent_publishers_do_not_block_each_other() {
        let (barrier, sinks) = build(3);
        // Members 0 and 1 belong to publisher A; member 2 to publisher B.
        barrier.register_matched_writer(0, wguid(0xAA, 1));
        barrier.register_matched_writer(1, wguid(0xAA, 2));
        barrier.register_matched_writer(2, wguid(0xBB, 1));

        // Publisher A completes a generation on both of its topics;
        // publisher B has produced nothing.
        barrier.deposit(0, key(0xAA), set_of(wguid(0xAA, 1), 12));
        barrier.deposit(1, key(0xAA), set_of(wguid(0xAA, 2), 12));

        assert!(barrier.take_one_aligned(0), "A must release despite B idle");
        assert!(barrier.take_one_aligned(1));
        assert!(!barrier.take_one_aligned(2), "B has nothing to deliver");
        assert_eq!(sinks[0].load(Ordering::SeqCst), 12);
        assert_eq!(sinks[1].load(Ordering::SeqCst), 12);
        assert_eq!(sinks[2].load(Ordering::SeqCst), 0);

        // Publisher B completes independently.
        barrier.deposit(2, key(0xBB), set_of(wguid(0xBB, 1), 7));
        assert!(barrier.take_one_aligned(2));
        assert_eq!(sinks[2].load(Ordering::SeqCst), 7);
    }

    /// Startup coherence: while any active member is still unresolved (no
    /// matched writer, nothing deposited), no key releases. Discovery does
    /// not resolve every reader at the same instant; an early release here
    /// would tear the first generations of a publisher whose remaining
    /// readers are still matching.
    #[test]
    fn unresolved_member_blocks_release_until_discovery_completes() {
        let (barrier, sinks) = build(3);
        barrier.register_matched_writer(0, wguid(0xAA, 1));
        barrier.register_matched_writer(1, wguid(0xAA, 2));
        // Member 2 is reserved but discovery has not resolved it yet.

        barrier.deposit(0, key(0xAA), set_of(wguid(0xAA, 1), 12));
        barrier.deposit(1, key(0xAA), set_of(wguid(0xAA, 2), 12));
        for id in 0..3 {
            assert!(
                !barrier.take_one_aligned(id),
                "unresolved member must hold the group"
            );
        }

        // Member 2 matches its writer from the same publisher: it is now
        // required for the key, so the group waits for its set.
        barrier.register_matched_writer(2, wguid(0xAA, 3));
        for id in 0..3 {
            assert!(!barrier.take_one_aligned(id));
        }

        // Its set arrives -> the generation is aligned.
        barrier.deposit(2, key(0xAA), set_of(wguid(0xAA, 3), 12));
        for id in 0..3 {
            assert!(barrier.take_one_aligned(id));
        }
        for sink in &sinks {
            assert_eq!(sink.load(Ordering::SeqCst), 12);
        }
    }

    /// Departure drain: once a publisher has no matched writers left on any
    /// member, its residual complete generations release across whichever
    /// members still hold them, so a publisher shutdown never strands
    /// delivered-but-unread sets.
    #[test]
    fn departed_publisher_drains_residual_generations() {
        let (barrier, sinks) = build(2);
        barrier.register_matched_writer(0, wguid(0xAA, 1));
        barrier.register_matched_writer(1, wguid(0xAA, 2));

        // A full generation is pending when the publisher goes away.
        barrier.deposit(0, key(0xAA), set_of(wguid(0xAA, 1), 12));
        barrier.deposit(1, key(0xAA), set_of(wguid(0xAA, 2), 12));
        barrier.unregister_matched_writer(0, wguid(0xAA, 1));
        barrier.unregister_matched_writer(1, wguid(0xAA, 2));

        assert!(barrier.take_one_aligned(0));
        assert!(barrier.take_one_aligned(1));
        assert_eq!(sinks[0].load(Ordering::SeqCst), 12);
        assert_eq!(sinks[1].load(Ordering::SeqCst), 12);

        // A residual set held by only one member (the peer never completed
        // its own) still drains: with no member required for the key any
        // more, holders release together.
        barrier.deposit(0, key(0xAA), set_of(wguid(0xAA, 1), 5));
        assert!(barrier.take_one_aligned(0));
        assert!(!barrier.take_one_aligned(1));
        assert_eq!(sinks[0].load(Ordering::SeqCst), 17);
        assert_eq!(sinks[1].load(Ordering::SeqCst), 12);
    }

    /// A GROUP set of the spec dialect that touches one member's topic
    /// only: the other member deposits its empty part (its writers' ends,
    /// D6), the round aligns on the generation, and the next one is not
    /// discarded for want of it.
    #[test]
    fn an_empty_spec_part_holds_its_generation_in_the_round() {
        let (barrier, sinks) = build_recording(2, true);
        match_all(&barrier, 2, 7);
        let (a, b) = (wguid(7, 1), wguid(7, 2));
        barrier.deposit(
            0,
            key(7),
            CoherentSet::spec_part(vec![(a, vec![payload(1)])], 1, false),
        );
        barrier.deposit(1, key(7), CoherentSet::spec_part(Vec::new(), 1, false));
        barrier.deposit(0, key(7), CoherentSet::spec_part(Vec::new(), 4, false));
        barrier.deposit(
            1,
            key(7),
            CoherentSet::spec_part(vec![(b, vec![payload(2)])], 4, false),
        );
        for _ in 0..4 {
            barrier.take_one_aligned(0);
            barrier.take_one_aligned(1);
        }
        assert_eq!(
            log_of(&sinks[0]),
            vec![(Some(1), 1)],
            "no empty part delivered"
        );
        assert_eq!(log_of(&sinks[1]), vec![(Some(4), 1)]);
    }

    /// What each member was handed: (generation, lost).
    type LostLog = Arc<std::sync::Mutex<Vec<(Option<u64>, bool)>>>;

    /// A member that could not make its part of a spec set whole deposits
    /// it lost: every member's part of that generation is handed over
    /// lost, the next generation as usual.
    #[test]
    fn a_lost_spec_part_loses_the_generation_for_every_member() {
        let barrier = Arc::new(CoherentPresentationBarrier::new());
        let mut logs = Vec::new();
        for t in 0..2 {
            let id = barrier.reserve(format!("topic{t}"), true);
            let log: LostLog = Arc::default();
            let sink = Arc::clone(&log);
            barrier.attach_deliver(
                id,
                Arc::new(move |set: CoherentSet| {
                    sink.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((set.gsn, set.lost));
                }),
            );
            logs.push(log);
        }
        match_all(&barrier, 2, 7);
        let (a, b) = (wguid(7, 1), wguid(7, 2));
        barrier.deposit(
            0,
            key(7),
            CoherentSet::spec_part(vec![(a, vec![payload(1)])], 1, false),
        );
        barrier.deposit(1, key(7), CoherentSet::spec_part(Vec::new(), 1, true));
        barrier.deposit(
            0,
            key(7),
            CoherentSet::spec_part(vec![(a, vec![payload(3)])], 3, false),
        );
        barrier.deposit(
            1,
            key(7),
            CoherentSet::spec_part(vec![(b, vec![payload(2)])], 3, false),
        );
        for _ in 0..4 {
            barrier.take_one_aligned(0);
            barrier.take_one_aligned(1);
        }
        let got = |i: usize| logs[i].lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(got(0), vec![(Some(1), true), (Some(3), false)]);
        assert_eq!(got(1), vec![(Some(1), true), (Some(3), false)]);
    }

    /// Two Publishers of one remote participant are two keys: their
    /// generations are numbered apart (each its own GSNs, RTPS v2.5
    /// Sec.8.7.5) and never aligned, paired nor discarded against each
    /// other. Keyed by the participant, publisher Y's generation 3 sat
    /// behind publisher X's generation 10 in one queue and was discarded as
    /// a generation the round had passed.
    #[test]
    fn two_publishers_of_one_participant_are_two_keys() {
        let (barrier, sinks) = build_recording(2, true);
        // Writers 1, 2 of Publisher X; 3, 4 of Publisher Y; one of each per
        // topic.
        let publisher = |w: &[u8; 16]| {
            Some(if w[15] <= 2 {
                [0, 0, 1, 8]
            } else {
                [0, 0, 2, 8]
            })
        };
        for id in 0..2 {
            barrier.attach_resolver(id, Arc::new(publisher));
        }
        let (x0, x1, y0, y1) = (
            wguid(0xAA, 1),
            wguid(0xAA, 2),
            wguid(0xAA, 3),
            wguid(0xAA, 4),
        );
        for (id, w) in [(0, x0), (1, x1), (0, y0), (1, y1)] {
            barrier.register_matched_writer(id, w);
        }
        let unused = key(0xAA);
        barrier.deposit(0, unused, gsn_set(x0, 10, 1));
        barrier.deposit(0, unused, gsn_set(y0, 3, 2));
        barrier.deposit(1, unused, gsn_set(y1, 3, 2));
        barrier.deposit(1, unused, gsn_set(x1, 10, 1));
        for _ in 0..4 {
            cycle(&barrier, 2);
        }
        for sink in &sinks {
            let mut got = log_of(sink);
            got.sort_unstable();
            assert_eq!(
                got,
                vec![(Some(3), 2), (Some(10), 1)],
                "both generations, whole"
            );
        }
    }
}

/// The Publisher key is a property of the writer, one for every member.
#[cfg(test)]
mod verify_barrier_keying {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn payload(seq: u64) -> PendingPayload {
        PendingPayload {
            order: None,
            order_token: None,
            version: crate::dds::CdrVersion::Xcdr2,
            remote_seq: seq,
            source_ts_ns: None,
            slot: None,
            prepared: crate::dds::reader::admission::Prepared::Discard,
            staged: None,
        }
    }
    fn wguid(p: u8, entity: u8) -> [u8; 16] {
        let mut g = [p; 16];
        g[12] = 0;
        g[13] = 0;
        g[14] = 0;
        g[15] = entity;
        g
    }
    type Log = Arc<Mutex<Vec<(Option<u64>, usize)>>>;
    fn build(n: usize, volatile: bool) -> (Arc<CoherentPresentationBarrier>, Vec<Log>) {
        let barrier = Arc::new(CoherentPresentationBarrier::new());
        let mut sinks = Vec::new();
        for t in 0..n {
            let id = barrier.reserve(format!("t{t}"), volatile);
            let sink: Log = Arc::new(Mutex::new(Vec::new()));
            let s = Arc::clone(&sink);
            barrier.attach_deliver(
                id,
                Arc::new(move |set: CoherentSet| {
                    let n: usize = set.writers.iter().map(|(_, p)| p.len()).sum();
                    s.lock().unwrap().push((set.gsn, n));
                }),
            );
            sinks.push(sink);
        }
        (barrier, sinks)
    }
    fn part(w: [u8; 16], gsn: u64, n: u64) -> CoherentSet {
        CoherentSet::spec_part(vec![(w, (0..n).map(payload).collect())], gsn, false)
    }

    /// (1) Resolver None when member A registers, Some when member B
    /// registers a writer of the SAME Publisher: the two members key the
    /// Publisher differently, so A's part of a generation is released
    /// alone while B has nothing (torn cross-topic group).
    #[test]
    fn v1_resolver_none_then_some_splits_one_publisher_across_two_keys() {
        let (barrier, sinks) = build(2, true);
        let known = Arc::new(AtomicBool::new(false));
        for id in 0..2 {
            let known = Arc::clone(&known);
            barrier.attach_resolver(
                id,
                Arc::new(move |_w: &[u8; 16]| known.load(Ordering::SeqCst).then_some([0, 0, 1, 8])),
            );
        }
        let (wa, wb) = (wguid(0xAA, 1), wguid(0xAA, 2));
        barrier.register_matched_writer(0, wa); // SEDP group id not known yet
        known.store(true, Ordering::SeqCst);
        barrier.register_matched_writer(1, wb);
        // Key stability per member: A keeps its first key.
        assert_eq!(
            barrier.registered_key(0, &wa),
            Some(publisher_key([0xAA; 12], [0; 4]))
        );
        // Generation 1: only A's part has arrived.
        barrier.deposit(0, publisher_key([0xAA; 12], [0, 0, 1, 8]), part(wa, 1, 2));
        barrier.take_one_aligned(0);
        barrier.take_one_aligned(1);
        assert!(
            sinks[0].lock().unwrap().is_empty(),
            "A released generation 1 while B (same Publisher) holds no part of it: {:?}",
            sinks[0].lock().unwrap()
        );
    }

    /// (1b) The writer's key comes from SEDP (None -> participant key) but
    /// an EMPTY spec part keeps the wire key (PID_GROUP_ENTITY_ID inline):
    /// B's empty part of generation 5 lands under another key, A's part
    /// waits for B under the participant key, and is discarded when B's
    /// generation 6 arrives (volatile) -- generation 5 lost for A.
    #[test]
    fn v1b_empty_spec_part_under_wire_key_loses_a_generation() {
        let (barrier, sinks) = build(2, true);
        for id in 0..2 {
            barrier.attach_resolver(id, Arc::new(|_w: &[u8; 16]| None));
        }
        let (wa, wb) = (wguid(0xAA, 1), wguid(0xAA, 2));
        barrier.register_matched_writer(0, wa);
        barrier.register_matched_writer(1, wb);
        let wire = publisher_key([0xAA; 12], [0, 0, 1, 8]);
        barrier.deposit(0, wire, part(wa, 5, 2));
        barrier.deposit(1, wire, CoherentSet::spec_part(Vec::new(), 5, false));
        barrier.deposit(0, wire, part(wa, 6, 1));
        barrier.deposit(1, wire, part(wb, 6, 1));
        for _ in 0..4 {
            barrier.take_one_aligned(0);
            barrier.take_one_aligned(1);
        }
        let got = sinks[0].lock().unwrap().clone();
        assert!(
            got.contains(&(Some(5), 2)),
            "A's part of generation 5 was never delivered: {got:?}"
        );
    }

    /// (1c) A writer registered under its participant's key while discovery
    /// did not know its Publisher moves to its Publisher's key once known,
    /// with its member: that member is then required for the Publisher, and
    /// the Publisher's generation waits for its part.
    #[test]
    fn v1c_a_writer_keyed_by_its_participant_moves_to_its_publisher() {
        let (barrier, sinks) = build(2, true);
        let known = Arc::new(AtomicBool::new(false));
        for id in 0..2 {
            let known = Arc::clone(&known);
            barrier.attach_resolver(
                id,
                Arc::new(move |_w: &[u8; 16]| known.load(Ordering::SeqCst).then_some([0, 0, 1, 8])),
            );
        }
        let (wa, wb) = (wguid(0xAB, 1), wguid(0xAB, 2));
        barrier.register_matched_writer(0, wa);
        known.store(true, Ordering::SeqCst);
        barrier.register_matched_writer(1, wb);
        // A's writer heard of again (a second match notification).
        barrier.register_matched_writer(0, wa);
        let publisher = publisher_key([0xAB; 12], [0, 0, 1, 8]);
        assert_eq!(barrier.registered_key(0, &wa), Some(publisher));
        // B's part of generation 1 alone: A, required, holds none yet.
        barrier.deposit(1, publisher, part(wb, 1, 2));
        barrier.take_one_aligned(0);
        barrier.take_one_aligned(1);
        assert!(
            sinks[1].lock().unwrap().is_empty(),
            "B released without A's part"
        );
    }

    /// (1d) What a member presented under its writer's participant key is
    /// what it presented of the Publisher once the writer moves there: a
    /// reader created later presents its part of that generation without
    /// waiting for it.
    #[test]
    fn v1d_what_was_presented_moves_with_the_writer() {
        let barrier = Arc::new(CoherentPresentationBarrier::new());
        let known = Arc::new(AtomicBool::new(false));
        let mut sinks: Vec<Log> = Vec::new();
        let add = |sinks: &mut Vec<Log>| {
            let id = barrier.reserve(format!("t{}", sinks.len()), false);
            let sink: Log = Arc::new(Mutex::new(Vec::new()));
            let s = Arc::clone(&sink);
            barrier.attach_deliver(
                id,
                Arc::new(move |set: CoherentSet| {
                    let n: usize = set.writers.iter().map(|(_, p)| p.len()).sum();
                    s.lock().unwrap().push((set.gsn, n));
                }),
            );
            let known = Arc::clone(&known);
            barrier.attach_resolver(
                id,
                Arc::new(move |_w: &[u8; 16]| known.load(Ordering::SeqCst).then_some([0, 0, 1, 8])),
            );
            sinks.push(sink);
            id
        };
        let (wa, wb) = (wguid(0xAC, 1), wguid(0xAC, 2));
        let participant = publisher_key([0xAC; 12], [0; 4]);
        let publisher = publisher_key([0xAC; 12], [0, 0, 1, 8]);
        let a = add(&mut sinks);
        barrier.register_matched_writer(a, wa);
        barrier.deposit(a, participant, part(wa, 79, 2));
        assert!(barrier.take_one_aligned(a), "a lone reader presents 79");

        known.store(true, Ordering::SeqCst);
        let b = add(&mut sinks);
        barrier.register_matched_writer(b, wb);
        barrier.register_matched_writer(a, wa);
        assert_eq!(barrier.registered_key(a, &wa), Some(publisher));
        barrier.deposit(b, publisher, part(wb, 79, 2));
        barrier.deposit(a, publisher, part(wa, 118, 1));
        barrier.deposit(b, publisher, part(wb, 118, 1));
        for _ in 0..3 {
            barrier.take_one_aligned(a);
            barrier.take_one_aligned(b);
        }
        assert_eq!(
            *sinks[0].lock().unwrap(),
            vec![(Some(79), 2), (Some(118), 1)]
        );
        assert_eq!(
            *sinks[1].lock().unwrap(),
            vec![(Some(79), 2), (Some(118), 1)]
        );
    }
}
