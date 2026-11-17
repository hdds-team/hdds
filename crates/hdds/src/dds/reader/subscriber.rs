// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Internal subscriber implementation for DataReader.
//!
//!
//! Bridges the engine's subscriber trait to the typed DataReader,
//! handling sample deserialization and duplicate detection.

use super::cache::{transition_state, HandleHasher, InstanceHandle, InstanceTable, Origin};
use super::coherent_barrier::{CoherentPresentationBarrier, CoherentSet, MemberId};
use super::registrations::ReaderRegistrations;
use super::reorder::{PendingPayload, ReorderGate};
use super::runtime::WakeWord;
use crate::core::rt;
use crate::dds::filter::FilterEvaluator;
use crate::dds::listener::{
    DataReaderListener, ReaderListenerSlot, SampleRejectedReason, SampleRejectedStatus,
};
use crate::dds::{GuardCondition, StatusCondition, StatusMask, DDS};
use crate::telemetry;
use crate::telemetry::metrics::current_time_ns;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::engine::subscriber::DisposeKind;

/// A single sample buffered for the coherent-set runtime (RTPS v2.5
/// sec. 8.7.5). Held in the per-writer staging FIFO until the matching
/// ECS DATA submessage arrives, then drained in writer-sequence order
/// and pushed through the normal admit pipeline. `group_sn` is the
/// Publisher GSN tag from inline QoS (only meaningful when the
/// publisher access_scope is GROUP); under TOPIC/INSTANCE scope it
/// remains `None`. Retained on the struct so future audits / packet
/// captures can correlate a buffered sample with the wire ECS that
/// bounds it even though the current dispatch logic keys on the
/// outer `(publisher_prefix, gsn)` map for GROUP-scope sets.
#[derive(Debug)]
pub(super) struct BufferedCoherentSample {
    order: Option<crate::engine::router::OrderedGroupChange>,
    order_token: Option<super::wire_order::OrderToken>,
    remote_seq: u64,
    /// The sample, decoded and stored before it was acknowledged, apart
    /// from the slab pool's tiers (`charge` is its charge);
    /// `Prepared::Discard` for a dispose or unregister (`lifecycle`).
    prepared: super::admission::Prepared,
    /// The representation its bytes were stored in, for the ring entry.
    version: crate::dds::CdrVersion,
    #[allow(dead_code)]
    group_sn: Option<u64>,
    /// The set's first SN (`PID_COHERENT_SET`) this sample belongs to, when
    /// known. Used by the explicit-end (vendor id 0x0101) path to commit ONLY
    /// the set being closed by an END marker, leaving samples of a later set
    /// that have already been staged (flush-on-new-set is suppressed on that
    /// path, so the next set accumulates in the same buffer until its own END
    /// arrives). Committing across set boundaries would breach the
    /// all-or-nothing atomic delivery contract (DDS v1.4 sec. 2.2.3.6).
    coherent_sn: Option<u64>,
    /// Whether it came from a writer with vendor id 0x0101, whose durable
    /// replay neither re-emits nor GAPs the sequence numbers its historical
    /// end markers took (see `flush_group_set`).
    from_vendor_0101: bool,
    /// A dispose or unregister of the set (instance key, kind), no sample
    /// (`on_lifecycle_coherent`): takes no place, delivered as the
    /// instance's transition (`PendingPayload::lifecycle`).
    lifecycle: Option<([u8; 16], DisposeKind)>,
    /// Its charge on the reader's staging budget, its storage's and its
    /// entry's (`staging_budget`): carried into the gate when its set
    /// commits, given back when it leaves it or is dropped.
    charge: Option<super::staging_budget::StagedCharge>,
    /// The datagram's INFO_TS (`router::route_source_ts_ns`), captured at
    /// STAGING time -- the one point this sample's own datagram is the
    /// one being routed, since by the time its set commits (possibly far
    /// later, behind other writers' traffic) the thread-local reflects
    /// whatever datagram is being routed THEN, not this one
    /// (`DisposeQueue::push`'s sibling doc on the non-coherent path makes
    /// the same point). `None` when the datagram carried no INFO_TS, or
    /// (for a GROUP-scope member admitted before any router call set it,
    /// an edge this field cannot distinguish from a genuinely absent
    /// INFO_TS) when none was observed -- the fallback is reception time,
    /// same as every other path with no source timestamp.
    source_ts_ns: Option<u64>,
}

/// What is left of a coherent set rejected whole for its storage
/// (`ReaderSubscriber::reject_staged_set`): the same few bytes whatever
/// the set's length. Its members are not staged: each is acknowledged,
/// steps its writer's gate (it delivers nothing) and is reported
/// SAMPLE_REJECTED as it lands.
#[derive(Debug, Clone, Copy, Default)]
struct RejectedSet {
    /// Its changes received, staged before the rejection or landed since.
    members: u64,
    /// Of those, the samples (not a dispose or unregister of the set),
    /// each reported.
    samples: u64,
    /// The instance its reports name: that of the last sample decoded
    /// when it was rejected (a member landing since is not decoded).
    instance: Option<InstanceHandle>,
}

/// The coherent sets of a reader rejected for their storage, each a
/// [`RejectedSet`]: at most `MAX_DISCARDED_SETS` per writer and
/// `MAX_DISCARDED_GROUP_SETS` GROUP sets, the oldest forgotten first.
#[derive(Debug, Default)]
struct RejectedSets {
    writers: HashMap<[u8; 16], BTreeMap<u64, RejectedSet>>,
    groups: HashMap<GroupSetKey, RejectedSet>,
    group_order: std::collections::VecDeque<GroupSetKey>,
}

impl RejectedSets {
    /// The record of `set`, if it was rejected.
    fn get_mut(&mut self, set: &StagedSet) -> Option<&mut RejectedSet> {
        match set {
            StagedSet::Writer(writer, start) => self.writers.get_mut(writer)?.get_mut(start),
            StagedSet::Group(key) => self.groups.get_mut(key),
        }
    }

    /// Whether `set` was rejected.
    fn contains(&self, set: &StagedSet) -> bool {
        match set {
            StagedSet::Writer(writer, start) => self
                .writers
                .get(writer)
                .is_some_and(|sets| sets.contains_key(start)),
            StagedSet::Group(key) => self.groups.contains_key(key),
        }
    }

    /// `set` recorded as rejected (kept if it was already); whether it is
    /// new.
    fn insert(&mut self, set: StagedSet) -> bool {
        match set {
            StagedSet::Writer(writer, start) => {
                let sets = self.writers.entry(writer).or_default();
                if sets.contains_key(&start) {
                    return false;
                }
                sets.insert(start, RejectedSet::default());
                while sets.len() > MAX_DISCARDED_SETS {
                    sets.pop_first();
                }
                true
            }
            StagedSet::Group(key) => {
                if self.groups.contains_key(&key) {
                    return false;
                }
                self.groups.insert(key, RejectedSet::default());
                self.group_order.push_back(key);
                while self.group_order.len() > MAX_DISCARDED_GROUP_SETS {
                    if let Some(oldest) = self.group_order.pop_front() {
                        self.groups.remove(&oldest);
                    }
                }
                true
            }
        }
    }
}

use super::staging_budget::{Admission, StagedSet};

/// Why `ReaderSubscriber::prepare_staged` stages no member.
enum NotStaged {
    /// No storage for it now (the heap tier has no handle left, or it
    /// cannot be stored for the ring): refused unacknowledged, with its
    /// instance.
    NoStorage(Option<InstanceHandle>),
    /// The reader's budget has no room for it now (`staging_budget`):
    /// refused unacknowledged, with its instance.
    NoRoom(Option<InstanceHandle>),
    /// Its set is rejected whole (`staging_budget`).
    Rejected,
}

/// A duplicate of provisional coherent DATA must not acknowledge storage
/// that the first arrival has not acquired yet.
struct CoherentAdmission<'a> {
    pending: &'a Mutex<HashSet<([u8; 16], u64)>>,
    key: ([u8; 16], u64),
}

impl Drop for CoherentAdmission<'_> {
    fn drop(&mut self) {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

/// Where `ReaderSubscriber::store` puts a sample: the slab pool's tiers as
/// a claim says, or apart from them for a coherent set staged
/// (`SlabPool::reserve_staged`, charged to the reader's staging budget).
#[derive(Clone, Copy)]
enum StoreAs {
    Pool(rt::Claim),
    Staged,
}

/// How many of `staged` are samples (not a dispose or unregister of their
/// set).
fn staged_samples(staged: &[BufferedCoherentSample]) -> u64 {
    u64::try_from(staged.iter().filter(|m| m.lifecycle.is_none()).count()).unwrap_or(u64::MAX)
}

impl BufferedCoherentSample {
    /// What the set delivers of it, given its place in the history.
    fn into_payload(self, slot: Option<super::admission::HistorySlot>) -> PendingPayload {
        let mut payload = match self.lifecycle {
            Some((key, kind)) => {
                PendingPayload::lifecycle(self.remote_seq, key, kind, self.source_ts_ns)
            }
            None => PendingPayload {
                order: self.order,
                order_token: None,
                version: self.version,
                remote_seq: self.remote_seq,
                // Captured at STAGING time (`source_ts_ns`'s own doc):
                // the one point this sample's datagram was the one being
                // routed.
                source_ts_ns: self.source_ts_ns,
                slot,
                prepared: self.prepared,
                staged: None,
            },
        };
        payload.order = self.order;
        payload.order_token = self.order_token;
        // Charged until it leaves the gate (`staging_budget`).
        payload.staged = self.charge;
        payload
    }
}

/// Composite key for the GROUP-scope coherent aggregation buffer:
/// `(participant_prefix, publisher_entity_id, group_sn)`. Lifted to a
/// `type` alias to keep clippy's `type_complexity` lint happy while
/// preserving the readability of the docstring on the buffer field.
pub(super) type GroupSetKey = ([u8; 12], [u8; 4], u64);

/// Per-(publisher, group_sn) atomic-delivery state for GROUP-scope
/// coherent_access (DDS v1.4 sec. 2.2.3.6 + RTPS v2.5 sec. 8.7.5).
///
/// Aggregates samples from every writer in the same Publisher that
/// tagged its DATA with `PID_GROUP_COHERENT_SET = gsn` and tracks which
/// of those writers have already announced the close of the set via an
/// ECS DATA submessage carrying the same GSN. The set becomes
/// deliverable when every writer with buffered samples has been
/// observed in `closers` (i.e. has sent its ECS), at which point all
/// staged samples whose `remote_seq <= writer_ceiling[writer]` are
/// flushed atomically and the entry is removed. Samples whose
/// `remote_seq` is past the closing writer's `coherent_sn` are
/// publisher-protocol violations and are dropped with a warn log:
/// flushing them with the just-closed set would breach the writer-
/// scoped ECS boundary (RTPS v2.5 sec. 8.7.5).
///
/// `closers` may temporarily contain a writer whose samples have not
/// yet arrived (UDP delivery reorder between samples and the ECS that
/// bounds them); the completion check tolerates this by re-evaluating
/// `per_writer.keys() subseteq closers` on every insertion. A writer
/// that contributes samples but never closes (e.g. dropped mid-set)
/// pins the set until `forget_writer` evicts it.
#[derive(Debug, Default)]
pub(super) struct GroupCoherentSet {
    /// Per-writer staged samples for this (publisher_prefix, group_sn).
    per_writer: HashMap<[u8; 16], Vec<BufferedCoherentSample>>,
    /// Writers with GROUP metadata or a DATA admission reservation. A
    /// sample's announced SN range distinguishes a part that the reliable
    /// gate passed without storing it from an idle writer's END-only part.
    /// Both bounds are fixed-size even when repeated DATA is refused.
    announcers: HashMap<[u8; 16], Option<(u64, u64)>>,
    /// Writers that have sent an ECS DATA closing this group_sn.
    closers: HashSet<[u8; 16]>,
    /// Per-writer writer-scoped coherent_sn ceiling, set when the
    /// writer's ECS arrives. At flush time each writer's samples are
    /// partitioned by this ceiling; samples with `remote_seq` past
    /// the ceiling are dropped (publisher protocol violation: the
    /// ECS announced the set ended at `coherent_sn`).
    writer_ceilings: HashMap<[u8; 16], u64>,
    /// Per-writer expected sample count for this set, recorded when the
    /// writer closed via an explicit end marker carrying
    /// `PID_END_COHERENT_SET_SAMPLE_COUNT` (0x8024). A writer with an
    /// expected count is only "complete" once that many samples are
    /// staged, so an END that overtook some of its own DATA on the wire
    /// (UDP reorder) defers the atomic flush until the stragglers land
    /// (all-or-nothing per DDS v1.4 Sec.2.2.3.6). Never populated by the
    /// HDDS-native ECS close path, whose completion model is unchanged.
    writer_expected: HashMap<[u8; 16], u32>,
    /// The set's writer set, when its writers speak the spec GROUP dialect:
    /// the GroupDigest_t of `PID_WRITER_GROUP_INFO` on its changes (RTPS
    /// v2.5 Sec.8.7.6, D5). `None`: a set of any other dialect, decided by
    /// the rule above.
    writer_set: Option<[u8; 4]>,
    /// Two changes of the set named different writer sets: a writer joined
    /// or left the Publisher inside the set (refused at its API, D11), so
    /// the set is never whole.
    writer_set_changed: bool,
    /// The writers of the set this reader must hear the end of the set
    /// from: the Publisher's writers on its topic (and not refused by it),
    /// taken from discovery once the Publisher's writers it knows are the
    /// writer set (their digest equals `writer_set`). `None` until then.
    required: Option<Vec<[u8; 16]>>,
    /// The roster's generation `required` was decided at
    /// (`GroupRoster::generation`).
    required_generation: u64,
    /// The Publisher's writers when `required` was decided, all of them,
    /// matched here or not: the writer set (their digest is `writer_set`).
    /// Decided again, `required` is the ones of them matched then: a writer
    /// shut out at the first decision (refused, not admitted) and matched
    /// since is waited for, one the Publisher gained since never is.
    roster: Vec<[u8; 4]>,
    /// Since when discovery's writers of the Publisher are not the set's
    /// writer set: past `ReaderSubscriber::group_roster_wait_ms`, the set is
    /// discarded (D7).
    roster_wait_since: Option<std::time::Instant>,
    /// For a set of the spec dialect, the first SN of each writer's part,
    /// from its end (`PID_COHERENT_SET`, Table 9.23): a part none of whose
    /// samples landed is known all the same, and one whose samples are
    /// GAPped as lost is never whole.
    part_first: HashMap<[u8; 16], u64>,
    /// The set's end GSN (RTPS v2.5 Sec.8.7.6: every writer's end of the
    /// set carries one, the set's last GSN plus one, D2), once an end
    /// carrying PID_GROUP_SEQ_NUM landed.
    ecs_gsn: Option<u64>,
    /// Greatest GSN of any member received, to validate the end GSN.
    /// A summary keeps metadata bounded even when DATA staging is refused.
    max_member_gsn: Option<u64>,
    /// The set's GSNs contradict the spec (two ends naming two end GSNs,
    /// a member outside [set's first GSN, end GSN), a writer's GSNs not
    /// increasing with its SNs): never whole.
    gsn_broken: bool,
}

/// What the reader knows of one remote writer's GSNs (RTPS v2.5
/// Sec.8.7.5): the checks of a GROUP set of the spec dialect.
#[derive(Debug, Default)]
pub(super) struct WriterGsns {
    /// The GSNs of its changes received, by SN (the newest
    /// `MAX_WRITER_GSNS`).
    by_sn: BTreeMap<u64, u64>,
    /// Its last HEARTBEAT's GroupInfo: [currentGSN, firstGSN, lastGSN].
    heartbeat: Option<[u64; 3]>,
}

/// How many GSNs of one writer's changes a reader remembers.
const MAX_WRITER_GSNS: usize = 512;

/// Whether a writer announced in its HEARTBEAT that it does not have the
/// change of GSN `gsn` (RTPS v2.5 Sec.8.7.5: "announced it does not have
/// the GSN-1 by sending a Heartbeat with Heartbeat.currentGSN.value >= GSN
/// and GSN-1 not in [firstGSN, lastGSN]", here for `gsn` itself):
/// `currentGSN >= gsn + 1` and `gsn` outside [firstGSN, lastGSN]. Such a
/// change never comes to this reader, repairs included.
pub(super) fn gsn_announced_absent(gsn: u64, heartbeat: [u64; 3]) -> bool {
    let [current, first, last] = heartbeat;
    current > gsn && !(first <= gsn && gsn <= last)
}

/// What discovery knows of a remote Publisher's writers (RTPS v2.5
/// Sec.8.7.5), consulted to decide a GROUP set of the spec dialect: the
/// writers its ends must come from.
pub(crate) trait GroupRoster: Send + Sync {
    /// The writers of Publisher `publisher` of participant `prefix`, by
    /// EntityId, each with whether the reader of `topic` is matched with
    /// it (it writes the topic, with a compatible QoS).
    fn writers_of(
        &self,
        prefix: &[u8; 12],
        publisher: [u8; 4],
        topic: &str,
    ) -> Vec<([u8; 4], bool)>;

    /// Optional global departure witness for a writer of a validated Publisher.
    /// A local unmatch or an unknown endpoint never supplies positive deletion.
    fn terminal_writer(
        &self,
        _writer: &[u8; 16],
        _publisher: [u8; 4],
    ) -> Option<Arc<crate::engine::demux::GroupWriterTerminal>> {
        None
    }

    /// An atomic provider snapshot, independent of whether discovery has
    /// validated the DATA's writer-set digest yet. Empty is not proof.
    fn terminal_writers(
        &self,
        _publisher: [u8; 16],
    ) -> Option<Vec<([u8; 4], Arc<crate::engine::demux::GroupWriterTerminal>)>> {
        None
    }

    /// The writer-set digest (the 4 octets a set's PID_WRITER_GROUP_INFO
    /// carries) of `writers` of the Publisher of participant `prefix`, in the
    /// form that participant's vendor writes. The RTPS v2.5 `group_digest`
    /// unless discovery knows the vendor writes another (Dust DDS:
    /// `group_digest_dust`).
    fn writer_set_digest(&self, _prefix: &[u8; 12], writers: &[[u8; 4]]) -> [u8; 4] {
        crate::protocol::group::group_digest(writers.iter().copied())
    }

    /// Whether `writers_of` can tell which writers the reader is matched
    /// with yet. Until then, no set is decided against it.
    fn ready(&self) -> bool {
        true
    }

    /// Moves when what `writers_of` answers may have changed (an endpoint
    /// discovered, updated or removed): a set decided against an older
    /// answer is decided again.
    fn generation(&self) -> u64 {
        0
    }
}

/// Tests only: `ReaderSubscriber::pushed_hook`.
#[cfg(test)]
pub(super) type PushedHook = Arc<dyn Fn(u64) + Send + Sync>;

/// Discovery's last answer for each remote Publisher, by participant prefix
/// and Publisher EntityId (`ReaderSubscriber::roster_seen`).
pub(super) type RosterSeen = HashMap<([u8; 12], [u8; 4]), Vec<([u8; 4], bool)>>;

/// Discovery's writers of a remote Publisher, as one reader sees them: a
/// writer counts as matched with the reader when the match registry's
/// pairing verdict pairs the two (`MatchNotificationRegistry::pairs_with`:
/// QoS, DataRepresentation, OWNERSHIP kind, type), the verdict that makes
/// the writer send the reader its changes. A writer of the Publisher the
/// reader cannot match sends it nothing, its end of set either: waited
/// for, it parked every set. Before the reader's entry is registered, it is
/// not ready: a set decided then required a writer the reader may never
/// pair with, for good.
pub(crate) struct DiscoveryRoster {
    pub(crate) fsm: Arc<crate::core::discovery::multicast::DiscoveryFsm>,
    pub(crate) registry: Arc<crate::dds::match_notification::MatchNotificationRegistry>,
    /// The reader's entry in `registry`.
    pub(crate) entry: Arc<std::sync::OnceLock<u64>>,
}

impl GroupRoster for DiscoveryRoster {
    fn writer_set_digest(&self, prefix: &[u8; 12], writers: &[[u8; 4]]) -> [u8; 4] {
        match self.fsm.group_dialect_known(prefix) {
            Some(crate::protocol::group::GroupDialect::SpecReceive) => {
                crate::protocol::group::group_digest_dust(writers.iter().copied())
            }
            _ => crate::protocol::group::group_digest(writers.iter().copied()),
        }
    }

    fn writers_of(
        &self,
        prefix: &[u8; 12],
        publisher: [u8; 4],
        topic: &str,
    ) -> Vec<([u8; 4], bool)> {
        let matched: HashSet<[u8; 4]> = self
            .fsm
            .find_writers_for_topic(topic)
            .iter()
            .filter(|w| {
                w.endpoint_guid.prefix == *prefix
                    && w.group_entity_id == Some(publisher)
                    && self
                        .entry
                        .get()
                        .is_none_or(|&entry| self.registry.pairs_with(entry, w))
            })
            .map(|w| w.endpoint_guid.entity_id)
            .collect();
        self.fsm
            .publisher_roster(prefix, publisher)
            .into_iter()
            .map(|writer| (writer, matched.contains(&writer)))
            .collect()
    }

    fn ready(&self) -> bool {
        self.entry.get().is_some()
    }

    fn generation(&self) -> u64 {
        self.fsm.topic_registry_generation()
    }
}

/// How long a GROUP set of the spec dialect waits for discovery to know
/// every writer of its writer set before it is discarded (D7). SEDP lags
/// the data by a round trip or a few resends; a writer set that stays
/// unknown that long names a writer this participant does not discover.
pub(super) const GROUP_ROSTER_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a best-effort coherent set waits for a member its end
/// overtook before it is lost (`ReaderSubscriber::best_effort_wait_over`).
/// A writer's members to a co-located reader take its shared-memory ring
/// and its end of set takes UDP: the end overtakes a member by the time the
/// ring takes to be drained, the shared-memory poller's idle sleep (100 us)
/// and the router's queue, microseconds to a few milliseconds with the
/// scheduler's jitter on a loaded host. Fifty milliseconds covers that many
/// times over, and is the longest a best-effort set whose member was truly
/// lost, its writer going quiet after it, waits to be reported lost. Any
/// later change of the writer decides it at once.
pub(super) const BEST_EFFORT_OVERTAKE_WAIT: std::time::Duration =
    std::time::Duration::from_millis(50);

impl GroupCoherentSet {
    /// Tests only: the writers the set waits for, once decided.
    #[cfg(test)]
    pub(super) fn required_for_test(&self) -> Option<Vec<[u8; 16]>> {
        self.required.clone()
    }

    /// Returns true when every writer with buffered samples has sent
    /// its ECS. An empty `per_writer` paired with non-empty `closers`
    /// also returns true (the writers that closed contributed zero
    /// samples) so the entry can be GC'd; the flush is then a no-op.
    ///
    /// Writers that closed via an explicit end marker with a sample
    /// count (`writer_expected`) must additionally have that many
    /// samples staged: an END that overtook its own DATA on the wire
    /// must not fire a partial atomic flush (DDS v1.4 Sec.2.2.3.6). The
    /// map is empty on the HDDS-native ECS path, keeping its completion
    /// rule byte-identical.
    fn is_complete(&self) -> bool {
        self.per_writer.keys().all(|w| self.closers.contains(w))
            && self.writer_expected.iter().all(|(w, &expected)| {
                self.per_writer.get(w).map_or(0, Vec::len) >= expected as usize
            })
    }

    /// Number of samples currently buffered across all writers.
    pub(super) fn total_samples(&self) -> usize {
        self.per_writer.values().map(Vec::len).sum()
    }

    /// Whether a writer has samples or control metadata in the set.
    pub(super) fn has_part_of(&self, writer: &[u8; 16]) -> bool {
        self.per_writer.contains_key(writer)
            || self.closers.contains(writer)
            || self.announcers.contains_key(writer)
    }
}

/// Configuration captured from the reader's QoS at subscriber
/// construction time so the data path can decide whether to buffer
/// per coherent set or to deliver immediately. Held by-value (the
/// QoS values are immutable for the life of the reader; DDS spec
/// 2.2.3.6 Presentation policy is non-runtime-changeable).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct CoherentConfig {
    /// Whether the reader's Presentation QoS enables coherent_access.
    /// When false the data path bypasses the buffer entirely and the
    /// per-sample coherent-set tags are ignored.
    pub coherent_access: bool,
    /// Whether the reader's Presentation QoS access_scope is GROUP.
    /// When true we wait for the ECS marker carrying
    /// `PID_GROUP_COHERENT_SET` before flushing; when false (TOPIC or
    /// INSTANCE) we flush as soon as we see ECS with `PID_COHERENT_SET`
    /// from the originating writer.
    pub is_group_scope: bool,
}

/// Merge two lifecycle transitions for the SAME instance.
///
/// Disposed and Unregistered are different facts and an instance can be both;
/// keeping only the later one would drop information the application needs to
/// tell "the writer said this instance is gone" from "no writer is left".
fn merge_dispose_kind(a: DisposeKind, b: DisposeKind) -> DisposeKind {
    match (a, b) {
        (DisposeKind::DisposedUnregistered, _) | (_, DisposeKind::DisposedUnregistered) => {
            DisposeKind::DisposedUnregistered
        }
        (DisposeKind::Disposed, DisposeKind::Unregistered)
        | (DisposeKind::Unregistered, DisposeKind::Disposed) => DisposeKind::DisposedUnregistered,
        (kind, _) => kind,
    }
}

/// A dispose/unregister lifecycle event received from the network.
///
/// Stored by ReaderSubscriber and drained by DataReader to surface
/// instance state changes to the application.
#[derive(Debug, Clone)]
pub(super) struct DisposeEvent {
    /// 16-byte key hash identifying the instance.
    pub key_hash: [u8; 16],
    /// Dispose, Unregister, or both.
    pub kind: DisposeKind,
    /// RTPS writer sequence number, as reported to the application.
    pub seq: u64,
    /// The DataWriter this transition came from, when it is known.
    ///
    /// Only two facts can place a transition among the samples around it:
    /// which writer emitted it, and where in that writer's sequence. Across
    /// two writers DDS promises no order at all, so a transition facing
    /// another writer's data is not held back by it.
    pub writer_guid: Option<[u8; 16]>,
    /// Where this transition sits in its writer's stream, for ORDERING only -
    /// never reported to the application, which keeps reading [`seq`].
    ///
    /// A transition read off the wire carries its own sequence number. One
    /// SYNTHESIZED because a writer disappeared has none: it happened after
    /// everything that writer ever sent, so it takes `u64::MAX` and can never
    /// jump ahead of that writer's last samples. The wire sentinel used to be
    /// `0`, i.e. "before everything", which is the exact opposite and would
    /// have reported an instance dead while its final samples were still
    /// queued.
    ///
    /// [`seq`]: DisposeEvent::seq
    pub order_seq: u64,
    /// Whether this transition has already been OFFERED to an accessor
    /// that could not express it (see [`DisposeQueue::announce`]).
    ///
    /// It separates "a wake-up is still owed for this transition" from
    /// "the transition is still owed to the application". Only the first
    /// keeps DATA_AVAILABLE raised; the second is settled by an accessor
    /// actually taking the event. Without the distinction the two are the
    /// same bit, and an accessor that cannot report the transition has
    /// only two moves, both wrong: leave it queued and spin for ever, or
    /// destroy it and lose it.
    pub announced: bool,
    /// Whether a `read` variant already returned this transition in place
    /// (DDS v1.4 Sec.2.2.2.5.1.2: its sample_state is READ from then on).
    /// A take is not a read: a transition taken unread leaves NOT_READ.
    pub read: bool,
    /// Queued from a LOCAL writer's lifecycle entry (the intra-process
    /// ring), not read off the wire. Such a transition and the local samples
    /// around it all carry no writer GUID; this says which GUID-less
    /// transition may be ordered against GUID-less samples by sequence number
    /// (`goes_before`). A network transition whose writer is unknown keeps
    /// going first, as before.
    pub from_local_writer: bool,
    /// The instance's `no_writers_generation_count` (DDS v1.4
    /// Sec.2.2.2.5.1.4) AT THE TIME this transition was queued, stamped by
    /// [`DisposeQueue::push`] - never read fresh from the instance table
    /// again, the same rule a data sample's copy of the count follows
    /// (`CachedSample::no_writers_generation_count`). Callers construct
    /// this as `0`; `push` overwrites it before the event is ever stored
    /// or handed back out.
    pub no_writers_generation_count: u32,
    /// DISPOSED-to-ALIVE transitions at this event's receipt.
    pub disposed_generation_count: u32,
    /// The writer's source timestamp for this dispose/unregister (DDS v1.4
    /// Sec.2.2.2.4.2.13, Sec.2.2.2.4.2.8: `dispose_w_timestamp` /
    /// `unregister_instance_w_timestamp`), carried to the `SampleInfo` of
    /// the NOT_ALIVE change it reports (Sec.2.2.2.5.5). NOT currently read
    /// for DESTINATION_ORDER BY_SOURCE_TIMESTAMP ordering: admission
    /// still orders across writers by reception, not by this field --
    /// reporting it correctly is a narrower fix than implementing that
    /// ordering. `None` for a transition this reader never received off
    /// the wire or its own local ring at all -- one synthesized from a
    /// writer's departure (`on_writer_dispose`), which carries no
    /// timestamp of its own: reception time is all that
    /// is known then, exactly what `SampleInfo::source_timestamp_ns`
    /// reports as absent.
    pub source_timestamp_ns: Option<u64>,
}

/// Dispose/unregister events waiting for `DataReader::get_dispose_events`,
/// and the producer of the reader's dispose wake word
/// (`WakeWord::Dispose` on the reader's `StatusCondition`).
///
/// The dispose path is the one producer of DATA_AVAILABLE that pushes
/// nowhere the reader's ring walk can see: `on_dispose` queues here, and
/// the queue raises the word. The reader clears each word after
/// observing every source empty and re-raises a word whose producer
/// stored before the clear (`DataReader::clear_data_available_if_idle`);
/// for the rings it re-checks their heads, for this word the re-check is
/// the word's own previous value. Walking the `Vec` under its mutex on
/// that path would put a lock acquisition on every clear.
///
/// RAISED on the word means "a dispose was queued and no wake-up has
/// covered it yet", not "the queue is non-empty". The distinction
/// matters: the reader re-raises DATA_AVAILABLE on an owed wake, and a
/// level-triggered "non-empty" bit would keep re-raising on every empty
/// take until the application drains the queue. A wait/take loop that
/// never calls `get_dispose_events` (the rmw layer is one) would then
/// spin as soon as a matched writer left, because `on_writer_dispose`
/// fans one event out per instance that writer ever delivered. The
/// reader's re-raise writes a different bit (RERAISED), which the next
/// clear reads as "delivered", so an undrained dispose costs exactly one
/// extra wake-up, the same wake-up the raise would have delivered had it
/// not been cleared.
///
/// Every write to the word is paired with the state it stands for:
/// - `push` stores RAISED under the lock, Release, sequenced after the
///   event is queued; the reader's clear (an AcqRel swap) that reads it
///   synchronizes-with it (`WakeWords` has the argument);
/// - `drain` stores zero under the lock, in the same critical section
///   that empties the `Vec`, so a push that follows the drain in lock
///   order stores RAISED again after the zero, and one that preceded it
///   had its event taken. Both stores are inside the critical section
///   because the word must agree with the queue at every lock release:
///   a zero written after the lock is dropped could land over the
///   RAISED of a push that slipped in between and strand that event's
///   wake-up.
///
/// The word's non-zero writes are all made under this mutex, which is
/// the "single producer" the per-word argument needs: they are ordered
/// among themselves by happens-before even when several threads call
/// `on_dispose`.
///
/// Two threads clearing the same reader at once must not erase an
/// undrained dispose's wake-up. `DataReader` is `Sync`, and
/// on a topology where two threads may drain it (K>1 local bindings, or
/// a network ring with no local producer) both can run
/// `clear_data_available_if_idle` concurrently. The interleaving, one
/// push and no drain:
///
/// 1. `push` queues the event and stores RAISED; the WaitSet is
///    signalled.
/// 2. Clearer C1 swaps the word (reads RAISED), so a wake-up is owed,
///    and re-raises: the word is RERAISED and the WaitSet is signalled
///    again.
/// 3. Clearer C2 swaps the word (reads RERAISED) before any waiter
///    observed the trigger. RERAISED alone was read as "that wake-up was
///    delivered", so C2 did not re-raise; the word went to zero.
/// 4. The waiter consumed the coalesced driver notification, read the
///    trigger false (`WaitSet::wait` keeps only the candidates whose
///    `get_trigger_value` is true), and slept with the event still
///    queued. The application was never told, with no error and no log.
///
/// Re-raising a bounded number of times per push only lengthens the
/// fuse: N clearers erase N re-raises. What closes it is the treatment
/// the ring words already get - re-raise on ANY non-zero previous value
/// and let the queue, not the clearer's bookkeeping, say whether
/// anything is still owed. Only `drain` settles the word, under this
/// queue's own lock.
///
/// The objection to that was the spin: an application that waits and
/// never drains is then woken for as long as it ignores the queue. That
/// is not a defect introduced by the fix. DDS statuses are
/// level-triggered, and a status that stays true until the application
/// reads it is the specified behaviour; the previous shape was the
/// deviation. The one in-house consumer that could never drain is the
/// rmw layer, because ROS 2 has no dispose-event API, and it now drains
/// in its wait cycle (`rmw::waitset`) - which also fixes a queue that
/// grew for the lifetime of every ROS 2 reader.
///
/// The sample path was never affected: a ring word re-raised by C1 is
/// re-checked by C2 against the rings and the cache themselves, not
/// against C1's bookkeeping. The DDS-conformant end state has that same
/// shape: deliver instance-state changes as NOT_ALIVE_DISPOSED samples
/// through the cache, so the cache check covers them and this word goes
/// away entirely. That remains an open item.
pub(super) struct DisposeQueue {
    events: Mutex<Vec<DisposeEvent>>,
    /// `events.len()`, readable WITHOUT taking the mutex.
    ///
    /// Every empty take reaches the idle clear, and every idle clear asks
    /// this queue a question. With the answer behind the mutex, a polling
    /// reader - the shape that polls precisely because it has nothing to do -
    /// paid a lock acquisition per empty poll for a queue that is empty
    /// essentially always. Relaxed is the right strength: a stale zero means
    /// one poll skips work it did not owe, and the push that raced it raises
    /// the wake word itself, which is what actually carries the obligation.
    pending: AtomicUsize,
    /// The reader's condition; this queue is the producer of its
    /// dispose wake word.
    status_condition: Arc<StatusCondition>,
    /// The reader's instance table, shared with its cache: every
    /// transition queued here first records the instance's new state
    /// there (DDS v1.4 Sec.2.2.2.5.1.3), so the retained data samples of
    /// the instance report it.
    instances: Arc<InstanceTable>,
    /// This reader's DEADLINE watches (DDS v1.4 Sec.2.2.3.7): `None`
    /// with an infinite deadline. An instance that leaves ALIVE here
    /// (disposed, or NOT_ALIVE_NO_WRITERS) is not one a publication
    /// contract can still be missed on -- see
    /// `crate::dds::liveliness::deadline` module doc.
    deadlines: Option<Arc<crate::dds::liveliness::ReaderDeadlines>>,
    /// The reader's writer registrations, for a BY_SOURCE_TIMESTAMP reader
    /// only (`revalidate_presence_with`): an unregister's "no writer holds
    /// the instance" is asked again under the instance lock.
    registrations: std::sync::OnceLock<Arc<super::registrations::ReaderRegistrations>>,
}

impl DisposeQueue {
    /// A queue with its own instance table (standalone subscribers in
    /// tests); the builder uses [`with_instances`](Self::with_instances).
    #[cfg(test)]
    pub(super) fn new(status_condition: Arc<StatusCondition>) -> Self {
        Self::with_instances(status_condition, Arc::new(InstanceTable::new()), None)
    }

    pub(super) fn with_instances(
        status_condition: Arc<StatusCondition>,
        instances: Arc<InstanceTable>,
        deadlines: Option<Arc<crate::dds::liveliness::ReaderDeadlines>>,
    ) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            pending: AtomicUsize::new(0),
            status_condition,
            instances,
            deadlines,
            registrations: std::sync::OnceLock::new(),
        }
    }

    /// Producer side: queue the event, raise the dispose wake word in
    /// the same critical section, then signal the WaitSets once the lock
    /// is released (the signal takes the condition's hook mutex and must
    /// not nest under this one).
    pub(super) fn push(&self, event: DisposeEvent) {
        self.push_ordered(event, false);
    }

    fn push_ordered(&self, mut event: DisposeEvent, compound: bool) {
        let handle = InstanceHandle::new(event.key_hash);
        // The instance state first, outside the events lock (the table has
        // its own): a data sample pumped after this sees the new state.
        // DDS v1.4 Sec.2.2.2.5.1.4: the count AT RECEIPT of this
        // transition, read under the lock that applies it - a transition
        // never moves the count, but a concurrent sample's revival would.
        let (changed, (disposed_generation_count, no_writers_generation_count)) =
            if self.instances.by_source_timestamp() {
                match self.admit_by_source(handle, &event, compound) {
                    Some(applied) => applied,
                    None => return,
                }
            } else {
                self.instances.mark_not_alive_stamped(
                    handle,
                    transition_state(event.kind),
                    (event.writer_guid, event.order_seq),
                )
            };
        event.no_writers_generation_count = no_writers_generation_count;
        event.disposed_generation_count = disposed_generation_count;
        // Disposal ends instance existence (DDS v1.4 Sec.2.2.3.23.3).
        // NO_WRITERS retains the deadline: periodic data uses DEADLINE
        // to report lost connectivity (Sec.2.2.3.23.2).
        if changed && transition_state(event.kind) == super::InstanceState::NotAliveDisposed {
            if let Some(deadlines) = self.deadlines.as_ref() {
                deadlines.remove_instance(handle);
            }
        }
        {
            let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
            // A transition that changed nothing (its writers leaving an
            // instance already disposed, `InstanceTable::mark_not_alive`)
            // owes the application no notification of its own; one still
            // queued for the instance absorbs it below.
            if !changed && !events.iter().any(|e| e.key_hash == event.key_hash) {
                return;
            }
            // AT MOST ONE notification per instance, whose state reflects
            // disposed, unregistered, or both. This is not an optimisation: a
            // single reserved invalid sample per instance is the model HDDS
            // follows, and a queue that grew one entry per event would make an
            // instance's notifications compete with each other and with its
            // data for the application's attention.
            if let Some(existing) = events.iter_mut().find(|e| e.key_hash == event.key_hash) {
                existing.kind = merge_dispose_kind(existing.kind, event.kind);
                existing.seq = existing.seq.max(event.seq);
                // Keep the ordering position, the writer it belongs to,
                // and its source timestamp together: adopting a later
                // position without its writer (or its timestamp) would
                // report an earlier change's instant for a later one
                // (DDS v1.4 Sec.2.2.2.5.5), which means nothing.
                //
                // `order_seq` only orders within ONE writer's own stream;
                // two different writers' sequence numbers are independent
                // (the `writer_guid` doc above: "DDS promises no order at
                // all" across them), so comparing them directly picked
                // whichever writer happened to have the larger raw number,
                // not whichever transition is actually newer. The
                // comparison is trustworthy only when BOTH events name the
                // SAME known writer: a `None` (every local writer's
                // lifecycle entry, `from_local_writer`'s own doc) proves
                // nothing about identity, so two `None`s are not known to
                // share a stream either. Whenever either side's writer is
                // unknown, or the two are simply different, this `push`
                // call is received strictly after whatever queued
                // `existing`, so arrival order is what is left to go by.
                let adopt = match (existing.writer_guid, event.writer_guid) {
                    (Some(a), Some(b)) if a == b => event.order_seq >= existing.order_seq,
                    _ => true,
                };
                if adopt {
                    existing.order_seq = event.order_seq;
                    existing.writer_guid = event.writer_guid;
                    existing.source_timestamp_ns = event.source_timestamp_ns;
                }
                existing.no_writers_generation_count = event.no_writers_generation_count;
                existing.disposed_generation_count = event.disposed_generation_count;
                // A further transition is NEW information, so it owes its own
                // wake-up even if the instance's previous one was already
                // announced. Re-arming here is what keeps the raise below
                // honest: the word is raised unconditionally, so leaving this
                // event marked announced would raise a word that
                // `has_unannounced` immediately contradicts.
                existing.announced = false;
            } else {
                events.push(event);
            }
            self.pending.store(events.len(), Ordering::Relaxed);
            self.status_condition
                .wake_words()
                .raise(WakeWord::Dispose.index());
        }
        self.status_condition.signal_data_available();
    }

    /// BY_SOURCE_TIMESTAMP admission of a transition (DDS v1.4
    /// Sec.2.2.3.17) through the watermark the reader's data admission
    /// moves (`instances` is the table this queue shares with the cache),
    /// fused with the not-alive transition into one lock acquisition
    /// (`InstanceTable::accept_and_mark_not_alive`). A transition with no
    /// source timestamp of its own (a synthesized "every writer departed",
    /// a network one received without INFO_TS) is not ordered.
    ///
    /// An unregister reaches here only when its caller found no ALIVE
    /// writer holding the instance (`WriterRegistrations::admit_lifecycle`'s
    /// `moves`, the LIVELINESS and departure paths): NOT_ALIVE_NO_WRITERS
    /// is writer PRESENCE (Sec.2.2.2.5.1.3), so it applies even when its
    /// key loses the ordering, without moving the watermark. That presence
    /// fact is asked again under the instance lock (`registrations`), so
    /// a writer that registered the instance in between keeps it ALIVE
    /// whichever of the two takes the lock first.
    fn admit_by_source(
        &self,
        handle: InstanceHandle,
        event: &DisposeEvent,
        compound: bool,
    ) -> Option<(bool, (u32, u32))> {
        let key = event
            .source_timestamp_ns
            .map(|ts| super::cache::SourceOrderKey(ts, event.writer_guid, event.order_seq));
        let force = event.kind == DisposeKind::Unregistered;
        let held = self.registrations.get().map(|registrations| {
            let key_hash = event.key_hash;
            move || registrations.is_held_alive(&key_hash)
        });
        if !compound {
            return self.instances.accept_and_mark_not_alive(
                handle,
                key,
                transition_state(event.kind),
                (event.writer_guid, event.order_seq),
                force,
                held.as_ref().map(|held| held as &dyn Fn() -> bool),
            );
        }
        self.instances.accept_and_mark_not_alive_ordered(
            handle,
            key,
            transition_state(event.kind),
            (event.writer_guid, event.order_seq),
            force,
            held.as_ref().map(|held| held as &dyn Fn() -> bool),
            compound,
        )
    }

    /// Re-check writer presence through `registrations` when this queue
    /// applies an unregister of a BY_SOURCE_TIMESTAMP reader
    /// (`admit_by_source`). Set once, by the builder; the first call wins.
    pub(super) fn revalidate_presence_with(
        &self,
        registrations: Arc<super::registrations::ReaderRegistrations>,
    ) {
        let _ = self.registrations.set(registrations);
    }

    /// Consumer side for the sample path: take ONE notification, oldest first,
    /// and settle the wake word when that was the last one.
    ///
    /// `take()` and `take_with_info()` come through here, which is what lets an
    /// ordinary wait/take loop settle the condition this queue raises. Before
    /// that existed, the only consumer was `get_dispose_events()`, so an
    /// application that did not call it - every C binding, every ROS 2 node -
    /// spun at 100% CPU for as long as one notification sat here.
    pub(super) fn pop_one(&self) -> Option<DisposeEvent> {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if events.is_empty() {
            return None;
        }
        let event = events.remove(0);
        self.pending.store(events.len(), Ordering::Relaxed);
        if !events.iter().any(|e| !e.announced) {
            self.status_condition
                .wake_words()
                .settle(WakeWord::Dispose.index());
        }
        Some(event)
    }

    /// Take the oldest transition IF it belongs ahead of the sample the cache
    /// would hand out next.
    ///
    /// `front` is that sample's `(writer, sequence)`, or `None` when the cache
    /// is empty. The rule:
    ///
    /// - **Same writer**: the wire says which came first, so compare sequence
    ///   numbers. Strictly less, because a writer that carries the dispose
    ///   flag on the value sample itself (in the SAME DATA submessage) gives
    ///   both the SAME number and delivers the value first - `n < n` is false,
    ///   the value goes out, and the transition follows it. No special case.
    /// - **Different writers, or either unknown**: DDS orders samples per
    ///   writer and per instance, never across writers, so there is nothing to
    ///   wait for. The transition goes out now. Holding it instead is what
    ///   starved it: a topic fed by any other writer would withhold it for as
    ///   long as the traffic lasted.
    /// - **Empty cache**: nothing competes, it goes out.
    ///
    /// - **BY_SOURCE_TIMESTAMP** (DDS v1.4 Sec.2.2.3.17, Sec.2.2.2.5.3.8):
    ///   the instance's changes are ordered by source timestamp whatever
    ///   their writers, so the transition also waits while a sample of ITS
    ///   instance from any writer, older by source order, is still there
    ///   for the access (`by_source`, empty for a default reader). Only
    ///   what is buffered and eligible counts: a sample already taken,
    ///   read past or not matched holds nothing back.
    ///
    /// Peeking and popping in one critical section, rather than a peek
    /// followed by a pop, so a concurrent drain cannot make the decision and
    /// the removal disagree.
    pub(super) fn pop_if_before(
        &self,
        pending: &[Origin],
        by_source: &[super::cache::SourcePending],
    ) -> Option<DisposeEvent> {
        if self.pending.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let candidate = events.first()?;
        if !Self::goes_before(candidate, pending, by_source) {
            return None;
        }
        let event = events.remove(0);
        self.pending.store(events.len(), Ordering::Relaxed);
        if !events.iter().any(|e| !e.announced) {
            self.status_condition
                .wake_words()
                .settle(WakeWord::Dispose.index());
        }
        Some(event)
    }

    /// Is any transition queued at all? Read before the ordering work so the
    /// ordinary "no transition pending" take keeps its fused single-lock
    /// shape untouched.
    pub(super) fn is_empty(&self) -> bool {
        self.pending.load(Ordering::Relaxed) == 0
    }

    /// Consumer side for an accessor that OBSERVED the transitions but
    /// cannot express them: mark every queued event announced and settle the
    /// word, without removing anything.
    ///
    /// `DataReader::take()` returns `Option<T>` and has no field in which to
    /// report an instance state, so it is in exactly that position. It used
    /// to pop the events and drop them on the floor, which settled the word
    /// at the cost of destroying transitions another accessor was about to
    /// return - `examples/shape_main.rs` drains with `take()` and then reads
    /// `get_dispose_events()` on the next line, so the OMG conformance binary
    /// stopped reporting instance states altogether.
    ///
    /// Announcing instead settles the wake-up debt, which is what stops the
    /// spin, and leaves the transition itself owed to whoever can carry it.
    /// The application is woken once per transition rather than for ever, and
    /// nothing is lost. A later transition on the same instance re-arms the
    /// event (see [`DisposeQueue::push`]), so this is not a permanent mute.
    pub(super) fn announce(&self) {
        if self.pending.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        for event in events.iter_mut() {
            event.announced = true;
        }
        self.status_condition
            .wake_words()
            .settle(WakeWord::Dispose.index());
    }

    /// Is a WAKE-UP still owed for some queued transition?
    ///
    /// This is the question the idle clear asks, and it is deliberately NOT
    /// "is the queue non-empty": an announced event is still owed to the
    /// application but its wake-up has been delivered, so keeping the status
    /// raised for it would spin the very loop that announced it.
    pub(super) fn has_unannounced(&self) -> bool {
        if self.pending.load(Ordering::Relaxed) == 0 {
            return false;
        }
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|e| !e.announced)
    }

    /// True when a queued transition satisfies `pred` (the ReadCondition
    /// trigger: a transition is a sample the Service manages, DDS v1.4
    /// Sec.2.2.4.5). Read-only; announces nothing and settles nothing.
    pub(super) fn any_matching(&self, pred: impl FnMut(&DisposeEvent) -> bool) -> bool {
        if self.pending.load(Ordering::Relaxed) == 0 {
            return false;
        }
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(pred)
    }

    /// The ordering rule shared by every consumer that interleaves a
    /// transition with data (`pop_if_before` states it in full): same
    /// writer, or a local transition facing local data (no GUID on either
    /// side), the sequence numbers decide; different or unknown writers,
    /// nothing orders them and the transition goes first; no competing
    /// data, it goes first. The one statement of the rule: every
    /// `*_if_before` asks it.
    ///
    /// `pending` is, for each writer with samples still in the cache, its
    /// earliest sequence number there (`SampleCache::pending_origins`): the
    /// transition waits while ITS writer has a sample at or before it,
    /// wherever that sample sits behind other writers' samples.
    fn goes_before(
        candidate: &DisposeEvent,
        pending: &[Origin],
        by_source: &[super::cache::SourcePending],
    ) -> bool {
        Self::goes_before_its_writers_data(candidate, pending)
            && !Self::waits_for_older_source_data(candidate, by_source)
    }

    /// The BY_SOURCE_TIMESTAMP half of `goes_before`: an older sample of
    /// the transition's instance, by `(source timestamp, writer)`, is
    /// still pending. Two changes of one writer with one timestamp are
    /// not ordered here but by its sequence numbers, the other half.
    fn waits_for_older_source_data(
        candidate: &DisposeEvent,
        by_source: &[super::cache::SourcePending],
    ) -> bool {
        let Some(ts) = candidate.source_timestamp_ns else {
            return false;
        };
        let handle = InstanceHandle::new(candidate.key_hash);
        let order = (ts, candidate.writer_guid);
        by_source
            .iter()
            .any(|&(instance, oldest)| instance == handle && oldest < order)
    }

    /// The writer half of `goes_before` (`pop_if_before` states it).
    fn goes_before_its_writers_data(candidate: &DisposeEvent, pending: &[Origin]) -> bool {
        let writer = match candidate.writer_guid {
            Some(writer) => Some(writer),
            // A local writer's dispose or unregister and the local samples
            // it follows both come through the merger without a writer GUID.
            // Their sequence numbers still order them: a transition must not
            // overtake the data written before it. (Two local writers compare
            // too; DDS orders nothing across writers.) Only a transition
            // KNOWN to be local: a network one whose writer is unknown has
            // no sequence to compare.
            None if candidate.from_local_writer => None,
            None => return true,
        };
        !pending
            .iter()
            .any(|&(w, seq)| w == writer && seq <= candidate.order_seq)
    }

    /// Consumer side for `take_w_condition`: remove and return the oldest
    /// queued transition satisfying `pred` IF it belongs ahead of `front`,
    /// the origin of the data sample the take would otherwise return next
    /// (`goes_before`). Settles the word as `pop_one` does.
    pub(super) fn pop_first_matching_if_before(
        &self,
        pending: &[Origin],
        by_source: &[super::cache::SourcePending],
        mut pred: impl FnMut(&DisposeEvent) -> bool,
    ) -> Option<DisposeEvent> {
        if self.pending.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let pos = events.iter().position(&mut pred)?;
        if !Self::goes_before(&events[pos], pending, by_source) {
            return None;
        }
        let event = events.remove(pos);
        self.pending.store(events.len(), Ordering::Relaxed);
        if !events.iter().any(|e| !e.announced) {
            self.status_condition
                .wake_words()
                .settle(WakeWord::Dispose.index());
        }
        Some(event)
    }

    /// Consumer side for `read_w_condition`: the oldest queued transition
    /// at index `from` or later satisfying `pred`, IF it belongs ahead of
    /// `front` (`goes_before`), copied with the state before this read,
    /// marked READ in place, returned with the index the next search
    /// starts from.
    pub(super) fn read_first_matching_from_if_before(
        &self,
        from: usize,
        pending: &[Origin],
        by_source: &[super::cache::SourcePending],
        mut pred: impl FnMut(&DisposeEvent) -> bool,
    ) -> Option<(usize, DisposeEvent)> {
        if self.pending.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let pos = from + events.iter().skip(from).position(&mut pred)?;
        if !Self::goes_before(&events[pos], pending, by_source) {
            return None;
        }
        let copy = events[pos].clone();
        events[pos].read = true;
        Some((pos + 1, copy))
    }

    /// Consumer side: take every queued event. An empty queue owes no
    /// wake-up, so the word is settled in the same critical section.
    pub(super) fn drain(&self) -> Vec<DisposeEvent> {
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let drained = std::mem::take(&mut *events);
        self.pending.store(0, Ordering::Relaxed);
        self.status_condition
            .wake_words()
            .settle(WakeWord::Dispose.index());
        drained
    }
}

/// A matched writer's LIVELINESS changed (DDS v1.4 Sec.2.2.3.11,
/// Sec.2.2.3.23.2): tell `registrations`, and queue a transition for every
/// instance this leaves without an alive writer through `dispose_events` -
/// the same mechanism a writer's departure or an explicit unregister
/// already drives (`ReaderSubscriber::on_writer_departure`,
/// `ReaderRegistrations::on_orphaned`), not a second copy of it.
///
/// Called from the participant's liveliness scheduler thread
/// (`dds::liveliness::ReaderLiveliness::transition`): this only updates
/// `registrations` and queues what the application is told
/// (`DisposeQueue::push` raises the StatusCondition and signals the
/// attached WaitSets, never a listener directly), so it is safe there -
/// no user callback runs on this thread.
pub(super) fn on_writer_alive(
    registrations: &ReaderRegistrations,
    dispose_events: &DisposeQueue,
    writer_guid: [u8; 16],
    alive: bool,
) {
    for (key_hash, seq) in registrations.writer_alive(writer_guid, alive) {
        dispose_events.push(DisposeEvent {
            key_hash,
            kind: DisposeKind::Unregistered,
            seq: 0,
            writer_guid: Some(writer_guid),
            // Not `u64::MAX`: `writer_guid` is still matched and keeps
            // counting from where it was (unlike a departure, this writer
            // was never retired), so its own later, bounded sample must
            // still land "after" this transition - `seq` is the writerSN
            // it last held the instance with.
            order_seq: seq,
            announced: false,
            read: false,
            from_local_writer: false,
            disposed_generation_count: 0,
            no_writers_generation_count: 0, // overwritten by `push`
            source_timestamp_ns: None,      // synthesized (LIVELINESS lease expiry), not received
        });
    }
}

/// The lifespans of remote writers that left, for the samples of theirs
/// this reader still receives or holds.
///
/// LIFESPAN is the writer's QoS (DDS v1.4 Sec.2.2.3.16), and a sample is
/// judged by it when the application reads, which may be long after its
/// writer left. The participant's record of the writer
/// (`TopicRegistry::writer_lifespan`) goes with the writer, so each reader
/// keeps its own copy, made as it hears of the departure. The copy is kept
/// until the writer is announced again (`forget`, from
/// `on_writer_qos_resolved`): not until the ring was seen empty, because a
/// DATA the writer sent before its departure may still land after it - the
/// DATA on the router thread, the dispose on the control thread - and must
/// expire by the same lifespan as its siblings. A writer announced again
/// is judged by its new record.
///
/// At most `MAX_DEPARTED_LIFESPANS` copies, the oldest dropped first: a
/// datagram that late behind that many departures is not one in flight.
/// Only a writer that announced a finite lifespan is recorded: the take
/// path pays one relaxed load while nothing is.
pub(super) struct DepartedLifespans {
    /// Whether `records` holds anything.
    any: std::sync::atomic::AtomicBool,
    records: Mutex<DepartedRecords>,
}

/// Bound of [`DepartedLifespans`].
const MAX_DEPARTED_LIFESPANS: usize = 1024;

#[derive(Default)]
struct DepartedRecords {
    /// The stamp the next copy takes, its age for the bound.
    next: u64,
    /// Writer GUID -> (its lifespan in ns, the stamp of the copy).
    by_writer: HashMap<[u8; 16], (u64, u64)>,
}

impl DepartedLifespans {
    pub(super) fn new() -> Self {
        Self {
            any: std::sync::atomic::AtomicBool::new(false),
            records: Mutex::new(DepartedRecords::default()),
        }
    }

    fn records(&self) -> std::sync::MutexGuard<'_, DepartedRecords> {
        self.records.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `writer`, whose lifespan was `lifespan_ns`, left.
    pub(super) fn record(&self, writer: [u8; 16], lifespan_ns: u64) {
        let mut records = self.records();
        let stamp = records.next;
        records.next += 1;
        records.by_writer.insert(writer, (lifespan_ns, stamp));
        if records.by_writer.len() > MAX_DEPARTED_LIFESPANS {
            let oldest = records
                .by_writer
                .iter()
                .min_by_key(|(_, &(_, stamp))| stamp)
                .map(|(guid, _)| *guid);
            if let Some(oldest) = oldest {
                records.by_writer.remove(&oldest);
            }
        }
        self.any.store(true, Ordering::Release);
    }

    /// `writer` was announced again: its new record judges its samples.
    pub(super) fn forget(&self, writer: &[u8; 16]) {
        if !self.any.load(Ordering::Acquire) {
            return;
        }
        let mut records = self.records();
        records.by_writer.remove(writer);
        if records.by_writer.is_empty() {
            self.any.store(false, Ordering::Release);
        }
    }

    /// The lifespan of `writer` if it left and was not announced again.
    #[inline]
    pub(super) fn lifespan_of(&self, writer: &[u8; 16]) -> Option<u64> {
        if !self.any.load(Ordering::Acquire) {
            return None;
        }
        self.records()
            .by_writer
            .get(writer)
            .map(|&(lifespan_ns, _)| lifespan_ns)
    }
}

/// The sequences of one writer this reader has admitted, so that a second
/// copy of one of them is dropped instead of delivered twice.
///
/// Drops duplicates so a writer that resends the same seq (e.g. intra-process
/// loopback collision + UDP delivery, or a late transient retransmit that
/// already reached the reader) doesn't deliver a sample twice.
///
/// RTPS v2.5 sec. 8.3.5.4 says sequence numbers are *per DataWriter*, so callers
/// must scope this window to a single writer GUID -- otherwise a second
/// writer's legitimate `seq=N` would be dropped as a duplicate of the first
/// writer's `seq=N`. The writer-tagged data path keeps one `SeenSeqs` per
/// writer in a HashMap; the legacy (no-GUID) path keeps a single global
/// instance, accepting the multi-writer false-positive that pre-dates this
/// module.
///
/// Every sequence admitted in `(high - WINDOW, high]` is recorded exactly,
/// one bit each. A sequence that leaves that window without having been
/// admitted is not forgotten by a reliable reader: it is kept in `missed`,
/// because the writer still owes it (RTPS v2.5 Sec.8.4.12.2) and its repair
/// may come after any number of newer samples. Taking the repair for a
/// duplicate would lose it for good, since a duplicate is credited as
/// received. A missed run leaves the record when admitted, or once the
/// reader's writer proxy no longer awaits it (received, declared irrelevant
/// by a GAP, or no longer available per a HEARTBEAT); the proxy is asked
/// when a copy of it arrives, and when the record is full. The record
/// outlives the proxy: after a re-match the fresh proxy requests everything
/// again, and what was admitted before is still told apart from what never
/// came.
///
/// The record is bounded, and a bound never forgets: a sample it cannot
/// record without dropping what is owed is `Seen::Full`, refused
/// unacknowledged, and the writer sends it again once the gap below fills.
#[derive(Debug)]
struct SeenSeqs {
    /// Highest seq admitted so far; `None` before the first admission.
    high: Option<u64>,
    /// One bit per sequence of the window, at `seq % WINDOW`.
    bits: Box<[u64]>,
    /// Runs of sequences below the window never admitted, `start -> end`
    /// inclusive, disjoint and not adjacent.
    missed: std::collections::BTreeMap<u64, u64>,
    /// The sequences reported lost as never received.
    reported: LostReported,
}

impl Default for SeenSeqs {
    fn default() -> Self {
        Self {
            high: None,
            bits: vec![0; Self::WORDS].into_boxed_slice(),
            missed: std::collections::BTreeMap::new(),
            reported: LostReported::default(),
        }
    }
}

/// What a reader is owed of the sequences that leave its duplicate window
/// unadmitted (see `SeenSeqs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Missed {
    /// Nothing: a best-effort reader ignores what is older than what it
    /// expects (RTPS v2.5 Sec.8.4.12.1), and the writer-less path has no
    /// writer to be owed by.
    Dropped,
    /// Everything the writer still has. What a VOLATILE reader must not
    /// deliver (written before it joined) is its reorder gate's decision,
    /// taken where the gate's join point is known; the proxy settles it.
    All,
}

impl Missed {
    /// What a reader is owed: nothing unless it is `reliable`.
    fn owed(reliable: bool) -> Self {
        if reliable {
            Missed::All
        } else {
            Missed::Dropped
        }
    }
}

/// The duplicate record's answer about one sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Not admitted before: to be admitted.
    New,
    /// Admitted before, or no longer owed.
    Duplicate,
    /// Owed, but the record cannot take it without dropping what else is
    /// owed: to be refused unacknowledged.
    Full,
}

impl SeenSeqs {
    const WINDOW: u64 = 4096;
    /// 64-bit words holding the window's WINDOW bits.
    const WORDS: usize = 64;
    /// Runs of missed sequences kept at most, as many as the reorder gate
    /// holds samples above a gap (`reorder::MAX_PENDING_PER_WRITER`): for a
    /// non-coherent reliable reader each run lies below a held sample, or
    /// its proxy settles it.
    const MISSED_RUNS: usize = 4096;

    /// Ranges already known owed by this reader's WriterProxy. Unlike a
    /// provisional duplicate bit, the proxy states actual receipt.
    fn report_owed_in(&mut self, ranges: &[(u64, u64)], filtered: &BTreeMap<u64, u64>) -> u64 {
        let mut count = 0u64;
        for &(lo, hi) in ranges {
            let mut at = lo;
            let first = filtered
                .range(..lo)
                .next_back()
                .map(|(&s, _)| s)
                .unwrap_or(lo);
            for (&start, &end) in filtered.range(first..hi) {
                if end <= at {
                    continue;
                }
                count = count.saturating_add(self.reported.report(at, start.max(at).min(hi)));
                at = at.max(end);
                if at >= hi {
                    break;
                }
            }
            if at < hi {
                count = count.saturating_add(self.reported.report(at, hi));
            }
        }
        count
    }

    /// The highest sequence the window no longer covers.
    fn floor(high: u64) -> u64 {
        high.saturating_sub(Self::WINDOW)
    }

    fn slot(seq: u64) -> (usize, u64) {
        let at = seq % Self::WINDOW;
        // `at` < WINDOW, so the word index is below WORDS.
        let word = usize::try_from(at / 64).unwrap_or(0);
        (word, 1 << (at % 64))
    }

    fn marked(&self, seq: u64) -> bool {
        let (word, bit) = Self::slot(seq);
        self.bits[word] & bit != 0
    }

    fn mark(&mut self, seq: u64, on: bool) {
        let (word, bit) = Self::slot(seq);
        if on {
            self.bits[word] |= bit;
        } else {
            self.bits[word] &= !bit;
        }
    }

    /// The runs of `[lo, hi)` not received (admitted), as `[start, end)`
    /// ranges in order, each passed to `run`, adjacent ones joined:
    /// arithmetic on the missed runs below the window, a walk of at most
    /// the window's bits within it, one range above it.
    fn for_each_unreceived(&self, lo: u64, hi: u64, run: &mut impl FnMut(u64, u64)) {
        if hi <= lo {
            return;
        }
        let mut pending: Option<(u64, u64)> = None;
        let mut push = |start: u64, end: u64| {
            if end <= start {
                return;
            }
            match pending.as_mut() {
                Some((_, last)) if *last == start => *last = end,
                _ => {
                    if let Some((s, e)) = pending.replace((start, end)) {
                        run(s, e);
                    }
                }
            }
        };
        match self.high {
            None => push(lo, hi),
            Some(high) => {
                let floor = Self::floor(high);
                // Below the window: the missed runs (inclusive) within
                // [lo, hi).
                if lo <= floor {
                    let below_hi = hi.min(floor.saturating_add(1));
                    let first = self
                        .missed
                        .range(..lo)
                        .next_back()
                        .map(|(&s, _)| s)
                        .unwrap_or(lo);
                    for (&start, &end) in self.missed.range(first..below_hi) {
                        push(start.max(lo), end.saturating_add(1).min(below_hi));
                    }
                }
                // The window: its unmarked bits.
                let win_hi = hi.min(high.saturating_add(1));
                let mut seq = lo.max(floor.saturating_add(1));
                while seq < win_hi {
                    if self.marked(seq) {
                        seq += 1;
                        continue;
                    }
                    let start = seq;
                    while seq < win_hi && !self.marked(seq) {
                        seq += 1;
                    }
                    push(start, seq);
                }
                // Above it: nothing received.
                push(lo.max(high.saturating_add(1)), hi);
            }
        }
        if let Some((s, e)) = pending {
            run(s, e);
        }
    }

    /// Count and remember unreceived, unfiltered changes exactly once.
    /// Called before advancing a BEST_EFFORT duplicate window, so a large
    /// sequence jump cannot forget the holes before they are counted.
    fn report_unreceived_in(
        &mut self,
        ranges: impl IntoIterator<Item = (u64, u64)>,
        filtered: &BTreeMap<u64, u64>,
    ) -> u64 {
        let record = self;
        let SeenSeqs { reported, .. } = record;
        let mut reported = std::mem::take(reported);
        let mut count = 0u64;
        for (lo, hi) in ranges {
            record.for_each_unreceived(lo, hi, &mut |lo, hi| {
                // `[lo, hi)` without what is filtered.
                let mut at = lo;
                let first = filtered
                    .range(..lo)
                    .next_back()
                    .map(|(&s, _)| s)
                    .unwrap_or(lo);
                for (&fs, &fe) in filtered.range(first..hi) {
                    if fe <= at {
                        continue;
                    }
                    count = count.saturating_add(reported.report(at, fs.max(at).min(hi)));
                    at = at.max(fe);
                    if at >= hi {
                        break;
                    }
                }
                if at < hi {
                    count = count.saturating_add(reported.report(at, hi));
                }
            });
        }
        record.reported = reported;
        count
    }

    /// [`for_each_unreceived`](Self::for_each_unreceived), collected.
    #[cfg(test)]
    fn unreceived_in(&self, lo: u64, hi: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        self.for_each_unreceived(lo, hi, &mut |s, e| out.push((s, e)));
        out
    }

    /// `seq`, received, is taken back: not received any more, so a copy of
    /// it is new again (a sample its writer's departure discarded before
    /// it was delivered). A missed run below the window takes it.
    fn unmark(&mut self, seq: u64) {
        let Some(high) = self.high else {
            return;
        };
        if seq == 0 || seq > high {
            return;
        }
        if seq > Self::floor(high) {
            self.mark(seq, false);
            return;
        }
        if self.missed_run(seq).is_some() {
            return;
        }
        let (mut start, mut end) = (seq, seq);
        if let Some((s, e)) = self.missed_run(seq.saturating_sub(1)) {
            if e.saturating_add(1) == seq {
                self.missed.remove(&s);
                start = s;
            }
        }
        if let Some(&e) = self.missed.get(&seq.saturating_add(1)) {
            self.missed.remove(&seq.saturating_add(1));
            end = e;
        }
        self.missed.insert(start, end);
    }

    /// The missed run holding `seq`, as `(start, end)`.
    fn missed_run(&self, seq: u64) -> Option<(u64, u64)> {
        self.missed
            .range(..=seq)
            .next_back()
            .filter(|(_, &end)| seq <= end)
            .map(|(&start, &end)| (start, end))
    }

    /// Admit `seq` if it is new. `settled` is the writer proxy's answer
    /// (see `ReaderAckCredit::settled`), asked only below the window or
    /// when the record is full.
    fn admit(&mut self, seq: u64, missed: Missed, settled: impl FnOnce() -> Option<u64>) -> Seen {
        let seen = self.judge(seq, missed, settled);
        if seen == Seen::New {
            self.record(seq, missed);
        }
        seen
    }

    /// Whether `seq` is new, without admitting it. Only forgets runs the
    /// proxy has settled.
    fn judge(&mut self, seq: u64, missed: Missed, settled: impl FnOnce() -> Option<u64>) -> Seen {
        let Some(high) = self.high else {
            return Seen::New;
        };
        if seq > Self::floor(high) {
            if seq <= high {
                return if self.marked(seq) {
                    Seen::Duplicate
                } else {
                    Seen::New
                };
            }
            // Moving the window up: the runs it leaves behind must fit.
            let runs = self.leaving(Some(high), seq, missed);
            let added = self.added(&runs);
            if added == 0 || self.missed.len() + added <= Self::MISSED_RUNS {
                return Seen::New;
            }
            if let Some(settled) = settled() {
                self.settle(settled);
            }
            let runs = self.leaving(Some(high), seq, missed);
            return if self.missed.len() + self.added(&runs) <= Self::MISSED_RUNS {
                Seen::New
            } else {
                Seen::Full
            };
        }
        if self.missed_run(seq).is_none() {
            return Seen::Duplicate;
        }
        if let Some(settled) = settled() {
            self.settle(settled);
        }
        // Settled or not, the run as it stands now.
        let Some((start, end)) = self.missed_run(seq) else {
            return Seen::Duplicate;
        };
        // Taking it out of the middle of its run splits the run in two.
        if start < seq && seq < end && self.missed.len() >= Self::MISSED_RUNS {
            return Seen::Full;
        }
        Seen::New
    }

    /// Admit `seq`, which `judge` found new under the same lock.
    fn record(&mut self, seq: u64, missed: Missed) {
        match self.high {
            Some(high) if seq <= Self::floor(high) => self.take_missed(seq),
            Some(high) if seq <= high => self.mark(seq, true),
            high => {
                for (start, end) in self.leaving(high, seq, missed) {
                    self.add_missed(start, end);
                }
                let top = high.unwrap_or(0);
                if seq - top >= Self::WINDOW {
                    self.bits.fill(0);
                } else {
                    // The sequences entering the window take the slots of
                    // those leaving it.
                    for entering in top + 1..seq {
                        self.mark(entering, false);
                    }
                }
                self.high = Some(seq);
                self.mark(seq, true);
            }
        }
    }

    /// The runs of sequences that leave the window unadmitted when its top
    /// moves from `high` up to `seq`, each maximal, in increasing order.
    fn leaving(&self, high: Option<u64>, seq: u64, missed: Missed) -> Vec<(u64, u64)> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        if missed == Missed::Dropped {
            return runs;
        }
        let top = high.unwrap_or(0);
        let to = Self::floor(seq);
        let mut push = |start: u64, end: u64| match runs.last_mut() {
            Some((_, last)) if *last + 1 == start => *last = end,
            _ => runs.push((start, end)),
        };
        for gone in high.map_or(0, Self::floor) + 1..=to.min(top) {
            if !self.marked(gone) {
                push(gone, gone);
            }
        }
        // Above the old top nothing was admitted.
        if to > top {
            push(top + 1, to);
        }
        runs
    }

    /// How many runs `runs` (from `leaving`) add to the record: the first
    /// one extends the last kept run when adjacent to it.
    fn added(&self, runs: &[(u64, u64)]) -> usize {
        let extends = runs.first().is_some_and(|&(start, _)| {
            self.missed
                .iter()
                .next_back()
                .is_some_and(|(_, &end)| end + 1 == start)
        });
        runs.len() - usize::from(extends)
    }

    /// Record `start..=end` as missed, merged with the last run when
    /// adjacent. Runs leave the window in increasing order, so nothing
    /// lies above.
    fn add_missed(&mut self, start: u64, end: u64) {
        if let Some((_, last)) = self.missed.iter_mut().next_back() {
            if last.saturating_add(1) == start {
                *last = end;
                return;
            }
        }
        self.missed.insert(start, end);
    }

    /// `seq`, missed until now, is admitted: split its run around it.
    fn take_missed(&mut self, seq: u64) {
        let Some((start, end)) = self.missed_run(seq) else {
            return;
        };
        self.missed.remove(&start);
        if start < seq {
            self.missed.insert(start, seq - 1);
        }
        if seq < end {
            self.missed.insert(seq + 1, end);
        }
    }

    /// The proxy awaits nothing up to `settled`: those runs are no longer
    /// owed, and a copy of one of them is a duplicate.
    fn settle(&mut self, settled: u64) {
        while let Some((&start, &end)) = self.missed.iter().next() {
            if start > settled {
                break;
            }
            self.missed.remove(&start);
            if end > settled {
                self.missed.insert(settled + 1, end);
                break;
            }
        }
    }

    /// Take back the admission of `seq`: the sample was refused before it
    /// was received, so the copy the writer sends again must be admitted.
    /// Below the window it goes back into the missed runs. That can take
    /// the record one run past its bound for each admission taken back
    /// after the window moved on: the coherent pass-through admits, then
    /// may refuse, in two steps.
    fn forget(&mut self, seq: u64) {
        let Some(high) = self.high else {
            return;
        };
        if seq > Self::floor(high) {
            if seq <= high {
                self.mark(seq, false);
            }
            return;
        }
        if self.missed_run(seq).is_some() {
            return;
        }
        let mut start = seq;
        let mut end = seq;
        if let Some(after) = self.missed.remove(&(seq + 1)) {
            end = after;
        }
        if let Some((&before, &before_end)) = self.missed.range(..seq).next_back() {
            if before_end + 1 == seq {
                start = before;
            }
        }
        self.missed.insert(start, end);
    }
}

/// A panic caught in a delivery, to go on once the delivery is done.
type Panic = Box<dyn std::any::Any + Send + 'static>;

/// What the gate released for a writer, and who delivers it.
enum Release<'a> {
    /// Nothing released.
    Nothing,
    /// This thread holds the writer's delivery lock: it delivers the batch,
    /// what was queued before included, in order.
    Now(std::sync::MutexGuard<'a, ()>, Vec<PendingPayload>),
    /// Another thread is delivering: the release was queued behind what it
    /// delivers, and this thread drains the queue once it is done.
    Queued,
}

impl<'a> Release<'a> {
    /// Under the gate's lock, with `released` just out of it: take the
    /// writer's delivery lock if free, else queue behind its holder. Only
    /// tried, so the gate's lock is never held waiting for it (a drain takes
    /// the delivery lock, then the gate's).
    fn from_gate(
        gate: &mut ReorderGate,
        writer_guid: [u8; 16],
        released: Vec<PendingPayload>,
        delivery_lock: &'a Mutex<()>,
    ) -> Self {
        let delivering = match delivery_lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                gate.hand_over(writer_guid, released);
                return Release::Queued;
            }
        };
        let mut batch = gate.take_ready(&writer_guid, &delivering);
        if batch.is_empty() {
            batch = released;
        } else {
            batch.extend(released);
        }
        Release::Now(delivering, batch)
    }
}

/// The instance of each entry of a reader's network ring, oldest first, as
/// the last full-ring compaction decoded them (`ReaderSubscriber::
/// drop_replaced`), good while no sample was pushed since. The reader's take
/// pops entries from the front only, so the keys of what is left are the
/// last ones. The pass before the reorder gate's lock and the one under it
/// meet the same ring at one arrival: the second decodes nothing.
#[derive(Default)]
struct RingKeys {
    /// Pushes into the ring since the reader was built, wrapping.
    pushes: u64,
    /// `pushes` when `keys` were recorded, and the keys.
    known: Option<(u64, Vec<Option<[u8; 16]>>)>,
}

impl RingKeys {
    /// One more sample pushed: what was recorded no longer covers the ring.
    fn pushed(&mut self) {
        self.pushes = self.pushes.wrapping_add(1);
    }

    /// The keys of a ring of `len` entries that nothing was pushed into
    /// since they were recorded, if any.
    fn take(&mut self, len: usize) -> Option<Vec<Option<[u8; 16]>>> {
        let (at, mut keys) = self.known.take()?;
        if at != self.pushes || keys.len() < len {
            return None;
        }
        keys.drain(..keys.len() - len);
        Some(keys)
    }

    /// The keys of the ring as it is now.
    fn record(&mut self, keys: Vec<Option<[u8; 16]>>) {
        self.known = Some((self.pushes, keys));
    }
}

/// The most coherent changes one writer may have staged (`coherent_buffer`);
/// the next is refused, unacknowledged, but one of the writer's set in
/// order, at most `N` more (`stage_coherent_change`). Small in tests, so
/// that a test reaches it quickly.
pub(super) const MAX_STAGED_PER_WRITER: usize = if cfg!(test) { 64 } else { 4_096 };

/// The most samples one GROUP set may have staged, all writers together.
pub(super) const MAX_STAGED_PER_GROUP: usize = if cfg!(test) { 128 } else { 8_192 };

/// The most GROUP sets one writer may have open with staged DATA or
/// control metadata (`group_coherent_buffer`): a change opening one more
/// is refused unacknowledged. A DATA in the writer's set in order may
/// open one more (`stage_coherent_change`); metadata can reserve that
/// exception for at most one set. A Publisher's sets above a gap wait
/// there for it. Uncapped, a peer opened a fresh GSN per change or end,
/// never completing any set. Small in tests.
pub(super) const MAX_OPEN_GROUP_SETS_PER_WRITER: usize = if cfg!(test) { 32 } else { 256 };

/// How long a departure is kept (`ReaderSubscriber::has_left`). Past it
/// the writer is forgotten, and what lands from it is heard as from a
/// writer not matched yet. Safe: a datagram the writer sent before it left
/// does not land two minutes later (a departure itself comes a lease
/// after its participant was last heard, or with the writer's own
/// disposal), and a writer that lives is discovered again well within it
/// (a participant announces itself several times per lease; Cyclone DDS's
/// default SPDP interval, the longest among the stacks HDDS meets, is 30
/// s). Kept for good, one writer that left made every DATA of every writer
/// take the door's slow path, and its record stayed in memory.
const DEPARTED_KEEP: std::time::Duration = std::time::Duration::from_secs(120);

/// A writer that left (`ReaderSubscriber::on_writer_dispose`), until it
/// is heard again (`ReaderSubscriber::has_left`).
struct Departed {
    /// When it left: a departure older than `DEPARTED_KEEP` is forgotten
    /// (`has_left`).
    left_at: std::time::Instant,
    /// Announced again since its departure (`on_writer_qos_resolved`).
    announced: bool,
    /// Matched again, its record waits for its first HEARTBEAT
    /// (`heartbeat_verdict`): the door stays shut until the record is back.
    awaiting_heartbeat: bool,
    /// A reliable reader's duplicate record of it and the highest sequence
    /// it holds, kept from its departure: `None` when nothing was received.
    /// A departure is not always a death, and the writer that comes back
    /// may be the same one (its sequence numbers go on: what it sends again
    /// is told from what was received) or a new one under the same GUID
    /// (they start again at 1, RTPS v2.5 Sec.8.3.5.4). Its first HEARTBEAT
    /// once matched again tells which (`heartbeat_verdict`).
    parked: Option<(SeenSeqs, u64)>,
    /// It said it left (`WriterDeparture::Deleted`): a writer seen again
    /// under its GUID is a new one, and nothing of the old one is staged
    /// after its departure (`refuses_staging`).
    deleted: bool,
    losses: Option<Arc<LossLedger>>,
}

/// What one writer's changes said of where its staged coherent sets end
/// (`ReaderSubscriber::try_commit_sets`). A set is the writer's changes from
/// its first sequence number, the `PID_COHERENT_SET` its samples carry, up
/// to the change before the first one that is not of the set (RTPS v2.5
/// Sec.8.7.5, Sec.8.7.6): another set's sample, a DATA with no coherent-set
/// inline QoS, an end-of-set marker. Those are learned here, besides what
/// the reorder gate holds.
#[derive(Default)]
pub(super) struct SetEnds {
    /// Set start -> its last sequence number, from an end marker that
    /// counts its samples.
    ends: BTreeMap<u64, u64>,
    /// First sequence numbers of sets, from samples refused unacknowledged
    /// when staged: not of any set that starts before them.
    starts: BTreeSet<u64>,
    /// Changes of no set (a DATA with no coherent-set inline QoS, an end
    /// marker) received while a set was staged, for a gate that keeps
    /// nothing (a reader with no reorder gate).
    others: BTreeSet<u64>,
}

/// The most ranges `SeenSeqs::reported` keeps.
const MAX_LOST_RANGES: usize = 256;

/// A writer's sequences reported lost (`ReaderSubscriber::never_received`),
/// kept with its duplicate record (`SeenSeqs::reported`), forgotten with it:
/// `ranges` (`[start, end)`, sorted, disjoint, not adjacent). Bounded: past
/// `MAX_LOST_RANGES` two neighbouring ranges are joined, the hole between
/// them then counted as reported: a sequence is never reported twice; one
/// in a joined hole that is lost later is not reported. After a report in
/// increasing order (the usual one) the two lowest are joined; after one
/// out of order, the two closest, which leaves the fewest such sequences
/// (a floor raised to the lowest range's end took everything below it,
/// reported or not).
#[derive(Debug, Default)]
struct LostReported {
    /// Reports come mostly in increasing order (a writer's GAPs follow its
    /// sequence numbers): those append or extend at the back.
    ranges: std::collections::VecDeque<(u64, u64)>,
}

type ArrivalContext = (
    [u8; 16],
    Option<u64>,
    Option<crate::engine::demux::GroupArrivalStamp>,
);
thread_local! {
    // @audit-ok: Per-thread event context, restored by GroupArrivalScope on every exit.
    static GROUP_ARRIVAL: std::cell::RefCell<Option<ArrivalContext>> = const { std::cell::RefCell::new(None) };
}

/// One captured wire event, shared across every subscriber callback.
pub(crate) struct GroupArrivalScope(Option<ArrivalContext>);
impl GroupArrivalScope {
    pub(crate) fn enter(
        writer: [u8; 16],
        seq: Option<u64>,
        stamp: Option<crate::engine::demux::GroupArrivalStamp>,
    ) -> Self {
        Self(GROUP_ARRIVAL.with(|slot| slot.replace(Some((writer, seq, stamp)))))
    }
    #[cfg(test)]
    fn present(writer: [u8; 16], seq: Option<u64>) -> bool {
        GROUP_ARRIVAL.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|(w, s, _)| *w == writer && *s == seq)
        })
    }
    pub(crate) fn captured(writer: [u8; 16]) -> Option<crate::engine::demux::GroupArrivalStamp> {
        GROUP_ARRIVAL.with(|slot| {
            slot.borrow()
                .as_ref()
                .filter(|(w, _, _)| *w == writer)
                .and_then(|(_, _, s)| s.clone())
        })
    }
}
impl Drop for GroupArrivalScope {
    fn drop(&mut self) {
        GROUP_ARRIVAL.with(|slot| slot.replace(self.0.take()));
    }
}

/// Admission frames may change while their logical writer namespace continues.
pub(super) struct LossLedger {
    incarnation: Arc<crate::core::reader::AdmissionFrame>,
    authority: Arc<crate::core::reader::GroupLossAuthority>,
    credit: Option<crate::core::reader::ReaderAckCredit>,
    writer: [u8; 16],
}

enum ControlReceipt {
    Plain,
    Group(Arc<LossLedger>),
}

impl std::fmt::Debug for LossLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LossLedger")
            .field("writer", &self.writer)
            .finish_non_exhaustive()
    }
}

impl Default for LossLedger {
    fn default() -> Self {
        Self::new(
            Arc::new(crate::core::reader::AdmissionFrame::new(true)),
            None,
            [0; 16],
        )
    }
}

impl LossLedger {
    fn new(
        incarnation: Arc<crate::core::reader::AdmissionFrame>,
        credit: Option<crate::core::reader::ReaderAckCredit>,
        writer: [u8; 16],
    ) -> Self {
        let authority = incarnation.loss_authority().clone();
        Self {
            incarnation,
            credit,
            writer,
            authority,
        }
    }

    pub(super) fn claim(
        &self,
        seq: u64,
        owned: bool,
    ) -> Option<Arc<crate::core::reader::LossTicket>> {
        if let Some(credit) = &self.credit {
            credit.claim_group_sample(&self.writer, &self.authority, seq, owned, &self.incarnation)
        } else {
            self.authority
                .claim(self.writer, seq, owned, &self.incarnation, None, false)
        }
    }

    pub(super) fn try_record(&self, seq: u64) -> Option<u64> {
        self.claim(seq, true).map(|ticket| ticket.mark_lost())
    }

    pub(super) fn classify_control(&self, seq: u64) -> bool {
        self.authority.classify_control(seq)
    }

    pub(super) fn record(&self, seq: u64) -> u64 {
        // The prepared sample keeps its in-flight loss right, so a ticket exists.
        let recorded = self.try_record(seq);
        debug_assert!(
            recorded.is_some(),
            "a prepared departed sample keeps its loss right"
        );
        recorded.unwrap_or(0)
    }

    fn take_pending(&self) -> u64 {
        self.authority.take_pending()
    }
}

impl LostReported {
    /// Of `[start, end)`, the sequences not reported yet; recorded as
    /// reported.
    fn report(&mut self, start: u64, end: u64) -> u64 {
        if end <= start {
            return 0;
        }
        let (fresh, in_order) = match self.ranges.back_mut() {
            None => {
                self.ranges.push_back((start, end));
                (end - start, true)
            }
            Some(last) if start >= last.1 => {
                if start == last.1 {
                    last.1 = end;
                } else {
                    self.ranges.push_back((start, end));
                }
                (end - start, true)
            }
            Some(_) => (self.merge(start, end), false),
        };
        if self.ranges.len() > MAX_LOST_RANGES {
            if in_order {
                // Reports in increasing order: the lowest hole is the one
                // least likely to be reported into (O(1)).
                self.join_at(1);
            } else {
                self.join_closest();
            }
        }
        fresh
    }

    /// Join the two neighbouring ranges with the smallest hole between.
    fn join_closest(&mut self) {
        if let Some(at) =
            (1..self.ranges.len()).min_by_key(|&i| self.ranges[i].0 - self.ranges[i - 1].1)
        {
            self.join_at(at);
        }
    }

    /// Join range `at` into the one before it, the hole between included.
    fn join_at(&mut self, at: usize) {
        if at == 0 || at >= self.ranges.len() {
            return;
        }
        let (_, end) = self.ranges[at];
        self.ranges[at - 1].1 = end;
        self.ranges.remove(at);
    }

    /// `[start, end)` merged into the ranges, wherever it falls; how many
    /// of its sequences none covered.
    fn merge(&mut self, start: u64, end: u64) -> u64 {
        // The first range ending at or after `start`: those before it
        // neither touch nor overlap.
        let at = self.ranges.partition_point(|&(_, e)| e < start);
        let (mut lo, mut hi) = (start, end);
        let mut covered = 0u64;
        while at < self.ranges.len() && self.ranges[at].0 <= end {
            let (s, e) = self.ranges[at];
            covered += e.min(end).saturating_sub(s.max(start));
            lo = lo.min(s);
            hi = hi.max(e);
            self.ranges.remove(at);
        }
        self.ranges.insert(at, (lo, hi));
        (end - start) - covered
    }
}

/// The most discarded sets `ReaderSubscriber::discarded_sets` keeps per
/// writer.
const MAX_DISCARDED_SETS: usize = 64;

/// The most discarded GROUP sets `ReaderSubscriber::discarded_group_sets`
/// keeps.
const MAX_DISCARDED_GROUP_SETS: usize = 256;

/// The most changes of no set `ReaderSubscriber::note_set_ends` keeps per
/// writer while none of its sets is staged.
const MAX_EARLY_SET_ENDS: usize = 64;

impl SetEnds {
    fn is_empty(&self) -> bool {
        self.ends.is_empty() && self.starts.is_empty() && self.others.is_empty()
    }

    /// Forget what concerns sequences up to `last`, committed.
    fn forget_through(&mut self, last: u64) {
        self.ends = self.ends.split_off(&last.saturating_add(1));
        self.starts = self.starts.split_off(&last.saturating_add(1));
        self.others = self.others.split_off(&last.saturating_add(1));
    }
}

/// What `ReaderSubscriber::replace_oldest` made of a full KEEP_LAST ring.
enum Replacement {
    /// The oldest sample of the incoming sample's instance was dropped; its
    /// place is the incoming sample's now.
    Made(super::admission::HistorySlot),
    /// There was one, but the incoming sample is not visible: it stays.
    NotVisible,
    /// The ring holds fewer than `depth` samples of that instance.
    NothingToReplace,
}

/// A sample about to be pushed into a full KEEP_LAST network ring, as
/// `ReaderSubscriber::compact` needs it to decide what the ring keeps:
/// its instance, and, for BY_SOURCE_TIMESTAMP compaction
/// (`replaced_by_source_order`), the EXACT SAME ordering fields
/// `InstanceTable::admit_by_source` compares -- without them,
/// compaction can discard the sample the gate would actually have kept
/// (or keep this one over a ring entry the gate would have preferred),
/// a different value depending only on which arrived first.
#[derive(Clone, Copy)]
struct CompactIncoming {
    key: [u8; 16],
    ts: Option<u64>,
    writer_guid: Option<[u8; 16]>,
    sn: u64,
}

/// One ring entry's BY_SOURCE_TIMESTAMP ordering fields: `(timestamp,
/// writer GUID, writer SN)`, timestamp `None` for an entry with no
/// genuine source timestamp. The EXACT total order
/// `InstanceTable::admit_by_source` uses (`SourceOrderKey`,
/// wrapped here since compaction's timestamp may be unknown and must
/// sort as the oldest, unlike the gate's own key).
type OrderTuple = (Option<u64>, Option<[u8; 16]>, u64);

/// When a full KEEP_LAST ring may drop the oldest sample of the incoming
/// sample's instance to make room for it (`ReaderSubscriber::reserve_place`).
#[derive(Debug, Clone, Copy)]
enum Replace {
    /// The sample is pushed once it has its place: its ownership is
    /// already arbitrated.
    Always,
    /// The sample replaces nothing: the reorder gate holds it, and whether
    /// it is visible is decided only at its release.
    Never,
    /// The sample, change `seq` of `writer`, is pushed only if its writer
    /// may modify its instance: arbitrated before anything is dropped.
    IfVisible { writer: [u8; 16], seq: u64 },
}

/// Why a RELIABLE reader refused a sample without acknowledging it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// Its history had no room (DDS v1.4 Sec.2.2.3.19): reported as
    /// SAMPLE_REJECTED, reason REJECTED_BY_SAMPLES_LIMIT.
    ResourceLimit,
    /// Its reorder gate would hold it before knowing where the writer's
    /// history starts, and the reader has no history room to keep one
    /// place for that gap with. Not a resource limit and not reported: the
    /// writer sends the sample again after its HEARTBEAT.
    GapUnknown,
    /// The reader already keeps all it can track above the writer's first
    /// missing sequence: its reorder gate holds its maximum, its duplicate
    /// record cannot take the sample without dropping what is owed, or
    /// holding it would leave its instance less room than the gap below it
    /// may need. Not reported: the writer sends it again once the gap
    /// fills.
    Backlog,
    /// The process-wide slab pool had no room to store it: reported as
    /// SAMPLE_REJECTED, reason REJECTED_BY_SAMPLES_LIMIT, like a full
    /// history, and counted as `samples_rejected_slab_exhausted`.
    Storage,
    /// Its instance is new and the history already manages
    /// RESOURCE_LIMITS `max_instances` (DDS v1.4 Sec.2.2.3.19): reported
    /// as SAMPLE_REJECTED, reason REJECTED_BY_INSTANCES_LIMIT.
    InstanceLimit,
    /// The history already holds RESOURCE_LIMITS `max_samples_per_instance`
    /// samples of its instance: reported as SAMPLE_REJECTED, reason
    /// REJECTED_BY_SAMPLES_PER_INSTANCE_LIMIT.
    SamplesPerInstanceLimit,
}

impl From<super::admission::Bound> for Refusal {
    fn from(bound: super::admission::Bound) -> Self {
        match bound {
            super::admission::Bound::Samples | super::admission::Bound::Kept => {
                Refusal::ResourceLimit
            }
            super::admission::Bound::Instances => Refusal::InstanceLimit,
            super::admission::Bound::SamplesPerInstance => Refusal::SamplesPerInstanceLimit,
            super::admission::Bound::GapHeadroom => Refusal::Backlog,
        }
    }
}

impl Refusal {
    /// The SAMPLE_REJECTED reason of a refusal the application hears about.
    fn reason(self) -> SampleRejectedReason {
        match self {
            Refusal::InstanceLimit => SampleRejectedReason::InstanceLimit,
            Refusal::SamplesPerInstanceLimit => SampleRejectedReason::SamplesPerInstanceLimit,
            Refusal::ResourceLimit | Refusal::Storage | Refusal::GapUnknown | Refusal::Backlog => {
                SampleRejectedReason::ResourceLimit
            }
        }
    }
}

/// What `ReaderSubscriber::prepare` made of a sample.
enum Preparation<T> {
    /// Decoded and copied into the slab pool (`len` bytes at `handle`).
    Stored {
        msg: T,
        handle: rt::SlabHandle,
        len: u32,
        legacy_key_hash: Option<[u8; 16]>,
    },
    /// Received, delivers nothing (see `admission::Prepared::Discard`).
    Discard,
    /// Decoded, but it cannot be re-encoded for the ring: received, delivers
    /// nothing, its writer still writes its instance.
    Unstorable(T),
    /// Decoded, but the slab pool has no room to store it.
    NoStorage { msg: T },
}

impl<T: DDS> Preparation<T> {
    /// The non-generic form a sample travels in through the reorder gate;
    /// `Err` with the decoded sample when there was no storage for it.
    fn into_prepared(self) -> Result<super::admission::Prepared, T> {
        match self {
            Preparation::Stored {
                msg,
                handle,
                len,
                legacy_key_hash,
            } => {
                let mut stored = super::admission::StoredSample::new(handle, len, Box::new(msg));
                stored.legacy_key_hash = legacy_key_hash;
                Ok(super::admission::Prepared::Stored(stored))
            }
            Preparation::Discard => Ok(super::admission::Prepared::Discard),
            Preparation::Unstorable(msg) => Ok(super::admission::Prepared::Unstorable {
                key: msg.compute_key(),
            }),
            Preparation::NoStorage { msg } => Err(msg),
        }
    }
}

/// A caught panic, resumed when this goes out of scope, unless the thread is
/// already unwinding from another one.
struct ResumeOnReturn(Option<Panic>);

impl Drop for ResumeOnReturn {
    fn drop(&mut self) {
        if let Some(panic) = self.0.take() {
            if !std::thread::panicking() {
                std::panic::resume_unwind(panic);
            }
        }
    }
}

/// An `Admit::Here` whose door count is unknown.
const NO_EPOCH: u64 = u64::MAX;

/// Who enters a sample in its writer's duplicate window (`SeenSeqs`).
#[derive(Debug, Clone, Copy)]
enum Admit<'a> {
    /// The delivery does, in the same step as it takes the sample's slot;
    /// the door let the sample in at this `departures` count
    /// (`NO_EPOCH`: look the writer up again under the gate).
    Here(u64),
    /// Direct DATA also keeps its writer incarnation across preparation.
    Direct(u64, &'a crate::core::reader::AdmissionFrame),
    /// A discovery-held sample belongs to this writer incarnation. Its
    /// departure invalidates the token before clearing admission state.
    Pending(&'a crate::core::reader::AdmissionFrame),
    /// The caller already did.
    Done,
}

/// One sample deferred by the OWNERSHIP data-plane gate while its writer's
/// SEDP announcement was still unresolved (see
/// `ReaderSubscriber::ownership_gate`). Owns the payload bytes because the
/// router's borrow ends when `on_data_with_writer` returns.
#[derive(Debug)]
struct PendingOwnershipSample {
    order: Option<crate::engine::router::OrderedGroupChange>,
    set_first_gsn: Option<u64>,
    remote_seq: u64,
    data: Vec<u8>,
    version: crate::dds::CdrVersion,
    source_ts_ns: Option<u64>,
    arrival_stamp: Option<crate::engine::demux::GroupArrivalStamp>,
    inline_lifecycle: Option<crate::engine::router::InlineLifecycleContext>,
    legacy_hash: Option<crate::engine::router::LegacyHashContext>,
    /// Shared only with samples and the drain of this writer incarnation.
    incarnation: Arc<crate::core::reader::AdmissionFrame>,
    /// A live DATA queued behind a flush still finishes its receive path.
    live: bool,
}

impl PendingOwnershipSample {
    fn capture(
        writer_guid: [u8; 16],
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        live: bool,
        incarnation: Arc<crate::core::reader::AdmissionFrame>,
    ) -> Self {
        let order = crate::engine::router::route_ordered_group(writer_guid, remote_seq);
        Self {
            order,
            set_first_gsn: order.and_then(crate::engine::router::route_ordered_group_set_first),
            remote_seq,
            data: data.to_vec(),
            version,
            source_ts_ns: crate::engine::router::route_source_ts_ns(),
            arrival_stamp: GroupArrivalScope::captured(writer_guid),
            inline_lifecycle: crate::engine::router::route_inline_lifecycle_context(
                Some(writer_guid),
                remote_seq,
            ),
            legacy_hash: crate::engine::router::route_legacy_hash_context(
                Some(writer_guid),
                remote_seq,
            ),
            live,
            incarnation,
        }
    }
}

/// Tri-state outcome of the OWNERSHIP data-plane gate for one writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnershipGate {
    /// Writer resolved (or the gate does not apply): deliver.
    Deliver,
    /// Writer resolved and OWNERSHIP kinds differ (RxO, DDS v1.4
    /// Sec.2.2.3.11): reject the sample and discard any deferred backlog.
    Reject,
    /// Writer not yet resolvable via SEDP: DEFER the sample -- neither
    /// deliver (the writer may turn out incompatible) nor discard (a
    /// TRANSIENT_LOCAL history burst is one-shot: the drop would be
    /// unrecoverable because it happens above the RTPS reliability layer).
    Unresolved,
}

/// Bounded holding area for samples deferred by the OWNERSHIP gate while
/// their writer's SEDP is still in flight. The race window is normally
/// milliseconds (data and SEDP ride the same discovery burst), so the caps
/// are sized for a single history burst, not sustained traffic. Overflow
/// evicts OLDEST first; for RELIABLE writers an evicted sample is recovered
/// by the normal retransmit machinery because eviction happens before the
/// sample is credited to the ACKNACK state (`deliver_admitted_sample`).
#[derive(Debug, Default)]
struct OwnershipPending {
    by_writer: HashMap<[u8; 16], std::collections::VecDeque<PendingOwnershipSample>>,
    /// Total samples across all writers (kept in sync with `by_writer`).
    total_samples: usize,
    /// Total payload bytes across all writers (kept in sync with `by_writer`).
    total_bytes: usize,
    /// Writers whose SEDP resolution callback has run. Kept independently
    /// of the queue so an enqueue just after that callback still wakes.
    /// Removed when the writer leaves.
    resolved: std::collections::HashSet<[u8; 16]>,
    /// The queue may be empty while its removed batch is being admitted.
    /// Later DATA joins that batch's drainer instead of overtaking it.
    flushing: HashMap<[u8; 16], Arc<crate::core::reader::AdmissionFrame>>,
    /// Shared by direct DATA, queued samples and their drain until the
    /// writer leaves. A new token cannot revive old prepared DATA.
    incarnations: HashMap<[u8; 16], Arc<crate::core::reader::AdmissionFrame>>,
    losses: HashMap<[u8; 16], Arc<LossLedger>>,
    /// Writers discovery holds whose QoS verdict is not on record, since when
    /// (`ReaderSubscriber::note_unjudged_writer`). Cleared when a sample of
    /// the writer is admitted or discarded.
    unjudged_since: HashMap<[u8; 16], std::time::Instant>,
    /// Reports made per writer, as unjudged past the discovery lease: at most
    /// one each.
    unjudged_reports: HashMap<[u8; 16], u32>,
}

impl OwnershipPending {
    fn loss_ledger(
        &mut self,
        writer: [u8; 16],
        expected: Option<&crate::core::reader::AdmissionFrame>,
        credit: Option<&crate::core::reader::ReaderAckCredit>,
    ) -> Option<Arc<LossLedger>> {
        let incarnation = self
            .incarnations
            .entry(writer)
            .or_insert_with(|| Arc::new(crate::core::reader::AdmissionFrame::new(true)));
        if !incarnation.load(Ordering::Acquire)
            || expected.is_some_and(|expected| !std::ptr::eq(expected, incarnation.as_ref()))
        {
            return None;
        }
        let ledger = self.losses.entry(writer).or_insert_with(|| {
            Arc::new(LossLedger::new(
                incarnation.clone(),
                credit.cloned(),
                writer,
            ))
        });
        debug_assert!(Arc::ptr_eq(&ledger.incarnation, incarnation));
        Some(ledger.clone())
    }
    fn incarnation(&mut self, writer: [u8; 16]) -> Arc<crate::core::reader::AdmissionFrame> {
        self.incarnations
            .entry(writer)
            .or_insert_with(|| Arc::new(crate::core::reader::AdmissionFrame::new(true)))
            .clone()
    }

    fn owns_flush(
        &self,
        writer: &[u8; 16],
        incarnation: &Arc<crate::core::reader::AdmissionFrame>,
    ) -> bool {
        self.flushing
            .get(writer)
            .is_some_and(|active| Arc::ptr_eq(active, incarnation))
    }

    fn finish_flush(
        &mut self,
        writer: &[u8; 16],
        incarnation: &Arc<crate::core::reader::AdmissionFrame>,
    ) {
        if self.owns_flush(writer, incarnation) {
            self.flushing.remove(writer);
        }
    }

    fn forget_idle_incarnation(&mut self, writer: &[u8; 16]) {
        if self
            .incarnations
            .get(writer)
            .is_some_and(|token| Arc::strong_count(token) == 1)
        {
            self.incarnations.remove(writer);
        }
    }

    /// Max deferred samples per unresolved writer. Covers the practical
    /// TRANSIENT_LOCAL burst that can land inside the SEDP resolution
    /// window; RELIABLE retransmits recover anything evicted beyond it.
    const PER_WRITER_CAP: usize = 64;
    /// Max deferred samples across all unresolved writers.
    const TOTAL_SAMPLES_CAP: usize = 256;
    /// Max deferred payload bytes across all unresolved writers.
    const TOTAL_BYTES_CAP: usize = 4 * 1024 * 1024;

    /// Stash one sample for `writer_guid`, enforcing the per-writer cap
    /// (evict this writer's oldest) and the global caps (evict the oldest
    /// of the largest backlog). Returns the evicted samples' writers and
    /// sequences, oldest first: never credited, they are owed to the
    /// reader, and its gate joins each writer at the first of them.
    fn push(
        &mut self,
        writer_guid: [u8; 16],
        sample: PendingOwnershipSample,
    ) -> Vec<([u8; 16], u64)> {
        let mut evicted = Vec::new();
        self.total_samples += 1;
        self.total_bytes += sample.data.len();
        {
            let queue = self.by_writer.entry(writer_guid).or_default();
            queue.push_back(sample);
            while queue.len() > Self::PER_WRITER_CAP {
                if let Some(old) = queue.pop_front() {
                    self.total_samples = self.total_samples.saturating_sub(1);
                    self.total_bytes = self.total_bytes.saturating_sub(old.data.len());
                    evicted.push((writer_guid, old.remote_seq));
                } else {
                    break;
                }
            }
        }
        while self.total_samples > Self::TOTAL_SAMPLES_CAP
            || self.total_bytes > Self::TOTAL_BYTES_CAP
        {
            // Evict from the largest backlog so one writer cannot starve
            // the rest of the map.
            let victim = self
                .by_writer
                .iter()
                .max_by_key(|(_, q)| q.len())
                .map(|(guid, _)| *guid);
            let Some(victim) = victim else {
                break;
            };
            let mut victim_empty = false;
            if let Some(queue) = self.by_writer.get_mut(&victim) {
                if let Some(old) = queue.pop_front() {
                    self.total_samples = self.total_samples.saturating_sub(1);
                    self.total_bytes = self.total_bytes.saturating_sub(old.data.len());
                    evicted.push((victim, old.remote_seq));
                }
                victim_empty = queue.is_empty();
            }
            if victim_empty {
                self.by_writer.remove(&victim);
                // Direct DATA may still be preparing outside this lock.
                self.forget_idle_incarnation(&victim);
                if self.by_writer.is_empty() {
                    break;
                }
            }
        }
        evicted
    }

    /// Remove and return every deferred sample for `writer_guid` in arrival
    /// order. `None` when nothing was deferred for that writer.
    fn take(
        &mut self,
        writer_guid: &[u8; 16],
    ) -> Option<std::collections::VecDeque<PendingOwnershipSample>> {
        let queue = self.by_writer.remove(writer_guid)?;
        self.total_samples = self.total_samples.saturating_sub(queue.len());
        let bytes: usize = queue.iter().map(|s| s.data.len()).sum();
        self.total_bytes = self.total_bytes.saturating_sub(bytes);
        Some(queue)
    }

    /// Whether any sample is currently deferred for `writer_guid`.
    fn has(&self, writer_guid: &[u8; 16]) -> bool {
        self.by_writer.contains_key(writer_guid)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SeqWindow {
    /// Base sequence number (first remote sequence observed).
    base: u64,
    /// Optional stride between consecutive remote sequences.
    ///
    /// - `None`  -> dense mode (delta fits in u32, seq++ style).
    /// - `Some`  -> stride mode (remote_seq = base + k * stride).
    stride: Option<u64>,
    /// Whether the window has seen at least one sequence number.
    initialized: bool,
}

impl SeqWindow {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            base: 0,
            stride: None,
            initialized: false,
        }
    }

    /// Map a 64-bit remote sequence number into a local 32-bit sequence.
    ///
    /// Behaviour:
    /// - First sequence initializes the window (base) and returns 0.
    /// - While deltas are small (<= u32::MAX), uses dense mapping `seq = delta`.
    /// - On first large delta, switches to stride mode where
    ///   `local_seq = (remote_seq - base) / stride` if aligned.
    #[allow(dead_code)]
    fn map(&mut self, remote_seq: u64) -> Option<u32> {
        // Note: Duplicate detection is disabled because SeqWindow is per-topic,
        // not per-writer-GUID. Multiple writers can use the same sequence numbers.
        // Fragment-level duplicate detection happens in FragmentBuffer.

        // 1) First sequence: initialize base.
        if !self.initialized {
            self.base = remote_seq;
            self.stride = None;
            self.initialized = true;
            return Some(0);
        }

        // 2) Handle sequences from potentially new writers.
        // If seq < base, this might be a new writer starting fresh.
        // Re-initialize the window for the new writer's sequence space.
        if remote_seq < self.base {
            log::debug!(
                "[reader] Sequence {} < base {}; possible new writer, reinitializing window",
                remote_seq,
                self.base
            );
            self.base = remote_seq;
            self.stride = None;
            return Some(0);
        }

        let delta = remote_seq - self.base;

        // 3) No stride yet: try dense mapping first.
        if self.stride.is_none() {
            if let Ok(value) = u32::try_from(delta) {
                return Some(value);
            }

            // First large delta: treat it as stride.
            // At this point we know remote_seq == base + stride, so index is 1.
            if delta == 0 {
                // Defensive: shouldn't happen here, but keep behaviour sane.
                return Some(0);
            }

            self.stride = Some(delta);
            return Some(1);
        }

        // 4) Stride mode: enforce alignment on stride and map to index.
        let stride = match self.stride {
            Some(s) if s > 0 => s,
            _ => {
                log::debug!(
                    "[reader] Invalid stride (base={}, stride={:?}); dropping seq={}",
                    self.base,
                    self.stride,
                    remote_seq
                );
                return None;
            }
        };

        let idx = delta / stride;
        let rem = delta % stride;

        if rem != 0 {
            log::debug!(
                "[reader] Sequence {} not aligned on stride {} (base={}); dropping UDP packet",
                remote_seq,
                stride,
                self.base
            );
            return None;
        }

        match u32::try_from(idx) {
            Ok(value) => Some(value),
            Err(_) => {
                log::debug!(
                    "[reader] Sequence {} maps to idx {} > u32::MAX (base={}, stride={}); dropping UDP packet",
                    remote_seq,
                    idx,
                    self.base,
                    stride
                );
                None
            }
        }
    }
}

/// One reader's PARTITION verdicts on the remote writers, keyed by the
/// writer's 16-byte GUID (`true` = deliver), read on the data path with no
/// lock taken.
///
/// The verdicts are published as an immutable map: a sample costs one
/// hazard-pointer load and one fold of the GUID ([`HandleHasher`]), never a
/// mutex acquisition, so the threads a reader receives on do not serialise
/// on, nor write to, one cache line per reader and per sample. A new
/// verdict, or the loss of one, clones the map and publishes it -- a cold
/// path, reached once per writer a reader judges, not once per sample.
///
/// `cold` serialises those two cold changes: resolving a writer's PARTITION
/// through SEDP and publishing its verdict, and forgetting a verdict when
/// the writer re-announces its QoS (DDS v1.4 sec. 2.2.3.13: PARTITION is
/// mutable) or departs. Holding it across both is what stops an offer read
/// before the writer's refresh from being published after it.
struct PartitionVerdicts {
    published: arc_swap::ArcSwap<
        std::collections::HashMap<[u8; 16], bool, BuildHasherDefault<HandleHasher>>,
    >,
    cold: Mutex<()>,
}

impl PartitionVerdicts {
    fn new() -> Self {
        Self {
            published: arc_swap::ArcSwap::from_pointee(std::collections::HashMap::with_hasher(
                BuildHasherDefault::default(),
            )),
            cold: Mutex::new(()),
        }
    }

    /// The verdict already reached on `writer`, if any.
    fn get(&self, writer: &[u8; 16]) -> Option<bool> {
        self.published.load().get(writer).copied()
    }

    /// Publish `deliver` for `writer`. The caller holds `cold`.
    fn publish(&self, writer: [u8; 16], deliver: bool) {
        let current = self.published.load();
        let mut next = (**current).clone();
        next.insert(writer, deliver);
        self.published.store(Arc::new(next));
    }

    /// Drop `writer`'s verdict: what it said of its PARTITION is not what
    /// its successor, or its next announcement, says.
    fn forget(&self, writer: &[u8; 16]) {
        let _cold = self.cold.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.published.load();
        if !current.contains_key(writer) {
            return;
        }
        let mut next = (**current).clone();
        next.remove(writer);
        self.published.store(Arc::new(next));
    }

    /// The cold section a verdict is resolved and published in, so that a
    /// refresh cannot slip between the two (see `writer_partition_incompatible`).
    fn resolve_under_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.cold.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub(super) struct ReaderSubscriber<T: DDS> {
    pub(super) topic: String,
    /// The join-clock tick of this reader's creation
    /// (`crate::engine::subscriber::join_clock_tick`): a DATA the router
    /// dropped after it was created only is owed nothing here
    /// (`on_dropped_before_discovery`).
    created_at: u64,
    pub(super) ring: Arc<rt::IndexRing>,
    pub(super) status_condition: Arc<StatusCondition>,
    pub(super) participant_guard: Option<Arc<GuardCondition>>,
    /// The participant's security suite, for the data-plane decrypt gate.
    /// `None` on a participant built without security; a secured payload
    /// arriving anyway is then dropped, never delivered as ciphertext.
    #[cfg(feature = "security")]
    pub(super) security: Option<Arc<crate::security::SecurityPluginSuite>>,
    /// What this reader's data plane resolved from the security documents
    /// (`security::protection_cache`): its topic's own payload protection
    /// (`is_payload_protected`, DDS-Security v1.1 Table 30) and each remote
    /// writer's announced attributes. Both used to be resolved per sample --
    /// a governance rule walk for the topic and a discovery scan, with a
    /// `Vec` allocation, for the writer -- and both are dropped when the
    /// document generation moves (a permissions overlay reload).
    #[cfg(feature = "security")]
    protection: std::sync::Mutex<crate::security::protection_cache::ReaderProtection>,
    /// Cleartext payloads refused because the topic's payload is protected.
    #[cfg(feature = "security")]
    cleartext_refused: std::sync::atomic::AtomicU64,
    /// Whether discovery runs the security plugins that judge a remote
    /// writer, resolved once at the first sample (`writer_not_admitted`).
    /// The plugins are installed when the participant is built, before any
    /// reader of it exists.
    #[cfg(feature = "security")]
    admission_gate: std::sync::OnceLock<bool>,
    #[allow(dead_code)]
    seq_window: Mutex<SeqWindow>,
    /// Recently admitted remote sequences for the legacy path that has no
    /// writer GUID. Single window because we cannot tell writers apart on
    /// this path; multi-writer scenarios on intra-process / writer-less
    /// transports are handled by the per-topic engine.
    seen_seqs: Mutex<SeenSeqs>,
    /// Per-writer recently admitted sequences for the network path. RTPS
    /// sequence numbers are scoped per DataWriter (RTPS v2.5 sec. 8.3.5.4) so
    /// the dedup window must be keyed by the writer's 16-byte GUID.
    seen_seqs_by_writer: Mutex<std::collections::HashMap<[u8; 16], SeenSeqs>>,
    /// Shared with the local pump: one TIME_BASED_FILTER history per reader.
    pub(super) time_filter_checkers:
        Arc<Mutex<HashMap<InstanceHandle, crate::qos::time_based_filter::TimeBasedFilterChecker>>>,
    pub(super) time_based_filter: crate::qos::time_based_filter::TimeBasedFilter,
    /// The reader's `ReaderStats::drops`: samples of this reader discarded
    /// after arrival (ring replacement, content filter). Shared with the
    /// reader's local doors and its `DataReader`; set by the builder.
    pub(super) dropped: Arc<AtomicU64>,
    /// Tells the application when a parked TIME_BASED_FILTER sample is due.
    /// `None` when the filter is off or the reader has no liveliness
    /// scheduler thread: the sample is then shown at the next access.
    pub(super) filter_waker: Option<Arc<super::filter_wake::FilterWaker<T>>>,
    /// Optional content filter (for ContentFilteredTopic).
    pub(super) content_filter: Option<FilterEvaluator>,
    /// How `content_filter` reads a sample's fields; `None` means
    /// `DDS::get_fields`. Set by the builder right after construction.
    pub(super) field_extractor: Option<super::conditions::FieldExtractor<T>>,
    /// The entity id this reader is announced under (`None` without a
    /// participant). A HEARTBEAT or GAP whose readerId names another reader
    /// is not handed to this one.
    pub(super) reader_entity_id: Option<[u8; 4]>,
    /// The room in `ring`: a sample takes a slot before it is acknowledged,
    /// and one that finds none is refused unacknowledged so the writer sends
    /// it again (see the `admission` module). A KEEP_ALL reader's slot is
    /// its place in the history until the application takes the sample; a
    /// KEEP_LAST reader's, whose history keeps the newest samples rather
    /// than refuse them, is its place in the ring only. `None` without a
    /// network ring. Set by the builder right after construction.
    pub(super) room: Option<Arc<super::admission::HistoryRoom>>,
    /// The reader's listener slot, shared with the `DataReader` (which
    /// replaces its content at runtime, `DataReader::set_listener`). The
    /// builder installs the reader's own slot right after construction.
    pub(super) listener: Arc<ReaderListenerSlot<T>>,
    /// Shared queue for dispose/unregister events (drained by DataReader).
    pub(super) dispose_events: Arc<DisposeQueue>,
    /// Per-writer reorder gate. Sample arrivals push into the gate via
    /// `on_data_with_writer`; the discovery control thread seeds the
    /// per-writer base sequence via `on_writer_heartbeat`.
    pub(super) reorder: Arc<Mutex<ReorderGate>>,
    /// The instances each remote DataWriter holds registered: written, and
    /// not unregistered since (`WriterRegistrations`). An unregister moves
    /// an instance to NOT_ALIVE_NO_WRITERS only when no other writer holds
    /// it (DDS v1.4 Sec.2.2.2.4.2.7), and a writer's departure - announced
    /// via SEDP DATA(d) on `ENTITYID_BUILTIN_PUBLICATIONS_WRITER`, with no
    /// per-instance payload - does the same for every instance it held.
    /// The transition is due whether or not the application already took
    /// the samples (DDS v1.4 Sec.2.2.4.2.2), so the tracker lives next to
    /// `dispose_events` (which survives `take()`) rather than inside the
    /// sample cache. Local writers reach the reader without a writer GUID:
    /// under EXCLUSIVE ownership their bindings' ownership gates record them
    /// here under the identity their merger carries; under SHARED they are
    /// not recorded per sample, and the table asks them, through the
    /// instances each one holds, before it declares an instance without
    /// writers (`ReaderRegistrations::held_locally`).
    ///
    /// Under EXCLUSIVE ownership the same table arbitrates each instance, and
    /// it is shared with the reader's intra-process bindings, which arbitrate
    /// local writers in it (`ReaderRegistrations`). The builder replaces the
    /// one `new_with_coherent` makes with the reader's.
    pub(super) writer_instances: Arc<ReaderRegistrations>,
    /// Per-reader coherent_access configuration captured at build time
    /// (Presentation QoS is immutable per DDS spec 2.2.3.6).
    pub(super) coherent_cfg: CoherentConfig,
    /// Per-writer FIFO of samples buffered while a coherent set is
    /// open (RTPS v2.5 sec. 8.7.5). The publisher tags each sample with
    /// `PID_COHERENT_SET = sample_sn` (writer-scoped) and the ECS
    /// DATA submessage with `PID_COHERENT_SET = last_sn_in_set`. On
    /// ECS arrival we drain every staged sample whose `remote_seq` is
    /// `<= ecs.coherent_sn`, sort them in writer order, and feed them
    /// through the regular admit pipeline so the application sees a
    /// complete in-order set.
    ///
    /// Used for TOPIC and INSTANCE access_scope (each writer's set is
    /// committed independently of other writers in the same Publisher).
    /// GROUP-scope sets are aggregated by `group_coherent_buffer` so the
    /// commit barrier waits for every writer in the publisher group
    /// before flushing.
    pub(super) coherent_buffer: Mutex<HashMap<[u8; 16], Vec<BufferedCoherentSample>>>,
    /// What each writer's changes said of where the coherent sets staged in
    /// `coherent_buffer` end (`SetEnds`), kept until those sets commit.
    pub(super) pending_coherent_end: Mutex<HashMap<[u8; 16], SetEnds>>,
    /// Held by whoever decides and commits the sets staged in
    /// `coherent_buffer` (`try_commit_sets`): one decision at a time, and
    /// what a commit releases is delivered in the order it left the gate.
    commit_lock: Mutex<()>,
    /// GROUP-scope coherent aggregation buffer, keyed by
    /// `(participant_prefix, publisher_entity_id, group_sn)` per
    /// DDS v1.4 sec. 2.2.3.6 GROUP access_scope + RTPS v2.5 sec. 9.3.2.1.
    /// The first 12 bytes of the writer GUID identify the Participant
    /// and `publisher_entity_id` (extracted from `PID_GROUP_ENTITY_ID`
    /// in inline QoS) identifies the Publisher within that Participant.
    /// Both are required: two Publishers in the same Participant can
    /// legitimately reuse the same GSN, so keying only by the prefix
    /// would alias their sets. When the wire doesn't carry
    /// `PID_GROUP_ENTITY_ID` we fall back to `[0; 4]` as a distinct
    /// "unspecified publisher" sentinel so an emitter that never
    /// advertises the PID doesn't collide with one that does.
    pub(super) group_coherent_buffer: Mutex<HashMap<GroupSetKey, GroupCoherentSet>>,
    /// Discovery's writers of a remote Publisher, for the GROUP sets of
    /// the spec dialect (`GroupRoster`). `None` (a reader without
    /// discovery): such a set is decided by the rule of the other dialects.
    pub(super) group_roster: std::sync::OnceLock<Arc<dyn GroupRoster>>,
    /// Discovery's last answer for each remote Publisher (`group_roster`),
    /// by participant prefix and Publisher EntityId: a writer discovery
    /// forgot (its participant's SPDP dispose, its SEDP dispose, read on
    /// the discovery thread) is still the reader's writer until its
    /// departure reaches the reader, behind its data (`engine::departures`,
    /// `forget_writer_in_group_sets`). `roster_answer`.
    pub(super) roster_seen: Mutex<RosterSeen>,
    /// What the reader knows of its GROUP writers' GSNs (`WriterGsns`).
    pub(super) writer_gsns: Mutex<HashMap<[u8; 16], WriterGsns>>,
    /// `GROUP_ROSTER_WAIT` in milliseconds; tests shorten it.
    pub(super) group_roster_wait_ms: std::sync::atomic::AtomicU64,
    /// `BEST_EFFORT_OVERTAKE_WAIT`, settable by a test.
    pub(super) best_effort_wait_ms: std::sync::atomic::AtomicU64,
    /// The best-effort sets waiting for a member their end overtook, by
    /// (writer, the set's or the writer's part's first SN): since when
    /// (`best_effort_wait_over`). Their count, read without the lock.
    best_effort_waits: Mutex<HashMap<([u8; 16], u64), std::time::Instant>>,
    best_effort_waiting: std::sync::atomic::AtomicUsize,
    /// A GROUP set waits for a writer's gate to reach its part
    /// (`try_flush_group_sets`): the next change delivered past a gate
    /// decides it again.
    group_sets_await_gate: std::sync::atomic::AtomicBool,
    /// The writers a set of which waits for the writer's gate to reach it
    /// (`try_commit_sets`), and whether there is any, read without the
    /// lock: the writer's next change delivered decides it again.
    pub(super) writer_sets_await_gate: Mutex<HashSet<[u8; 16]>>,
    writer_sets_awaiting: std::sync::atomic::AtomicBool,
    /// Per-writer delivery serialisation mutex. Released samples from a
    /// given writer GUID are pushed to the ring under this lock -- keeps
    /// per-writer FIFO order without holding the reorder gate (which
    /// gates ALL writers and would block on user listener callbacks).
    /// Lookup is constant-time; the outer Mutex is held only briefly to
    /// fetch / insert the per-writer Arc<Mutex<()>>.
    delivery_locks: Mutex<std::collections::HashMap<[u8; 16], Arc<Mutex<()>>>>,
    /// Held around each push into `ring`, which has one producer
    /// (`IndexRing`), while this reader is delivered on several threads:
    /// the router thread (DATA), the control thread (what a HEARTBEAT or a
    /// GAP releases from the gate), a TCP or QUIC routing thread, and the
    /// application thread behind a coherent-presentation barrier. The
    /// per-writer delivery locks order one writer's pushes, not two
    /// writers'. Only the push is held: never a listener. It guards what a
    /// full-ring compaction learned of the ring's entries ([`RingKeys`]),
    /// which every push makes stale.
    push_lock: Mutex<RingKeys>,
    /// Reusable buffer for the re-encode of each received sample before it
    /// enters the slab, kept all zero at rest (see `dds::encode_scratch`):
    /// replaces a fresh zeroed 64 KiB allocation per received sample.
    reencode_scratch: Mutex<Vec<u8>>,
    /// What the head of a gap is taken to need when held storage keeps its
    /// room (`SlabPool::hold`): the missing sample's size is not on the
    /// wire, and the samples this reader stores lately are its best
    /// estimate. A larger sample raises it at once; each smaller one lowers
    /// it by an eighth of the difference (rounded up), so that one large
    /// sample does not keep it high for the reader's lifetime: kept that
    /// high, it left no room to hold anything, for good. A head larger than
    /// the estimate still finds storage, past the heap tier's ceiling by
    /// one sample (`rt::Claim::Head`).
    head_estimate: AtomicUsize,
    /// The budget the coherent sets this reader stages take their storage
    /// from (`staging_budget`): sized from its QoS by the builder
    /// (`StagingBudget::samples_for`), `MAX_STAGED_PER_WRITER` samples a
    /// set otherwise.
    pub(super) staging: Arc<super::staging_budget::StagingBudget>,
    /// Shared match-notification registry (same Arc the DiscoveryFsm holds).
    /// Carries, for each remote writer, the local readers that refuse it on
    /// its type (DDS-XTypes v1.3 sec. 7.6.3.4.3) or its QoS (DDS v1.4
    /// Sec.2.2.3). The data path consults it (`writer_refused`) to drop
    /// what a writer this reader is not matched with sends, deterministically,
    /// instead of relying on a notification winning the race against data
    /// arrival. None on the participant-less / intra-process path.
    match_registry: Option<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
    /// This reader's entry in `match_registry`, set by the builder once the
    /// entry is registered: the data-plane gate is per (writer, reader)
    /// pair, and this is the reader half of the key.
    pub(super) match_entry: Arc<std::sync::OnceLock<u64>>,
    /// The liveliness of the writers this reader matches, renewed by the
    /// data of a MANUAL one (`ReaderLiveliness::on_data`). None without a
    /// participant liveliness.
    pub(super) liveliness: Option<Arc<crate::dds::liveliness::ReaderLiveliness>>,
    /// The registration a fixture made by hand
    /// (`register_match_entry_for_test`), held as the reader holds its own.
    #[cfg(test)]
    test_match_token: std::sync::OnceLock<crate::dds::match_notification::MatchToken>,
    /// This reader's handle on the reliable-reader proxy registry (the same
    /// Arc<DashMap> the ControlHandler holds). On every admitted user DATA the
    /// subscriber calls `on_data(writer_guid, seq)` so the contiguous-prefix
    /// `low_mark` of THIS reader's proxy for that writer reflects what THIS
    /// reader received; the ControlHandler then builds this reader's ACKNACK
    /// base + bitmap from it (RTPS v2.5 Sec.8.4.12). Without this
    /// the reliable reader state never learns what arrived and the ACKNACK
    /// base stays frozen, starving late-joiner / strict-reliable history.
    /// `None` for BEST_EFFORT / participant-less readers.
    ack_credit: Option<crate::core::reader::ReaderAckCredit>,
    /// Cumulative SAMPLE_REJECTED status (DDS v1.4 Sec.2.2.4.1.9,
    /// specifically REJECTED_BY_SAMPLES_LIMIT): raised when a sample this
    /// reader already accepted at the RTPS layer -- dedup'd and credited to
    /// the control-plane proxy registry in `deliver_admitted_sample`,
    /// before the reorder gate -- is then discarded in `process_admitted`
    /// because this reader's own ring is full or the process-wide slab
    /// budget is exhausted. The writer is never NACKed for it (the sample
    /// WAS received), so this status, the telemetry counters, and (if
    /// attached) the listener are the only visibility into the loss.
    ///
    /// Shared (same `Arc`) with the owning `DataReader`, wired up in
    /// `ReaderBuilder::build` exactly like `status_condition`: the
    /// `DataReader::get_sample_rejected_status` accessor reads and resets
    /// this same state, so a read from either side sees the other's
    /// writes. `total_count_change` resets to 0 the moment the status is
    /// delivered -- a listener call or a `get_sample_rejected_status`
    /// read, DDS v1.4 Sec.2.2.4.2.1 -- via `report_sample_rejected`, which
    /// also serializes concurrent rejections through
    /// the status lock, whose snapshots reach the listener in the order
    /// they were taken (`rejected_notices`), so two racing admission
    /// callers (`process_admitted`'s ring-full and slab-exhausted exits)
    /// can never over-deliver or erase each other's delta. SAMPLE_LOST is a
    /// different status (a GAP or writer-side history eviction) and is
    /// not touched here.
    sample_rejected: Arc<Mutex<SampleRejectedStatus>>,
    /// SAMPLE_LOST, shared with the reader (the builder sets it; see
    /// `report_sample_lost`).
    pub(super) sample_lost: Arc<Mutex<crate::dds::listener::SampleLostStatus>>,
    /// The SAMPLE_REJECTED and SAMPLE_LOST snapshots for the listener, in
    /// the order they were taken (`notices::Ordered`): queued under their
    /// status lock, told with no lock of the reader held.
    rejected_notices: Arc<super::notices::Ordered>,
    lost_notices: Arc<super::notices::Ordered>,
    /// Reader-requested DataRepresentationQosPolicy accepted set (the codes
    /// from PID_DATA_REPRESENTATION: 0x0000 = XCDR1, 0x0002 = XCDR2). Empty
    /// means "no restriction" (HDDS accepts any wire form). When non-empty,
    /// the data path drops any sample whose wire CDR version is not in this
    /// set (DDS-XTypes v1.3 sec. 7.6.3.1.2): an explicit `-x 2` reader must not
    /// accept XCDR1-encoded data and vice versa. This is enforced per-sample
    /// (race-free) so an incompatible writer's samples never reach the
    /// application regardless of discovery-vs-data timing; the matching
    /// on_requested_incompatible_qos notification is fired separately by the
    /// match-notification path.
    accepted_data_repr: Vec<u16>,
    /// This reader's REAL XCDR1 decode capability (`DDS::encodes_xcdr1_natively`
    /// via `Xcdr1Encoding::of::<T>()`), resolved once here at construction --
    /// never looked up per message. A backstop independent of matching and of
    /// `accepted_data_repr` (DDS-XTypes v1.3 Sec.7.6.3.1.1): the builder
    /// refuses to create a reader that explicitly requests XCDR1 while its
    /// type cannot decode it (`resolve_reader_data_representation`), so in
    /// the steady state this can never fire; it exists so an XCDR1-encoded
    /// sample is dropped here, counted and logged, rather than handed to a
    /// `T::decode` that silently reads the XCDR2 layout under an XCDR1
    /// header, should that invariant ever be bypassed (a future reader
    /// construction path, a QoS mutation seam, a programming error).
    xcdr1: crate::dds::cdr_negotiation::Xcdr1Encoding,
    /// This reader's requested PARTITION QoS (DDS v1.4 sec. 2.2.3.13). When the
    /// reader left it at the default (empty) partition the partition data-plane
    /// gate is a no-op -- default-partition readers match all default-partition
    /// writers and the rest of the suite is unaffected. When the reader
    /// requested an explicit partition, the data path drops samples from any
    /// writer whose partition does not intersect this one, resolved per-writer
    /// at delivery time (race-free vs the SEDP-vs-data arrival order).
    reader_partition: crate::qos::partition::Partition,
    /// Per-writer partition verdict (`true` = deliver), published so the
    /// data path reads it without a lock. Only positive resolutions (writer
    /// already discovered via SEDP) are cached; an as-yet-unresolved writer
    /// is re-checked on each sample until its SEDP is processed. Keyed by
    /// the 16-byte writer GUID.
    partition_verdict: PartitionVerdicts,
    /// This reader's requested OWNERSHIP kind (DDS v1.4 sec. 2.2.3.11). Unlike
    /// PARTITION there is no "default means skip the gate" case: SHARED is
    /// as concrete a requested kind as EXCLUSIVE, so the ownership data-plane
    /// gate always runs. Set once at construction from the reader's built QoS.
    reader_ownership: crate::qos::ownership::OwnershipKind,
    /// Cached per-writer OWNERSHIP-compatibility verdict (`true` = deliver).
    /// Same shape as `partition_verdict`: only positive resolutions (writer
    /// already discovered via SEDP) are cached; an as-yet-unresolved writer
    /// is re-checked on each sample until its SEDP is processed. Keyed by the
    /// 16-byte writer GUID.
    ownership_verdict: Mutex<std::collections::HashMap<[u8; 16], bool>>,
    /// Samples DEFERRED by the OWNERSHIP gate because their writer was not
    /// yet resolvable via SEDP (`OwnershipGate::Unresolved`). Bounded (see
    /// `OwnershipPending` caps). Flushed in arrival order, or discarded,
    /// the moment the writer's verdict resolves -- via the next live sample
    /// from that writer (lazy) or via `on_writer_qos_resolved` (proactive,
    /// kicked by the SEDP handler). Discarding here instead would lose
    /// one-shot TRANSIENT_LOCAL history bursts racing their own SEDP: the
    /// drop happens above the RTPS reliability layer, so the writer never
    /// retransmits and that history is lost.
    ownership_pending: Mutex<OwnershipPending>,
    /// The participant's engine TopicRegistry: the PRIMARY resolution source
    /// for the OWNERSHIP and PARTITION gates (recorded at SEDP
    /// parse time and never purged). The discovery FSM registry is only the
    /// fallback: its endpoints are removed by the unconfirmed-participant
    /// zombie sweep, and a slow-announcing vendor (one SPDP inside the
    /// probation window) never re-sends its reliably-ACKed SEDP -- resolving
    /// through the FSM alone blackholes such a writer's data forever.
    /// `None` on the participant-less /
    /// intra-process path.
    topic_registry: Option<Arc<crate::engine::TopicRegistry>>,
    /// Cross-reader coherent presentation barrier, shared with every
    /// coherent reader attached to the same Subscriber entity. `Some` only
    /// for coherent-access readers built through
    /// `ReaderBuilder::subscriber`; when present, a completed per-topic
    /// coherent set is DEPOSITED here (whole, keyed by remote publisher)
    /// instead of being pushed to the ring, and released to the ring only
    /// once every group member fed by that publisher has an aligned set
    /// (see the `coherent_barrier` module docs). `None` keeps the direct
    /// commit-to-ring delivery, so non-coherent and unattached readers are
    /// byte-unchanged.
    coherent_barrier: Option<Arc<CoherentPresentationBarrier>>,
    /// This reader's member id within `coherent_barrier` (the deposit slot).
    barrier_member: Option<MemberId>,
    pub(super) wire_reliable: bool,
    pub(super) wire_durable: bool,
    pub(super) wire_bindings: Option<std::sync::Weak<super::runtime::ReaderBindings>>,
    /// The lifespans of the writers that left while samples of theirs may
    /// still be in `ring`, shared with the `DataReader`, which expires those
    /// samples by them.
    pub(super) departed_lifespans: Arc<DepartedLifespans>,
    pub(super) _phantom: core::marker::PhantomData<T>,
    /// The coherent sets discarded because they can never be whole, by
    /// writer (start -> last, at most `MAX_DISCARDED_SETS` each, the
    /// lowest dropped first): a sample of one that lands after the set was
    /// discarded is of a set that no longer exists, and is stepped over,
    /// never staged under it again (`discarded_member`).
    discarded_sets: Mutex<HashMap<[u8; 16], BTreeMap<u64, u64>>>,
    /// The GROUP sets discarded (the keys, and the order they were
    /// discarded in, at most `MAX_DISCARDED_GROUP_SETS`): a sample or an end
    /// of one that lands afterwards is stepped over, never staged under the
    /// set again, where it started a set of its own that delivered the
    /// discarded set in part, or that nothing ever closed.
    discarded_group_sets: Mutex<(
        HashSet<GroupSetKey>,
        std::collections::VecDeque<GroupSetKey>,
    )>,
    /// The coherent sets rejected for their storage (`reject_staged_set`),
    /// each as a constant-size record. Taken after the staging's locks
    /// (`coherent_buffer`, `group_coherent_buffer`) when both are held.
    rejected_sets: Mutex<RejectedSets>,
    coherent_admissions: Mutex<HashSet<([u8; 16], u64)>>,
    /// The writers that left (`on_writer_dispose`) and were not heard
    /// again since (`has_left`): what lands from one meanwhile, sent before
    /// it left, is dropped at the door, holding nothing.
    departed: parking_lot::RwLock<HashMap<[u8; 16], Departed>>,
    /// How many writers `departed` holds: the door reads it alone, lock
    /// free, while no writer is gone (`has_left`).
    departed_count: std::sync::atomic::AtomicUsize,
    /// How long a departure is kept, in milliseconds (`DEPARTED_KEEP`;
    /// tests shorten it).
    departed_keep_ms: std::sync::atomic::AtomicU64,
    /// Bumped by every departure, once its writer is in `departed`: a
    /// delivery reads it at the door and again under the gate's lock, and
    /// looks the writer up again only when it moved (`deliver_sample`).
    departures: std::sync::atomic::AtomicU64,
    /// Each writer's last departure: the `departures` count it reached and
    /// when (kept `DEPARTED_KEEP`). Unlike `departed`, a re-announcement
    /// does not forget it, so a DATA read at the door before that departure
    /// is refused even once the writer is matched again (`left_since`).
    left_counts: parking_lot::Mutex<HashMap<[u8; 16], (u64, std::time::Instant)>>,
    /// When the oldest departure in `departed` expires, in milliseconds
    /// since `departed_base` (`u64::MAX`: none): the door forgets expired
    /// departures, all at once, only once one is due (`has_left_slow`).
    departed_purge_due_ms: std::sync::atomic::AtomicU64,
    departed_base: std::time::Instant,
    /// Tests only: run once by the next full-ring compaction, with the ring
    /// popped and nothing pushed back yet.
    #[cfg(test)]
    compaction_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: observe completed delivery outside the delivery locks.
    #[cfg(test)]
    pub(super) delivered_hook: Mutex<Option<PushedHook>>,
    /// Tests only: pause one discovery deferral or queue flush.
    #[cfg(test)]
    pub(super) pending_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: pause a refused value after its BEST_EFFORT gate step.
    #[cfg(test)]
    pub(super) refusal_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: choose a competing arrival before refusal bookkeeping.
    #[cfg(test)]
    pub(super) refusal_entry_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: pause DATA after routing, before its pair verdict.
    #[cfg(test)]
    pub(super) pair_gate_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: run once right after the router's framing decision.
    #[cfg(test)]
    pub(super) framing_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: run once when a set next finds too little room, before
    /// the room is marked as waited for.
    #[cfg(test)]
    refused_room_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: run once by `heartbeat_verdict` right before the record
    /// of the same writer goes back.
    #[cfg(test)]
    pub(super) verdict_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: run once by `heartbeat_verdict` once the door is open.
    #[cfg(test)]
    pub(super) opened_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: run once by the next delivery past the door, right
    /// before it takes the gate's lock, or the next coherent change right
    /// before it is admitted.
    #[cfg(test)]
    pub(super) admission_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: how many coherent members were decoded and stored to
    /// be staged (`prepare_staged`).
    #[cfg(test)]
    pub(super) staged_prepares: AtomicUsize,
    /// Tests only: run once between a coherent change's admission and its
    /// push into the per-writer staging buffer.
    #[cfg(test)]
    pub(super) staging_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: run once between a coherent change's admission and the
    /// gate's look at it (`ReorderGate::hold_staged`).
    #[cfg(test)]
    pub(super) hold_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    pub(super) wire_claim_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Tests only: run with each sample's sequence number once it is in
    /// the ring, under the locks of its delivery (where a listener was
    /// called before `notices`): the point a test pauses a delivery at.
    #[cfg(test)]
    pub(super) pushed_hook: Mutex<Option<PushedHook>>,
    /// Tests only: how many ring entries full-ring compactions decoded.
    #[cfg(test)]
    compaction_decodes: std::sync::atomic::AtomicUsize,
}

impl<T: DDS> ReaderSubscriber<T> {
    /// A parked TIME_BASED_FILTER sample's window ended: tell the
    /// application there is data to take, as an arrival does. The sample is
    /// not touched here; it enters the history at the application's next
    /// access (`SampleCache`), which this wakes.
    pub(super) fn filter_window_ended(&self) {
        self.status_condition
            .raise_data_available_shared(WakeWord::Network.index());
        if let Some(guard) = &self.participant_guard {
            guard.set_trigger_value(true);
        }
        if let Some(listener) = self.listener.get(StatusMask::DATA_AVAILABLE) {
            super::notices::notify(move || listener.on_data_available_notification());
        }
    }
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub fn new(
        topic: String,
        ring: Arc<rt::IndexRing>,
        status_condition: Arc<StatusCondition>,
        participant_guard: Option<Arc<GuardCondition>>,
        content_filter: Option<FilterEvaluator>,
        listener: Option<Arc<dyn DataReaderListener<T>>>,
        dispose_events: Arc<DisposeQueue>,
        reorder: Arc<Mutex<ReorderGate>>,
    ) -> Self {
        Self::new_with_coherent(
            topic,
            ring,
            status_condition,
            participant_guard,
            content_filter,
            listener,
            dispose_events,
            reorder,
            CoherentConfig::default(),
            None,
            None,
            // Self-contained, not shared with any DataReader: bare `new()`
            // callers build a standalone subscriber with no reader to share
            // status with. Callers that need `DataReader::get_sample_rejected_status`
            // to see this subscriber's rejections use `new_with_coherent`
            // directly with a shared Arc (see the reader test seam
            // `sample_rejected_for_test`).
            Arc::new(Mutex::new(SampleRejectedStatus::default())),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            None,
            None,
            None,
            #[cfg(feature = "security")]
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_with_coherent(
        topic: String,
        ring: Arc<rt::IndexRing>,
        status_condition: Arc<StatusCondition>,
        participant_guard: Option<Arc<GuardCondition>>,
        content_filter: Option<FilterEvaluator>,
        listener: Option<Arc<dyn DataReaderListener<T>>>,
        dispose_events: Arc<DisposeQueue>,
        reorder: Arc<Mutex<ReorderGate>>,
        coherent_cfg: CoherentConfig,
        match_registry: Option<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
        ack_credit: Option<crate::core::reader::ReaderAckCredit>,
        sample_rejected: Arc<Mutex<SampleRejectedStatus>>,
        accepted_data_repr: Vec<u16>,
        reader_partition: crate::qos::partition::Partition,
        reader_ownership: crate::qos::ownership::OwnershipKind,
        topic_registry: Option<Arc<crate::engine::TopicRegistry>>,
        coherent_barrier: Option<Arc<CoherentPresentationBarrier>>,
        barrier_member: Option<MemberId>,
        #[cfg(feature = "security")] security: Option<Arc<crate::security::SecurityPluginSuite>>,
    ) -> Self {
        if participant_guard.is_some() {
            log::debug!(
                "[READER-SUB] participant guard attached for topic='{}'",
                topic
            );
        } else {
            log::debug!("[READER-SUB] no participant guard for topic='{}'", topic);
        }
        if content_filter.is_some() {
            log::debug!("[READER-SUB] content filter attached for topic='{}'", topic);
        }
        if coherent_cfg.coherent_access {
            log::debug!(
                "[READER-SUB] coherent_access enabled topic='{}' group_scope={}",
                topic,
                coherent_cfg.is_group_scope
            );
        }
        let departed_lifespans = Arc::new(DepartedLifespans::new());
        Self {
            topic,
            created_at: crate::engine::subscriber::join_clock_tick(),
            ring,
            status_condition,
            participant_guard,
            #[cfg(feature = "security")]
            security,
            #[cfg(feature = "security")]
            protection: std::sync::Mutex::new(Default::default()),
            #[cfg(feature = "security")]
            cleartext_refused: std::sync::atomic::AtomicU64::new(0),
            #[cfg(feature = "security")]
            admission_gate: std::sync::OnceLock::new(),
            seq_window: Mutex::new(SeqWindow::new()),
            seen_seqs: Mutex::new(SeenSeqs::default()),
            seen_seqs_by_writer: Mutex::new(std::collections::HashMap::new()),
            content_filter,
            time_filter_checkers: Arc::new(Mutex::new(HashMap::new())),
            time_based_filter: crate::qos::time_based_filter::TimeBasedFilter::default(),
            dropped: Arc::new(AtomicU64::new(0)),
            filter_waker: None,
            field_extractor: None,
            reader_entity_id: None,
            room: None,
            listener: Arc::new(ReaderListenerSlot::new(listener)),
            dispose_events,
            reorder,
            writer_instances: Arc::new(ReaderRegistrations::new(
                reader_ownership == crate::qos::ownership::OwnershipKind::Exclusive,
                None,
                topic_registry.clone(),
            )),
            coherent_cfg,
            coherent_buffer: Mutex::new(HashMap::new()),
            pending_coherent_end: Mutex::new(HashMap::new()),
            commit_lock: Mutex::new(()),
            group_coherent_buffer: Mutex::new(HashMap::new()),
            group_roster: std::sync::OnceLock::new(),
            roster_seen: Mutex::new(HashMap::new()),
            writer_gsns: Mutex::new(HashMap::new()),
            group_roster_wait_ms: std::sync::atomic::AtomicU64::new(
                u64::try_from(GROUP_ROSTER_WAIT.as_millis()).unwrap_or(u64::MAX),
            ),
            best_effort_wait_ms: std::sync::atomic::AtomicU64::new(
                u64::try_from(BEST_EFFORT_OVERTAKE_WAIT.as_millis()).unwrap_or(u64::MAX),
            ),
            best_effort_waits: Mutex::new(HashMap::new()),
            best_effort_waiting: std::sync::atomic::AtomicUsize::new(0),
            group_sets_await_gate: std::sync::atomic::AtomicBool::new(false),
            writer_sets_await_gate: Mutex::new(HashSet::new()),
            writer_sets_awaiting: std::sync::atomic::AtomicBool::new(false),
            delivery_locks: Mutex::new(std::collections::HashMap::new()),
            push_lock: Mutex::new(RingKeys::default()),
            reencode_scratch: Mutex::new(Vec::new()),
            head_estimate: AtomicUsize::new(0),
            staging: super::staging_budget::StagingBudget::new(MAX_STAGED_PER_WRITER),
            match_registry,
            match_entry: Arc::new(std::sync::OnceLock::new()),
            liveliness: None,
            #[cfg(test)]
            test_match_token: std::sync::OnceLock::new(),
            ack_credit,
            sample_rejected,
            sample_lost: Arc::new(Mutex::new(crate::dds::listener::SampleLostStatus::default())),
            rejected_notices: Arc::default(),
            lost_notices: Arc::default(),
            accepted_data_repr,
            xcdr1: crate::dds::cdr_negotiation::Xcdr1Encoding::of::<T>(),
            reader_partition,
            partition_verdict: PartitionVerdicts::new(),
            reader_ownership,
            ownership_verdict: Mutex::new(std::collections::HashMap::new()),
            ownership_pending: Mutex::new(OwnershipPending::default()),
            topic_registry,
            coherent_barrier,
            barrier_member,
            wire_reliable: false,
            wire_durable: false,
            wire_bindings: None,
            departed_lifespans,
            _phantom: core::marker::PhantomData,
            departed: parking_lot::RwLock::new(HashMap::new()),
            departed_count: std::sync::atomic::AtomicUsize::new(0),
            departed_keep_ms: std::sync::atomic::AtomicU64::new(
                u64::try_from(DEPARTED_KEEP.as_millis()).unwrap_or(u64::MAX),
            ),
            departures: std::sync::atomic::AtomicU64::new(0),
            left_counts: parking_lot::Mutex::new(HashMap::new()),
            departed_purge_due_ms: std::sync::atomic::AtomicU64::new(u64::MAX),
            departed_base: std::time::Instant::now(),
            discarded_sets: Mutex::new(HashMap::new()),
            discarded_group_sets: Mutex::new((HashSet::new(), std::collections::VecDeque::new())),
            rejected_sets: Mutex::new(RejectedSets::default()),
            coherent_admissions: Mutex::new(HashSet::new()),
            #[cfg(test)]
            compaction_hook: Mutex::new(None),
            #[cfg(test)]
            pending_hook: Mutex::new(None),
            #[cfg(test)]
            delivered_hook: Mutex::new(None),
            #[cfg(test)]
            refusal_hook: Mutex::new(None),
            #[cfg(test)]
            refusal_entry_hook: Mutex::new(None),
            #[cfg(test)]
            pair_gate_hook: Mutex::new(None),
            #[cfg(test)]
            framing_hook: Mutex::new(None),
            #[cfg(test)]
            refused_room_hook: Mutex::new(None),
            #[cfg(test)]
            verdict_hook: Mutex::new(None),
            #[cfg(test)]
            opened_hook: Mutex::new(None),
            #[cfg(test)]
            admission_hook: Mutex::new(None),
            #[cfg(test)]
            staged_prepares: AtomicUsize::new(0),
            #[cfg(test)]
            staging_hook: Mutex::new(None),
            #[cfg(test)]
            hold_hook: Mutex::new(None),
            #[cfg(test)]
            wire_claim_hook: Mutex::new(None),
            #[cfg(test)]
            pushed_hook: Mutex::new(None),
            #[cfg(test)]
            compaction_decodes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub(super) fn barrier_member_for_test(&self) -> Option<MemberId> {
        self.barrier_member
    }

    fn note_wire_control_prefix(
        &self,
        writer: [u8; 16],
        seq: u64,
        order: Option<crate::engine::router::OrderedGroupChange>,
    ) {
        let Some(change) = order else { return };
        if self
            .ack_credit
            .as_ref()
            .and_then(|credit| credit.settled(&writer))
            .is_some_and(|through| through >= seq)
        {
            if let Some((barrier, member)) = self.coherent_barrier.as_ref().zip(self.barrier_member)
            {
                barrier.wire_control_prefix(member, writer, change);
            }
        }
    }

    #[cfg(test)]
    #[inline(always)]
    fn group_arrival_scope(&self, writer: [u8; 16], seq: Option<u64>) -> Option<GroupArrivalScope> {
        self.wire_bindings.as_ref()?;
        if GroupArrivalScope::present(writer, seq) {
            return None;
        }
        let stamp = self
            .topic_registry
            .as_ref()
            .and_then(|r| r.capture_group_arrival(&writer));
        Some(GroupArrivalScope::enter(writer, seq, stamp))
    }

    fn apply_group_arrival(
        &self,
        writer: [u8; 16],
        expected: Option<&crate::core::reader::AdmissionFrame>,
    ) -> bool {
        let Some(registry) = &self.topic_registry else {
            return true;
        };
        let Some(stamp) = GroupArrivalScope::captured(writer) else {
            return true;
        };
        let pending = self
            .ownership_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(expected) = expected {
            if !pending.incarnations.get(&writer).is_some_and(|current| {
                std::ptr::eq(current.as_ref(), expected) && current.load(Ordering::Acquire)
            }) {
                return false;
            }
        }
        registry.note_group_writer_alive_stamped(&writer, &stamp)
    }

    fn capture_wire_order(
        &self,
        writer: [u8; 16],
        seq: u64,
    ) -> Option<crate::engine::router::OrderedGroupChange> {
        self.wire_bindings.as_ref()?;
        crate::engine::router::route_ordered_group(writer, seq)
    }

    /// Whether `seq` of `writer` carries GROUP metadata this reader cannot
    /// order yet (the writer's class or Publisher unknown, typically before
    /// discovery holds the writer): the change is then dropped
    /// unacknowledged, and the writer sends it again. It is filed as owed
    /// (from `set_start` for a coherent set's member), so the resend is not
    /// judged history by a join point taken from a later change
    /// (`ReorderGate::on_dropped_without_group_context`).
    fn wire_context_pending(&self, writer: [u8; 16], seq: u64, set_start: Option<u64>) -> bool {
        if !(self.wire_bindings.is_some()
            && crate::engine::router::route_order_needs_context(writer, seq))
        {
            return false;
        }
        let discovered = !self.writer_undiscovered(&writer);
        self.reorder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .on_dropped_without_group_context(writer, seq, set_start, discovered);
        if !discovered {
            self.recheck_discovered(&writer);
        }
        true
    }

    fn order_gap_consumed(&self, writer: [u8; 16], end: u64) -> bool {
        let Some((barrier, member)) = self.coherent_barrier.as_ref().zip(self.barrier_member)
        else {
            return false;
        };
        let Some(entity) = self
            .topic_registry
            .as_ref()
            .and_then(|r| r.writer_spec_group(&writer))
        else {
            return false;
        };
        let mut publisher = writer;
        publisher[12..].copy_from_slice(&entity);
        barrier.wire_gap_consumed(publisher, member, end)
    }

    fn refresh_order_gap(&self, writer: [u8; 16], ledger: &LossLedger) {
        let end = ledger.authority.order_gap_end();
        if end != 0 && self.order_gap_consumed(writer, end) {
            ledger.authority.complete_order_gap(end);
        }
    }

    /// Core receipt callbacks do not call user code while this identity is held.
    fn with_current_loss_frame<R>(
        &self,
        writer: [u8; 16],
        ledger: &LossLedger,
        apply: impl FnOnce() -> R,
    ) -> Option<R> {
        if self.wire_bindings.as_ref().is_some_and(|bindings| {
            bindings
                .upgrade()
                .is_none_or(|bindings| bindings.is_closed())
        }) {
            return None;
        }
        let pending = self
            .ownership_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !pending.incarnations.get(&writer).is_some_and(|current| {
            Arc::ptr_eq(current, &ledger.incarnation) && current.load(Ordering::Acquire)
        }) {
            return None;
        }
        Some(apply())
    }

    #[inline(always)]
    fn register_wire_order(
        &self,
        writer: [u8; 16],
        seq: u64,
        prepared: &super::admission::Prepared,
        order: Option<crate::engine::router::OrderedGroupChange>,
        admit: Admit<'_>,
    ) -> Option<super::wire_order::OrderToken> {
        let bindings = self.wire_bindings.as_ref()?;
        self.register_group_wire_order(bindings, writer, seq, prepared, order, admit)
    }

    #[cold]
    #[inline(never)]
    fn register_group_wire_order(
        &self,
        bindings: &std::sync::Weak<super::runtime::ReaderBindings>,
        writer: [u8; 16],
        seq: u64,
        prepared: &super::admission::Prepared,
        order: Option<crate::engine::router::OrderedGroupChange>,
        admit: Admit<'_>,
    ) -> Option<super::wire_order::OrderToken> {
        let order = order?;
        let incarnation = match admit {
            Admit::Direct(_, incarnation) | Admit::Pending(incarnation) => Some(incarnation),
            _ => None,
        };
        #[cfg(test)]
        {
            let hook = self
                .wire_claim_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
        let loss = self.wire_loss_ledger(writer, incarnation)?;
        if !loss.incarnation.load(Ordering::Acquire) {
            if matches!(prepared, super::admission::Prepared::Stored(_)) {
                self.report_sample_lost(loss.record(seq));
            }
            return None;
        }
        if !self.apply_group_arrival(writer, Some(loss.incarnation.as_ref())) {
            return None;
        }
        if prepared.slab_handle().is_none() && !loss.classify_control(seq) {
            return None;
        }
        let token = super::wire_order::OrderToken::new(
            bindings,
            prepared.slab_handle(),
            order,
            self.coherent_barrier.as_ref()?,
            self.barrier_member?,
            self.data_lifespan(
                prepared,
                writer,
                crate::engine::router::route_source_ts_ns(),
            ),
            super::wire_order::LossContext {
                writer,
                seq,
                reporter: loss.clone(),
            },
        );
        self.report_sample_lost(loss.take_pending());
        token
    }

    fn coherent_history_repair(
        &self,
        change: crate::engine::router::OrderedGroupChange,
        first: Option<u64>,
    ) -> Option<super::wire_order::CoherentRepair> {
        let first = first?;
        let key = (
            change.publisher[..12].try_into().ok()?,
            change.publisher[12..].try_into().ok()?,
            first,
        );
        if self.group_set_discarded(&key) {
            return None;
        }
        let (barrier, member) = self.coherent_barrier.as_ref().zip(self.barrier_member)?;
        barrier.wire_history_repair(change, member, first)
    }

    // Admission includes the source change, replay ownership and captured frame.
    #[allow(clippy::too_many_arguments)]
    fn register_coherent_wire_order(
        &self,
        writer: [u8; 16],
        seq: u64,
        prepared: &super::admission::Prepared,
        change: Option<crate::engine::router::OrderedGroupChange>,
        first: Option<u64>,
        repair: Option<super::wire_order::CoherentRepair>,
        incarnation: Option<&crate::core::reader::AdmissionFrame>,
    ) -> Option<super::wire_order::OrderToken> {
        self.wire_bindings.as_ref()?;
        let change = change?;
        let first = first?;
        #[cfg(test)]
        {
            let hook = self
                .wire_claim_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
        let loss = self.wire_loss_ledger(writer, incarnation)?;
        if !loss.incarnation.load(Ordering::Acquire) {
            if matches!(prepared, super::admission::Prepared::Stored(_)) {
                self.report_sample_lost(loss.record(seq));
            }
            return None;
        }
        if !self.apply_group_arrival(writer, Some(loss.incarnation.as_ref())) {
            return None;
        }
        if prepared.slab_handle().is_none() && !loss.classify_control(seq) {
            return None;
        }
        let token = super::wire_order::OrderToken::new_coherent(
            self.wire_bindings.as_ref()?,
            prepared.slab_handle(),
            change,
            self.coherent_barrier.as_ref()?,
            self.barrier_member?,
            first,
            repair,
            self.data_lifespan(
                prepared,
                writer,
                crate::engine::router::route_source_ts_ns(),
            ),
            super::wire_order::LossContext {
                writer,
                seq,
                reporter: loss.clone(),
            },
        );
        self.report_sample_lost(loss.take_pending());
        token
    }

    fn wire_loss_ledger(
        &self,
        writer: [u8; 16],
        incarnation: Option<&crate::core::reader::AdmissionFrame>,
    ) -> Option<Arc<LossLedger>> {
        let mut pending = self
            .ownership_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(expected) = incarnation {
            if let Some(ledger) = pending
                .losses
                .get(&writer)
                .filter(|l| std::ptr::eq(expected, l.incarnation.as_ref()))
            {
                return Some(ledger.clone());
            }
            if let Some(ledger) = self
                .departed
                .read()
                .get(&writer)
                .and_then(|e| e.losses.clone())
                .filter(|l| std::ptr::eq(expected, l.incarnation.as_ref()))
            {
                return Some(ledger);
            }
        }
        pending.loss_ledger(writer, incarnation, self.ack_credit.as_ref())
    }

    fn watch_wire_losses(&self, writer: [u8; 16], seq: u64) -> super::wire_order::LossWatchResult {
        let ledger = {
            let mut pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self
                .ack_credit
                .as_ref()
                .is_some_and(|credit| credit.is_matched(&writer))
            {
                pending.loss_ledger(writer, None, self.ack_credit.as_ref())
            } else {
                self.departed
                    .read()
                    .get(&writer)
                    .and_then(|entry| entry.losses.clone())
            }
        };
        let Some(ledger) = ledger else {
            return super::wire_order::LossWatchResult::Unmatched;
        };
        match ledger.claim(seq, false) {
            Some(ticket) => super::wire_order::LossWatchResult::Ticket(ticket),
            None => super::wire_order::LossWatchResult::Full,
        }
    }

    fn restore_wire_loss_epoch(&self, writer: [u8; 16], old: &LossLedger) {
        if self.wire_bindings.is_none() {
            return;
        }
        let mut pending = self
            .ownership_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if pending
            .losses
            .get(&writer)
            .is_some_and(|current| !Arc::ptr_eq(&current.authority, &old.authority))
        {
            // A replacement already established its own namespace while
            // an older continuation verdict was finishing.
            return;
        }
        let incarnation = pending.incarnation(writer);
        if !incarnation.inherit_loss_authority(old.authority.clone()) {
            return;
        }
        pending.losses.insert(
            writer,
            Arc::new(LossLedger {
                incarnation,
                authority: old.authority.clone(),
                credit: self.ack_credit.clone(),
                writer,
            }),
        );
        drop(pending);
        if let Some(credit) = &self.ack_credit {
            credit.resume_group_loss(&writer, &old.authority);
        }
    }

    fn data_lifespan(
        &self,
        prepared: &super::admission::Prepared,
        writer: [u8; 16],
        source: Option<u64>,
    ) -> Option<std::time::Duration> {
        matches!(prepared, super::admission::Prepared::Stored(_))
            .then(|| self.remaining_lifespan(writer, source))
            .flatten()
    }

    fn remaining_lifespan(
        &self,
        writer: [u8; 16],
        source_ts_ns: Option<u64>,
    ) -> Option<std::time::Duration> {
        let source = source_ts_ns?;
        let lifespan = self
            .topic_registry
            .as_ref()
            .and_then(|registry| registry.writer_lifespan(&writer))
            .or_else(|| self.departed_lifespans.lifespan_of(&writer))?;
        if lifespan == u64::MAX {
            return None;
        }
        let deadline = source.checked_add(lifespan)?;
        Some(std::time::Duration::from_nanos(
            deadline.saturating_sub(current_time_ns()),
        ))
    }

    fn ordered_payload(
        &self,
        writer: [u8; 16],
        mut payload: PendingPayload,
    ) -> super::wire_order::OrderedPayload {
        let token = payload.order_token.take().or_else(|| {
            self.wire_bindings.as_ref().and_then(|bindings| {
                super::wire_order::OrderToken::new(
                    bindings,
                    payload.prepared.slab_handle(),
                    payload.order?,
                    self.coherent_barrier.as_ref()?,
                    self.barrier_member?,
                    self.data_lifespan(&payload.prepared, writer, payload.source_ts_ns),
                    super::wire_order::LossContext {
                        writer,
                        seq: payload.remote_seq,
                        reporter: self.wire_loss_ledger(writer, None)?,
                    },
                )
            })
        });
        super::wire_order::OrderedPayload { payload, token }
    }

    fn process_ordered_payload(
        &self,
        writer: [u8; 16],
        mut ordered: super::wire_order::OrderedPayload,
    ) {
        let Some(token) = ordered.token.as_mut() else {
            return;
        };
        if !token.attach() {
            return;
        }
        let payload = ordered.payload;
        let delivered = self.process_admitted(
            Some(writer),
            payload.remote_seq,
            payload.version,
            payload.source_ts_ns,
            payload.slot,
            payload.prepared,
            None,
        );
        if delivered {
            if let Some(token) = ordered.token.as_mut() {
                token.commit();
            }
        }
        self.finish_departed_ordered_delivery(writer);
    }

    /// A retained value may be presented after its writer departed. Keep
    /// that value, then close the registration it would otherwise revive.
    fn finish_departed_ordered_delivery(&self, writer: [u8; 16]) {
        if self.has_left(&writer) {
            for key in self.writer_instances.retire(&writer) {
                self.queue_transition(
                    key,
                    DisposeKind::Unregistered,
                    0,
                    Some(writer),
                    u64::MAX,
                    None,
                );
            }
        }
    }

    /// An admitted coherent copy can lose its unit before its handoff.
    /// Its captured ledger is also the one departure used for owed copies.
    fn discard_prepared_coherent(
        &self,
        writer: [u8; 16],
        seq: u64,
        prepared: &super::admission::Prepared,
        lifecycle: bool,
        token: Option<&super::wire_order::OrderToken>,
    ) {
        let Some(token) = token else {
            self.step_gate_over_staged(writer, seq);
            return;
        };
        token.mark_lost();
        self.release_through_gate(writer, |gate| {
            if self.has_left(&writer) {
                Vec::new()
            } else {
                gate.on_staged(writer, seq, PendingPayload::nothing(seq))
            }
        });
        if !lifecycle && matches!(prepared, super::admission::Prepared::Stored(_)) {
            self.report_sample_lost(token.loss_count(seq));
        }
    }

    fn received_payload_lost(&self, writer: [u8; 16], payload: &PendingPayload) -> u64 {
        if let Some(token) = &payload.order_token {
            token.mark_lost();
        }
        if !matches!(payload.prepared, super::admission::Prepared::Stored(_)) {
            return 0;
        }
        payload.order_token.as_ref().map_or_else(
            || self.received_sequence_lost(writer, payload.remote_seq),
            |token| token.loss_count(payload.remote_seq),
        )
    }

    fn received_staged_lost(&self, writer: [u8; 16], sample: &BufferedCoherentSample) -> u64 {
        if let Some(token) = &sample.order_token {
            token.mark_lost();
        }
        if sample.lifecycle.is_some()
            || !matches!(sample.prepared, super::admission::Prepared::Stored(_))
        {
            return 0;
        }
        sample.order_token.as_ref().map_or_else(
            || self.received_sequence_lost(writer, sample.remote_seq),
            |token| token.loss_count(sample.remote_seq),
        )
    }

    fn received_sequence_lost(&self, writer: [u8; 16], seq: u64) -> u64 {
        let mut records = self
            .seen_seqs_by_writer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let record = if self.has_left(&writer) {
            records.get_mut(&writer)
        } else {
            Some(records.entry(writer).or_default())
        };
        record.map_or(1, |record| {
            record.reported.report(seq, seq.saturating_add(1))
        })
    }

    /// Inspect a terminal late copy without acquiring storage or changing
    /// content-filter state. Controls and irrelevant values are not losses.
    fn stale_data_is_relevant(&self, data: &[u8], version: crate::dds::CdrVersion) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(sample) = T::decode(data, version) else {
                return false;
            };
            let Some(filter) = &self.content_filter else {
                return true;
            };
            let fields = match &self.field_extractor {
                Some(extract) => match extract(&sample) {
                    Some(fields) => fields,
                    None => return false,
                },
                None => T::get_fields(&sample),
            };
            filter.matches(&fields).unwrap_or(false)
        }))
        .unwrap_or(false)
    }

    /// Expire a concrete owned coherent unit, never an unknown GSN prefix.
    fn expire_wire_owner(&self, owner: u64) -> bool {
        let retired: Vec<_> = self
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter_mut()
            .filter(|(_, set)| {
                set.per_writer.values().flatten().any(|sample| {
                    sample
                        .order_token
                        .as_ref()
                        .is_some_and(|token| token.owner_id() == owner)
                })
            })
            .map(|(key, set)| {
                let pin = set
                    .per_writer
                    .values_mut()
                    .flatten()
                    .find_map(|sample| sample.charge.take())
                    .map(super::staging_budget::StagedCharge::pin_loss_marker);
                (*key, pin)
            })
            .collect();
        let generations: Vec<_> = retired.iter().map(|(key, _)| *key).collect();
        self.discard_group_sets(|key, _| generations.contains(key), None);
        let found = !generations.is_empty();
        if let Some((barrier, member)) = self.coherent_barrier.as_ref().zip(self.barrier_member) {
            for (key, pin) in retired {
                let publisher = super::coherent_barrier::publisher_key(key.0, key.1);
                barrier.retire_wire_generation(publisher, key.2);
                if let Some(pin) = pin {
                    barrier.pin_wire_loss_marker(member, publisher, key.2, pin);
                }
            }
            return barrier.retire_wire_owner(member, owner) || found;
        }
        found
    }

    /// Register the barrier release closure for this reader (called from
    /// the builder once the `Arc<ReaderSubscriber>` exists). The closure
    /// captures a `Weak` so the barrier never keeps a dropped reader alive.
    /// No-op for readers without a barrier.
    pub(super) fn attach_barrier_delivery(self: &Arc<Self>) -> bool {
        if let (Some(barrier), Some(member)) = (self.coherent_barrier.as_ref(), self.barrier_member)
        {
            let weak = Arc::downgrade(self);
            barrier.attach_deliver(
                member,
                Arc::new(move |set: CoherentSet| {
                    if let Some(sub) = weak.upgrade() {
                        sub.deliver_coherent_set(set);
                    }
                }),
            );
            if self.wire_bindings.is_some() {
                let weak = Arc::downgrade(self);
                let roster = Arc::downgrade(self);
                barrier.attach_wire_order_pending(
                    member,
                    Arc::new(move |writer, payload| {
                        if let Some(sub) = weak.upgrade() {
                            let lock = sub.writer_delivery_lock(writer);
                            let _delivery = lock.lock().unwrap_or_else(|e| e.into_inner());
                            match payload {
                                super::wire_order::OrderedDelivery::Data(payload) => {
                                    sub.process_ordered_payload(writer, payload);
                                }
                                super::wire_order::OrderedDelivery::Lost(payload) => {
                                    if let Some(token) = &payload.token {
                                        token.mark_lost();
                                    }
                                    let lost = match &payload.token {
                                        Some(token)
                                            if matches!(
                                                payload.payload.prepared,
                                                super::admission::Prepared::Stored(_)
                                            ) =>
                                        {
                                            token.loss_count(payload.payload.remote_seq)
                                        }
                                        _ => sub.received_payload_lost(writer, &payload.payload),
                                    };
                                    sub.report_sample_lost(lost);
                                }
                            }
                        }
                    }),
                    Arc::new(move |publisher| {
                        let sub = roster.upgrade()?;
                        let source = sub.group_roster.get()?;
                        if !source.ready() {
                            return None;
                        }
                        let prefix = publisher[..12].try_into().ok()?;
                        Some(
                            source
                                .writers_of(&prefix, publisher[12..].try_into().ok()?, &sub.topic)
                                .into_iter()
                                .map(|(entity, matched)| {
                                    let mut writer = publisher;
                                    writer[12..].copy_from_slice(&entity);
                                    let alive = sub.liveliness.as_ref().and_then(|liveliness| {
                                        liveliness.is_alive(
                                            &crate::core::discovery::GUID::from_bytes(writer),
                                        )
                                    }) != Some(false);
                                    (entity, matched && alive && !sub.has_left(&writer))
                                })
                                .collect(),
                        )
                    }),
                    self.wire_reliable,
                    self.wire_durable,
                    self.wire_bindings.clone().unwrap_or_default(),
                );
                let snapshot = Arc::downgrade(self);
                barrier.attach_wire_snapshot(
                    member,
                    Arc::new(move |publisher| {
                        let sub = snapshot.upgrade()?;
                        sub.topic_registry.as_ref().map_or_else(
                            || sub.group_roster.get()?.terminal_writers(publisher),
                            |registry| Some(registry.snapshot_group_writers(publisher)),
                        )
                    }),
                );
            }
            if self.wire_bindings.is_some() {
                let history = Arc::downgrade(self);
                barrier.attach_wire_history(
                    member,
                    Arc::new(move |proof| {
                        if let Some(sub) = history.upgrade() {
                            match proof {
                                super::wire_order::HistoryProof::Lifespan { owner_token } => {
                                    return sub.expire_wire_owner(owner_token);
                                }
                                super::wire_order::HistoryProof::KnownOwed { ticket } => {
                                    sub.report_sample_lost(ticket.mark_lost());
                                    return true;
                                }
                            }
                        }
                        true
                    }),
                );
                let weak = Arc::downgrade(self);
                barrier.attach_wire_terminal(
                    member,
                    Arc::new(move |publisher, entity| {
                        let sub = weak.upgrade()?;
                        let mut writer = publisher;
                        writer[12..].copy_from_slice(&entity);
                        let publisher = publisher[12..].try_into().ok()?;
                        sub.topic_registry
                            .as_ref()
                            .and_then(|registry| registry.group_writer_terminal(&writer, publisher))
                            .or_else(|| sub.group_roster.get()?.terminal_writer(&writer, publisher))
                    }),
                );
                let losses = Arc::downgrade(self);
                if !barrier.attach_wire_loss_watch(
                    member,
                    Arc::new(move |writer, seq| {
                        losses
                            .upgrade()
                            .map_or(super::wire_order::LossWatchResult::Unmatched, |sub| {
                                sub.watch_wire_losses(writer, seq)
                            })
                    }),
                ) {
                    return false;
                }
            }
        }
        true
    }

    /// Deliver a whole coherent set to this reader's ring in per-writer
    /// order. Invoked by the presentation barrier's release closure on the
    /// app thread (`take_all`); the barrier guarantees the set is complete
    /// and publisher-aligned before this runs. The per-writer delivery lock
    /// serialises these pushes against the RX-thread pushes for the same
    /// writer (e.g. a non-coherent boundary sample between two sets), the
    /// same discipline the non-coherent delivery paths follow.
    pub(super) fn deliver_coherent_set(&self, set: CoherentSet) {
        // Its listeners are told once its delivery locks are released.
        let _delivering = super::notices::Delivering::enter();
        if set.lost {
            // Another member could not make the set whole: this part is
            // discarded with it, reported lost, its places given back
            // (RTPS v2.5 Sec.8.7.6).
            let mut lost = 0u64;
            for (writer, payloads) in set.writers {
                for payload in payloads {
                    lost = lost.saturating_add(self.received_payload_lost(writer, &payload));
                    if let Some(slot) = payload.slot {
                        slot.give_back_quietly();
                    }
                }
            }
            self.report_sample_lost(lost);
            return;
        }
        for (writer_guid, payloads) in set.writers {
            if !payloads.is_empty() {
                let lock = self.writer_delivery_lock(writer_guid);
                let _del_guard = match lock.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                self.deliver_released(Some(writer_guid), payloads);
            }
        }
    }

    /// Emit a completed per-topic coherent set: DEPOSIT it into the
    /// cross-reader barrier for publisher-aligned release when one is wired
    /// (reader attached to a Subscriber), otherwise deliver it straight to
    /// the ring (unattached reader). Keeping the branch here means every
    /// commit path (ECS, classic implicit-close, explicit-end, GROUP flush)
    /// gets alignment for free without duplicating the barrier plumbing.
    fn emit_coherent_payloads(&self, writer_guid: [u8; 16], payloads: Vec<PendingPayload>) {
        // A change that delivers nothing (an end of set the gate stepped
        // over, `PendingPayload::nothing`) is no part of this unit: left
        // in, a set of ONLY such changes is non-empty by `len()` alone, so
        // the `is_empty()` guard below never caught it, and it was
        // deposited into the barrier as a generation of its own -- with
        // two members, that empty generation paired with the OTHER
        // member's real set and split it across two accesses. Same rule,
        // same predicate as `emit_coherent_group`'s own filter.
        let payloads: Vec<PendingPayload> = payloads
            .into_iter()
            .filter(|p| {
                p.slot.is_some() || !matches!(p.prepared, super::admission::Prepared::Discard)
            })
            .collect();
        if payloads.is_empty() {
            return;
        }
        match (self.coherent_barrier.as_ref(), self.barrier_member) {
            (Some(barrier), Some(member)) => {
                let prefix: [u8; 12] = match writer_guid[..12].try_into() {
                    Ok(p) => p,
                    Err(_) => {
                        // Unreachable for a 16-byte GUID; deliver directly
                        // rather than dropping the set.
                        self.deliver_released(Some(writer_guid), payloads);
                        return;
                    }
                };
                // Its writer's Publisher, which the barrier knows.
                barrier.deposit(
                    member,
                    super::coherent_barrier::publisher_key(prefix, [0; 4]),
                    CoherentSet::single(writer_guid, payloads),
                );
            }
            _ => self.deliver_released(Some(writer_guid), payloads),
        }
    }

    /// Emit a completed GROUP-scope coherent set spanning several writers
    /// of the same Publisher as ONE atomic unit (the whole cross-writer set
    /// must land in one read cycle, DDS v1.4 sec. 2.2.3.6 GROUP scope).
    /// Deposits into the barrier when wired, else delivers each writer's
    /// payloads straight to the ring.
    fn emit_coherent_group(
        &self,
        publisher: super::coherent_barrier::PublisherKey,
        writers: Vec<([u8; 16], Vec<PendingPayload>)>,
        gsn: Option<u64>,
        spec: bool,
    ) {
        // A change that delivers nothing (an end of set the gate stepped
        // over, `PendingPayload::nothing`) is no part of a unit: a unit of
        // nothing else, deposited, took a place in a release round and was
        // paired with another member's generation, splitting it across two
        // accesses.
        let writers: Vec<([u8; 16], Vec<PendingPayload>)> = writers
            .into_iter()
            .map(|(writer, payloads)| {
                let payloads: Vec<PendingPayload> = payloads
                    .into_iter()
                    .filter(|p| {
                        p.slot.is_some()
                            || !matches!(p.prepared, super::admission::Prepared::Discard)
                    })
                    .collect();
                (writer, payloads)
            })
            .filter(|(_, payloads)| !payloads.is_empty())
            .collect();
        match (self.coherent_barrier.as_ref(), self.barrier_member, gsn) {
            // A part of a set of the spec dialect, empty too: every
            // member holds every generation (`CoherentSet::spec_part`).
            (Some(barrier), Some(member), Some(gsn)) if spec => {
                barrier.deposit(
                    member,
                    publisher,
                    CoherentSet::spec_part(writers, gsn, false),
                );
                return;
            }
            _ => {}
        }
        if writers.iter().all(|(_, p)| p.is_empty()) {
            return;
        }
        match (self.coherent_barrier.as_ref(), self.barrier_member) {
            (Some(barrier), Some(member)) => {
                barrier.deposit(
                    member,
                    publisher,
                    CoherentSet {
                        writers,
                        gsn,
                        lost: false,
                    },
                );
            }
            _ => {
                for (writer_guid, payloads) in writers {
                    if !payloads.is_empty() {
                        self.deliver_released(Some(writer_guid), payloads);
                    }
                }
            }
        }
    }

    /// Split a committed coherent set's reorder-gate output into the set
    /// itself and any rescued strays the gate released around it.
    ///
    /// The commit paths feed a completed set's samples through the
    /// per-writer reorder gate one by one. At a discovery seam the gate
    /// can hold previously parked samples (a set that was fed while its
    /// sequence numbers were still a future gap, e.g. the writer's first
    /// live set racing a stale pre-match retransmit): feeding this set may
    /// then release those parked samples APPENDED to this set's own. Left
    /// merged, one deposit would carry two publisher generations and a
    /// single read cycle would expose both (a doubled read cycle downstream
    /// -- the atomic presentation contract of DDS v1.4 sec. 2.2.3.6 requires
    /// one set at a time). Partitioning by the set's own SN span keeps
    /// every deposit a single generation:
    ///
    /// * `below`: strays before the set's first fed SN (an earlier set's
    ///   rescued samples) -- emitted as their own unit BEFORE the set;
    /// * `in_set`: the set itself (`first_sn..=ceiling_sn`);
    /// * `above`: strays past the writer's set ceiling (a later set's
    ///   rescued samples) -- emitted as their own unit AFTER the set.
    fn partition_gate_strays(
        payloads: Vec<PendingPayload>,
        first_sn: u64,
        ceiling_sn: u64,
    ) -> (
        Vec<PendingPayload>,
        Vec<PendingPayload>,
        Vec<PendingPayload>,
    ) {
        let mut below = Vec::new();
        let mut in_set = Vec::new();
        let mut above = Vec::new();
        for p in payloads {
            if p.remote_seq < first_sn {
                below.push(p);
            } else if p.remote_seq > ceiling_sn {
                above.push(p);
            } else {
                in_set.push(p);
            }
        }
        (below, in_set, above)
    }

    /// Whether an incoming sample's wire CDR `version` is rejected by this
    /// reader, either by its explicit DataRepresentationQosPolicy or by its
    /// type's real decode capability (DDS-XTypes v1.3 sec. 7.6.3.1.2).
    ///
    /// The capability check runs first and is unconditional: an XCDR1-encoded
    /// sample is dropped whenever `self.xcdr1.refuses_xcdr1()`, independent
    /// of `accepted_data_repr` and of the match verdict. This is the backstop
    /// the SEDP writer-block gate and the per-pair match verdict are not: a
    /// writer discovered compatible with SOME other local reader on this
    /// topic is not blocked at the router, and a remote writer judges this
    /// reader only by the list it announced over SEDP, which may name XCDR1
    /// even when this reader's actual Rust type cannot decode it (the
    /// builder refuses to create such a reader, `resolve_reader_data_representation`,
    /// but this check does not rely on that invariant holding).
    ///
    /// Then the explicit accepted-set check: returns false (accept) when the
    /// reader left its accepted set empty ("no restriction"). When the reader
    /// explicitly requested a representation, a sample whose wire form is not
    /// in that set is dropped: e.g. an `-x 2` (XCDR2-only) reader rejects
    /// XCDR1-encoded data. This is the data-plane half of the policy-23 RxO
    /// rule; the notification half is fired by the match-notification path.
    fn data_repr_incompatible(&self, version: crate::dds::CdrVersion) -> bool {
        if version == crate::dds::CdrVersion::Xcdr1 && self.xcdr1.refuses_xcdr1() {
            return true;
        }
        if self.accepted_data_repr.is_empty() {
            return false;
        }
        let code: u16 = match version {
            crate::dds::CdrVersion::Xcdr1 => 0x0000,
            crate::dds::CdrVersion::Xcdr2 => 0x0002,
        };
        !self.accepted_data_repr.contains(&code)
    }

    /// Register this reader in its match registry, as `ReaderBuilder` does
    /// once the subscriber exists, with `qos` (a fixture that builds the
    /// subscriber by hand). The entry stays registered as long as the
    /// subscriber lives.
    #[cfg(test)]
    pub(super) fn register_match_entry_for_test(&self, qos: crate::dds::QoS) {
        self.register_match_entry_with_peer_for_test(qos, None);
    }

    #[cfg(test)]
    pub(super) fn register_match_entry_with_peer_for_test(
        &self,
        qos: crate::dds::QoS,
        peer: Option<crate::dds::match_notification::PeerCallback>,
    ) {
        let Some(reg) = self.match_registry.as_ref() else {
            return;
        };
        // The name this reader announces is the one of `T`, the type it reads.
        let token = reg.register_reader_with_lifespan(
            self.topic.clone(),
            qos,
            crate::dds::match_notification::LocalType::new(
                crate::dds::cdr_negotiation::Xcdr1Encoding::of::<T>(),
                T::type_descriptor().type_name,
            ),
            None,
            |_, _, _, _, _| {},
            peer,
            None,
            None,
            Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            crate::transport::shm::ShmPolicy::default(),
        );
        let _ = self.match_entry.set(token.id());
        let _ = self.test_match_token.set(token);
    }

    /// Whether THIS reader refuses the remote writer, as the match
    /// registry's verdicts on the (writer, this reader) pair recorded them:
    /// its type (DDS-XTypes v1.3 sec. 7.6.3.4.3) or its QoS (the one RxO
    /// verdict, DDS v1.4 Sec.2.2.3: "for the Subscriber to receive data the
    /// DataReader's requested value must be compatible with the DataWriter's
    /// offered value"). When true the reader data path drops what the writer
    /// sends, samples and lifecycle changes, before any reception
    /// bookkeeping or application delivery. Another local reader's refusal
    /// of the same writer gates nothing here, and a compatible sibling's
    /// match opens nothing here either. Before this reader's entry is
    /// registered and judged against the writers already known (`catch_up`)
    /// it is matched with nothing, and refuses every writer: its subscriber
    /// is reachable from the router before then (`register_subscriber`
    /// precedes the match registration in the builder).
    ///
    /// One lookup per sample: the verdicts are judged on the cold path (the
    /// writer's announcements, this reader's registration), never here.
    #[inline]
    fn writer_refused(&self, writer_guid: &[u8; 16]) -> bool {
        self.match_registry
            .as_ref()
            .is_some_and(|reg| match self.match_entry.get() {
                Some(&entry) => reg.is_writer_refused_by(writer_guid, entry),
                None => true,
            })
    }

    /// `writer_refused`, for a test's fixture.
    #[cfg(test)]
    pub(super) fn writer_refused_for_test(&self, writer_guid: &[u8; 16]) -> bool {
        self.writer_refused(writer_guid)
    }

    /// Reports of writers held without their QoS verdict past the discovery
    /// lease (`note_unjudged_writer`), for a test's fixture.
    #[cfg(test)]
    pub(super) fn unjudged_reports_for_test(&self) -> u32 {
        self.ownership_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unjudged_reports
            .values()
            .sum()
    }

    /// Move the start of a writer's unjudged stall back by `by`, as if the
    /// stall had begun that long ago (`note_unjudged_writer`), for a test's
    /// fixture.
    #[cfg(test)]
    pub(super) fn age_unjudged_writer_for_test(
        &self,
        writer_guid: &[u8; 16],
        by: std::time::Duration,
    ) {
        let mut pending = self
            .ownership_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(since) = pending.unjudged_since.get_mut(writer_guid) {
            *since = since
                .checked_sub(by)
                .expect("fixture: stall start in range");
        }
    }

    /// Whether a writer may participate in this reader's coherent/GROUP
    /// state (DDS v1.4 Sec.2.2.3.6, Sec.2.2.3.13). An undiscovered writer
    /// has no matched writer proxy, including on the default partition.
    /// Discovery and PARTITION resolve through durable router metadata so
    /// a departing writer can still close its queued final set after the
    /// discovery FSM has removed its endpoint.
    fn writer_shut_out(&self, writer_guid: &[u8; 16]) -> bool {
        if self.writer_refused(writer_guid) || self.writer_undiscovered(writer_guid) {
            return true;
        }
        if self.writer_partition_incompatible(writer_guid) {
            return true;
        }
        #[cfg(feature = "security")]
        if self.writer_not_admitted(writer_guid) {
            return true;
        }
        false
    }

    /// Whether this reader refuses what the remote writer sends - samples,
    /// dispose, unregister - because the security plugins do not admit it:
    /// its participant is not authenticated where the governance requires
    /// it, its handshake has not completed, or its permissions do not let
    /// it publish this topic in its partitions. The same verdict discovery's
    /// match reached (`DiscoveryFsm::admits_remote_endpoint`): the match is
    /// refused there, but user data is routed by topic name, so without this
    /// the writer's samples reached the reader all the same.
    ///
    /// One flag, resolved once, skips the gate for good on a participant
    /// without the security plugins; otherwise one cached lookup per
    /// sample, keyed by the writer's participant (bounded, and judged again
    /// whenever what it was reached from changes: a departure, an
    /// authentication state change, a new announcement).
    #[cfg(feature = "security")]
    fn writer_not_admitted(&self, writer_guid: &[u8; 16]) -> bool {
        let Some(reg) = self.match_registry.as_ref() else {
            // Participant-less / intra-process path: no discovery, no gate.
            return false;
        };
        if !*self
            .admission_gate
            .get_or_init(|| reg.admission_gate_active())
        {
            return false;
        }
        !reg.admits_remote_writer(writer_guid, &self.topic)
    }

    /// Whether this reader refuses a sample or a lifecycle change that names
    /// no writer (the writer-less ingest paths, `on_data_with_version` and
    /// `on_dispose`): under the security plugins nothing can be admitted
    /// that cannot be attributed to an admitted writer. Network traffic
    /// always names its writer; nothing in this crate routes a GUID-less
    /// change to a reader of a participant with security.
    #[cfg(feature = "security")]
    fn unattributed_refused(&self) -> bool {
        self.match_registry.as_ref().is_some_and(|reg| {
            *self
                .admission_gate
                .get_or_init(|| reg.admission_gate_active())
        })
    }

    /// Whether this participant has never discovered `writer_guid` via SEDP
    /// at all: no matched writer proxy exists for it (RTPS v2.5 sec. 8.4.15),
    /// so it is not a writer of this reader under any QoS axis.
    ///
    /// Resolved through the engine `TopicRegistry`'s GUID->topic routing
    /// record first, when wired: durable for the writer's lifetime in this
    /// participant (never retired on its departure, `Deleted` or
    /// `Unheard` -- see `TopicRegistry::notify_writer_departure`), so a
    /// writer's own final change, arriving as it departs, does not race
    /// its own removal here the way a live discovery-FSM lookup would
    /// (confirmed by `shm_departure_after_last_set.rs`: an FSM-based
    /// version of this check lost a departing writer's last coherent set
    /// in every run). Falls back to the match registry's own SEDP-backed
    /// cache (`resolve_writer_partition`) when no `TopicRegistry` is
    /// wired, same source `writer_partition_incompatible` reads.
    ///
    /// Participant-less / intra-process readers have no SEDP and no gate
    /// (`false`, same convention as every other data-plane gate here).
    fn writer_undiscovered(&self, writer_guid: &[u8; 16]) -> bool {
        if let Some(reg) = self.topic_registry.as_ref() {
            return reg.get_topic_by_guid(writer_guid).is_none();
        }
        self.match_registry.as_ref().is_some_and(|reg| {
            reg.resolve_writer_partition(&self.topic, writer_guid)
                .is_none()
        })
    }

    /// Whether a remote writer was recorded at SEDP time as carrying a
    /// PARTITION that does not intersect this reader's partition (DDS v1.4
    /// sec. 2.2.3.13). When true the reader data path drops the writer's samples:
    /// HDDS routes user DATA by topic name, so an unmatched writer's multicast
    /// would otherwise reach this reader despite the matcher reporting
    /// no match on the discovery plane.
    fn writer_partition_incompatible(&self, writer_guid: &[u8; 16]) -> bool {
        // Fast path, no lock: a writer already judged under SEDP has a
        // published verdict.
        if let Some(deliver) = self.partition_verdict.get(writer_guid) {
            return !deliver;
        }
        if self.match_registry.is_none() && self.topic_registry.is_none() {
            // Participant-less / intra-process path: no SEDP, no gate.
            return false;
        }
        // Keep resolution and publication in the same section as SEDP's
        // invalidation: an old offer must not be published after its
        // refresh.
        let _cold = self.partition_verdict.resolve_under_lock();
        // Another thread may have judged the writer while this one waited.
        if let Some(deliver) = self.partition_verdict.get(writer_guid) {
            return !deliver;
        }
        let resolved = self
            .topic_registry
            .as_ref()
            .and_then(|reg| reg.writer_partition(writer_guid))
            .or_else(|| {
                self.match_registry
                    .as_ref()
                    .and_then(|reg| reg.resolve_writer_partition(&self.topic, writer_guid))
            });
        match resolved {
            Some(writer_partition) => {
                // PARTITION RxO (DDS v1.4 sec. 2.2.3.13): writer.offered must
                // intersect reader.requested. Publish the now-stable verdict.
                let deliver = writer_partition.is_compatible_with(&self.reader_partition);
                self.partition_verdict.publish(*writer_guid, deliver);
                !deliver
            }
            // Default-partition DATA is held by the OWNERSHIP unresolved
            // queue until SEDP judges the pair. Coherent controls instead
            // require discovery explicitly in writer_shut_out.
            None => !self.reader_partition.is_default(),
        }
    }

    /// Resolve the OWNERSHIP data-plane verdict for a remote writer: the
    /// writer's OWNERSHIP kind (inferred from SEDP PIDs, same rule as the
    /// match-notification path: PID_OWNERSHIP present -> use it; absent +
    /// PID_OWNERSHIP_STRENGTH present -> EXCLUSIVE; both absent -> SHARED)
    /// must match this reader's requested kind exactly (DDS v1.4 sec. 2.2.3.11
    /// RxO). Mirrors `writer_partition_incompatible`'s resolve-then-cache
    /// shape; unlike PARTITION, unresolved DATA is held for every reader,
    /// because SHARED is as concrete a requested kind as EXCLUSIVE.
    ///
    /// This is the data-plane half of the OWNERSHIP RxO rule. Without it, a
    /// writer whose SEDP was cached by this participant's discovery FSM
    /// before this reader finished registering with the match-notification
    /// registry (a registration-order race, not a wire-protocol one) can
    /// deliver data to the application before -- or regardless of whether --
    /// the separate on_requested_incompatible_qos notification ever wins its
    /// race with the data in the application's view (the router-level
    /// `block_writer` gate in
    /// `sedp_handler.rs` only fires when at least one local reader was
    /// already registered at the moment the writer's SEDP was processed, so
    /// it cannot be relied on alone to close this race).
    ///
    /// A writer that is not yet resolvable via SEDP yields `Unresolved`,
    /// which the caller must treat as DEFER, never as discard: the reverse
    /// race (data beating the writer's own SEDP to this participant) is
    /// normal for a TRANSIENT_LOCAL late-joiner history burst, and that
    /// burst is one-shot -- a discard here happens above the RTPS
    /// reliability layer, so the writer never retransmits and the history
    /// is lost for good.
    fn ownership_gate(&self, writer_guid: &[u8; 16]) -> OwnershipGate {
        // Fast path: a writer already resolved via SEDP has a cached verdict.
        {
            let cache = self
                .ownership_verdict
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(&deliver) = cache.get(writer_guid) {
                return if deliver {
                    OwnershipGate::Deliver
                } else {
                    OwnershipGate::Reject
                };
            }
        }
        if self.match_registry.is_none() && self.topic_registry.is_none() {
            // Participant-less / intra-process path: no SEDP, no gate.
            return OwnershipGate::Deliver;
        }
        // SEDP publishes the router's topic and OWNERSHIP metadata before
        // discovery judges the pair. An addressed DATA may already be on
        // its way here when that metadata appears. Wait for the recorded
        // verdict before caching any admission based on the router's record
        // (DDS v1.4 Sec.2.2.3). Also observe a refusal recorded since this
        // sample's first pair-gate check. A QoS refusal is not cached here:
        // a later compatible announcement can lift it.
        if self.topic_registry.is_some() {
            if let (Some(reg), Some(entry)) = (&self.match_registry, self.match_entry.get()) {
                match reg.writer_pair_verdict(writer_guid, *entry, &self.topic) {
                    Some(true) => {}
                    Some(false) => return OwnershipGate::Reject,
                    None => {
                        self.note_unjudged_writer(reg, writer_guid, *entry);
                        return OwnershipGate::Unresolved;
                    }
                }
            }
        }
        // Primary source: the engine TopicRegistry's SEDP-time record
        // (durable across FSM zombie purges -- see the `topic_registry`
        // field doc). Fallback: the discovery FSM endpoint registry, which
        // covers ingestion paths that bypass the SEDP packet handler.
        let resolved = self
            .topic_registry
            .as_ref()
            .and_then(|reg| reg.writer_ownership_kind(writer_guid))
            .or_else(|| {
                self.match_registry
                    .as_ref()
                    .and_then(|reg| reg.resolve_writer_ownership(&self.topic, writer_guid))
            });
        match resolved {
            Some(writer_ownership) => {
                // OWNERSHIP RxO (DDS v1.4 sec. 2.2.3.11): kinds must match
                // exactly. Cache the now-stable verdict.
                let deliver = writer_ownership == self.reader_ownership;
                self.ownership_verdict
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(*writer_guid, deliver);
                if deliver {
                    OwnershipGate::Deliver
                } else {
                    OwnershipGate::Reject
                }
            }
            None => OwnershipGate::Unresolved,
        }
    }

    /// Report a writer that discovery holds while its QoS verdict stays off
    /// the record past the discovery lease, once per writer. Its samples are
    /// deferred for as long as the verdict is missing, and the reliable stream
    /// behind them stalls: the state is an invariant violation (the registry
    /// judges every writer discovery holds), so it is named in the log instead
    /// of only showing as a stall. Nothing is discarded. Cold path: runs for a
    /// deferred sample only.
    fn note_unjudged_writer(
        &self,
        reg: &crate::dds::match_notification::MatchNotificationRegistry,
        writer_guid: &[u8; 16],
        reader_entry: u64,
    ) {
        if !reg.writer_held_but_unjudged(writer_guid, &self.topic, reader_entry) {
            return;
        }
        let Some(lease_ms) = reg.discovery_lease_ms() else {
            return;
        };
        let now = std::time::Instant::now();
        let report = {
            let mut pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let since = *pending.unjudged_since.entry(*writer_guid).or_insert(now);
            if now.duration_since(since) < std::time::Duration::from_millis(lease_ms) {
                return;
            }
            let reports = pending.unjudged_reports.entry(*writer_guid).or_insert(0);
            if *reports > 0 {
                return;
            }
            *reports += 1;
            true
        };
        if report {
            log::error!(
                "[READER-SUB] writer={:02x?} topic='{}' is known to discovery but its QoS verdict \
                 is not recorded after {} ms (discovery lease): its samples stay deferred",
                &writer_guid[..4],
                self.topic,
                lease_ms
            );
        }
    }

    /// Recheck deferred samples after discovery or a concurrent match.
    /// Unlike the announcement hook this does not revive a departed writer.
    fn flush_resolved_ownership_pending(&self, writer_guid: [u8; 16]) {
        {
            let pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !pending.has(&writer_guid) {
                return;
            }
        }
        // A readerId identifies the destination, not the writer's topic.
        // A later announcement on another topic cannot admit the deferred
        // sample, even if its OWNERSHIP kind happens to agree.
        if self
            .topic_registry
            .as_ref()
            .and_then(|reg| reg.get_topic_by_guid(&writer_guid))
            .is_some_and(|topic| topic != self.topic)
        {
            let _ = self.discard_ownership_pending(writer_guid);
            return;
        }
        // Deferred before the writer was known, refused now that it is: the
        // samples were never this reader's to deliver (`writer_refused`).
        if self.writer_refused(&writer_guid) {
            let _ = self.discard_ownership_pending(writer_guid);
            return;
        }
        match self.ownership_gate(&writer_guid) {
            OwnershipGate::Deliver => {
                let _ = self.flush_ownership_pending(writer_guid, None);
            }
            OwnershipGate::Reject => {
                let _ = self.discard_ownership_pending(writer_guid);
            }
            // Still not visible in the FSM registry (e.g. the endpoint was
            // purged between the SEDP processing and this hook): keep
            // holding -- the caps bound memory and the next live sample or
            // hook invocation re-evaluates.
            OwnershipGate::Unresolved => {}
        }
    }

    /// Stash one sample for a writer whose OWNERSHIP verdict is still
    /// unresolved. Bounded by the `OwnershipPending` caps (oldest evicted
    /// on overflow; RELIABLE retransmits recover evictions because the
    /// sample was never credited to the ACKNACK state).
    fn defer_ownership_pending(
        &self,
        writer_guid: [u8; 16],
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) -> bool {
        #[cfg(test)]
        self.pause_pending_for_test();
        let (evicted, resolved) = {
            let mut pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let incarnation = pending.incarnation(writer_guid);
            let evicted = pending.push(
                writer_guid,
                PendingOwnershipSample::capture(
                    writer_guid,
                    remote_seq,
                    data,
                    version,
                    false,
                    incarnation,
                ),
            );
            // Publish the evicted prefix before a flush can take the
            // retained tail. Lock order here and in the flush is pending
            // queue, then reorder gate; neither holds one in reverse.
            if !evicted.is_empty() {
                let mut gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
                for &(writer, seq) in &evicted {
                    gate.on_deferred(writer, seq);
                }
            }
            (evicted, pending.resolved.contains(&writer_guid))
        };
        log::debug!(
            "[READER-SUB] deferring sample from ownership-unresolved writer={:02x?} topic='{}' seq={}",
            &writer_guid[..4],
            self.topic,
            remote_seq
        );
        if !evicted.is_empty() {
            log::debug!(
                "[READER-SUB] ownership-pending overflow topic='{}': evicted {} oldest sample(s)",
                self.topic,
                evicted.len()
            );
        }
        resolved
    }

    /// Deliver every sample deferred for `writer_guid` in arrival order.
    /// Called once the writer's OWNERSHIP verdict resolves to compatible;
    /// each sample re-enters the normal admission path (duplicate window +
    /// reliable credit + reorder gate), exactly as if it had just arrived.
    /// Return the live DATA's incarnation when it can be admitted directly,
    /// or None when there is no live DATA or it joined a pending flush. In
    /// the steady state no payload is copied and no extra lock is taken.
    fn flush_ownership_pending(
        &self,
        writer_guid: [u8; 16],
        live: Option<(u64, &[u8], crate::dds::CdrVersion)>,
    ) -> Option<Arc<crate::core::reader::AdmissionFrame>> {
        let (mut samples, incarnation) = {
            let mut pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !pending.unjudged_since.is_empty() {
                pending.unjudged_since.remove(&writer_guid);
            }
            if !pending.has(&writer_guid) && !pending.flushing.contains_key(&writer_guid) {
                return live.map(|_| pending.incarnation(writer_guid));
            }
            let draining = pending.flushing.contains_key(&writer_guid);
            let incarnation = pending.incarnation(writer_guid);
            // Take the retained batch before live DATA can enforce the
            // bounded holding area's limits against it or another writer.
            let mut samples = if draining {
                Default::default()
            } else {
                pending.take(&writer_guid).unwrap_or_default()
            };
            if let Some((seq, data, version)) = live {
                let sample = PendingOwnershipSample::capture(
                    writer_guid,
                    seq,
                    data,
                    version,
                    true,
                    incarnation.clone(),
                );
                if draining {
                    let evicted = pending.push(writer_guid, sample);
                    if !evicted.is_empty() {
                        let mut gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
                        for (writer, seq) in evicted {
                            gate.on_deferred(writer, seq);
                        }
                    }
                } else {
                    samples.push_back(sample);
                }
            }
            if draining {
                return None;
            }
            pending.flushing.insert(writer_guid, incarnation.clone());
            // Preserve the reliable reader's delivery floor, including
            // the prefix evicted before discovery resolved. The flushing
            // marker also orders BEST_EFFORT DATA, whose gate deliberately
            // never waits for missing sequence numbers.
            if let Some(first) = samples.iter().map(|s| s.remote_seq).min() {
                self.reorder
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .on_deferred(writer_guid, first);
            }
            (samples, incarnation)
        };
        // Drop the in-flight marker even if application code unwinds. On
        // normal completion it is removed under the queue lock, before a
        // later DATA can choose the direct path.
        struct FlushReset<'a> {
            pending: &'a Mutex<OwnershipPending>,
            writer: [u8; 16],
            incarnation: Arc<crate::core::reader::AdmissionFrame>,
            armed: bool,
        }
        impl Drop for FlushReset<'_> {
            fn drop(&mut self) {
                if self.armed {
                    self.pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .finish_flush(&self.writer, &self.incarnation);
                }
            }
        }
        let mut reset = FlushReset {
            pending: &self.ownership_pending,
            writer: writer_guid,
            incarnation: incarnation.clone(),
            armed: true,
        };
        log::debug!(
            "[READER-SUB] flushing {} deferred sample(s) from resolved writer={:02x?} topic='{}'",
            samples.len(),
            &writer_guid[..4],
            self.topic
        );
        // A SEDP callback or a later DATA can flush this queue on another
        // thread. Each deferred DATA keeps its own INFO_TS (RTPS 2.5
        // 8.3.8.11, 8.7.7), never the flushing packet's timestamp. Restore
        // the caller's context even if delivery unwinds.
        struct RestoreSourceTime(Option<u64>);
        impl Drop for RestoreSourceTime {
            fn drop(&mut self) {
                crate::engine::router::set_route_source_ts_ns(self.0);
            }
        }
        let _restore = RestoreSourceTime(crate::engine::router::route_source_ts_ns());
        // The same deterministic pause used after a gate release, before
        // this queue's first sample reaches the gate.
        #[cfg(test)]
        self.pause_pending_for_test();
        // Application code can unwind while a later DATA has already
        // entrusted its sample to this drain. Finish every retained batch
        // before resuming the first panic, as for a reorder-gate release.
        let mut panicked = None;
        loop {
            for sample in samples {
                if !sample
                    .incarnation
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    continue;
                }
                let delivered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _arrival = GroupArrivalScope::enter(
                        writer_guid,
                        Some(sample.remote_seq),
                        sample.arrival_stamp.clone(),
                    );
                    let _inline =
                        crate::engine::router::InlineLifecycleScope::enter(sample.inline_lifecycle);
                    let _legacy = crate::engine::router::LegacyHashScope::enter(sample.legacy_hash);
                    let _order = crate::engine::router::OrderedGroupScope::enter_with_set(
                        writer_guid,
                        sample.remote_seq,
                        sample.order,
                        sample.set_first_gsn,
                    );
                    crate::engine::router::set_route_source_ts_ns(sample.source_ts_ns);
                    if sample.live {
                        self.receive_resolved(
                            writer_guid,
                            sample.remote_seq,
                            &sample.data,
                            sample.version,
                            Admit::Pending(&sample.incarnation),
                        );
                    } else {
                        self.admit_and_deliver(
                            writer_guid,
                            sample.remote_seq,
                            &sample.data,
                            sample.version,
                            Admit::Pending(&sample.incarnation),
                        );
                    }
                }));
                if let Err(panic) = delivered {
                    panicked.get_or_insert(panic);
                }
            }
            let mut pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // An old drainer cannot take or clear a successor's queue.
            let next = if pending.owns_flush(&writer_guid, &incarnation) {
                pending.take(&writer_guid)
            } else {
                None
            };
            match next {
                Some(next) => samples = next,
                None => {
                    pending.finish_flush(&writer_guid, &incarnation);
                    reset.armed = false;
                    drop(pending);
                    if let Some(panic) = panicked {
                        std::panic::resume_unwind(panic);
                    }
                    return None;
                }
            }
        }
    }

    /// Drop every sample deferred for `writer_guid`. Called once the
    /// writer's OWNERSHIP verdict resolves to incompatible -- the correct
    /// RxO outcome; the on_requested_incompatible_qos notification is
    /// raised by the match-notification path.
    fn discard_ownership_pending(&self, writer_guid: [u8; 16]) -> Vec<u64> {
        let seqs: Vec<u64> = {
            let mut pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !pending.unjudged_since.is_empty() {
                pending.unjudged_since.remove(&writer_guid);
            }
            let samples = pending.take(&writer_guid);
            let seqs = samples
                .map(|q| q.iter().map(|sample| sample.remote_seq).collect())
                .unwrap_or_default();
            pending.forget_idle_incarnation(&writer_guid);
            seqs
        };
        let dropped = seqs.len();
        if dropped > 0 {
            log::debug!(
                "[READER-SUB] discarded {} deferred sample(s) from ownership-incompatible writer={:02x?} topic='{}'",
                dropped,
                &writer_guid[..4],
                self.topic
            );
        }
        seqs
    }

    /// Get or create the per-writer delivery lock. Held while a writer's
    /// samples are delivered (`deliver_in_order`, and the coherent paths'
    /// `deliver_released`) to preserve per-writer FIFO order on the ring
    /// without serialising across all writers.
    /// How many writers this reader keeps a delivery lock for.
    #[cfg(test)]
    pub(super) fn delivery_lock_count(&self) -> usize {
        self.delivery_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    fn writer_delivery_lock(&self, writer_guid: [u8; 16]) -> Arc<Mutex<()>> {
        let mut map = match self.delivery_locks.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        map.entry(writer_guid)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// `Some(handle)` for a keyed type (`T::has_key()`), `None` for a
    /// keyless one -- the derive macro's default `compute_key` is a
    /// meaningless all-zero hash for a type with no `@key` fields, so
    /// reporting it as an instance handle would be misleading rather than
    /// merely imprecise. The handle is the full 16-byte key hash, the same
    /// `InstanceHandle` the reader's `SampleInfo::instance_handle` carries
    /// for that instance and `DataReader::take_instance` accepts: DDS v1.4
    /// Sec.2.2.4.1.9 names the affected instance, not a diagnostic
    /// identifier.
    fn instance_handle_for_rejection(msg: &T) -> Option<InstanceHandle> {
        if T::has_key() {
            Some(InstanceHandle::new(msg.compute_key()))
        } else {
            None
        }
    }

    /// A refusal the application hears about, `SAMPLE_REJECTED` with the
    /// reason of `refusal`: the one door every refused sample takes, where
    /// the telemetry counters of a ResourceLimit rejection are raised too.
    fn report_refusal(&self, refusal: Refusal, last_instance_handle: Option<InstanceHandle>) {
        let reason = refusal.reason();
        if reason == SampleRejectedReason::ResourceLimit {
            // Every ResourceLimit report is counted in exactly one of the
            // two counters, whichever path refused: the report is the one
            // door they all take, and the counters are the only way to tell
            // the history bound from the slab budget.
            if let Some(m) = telemetry::get_metrics_opt() {
                match refusal {
                    Refusal::Storage => m.increment_samples_rejected_slab_exhausted(1),
                    _ => m.increment_samples_rejected_ring_full(1),
                }
            }
        }
        self.report_sample_rejected(reason, last_instance_handle);
    }

    /// Record a resource-limit rejection (ring full or slab pool
    /// exhausted): bump the cumulative `SampleRejectedStatus`, deliver to
    /// the listener if attached, and update `StatusMask::SAMPLE_REJECTED`
    /// on the status condition.
    ///
    /// The increment, the delta reset and the snapshot are one critical
    /// section of the status lock, and the snapshot is queued there
    /// (`rejected_notices`): two concurrent rejections reach the listener
    /// in the order of their snapshots, a gap-free `total_count_change`
    /// sequence summing to the final `total_count`, however the
    /// deliveries that hold them end. The listener is called with no lock
    /// of the reader held (`notices`).
    ///
    /// DDS v1.4 Sec.2.2.4.2.1: "the status is reset prior to calling the
    /// listener" -- so when a listener is attached, `total_count_change`
    /// is zeroed and `SAMPLE_REJECTED` is cleared in the same breath as
    /// the snapshot, before `on_sample_rejected` runs; an application that
    /// calls `DataReader::get_sample_rejected_status` from inside that
    /// callback then correctly sees the status already reset (spec,
    /// same section). With no listener attached nothing consumes the
    /// event yet, so the bit is raised (not cleared) and the delta keeps
    /// accumulating for a future `get_sample_rejected_status` read. The
    /// bit transition happens under the state lock, in the same critical
    /// section as the increment, so it is ordered against the getter's
    /// own snapshot-reset-clear section: the getter can never clear a
    /// rejection it did not return. The WaitSet notification for that
    /// raise runs after the lock is released: `WaitsetSignal` hooks are
    /// public trait code and may read the status back from inside
    /// `signal()`.
    fn report_sample_rejected(
        &self,
        reason: SampleRejectedReason,
        last_instance_handle: Option<InstanceHandle>,
    ) {
        // One snapshot for the whole report: the listener that consumes
        // the status below is the one called with it.
        let installed = self.listener.get(StatusMask::SAMPLE_REJECTED);
        let has_listener = installed.is_some();
        let mut own = None;
        {
            let mut status = match self.sample_rejected.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            status.total_count = status.total_count.saturating_add(1);
            status.total_count_change = status.total_count_change.saturating_add(1);
            status.last_reason = reason;
            status.last_instance_handle = last_instance_handle;
            if let Some(listener) = installed {
                let snap = status.clone();
                status.total_count_change = 0;
                self.status_condition
                    .clear_active_status(StatusMask::SAMPLE_REJECTED);
                own = self
                    .rejected_notices
                    .push(Box::new(move || listener.on_sample_rejected(snap)))
                    .err();
            } else {
                // Raise only. The WaitSet signal hooks run below, after
                // this lock is released: a hook is public trait code
                // (`WaitsetSignal`) and may read the status back through
                // `get_sample_rejected_status`, which takes this lock.
                self.status_condition
                    .raise_active_statuses(StatusMask::SAMPLE_REJECTED);
            }
        }
        if let Some(own) = own {
            // The queue is full: this report tells its own.
            super::notices::notify(own);
        } else if has_listener {
            let notices = Arc::clone(&self.rejected_notices);
            super::notices::notify(move || notices.tell());
        } else {
            // `WaitsetSignal` hooks are public trait code too.
            let status_condition = Arc::clone(&self.status_condition);
            super::notices::notify(move || {
                status_condition.notify_waitsets_for(StatusMask::SAMPLE_REJECTED);
            });
        }
    }

    /// The queues of this reader's ordered listener calls, for its
    /// `DataReader` to close when dropped.
    pub(super) fn listener_queues(&self) -> Vec<Arc<super::notices::Ordered>> {
        vec![
            Arc::clone(&self.rejected_notices),
            Arc::clone(&self.lost_notices),
        ]
    }

    /// Test seam: drive `report_sample_rejected` directly, bypassing
    /// `process_admitted`, so a concurrency test can hammer it from
    /// multiple threads without needing two real admission races.
    #[cfg(test)]
    pub(super) fn report_sample_rejected_for_test(
        &self,
        reason: SampleRejectedReason,
        last_instance_handle: Option<InstanceHandle>,
    ) {
        self.report_sample_rejected(reason, last_instance_handle);
    }

    /// Decode, filter, re-encode and copy into the slab pool one sample, the
    /// storage half of the decode -> filter -> re-encode -> slab -> ring ->
    /// listener pipeline. Run before a sample is acknowledged wherever the
    /// reader can still refuse it (`deliver_sample`), so a sample the slab
    /// pool has no room for is refused unacknowledged and sent again; run at
    /// the ring push for the paths that hand raw bytes over
    /// (`process_admitted` with nothing prepared).
    ///
    /// A sample that does not decode or that the content filter rejects
    /// (RTPS v2.5 Sec.8.3.8.4: a filtered change was still received) is
    /// `Discard`ed, one that cannot be re-encoded is `Unstorable`: either is
    /// received and delivers nothing, whenever the writer sends it.
    ///
    /// When the originating writer is known, the slab payload is laid out as
    /// [16-byte writer GUID | encoded sample] and the ring entry is
    /// GUID_PREFIX-flagged: the GUID would otherwise die here (IndexEntry
    /// carries no writer id), and an in-band prefix is per-sample
    /// self-describing -- no seq-keyed side map, which would inherit the
    /// cache's cross-writer seq collisions.
    fn prepare(
        &self,
        writer_guid: Option<[u8; 16]>,
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) -> Preparation<T> {
        self.prepare_as(
            writer_guid,
            remote_seq,
            data,
            version,
            StoreAs::Pool(rt::Claim::Reader),
        )
    }

    /// [`prepare`](Self::prepare), stored as `store_as` says.
    fn prepare_as(
        &self,
        writer_guid: Option<[u8; 16]>,
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        store_as: StoreAs,
    ) -> Preparation<T> {
        let msg = match T::decode(data, version) {
            Ok(m) => m,
            Err(_e) => {
                log::debug!(
                    "[READER-SUB] decode failed topic='{}' seq={} len={}: {:?}",
                    self.topic,
                    remote_seq,
                    data.len(),
                    _e
                );
                return Preparation::Discard;
            }
        };

        // Apply content filter if present
        if let Some(ref filter) = self.content_filter {
            let fields = match &self.field_extractor {
                Some(extract) => match extract(&msg) {
                    Some(fields) => fields,
                    None => {
                        // No field map (the descriptor does not decode the
                        // payload): rejected like a sample failing the filter.
                        log::debug!(
                            "[READER-SUB] Sample has no field map, rejected by content filter \
                             for topic='{}'",
                            self.topic
                        );
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        if let Some(metrics) = telemetry::get_metrics_opt() {
                            metrics.increment_dropped(1);
                        }
                        return Preparation::Discard;
                    }
                },
                None => T::get_fields(&msg),
            };
            match filter.matches(&fields) {
                Ok(true) => {
                    log::trace!(
                        "[READER-SUB] Sample passed content filter for topic='{}'",
                        self.topic
                    );
                }
                Ok(false) => {
                    log::debug!(
                        "[READER-SUB] Sample rejected by content filter for topic='{}'",
                        self.topic
                    );
                    // RTPS v2.5 Sec.8.3.8.4: a filtered change was still
                    // received, and is acknowledged: the writer is not
                    // NACKed for a sample this reader deliberately discarded.
                    return Preparation::Discard;
                }
                Err(e) => {
                    log::debug!(
                        "[READER-SUB] Filter evaluation error for topic='{}': {:?}",
                        self.topic,
                        e
                    );
                    // On error, reject the sample (fail-safe). The wire
                    // delivery still happened and is acknowledged (see the
                    // Ok(false) arm above).
                    return Preparation::Discard;
                }
            }
        }
        let mut prepared = self.store(writer_guid, remote_seq, msg, version, store_as);
        if let Preparation::Stored {
            legacy_key_hash, ..
        } = &mut prepared
        {
            *legacy_key_hash = crate::engine::router::route_legacy_hash(writer_guid, remote_seq);
        }
        prepared
    }

    /// Store a decoded sample in the slab pool as `store_as` says, in the
    /// form the ring carries (re-encoded, after its writer's GUID when
    /// known, and after the writer's full sequence number `remote_seq`
    /// when source ordering needs it or it exceeds the ring's 32 bits.
    /// Presentation compares DATA and lifecycle using the same full SN;
    /// ordinary reception-order entries keep their existing layout,
    /// `process_admitted` flags the entry to match).
    fn store(
        &self,
        writer_guid: Option<[u8; 16]>,
        remote_seq: u64,
        msg: T,
        version: crate::dds::CdrVersion,
        store_as: StoreAs,
    ) -> Preparation<T> {
        // Re-encode into this reader's retained scratch (dds::encode_scratch:
        // starts at 64KB, doubles on BufferTooSmall up to 16MB for DATA_FRAG
        // reassembled payloads, kept all zero at rest so no byte of an
        // earlier sample can survive into this one).
        let with_sn = writer_guid.is_some()
            && (remote_seq > u64::from(u32::MAX)
                || self.dispose_events.instances.by_source_timestamp());
        let guid_prefix_len =
            if writer_guid.is_some() { 16usize } else { 0 } + 8 * usize::from(with_sn);
        let mut encoded = match crate::dds::encode_scratch::encode_into_after(
            &self.reencode_scratch,
            guid_prefix_len,
            &msg,
            version,
        ) {
            Ok(encoded) => encoded,
            Err(_e) => {
                log::debug!("[READER-SUB] re-encode failed: {:?}", _e);
                return Preparation::Unstorable(msg);
            }
        };
        if let Some(guid) = writer_guid {
            let prefix = encoded.prefix_mut();
            prefix[..16].copy_from_slice(&guid);
            if with_sn {
                prefix[16..24].copy_from_slice(&remote_seq.to_le_bytes());
            }
        }
        let slab_len = encoded.bytes().len();
        // A load on every sample, a store on one of another size: an
        // estimate, two threads racing on it may lose a step.
        let estimate = self.head_estimate.load(Ordering::Relaxed);
        if slab_len != estimate {
            let next = if slab_len > estimate {
                slab_len
            } else {
                estimate - (estimate - slab_len).div_ceil(8)
            };
            self.head_estimate.store(next, Ordering::Relaxed);
        }
        let Ok(len) = u32::try_from(slab_len) else {
            drop(encoded);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            if let Some(m) = telemetry::get_metrics_opt() {
                m.increment_dropped(1);
            }
            log::debug!(
                "[reader] Serialized payload too large ({} bytes); dropping UDP packet",
                slab_len
            );
            return Preparation::Unstorable(msg);
        };

        let pool = rt::get_slab_pool_ref();
        let reserved = match store_as {
            StoreAs::Pool(claim) => pool
                .reserve_and_write(encoded.bytes(), claim)
                .map(|(handle, _metric)| handle),
            StoreAs::Staged => pool.reserve_staged(encoded.bytes()),
        };
        // Copied into the slab (or refused): give the scratch back before
        // anything below can reach a listener.
        drop(encoded);
        match reserved {
            Some(handle) => Preparation::Stored {
                msg,
                handle,
                len,
                legacy_key_hash: None,
            },
            // The process-wide slab byte budget (`SlabPool`, shared by
            // every reader in this process, primary + large + heap tiers)
            // had no room left for this sample, regardless of whether THIS
            // reader's own history has space: an idle reader can be
            // refused here by a busy neighbour's traffic.
            None => {
                log::debug!("[READER-SUB] slab_pool exhausted");
                Preparation::NoStorage { msg }
            }
        }
    }

    /// Store and deliver a sample of the path with no writer GUID, which
    /// credits nothing (no writer to acknowledge) and passes no gate. A
    /// sample with no storage is a resource limit the application hears
    /// about.
    fn deliver_unattributed(&self, remote_seq: u64, data: &[u8], version: crate::dds::CdrVersion) {
        let prepared = match self
            .prepare(None, remote_seq, data, version)
            .into_prepared()
        {
            Ok(prepared) => prepared,
            Err(msg) => {
                self.report_refusal(Refusal::Storage, Self::instance_handle_for_rejection(&msg));
                return;
            }
        };
        self.process_admitted(
            None,
            remote_seq,
            version,
            crate::engine::router::route_source_ts_ns(),
            None,
            prepared,
            None,
        );
    }

    /// Run a sample through the rest of the pipeline: ownership, ring push,
    /// listener. `prepared` is the sample decoded and stored before it was
    /// acknowledged (`deliver_sample`, a coherent set's staging), or, on the
    /// path with no writer GUID, just now (`deliver_unattributed`).
    /// `on_data_available` fires ONLY after the ring push succeeds: RTPS
    /// admission is not DDS delivery.
    ///
    /// A RELIABLE reader's sample reaching this point holds everything it
    /// needs: its storage and, for a reader with a history room, its place
    /// in the ring, both taken before its credit (RTPS v2.5 Sec.8.4.12.2,
    /// T8: `add_change`, then `received_change_set`); a coherent set's
    /// sample, its storage before its credit and its place at the commit. The slab-exhausted exit below is then
    /// reached only by the path with no writer GUID, which credits nothing;
    /// the full-ring exit, by a sample that came without a place.
    ///
    /// `slot` is the sample's place in the reader's history. A sample that
    /// arrives without one takes one here, and the full-ring exit is where
    /// it is refused.
    ///
    /// When `writer_guid` is `Some`, the writer is recorded in
    /// `writer_instances` as holding the decoded sample's instance, as of
    /// change `remote_seq`, so an unregister or a departure can tell
    /// whether another writer still writes it (DDS v1.4 Sec.2.2.2.4.2.7).
    ///
    /// `deferred`: a sample of a coherent set, announced (its listener, the
    /// reader's wake) with the rest of the set once the whole set is in the
    /// ring (`deliver_released`): announced one by one, a WaitSet woke on
    /// the set's first sample and the application took the set in part.
    #[allow(clippy::too_many_arguments)]
    fn process_admitted(
        &self,
        writer_guid: Option<[u8; 16]>,
        remote_seq: u64,
        version: crate::dds::CdrVersion,
        source_ts_ns: Option<u64>,
        slot: Option<super::admission::HistorySlot>,
        prepared: super::admission::Prepared,
        deferred: Option<&mut Vec<T>>,
    ) -> bool {
        let lifecycle = match &prepared {
            super::admission::Prepared::Stored(stored) => stored.inline_lifecycle,
            _ => None,
        };
        let delivered = self.process_admitted_data(
            writer_guid,
            remote_seq,
            version,
            source_ts_ns,
            slot,
            prepared,
            deferred,
        );
        if let (Some(writer), Some((key, kind))) = (writer_guid, lifecycle) {
            self.apply_lifecycle_ordered(writer, remote_seq, key, kind, source_ts_ns, true);
        }
        delivered
    }

    #[allow(clippy::too_many_arguments)]
    fn process_admitted_data(
        &self,
        writer_guid: Option<[u8; 16]>,
        remote_seq: u64,
        version: crate::dds::CdrVersion,
        source_ts_ns: Option<u64>,
        mut slot: Option<super::admission::HistorySlot>,
        prepared: super::admission::Prepared,
        deferred: Option<&mut Vec<T>>,
    ) -> bool {
        let legacy_hash = match &prepared {
            super::admission::Prepared::Stored(stored) => stored.legacy_key_hash,
            _ => None,
        };
        let learn = |key| {
            if !T::has_key() {
                return;
            }
            if let (Some(writer), Some(hash)) = (writer_guid, legacy_hash) {
                self.writer_instances
                    .learn_legacy_key_hash(writer, hash, key);
            }
        };
        let slab_pool = rt::get_slab_pool_ref();
        let (handle, len, msg) = match prepared {
            super::admission::Prepared::Discard => return false,
            // A dispose or unregister of a coherent set, delivered with the
            // set: its transition, now, in the set's order.
            super::admission::Prepared::Lifecycle { key, kind } => {
                if let Some(guid) = writer_guid {
                    self.apply_lifecycle(guid, remote_seq, key, kind, source_ts_ns);
                }
                return false;
            }
            super::admission::Prepared::Unstorable { key } => {
                // The writer is writing the instance all the same.
                if let Some(guid) = writer_guid {
                    self.writer_instances.admit_sample(guid, key, remote_seq);
                }
                return false;
            }
            super::admission::Prepared::Stored(stored) => match stored.take::<T>() {
                Some(parts) => parts,
                None => return false,
            },
        };

        // The writer holds the instance from this sample on. Done after the
        // content filter so a sample the reader explicitly rejected does
        // not later resurface as a NOT_ALIVE event on the departure path,
        // and before the ring push so the record is not coupled to
        // history/lifespan eviction; DDS v1.4 Sec.2.2.4.2.2 says the
        // instance-state transition is independent of whether the
        // application took the samples.
        //
        // Under EXCLUSIVE ownership the same lock arbitrates the instance
        // (Sec.2.2.3.10: "The arbitration is performed by the DataReader").
        // A writer that does not own it is still registered first: it IS
        // writing the instance, so the owner's unregister must not leave it
        // with no writers (Sec.2.2.2.4.2.7), and it is the one that takes
        // over once the owner lets go.
        let by_source = self.dispose_events.instances.by_source_timestamp();
        if let Some(guid) = writer_guid {
            let key_hash = msg.compute_key();
            let owned = self
                .writer_instances
                .admit_sample(guid, key_hash, remote_seq);
            if !owned {
                if by_source {
                    self.dispose_events
                        .instances
                        .revive_if_held(InstanceHandle::new(key_hash), || {
                            self.writer_instances.is_held_alive(&key_hash)
                        });
                }
                // Admitted, but hidden by EXCLUSIVE arbitration. Its own
                // unregister still needs to name the instance it writes.
                learn(key_hash);
                slab_pool.release(handle);
                log::debug!(
                    "[READER-SUB] topic='{}' writer={:02x?} seq={}: does not own the instance, \
                     sample not visible (EXCLUSIVE ownership)",
                    self.topic,
                    &guid[..4],
                    remote_seq
                );
                return false;
            }
        }

        // BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17): a sample older than
        // the last change its instance accepted is refused at admission,
        // whenever that runs, since the watermark only rises. Refused here,
        // before it takes a place in the history or the ring, it holds
        // nothing a later sample needs and owes no wake-up. It was
        // received all the same: like a sample of an instance its writer
        // does not own, it is acknowledged and not stored.
        if by_source {
            if let Some(ts) = source_ts_ns {
                let key = super::cache::SourceOrderKey(ts, writer_guid, remote_seq);
                if self
                    .dispose_events
                    .instances
                    .would_reject_by_source_order(InstanceHandle::new(msg.compute_key()), key)
                {
                    // A value refused by source order still proves writer
                    // presence; this is independent of storage admission.
                    let instance = InstanceHandle::new(msg.compute_key());
                    self.dispose_events.instances.revive_if_held(instance, || {
                        self.writer_instances.is_held_alive(&instance.0)
                    });
                    slab_pool.release(handle);
                    log::debug!(
                        "[READER-SUB] topic='{}' seq={}: older than its instance's last \
                         accepted change, not stored (BY_SOURCE_TIMESTAMP)",
                        self.topic,
                        remote_seq
                    );
                    return false;
                }
            }
        }

        // Use the raw remote_seq (truncated to u32) directly. Previously
        // we mapped via `SeqWindow::map` which re-initialises its `base` on
        // any arrival with `remote_seq < base` (SeqWindow step 2). When a
        // late-joiner buffered live samples (seq >> 1) before its HEARTBEAT
        // seed and only then drained the retransmits of seq 1..N, the re-init
        // mapped the smaller historical seqs onto the same local slot as the
        // earlier-buffered larger live seq -- SampleCache then duplicate-dropped
        // them silently, so sample seq 1 was lost on the application read.
        // Keying on the raw RTPS sequence avoids the slot collision and gives
        // every distinct remote_seq its own ring key. The slab prefix
        // preserves the full writer sequence number beyond the ring's width;
        // the decoded cache uses that full number, not this ring key.
        let seq = remote_seq as u32; // @audit-ok: `rt::IndexEntry.seq` IS a u32 (core/rt/indexring.rs) - this is the cache key's real width, not a narrowing choice made here; widening the entry is a core/rt change, see TODO

        let mut entry = rt::IndexEntry {
            seq,
            handle,
            len,
            flags: 0x01,
            cdr_version: version,
            // Lifespan is measured from the writer's source timestamp (DDS
            // v1.4 sec. 2.2.3 + RTPS v2.5 sec. 8.7.7). Use the datagram's INFO_TS when
            // present; fall back to reception time for datagrams without one.
            timestamp_ns: source_ts_ns.unwrap_or_else(current_time_ns),
        };
        // Preserve the source-vs-reception distinction (the value alone
        // cannot carry it) and announce the GUID prefix laid down above.
        if source_ts_ns.is_some() {
            entry.mark_source_ts();
        }
        if writer_guid.is_some() {
            entry.mark_guid_prefix();
            // Same layout decision as `store`: default entries need the
            // extra prefix only once the writer exceeds the ring's width.
            if remote_seq > u64::from(u32::MAX) || by_source {
                entry.mark_writer_sn_prefix();
            }
        }

        // A sample that reached this point without a slot (a coherent set's
        // commit, the path with no writer GUID) takes one now: every push
        // into the ring is reserved, which is what lets a reserved push
        // always find room.
        let mut refused = Refusal::ResourceLimit;
        if slot.is_none() {
            if let Some(ref room) = self.room {
                // A sample with no writer was acknowledged to nobody: it
                // leaves the writers' gaps their places, as every sample
                // that may still be refused does. One acknowledged already
                // (a coherent set's commit) takes what is free.
                let keep = match writer_guid {
                    None => match self.reorder.lock() {
                        Ok(gate) => gate.places_owed_by_all(),
                        Err(e) => e.into_inner().places_owed_by_all(),
                    },
                    Some(_) => 0,
                };
                match self.reserve_place(
                    room,
                    keep,
                    0,
                    || Some(msg.compute_key()),
                    source_ts_ns,
                    writer_guid,
                    remote_seq,
                    Replace::Always,
                ) {
                    Ok(granted) => slot = granted,
                    Err(bound) => refused = Refusal::from(bound),
                }
            }
        }
        let has_room = slot.is_some() || self.room.is_none();
        let instance_handle = InstanceHandle::new(msg.compute_key());
        let pushed = has_room && {
            let mut producer = match self.push_lock.lock() {
                Ok(guard) => guard,
                Err(e) => e.into_inner(),
            };
            if self.ring.is_full() {
                false
            } else {
                // A reader ordering by source timestamp asks the strict
                // separation here, in its admission. Every other reader
                // shows its samples at the application boundary (the cache
                // decides what is visible, on the instant it becomes so)
                // and admits every sample it has room for: a sample the
                // writer was credited for is never refused here, and the
                // newest of an instance always reaches the cache.
                let filter = || {
                    if self.time_based_filter.is_disabled() {
                        return true;
                    }
                    let mut checkers = self
                        .time_filter_checkers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let checker = checkers.entry(instance_handle).or_insert_with(|| {
                        crate::qos::time_based_filter::TimeBasedFilterChecker::new(
                            self.time_based_filter,
                        )
                    });
                    if !checker.should_accept() {
                        return false;
                    }
                    checker.mark_accepted();
                    true
                };
                // Admission is a receipt event, independent of the lazy pump.
                // Reserve storage and history first; a refusal changes no
                // instance counters, ordering watermark, or filter history.
                let counts = if by_source {
                    let key = source_ts_ns
                        .map(|ts| super::cache::SourceOrderKey(ts, writer_guid, remote_seq));
                    self.dispose_events.instances.admit_by_source(
                        instance_handle,
                        key,
                        (writer_guid, remote_seq),
                        || self.writer_instances.is_held_alive(&instance_handle.0),
                        filter,
                    )
                } else {
                    Some(
                        self.dispose_events
                            .instances
                            .arrive(instance_handle, (writer_guid, remote_seq)),
                    )
                };
                let Some(counts) = counts else {
                    slab_pool.release(handle);
                    return false;
                };
                slab_pool.set_generation_counts(handle, counts);
                entry.mark_generation_counts();
                producer.pushed();
                self.ring.push(entry)
            }
        };
        if pushed {
            // Storage and history admission succeeded, under the writer's
            // delivery fence. Refused samples never teach the legacy map.
            if legacy_hash.is_some() {
                learn(msg.compute_key());
            }
            // DEADLINE measures reception, independently of when the
            // application drains the ring (DDS v1.4 Sec.2.2.3.7).
            if let Some(deadlines) = self.dispose_events.deadlines.as_ref() {
                deadlines.on_sample(InstanceHandle::new(msg.compute_key()));
            }
            // In the ring now: the entry carries the sample's place until
            // the application takes it (see `HistoryRoom::adopt`).
            if let Some(slot) = slot {
                slot.into_ring();
            }
            log::debug!(
                "[READER-SUB] pushed topic='{}' seq={} len={}",
                self.topic,
                seq,
                len
            );
            // Preserve notification-only BY_SOURCE_TIMESTAMP callbacks;
            // its admitted samples are available through read/take. A
            // TIME_BASED_FILTER reader's are too: which sample the
            // application sees is decided when it enters the history.
            let notification_only = by_source || !self.time_based_filter.is_disabled();
            if let Some(deferred) = deferred {
                if !notification_only {
                    deferred.push(msg);
                }
                return true;
            }
            // The sample is in the ring now: safe to announce. See the
            // comment above this block for why this call moved here from
            // right after the content filter.
            // The network wake word is raised with the shared
            // (read-modify-write) form. This push has callers on four
            // threads: the router thread (DATA), the control thread (a
            // HEARTBEAT or GAP that releases samples) and a TCP or QUIC
            // routing thread through the reorder gate, and, for a reader
            // behind a
            // coherent-presentation barrier, the application thread
            // through `deliver_coherent_set` inside `take_all`. The
            // per-writer delivery lock serializes the pushes of ONE
            // writer; nothing orders two writers' pushes against each
            // other, so two plain stores of the word would not form one
            // release sequence and the reader's clearing swap would
            // synchronize with only one of them (see WakeWords). The RMW
            // keeps every raise in one sequence; it is not on the
            // intra-process crown path.
            //
            // The ring itself is single-producer (`IndexRing`): its
            // producers take `push_lock` (see there).
            self.status_condition
                .raise_data_available_shared(WakeWord::Network.index());
            if let Some(guard) = &self.participant_guard {
                log::debug!(
                    "[READER-SUB-SIGNAL] triggering participant guard topic='{}'",
                    self.topic
                );
                guard.set_trigger_value(true);
            }
            // The listener after the wake: a listener that panics does not
            // keep the sample, in the ring, from waking the reader. Called
            // with no lock of the reader held (`notices`): this push may be
            // under a writer's delivery lock.
            #[cfg(test)]
            {
                let hook = self
                    .pushed_hook
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(hook) = hook {
                    hook(remote_seq);
                }
            }
            if notification_only {
                if let Some(listener) = self.listener.get(StatusMask::DATA_AVAILABLE) {
                    super::notices::notify(move || listener.on_data_available_notification());
                }
                return true;
            }
            if let Some(listener) = self.listener.get(StatusMask::DATA_AVAILABLE) {
                super::notices::notify(move || listener.on_data_available(&msg));
            }
            true
        } else {
            // This reader's OWN history/ring bound is full (DDS
            // REJECTED_BY_SAMPLES_LIMIT), independent of any other
            // reader's traffic -- the counterpart of the slab-exhausted
            // exit above, distinguished by `samples_rejected_ring_full`.
            // Reached only by a sample that came without a place (see the
            // comment on this function).
            slab_pool.release(handle);
            log::debug!("Reader history full - dropping sample ({:?})", refused);
            self.report_refusal(refused, Self::instance_handle_for_rejection(&msg));
            false
        }
    }

    /// Push the payloads of a coherent set (in writer-seq order) through
    /// the per-sample pipeline. `writer_guid` tags the
    /// originating DataWriter so `process_admitted` can update the
    /// per-(writer, instance) tracker used by SEDP-W dispose detection.
    fn deliver_released(&self, writer_guid: Option<[u8; 16]>, released: Vec<PendingPayload>) {
        let mut pushed: Vec<T> = Vec::new();
        let mut any = false;
        for payload in released {
            if let (Some(change), Some(writer), Some(barrier)) =
                (payload.order, writer_guid, self.coherent_barrier.as_ref())
            {
                let mut ordered = self.ordered_payload(writer, payload);
                let Some(token) = ordered.token.as_mut() else {
                    continue;
                };
                if !token.attach() {
                    continue;
                }
                let payload = ordered.payload;
                let delivered = self.process_admitted(
                    Some(writer),
                    payload.remote_seq,
                    payload.version,
                    payload.source_ts_ns,
                    payload.slot,
                    payload.prepared,
                    Some(&mut pushed),
                );
                if delivered {
                    if let Some(token) = ordered.token.as_mut() {
                        token.commit();
                    }
                }
                self.finish_departed_ordered_delivery(writer);
                if let Some(member) = self.barrier_member {
                    barrier.wire_settled(member, writer, change);
                }
                any |= delivered;
                continue;
            }
            any |= self.process_admitted(
                writer_guid,
                payload.remote_seq,
                payload.version,
                payload.source_ts_ns,
                payload.slot,
                payload.prepared,
                Some(&mut pushed),
            );
        }
        self.announce(any, pushed);
    }

    /// Announce samples pushed into the ring, together (`process_admitted`):
    /// the reader's wake at once, once (not application code: a WaitSet on
    /// the reader learns of them even if what follows fails), then each to
    /// the listener, with no lock of the reader held (`notices`): for a
    /// coherent set, once every part of its generation is in its reader's
    /// ring. A listener that panics does not keep the others from being
    /// told. `any`: whether anything was pushed at all, which `pushed`
    /// alone does not say for a BY_SOURCE_TIMESTAMP reader: its samples
    /// notify the listener without a payload (`process_admitted`).
    fn announce(&self, any: bool, pushed: Vec<T>) {
        if !any {
            return;
        }
        // Shared (read-modify-write) raise, as every raise of the network
        // word (see `process_admitted`).
        self.status_condition
            .raise_data_available_shared(WakeWord::Network.index());
        if let Some(guard) = &self.participant_guard {
            guard.set_trigger_value(true);
        }
        if self.dispose_events.instances.by_source_timestamp()
            || !self.time_based_filter.is_disabled()
        {
            if let Some(listener) = self.listener.get(StatusMask::DATA_AVAILABLE) {
                super::notices::notify(move || listener.on_data_available_notification());
            }
            return;
        }
        if pushed.is_empty() {
            return;
        }
        let Some(listener) = self.listener.get(StatusMask::DATA_AVAILABLE) else {
            return;
        };
        super::notices::notify(move || {
            let mut panic = None;
            for msg in &pushed {
                if let Err(p) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    listener.on_data_available(msg);
                })) {
                    panic.get_or_insert(p);
                }
            }
            if let Some(panic) = panic {
                std::panic::resume_unwind(panic);
            }
        });
    }

    /// Commit, each as one unit, the coherent sets staged for `writer_guid`
    /// (`coherent_buffer`, TOPIC or INSTANCE scope, and a GROUP reader's
    /// classic writers) that are both closed and complete.
    ///
    /// A set is the writer's changes from its first sequence number, the
    /// `PID_COHERENT_SET` its samples carry, up to the one before the first
    /// change that is not of the set (RTPS v2.5 Sec.8.7.5, Sec.8.7.6): the
    /// first sample of another set, a DATA with no coherent-set inline QoS,
    /// an end-of-set marker (classic or HDDS). That change is the earliest
    /// of: what the reorder gate holds above the set's start (plain DATA and
    /// markers take their turn there, and it cannot pass a set not
    /// committed); the starts of later sets, staged or refused; the end an
    /// end marker counts; for a reader with no gate, the plain DATA and
    /// markers recorded meanwhile (`SetEnds`). The set is complete once
    /// every sequence number of it is staged.
    ///
    /// Committing on the end alone, or on the next set's first sample,
    /// delivered whatever was staged, and a sample of the set lost on the
    /// way, or refused when staged, was then staged into a set that never
    /// closed: the set reached the application in part, and the rest of it
    /// was acknowledged and never delivered (DDS v1.4 Sec.2.2.3.6; RTPS v2.5
    /// Sec.8.7.6, "Incomplete coherent sets shall not be added"). A plain
    /// DATA closed nothing, and the set it followed waited for a next set
    /// that might never come.
    ///
    /// A committed set enters the reorder gate as staged samples
    /// (`ReorderGate::on_staged`): delivered in the writer's order, with
    /// what the gate held behind it, as one unit when the gate releases it
    /// whole. `pause_for_test` is where a test pauses a commit decided from
    /// what was staged (`ReaderAckCredit::hold_next`).
    fn try_commit_sets(&self, writer_guid: [u8; 16], pause_for_test: bool) {
        // A pass that decided a set moved its writer's gate: a later set
        // that waited for it is decided by the next pass. A loop, not a
        // call per set: as many passes as sets chained behind one another,
        // on any stack.
        //
        // Decided again here, the writer's sets wait no more but as this
        // decision says (a pass that finds one waiting records it again).
        self.forget_wait_on_gate(&writer_guid);
        let mut pause = pause_for_test;
        while self.commit_sets_pass(writer_guid, std::mem::take(&mut pause)) {}
    }

    /// `writer_guid`'s sets wait for its gate no more (`try_commit_sets`):
    /// whether they did.
    fn forget_wait_on_gate(&self, writer_guid: &[u8; 16]) -> bool {
        if !self
            .writer_sets_awaiting
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }
        let mut waiting = self
            .writer_sets_await_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let waited = waiting.remove(writer_guid);
        if waiting.is_empty() {
            self.writer_sets_awaiting
                .store(false, std::sync::atomic::Ordering::Release);
        }
        waited
    }

    /// One pass of [`try_commit_sets`](Self::try_commit_sets): whether it
    /// decided a set while another of the writer's waited for its gate.
    fn commit_sets_pass(&self, writer_guid: [u8; 16], pause_for_test: bool) -> bool {
        // Its listeners are told once its delivery locks are released.
        let _delivering = super::notices::Delivering::enter();
        let committing = self.commit_lock.lock().unwrap_or_else(|e| e.into_inner());
        // (seq, set start) of what is staged.
        let staged: Vec<(u64, u64)> = {
            let buf = self
                .coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            buf.get(&writer_guid)
                .map(|samples| {
                    samples
                        .iter()
                        .filter_map(|s| s.coherent_sn.map(|start| (s.remote_seq, start)))
                        .collect()
                })
                .unwrap_or_default()
        };
        #[cfg(test)]
        if pause_for_test {
            self.test_pause();
        }
        #[cfg(not(test))]
        let _ = pause_for_test;
        if staged.is_empty() {
            return false;
        }
        let mut members: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for &(seq, start) in &staged {
            members.entry(start).or_default().insert(seq);
        }
        let (ends, mut starts, others) = {
            let pend = self
                .pending_coherent_end
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match pend.get(&writer_guid) {
                Some(e) => (e.ends.clone(), e.starts.clone(), e.others.clone()),
                None => Default::default(),
            }
        };
        starts.extend(members.keys().copied());
        // Each closed set that is complete, or can never be (`broken`): its
        // start, its last sequence, whether broken.
        //
        // A BEST_EFFORT writer repairs nothing: a closed set with a member
        // missing will never be whole, and is discarded at once, reported
        // as lost (RTPS v2.5 Sec.8.7.6: samples lost to the best-effort
        // protocol leave the set incomplete, and an incomplete set's
        // changes "shall be discarded by the Subscriber"). Kept staged, its
        // remnants piled up to the staging bound, which then refused every
        // later sample of the writer for good.
        let best_effort = self.ack_credit.is_none();
        let mut wake = None;
        let mut awaits_gate = false;
        let ready: Vec<(u64, u64, bool)> = {
            let gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            members
                .iter()
                .filter_map(|(&start, seqs)| {
                    let after = [
                        gate.held_after(&writer_guid, start),
                        starts.range(start.saturating_add(1)..).next().copied(),
                        others.range(start.saturating_add(1)..).next().copied(),
                        ends.get(&start).map(|end| end.saturating_add(1)),
                    ];
                    let end = after.into_iter().flatten().min()?.checked_sub(1)?;
                    // Whole: every sequence of the set staged, but those
                    // its writer filtered for this reader, which are not
                    // part of it (`ReorderGate::note_filtered`).
                    let whole = end >= start
                        && u64::try_from(seqs.range(start..=end).count())
                            .ok()
                            .map(|held| {
                                held.saturating_add(gate.filtered_in(&writer_guid, start, end))
                            })
                            == Some(end - start + 1);
                    // A sample of the set a GAP declared irrelevant (its
                    // writer no longer has it): the set can never be whole
                    // either (RTPS v2.5 Sec.8.7.6, lines 7500-7515 of the
                    // 2.5 text: the subscriber-relevant set leaves out only
                    // changes filtered out or of writers not matched, and
                    // "if any is not received the coherent set is not
                    // complete").
                    //
                    // A best-effort reader decides it on the same rule: a
                    // sample the gate passed without it is lost for good (it
                    // decides on arrival, Sec.8.4.12.1). One it has not passed
                    // may still come: the end can overtake the set's last
                    // samples (they over shared memory, it over UDP, two legs
                    // with no order between them), and the set waits for
                    // them; decided at once, it was lost whole and the late
                    // samples stepped over.
                    // (A reader with no acknowledgement state and a gate
                    // that is not best-effort's, a test fixture's, keeps
                    // deciding it at once.)
                    let broken = !whole
                        && end >= start
                        && ((best_effort && !gate.is_best_effort())
                            || gate.misses_for_good(&writer_guid, start, end, seqs)
                            || (gate.is_best_effort()
                                && self.wire_bindings.is_none()
                                && self.best_effort_wait_over(writer_guid, start, &mut wake)));
                    // A whole set is delivered once its writer's gate can
                    // pass it, nothing of the writer before it still
                    // awaited, as a GROUP set's part is
                    // (`try_flush_group_sets`): fed into a gate that would
                    // hold it, the set was held there and released later
                    // on its own, outside its set and its Subscriber's
                    // barrier.
                    if whole && gate.would_hold(&writer_guid, start) {
                        awaits_gate = true;
                        return None;
                    }
                    (whole || broken).then_some((start, end, broken))
                })
                .collect()
        };
        if awaits_gate {
            self.writer_sets_await_gate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(writer_guid);
            self.writer_sets_awaiting
                .store(true, std::sync::atomic::Ordering::Release);
        }
        self.wake_best_effort_wait(wake);
        self.end_best_effort_waits(ready.iter().map(|&(start, _, _)| (writer_guid, start)));
        // What each set must leave free when it takes its places, as a
        // sample it holds would (`deliver_sample`): the places the gap
        // below it needs, and the other writers' gaps unless it fills its
        // own. Before the writer's first HEARTBEAT that gap is unknown, and
        // no set commits: the HEARTBEAT tries again (`on_writer_heartbeat`).
        let keeps: Vec<Option<(usize, usize)>> = {
            let gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            ready
                .iter()
                .map(|&(start, _, _)| {
                    let below = gate.places_to_keep(&writer_guid, start)?;
                    let owed = if below == 0 && gate.has_gap(&writer_guid) {
                        0
                    } else {
                        gate.places_owed_except(&writer_guid)
                    };
                    Some((below.saturating_add(owed), below))
                })
                .collect()
        };
        if ready.is_empty() {
            return false;
        }
        let mut taken: Vec<BufferedCoherentSample> = {
            let mut buf = self
                .coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let Some(entry) = buf.get_mut(&writer_guid) else {
                return false;
            };
            let (taken, rest): (Vec<_>, Vec<_>) = entry.drain(..).partition(|s| {
                s.coherent_sn.is_some_and(|start| {
                    ready
                        .iter()
                        .any(|&(f, e, _)| start == f && (f..=e).contains(&s.remote_seq))
                })
            });
            *entry = rest;
            taken
        };
        taken.sort_by_key(|s| s.remote_seq);
        // Each set takes, before it commits, a place in the history for
        // every one of its samples, all of them or none: its samples were
        // acknowledged when staged, and one refused at the push for want
        // of a place delivered the set in part and lost that sample. A set
        // that does not fit waits, staged, until a take gives places back
        // (`HistoryRoom::wait_for_room`), and the sets after it with it.
        let mut committed: Vec<(
            BufferedCoherentSample,
            Option<super::admission::HistorySlot>,
        )> = Vec::with_capacity(taken.len());
        let mut committed_sets: Vec<(u64, u64)> = Vec::new();
        let mut put_back: Vec<BufferedCoherentSample> = Vec::new();
        let mut rejected: Vec<(Vec<BufferedCoherentSample>, super::admission::Bound)> = Vec::new();
        // Sets that can never be whole: their staged members, the set's size.
        let mut lost: Vec<(Vec<BufferedCoherentSample>, u64)> = Vec::new();
        for (&(first, end, broken), &keep) in ready.iter().zip(&keeps) {
            let members: Vec<BufferedCoherentSample> = {
                let (members, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut taken)
                    .into_iter()
                    .partition(|s| (first..=end).contains(&s.remote_seq));
                taken = rest;
                members
            };
            if broken {
                self.note_discarded(writer_guid, first, end);
                // The samples it loses: its staged members, received,
                // discarded with it, and those never received.
                let count = staged_samples(&members).saturating_add(self.never_received(
                    writer_guid,
                    first,
                    end,
                ));
                lost.push((members, count));
                committed_sets.push((first, end));
                continue;
            }
            if !put_back.is_empty() {
                put_back.extend(members);
                continue;
            }
            // A set no history of this reader can ever hold whole (more
            // samples than its places, or than an instance or the instances
            // may count) is rejected whole, reported: waiting, it blocked
            // its writer's stream for good.
            if let Some(bound) = self.never_holds(&members) {
                rejected.push((members, bound));
                committed_sets.push((first, end));
                continue;
            }
            let Some((keep, headroom)) = keep else {
                put_back.extend(members);
                continue;
            };
            match self.places_or_wait(writer_guid, &members, keep, headroom) {
                Ok(slots) => {
                    committed.extend(members.into_iter().zip(slots));
                    committed_sets.push((first, end));
                }
                Err(Some(bound)) => {
                    rejected.push((members, bound));
                    committed_sets.push((first, end));
                }
                Err(None) => put_back.extend(members),
            }
        }
        // The members of a set rejected while this commit had them out of
        // the staging (`reject_staged_set` found nothing of it to free):
        // not put back, taken as the set's later members are once the
        // commit's locks are let go. Put back, their charges stayed and
        // the set they were staged under was delivered after all.
        let mut orphans: Vec<([u8; 16], StagedSet, BufferedCoherentSample)> = Vec::new();
        let drained = {
            let mut buf = self
                .coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !put_back.is_empty() {
                // Rejections are recorded under this lock.
                let (gone, kept): (Vec<_>, Vec<_>) = put_back.into_iter().partition(|m| {
                    self.set_rejected(StagedSet::Writer(
                        writer_guid,
                        m.coherent_sn.unwrap_or(m.remote_seq),
                    ))
                });
                orphans.extend(gone.into_iter().map(|m| {
                    let set = StagedSet::Writer(writer_guid, m.coherent_sn.unwrap_or(m.remote_seq));
                    (writer_guid, set, m)
                }));
                if !kept.is_empty() {
                    buf.entry(writer_guid).or_default().extend(kept);
                }
            }
            let drained = buf.get(&writer_guid).is_none_or(Vec::is_empty);
            if drained {
                buf.remove(&writer_guid);
            }
            drained
        };
        if committed_sets.is_empty() {
            drop(committing);
            self.take_orphaned_members(orphans);
            return false;
        }
        let ready = committed_sets;
        let last = ready.iter().map(|&(_, e)| e).max().unwrap_or(0);
        {
            let mut pend = self
                .pending_coherent_end
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Nothing staged any more: what was learned of where sets end
            // concerns sets the gate now orders.
            if drained {
                pend.remove(&writer_guid);
            } else if let Some(e) = pend.get_mut(&writer_guid) {
                e.forget_through(last);
                if e.is_empty() {
                    pend.remove(&writer_guid);
                }
            }
        }
        log::debug!(
            "[READER-SUB] coherent commit topic='{}' writer={:02x?} sets={:?}",
            self.topic,
            &writer_guid[..4],
            ready
        );
        // The writer's delivery lock before the gate's (a drain takes them in
        // that order), held until the sets are delivered: what the gate
        // releases for this writer meanwhile, on another thread, is queued
        // behind them (`Release::from_gate`), and what it queued before is
        // delivered first. The commit lock is let go before anything is
        // delivered: an application listener runs then, and may take, read
        // or write, with none of the reader's commit state held.
        let delivery_lock = self.writer_delivery_lock(writer_guid);
        let delivering = match delivery_lock.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let lost_count: u64 = lost.iter().map(|(_, n)| n).sum();
        let reports: Vec<(Refusal, Option<InstanceHandle>)> = rejected
            .iter()
            .flat_map(|(members, bound)| {
                // Its samples: a dispose or unregister of the set takes no
                // place and is no sample (`staged_samples`).
                members
                    .iter()
                    .filter(|m| m.lifecycle.is_none())
                    .map(move |member| {
                        (
                            Refusal::from(*bound),
                            Self::decode_staged(member)
                                .and_then(Self::instance_handle_for_rejection),
                        )
                    })
            })
            .collect();
        for (members, bound) in &rejected {
            log::debug!(
                "[READER-SUB] coherent set of {} samples rejected whole topic='{}' writer={:02x?} ({:?})",
                members.len(),
                self.topic,
                &writer_guid[..4],
                bound
            );
        }
        let released: Vec<PendingPayload> = {
            let mut gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            let mut released = gate.take_ready(&writer_guid, &delivering);
            let mut fed: Vec<(
                BufferedCoherentSample,
                Option<super::admission::HistorySlot>,
                bool,
            )> = committed
                .into_iter()
                .map(|(s, slot)| (s, slot, true))
                .collect();
            for (members, _) in &mut rejected {
                fed.extend(
                    std::mem::take(members)
                        .into_iter()
                        .map(|s| (s, None, false)),
                );
            }
            for (members, _) in &mut lost {
                fed.extend(
                    std::mem::take(members)
                        .into_iter()
                        .map(|s| (s, None, false)),
                );
            }
            fed.sort_by_key(|(s, _, _)| s.remote_seq);
            for (sample, slot, delivers) in fed {
                if !delivers {
                    released.extend(gate.on_staged(
                        writer_guid,
                        sample.remote_seq,
                        PendingPayload::nothing(sample.remote_seq),
                    ));
                    continue;
                }
                let seq = sample.remote_seq;
                released.extend(gate.on_staged(writer_guid, seq, sample.into_payload(slot)));
            }
            released
        };
        drop(committing);
        for (refusal, instance) in reports {
            self.report_refusal(refusal, instance);
        }
        self.report_sample_lost(lost_count);
        // One unit per set, every other change on its own, in order.
        let mut unit: Vec<PendingPayload> = Vec::new();
        let mut unit_set: Option<u64> = None;
        for payload in released {
            let set = ready
                .iter()
                .find(|&&(f, e)| (f..=e).contains(&payload.remote_seq))
                .map(|&(f, _)| f);
            if set.is_none() || set != unit_set {
                self.emit_coherent_payloads(writer_guid, std::mem::take(&mut unit));
            }
            unit_set = set;
            unit.push(payload);
        }
        self.emit_coherent_payloads(writer_guid, unit);
        drop(delivering);
        self.take_orphaned_members(orphans);
        awaits_gate
    }

    /// Members a commit had out of the staging when their set was rejected
    /// (`try_commit_sets`, `try_flush_group_sets`): each gives its storage
    /// and charge back and is taken as a member of the set landing since
    /// (`take_rejected_member`). Called with no lock of the commit held.
    fn take_orphaned_members(
        &self,
        mut orphans: Vec<([u8; 16], StagedSet, BufferedCoherentSample)>,
    ) {
        orphans.sort_by_key(|(writer, _, member)| (*writer, member.remote_seq));
        for (writer, set, member) in orphans {
            let (seq, sample) = (member.remote_seq, member.lifecycle.is_none());
            drop(member);
            self.take_rejected_member(writer, seq, set, sample);
        }
    }

    /// A place in the history for each of `members`, all or none (`None`),
    /// each leaving `keep` places free, and `headroom` samples of its
    /// instance and instances when the gate will hold it above a gap (see
    /// `HistoryRoom::reserve_for`).
    /// A reader with no history room needs none (`Ok` of no slot each).
    /// `Err`: the bound a member met.
    fn places_for<M: std::borrow::Borrow<BufferedCoherentSample>>(
        &self,
        writer: [u8; 16],
        members: &[M],
        keep: usize,
        headroom: usize,
    ) -> Result<Vec<Option<super::admission::HistorySlot>>, super::admission::Bound> {
        let Some(room) = &self.room else {
            return Ok(members.iter().map(|_| None).collect());
        };
        let mut slots = Vec::with_capacity(members.len());
        for member in members {
            let member: &BufferedCoherentSample = member.borrow();
            // A dispose or unregister of the set takes no place.
            if member.lifecycle.is_some() {
                slots.push(None);
                continue;
            }
            let key = || Self::decode_staged(member).map(|msg| msg.compute_key());
            // KEEP_LAST: a set's sample replaces the oldest of its instance
            // in a full ring, as a single sample does (its ownership
            // arbitrated first, `Replace::IfVisible`): a KEEP_LAST history
            // never makes a reliable writer wait, and a set that waited for
            // a take there held its writer's stream behind it.
            let replace = if room.keep_last().is_some() {
                Replace::IfVisible {
                    writer,
                    seq: member.remote_seq,
                }
            } else {
                Replace::Never
            };
            match self.reserve_place(
                room,
                keep,
                headroom,
                key,
                member.source_ts_ns,
                Some(writer),
                member.remote_seq,
                replace,
            ) {
                Ok(slot) => slots.push(slot),
                Err(bound) => {
                    Self::give_back_quietly(slots);
                    return Err(bound);
                }
            }
        }
        Ok(slots)
    }

    /// [`places_for`](Self::places_for), or, if the set does not fit, the
    /// room marked as waited for (`HistoryRoom::wait_for_room`) and the
    /// places asked once more. Room given back between the refusal and the
    /// mark found no set waiting and scheduled nothing: asked only before
    /// the mark, the set then waited for room that had already come back,
    /// for good if nothing else was ever given back.
    ///
    /// A best-effort reader never waits (`Err`, the bound met): its gate
    /// passes the writer's later changes at once, and a set that waited for
    /// a take reached the application behind them. It is rejected whole, as
    /// a single sample that finds no place is.
    fn places_or_wait<M: std::borrow::Borrow<BufferedCoherentSample>>(
        &self,
        writer: [u8; 16],
        members: &[M],
        keep: usize,
        headroom: usize,
    ) -> Result<Vec<Option<super::admission::HistorySlot>>, Option<super::admission::Bound>> {
        let bound = match self.places_for(writer, members, keep, headroom) {
            Ok(slots) => return Ok(slots),
            Err(bound) => bound,
        };
        if self.ack_credit.is_none() {
            return Err(Some(bound));
        }
        #[cfg(test)]
        if let Some(hook) = self
            .refused_room_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            hook();
        }
        if let Some(room) = self.room.as_ref() {
            room.wait_for_room();
        }
        self.places_for(writer, members, keep, headroom)
            .map_err(|_| None)
    }

    /// The places of a set that does not fit, given back without scheduling
    /// a retry (`HistorySlot::give_back_quietly`).
    fn give_back_quietly(slots: Vec<Option<super::admission::HistorySlot>>) {
        for slot in slots.into_iter().flatten() {
            slot.give_back_quietly();
        }
    }

    /// A staged sample, decoded when it was staged; `None` for one that
    /// delivers nothing (it does not decode, the content filter rejects it,
    /// it cannot be stored for the ring).
    fn decode_staged(member: &BufferedCoherentSample) -> Option<&T> {
        member.prepared.sample::<T>()
    }

    /// The bound a set of `members` exceeds in any history of this reader
    /// (`HistoryRoom::never_holds`), if any. (A set rejected for its
    /// storage is staged no more, `reject_staged_set`.)
    fn never_holds<M: std::borrow::Borrow<BufferedCoherentSample>>(
        &self,
        members: &[M],
    ) -> Option<super::admission::Bound> {
        let room = self.room.as_ref()?;
        // A dispose or unregister of the set takes no place.
        let samples = members
            .iter()
            .map(std::borrow::Borrow::borrow)
            .filter(|m: &&BufferedCoherentSample| m.lifecycle.is_none());
        let keys: Vec<Option<[u8; 16]>> = if room.counts_instances() {
            samples
                .map(|m| Self::decode_staged(m).map(|msg| msg.compute_key()))
                .collect()
        } else {
            samples.map(|_| None).collect()
        };
        room.never_holds(&keys)
    }

    /// Every writer's staged sets tried again (`try_commit_sets`): a take
    /// gave places back (`HistoryRoom::wait_for_room`).
    pub(super) fn retry_waiting_sets(&self) {
        let writers: Vec<[u8; 16]> = self
            .coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect();
        for writer in writers {
            self.try_commit_sets(writer, false);
        }
        self.try_flush_group_sets();
    }

    /// How many of `writer_guid`'s sequences `first..=last` are samples
    /// lost: never received (`SeenSeqs::unreceived_in`), not filtered for this
    /// reader (RTPS v2.5 Sec.8.3.8.4: "Filtered changes should not be
    /// treated as samples lost"), not reported before. Recorded as reported.
    /// DDS v1.4 Sec.2.2.4.1: SAMPLE_LOST, "A sample has been lost (never
    /// received)". A change received, a sample or not (a dispose, an end of
    /// set marker), delivered or discarded, is not one; a change never
    /// received is counted as a sample, its kind unknown.
    /// A best-effort set of `writer_guid` starting at `first` misses a
    /// member its gate has not passed: whether it has waited for it long
    /// enough (`BEST_EFFORT_OVERTAKE_WAIT`), the member then lost. Its first
    /// look starts the wait, and returns when a retry must decide it again
    /// (`wake`); the caller schedules it once its locks are released.
    fn best_effort_wait_over(
        &self,
        writer_guid: [u8; 16],
        first: u64,
        wake: &mut Option<std::time::Instant>,
    ) -> bool {
        let bound = std::time::Duration::from_millis(
            self.best_effort_wait_ms
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        let mut waits = self
            .best_effort_waits
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(since) = waits.get(&(writer_guid, first)) {
            return since.elapsed() >= bound;
        }
        let now = std::time::Instant::now();
        // What waits that long for nothing (its set gone another way) is
        // forgotten.
        let stale = bound
            .saturating_mul(20)
            .max(std::time::Duration::from_secs(1));
        waits.retain(|_, since| since.elapsed() < stale);
        waits.insert((writer_guid, first), now);
        self.best_effort_waiting
            .store(waits.len(), std::sync::atomic::Ordering::Release);
        if bound.is_zero() {
            return true;
        }
        *wake = Some(wake.map_or(now + bound, |at| at.min(now + bound)));
        false
    }

    /// The best-effort sets `sets` (writer, first SN) are decided: they
    /// wait no more.
    fn end_best_effort_waits(&self, sets: impl IntoIterator<Item = ([u8; 16], u64)>) {
        if self
            .best_effort_waiting
            .load(std::sync::atomic::Ordering::Acquire)
            == 0
        {
            return;
        }
        let mut waits = self
            .best_effort_waits
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for set in sets {
            waits.remove(&set);
        }
        self.best_effort_waiting
            .store(waits.len(), std::sync::atomic::Ordering::Release);
    }

    /// Schedule the retry a best-effort wait asked for.
    fn wake_best_effort_wait(&self, wake: Option<std::time::Instant>) {
        if let (Some(at), Some(room)) = (wake, self.room.as_ref()) {
            room.retry_at(at);
        }
    }

    fn never_received(&self, writer_guid: [u8; 16], first: u64, last: u64) -> u64 {
        if last < first {
            return 0;
        }
        let filtered = self
            .reorder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .filtered_ranges(&writer_guid);
        self.never_received_in(
            writer_guid,
            [(first.max(1), last.saturating_add(1))],
            &filtered,
        )
    }

    /// Apply T2 to a sample-less DATA, before its sequence can roll the
    /// receipt window past unreceived samples (RTPS v2.5 Sec.8.4.12.1,
    /// Sec.8.7.6). A received control is never itself SAMPLE_LOST, even
    /// when no staging metadata can be kept for it.
    fn accept_best_effort_control(&self, writer: [u8; 16], seq: u64) -> Option<Seen> {
        if self.ack_credit.is_some() {
            return None;
        }
        let (admitted, lost) = {
            let mut gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
            if !gate.is_best_effort() {
                return None;
            }
            if self.has_left(&writer) {
                return Some(Seen::Duplicate);
            }
            let mut seen = self
                .seen_seqs_by_writer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let record = seen.entry(writer).or_default();
            let admitted = record.judge(seq, Missed::Dropped, || None);
            let mut lost = 0;
            if admitted == Seen::New {
                if let Some(next) = gate.next_seq(&writer).filter(|&next| next < seq) {
                    lost =
                        record.report_unreceived_in([(next, seq)], &gate.filtered_ranges(&writer));
                }
                record.record(seq, Missed::Dropped);
                record.settle(seq);
                gate.observe(writer, seq, None);
            }
            (admitted, lost)
        };
        self.report_sample_lost(lost);
        Some(admitted)
    }

    /// A staged BEST_EFFORT DATA is about to advance the gate. Its
    /// admission kept missed runs until this decision, so even a jump
    /// beyond the duplicate window reports every unreceived sample.
    /// Called with the reorder gate held, before `observe` advances it.
    fn best_effort_gap_before(&self, gate: &ReorderGate, writer: [u8; 16], seq: u64) -> u64 {
        if !gate.is_best_effort() {
            return 0;
        }
        let mut seen = self
            .seen_seqs_by_writer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let record = seen.entry(writer).or_default();
        let lost = gate
            .next_seq(&writer)
            .filter(|&next| next < seq)
            .map_or(0, |next| {
                record.report_unreceived_in([(next, seq)], &gate.filtered_ranges(&writer))
            });
        record.settle(seq);
        lost
    }

    /// [`never_received`](Self::never_received) over `ranges` (`[start,
    /// end)`, in order, disjoint), but `filtered` (`ReorderGate::
    /// filtered_ranges`): ranges and runs throughout, never a walk of the
    /// sequences, under the duplicate record's lock alone.
    fn never_received_in(
        &self,
        writer_guid: [u8; 16],
        ranges: impl IntoIterator<Item = (u64, u64)>,
        filtered: &BTreeMap<u64, u64>,
    ) -> u64 {
        if self.wire_bindings.is_some() {
            if let Some(credit) = &self.ack_credit {
                let ledger = self.wire_loss_ledger(writer_guid, None).or_else(|| {
                    self.departed
                        .read()
                        .get(&writer_guid)
                        .and_then(|entry| entry.losses.clone())
                });
                let Some(ledger) = ledger else { return 0 };
                return ranges.into_iter().fold(0u64, |count, (lo, hi)| {
                    let lost = match (i64::try_from(lo), i64::try_from(hi)) {
                        (Ok(lo), Ok(hi)) => credit
                            .group_gap_loss(&writer_guid, &ledger.authority, lo, hi, &[], filtered)
                            .unwrap_or(0),
                        _ => 0,
                    };
                    count.saturating_add(lost)
                });
            }
        }
        let mut map = self
            .seen_seqs_by_writer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let record = map.entry(writer_guid).or_default();
        record.report_unreceived_in(ranges, filtered)
    }

    /// How many of the changes a GAP of `writer_guid` declares (RTPS v2.5
    /// Sec.8.3.8.4: `[gap_start, gap_list_base)` and `gap_list_seqs`) are
    /// samples lost (`never_received`): only those this reader is owed, at
    /// or above `owed_from`, where its seeded gate was when the GAP came;
    /// but `filtered`.
    fn lost_to_gap(
        &self,
        writer_guid: [u8; 16],
        owed_from: u64,
        filtered: &BTreeMap<u64, u64>,
        gap: (u64, u64, &BTreeSet<u64>),
    ) -> u64 {
        let (gap_start, gap_list_base, listed) = gap;
        let owed_from = owed_from.max(1);
        // The GAP's set: [gapStart, gapList.base - 1] and what gapList lists
        // beyond it (`listed`; a gapList.base at or below gapStart adds no
        // range).
        let from = gap_start.max(owed_from);
        let range = (from < gap_list_base).then_some((from, gap_list_base));
        // In order: what gapList lists below gapStart, the range, what it
        // lists at or above gapList.base.
        let below: Vec<(u64, u64)> = listed
            .range(owed_from..gap_start.max(owed_from))
            .map(|&seq| (seq, seq.saturating_add(1)))
            .collect();
        let above = listed
            .range(gap_list_base.max(gap_start).max(owed_from)..)
            .map(|&seq| (seq, seq.saturating_add(1)));
        self.never_received_in(
            writer_guid,
            below.into_iter().chain(range).chain(above),
            filtered,
        )
    }

    /// Record that `writer_guid`'s set `first..=last` was discarded.
    fn note_discarded(&self, writer_guid: [u8; 16], first: u64, last: u64) {
        let mut discarded = self
            .discarded_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sets = discarded.entry(writer_guid).or_default();
        sets.insert(first, last);
        while sets.len() > MAX_DISCARDED_SETS {
            sets.pop_first();
        }
    }

    /// Record that the GROUP set `key` was discarded.
    /// This member's part of GROUP set `key` of the spec dialect is
    /// discarded: the set is lost for every member of the Subscriber's
    /// barrier (`CoherentSet::lost`). Nothing without a barrier.
    fn abandon_spec_generation(&self, key: GroupSetKey) {
        if let (Some(barrier), Some(member)) = (self.coherent_barrier.as_ref(), self.barrier_member)
        {
            barrier.deposit(
                member,
                super::coherent_barrier::publisher_key(key.0, key.1),
                CoherentSet::spec_part(Vec::new(), key.2, true),
            );
        }
    }

    fn note_group_discarded(&self, key: GroupSetKey) {
        let mut discarded = self
            .discarded_group_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (keys, order) = &mut *discarded;
        if keys.insert(key) {
            order.push_back(key);
            if order.len() > MAX_DISCARDED_GROUP_SETS {
                if let Some(oldest) = order.pop_front() {
                    keys.remove(&oldest);
                }
            }
        }
    }

    /// Whether the GROUP set `key` was discarded already, or rejected for
    /// its storage (`reject_staged_set`): an end or a change of it opens
    /// no set again.
    fn group_set_discarded(&self, key: &GroupSetKey) -> bool {
        let discarded = self
            .discarded_group_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .contains(key);
        discarded || self.set_rejected(StagedSet::Group(*key))
    }

    /// Whether `seq`, of the set that starts at `set_start`, belongs to a
    /// set of `writer_guid` discarded already.
    fn discarded_member(&self, writer_guid: &[u8; 16], set_start: u64, seq: u64) -> bool {
        self.discarded_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(writer_guid)
            .and_then(|sets| sets.get(&set_start))
            .is_some_and(|&last| seq <= last)
    }

    /// Admit a change of `writer_guid` that carries no sample into the
    /// duplicate record its DATA samples share, and credit it as received:
    /// whether it is new. A repair of one admitted already is credited and
    /// moves nothing more; one the record cannot take without dropping
    /// something it owes is refused unacknowledged, as a sample is, and the
    /// writer sends it again.
    fn admit_change_without_sample(&self, writer_guid: [u8; 16], seq: u64) -> bool {
        let Some(receipt) = self.prepare_control_receipt(writer_guid, seq) else {
            return false;
        };
        // A control carrying GROUP_INFO occupies its GSN even though it
        // carries no application sample. Bound that proof before receipt.
        let order = self.capture_wire_order(writer_guid, seq);
        if let Some(change) = order {
            let Some((barrier, member)) = self.coherent_barrier.as_ref().zip(self.barrier_member)
            else {
                return false;
            };
            if !barrier.wire_accounted(change, member) {
                return false;
            }
        }
        let admitted = self
            .accept_best_effort_control(writer_guid, seq)
            .unwrap_or_else(|| {
                let mut map = match self.seen_seqs_by_writer.lock() {
                    Ok(lock) => lock,
                    Err(e) => e.into_inner(),
                };
                self.admit_seen(
                    map.entry(writer_guid).or_default(),
                    writer_guid,
                    seq,
                    self.missed(),
                )
            });
        let fresh = match admitted {
            Seen::New => true,
            Seen::Duplicate => false,
            // Unrecorded, unacknowledged: the writer sends it again.
            Seen::Full => return false,
        };
        // A duplicate is received too, but must not close a set twice.
        if !self.credit_control_receipt(writer_guid, seq, &receipt) {
            return false;
        }
        self.note_wire_control_prefix(writer_guid, seq, order);
        fresh
    }

    /// Pass a change without a sample, admitted, through `writer_guid`'s
    /// gate. Whoever moves the proxy moves the gate (see `follow_proxy`):
    /// the gate does not record a sample-less sequence above its base, and
    /// the proxy, now settled past it, may have been waiting on it.
    fn pass_change_without_sample(&self, writer_guid: [u8; 16], seq: u64) {
        let settled = self
            .gate_is_bounded()
            .then(|| self.settled(writer_guid))
            .flatten();
        self.release_through_gate(writer_guid, |gate| {
            let mut released = gate.on_non_data(writer_guid, seq);
            if let Some(settled) = settled {
                released.append(&mut gate.catch_up(writer_guid, settled));
            }
            released
        });
    }

    /// Record, for the sets of `writer_guid` staged now, what a change
    /// says of where they end: `start` the start of a set (a sample refused
    /// when staged), `other` a change of no set, `counted` a set's start and
    /// its last sequence (an end marker that counts its samples).
    fn note_set_ends(
        &self,
        writer_guid: [u8; 16],
        start: Option<u64>,
        other: Option<u64>,
        counted: Option<(u64, u64)>,
    ) {
        let mut early = false;
        if other.is_some() && start.is_none() && counted.is_none() {
            // Only while a set is staged: the gate keeps the rest. A gate
            // that does not keep a change without a sample keeps nothing of
            // it (`ReorderGate::keeps_non_data`): a best-effort gate, which
            // passes it as a GAP, and a volatile reliable gate its writer's
            // first DATA has not seeded yet. An end of set that overtook
            // every member of its set (they over shared memory, it over
            // UDP; a member still being reassembled from DATA_FRAG) is kept
            // here, or its set, staged next, never knew where it ended.
            let staged = self
                .coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&writer_guid);
            let gate_keeps = self
                .reorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .keeps_non_data(&writer_guid);
            if !staged && gate_keeps {
                return;
            }
            early = !staged;
        }
        let mut pend = self
            .pending_coherent_end
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ends = pend.entry(writer_guid).or_default();
        if let Some(start) = start {
            ends.starts.insert(start);
        }
        if let Some(other) = other {
            ends.others.insert(other);
            // Kept before any set is staged, bounded: the lowest ones end
            // the sets to come first.
            if early && ends.others.len() > MAX_EARLY_SET_ENDS {
                ends.others.pop_last();
            }
        }
        if let Some((start, last)) = counted {
            ends.ends.insert(start, last);
        }
    }

    /// Step the per-writer reorder gate past the End-of-Coherent-Set DATA
    /// marker's own writer sequence number.
    ///
    /// The HDDS coherent model (RTPS v2.5 sec. 8.7.5) sends the ECS as a real
    /// DATA submessage that reserves a fresh writer SN of its own,
    /// immediately after the set's last in-set sample. That SN is a
    /// coherent-set marker -- it is dispatched to `on_ecs`, never delivered
    /// through the data path, so the reorder gate (enabled for RELIABLE
    /// readers) never sees it as DATA. Without
    /// this skip the gate's `next_seq` parks on the marker SN and every
    /// subsequent coherent set is buffered as a permanent future-gap -- a
    /// multi-set stall on the HDDS<->HDDS path.
    ///
    /// Reuses the unit-tested GAP machinery: `on_gap` declares `ecs_seq`
    /// irrelevant, advances `next_seq` only if it sits exactly on the
    /// marker (so a genuine pre-marker data gap is NOT over-advanced), and
    /// drains any parked samples already staged behind it. No-op when the
    /// gate is disabled (BEST_EFFORT) -- zero regression by construction.
    ///
    /// Samples the skip rescues out of the gate belong to a coherent set
    /// that was previously swallowed as a future gap (a discovery-seam
    /// artifact), so they are emitted as one atomic unit through the
    /// coherent path -- for a barrier-wired reader that deposits them for
    /// aligned release instead of pushing them straight to the ring, where
    /// they would surface ON TOP of an aligned generation in the same read
    /// cycle (a doubled read cycle, breaching the one-set-per-cycle
    /// presentation of DDS v1.4 sec. 2.2.3.6). Readers without a barrier keep
    /// the direct ring delivery (emit falls back to it).
    fn skip_ecs_seq_in_gate(&self, writer_guid: [u8; 16], ecs_seq: u64) {
        let released = {
            let mut gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            // A gate seeded by a HEARTBEAT, or seeded already, takes the
            // marker as a change without a sample, kept until the gate
            // reaches it: as a GAP it seeded a gate not seeded yet past
            // itself, and the samples before it, its set included, were
            // dropped as delivered; above the base, it was recorded only as
            // passed over, which a coherent reader's gate never crosses.
            if gate.seeded_by_heartbeat() || gate.next_seq(&writer_guid).is_some() {
                gate.on_non_data(writer_guid, ecs_seq)
            } else {
                // No real gap_list_base available here (this is a marker
                // skip, not a wire GAP) -- gap_start + 1 declares only
                // ecs_seq itself irrelevant.
                gate.on_gap(writer_guid, ecs_seq, ecs_seq + 1, std::iter::empty())
            }
        };
        if !released.is_empty() {
            self.emit_coherent_payloads(writer_guid, released);
        }
    }

    /// Stage a sample into the GROUP-scope aggregation buffer
    /// (DDS v1.4 sec. 2.2.3.6 + RTPS v2.5 sec. 8.7.5). Called from
    /// `on_data_coherent` when the reader's Presentation access_scope
    /// is GROUP and the sample carries `PID_GROUP_COHERENT_SET = gsn`.
    /// Bucketed by `(participant_prefix, publisher_entity_id, gsn)` so
    /// multi-writer GROUP sets commit atomically once every
    /// contributing writer has closed via ECS, and two Publishers in
    /// the same Participant do not alias on the same GSN
    /// (RTPS v2.5 sec. 9.3.2.1).
    #[allow(clippy::too_many_arguments)]
    fn stage_group_sample(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        prepared: super::admission::Prepared,
        version: crate::dds::CdrVersion,
        set_start: Option<u64>,
        gsn: u64,
        publisher_entity_id: [u8; 4],
        lifecycle: Option<([u8; 16], DisposeKind)>,
        charge: Option<super::staging_budget::StagedCharge>,
        order_token: Option<super::wire_order::OrderToken>,
    ) {
        let lifespan_owner = order_token.as_ref().map(|token| token.owner_id());
        let publisher_prefix: [u8; 12] = match writer_guid[..12].try_into() {
            Ok(p) => p,
            Err(_) => return,
        };
        let key = (publisher_prefix, publisher_entity_id, gsn);
        let rejected = |sub: &Self| {
            sub.rejected_sets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&StagedSet::Group(key))
        };
        // A change of a set rejected meanwhile (`reject_staged_set`), on
        // another thread: taken as its set's later changes are.
        if rejected(self) {
            drop(prepared);
            self.take_rejected_member(writer_guid, seq, StagedSet::Group(key), lifecycle.is_none());
            return;
        }
        // A sample of a set discarded already: stepped over, not staged.
        if self.group_set_discarded(&key) {
            self.discard_prepared_coherent(
                writer_guid,
                seq,
                &prepared,
                lifecycle.is_some(),
                order_token.as_ref(),
            );
            return;
        }

        let mut buf = match self.group_coherent_buffer.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        // Its writer said it left since: as for a classic set
        // (`stage_coherent_change`).
        if self.refuses_staging(&writer_guid) {
            drop(buf);
            self.discard_prepared_coherent(
                writer_guid,
                seq,
                &prepared,
                lifecycle.is_some(),
                order_token.as_ref(),
            );
            return;
        }
        // Rejected between the look above and this lock: the rejection
        // records it under this lock.
        if rejected(self) {
            drop(buf);
            drop(prepared);
            self.take_rejected_member(writer_guid, seq, StagedSet::Group(key), lifecycle.is_none());
            return;
        }

        // The pre-storage admission reserved this writer's part. A set
        // retired while storage was prepared cannot be reopened here,
        // after its receipt, or bypass the open-set bound.
        let set = match buf.get_mut(&key) {
            Some(set)
                if !self.group_set_discarded(&key) && set.per_writer.contains_key(&writer_guid) =>
            {
                set
            }
            _ => {
                drop(buf);
                self.discard_prepared_coherent(
                    writer_guid,
                    seq,
                    &prepared,
                    lifecycle.is_some(),
                    order_token.as_ref(),
                );
                return;
            }
        };
        // Classification belongs to this change even if its metadata was
        // refused or discovery changed during its announcement.
        let legacy =
            !crate::engine::router::route_group_is_spec(writer_guid, seq).unwrap_or_else(|| {
                self.topic_registry
                    .as_ref()
                    .map_or(set.writer_set.is_some(), |registry| {
                        registry.writer_speaks_spec_group(&writer_guid)
                    })
            });
        let entry = set.per_writer.entry(writer_guid).or_default();
        entry.push(BufferedCoherentSample {
            order: self.capture_wire_order(writer_guid, seq),
            order_token,
            remote_seq: seq,
            prepared,
            version,
            group_sn: Some(gsn),
            coherent_sn: set_start,
            from_vendor_0101: crate::engine::router::route_writer_is_connext(),
            lifecycle,
            charge,
            source_ts_ns: crate::engine::router::route_source_ts_ns(),
        });
        log::debug!(
            "[READER-SUB] GROUP coherent buffer topic='{}' writer={:02x?} seq={} gsn={} \
             pub_eid={:02x?} writer_buf={} group_buf={}",
            self.topic,
            &writer_guid[..4],
            seq,
            gsn,
            publisher_entity_id,
            entry.len(),
            set.total_samples(),
        );

        drop(buf);
        if let Some((barrier, owner)) = self.coherent_barrier.as_ref().zip(lifespan_owner) {
            barrier.activate_wire_lifespan(owner);
        }
        if legacy {
            self.discard_sets_of_the_other_dialect(key, writer_guid, false);
        }
        self.try_flush_group_sets();
    }

    /// A change of `writer_guid` in the GROUP set `key`, of the spec dialect
    /// (`spec`) or the 1.4.x one: the sets of its Publisher staged in the
    /// other dialect with a part of that writer are never closed in that
    /// dialect any more (its dialect was decided again, 4b520f49: the two
    /// name a set by different numbers). Discarded whole and reported lost,
    /// not parked in front of the writer's later sets.
    fn discard_sets_of_the_other_dialect(
        &self,
        key: GroupSetKey,
        writer_guid: [u8; 16],
        spec: bool,
    ) {
        let other = |k: &GroupSetKey, set: &GroupCoherentSet| {
            k.0 == key.0
                && k.1 == key.1
                && *k != key
                && set.writer_set.is_some() != spec
                && set.has_part_of(&writer_guid)
        };
        let any = self
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|(k, set)| other(k, set));
        if any {
            // A writer recorded as Dust (`SpecReceive`, decided once at its
            // discovery) names its writer set on the end of a set only, never
            // on a member: a set of it staged with no writer set is a set not
            // ended yet, not a set of another dialect. A reader that matches
            // while the writer is inside a set gets that set's live members
            // before the replay's first end; discarded here, the set was never
            // delivered and its peers' presentation waited for it for good.
            // Asked only once a set of no writer set is found, so the spec
            // path pays nothing.
            if spec
                && self
                    .topic_registry
                    .as_ref()
                    .is_some_and(|registry| registry.writer_is_spec_receive(&writer_guid))
            {
                return;
            }
            log::debug!(
                "[READER-SUB] GROUP writer {:02x?} topic='{}' changed dialect mid-set: its sets \
                 of the other dialect discarded",
                &writer_guid[12..],
                self.topic
            );
            self.discard_group_sets(other, None);
        }
    }

    /// Controls occupy a writer's open-set budget just as staged samples do.
    /// Refuse a new part at the bound; an existing part must still close.
    fn group_part_has_room(
        buf: &HashMap<GroupSetKey, GroupCoherentSet>,
        key: &GroupSetKey,
        writer: &[u8; 16],
        head: bool,
    ) -> bool {
        buf.get(key).is_some_and(|set| set.has_part_of(writer))
            || buf.values().filter(|set| set.has_part_of(writer)).count()
                < MAX_OPEN_GROUP_SETS_PER_WRITER + usize::from(head)
    }

    /// A reliable gate passed a sample announced but never staged: that
    /// part cannot become whole. Retire its whole set through the normal
    /// discard path, including reporting any other writer's staged parts.
    /// Received parts are retained: their staged changes hold the gate.
    fn retire_passed_group_announcers(&self, writer: [u8; 16]) {
        let (next, filtered, filter_floor) = {
            let gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
            if gate.is_best_effort() {
                return;
            }
            (
                gate.next_seq(&writer),
                gate.filtered_ranges(&writer),
                gate.filtered_history_floor(&writer),
            )
        };
        let Some(next) = next else {
            return;
        };
        let passed = |_: &GroupSetKey, set: &GroupCoherentSet| {
            set.announcers
                .get(&writer)
                .copied()
                .flatten()
                .is_some_and(|(first, last)| {
                    let end = last.min(next.saturating_sub(1));
                    // Filtered members are outside the relevant set
                    // (RTPS v2.5 Sec.8.7.6). A reported loss is not a
                    // filter: only the gate's filtered ranges exempt it.
                    first >= filter_floor
                        && first <= end
                        && super::reorder::covered_in(&filtered, first, end.saturating_add(1))
                            < end - first + 1
                })
                && set.per_writer.get(&writer).is_none_or(Vec::is_empty)
        };
        let any = self
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|(key, set)| passed(key, set));
        if any {
            self.discard_group_sets(passed, None);
        }
    }

    /// Record the writer set a writer of the spec GROUP dialect announced
    /// for the GROUP set `key`, and on its end the first SN of its part
    /// (`Subscriber::on_group_writer_set`).
    fn note_group_change(
        &self,
        key: GroupSetKey,
        writer_guid: [u8; 16],
        change: crate::engine::subscriber::GroupChange,
    ) {
        self.retire_passed_group_announcers(writer_guid);
        if self.group_set_discarded(&key) {
            return;
        }
        // A sample the gate passed is not staged. Its metadata must not
        // reserve an open set or the exception for the current head.
        let passed = change.part_first_sn.is_none()
            && self
                .reorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .next_seq(&writer_guid)
                .is_some_and(|next| change.seq < next);
        if passed {
            return;
        }
        {
            let mut seen = self
                .seen_seqs_by_writer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if seen.get_mut(&writer_guid).is_some_and(|record| {
                self.judge_seen(record, writer_guid, change.seq, self.missed()) == Seen::Duplicate
            }) {
                return;
            }
        }
        let head = change.part_first_sn.is_none()
            && self.staged_in_order(writer_guid, change.seq, StagedSet::Group(key), None)
                == Some(true);
        self.discard_sets_of_the_other_dialect(key, writer_guid, true);
        let writer_set = change.writer_set;
        // The writer's GSNs increase with its SNs (Sec.8.7.5: "strictly
        // monotonically increasing").
        let monotonic = change.gsn.is_none_or(|gsn| {
            let mut writers = self.writer_gsns.lock().unwrap_or_else(|e| e.into_inner());
            let gsns = writers.entry(writer_guid).or_default();
            let below = gsns.by_sn.range(..change.seq).next_back().map(|(_, g)| *g);
            let above = gsns.by_sn.range(change.seq + 1..).next().map(|(_, g)| *g);
            let known = gsns.by_sn.get(&change.seq).copied();
            gsns.by_sn.insert(change.seq, gsn);
            while gsns.by_sn.len() > MAX_WRITER_GSNS {
                gsns.by_sn.pop_first();
            }
            known.is_none_or(|g| g == gsn)
                && below.is_none_or(|g| g < gsn)
                && above.is_none_or(|g| g > gsn)
        });
        let mut buf = self
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Rejected since the look above (`reject_staged_set`, under this
        // lock): a change of it opens no set again.
        if self.set_rejected(StagedSet::Group(key)) {
            return;
        }
        if !Self::group_part_has_room(&buf, &key, &writer_guid, head) {
            return;
        }
        let set = buf.entry(key).or_default();
        let first = set.announcers.entry(writer_guid).or_default();
        if change.part_first_sn.is_none() {
            *first = Some(first.map_or((change.seq, change.seq), |(first, last)| {
                (first.min(change.seq), last.max(change.seq))
            }));
        }
        if !monotonic {
            set.gsn_broken = true;
        }
        if let Some(gsn) = change.gsn {
            if change.part_first_sn.is_some() {
                // An end of the set: its GSN is the set's end GSN, the same
                // for every writer, not below the set's first.
                if set.ecs_gsn.is_some_and(|e| e != gsn)
                    || gsn < key.2
                    || set.max_member_gsn.is_some_and(|member| member >= gsn)
                {
                    set.gsn_broken = true;
                }
                set.ecs_gsn = Some(gsn);
            } else {
                if gsn < key.2 || set.ecs_gsn.is_some_and(|e| gsn >= e) {
                    set.gsn_broken = true;
                }
                set.max_member_gsn = Some(set.max_member_gsn.map_or(gsn, |member| member.max(gsn)));
            }
            if set.gsn_broken {
                log::debug!(
                    "[READER-SUB] GROUP set gsn={} topic='{}': GSN {} of writer {:02x?} SN {} \
                     contradicts the set, never whole",
                    key.2,
                    self.topic,
                    gsn,
                    &writer_guid[12..],
                    change.seq
                );
            }
        }
        if let Some(first) = change.part_first_sn {
            set.part_first.insert(writer_guid, first);
        }
        match set.writer_set {
            None => set.writer_set = Some(writer_set),
            Some(known) if known != writer_set => {
                log::debug!(
                    "[READER-SUB] GROUP set gsn={} named two writer sets {:02x?} and {:02x?} \
                     topic='{}': never whole",
                    key.2,
                    known,
                    writer_set,
                    self.topic
                );
                set.writer_set_changed = true;
            }
            Some(_) => {}
        }
    }

    /// For each GROUP set of the spec dialect whose writers are not known
    /// yet, ask discovery for the Publisher's writers: when they are the
    /// set's writer set (same GroupDigest_t), the ones on this reader's
    /// topic that it does not refuse are the writers it must hear the end
    /// of the set from (RTPS v2.5 Sec.8.7.6: a set is whole once every
    /// writer of the Publisher matched here ended it, D6/W3). Returns the
    /// sets that can never be decided (two writer sets named by one set, D7,
    /// D11; GSNs that contradict the spec; an end GSN a required writer
    /// announced absent), and apart, the sets whose writers discovery has
    /// not known for longer than `group_roster_wait_ms`: those are
    /// undecidable only while their writers stay unknown, which another
    /// refresh may have learnt since (`try_flush_group_sets`).
    ///
    /// Called with no lock of this reader held: discovery is asked outside
    /// them.
    fn refresh_group_rosters(&self) -> (Vec<GroupSetKey>, Vec<GroupSetKey>) {
        let Some(source) = self.group_roster.get() else {
            return (Vec::new(), Vec::new());
        };
        let ready = source.ready();
        let generation = source.generation();
        let mut undecidable = Vec::new();
        let mut timed_out = Vec::new();
        let pending: Vec<(GroupSetKey, [u8; 4])> = {
            let buf = self
                .group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            buf.iter()
                .filter_map(|(key, set)| {
                    if set.writer_set_changed || set.gsn_broken {
                        undecidable.push(*key);
                        return None;
                    }
                    // A writer the set waits for announced (Sec.8.7.5) it
                    // does not have the set's end GSN: its end never comes,
                    // repairs included (evicted from its history before
                    // this reader joined): never whole.
                    if let (Some(end), Some(required)) = (set.ecs_gsn, set.required.as_ref()) {
                        let gsns = self.writer_gsns.lock().unwrap_or_else(|e| e.into_inner());
                        if required.iter().any(|w| {
                            !set.closers.contains(w)
                                && gsns
                                    .get(w)
                                    .and_then(|g| g.heartbeat)
                                    .is_some_and(|hb| gsn_announced_absent(end, hb))
                        }) {
                            undecidable.push(*key);
                            return None;
                        }
                    }
                    // Not decided yet, or decided against a roster that has
                    // changed since (a writer matched, unmatched, gone).
                    match (set.writer_set, &set.required) {
                        (Some(writer_set), None) => Some((*key, writer_set)),
                        (Some(writer_set), Some(_)) if set.required_generation != generation => {
                            Some((*key, writer_set))
                        }
                        _ => None,
                    }
                })
                .collect()
        };
        for (key, writer_set) in pending {
            let writers = self.roster_answer(source.as_ref(), &key.0, key.1);
            let ids: Vec<[u8; 4]> = writers.iter().map(|(id, _)| *id).collect();
            let digest = source.writer_set_digest(&key.0, &ids);
            // The writers of the Publisher the reader is matched with (on
            // its topic, and not refused by it, nor shut out by its
            // partition or the security plugins: their ends are refused,
            // and waited for, they parked every set of the Publisher).
            let matched: Vec<[u8; 16]> = writers
                .iter()
                .filter(|(_, on_topic)| *on_topic)
                .map(|(id, _)| {
                    let mut guid = [0u8; 16];
                    guid[..12].copy_from_slice(&key.0);
                    guid[12..].copy_from_slice(id);
                    guid
                })
                .filter(|guid| !self.writer_shut_out(guid))
                .collect();
            let mut buf = self
                .group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let Some(set) = buf.get_mut(&key) else {
                continue;
            };
            if let Some(required) = set.required.as_mut() {
                // Decided already. Decided at this generation or a newer
                // one (a refresh on another thread): the answer read here is
                // no newer. Decided at an older one: decided again, the
                // writers of the set's roster the reader is matched with
                // now: one it is no longer matched with is waited for no
                // more, one matched since (shut out at the first decision,
                // its verdict flipped) is waited for. The writer set was
                // named when the set began: a writer the Publisher gained
                // since (a digest that changed) is no writer of this set,
                // and never undoes the decision.
                if set.required_generation >= generation || !ready {
                    continue;
                }
                let roster = &set.roster;
                *required = matched
                    .iter()
                    .filter(|guid| roster.iter().any(|id| guid[12..] == id[..]))
                    .copied()
                    .collect();
                set.required_generation = generation;
                continue;
            }
            if ready && digest == writer_set {
                set.roster = writers.iter().map(|(id, _)| *id).collect();
                set.required = Some(matched);
                set.required_generation = generation;
                set.roster_wait_since = None;
                continue;
            }
            if self.wire_bindings.is_some() {
                // Missing discovery is not proof that retained DATA or
                // an end marker has become unavailable.
                continue;
            }
            let since = *set
                .roster_wait_since
                .get_or_insert_with(std::time::Instant::now);
            let wait = std::time::Duration::from_millis(
                self.group_roster_wait_ms
                    .load(std::sync::atomic::Ordering::Relaxed),
            );
            if since.elapsed() < wait {
                // Decided then whatever comes meanwhile: a silent
                // Publisher must not park the set for good.
                if let Some(room) = self.room.as_ref() {
                    room.retry_at(since + wait);
                }
            }
            if since.elapsed() >= wait {
                log::debug!(
                    "[READER-SUB] GROUP set gsn={} topic='{}': discovery's writers \
                     {:02x?} are not its writer set {:02x?} after {:?}, discarded",
                    key.2,
                    self.topic,
                    digest,
                    writer_set,
                    wait
                );
                timed_out.push(key);
            }
        }
        (undecidable, timed_out)
    }

    /// Whether a GROUP set of the spec dialect still open (staged, not
    /// committed) has a part of `writer_guid` that comes before its change
    /// `seq`: one whose end that writer has not sent yet, or sent before
    /// `seq`.
    fn group_set_open_below(&self, writer_guid: &[u8; 16], seq: u64) -> bool {
        let buf = self
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        buf.values().any(|set| {
            set.writer_set.is_some()
                && (set.per_writer.contains_key(writer_guid)
                    || set.closers.contains(writer_guid)
                    || set
                        .required
                        .as_ref()
                        .is_some_and(|required| required.contains(writer_guid)))
                && set
                    .part_first
                    .get(writer_guid)
                    .copied()
                    .or_else(|| {
                        set.per_writer
                            .get(writer_guid)
                            .and_then(|v| v.iter().map(|s| s.remote_seq).min())
                    })
                    .is_none_or(|first| first < seq)
        })
    }

    /// Whether every end GROUP set `set` needs was received: from every
    /// writer with a sample in it (`GroupCoherentSet::is_complete`) and,
    /// for a set of the spec dialect, from every writer this reader must
    /// hear it from (`refresh_group_rosters`), which an idle writer sends
    /// too (D6).
    fn group_set_closed(&self, set: &GroupCoherentSet) -> bool {
        if !set.is_complete() {
            return false;
        }
        if set.writer_set.is_none() || self.group_roster.get().is_none() {
            return !set.per_writer.is_empty();
        }
        set.required
            .as_ref()
            .is_some_and(|required| required.iter().all(|w| set.closers.contains(w)))
    }

    /// Flush, each as one unit, the GROUP sets (`group_coherent_buffer`)
    /// that are closed, complete and have room, as `try_commit_sets` does
    /// for a writer's sets.
    ///
    /// Closed: every writer with samples in it sent its end (`closers`,
    /// as before). Complete: for each such writer, every sequence number
    /// from its part's first, the `PID_COHERENT_SET` its samples carry, to
    /// the last its end names is staged; an end that overtook a sample of
    /// its set waits for it. Flushing on the end alone delivered the set in
    /// part, and the late sample, acknowledged, was staged under a set
    /// that never closed again. With room: a place for every sample, all
    /// or none, as a held sample would take it; a set that does not fit
    /// waits for a take, and one that never can is rejected whole,
    /// reported. A writer's part is not decided before its first
    /// HEARTBEAT: the gap below it is unknown.
    fn try_flush_group_sets(&self) {
        // Its listeners are told once its delivery locks are released.
        let _delivering = super::notices::Delivering::enter();
        let (undecidable, timed_out) = self.refresh_group_rosters();
        if !undecidable.is_empty() || !timed_out.is_empty() {
            // A set timed out waiting for its writers is discarded only if
            // they are still unknown: a refresh on another thread (the
            // discovery that brought them, or the timer) may have decided it
            // between the two locks.
            self.discard_group_sets(
                |key, set| {
                    undecidable.contains(key) || (timed_out.contains(key) && set.required.is_none())
                },
                None,
            );
        }
        let committing = self.commit_lock.lock().unwrap_or_else(|e| e.into_inner());
        // What is decided under the commit lock, delivered after it.
        type Slots = HashMap<[u8; 16], Vec<Option<super::admission::HistorySlot>>>;
        type Parts = HashMap<[u8; 16], Vec<BufferedCoherentSample>>;
        let mut flushes: Vec<(GroupSetKey, GroupCoherentSet, Slots)> = Vec::new();
        // Sets rejected while out of the staging here (`take_orphaned_members`).
        let mut orphans: Vec<([u8; 16], StagedSet, BufferedCoherentSample)> = Vec::new();
        // Sets rejected whole (`Some` bound) or that can never be whole
        // (`None`: a sample GAPped): the instance of each of their staged
        // samples, the bound, how many samples the set lost, their parts.
        type Instances = Vec<Option<InstanceHandle>>;
        let mut rejections: Vec<(Instances, Option<super::admission::Bound>, u64, Parts)> =
            Vec::new();
        type Part = ([u8; 16], u64, Vec<(u64, Option<u64>)>, Option<u64>);
        // For each closed set: each closing writer, its last, its staged
        // (seq, set start), the first SN of its part when its end named it.
        let candidates: Vec<(GroupSetKey, Vec<Part>, bool)> = {
            let buf = self
                .group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut c: Vec<(GroupSetKey, Vec<Part>, bool)> = buf
                .iter()
                .filter(|(_, set)| self.group_set_closed(set))
                .map(|(key, set)| {
                    let parts = set
                        .closers
                        .iter()
                        .map(|w| {
                            let last = set.writer_ceilings.get(w).copied().unwrap_or(u64::MAX);
                            let staged = set
                                .per_writer
                                .get(w)
                                .map(|v| v.iter().map(|s| (s.remote_seq, s.coherent_sn)).collect())
                                .unwrap_or_default();
                            (
                                *w,
                                last,
                                staged,
                                set.part_first
                                    .get(w)
                                    .copied()
                                    .into_iter()
                                    .chain(
                                        set.announcers
                                            .get(w)
                                            .copied()
                                            .flatten()
                                            .map(|(first, _)| first),
                                    )
                                    .min(),
                            )
                        })
                        .collect();
                    // A writer replaying without markers has the hole
                    // below its part stepped over by the flush itself
                    // (`flush_group_set`): its part waits for no gate.
                    let awaits_gates = !set
                        .per_writer
                        .values()
                        .flatten()
                        .any(|s| s.from_vendor_0101);
                    (*key, parts, awaits_gates)
                })
                .collect();
            c.sort_by_key(|(key, _, _)| key.2);
            c
        };
        if candidates.is_empty() {
            return;
        }
        // For each set whose parts are complete: per writer, its keep and
        // headroom (`None`: not decided yet, before the first HEARTBEAT).
        type Room = HashMap<[u8; 16], Option<(usize, usize)>>;
        let best_effort = self.ack_credit.is_none();
        let mut wake = None;
        let ready: Vec<(GroupSetKey, Room, bool)> = {
            let gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            candidates
                .into_iter()
                .filter_map(|(key, parts, awaits_gates)| {
                    let mut room: Room = HashMap::new();
                    let broken = parts.iter().any(|(writer, last, staged, part_first)| {
                        let first = staged
                            .iter()
                            .map(|&(seq, start)| start.unwrap_or(seq))
                            .chain(*part_first)
                            .min();
                        // A part one of whose samples will never come can
                        // never be whole, nor its set.
                        // An end that names no last closes what is staged.
                        let have: BTreeSet<u64> = staged.iter().map(|&(seq, _)| seq).collect();
                        let end = if *last == u64::MAX {
                            have.last().copied().unwrap_or(0)
                        } else {
                            *last
                        };
                        first.is_some_and(|first| gate.misses_for_good(writer, first, end, &have))
                    });
                    if broken {
                        return Some((key, room, true));
                    }
                    // A GROUP set spans its writers, whatever its dialect:
                    // it is delivered once every writer's part can be, in
                    // that writer's order, nothing of the writer before the
                    // part still awaited. Fed into a gate that would hold
                    // it (`ReorderGate::would_hold`), a part was held there,
                    // the others delivered: the set in part, the held part
                    // released later on its own, outside its set.
                    if awaits_gates
                        && parts.iter().any(|(writer, _, staged, part_first)| {
                            staged
                                .iter()
                                .map(|&(seq, start)| start.unwrap_or(seq))
                                .chain(*part_first)
                                .min()
                                .is_some_and(|first| gate.would_hold(writer, first))
                        })
                    {
                        self.group_sets_await_gate
                            .store(true, std::sync::atomic::Ordering::Release);
                        return None;
                    }
                    for (writer, last, staged, part_first) in parts {
                        if staged.is_empty() {
                            // A part with no sample: complete once the
                            // gate is past its end.
                            if gate.next_seq(&writer).is_none_or(|next| next <= last) {
                                return None;
                            }
                            // A DATA reservation can finish as an empty
                            // filtered part. It needs no history places.
                            room.insert(writer, Some((0, 0)));
                            continue;
                        }
                        let first = staged
                            .iter()
                            .map(|&(seq, start)| start.unwrap_or(seq))
                            .chain(part_first)
                            .min()?;
                        let seqs: BTreeSet<u64> = staged.iter().map(|&(seq, _)| seq).collect();
                        // An end that names no last (no marker, no count)
                        // closes what is staged.
                        if last != u64::MAX
                            && (last < first
                                || u64::try_from(seqs.range(first..=last).count()).ok().map(
                                    |held| {
                                        held.saturating_add(gate.filtered_in(&writer, first, last))
                                    },
                                ) != Some(last - first + 1))
                        {
                            // A best-effort writer repairs nothing: closed
                            // with a member the gate passed without it, the
                            // set is never whole (as `try_commit_sets`
                            // decides for a writer's set). A member not
                            // passed yet may still come (its end overtook
                            // it): the set waits, for a while
                            // (`BEST_EFFORT_OVERTAKE_WAIT`).
                            return (best_effort
                                && (!gate.is_best_effort()
                                    || gate.misses_for_good(&writer, first, last, &seqs)
                                    || (self.wire_bindings.is_none()
                                        && self.best_effort_wait_over(writer, first, &mut wake))))
                            .then(|| (key, HashMap::new(), true));
                        }
                        let keep = gate.places_to_keep(&writer, first).map(|below| {
                            let owed = if below == 0 && gate.has_gap(&writer) {
                                0
                            } else {
                                gate.places_owed_except(&writer)
                            };
                            (below.saturating_add(owed), below)
                        });
                        room.insert(writer, keep);
                    }
                    Some((key, room, false))
                })
                .collect()
        };
        self.wake_best_effort_wait(wake);
        for (key, room, broken) in ready {
            let Some(mut set) = self
                .group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key)
            else {
                continue;
            };
            for samples in set.per_writer.values_mut() {
                samples.sort_by_key(|s| s.remote_seq);
            }
            // Decided: its parts wait no more (`best_effort_wait_over`).
            self.end_best_effort_waits(set.per_writer.iter().filter_map(|(w, v)| {
                v.iter()
                    .map(|s| s.coherent_sn.unwrap_or(s.remote_seq))
                    .chain(set.part_first.get(w).copied())
                    .min()
                    .map(|first| (*w, first))
            }));
            let all: Vec<&BufferedCoherentSample> = set
                .per_writer
                .iter()
                .flat_map(|(w, v)| {
                    let last = set.writer_ceilings.get(w).copied().unwrap_or(u64::MAX);
                    v.iter().filter(move |s| s.remote_seq <= last)
                })
                .collect();
            // What a rejection reports of them: the instance of each sample.
            let reported = |all: &[&BufferedCoherentSample]| -> Vec<Option<InstanceHandle>> {
                all.iter()
                    .filter(|m| m.lifecycle.is_none())
                    .map(|m| Self::decode_staged(m).and_then(Self::instance_handle_for_rejection))
                    .collect()
            };
            if broken {
                // The samples it loses: its staged members, and those never
                // received of each part whose end is known.
                let count: u64 = set
                    .per_writer
                    .iter()
                    .map(|(w, v)| {
                        let staged = staged_samples(v);
                        let first = v
                            .iter()
                            .map(|s| s.coherent_sn.unwrap_or(s.remote_seq))
                            .min();
                        match (first, set.writer_ceilings.get(w)) {
                            (Some(first), Some(&last)) => {
                                staged.saturating_add(self.never_received(*w, first, last))
                            }
                            _ => staged,
                        }
                    })
                    .sum();
                for (w, v) in &set.per_writer {
                    if let (Some(&last), Some(first)) = (
                        set.writer_ceilings.get(w),
                        v.iter()
                            .map(|s| s.coherent_sn.unwrap_or(s.remote_seq))
                            .min(),
                    ) {
                        self.note_discarded(*w, first, last);
                    }
                }
                self.note_group_discarded(key);
                if set.writer_set.is_some() {
                    self.abandon_spec_generation(key);
                }
                let all = reported(&all);
                rejections.push((all, None, count, std::mem::take(&mut set.per_writer)));
                continue;
            }
            // A configured history bound is not an availability proof.
            // Protected units use the normal reservation/put-back path,
            // including its concurrent rejection and orphan checks.
            if let Some(bound) = self
                .never_holds(&all)
                .filter(|_| self.ack_credit.is_none() || self.wire_bindings.is_none())
            {
                log::debug!(
                    "[READER-SUB] GROUP set of {} samples rejected whole topic='{}' gsn={} ({:?})",
                    all.len(),
                    self.topic,
                    key.2,
                    bound
                );
                let count = u64::try_from(all.len()).unwrap_or(u64::MAX);
                if set.writer_set.is_some() {
                    self.abandon_spec_generation(key);
                }
                let all = reported(&all);
                rejections.push((all, Some(bound), count, std::mem::take(&mut set.per_writer)));
                continue;
            }
            let mut slots: HashMap<[u8; 16], Vec<Option<super::admission::HistorySlot>>> =
                HashMap::new();
            let mut fits = true;
            let mut refused = None;
            for (writer, samples) in &set.per_writer {
                let last = set.writer_ceilings.get(writer).copied().unwrap_or(u64::MAX);
                let members: Vec<&BufferedCoherentSample> =
                    samples.iter().filter(|s| s.remote_seq <= last).collect();
                let Some(Some((keep, headroom))) = room.get(writer).copied() else {
                    fits = false;
                    break;
                };
                match self.places_or_wait(*writer, &members, keep, headroom) {
                    Ok(taken) => {
                        slots.insert(*writer, taken);
                    }
                    Err(bound) => {
                        refused = bound;
                        fits = false;
                        break;
                    }
                }
            }
            if let Some(bound) =
                refused.filter(|_| self.ack_credit.is_none() || self.wire_bindings.is_none())
            {
                // A best-effort reader: rejected whole (`places_or_wait`).
                for (_, taken) in slots {
                    Self::give_back_quietly(taken);
                }
                let count = u64::try_from(all.len()).unwrap_or(u64::MAX);
                if set.writer_set.is_some() {
                    self.abandon_spec_generation(key);
                }
                let all = reported(&all);
                rejections.push((all, Some(bound), count, std::mem::take(&mut set.per_writer)));
                continue;
            }
            if !fits {
                // The places taken go back; the set waits.
                for (_, taken) in slots {
                    Self::give_back_quietly(taken);
                }
                let mut buf = self
                    .group_coherent_buffer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                // Rejected while it was out of the staging here (recorded
                // under this lock): not put back (`try_commit_sets`).
                if self.set_rejected(StagedSet::Group(key)) {
                    drop(buf);
                    orphans.extend(set.per_writer.into_iter().flat_map(|(w, v)| {
                        v.into_iter().map(move |m| (w, StagedSet::Group(key), m))
                    }));
                    continue;
                }
                buf.insert(key, set);
                continue;
            }
            flushes.push((key, set, slots));
        }
        if flushes.is_empty() && rejections.is_empty() {
            drop(committing);
            self.take_orphaned_members(orphans);
            return;
        }
        // The delivery locks of every writer involved, in one order, before
        // the commit lock is let go (see `try_commit_sets`).
        let mut writers: Vec<[u8; 16]> = flushes
            .iter()
            .flat_map(|(_, set, _)| set.per_writer.keys().copied())
            .chain(
                rejections
                    .iter()
                    .flat_map(|(_, _, _, parts)| parts.keys().copied()),
            )
            .collect();
        writers.sort_unstable();
        writers.dedup();
        let locks: Vec<([u8; 16], Arc<Mutex<()>>)> = writers
            .iter()
            .map(|w| (*w, self.writer_delivery_lock(*w)))
            .collect();
        let delivering: HashMap<[u8; 16], std::sync::MutexGuard<'_, ()>> = locks
            .iter()
            .map(|(w, lock)| {
                (
                    *w,
                    match lock.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    },
                )
            })
            .collect();
        drop(committing);
        for (instances, bound, count, parts) in rejections {
            match bound {
                Some(bound) => {
                    for instance in instances {
                        self.report_refusal(Refusal::from(bound), instance);
                    }
                }
                None => self.report_sample_lost(count),
            }
            for (writer, samples) in parts {
                let Some(guard) = delivering.get(&writer) else {
                    continue;
                };
                let released = {
                    let mut gate = match self.reorder.lock() {
                        Ok(lock) => lock,
                        Err(e) => e.into_inner(),
                    };
                    let mut released = gate.take_ready(&writer, guard);
                    for s in &samples {
                        released.extend(gate.on_staged(
                            writer,
                            s.remote_seq,
                            PendingPayload::nothing(s.remote_seq),
                        ));
                    }
                    released
                };
                if let Some(panic) = self.deliver_in_order(writer, released, guard) {
                    std::panic::resume_unwind(panic);
                }
            }
        }
        // The newest sample each flush releases of each writer: a
        // best-effort reader discards what is still staged behind it.
        let released: Vec<([u8; 16], u64)> = flushes
            .iter()
            .flat_map(|(_, set, _)| {
                set.per_writer
                    .iter()
                    .filter_map(|(w, v)| v.iter().map(|s| s.remote_seq).max().map(|m| (*w, m)))
            })
            .collect();
        for (key, set, slots) in flushes {
            // A set decided is final, in either dialect: what lands of it
            // afterwards (a repair sent twice, a writer's end again, the
            // part of a writer the flush went without) is stepped over as
            // for a set discarded, reported lost if it was never delivered,
            // opening no set that would never close, nor delivering the set
            // in a second part (DDS v1.4 Sec.2.2.3.6).
            self.note_group_discarded(key);
            self.flush_group_set(key.0, key.1, key.2, set, slots, Some(&delivering));
        }
        drop(delivering);
        self.take_orphaned_members(orphans);
        for (writer, seq) in released {
            self.discard_group_sets_behind(writer, seq);
        }
        // A set delivered moved its writers' gates: a later set that waited
        // for them is decided now.
        if self
            .group_sets_await_gate
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.try_flush_group_sets();
        }
    }

    /// Mark `writer_guid` as having closed the group set identified by
    /// `(participant_prefix, publisher_entity_id, gsn)` and flush
    /// atomically once every writer with buffered samples has been
    /// observed in `closers`. `coherent_sn` is the writer's own
    /// last-sample SN per the ECS marker; samples whose `remote_seq`
    /// is past this value are dropped at flush time because the ECS
    /// announced the set ended at `coherent_sn` and including them
    /// would breach the writer-scoped ECS boundary
    /// (RTPS v2.5 sec. 8.7.5).
    ///
    /// `ecs_seq` is the closing marker's own writer SN when known
    /// (`None` when the caller could not derive it); when present the
    /// flush steps the per-writer reorder gate over it. `expected` is
    /// the set's per-writer sample count from an explicit end
    /// marker (0x8024): when present, this writer only counts as
    /// complete once that many samples are staged (see
    /// `GroupCoherentSet::is_complete`); the straggler that completes
    /// the set then fires the flush from `stage_group_sample`. The
    /// HDDS-native ECS path passes `Some(ecs_seq)` / `None` and is
    /// behaviourally unchanged.
    fn close_group_set(
        &self,
        writer_guid: [u8; 16],
        ecs_seq: Option<u64>,
        coherent_sn: u64,
        expected: Option<u32>,
        gsn: u64,
        publisher_entity_id: [u8; 4],
    ) {
        let _delivering = super::notices::Delivering::enter();
        let control_receipt = if let Some(seq) = ecs_seq {
            let Some(receipt) = self.prepare_control_receipt(writer_guid, seq) else {
                return;
            };
            Some((seq, receipt))
        } else {
            None
        };
        let best_effort = ecs_seq.and_then(|seq| self.accept_best_effort_control(writer_guid, seq));
        if matches!(best_effort, Some(Seen::Duplicate | Seen::Full)) {
            return;
        }
        let publisher_prefix: [u8; 12] = match writer_guid[..12].try_into() {
            Ok(p) => p,
            Err(_) => return,
        };
        // An end of set comes after the set's last change: one naming its
        // own SN or a later one as that last change names a change that
        // does not exist, and the set waited for it forever, every later
        // change of the writer behind it. An HDDS writer gave the SN of an
        // abandoned change back and its end of set took it, still named as
        // the set's last (fixed in the writer since): the set's last
        // change is the one before the end.
        let coherent_sn = match ecs_seq {
            Some(marker_seq) if coherent_sn >= marker_seq => {
                log::debug!(
                    "[READER-SUB] GROUP ECS topic='{}' writer={:02x?} at seq={} names last seq={}: read as {}",
                    self.topic,
                    &writer_guid[..4],
                    marker_seq,
                    coherent_sn,
                    marker_seq.saturating_sub(1)
                );
                marker_seq.saturating_sub(1)
            }
            _ => coherent_sn,
        };
        let key = (publisher_prefix, publisher_entity_id, gsn);
        {
            let mut buf = self
                .group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let discarded =
                self.group_set_discarded(&key) || self.set_rejected(StagedSet::Group(key));
            if let Some(marker_seq) = ecs_seq.filter(|_| best_effort.is_none()) {
                let mut seen = self
                    .seen_seqs_by_writer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let record = seen.entry(writer_guid).or_default();
                match self.judge_seen(record, writer_guid, marker_seq, self.missed()) {
                    Seen::Duplicate => {
                        drop(seen);
                        drop(buf);
                        if let Some((_, receipt)) = control_receipt.as_ref() {
                            self.credit_control_receipt(writer_guid, marker_seq, receipt);
                        }
                        return;
                    }
                    Seen::Full => return,
                    Seen::New => {}
                }
                // Do not record or acknowledge a marker whose metadata has
                // no room: its reliable repair must be able to close later.
                if !discarded && !Self::group_part_has_room(&buf, &key, &writer_guid, false) {
                    return;
                }
                record.record(marker_seq, self.missed());
            } else if !discarded && !Self::group_part_has_room(&buf, &key, &writer_guid, false) {
                return;
            }
            if discarded {
                drop(buf);
                if let Some((marker_seq, receipt)) = control_receipt.as_ref() {
                    if !self.credit_control_receipt(writer_guid, *marker_seq, receipt) {
                        return;
                    }
                    self.skip_ecs_seq_in_gate(writer_guid, *marker_seq);
                }
                return;
            }

            let set = buf.entry(key).or_default();
            let inserted = set.closers.insert(writer_guid);
            // Record this writer's per-set ceiling so flush_group_set
            // can drop samples past coherent_sn (publisher-protocol
            // violations that must NOT be delivered with the set).
            set.writer_ceilings.insert(writer_guid, coherent_sn);
            if let Some(expected) = expected {
                set.writer_expected.insert(writer_guid, expected);
            }
            log::debug!(
                "[READER-SUB] GROUP ECS topic='{}' writer={:02x?} gsn={} coherent_sn={} \
                 pub_eid={:02x?} first_close={} contributors={} closers={}",
                self.topic,
                &writer_guid[..4],
                gsn,
                coherent_sn,
                publisher_entity_id,
                inserted,
                set.per_writer.len(),
                set.closers.len(),
            );
        }
        // The marker is a change of no set: it takes its turn in the gate
        // now. Stepped over only at the set's flush, it was never stepped
        // over for a set that waited for a late sample.
        if let Some((marker_seq, receipt)) = control_receipt.as_ref() {
            if !self.credit_control_receipt(writer_guid, *marker_seq, receipt) {
                return;
            }
            self.skip_ecs_seq_in_gate(writer_guid, *marker_seq);
        }
        self.try_flush_group_sets();
    }

    /// Drain a completed GROUP set through the regular admit pipeline.
    /// Samples are released in `(writer_guid, remote_seq)` order so the
    /// application sees a deterministic interleaving even when UDP
    /// reordered the arrivals; per-writer monotonic seq order is
    /// preserved because the reorder gate is invoked per-writer.
    /// Samples whose `remote_seq` is past the per-writer `coherent_sn`
    /// ceiling are dropped with a warn -- they are publisher-protocol
    /// violations and must NOT be included in the atomic batch
    /// (RTPS v2.5 sec. 8.7.5).
    fn flush_group_set(
        &self,
        publisher_prefix: [u8; 12],
        publisher_entity_id: [u8; 4],
        gsn: u64,
        mut set: GroupCoherentSet,
        mut slots: HashMap<[u8; 16], Vec<Option<super::admission::HistorySlot>>>,
        delivering: Option<&HashMap<[u8; 16], std::sync::MutexGuard<'_, ()>>>,
    ) {
        // Stable ordering: sort writer entries by writer_guid so a
        // re-run of the same scenario produces the same interleaving.
        // Within each writer, samples are released in remote_seq order
        // (the reorder gate enforces this; we also sort the buffer to
        // bypass any quirk in the gate's stride-detection heuristics).
        let spec = set.writer_set.is_some();
        let ceilings = std::mem::take(&mut set.writer_ceilings);
        let mut writers: Vec<_> = set.per_writer.drain().collect();
        writers.sort_by_key(|(guid, _)| *guid);

        let total: usize = writers.iter().map(|(_, v)| v.len()).sum();
        log::debug!(
            "[READER-SUB] GROUP set flush topic='{}' publisher={:02x?} pub_eid={:02x?} gsn={} \
             writers={} samples={}",
            self.topic,
            &publisher_prefix[..4],
            publisher_entity_id,
            gsn,
            writers.len(),
            total,
        );

        // Collect every writer's committed samples so the whole cross-writer
        // group is emitted as ONE atomic unit (deposited into the barrier
        // for publisher-aligned release, or delivered straight to the ring
        // when no barrier is wired). Draining writer-by-writer to the ring
        // would let a concurrent read cycle catch only some writers of the
        // group (DDS v1.4 sec. 2.2.3.6 GROUP scope is all-or-nothing).
        // Gate-rescued strays of neighbouring sets (see
        // partition_gate_strays) are collected apart so one emitted group
        // unit never spans two publisher generations.
        let mut group_writers: Vec<([u8; 16], Vec<PendingPayload>)> = Vec::new();
        let mut stray_below_writers: Vec<([u8; 16], Vec<PendingPayload>)> = Vec::new();
        let mut stray_above_writers: Vec<([u8; 16], Vec<PendingPayload>)> = Vec::new();
        for (writer_guid, mut samples) in writers {
            // Apply the writer's ECS ceiling: drop samples beyond it.
            // If the writer had no ECS (set flushed via writer-lost
            // path) treat `u64::MAX` as the ceiling so all buffered
            // samples are released -- the writer-lost code already
            // logged the drop intent.
            let ceiling = ceilings.get(&writer_guid).copied().unwrap_or(u64::MAX);
            samples.retain(|s| {
                if s.remote_seq > ceiling {
                    log::warn!(
                        "[READER-SUB] GROUP coherent sample past close -- dropped topic='{}' \
                         writer={:02x?} gsn={} sample_seq={} ecs_coherent_sn={}",
                        self.topic,
                        &writer_guid[..4],
                        gsn,
                        s.remote_seq,
                        ceiling,
                    );
                    false
                } else {
                    true
                }
            });
            samples.sort_by_key(|s| s.remote_seq);
            let first_sn = samples.first().map_or(0, |s| s.remote_seq);
            let mut writer_payloads: Vec<PendingPayload> = Vec::with_capacity(samples.len());
            // One gate critical section for the writer's whole part: what
            // the gate released for this writer before, queued behind the
            // delivery lock this flush holds, then the set's samples. The
            // receive thread hands the gate's releases over to this flush
            // while it holds the delivery lock (`Release::from_gate`):
            // taken before the samples in one lock and fed in another, a
            // change released in between was left queued, and delivered
            // after the set's later samples by the next drain.
            let mut gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            if let Some(guard) = delivering.and_then(|d| d.get(&writer_guid)) {
                writer_payloads.extend(gate.take_ready(&writer_guid, guard));
            }
            // The places taken for the set (`try_flush_group_sets`), one
            // per sample in sequence order; none for a flush that did not
            // take them.
            let mut writer_slots = slots.remove(&writer_guid).unwrap_or_default().into_iter();
            // A remote TRANSIENT_LOCAL writer replays its historical
            // samples but may neither re-emit the SNs its coherent END
            // markers consumed nor GAP them, so the pre-join sets can never close and the gate --
            // seeded at the durable HEARTBEAT firstSN -- would wait
            // forever for SNs that only exist inside those never-closing
            // sets, starving every completed set behind it. Cross-set
            // ordering under GROUP scope is owned by the barrier's GSN
            // alignment, not this gate: declare the hole below this
            // set's floor irrelevant, exactly as a writer-sent GAP
            // would. In every flow where sets close in order the gate
            // already sits on the set floor and this is a no-op.
            //
            // Only for that vendor: for any other writer the hole holds
            // sequences still to come (samples being repaired, a set not
            // complete yet), and declared irrelevant they were dropped as
            // delivered when they came: lost, acknowledged.
            let replays_without_markers = samples.first().is_some_and(|s| s.from_vendor_0101);
            if first_sn > 0 && replays_without_markers {
                if let Some(next) = gate.next_seq(&writer_guid) {
                    if next < first_sn {
                        log::debug!(
                            "[READER-SUB] GROUP flush stepping gate over seam hole \
                             topic='{}' writer={:02x?} gate_next={} set_floor={}",
                            self.topic,
                            &writer_guid[..4],
                            next,
                            first_sn,
                        );
                        // The never-closing replayed sets below the floor
                        // hold places (`hold_staged`) the step would not
                        // cross: given back, so that it does. The HDDS rule
                        // (a staged change waits in its turn) holds for
                        // every other writer.
                        let given = gate.give_up_staged_places_below(&writer_guid, first_sn);
                        if given > 0 {
                            log::debug!(
                                "[READER-SUB] GROUP seam step gives up {} staged places \
                                 topic='{}' writer={:02x?} set_floor={}",
                                given,
                                self.topic,
                                &writer_guid[..4],
                                first_sn,
                            );
                        }
                        // [next, first_sn) is a genuine contiguous range (not
                        // a bitmap-listed set), so pass it as gap_list_base
                        // rather than expanding it into gap_list_seqs -- the
                        // gate crosses it with a single jump instead of
                        // materializing every sequence in between.
                        writer_payloads.extend(gate.on_gap(
                            writer_guid,
                            next,
                            first_sn,
                            std::iter::empty(),
                        ));
                    }
                }
            }
            for sample in samples {
                let released = {
                    // Coherent re-stage: source INFO_TS for the original
                    // datagram is not retained across staging; reception-time
                    // lifespan (`BufferedCoherentSample::into_payload`).
                    let seq = sample.remote_seq;
                    let payload = sample.into_payload(writer_slots.next().flatten());
                    // Staged, it may have been passed by the gate meanwhile
                    // (a HEARTBEAT's firstSN): released all the same, never
                    // dropped as stale (`ReorderGate::on_staged`).
                    gate.on_staged(writer_guid, seq, payload)
                };
                writer_payloads.extend(released);
            }
            drop(gate);
            let (below, in_set, above) =
                Self::partition_gate_strays(writer_payloads, first_sn, ceiling);
            if !below.is_empty() || !above.is_empty() {
                log::debug!(
                    "[READER-SUB] GROUP flush rescued strays topic='{}' writer={:02x?} \
                     gsn={} set=[{}..={}] below={} above={}",
                    self.topic,
                    &writer_guid[..4],
                    gsn,
                    first_sn,
                    ceiling,
                    below.len(),
                    above.len(),
                );
            }
            if !below.is_empty() {
                stray_below_writers.push((writer_guid, below));
            }
            if !in_set.is_empty() {
                group_writers.push((writer_guid, in_set));
            }
            if !above.is_empty() {
                stray_above_writers.push((writer_guid, above));
            }
        }
        // Strays are one-set units of UNKNOWN generation (their identity
        // was lost in the gate): emitted around the set in SN order as
        // alignment wildcards (see the coherent_barrier module docs).
        let publisher =
            super::coherent_barrier::publisher_key(publisher_prefix, publisher_entity_id);
        self.emit_coherent_group(publisher, stray_below_writers, None, false);
        self.emit_coherent_group(publisher, group_writers, Some(gsn), spec);
        self.emit_coherent_group(publisher, stray_above_writers, None, false);
    }

    /// Discovery's writers of Publisher `publisher` of `prefix`
    /// (`GroupRoster::writers_of`), and those of them it forgot whose
    /// departure has not reached this reader yet (`roster_seen`): the
    /// readers hear of a departure behind the data queued before it, and
    /// the end of a set queued there is decided against the writers its
    /// Publisher had. Decided against discovery's answer alone, a set
    /// whose end was queued when discovery forgot the Publisher waited for
    /// writers discovery no longer knew, and the departure discarded it.
    fn roster_answer(
        &self,
        source: &dyn GroupRoster,
        prefix: &[u8; 12],
        publisher: [u8; 4],
    ) -> Vec<([u8; 4], bool)> {
        let mut writers = source.writers_of(prefix, publisher, &self.topic);
        let mut seen = self.roster_seen.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(known) = seen.get(&(*prefix, publisher)) {
            for &(id, on_topic) in known {
                if !writers.iter().any(|(w, _)| *w == id) {
                    writers.push((id, on_topic));
                }
            }
        }
        if writers.iter().any(|(_, on_topic)| *on_topic) {
            seen.insert((*prefix, publisher), writers.clone());
        }
        writers
    }

    /// Evict a writer from every GROUP set it participates in. Called
    /// from the writer-dispose / writer-lost path so a publisher
    /// dropping mid-set doesn't pin the buffer forever. The sweep
    /// covers every `publisher_entity_id` for this writer's
    /// participant prefix; a single writer belongs to exactly one
    /// Publisher in DDS but the receiver may have observed a sample
    /// for that writer with `PID_GROUP_ENTITY_ID` missing
    /// (cross-vendor edge case) and bucketed it under the `[0; 4]`
    /// sentinel, so we drop the writer from all such variants.
    fn forget_writer_in_group_sets(&self, writer_guid: [u8; 16]) {
        let publisher_prefix: [u8; 12] = match writer_guid[..12].try_into() {
            Ok(p) => p,
            Err(_) => return,
        };
        // A GROUP set the departed writer took part in (a sample staged,
        // or its end) can never be whole: discarded whole, reported lost,
        // the other writers' staged samples stepped over by their gates.
        // Flushing the others' parts without it delivered a partial
        // GROUP set, and flushed them without the completeness and the
        // places every other flush asks (DDS v1.4 Sec.2.2.3.6, RTPS v2.5
        // Sec.8.7.6: "Writers are not allowed to be added or removed from
        // a Publisher from the time that a coherent set begins until
        // after it ends").
        // Its departure reached the reader: no longer one of its Publisher's
        // writers here (`roster_answer`). A Publisher none of whose writers
        // of this topic is left is forgotten.
        {
            let mut seen = self.roster_seen.lock().unwrap_or_else(|e| e.into_inner());
            seen.retain(|(prefix, _), writers| {
                if *prefix == publisher_prefix {
                    writers.retain(|(id, _)| writer_guid[12..] != id[..]);
                }
                writers.iter().any(|(_, on_topic)| *on_topic)
            });
        }
        self.discard_group_sets(
            |(prefix, _, _), set| {
                *prefix == publisher_prefix
                    && (set.has_part_of(&writer_guid)
                        || set
                            .required
                            .as_ref()
                            .is_some_and(|required| required.contains(&writer_guid)))
            },
            Some(writer_guid),
        );
    }

    /// A best-effort reader released `writer_guid`'s change `seq` to the
    /// application: a GROUP set still staged with an older sample of that
    /// writer can no longer reach it in the writer's order, and a
    /// best-effort writer repairs nothing that would let it be whole in
    /// time. It is discarded, reported lost. Flushed later, it delivered
    /// the older sample after the newer one.
    fn discard_group_sets_behind(&self, writer_guid: [u8; 16], seq: u64) {
        if self.ack_credit.is_some() || !self.coherent_cfg.is_group_scope {
            return;
        }
        let publisher_prefix: [u8; 12] = match writer_guid[..12].try_into() {
            Ok(p) => p,
            Err(_) => return,
        };
        self.discard_group_sets(
            |(prefix, _, _), set| {
                *prefix == publisher_prefix
                    && set
                        .per_writer
                        .get(&writer_guid)
                        .is_some_and(|v| v.iter().any(|s| s.remote_seq < seq))
            },
            None,
        );
    }

    /// Discard whole, report lost, the staged GROUP sets `which` selects:
    /// each is recorded as discarded (`note_group_discarded`), and its
    /// writers' staged samples are stepped over by their gates, but for
    /// `departed`'s, a writer that left.
    fn discard_group_sets(
        &self,
        which: impl Fn(&GroupSetKey, &GroupCoherentSet) -> bool,
        departed: Option<[u8; 16]>,
    ) {
        // Its listeners are told once its delivery locks are released.
        let _delivering = super::notices::Delivering::enter();
        let committing = self.commit_lock.lock().unwrap_or_else(|e| e.into_inner());
        let broken: Vec<GroupCoherentSet> = {
            let mut buf = match self.group_coherent_buffer.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let keys: Vec<GroupSetKey> = buf
                .iter()
                .filter(|(key, set)| which(key, set))
                .map(|(key, _)| *key)
                .collect();
            for key in &keys {
                self.note_group_discarded(*key);
                if buf.get(key).is_some_and(|set| set.writer_set.is_some()) {
                    self.abandon_spec_generation(*key);
                }
            }
            keys.iter().filter_map(|key| buf.remove(key)).collect()
        };
        if broken.is_empty() {
            return;
        }
        let mut received_lost = 0u64;
        for set in &broken {
            for (w, v) in &set.per_writer {
                for sample in v {
                    received_lost =
                        received_lost.saturating_add(self.received_staged_lost(*w, sample));
                }
                self.note_reported(*w, v.iter().map(|sample| sample.remote_seq));
            }
        }
        // The samples they lose: their staged members, and those never
        // received of each part whose end is known (a departed writer's
        // too: its samples are lost all the same).
        let lost: u64 = broken
            .iter()
            .map(|set| {
                let unreceived: u64 = set
                    .per_writer
                    .iter()
                    .filter_map(|(w, v)| {
                        let first = v
                            .iter()
                            .map(|s| s.coherent_sn.unwrap_or(s.remote_seq))
                            .min()?;
                        let last = *set.writer_ceilings.get(w)?;
                        Some(self.never_received(*w, first, last))
                    })
                    .sum();
                unreceived
            })
            .sum::<u64>()
            .saturating_add(received_lost);
        // The other writers' staged samples, by writer.
        let mut parts: HashMap<[u8; 16], Vec<u64>> = HashMap::new();
        for set in broken {
            for (writer, samples) in set.per_writer {
                if Some(writer) != departed {
                    if let (Some(&last), Some(first)) = (
                        set.writer_ceilings.get(&writer),
                        samples
                            .iter()
                            .map(|s| s.coherent_sn.unwrap_or(s.remote_seq))
                            .min(),
                    ) {
                        self.note_discarded(writer, first, last);
                    }
                    parts
                        .entry(writer)
                        .or_default()
                        .extend(samples.iter().map(|s| s.remote_seq));
                }
            }
        }
        let mut writers: Vec<[u8; 16]> = parts.keys().copied().collect();
        writers.sort_unstable();
        let locks: Vec<([u8; 16], Arc<Mutex<()>>)> = writers
            .iter()
            .map(|w| (*w, self.writer_delivery_lock(*w)))
            .collect();
        let delivering: Vec<([u8; 16], std::sync::MutexGuard<'_, ()>)> = locks
            .iter()
            .map(|(w, lock)| {
                (
                    *w,
                    match lock.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    },
                )
            })
            .collect();
        drop(committing);
        log::debug!(
            "[READER-SUB] GROUP sets discarded topic='{}' departed={} lost_samples={}",
            self.topic,
            departed.is_some(),
            lost
        );
        self.report_sample_lost(lost);
        for (writer, guard) in &delivering {
            let mut seqs = parts.remove(writer).unwrap_or_default();
            seqs.sort_unstable();
            let released = {
                let mut gate = match self.reorder.lock() {
                    Ok(lock) => lock,
                    Err(e) => e.into_inner(),
                };
                let mut released = gate.take_ready(writer, guard);
                for seq in seqs {
                    released.extend(gate.on_staged(*writer, seq, PendingPayload::nothing(seq)));
                }
                released
            };
            if let Some(panic) = self.deliver_in_order(*writer, released, guard) {
                std::panic::resume_unwind(panic);
            }
        }
    }

    /// What this reader is owed of the sequences leaving its duplicate
    /// windows unadmitted: everything, when it is reliable.
    fn missed(&self) -> Missed {
        Missed::owed(self.ack_credit.is_some())
    }

    /// Up to which sequence of `writer_guid` this reliable reader awaits
    /// nothing, as its writer proxy records it; `None` without one.
    fn settled(&self, writer_guid: [u8; 16]) -> Option<u64> {
        self.ack_credit
            .as_ref()
            .and_then(|credit| credit.settled(&writer_guid))
    }

    fn duplicate_settled(&self, writer: [u8; 16], seq: u64) -> Option<u64> {
        if self.wire_bindings.is_none() {
            return self.settled(writer);
        }
        self.wire_loss_ledger(writer, None).map(|ledger| {
            ledger
                .authority
                .accounted_prefix()
                .min(seq.saturating_sub(1))
        })
    }

    #[inline(always)]
    fn judge_seen(&self, seen: &mut SeenSeqs, writer: [u8; 16], seq: u64, missed: Missed) -> Seen {
        let verdict = seen.judge(seq, missed, || self.duplicate_settled(writer, seq));
        if verdict != Seen::Full || self.wire_bindings.is_none() {
            return verdict;
        }
        if let Some(ledger) = self.wire_loss_ledger(writer, None) {
            let mut keep = BTreeMap::new();
            for (&lo, &hi) in &seen.missed {
                for (start, end) in ledger.authority.unaccounted(lo, hi.saturating_add(1)) {
                    keep.insert(start, end - 1);
                }
                if lo <= seq
                    && seq <= hi
                    && keep
                        .range(..=seq)
                        .next_back()
                        .is_none_or(|(_, end)| *end < seq)
                {
                    keep.insert(seq, seq);
                }
            }
            let mut merged: BTreeMap<u64, u64> = BTreeMap::new();
            for (lo, hi) in keep {
                match merged.last_entry() {
                    Some(mut last) if last.get().saturating_add(1) >= lo => {
                        let end = (*last.get()).max(hi);
                        *last.get_mut() = end;
                    }
                    _ => {
                        merged.insert(lo, hi);
                    }
                }
            }
            seen.missed = merged;
        }
        seen.judge(seq, missed, || self.duplicate_settled(writer, seq))
    }

    #[inline(always)]
    fn admit_seen(&self, seen: &mut SeenSeqs, writer: [u8; 16], seq: u64, missed: Missed) -> Seen {
        let verdict = self.judge_seen(seen, writer, seq, missed);
        if verdict == Seen::New {
            seen.record(seq, missed);
        }
        verdict
    }

    /// Credit this reader's WriterProxy with a DATA it received from
    /// `writer_guid` (RTPS v2.5 Sec.8.4.12): the ACKNACK the control thread
    /// builds for this reader reflects it. No-op for a BEST_EFFORT reader.
    /// A duplicate is credited too: it was received, and after a re-match
    /// the retransmission a fresh proxy asks for IS a duplicate here.
    fn credit_receipt(&self, writer_guid: [u8; 16], seq: u64) {
        if let Some(ref credit) = self.ack_credit {
            // A sequence number is a signed 64-bit value on the wire (RTPS
            // 2.5 8.3.5.4); one past i64::MAX was not written by any writer.
            if let Ok(seq) = i64::try_from(seq) {
                credit.on_data(writer_guid, seq);
            }
        }
    }

    /// Classify an authenticated control before admitting its metadata.
    /// Its WriterSN cannot become a lost application sample, even if the
    /// control still needs repair. This does not grant receipt credit.
    fn prepare_control_receipt(&self, writer: [u8; 16], seq: u64) -> Option<ControlReceipt> {
        if self.ack_credit.is_some()
            && self.coherent_cfg.coherent_access
            && self
                .coherent_admissions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&(writer, seq))
        {
            return None;
        }
        if self.wire_bindings.is_none() {
            return Some(ControlReceipt::Plain);
        }
        let ledger = self.wire_loss_ledger(writer, None)?;
        if !self.apply_group_arrival(writer, Some(ledger.incarnation.as_ref())) {
            return None;
        }
        if !ledger.classify_control(seq) {
            return None;
        }
        Some(ControlReceipt::Group(ledger))
    }

    /// Credit only the admission frame that classified this control.
    fn credit_control_receipt(&self, writer: [u8; 16], seq: u64, receipt: &ControlReceipt) -> bool {
        match receipt {
            ControlReceipt::Plain => self.credit_receipt(writer, seq),
            ControlReceipt::Group(ledger) => {
                let pending = self
                    .ownership_pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !pending.incarnations.get(&writer).is_some_and(|current| {
                    Arc::ptr_eq(current, &ledger.incarnation) && current.load(Ordering::Acquire)
                }) {
                    return false;
                }
                // Core receipt does not invoke a subscriber callback. The
                // frame stays current through the proxy update.
                self.credit_receipt(writer, seq);
            }
        }
        true
    }

    /// A different callback for the same provisional coherent WriterSN
    /// cannot turn a refused DATA into an acknowledged control change.
    fn credit_duplicate_receipt(&self, writer: [u8; 16], seq: u64) {
        if self.ack_credit.is_some()
            && self.coherent_cfg.coherent_access
            && self
                .coherent_admissions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&(writer, seq))
        {
            return;
        }
        self.credit_receipt(writer, seq);
    }

    /// Run the per-writer duplicate admission window and, when admitted,
    /// deliver. The shared tail of `on_data_with_writer` (live samples that
    /// cleared every gate) and `flush_ownership_pending` (samples deferred
    /// while their writer's OWNERSHIP verdict was unresolved -- they cleared
    /// the other gates at arrival time), so a retransmit that arrives both
    /// deferred and live is admitted exactly once.
    ///
    /// `admit` carries either the door's departure count or the deferred
    /// sample's writer incarnation, checked under the admission lock.
    fn admit_and_deliver(
        &self,
        writer_guid: [u8; 16],
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        admit: Admit<'_>,
    ) {
        self.deliver_sample(writer_guid, remote_seq, data, version, admit);
    }

    /// Deliver a sample that has already cleared the type / partition /
    /// data-representation / duplicate gates. Split out of
    /// `on_data_with_writer` so the coherent dispatch can pass a sample
    /// straight through WITHOUT a second dedup pass: `on_data_coherent`
    /// already admits the seq into `seen_seqs_by_writer`, so re-entering
    /// `on_data_with_writer` would see the sample as a duplicate and silently
    /// drop it. A GROUP-scope reader fed by a classic-model writer
    /// (PID_COHERENT_SET per DATA, no PID_GROUP_COHERENT_SET tag) hits exactly
    /// that pass-through and otherwise receives nothing.
    fn deliver_admitted_sample(
        &self,
        writer_guid: [u8; 16],
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) {
        self.deliver_sample(writer_guid, remote_seq, data, version, Admit::Done);
    }

    /// Report SAMPLE_LOST for `count` samples discarded with no other
    /// record: a coherent set that can never be whole (DDS v1.4
    /// Sec.2.2.4.1; RTPS v2.5 Sec.8.7.6: such a set's changes "shall be
    /// discarded by the Subscriber"), or a parked head the K>1 merge
    /// (`DataReader::pump_merge_locked`) could not keep across a sibling
    /// ring's decode failure. One door for both: the status, its
    /// condition, the listener -- `DataReader`'s own counter would
    /// otherwise be a second, listener-less copy of this one. Never
    /// called with a reader lock held.
    pub(super) fn report_sample_lost(&self, count: u64) {
        if count == 0 {
            return;
        }
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        let installed = self.listener.get(StatusMask::SAMPLE_LOST);
        let mut own = None;
        {
            let mut status = match self.sample_lost.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            status.total_count = status.total_count.saturating_add(count);
            status.total_count_change = status
                .total_count_change
                .saturating_add(i32::try_from(count).unwrap_or(i32::MAX));
            if let Some(listener) = installed.clone() {
                let snap = status.clone();
                status.total_count_change = 0;
                self.status_condition
                    .clear_active_status(StatusMask::SAMPLE_LOST);
                own = self
                    .lost_notices
                    .push(Box::new(move || listener.on_sample_lost(snap)))
                    .err();
            } else {
                self.status_condition
                    .raise_active_statuses(StatusMask::SAMPLE_LOST);
            }
        }
        if let Some(own) = own {
            super::notices::notify(own);
        } else if installed.is_some() {
            let notices = Arc::clone(&self.lost_notices);
            super::notices::notify(move || notices.tell());
        } else {
            // `WaitsetSignal` hooks are public trait code too.
            let status_condition = Arc::clone(&self.status_condition);
            super::notices::notify(move || {
                status_condition.notify_waitsets_for(StatusMask::SAMPLE_LOST);
            });
        }
    }

    /// Whether what `writer_guid` sent is from before it left, or from a
    /// writer not heard again yet, and is dropped at the door, holding
    /// nothing. Its gate state, staged sets and acknowledgement state went
    /// with its departure: a DATA held by a gate that will never see that
    /// writer's HEARTBEAT again kept its place in the history for good, a
    /// staged sample stayed staged, and a late copy of a change delivered
    /// already was delivered again. Dropped, it is not acknowledged: the
    /// writer, if it lives, sends it again.
    ///
    /// A departure is not always a death: a participant's lease expires
    /// over a network outage, a probation purge removes a peer that is
    /// still there. Such a writer comes back the way RTPS brings a writer
    /// back: its participant is discovered again and its announcement is
    /// received again (SEDP), which matches it again. The door lifts then:
    /// on its announcement (`on_writer_qos_resolved`), or, for a reliable
    /// reader, on its writer proxy matched again. A reliable reader that
    /// had received from it waits on top for its first HEARTBEAT, which
    /// tells the same writer from a new one under the same GUID
    /// (`heartbeat_verdict`): what lands before it is dropped too.
    ///
    /// The hot path reads one atomic while no writer is gone.
    #[inline]
    fn has_left(&self, writer_guid: &[u8; 16]) -> bool {
        if self
            .departed_count
            .load(std::sync::atomic::Ordering::Acquire)
            == 0
        {
            return false;
        }
        self.has_left_slow(writer_guid)
    }

    /// [`has_left`](Self::has_left), with some writer gone: one lookup.
    /// Departures older than `DEPARTED_KEEP` are forgotten here, all at
    /// once, when the oldest is due (`departed_purge_due_ms`): the fast path
    /// comes back once none is left.
    #[cold]
    fn has_left_slow(&self, writer_guid: &[u8; 16]) -> bool {
        let now = std::time::Instant::now();
        let keep = std::time::Duration::from_millis(
            self.departed_keep_ms
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        if self.departed_ms(now)
            >= self
                .departed_purge_due_ms
                .load(std::sync::atomic::Ordering::Acquire)
        {
            let mut departed = self.departed.write();
            let mut forgotten = Vec::new();
            departed.retain(|guid, d| {
                let kept = now.saturating_duration_since(d.left_at) < keep;
                if !kept {
                    forgotten.push(*guid);
                }
                kept
            });
            self.departed_count
                .store(departed.len(), std::sync::atomic::Ordering::Release);
            let due = departed
                .values()
                .map(|d| {
                    self.departed_ms(d.left_at)
                        .saturating_add(Self::millis(keep))
                })
                .min()
                .unwrap_or(u64::MAX);
            self.departed_purge_due_ms
                .store(due, std::sync::atomic::Ordering::Release);
            drop(departed);
            // A writer that fell silent kept its GSN record
            // (`on_writer_departure`) in case it came back; one that has
            // not by now is forgotten with its departure.
            forgotten.retain(|guid| !self.matched_again(guid));
            if !forgotten.is_empty() {
                let mut gsns = self.writer_gsns.lock().unwrap_or_else(|e| e.into_inner());
                for guid in &forgotten {
                    gsns.remove(guid);
                }
            }
        }
        let entry = self
            .departed
            .read()
            .get(writer_guid)
            .map(|d| (d.left_at, d.announced, d.awaiting_heartbeat));
        let Some((left_at, announced, awaiting_heartbeat)) = entry else {
            return false;
        };
        if now.saturating_duration_since(left_at) >= keep {
            return false;
        }
        if !announced && !self.matched_again(writer_guid) {
            return true;
        }
        if awaiting_heartbeat {
            // Matched again: its first HEARTBEAT decides.
            return true;
        }
        self.forget_departure(writer_guid, true);
        false
    }

    /// `at`, in milliseconds since `departed_base`.
    fn departed_ms(&self, at: std::time::Instant) -> u64 {
        Self::millis(at.saturating_duration_since(self.departed_base))
    }

    fn millis(d: std::time::Duration) -> u64 {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
    }

    /// Record `writer`'s departure at `departures` count `count`, and forget
    /// the records older than `DEPARTED_KEEP` (no DATA stays that long).
    fn record_left(&self, writer: [u8; 16], count: u64, at: std::time::Instant) {
        let mut left = self.left_counts.lock();
        left.retain(|_, (_, t)| at.saturating_duration_since(*t) < DEPARTED_KEEP);
        left.insert(writer, (count, at));
    }

    /// Whether `writer` left after the door read the `departures` count
    /// `epoch`, even if it was matched again since. Read only once that
    /// count moved (`deliver_prepared`).
    fn left_since(&self, writer: &[u8; 16], epoch: u64) -> bool {
        self.left_counts
            .lock()
            .get(writer)
            .is_some_and(|(count, _)| *count > epoch)
    }

    /// Whether `writer_guid` said it left and is not matched again: a
    /// change of it admitted before the departure and staged after it
    /// drained the staging is refused (the departure's drain and this test
    /// run under the staging buffer's lock). Staged, a new writer under the
    /// GUID had the old one's sample delivered in place of its own.
    fn refuses_staging(&self, writer_guid: &[u8; 16]) -> bool {
        self.departed_count
            .load(std::sync::atomic::Ordering::Acquire)
            != 0
            && self
                .departed
                .read()
                .get(writer_guid)
                .is_some_and(|d| d.deleted)
    }

    /// Whether a reliable reader's proxy of `writer_guid` exists again.
    fn matched_again(&self, writer_guid: &[u8; 16]) -> bool {
        self.ack_credit
            .as_ref()
            .is_some_and(|credit| credit.settled(writer_guid).is_some())
    }

    /// `writer_guid` is a writer of this reader again (`has_left`).
    fn forget_departure(&self, writer_guid: &[u8; 16], continuing: bool) {
        let mut departed = self.departed.write();
        let removed = departed.remove(writer_guid);
        if removed.is_some() {
            self.departed_count
                .store(departed.len(), std::sync::atomic::Ordering::Release);
        }
        drop(departed);
        if let Some(old) = removed
            .filter(|old| continuing && !old.deleted)
            .and_then(|old| old.losses)
        {
            self.restore_wire_loss_epoch(*writer_guid, &old);
        }
    }

    /// The first HEARTBEAT (lastSN `last_seq`) of a departed writer:
    /// whether it is heard (`None`: the writer is not matched again, the
    /// HEARTBEAT is dropped), and the ranges (`[start, end)`) it delivered
    /// before it left, for a writer that is the same one.
    ///
    /// A writer's sequence numbers only grow (RTPS v2.5 Sec.8.3.5.4): one
    /// whose lastSN is below the highest this reader received from it
    /// before is a new writer under the same GUID, starting again at 1; its
    /// record goes. Otherwise it is the same writer, back after a false
    /// departure: its record comes back, so what it sends again (its
    /// history, to a durable reader whose new proxy asks for it) is a
    /// duplicate, acknowledged and not delivered (its new gate steps over
    /// it: the ranges returned), and what was never received, or thrown away
    /// at the departure (`on_writer_dispose` takes it back), is delivered.
    fn heartbeat_verdict(&self, writer_guid: [u8; 16], last_seq: u64) -> Option<Vec<(u64, u64)>> {
        let mut delivered = Vec::new();
        let (parked, deleted) = {
            let mut departed = self.departed.write();
            let Some(entry) = departed.get_mut(&writer_guid) else {
                return Some(delivered);
            };
            if !entry.announced && !self.matched_again(&writer_guid) {
                return None;
            }
            // Another HEARTBEAT's verdict is putting the record back (it took
            // it, the door still shut): this one is dropped, and opens
            // nothing. Gone on, it opened the door before the record was
            // back. The writer sends HEARTBEATs again.
            if entry.awaiting_heartbeat && entry.parked.is_none() {
                return None;
            }
            // The door stays shut (`awaiting_heartbeat`) while the record
            // goes back: a DATA landing in between would find no record,
            // be admitted into a fresh one, and the record put back after
            // would forget it, or deliver a copy.
            (entry.parked.take(), entry.deleted)
        };
        let continuing = !deleted && parked.as_ref().is_none_or(|(_, high)| last_seq >= *high);
        if let Some((record, high)) = parked {
            if last_seq < high {
                log::debug!(
                    "[READER-SUB] writer {:02x?} back with lastSN {} below {}: a new writer",
                    &writer_guid[..4],
                    last_seq,
                    high
                );
            } else {
                log::debug!(
                    "[READER-SUB] writer {:02x?} back with lastSN {} at or above {}: the same writer",
                    &writer_guid[..4],
                    last_seq,
                    high
                );
                // What it delivered before it left: received, but those
                // thrown away at the departure (taken back).
                let mut at = 1;
                record.for_each_unreceived(1, high.saturating_add(1), &mut |lo, hi| {
                    if at < lo {
                        delivered.push((at, lo));
                    }
                    at = hi;
                });
                if at <= high {
                    delivered.push((at, high.saturating_add(1)));
                }
                #[cfg(test)]
                if let Some(hook) = self
                    .verdict_hook
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    hook();
                }
                self.seen_seqs_by_writer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(writer_guid, record);
            }
        }
        // Its new gate steps over what it delivered before it left, before
        // the door opens: the copies the writer sends again are duplicates
        // to its record, and the gate does not wait for them; a VOLATILE
        // gate, seeded by this, does not take the first DATA landing after
        // the door opens for where the reader joined (what the writer wrote
        // while taken for departed is owed).
        if !delivered.is_empty() {
            self.release_through_gate(writer_guid, |gate| {
                let mut released = Vec::new();
                for &(start, end) in &delivered {
                    released.extend(gate.on_gap(writer_guid, start, end, std::iter::empty()));
                }
                released
            });
        }
        self.forget_departure(&writer_guid, continuing);
        #[cfg(test)]
        if let Some(hook) = self
            .opened_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            hook();
        }
        Some(delivered)
    }

    /// Tests only: `DEPARTED_KEEP` set to `keep`.
    #[cfg(test)]
    pub(super) fn set_departed_keep_for_test(&self, keep: std::time::Duration) {
        self.departed_keep_ms.store(
            u64::try_from(keep.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.departed_purge_due_ms
            .store(0, std::sync::atomic::Ordering::Release);
    }

    /// Tests only: `reject_staged_set` of the writer's set starting at
    /// `start`.
    #[cfg(test)]
    pub(super) fn reject_staged_set_for_test(&self, writer_guid: [u8; 16], start: u64) {
        self.reject_staged_set(StagedSet::Writer(writer_guid, start));
    }

    /// Tests only: `emit_coherent_payloads` as a commit whose every member
    /// was rejected for storage (`take_rejected_member`) presents it --
    /// a non-empty `Vec` of nothing but `PendingPayload::nothing(seq)`.
    /// The deterministic seam for the real (racy, room-wait-triggered)
    /// path `reject_staged_set_for_test` otherwise requires.
    #[cfg(test)]
    pub(super) fn emit_all_rejected_set_for_test(&self, writer_guid: [u8; 16], seq: u64) {
        self.emit_coherent_payloads(
            writer_guid,
            vec![super::reorder::PendingPayload::nothing(seq)],
        );
    }

    /// Tests only: `reject_staged_set` of the GROUP set `key`.
    #[cfg(test)]
    pub(super) fn reject_group_set_for_test(&self, key: GroupSetKey) {
        self.reject_staged_set(StagedSet::Group(key));
    }

    /// Tests only: `step_gate_over_staged`.
    #[cfg(test)]
    pub(super) fn step_gate_over_staged_for_test(&self, writer_guid: [u8; 16], seq: u64) {
        self.step_gate_over_staged(writer_guid, seq);
    }

    /// Tests only: `note_reported`.
    #[cfg(test)]
    pub(super) fn note_reported_for_test(&self, writer_guid: [u8; 16], seq: u64) {
        self.note_reported(writer_guid, [seq]);
    }

    /// Tests only: how many departures the door keeps.
    #[cfg(test)]
    pub(super) fn departed_count_for_test(&self) -> usize {
        self.departed_count
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Tests only: this subscriber with `room`, the network room of the
    /// reader whose network ring it feeds (the builder sets it in
    /// production): every entry of that ring holds one of its places.
    #[cfg(test)]
    pub(super) fn with_room(mut self, room: Option<Arc<super::admission::HistoryRoom>>) -> Self {
        self.room = room;
        self
    }

    /// Decode, filter and store a member of the coherent set `set` (a
    /// sample when `data` is given; a dispose or unregister of the set
    /// otherwise, no storage), staged until the set commits and
    /// acknowledged long before: its storage is taken apart from the slab
    /// pool's tiers (`SlabPool::reserve_staged`), and the member, its
    /// storage and its entry (`staging_budget::cost_of`), is charged to
    /// this reader's staging budget (`staging_budget`, which states the
    /// rule), `in_order` saying whether it arrived in order
    /// (`staged_in_order`). `NotStaged::NoRoom` when the budget has no room
    /// for it now, `NotStaged::Rejected` when it rejects its set (the
    /// process ceiling makes room by rejecting sets whole, this reader's or
    /// another's), `NotStaged::NoStorage` when the heap tier has no handle
    /// left or it cannot be stored for the ring (a refusal names its
    /// instance). A sample with no storage (it does not decode, or is
    /// filtered) is charged its entry. A panic while preparing is taken as
    /// a sample that delivers nothing, as `deliver_sample` takes it.
    #[allow(clippy::too_many_arguments)]
    fn prepare_staged(
        &self,
        writer_guid: [u8; 16],
        remote_seq: u64,
        data: Option<&[u8]>,
        version: crate::dds::CdrVersion,
        set: StagedSet,
        in_order: bool,
    ) -> Result<
        (
            super::admission::Prepared,
            super::staging_budget::StagedCharge,
        ),
        NotStaged,
    > {
        let prepared = match data {
            None => super::admission::Prepared::Discard,
            Some(data) => {
                #[cfg(test)]
                self.staged_prepares.fetch_add(1, Ordering::AcqRel);
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match self.prepare_as(
                        Some(writer_guid),
                        remote_seq,
                        data,
                        version,
                        StoreAs::Staged,
                    ) {
                        // No handle left in the heap tier: refused, as a
                        // member the budget has no room for is.
                        Preparation::NoStorage { msg } => Err(NotStaged::NoStorage(
                            Self::instance_handle_for_rejection(&msg),
                        )),
                        prepared => prepared.into_prepared().map_err(|msg| {
                            NotStaged::NoStorage(Self::instance_handle_for_rejection(&msg))
                        }),
                    }
                }))
                .unwrap_or(Ok(super::admission::Prepared::Discard))?
            }
        };
        let prepared = prepared.with_inline_lifecycle::<T>(
            crate::engine::router::route_inline_lifecycle(Some(writer_guid), remote_seq),
        );
        let len = super::staging_budget::cost_of(prepared.stored_len());
        // Room is made by rejecting sets whole, this reader's here.
        let reject_own = |victim: StagedSet| self.reject_staged_set(victim);
        let admission = if self.ack_credit.is_some() && self.wire_bindings.is_some() {
            self.staging.admit_retaining(set, len, in_order)
        } else {
            self.staging.admit(set, len, in_order, &reject_own)
        };
        match admission {
            Admission::Admitted => {
                let charge = super::staging_budget::StagedCharge::new(&self.staging, set, len);
                Ok((prepared, charge))
            }
            Admission::Refused => {
                log::debug!(
                    "[READER-SUB] coherent staging refused topic='{}' writer={:02x?} seq={} \
                     len={} staged={} budget={}",
                    self.topic,
                    &writer_guid[..4],
                    remote_seq,
                    len,
                    self.staging.used(),
                    self.staging.budget()
                );
                Err(NotStaged::NoRoom(
                    prepared
                        .sample::<T>()
                        .and_then(Self::instance_handle_for_rejection),
                ))
            }
            Admission::Rejected => {
                log::debug!(
                    "[READER-SUB] coherent staging rejects its set topic='{}' writer={:02x?} \
                     seq={} len={} staged={} budget={}",
                    self.topic,
                    &writer_guid[..4],
                    remote_seq,
                    len,
                    self.staging.used(),
                    self.staging.budget()
                );
                Err(NotStaged::Rejected)
            }
        }
    }

    /// Whether the coherent set `set` was rejected for its storage
    /// (`reject_staged_set`): one lookup, whatever the set's length.
    fn set_rejected(&self, set: StagedSet) -> bool {
        self.rejected_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&set)
    }

    /// Whether a member `seq` of `writer`'s part of the set `set` (whose
    /// first SN there is `start`, when known) arrived in order: nothing of
    /// its writer awaited below the part's first sequence number. `None`
    /// while the gate has no baseline for the writer yet (no HEARTBEAT, or
    /// no DATA through a gate seeded by its first): it joins at this set,
    /// which the budget takes as in order (see `staging_budget`), and the
    /// writer's staging bounds do not.
    fn staged_in_order(
        &self,
        writer: [u8; 16],
        seq: u64,
        set: StagedSet,
        start: Option<u64>,
    ) -> Option<bool> {
        let mut first = start.unwrap_or(seq).min(seq);
        if let StagedSet::Group(key) = set {
            if let Some(staged) = self
                .group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&key)
                .and_then(|set| set.per_writer.get(&writer))
            {
                first = staged
                    .iter()
                    .map(|m| m.coherent_sn.unwrap_or(m.remote_seq).min(m.remote_seq))
                    .fold(first, u64::min);
            }
        }
        let gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
        // A gate seeded by the first DATA it passes says nothing awaited
        // before it has one: no baseline either.
        gate.next_seq(&writer)?;
        gate.places_to_keep(&writer, first).map(|below| below == 0)
    }

    /// Reject the coherent set `set` whole for its storage
    /// (`staging_budget`): its staged members leave the staging at once,
    /// their storage given back before this returns; each steps its
    /// writer's gate, delivering nothing, and each sample is reported
    /// SAMPLE_REJECTED. What is left of the set is a [`RejectedSet`], the
    /// same few bytes whatever its length: a change of it landing later
    /// takes no storage and no staging entry (`take_rejected_member`). A
    /// GROUP set goes whole, every writer's part, and a set of the spec
    /// dialect is lost to the Subscriber's barrier.
    ///
    /// Kept staged until closed instead, a set that never closed took one
    /// staging entry per member, for good, and every member walked them
    /// all.
    /// Ordered GROUP reliable staging keeps bytes already acknowledged.
    /// Other profiles retain their existing resource-limit reclamation.
    fn reject_staged_set(&self, set: StagedSet) {
        if self.ack_credit.is_some() && self.wire_bindings.is_some() {
            return;
        }
        // Its listeners are told once its delivery locks are released.
        let _delivering = super::notices::Delivering::enter();
        // The record goes in under the staging's lock, which a member takes
        // to be staged: none is staged under the set past this point.
        let (removed, spec): (Vec<([u8; 16], BufferedCoherentSample)>, bool) = match set {
            StagedSet::Writer(writer, start) => {
                let mut buf = self
                    .coherent_buffer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mut removed = Vec::new();
                if let Some(staged) = buf.get_mut(&writer) {
                    let (out, kept): (Vec<_>, Vec<_>) = std::mem::take(staged)
                        .into_iter()
                        .partition(|member| member.coherent_sn == Some(start));
                    *staged = kept;
                    if staged.is_empty() {
                        buf.remove(&writer);
                    }
                    removed = out.into_iter().map(|m| (writer, m)).collect();
                }
                self.rejected_sets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(set);
                (removed, false)
            }
            StagedSet::Group(key) => {
                let mut buf = self
                    .group_coherent_buffer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let staged = buf.remove(&key);
                self.rejected_sets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(set);
                drop(buf);
                let spec = staged.as_ref().is_some_and(|s| s.writer_set.is_some());
                let removed = staged
                    .map(|s| {
                        s.per_writer
                            .into_iter()
                            .flat_map(|(w, v)| v.into_iter().map(move |m| (w, m)))
                            .collect()
                    })
                    .unwrap_or_default();
                (removed, spec)
            }
        };
        // A writer's set committed already, held by its gate above a gap:
        // its members there deliver nothing, their storage and charges
        // given back (none of it reached the application: the gate
        // releases a set's members together, once nothing is awaited below
        // them). Kept, the room its rejection was to make was never made.
        // A GROUP set's parts are flushed writer by writer, and may have
        // left already: what its gates hold stays charged until it leaves.
        let stripped = match set {
            StagedSet::Writer(writer, _) => self
                .reorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .strip_held(&writer, |payload| {
                    payload
                        .staged
                        .as_ref()
                        .is_some_and(|charge| charge.set() == set)
                }),
            StagedSet::Group(_) => Vec::new(),
        };
        // Their storage, given back now; what the reports name, decoded
        // before.
        let mut seqs: Vec<([u8; 16], u64)> = Vec::with_capacity(removed.len());
        let mut instances: Vec<Option<InstanceHandle>> = Vec::new();
        let mut lost = 0u64;
        for (writer, member) in removed {
            if self.wire_bindings.is_some() {
                lost = lost.saturating_add(self.received_staged_lost(writer, &member));
            }
            seqs.push((writer, member.remote_seq));
            if member.lifecycle.is_none() {
                instances.push(
                    Self::decode_staged(&member).and_then(Self::instance_handle_for_rejection),
                );
            }
        }
        let held = stripped.len();
        for payload in stripped {
            match set {
                StagedSet::Writer(writer, _) if self.wire_bindings.is_some() => {
                    lost = lost.saturating_add(self.received_payload_lost(writer, &payload));
                }
                _ => {}
            }
            if !matches!(
                payload.prepared,
                super::admission::Prepared::Lifecycle { .. }
            ) {
                instances.push(
                    payload
                        .prepared
                        .sample::<T>()
                        .and_then(Self::instance_handle_for_rejection),
                );
            }
        }
        {
            let mut rejected = self.rejected_sets.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(record) = rejected.get_mut(&set) {
                record.members = record.members.saturating_add(
                    u64::try_from(seqs.len().saturating_add(held)).unwrap_or(u64::MAX),
                );
                record.samples = record
                    .samples
                    .saturating_add(u64::try_from(instances.len()).unwrap_or(u64::MAX));
                if let Some(instance) = instances.iter().rev().flatten().next() {
                    record.instance = Some(*instance);
                }
            }
        }
        log::debug!(
            "[READER-SUB] coherent set {:?} rejected whole for its storage topic='{}' \
             staged members={} samples={}",
            set,
            self.topic,
            seqs.len(),
            instances.len()
        );
        seqs.sort_unstable();
        for (writer, seq) in seqs {
            self.step_gate_over_rejected(writer, seq);
        }
        for instance in instances {
            self.report_refusal(Refusal::Storage, instance);
        }
        self.report_sample_lost(lost);
        if let StagedSet::Group(key) = set {
            if spec {
                self.abandon_spec_generation(key);
            }
        }
        self.retry_group_sets_awaiting_gates();
    }

    /// A GROUP set waiting for a writer's gate to reach its part
    /// (`try_flush_group_sets`) is decided again: a gate moved.
    fn retry_group_sets_awaiting_gates(&self) {
        if self
            .group_sets_await_gate
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.try_flush_group_sets();
        }
    }

    /// A change `seq` of `writer`'s, a member of the coherent set `set`
    /// rejected for its storage, landed (a sample when `sample`, else a
    /// dispose or unregister of the set), received and acknowledged
    /// already, its gate told of it (`ReorderGate::observe`): taken with no
    /// storage and no staging entry. It steps its writer's gate, delivering
    /// nothing, and a sample is reported SAMPLE_REJECTED, naming the
    /// instance the set's record keeps. Constant time.
    fn take_rejected_member(&self, writer: [u8; 16], seq: u64, set: StagedSet, sample: bool) {
        // Its listeners are told once its delivery locks are released.
        let _delivering = super::notices::Delivering::enter();
        let instance = {
            let mut rejected = self.rejected_sets.lock().unwrap_or_else(|e| e.into_inner());
            rejected.get_mut(&set).and_then(|record| {
                record.members = record.members.saturating_add(1);
                if sample {
                    record.samples = record.samples.saturating_add(1);
                }
                record.instance
            })
        };
        self.step_gate_over_rejected(writer, seq);
        if sample {
            self.report_refusal(Refusal::Storage, instance);
        }
        self.retry_group_sets_awaiting_gates();
    }

    /// A change of a coherent set rejected for its storage landed
    /// (`stage_coherent_change`, past its duplicate record): acknowledged
    /// and taken (`take_rejected_member`), unless its writer's gate holds
    /// no more above a gap (`ReorderGate::holds_no_more`), where it is
    /// refused unacknowledged, as any change is, and sent again.
    fn rejected_member_lands(
        &self,
        writer: [u8; 16],
        seq: u64,
        coherent_sn: Option<u64>,
        set: StagedSet,
        sample: bool,
    ) {
        let holds_no_more = {
            let gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
            gate.holds_no_more(&writer, seq)
        };
        if holds_no_more {
            self.join_at_refused_member(writer, seq, coherent_sn);
            self.refuse_unacknowledged(writer, seq, true, Refusal::Backlog, None);
            return;
        }
        self.credit_receipt(writer, seq);
        let (behind, lost) = {
            let mut gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
            let behind = gate.is_behind(&writer, seq);
            let lost = self.best_effort_gap_before(&gate, writer, seq);
            if !behind {
                gate.observe(writer, seq, coherent_sn);
            }
            (behind, lost)
        };
        self.report_sample_lost(lost);
        if behind {
            return;
        }
        self.take_rejected_member(writer, seq, set, sample);
    }

    /// Step `writer_guid`'s gate over `seq`, a change received of a set
    /// rejected for its storage: it takes its turn and delivers nothing.
    /// Not reported lost (it was received, and reported rejected).
    fn step_gate_over_rejected(&self, writer_guid: [u8; 16], seq: u64) {
        self.release_through_gate(writer_guid, |gate| {
            if self.has_left(&writer_guid) {
                return Vec::new();
            }
            gate.on_staged(writer_guid, seq, PendingPayload::nothing(seq))
        });
    }

    /// Store the sample and take its slot in the reader's history (or
    /// refuse it unacknowledged), admit it into the duplicate window when
    /// `admit` says so, run the per-writer reorder gate, credit reliable
    /// receipt, and push any released samples to the application. The one
    /// door every sample that is credited on arrival goes through: whatever
    /// it needs to reach the application is held before the credit.
    fn deliver_sample(
        &self,
        writer_guid: [u8; 16],
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        admit: Admit<'_>,
    ) {
        // Its listeners are told once its delivery locks are released.
        let _delivering = super::notices::Delivering::enter();
        // Run the sample through the per-writer reorder gate. For Volatile
        // readers the gate is disabled and returns the sample immediately;
        // for TRANSIENT_LOCAL+ readers it holds out-of-order arrivals until
        // the writer-seq prefix is contiguous (DDS v1.4 sec. 2.2.3.4 + RTPS
        // v2.5 sec. 8.4.2.2 reliable-retransmit interleaving).
        //
        // The reader first takes the sample's slot in its history,
        // under the gate's lock so the gate cannot move between the question
        // "will it be held?" and the answer. No slot, no receipt: the sample
        // is refused before anything records it. The duplicate question,
        // the slot and the admission are one step under that lock: a copy
        // of the same sequence arriving on another thread either finds it
        // admitted with its slot (and is a duplicate the reader did keep) or
        // not admitted at all, never admitted and about to be refused.
        //
        // The sample is stored first, outside the gate's lock: the slab
        // buffer it needs is one more thing it must hold before anything
        // records its receipt. A sample the slab pool has no room for is
        // refused below like one the history has no room for; a duplicate
        // or a refused sample gives its buffer back as `prepared` drops.
        //
        // A panic while preparing (a decoder, a field extractor) does not
        // leave the sample unacknowledged for ever: it would panic again at
        // every resend and stop its writer's stream at its sequence. It is
        // taken as a sample that delivers nothing, and goes on once the
        // sample is through.
        let (prepared, _resume) =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.prepare(Some(writer_guid), remote_seq, data, version)
                    .into_prepared()
            })) {
                Ok(prepared) => (prepared, ResumeOnReturn(None)),
                Err(panic) => (
                    Ok(super::admission::Prepared::Discard),
                    ResumeOnReturn(Some(panic)),
                ),
            };
        self.deliver_prepared(writer_guid, remote_seq, version, admit, prepared);
        #[cfg(test)]
        {
            let hook = self
                .delivered_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(hook) = hook {
                hook(remote_seq);
            }
        }
    }

    /// Count actual storage abandoned when its admission frame departed.
    #[cold]
    #[inline(never)]
    fn report_prepared_departure(
        &self,
        writer: [u8; 16],
        seq: u64,
        prepared: &Result<super::admission::Prepared, T>,
        admit: Admit<'_>,
    ) {
        if self.wire_bindings.is_none()
            || !matches!(prepared, Ok(super::admission::Prepared::Stored(_)))
        {
            return;
        }
        let frame = match admit {
            Admit::Direct(_, frame) | Admit::Pending(frame) => frame,
            Admit::Here(_) | Admit::Done => return,
        };
        let lost = frame.loss_authority().record_prepared_loss(writer, seq);
        self.report_sample_lost(lost);
    }

    /// Admit DATA and lifecycle changes through one duplicate and reorder gate.
    fn deliver_prepared(
        &self,
        writer_guid: [u8; 16],
        remote_seq: u64,
        version: crate::dds::CdrVersion,
        admit: Admit<'_>,
        prepared: Result<super::admission::Prepared, T>,
    ) {
        let _delivering = super::notices::Delivering::enter();
        // A full KEEP_LAST ring drops what newer samples replace before the
        // gate's lock is taken: the pass decodes the whole ring, and every
        // writer of this reader waits for the gate. The place is still asked
        // under the gate below, where a ring filled again in between is
        // compacted all the same. This pass does not count the incoming
        // sample: it is not yet known to be delivered (a duplicate, a sample
        // the gate refuses or holds, one its writer does not own), and
        // counted it would drop the newest sample of its instance, already
        // acknowledged, for a sample that never takes its place.
        if let (Some(room), Ok(stored)) = (&self.room, &prepared) {
            if let (Some(depth), Some(_)) = (room.keep_last(), stored.sample::<T>()) {
                if self.ring.is_full() {
                    self.drop_replaced(room, depth);
                }
            }
        }
        // Read before the gate's lock: the staging buffers are never locked
        // under it.
        let below_open_group_set = self.room.is_some()
            && self.coherent_cfg.is_group_scope
            && self.group_set_open_below(&writer_guid, remote_seq);
        let delivery_lock = self.writer_delivery_lock(writer_guid);
        #[cfg(test)]
        if let Some(hook) = self
            .admission_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            hook();
        }
        let mut lost = 0u64;
        let (release, waiting) = {
            let mut gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            // The writer left since this DATA passed the door: its record and
            // its gate went in a section of this lock (`on_writer_dispose`),
            // and admitted now, the DATA would open a fresh record the
            // departure never saw. Dropped, unacknowledged: a writer that
            // comes back sends it again. A sample admitted before the
            // departure (`Admit::Done`, a staged set's) is delivered.
            // The count avoids another lookup while unchanged.
            if let Admit::Here(epoch) | Admit::Direct(epoch, _) = admit {
                if self.departures.load(std::sync::atomic::Ordering::Acquire) != epoch
                    && (self.has_left(&writer_guid) || self.left_since(&writer_guid, epoch))
                {
                    self.report_prepared_departure(writer_guid, remote_seq, &prepared, admit);
                    return;
                }
            }
            // A re-announcement may already have lifted `has_left`. The
            // token still identifies the writer that prepared this DATA,
            // not its successor (RTPS 2.5 Sec.8.4.10.3, 8.4.12.1).
            if let Admit::Direct(_, incarnation) = admit {
                if !incarnation.load(std::sync::atomic::Ordering::Acquire) {
                    self.report_prepared_departure(writer_guid, remote_seq, &prepared, admit);
                    return;
                }
            }
            if let Admit::Pending(incarnation) = admit {
                if !incarnation.load(std::sync::atomic::Ordering::Acquire)
                    || self.has_left(&writer_guid)
                {
                    self.report_prepared_departure(writer_guid, remote_seq, &prepared, admit);
                    return;
                }
            }
            let mut seen_map = match admit {
                Admit::Here(_) | Admit::Direct(_, _) | Admit::Pending(_) => {
                    Some(match self.seen_seqs_by_writer.lock() {
                        Ok(lock) => lock,
                        Err(e) => e.into_inner(),
                    })
                }
                Admit::Done => None,
            };
            let seen = match seen_map {
                Some(ref mut map) => self.judge_seen(
                    map.entry(writer_guid).or_default(),
                    writer_guid,
                    remote_seq,
                    self.missed(),
                ),
                None => Seen::New,
            };
            if seen == Seen::Duplicate {
                drop(seen_map);
                drop(gate);
                log::debug!(
                    "[READER-SUB] dropping duplicate remote_seq={} writer={:02x?} topic='{}'",
                    remote_seq,
                    &writer_guid[..4],
                    self.topic
                );
                // Dropped, but received: a retransmission requested after
                // a re-match (whose fresh proxy knows nothing) must still
                // move this reader's acknowledgement forward.
                self.credit_duplicate_receipt(writer_guid, remote_seq);
                return;
            }
            // The gate holds no more above the gap below this sample, or
            // the duplicate record cannot take it without dropping what
            // is owed: refused, unacknowledged, sent again later. A coherent
            // reader's gate too: past its bound it made "forced progress",
            // giving up the gap below, whose repair it then took for
            // history, acknowledged and never delivered.
            if seen == Seen::Full || gate.holds_no_more(&writer_guid, remote_seq) {
                let admitted_already = seen_map.is_none();
                drop(seen_map);
                gate.on_refused(writer_guid, remote_seq);
                self.finish_refusal(
                    Some(gate),
                    writer_guid,
                    remote_seq,
                    admitted_already,
                    Refusal::Backlog,
                    None,
                );
                return;
            }
            // Every sample takes, before its credit, everything it needs to
            // reach the application: its storage and its place in the
            // reader's history (RTPS v2.5 Sec.8.4.12.2, T8). A sample the
            // gate holds keeps free what the gap below it needs: places (see
            // `places_to_keep`) and the storage of the gap's head (see
            // `SlabPool::hold`). With the process-wide slab pool full of
            // held samples, the sample the gate waits for would be refused
            // for ever, and the held ones never released.
            let keep = gate.places_to_keep(&writer_guid, remote_seq);
            // Held above a GROUP set of the spec dialect its writer has a
            // part in, still open: the set takes the places of every
            // writer's part at once when it commits, parts not all landed
            // yet, so how many places the gap below this sample needs is
            // not known. Held with a place, it kept one of them, and the
            // set waited for it while it waited for the set.
            let keep = keep.filter(|&keep| keep == 0 || !below_open_group_set);
            let wire_keep = self
                .capture_wire_order(writer_guid, remote_seq)
                .zip(self.coherent_barrier.as_ref())
                .zip(self.barrier_member)
                .map_or(0, |((change, barrier), member)| {
                    if self.ack_credit.is_some()
                        && self.coherent_cfg.coherent_access
                        && !barrier.wire_may_stage_unit(writer_guid, change, member, change.gsn)
                    {
                        // A future singleton cannot take a place that the
                        // unresolved head coherent unit may need in full.
                        return usize::MAX;
                    }
                    barrier.wire_needs_predecessor_room(writer_guid, change, member)
                });
            let keep = keep.map(|keep| keep.max(wire_keep));
            let straight_on = keep == Some(0);
            // A reliable reader holds a sample only for a writer it is
            // matched with: one it keeps no proxy of (not matched yet, or
            // gone and forgotten, `DEPARTED_KEEP`) sends no HEARTBEAT to
            // this reader that would release it, and held it kept a place
            // for good. Refused, unacknowledged: a writer matched later
            // sends it again (RTPS v2.5 Sec.8.4.12: a reliable reader takes
            // a writer's changes through its WriterProxy).
            if !straight_on
                && self
                    .ack_credit
                    .as_ref()
                    .is_some_and(|credit| credit.settled(&writer_guid).is_none())
            {
                let admitted_already = seen_map.is_none();
                drop(seen_map);
                self.finish_refusal(
                    Some(gate),
                    writer_guid,
                    remote_seq,
                    admitted_already,
                    Refusal::Backlog,
                    None,
                );
                return;
            }
            // Before the writer's first HEARTBEAT the gap below a held
            // sample is unknown. The reader holds it all the same, with its
            // place, keeping one place (and instance room for one sample)
            // free: the first sample of that gap, once known, arrives in
            // order and needs one; with it the gap fills one sample at a
            // time as the application takes (every sample in order is the
            // application's to take), so the held samples are released.
            // Held samples that took the last place would wait for good for
            // a gap with none. Refusing them all instead costs the first
            // samples of every newly matched reader a round trip: RTPS v2.5
            // Sec.8.4.15.4 has the HEARTBEAT follow the DATA.
            //
            // Not for a reader with coherent access: the gap may be filled
            // by a coherent set, which takes the places of all its samples
            // at once, and one place left would not hold it: the samples
            // held above the gap would wait for the set, and the set for
            // their places, for good. It refuses until the gap is known.
            let gap_unknown = keep.is_none();
            let keep = match (keep, &self.room) {
                (None, Some(_)) if !self.coherent_cfg.coherent_access => Some(1),
                (keep, _) => keep,
            };
            // One history for every writer: the places another writer's
            // gap needs are kept free from this one, whose samples would
            // otherwise take them while that writer waits for its repair,
            // and refuse the repair for want of a place at each
            // retransmission (see `ReorderGate::places_owed_except`).
            //
            // Except for the sample that fills its own writer's gap (in
            // order, its writer's gate holding samples above it): it is the
            // repair those places are kept for, whichever gap. Kept from it,
            // two writers whose gaps were owed more than the free places
            // (gaps learned at a HEARTBEAT, after their samples were held)
            // refused each other's repair for good, and nothing the
            // application could take freed a place.
            let owed = match self.room {
                Some(_) if straight_on && gate.has_gap(&writer_guid) => 0,
                Some(_) => gate.places_owed_except(&writer_guid),
                None => 0,
            };
            // Held, its storage is kept for the gap's head too; refused that,
            // it is refused as one with no storage.
            let head = self.head_estimate.load(Ordering::Relaxed);
            let kept = match prepared {
                Ok(mut prepared) => {
                    if straight_on || prepared.hold(head) {
                        Ok(prepared)
                    } else {
                        Err(prepared
                            .sample::<T>()
                            .and_then(Self::instance_handle_for_rejection))
                    }
                }
                // The next sample of its writer, in order, with no storage:
                // the samples held above it wait for it, and the storage
                // they hold, or a co-located writer's history that only its
                // acknowledgement frees (a readers' share smaller than one
                // sample keeps no room for it), may be what it lacks: waited
                // for, it waited for good. It takes the heap tier past its
                // ceiling by this one sample (`rt::Claim::Head`). A reliable
                // reader's only: nothing waits for a best-effort one.
                Err(msg) if straight_on && self.ack_credit.is_some() => {
                    match self
                        .store(
                            Some(writer_guid),
                            remote_seq,
                            msg,
                            version,
                            StoreAs::Pool(rt::Claim::Head),
                        )
                        .into_prepared()
                    {
                        Ok(prepared) => Ok(prepared),
                        Err(msg) => Err(Self::instance_handle_for_rejection(&msg)),
                    }
                }
                Err(msg) => Err(Self::instance_handle_for_rejection(&msg)),
            };
            let mut prepared = match kept {
                Ok(prepared) => prepared,
                // No storage: refused, unacknowledged, a resource limit the
                // application hears about. It comes again, in order.
                Err(instance) => {
                    let admitted_already = seen_map.is_none();
                    drop(seen_map);
                    gate.on_refused(writer_guid, remote_seq);
                    self.finish_refusal(
                        Some(gate),
                        writer_guid,
                        remote_seq,
                        admitted_already,
                        Refusal::Storage,
                        instance,
                    );
                    return;
                }
            };
            // The gap head may have retried storage after preparation.
            if let super::admission::Prepared::Stored(stored) = &mut prepared {
                if stored.legacy_key_hash.is_none() {
                    stored.legacy_key_hash =
                        crate::engine::router::route_legacy_hash(Some(writer_guid), remote_seq);
                }
            }
            prepared = prepared.with_inline_lifecycle::<T>(
                crate::engine::router::route_inline_lifecycle(Some(writer_guid), remote_seq),
            );
            // A sample passed straight on that delivers nothing needs no
            // place: refusing it for want of one would only have it resent.
            let delivers = !matches!(
                prepared,
                super::admission::Prepared::Discard
                    | super::admission::Prepared::Unstorable { .. }
                    | super::admission::Prepared::Lifecycle { .. }
            );
            let mut slot = match self.room {
                Some(ref room) if delivers => {
                    // No place, or no way yet to know how many the gap
                    // below needs: refused, unacknowledged. Only the first
                    // is a resource limit the application hears about.
                    let granted = match keep {
                        Some(keep) => self
                            .reserve_place(
                                room,
                                keep.saturating_add(owed),
                                keep,
                                || prepared.sample::<T>().map(DDS::compute_key),
                                crate::engine::router::route_source_ts_ns(),
                                Some(writer_guid),
                                remote_seq,
                                // A held sample replaces nothing: whether it
                                // is visible is known only at its release, in
                                // order.
                                if straight_on {
                                    Replace::IfVisible {
                                        writer: writer_guid,
                                        seq: remote_seq,
                                    }
                                } else {
                                    Replace::Never
                                },
                            )
                            .map_err(|bound| match bound {
                                // A full KEEP_LAST ring refusing a held
                                // sample: it comes again in order, and may
                                // then replace the oldest of its instance.
                                // Not a limit it is beyond, not reported.
                                // Nor one that would take the place kept for
                                // a gap not known yet.
                                super::admission::Bound::Samples
                                    if !straight_on
                                        && (gap_unknown || room.keep_last().is_some()) =>
                                {
                                    Refusal::Backlog
                                }
                                bound => Refusal::from(bound),
                            }),
                        None => Err(Refusal::GapUnknown),
                    };
                    match granted {
                        // `None`: its writer does not own its instance, it
                        // takes no place (and replaces nothing).
                        Ok(slot) => slot,
                        Err(refusal) => {
                            let admitted_already = seen_map.is_none();
                            drop(seen_map);
                            gate.on_refused(writer_guid, remote_seq);
                            let instance = match refusal {
                                Refusal::ResourceLimit
                                | Refusal::InstanceLimit
                                | Refusal::SamplesPerInstanceLimit => prepared
                                    .sample::<T>()
                                    .and_then(Self::instance_handle_for_rejection),
                                _ => None,
                            };
                            self.finish_refusal(
                                Some(gate),
                                writer_guid,
                                remote_seq,
                                admitted_already,
                                refusal,
                                instance,
                            );
                            return;
                        }
                    }
                }
                _ => None,
            };
            let mut order = self.capture_wire_order(writer_guid, remote_seq);
            let mut order_token =
                self.register_wire_order(writer_guid, remote_seq, &prepared, order, admit);
            if let Some(change) = order.filter(|_| order_token.is_none()) {
                let stale = self
                    .coherent_barrier
                    .as_ref()
                    .zip(self.barrier_member)
                    .is_some_and(|(barrier, member)| barrier.wire_is_stale(change, member));
                if stale {
                    // This member already settled this Publisher prefix. Its
                    // writer SN still passes the receive gate without data.
                    if matches!(prepared, super::admission::Prepared::Stored(_)) {
                        let count = if self.wire_bindings.is_some() {
                            let incarnation = match admit {
                                Admit::Direct(_, incarnation) | Admit::Pending(incarnation) => {
                                    Some(incarnation)
                                }
                                _ => None,
                            };
                            let count = self
                                .wire_loss_ledger(writer_guid, incarnation)
                                .and_then(|ledger| ledger.try_record(remote_seq));
                            let Some(count) = count else {
                                let admitted_already = seen_map.is_none();
                                drop(seen_map);
                                gate.on_refused(writer_guid, remote_seq);
                                self.finish_refusal(
                                    Some(gate),
                                    writer_guid,
                                    remote_seq,
                                    admitted_already,
                                    Refusal::Backlog,
                                    None,
                                );
                                return;
                            };
                            count
                        } else {
                            match seen_map {
                                Some(ref mut map) => map
                                    .entry(writer_guid)
                                    .or_default()
                                    .reported
                                    .report(remote_seq, remote_seq.saturating_add(1)),
                                None => self.received_sequence_lost(writer_guid, remote_seq),
                            }
                        };
                        lost = lost.saturating_add(count);
                    }
                    drop(slot.take());
                    prepared = super::admission::Prepared::Discard;
                    order = None;
                    order_token = None;
                } else {
                    let admitted_already = seen_map.is_none();
                    drop(seen_map);
                    gate.on_refused(writer_guid, remote_seq);
                    self.finish_refusal(
                        Some(gate),
                        writer_guid,
                        remote_seq,
                        admitted_already,
                        Refusal::Backlog,
                        None,
                    );
                    return;
                }
            }
            // BEST_EFFORT irreversibly passes the missing prefix on this
            // DATA (RTPS v2.5 Sec.8.4.12.1, T2). Count only unreceived,
            // unfiltered samples since the established baseline (DDS v1.4
            // Sec.2.2.4.1), before recording this sequence can roll the
            // duplicate window past those holes. The gate serializes this
            // decision with competing DATA and filtered GAPs.
            if gate.is_best_effort() {
                if let Some(next) = gate
                    .next_seq(&writer_guid)
                    .filter(|&next| next < remote_seq)
                {
                    let filtered = gate.filtered_ranges(&writer_guid);
                    lost = lost.saturating_add(match seen_map {
                        Some(ref mut map) => map
                            .entry(writer_guid)
                            .or_default()
                            .report_unreceived_in([(next, remote_seq)], &filtered),
                        None => {
                            self.never_received_in(writer_guid, [(next, remote_seq)], &filtered)
                        }
                    });
                }
            }
            if let Some(ref mut map) = seen_map {
                map.entry(writer_guid)
                    .or_default()
                    .record(remote_seq, self.missed());
            }
            drop(seen_map);
            let pending_legacy_instance = match &prepared {
                super::admission::Prepared::Stored(stored) if T::has_key() => stored
                    .legacy_key_hash
                    .and_then(|hash| prepared.sample::<T>().map(|msg| (hash, msg.compute_key()))),
                _ => None,
            };
            let pending_legacy_lifecycle = match &prepared {
                super::admission::Prepared::Lifecycle { key, kind } => Some((*key, *kind)),
                super::admission::Prepared::Stored(stored) => stored.inline_lifecycle,
                _ => None,
            };
            let payload = PendingPayload {
                order,
                order_token,
                version,
                remote_seq,
                source_ts_ns: crate::engine::router::route_source_ts_ns(),
                slot,
                prepared,
                staged: None,
            };
            let released = gate.on_data(writer_guid, remote_seq, payload);
            // Retained above a gap or released behind another delivery
            // is already admitted (RTPS 2.5 Sec.8.4.12.2 T8). Its alias
            // facts must precede any concurrent later DATA's hint.
            let retained = gate.holds_sample(&writer_guid, remote_seq)
                || released
                    .iter()
                    .any(|payload| payload.remote_seq == remote_seq);
            if retained {
                if let Some((hash, key)) = pending_legacy_instance {
                    self.writer_instances.learn_pending_legacy_key_hash(
                        writer_guid,
                        hash,
                        key,
                        remote_seq,
                    );
                }
                if let Some((key, kind)) = pending_legacy_lifecycle {
                    self.writer_instances.note_pending_legacy_lifecycle(
                        writer_guid,
                        key,
                        remote_seq,
                        kind,
                    );
                }
            }
            let waiting = gate.may_trail_proxy(&writer_guid);
            if released.is_empty() {
                (Release::Nothing, waiting)
            } else {
                (
                    Release::from_gate(&mut gate, writer_guid, released, &delivery_lock),
                    waiting,
                )
            }
        };
        #[cfg(test)]
        if !matches!(release, Release::Nothing) {
            self.left_the_gate();
        }

        // Advance the reliable reader's contiguous-prefix state with the
        // sequence we actually received, once the sample is in the reader's
        // keeping (RTPS v2.5 Sec.8.4.12.2, T8: `add_change`, then
        // `received_change_set`). This is what makes the ACKNACK base/bitmap
        // reflect real receipt; the ControlHandler reads this same registry
        // when a HEARTBEAT arrives. A sample the gate dropped as already
        // delivered was received too. No-op for VOLATILE / intra-process
        // readers (registry is None).
        self.credit_receipt(writer_guid, remote_seq);
        // `release` is consumed here, its delivery lock with it: the gate
        // may release more for this writer in `follow_proxy`, which takes
        // that lock again.
        let panicked = self.deliver_release(writer_guid, release);
        self.report_sample_lost(lost);
        // A listener's panic does not stop the gate from following the
        // proxy: what the gate still holds would otherwise wait for a
        // message a writer with everything acknowledged never sends.
        if waiting {
            self.follow_proxy(writer_guid);
        }
        if let Some(panic) = panicked {
            std::panic::resume_unwind(panic);
        }
    }

    /// Whoever moves the writer proxy moves the gate: once the proxy awaits
    /// nothing up to a sequence the gate still waits for (a GAP or a
    /// sample-less DATA above the gate's base, which the gate does not
    /// record), the gate follows (`ReorderGate::catch_up`) and what it
    /// releases is delivered now. Waiting for a later message instead is
    /// waiting for what may never come: a writer whose changes are all
    /// acknowledged goes quiet (RTPS v2.5 Sec.8.4.9.2).
    fn follow_proxy(&self, writer_guid: [u8; 16]) {
        if !self.gate_is_bounded() {
            return;
        }
        let Some(settled) = self.settled(writer_guid) else {
            return;
        };
        self.release_through_gate(writer_guid, |gate| gate.catch_up(writer_guid, settled));
    }

    /// Run `step` on the reorder gate and deliver what it releases for
    /// `writer_guid`, in the order it leaves the gate.
    fn release_through_gate(
        &self,
        writer_guid: [u8; 16],
        step: impl FnOnce(&mut ReorderGate) -> Vec<PendingPayload>,
    ) {
        // Its listeners are told once its delivery locks are released.
        let _delivering = super::notices::Delivering::enter();
        let delivery_lock = self.writer_delivery_lock(writer_guid);
        let release = {
            let mut gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            let released = step(&mut gate);
            if released.is_empty() {
                return;
            }
            Release::from_gate(&mut gate, writer_guid, released, &delivery_lock)
        };
        #[cfg(test)]
        self.left_the_gate();
        if let Some(panic) = self.deliver_release(writer_guid, release) {
            std::panic::resume_unwind(panic);
        }
    }

    /// Deliver what `Release::from_gate` decided, in the order it left the
    /// gate; the first panic of the delivery, if any, for the caller to
    /// resume once it is done.
    #[must_use]
    fn deliver_release(&self, writer_guid: [u8; 16], release: Release<'_>) -> Option<Panic> {
        match release {
            Release::Nothing => None,
            Release::Now(delivering, batch) => {
                self.deliver_in_order(writer_guid, batch, &delivering)
            }
            Release::Queued => self.drain_ready(writer_guid),
        }
    }

    /// Deliver what `writer_guid`'s gate queued (`ReorderGate::hand_over`)
    /// under that writer's delivery lock, what other threads queued
    /// meanwhile included. A thread that released a sample before another
    /// may reach the delivery lock after it: the samples are delivered in
    /// the order they left the gate all the same, whichever thread delivers
    /// them. One take is enough: whoever queues a sample drains after, so
    /// what is queued after this take is some later drain's.
    #[must_use]
    fn drain_ready(&self, writer_guid: [u8; 16]) -> Option<Panic> {
        // Its listeners are told once its delivery locks are released.
        let _delivering = super::notices::Delivering::enter();
        let lock = self.writer_delivery_lock(writer_guid);
        let delivering = match lock.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let ready = {
            let mut gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            gate.take_ready(&writer_guid, &delivering)
        };
        self.deliver_in_order(writer_guid, ready, &delivering)
    }

    /// Deliver `batch`, taken from the gate under `writer_guid`'s delivery
    /// lock (`_delivering`), sample by sample. A sample whose delivery
    /// panics (an application listener) does not hold back those after it:
    /// they may have been released by another thread, and they are
    /// acknowledged, so nothing would bring them again (a writer whose
    /// changes are all acknowledged goes quiet, RTPS v2.5 Sec.8.4.9.2). The
    /// first panic is returned once the batch is delivered, for the caller
    /// to resume when it has done what it still must (the router catches it
    /// and the thread lives on).
    #[must_use]
    fn deliver_in_order(
        &self,
        writer_guid: [u8; 16],
        batch: Vec<PendingPayload>,
        _delivering: &std::sync::MutexGuard<'_, ()>,
    ) -> Option<Panic> {
        let mut panicked = None;
        for payload in batch {
            if let (Some(change), Some(barrier), Some(member)) = (
                payload.order,
                self.coherent_barrier.as_ref(),
                self.barrier_member,
            ) {
                let ordered = self.ordered_payload(writer_guid, payload);
                barrier.deposit_wire_order(member, writer_guid, change, ordered);
                continue;
            }
            let delivered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.process_admitted(
                    Some(writer_guid),
                    payload.remote_seq,
                    payload.version,
                    payload.source_ts_ns,
                    payload.slot,
                    payload.prepared,
                    None,
                );
            }));
            if let Err(panic) = delivered {
                panicked.get_or_insert(panic);
            }
        }
        panicked
    }

    /// Tests only: run `hook` in the next full-ring compaction, while the
    /// ring is popped and nothing is pushed back.
    #[cfg(test)]
    pub(super) fn on_next_compaction(&self, hook: Box<dyn FnOnce() + Send>) {
        *self
            .compaction_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(hook);
    }

    /// Tests only: run `hook` when a set next finds too little room.
    #[cfg(test)]
    pub(super) fn on_next_refused_room(&self, hook: Box<dyn FnOnce() + Send>) {
        *self
            .refused_room_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(hook);
    }

    /// Tests only: how many ring entries full-ring compactions decoded.
    #[cfg(test)]
    pub(super) fn compaction_decodes(&self) -> usize {
        self.compaction_decodes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Compact an explicitly prepared history fixture, apart from admission.
    #[cfg(test)]
    pub(super) fn compact_history_for_test(&self, depth: usize) {
        let room = self.room.as_ref().expect("network history room");
        self.compact(room, depth, None, None);
    }

    /// Tests only: where a release has left the gate and is yet to be
    /// delivered, the thread `ReaderAckCredit::hold_next` names waits.
    #[cfg(test)]
    fn left_the_gate(&self) {
        if let Some(credit) = &self.ack_credit {
            credit.pass();
        }
    }

    /// Tests only: just after a count of a coherent set's staged samples
    /// (`staged_count_for_sn`), the thread `ReaderAckCredit::hold_next`
    /// names waits.
    #[cfg(test)]
    fn test_pause(&self) {
        if let Some(credit) = &self.ack_credit {
            credit.pass();
        }
    }

    #[cfg(test)]
    fn pause_pending_for_test(&self) {
        let hook = self
            .pending_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        } else {
            self.test_pause();
        }
    }

    /// Whether a coherent sample of `writer_guid` staged now would take,
    /// once its set commits, a place another writer's gap needs: some
    /// writer other than it has a gap open (`places_owed_except`), and the
    /// history's free places do not exceed what the gaps need plus the
    /// samples already staged that fill no gap.
    ///
    /// A staged sample is acknowledged when staged and takes its place only
    /// when its set commits, where it cannot be refused: a coherent stream
    /// then took the places another writer's repair needed, and that
    /// writer's held samples waited while the stream went on (see
    /// `ReorderGate::places_owed_except`). Refused here instead, it is
    /// sent again. Staged samples hold no place, so two sets being staged
    /// never wait for each other's places.
    ///
    /// A sample that fills its own writer's gap (`ReorderGate::awaits`) is
    /// never refused here: it is a repair the gaps' places are kept for. A
    /// sample above it, or of a writer with no gap, is a stream like any
    /// other. Refusing it keeps no gap open for good: a set's end is learned
    /// from a refused sample too (`SetEnds`), and every gap fills with
    /// samples this check never refuses. A staged sample that fills a gap
    /// is not counted as staged either: its place is already among those
    /// the gap owes. A snapshot, not a reservation: a set commits only once
    /// it has its places (`try_commit_sets`).
    ///
    /// Cost: one gate lock per staged sample; the staged samples are read
    /// only while another writer's gap is open.
    fn staging_would_take_owed_places(&self, writer_guid: &[u8; 16], seq: u64) -> bool {
        let Some(room) = self.room.as_ref() else {
            return false;
        };
        let owed = {
            let gate = match self.reorder.lock() {
                Ok(gate) => gate,
                Err(e) => e.into_inner(),
            };
            if gate.awaits(writer_guid, seq) {
                return false;
            }
            gate.places_owed_except(writer_guid)
        };
        if owed == 0 {
            return false;
        }
        // What is staged, read before the gate is asked about it: the
        // staging buffers are never locked under the gate's lock.
        let mut staged: Vec<([u8; 16], u64)> = {
            let buf = self
                .coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            buf.iter()
                .flat_map(|(writer, samples)| samples.iter().map(|s| (*writer, s.remote_seq)))
                .collect()
        };
        {
            let buf = self
                .group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for set in buf.values() {
                for (writer, samples) in &set.per_writer {
                    staged.extend(samples.iter().map(|s| (*writer, s.remote_seq)));
                }
            }
        }
        let gate = match self.reorder.lock() {
            Ok(gate) => gate,
            Err(e) => e.into_inner(),
        };
        let owed = gate.places_owed_except(writer_guid);
        let staged = staged
            .iter()
            .filter(|(writer, seq)| !gate.awaits(writer, *seq))
            .count();
        room.free() <= owed.saturating_add(staged)
    }

    /// Whether this reader's reorder gate follows the writer proxy. Not for
    /// a coherent reader: it credits a coherent sample when staging it,
    /// before the sample reaches the gate, so its proxy can run ahead of its
    /// gate. (Every reader's gate refuses at its bound, `holds_no_more`.)
    fn gate_is_bounded(&self) -> bool {
        !self.coherent_cfg.coherent_access
    }

    /// A place in `room` for a sample of instance `key`, keeping `keep`
    /// free, or `None` when the reader has no room for it.
    ///
    /// A KEEP_LAST reader's ring full of samples does not refuse the newer
    /// one (DDS v1.4 Sec.2.2.3.18: the most recent `depth` values of each
    /// instance are kept): the samples it would replace are dropped from the
    /// ring first ([`Self::drop_replaced`]), and the place is asked again.
    /// Only a ring full of samples the history still keeps refuses. The
    /// common case, a place free, costs what `reserve` costs.
    ///
    /// In a room that bounds instances the slot also counts the sample for
    /// its instance, `key()` (`None` when the sample names none), or the
    /// place is refused with the bound it would exceed; an instance no
    /// writer holds any more and with no sample left is forgotten then.
    ///
    /// The ring is compacted in two steps. First what newer samples already
    /// in the ring replace: that drops nothing the history keeps, whatever
    /// becomes of the incoming sample. Then, if the ring is still full, the
    /// oldest sample of the incoming sample's own instance, which the
    /// incoming one replaces: only once the incoming sample is certain to be
    /// pushed, as `replace` says. A sample that would not be pushed (its
    /// writer does not own the instance) must not drop the value it would
    /// have replaced: that value was acknowledged and is never sent again.
    ///
    /// `Ok(None)`: the sample is not visible ([`Replace::IfVisible`]) and
    /// takes no place.
    #[allow(clippy::too_many_arguments)]
    fn reserve_place(
        &self,
        room: &Arc<super::admission::HistoryRoom>,
        keep: usize,
        headroom: usize,
        key: impl Fn() -> Option<[u8; 16]>,
        source_ts_ns: Option<u64>,
        incoming_writer: Option<[u8; 16]>,
        incoming_sn: u64,
        replace: Replace,
    ) -> Result<Option<super::admission::HistorySlot>, super::admission::Bound> {
        use super::admission::Bound;
        let instance = if room.counts_instances() { key() } else { None };
        let reserve = || {
            room.reserve_for(keep, headroom, instance, |key| {
                self.writer_instances.is_held(key)
            })
            .map(Some)
        };
        match reserve() {
            Err(Bound::Samples) => {}
            granted => return granted,
        }
        if let Some(depth) = room.keep_last() {
            if self.drop_replaced(room, depth) > 0 {
                match reserve() {
                    Err(Bound::Samples) => {}
                    granted => return granted,
                }
            }
        }
        let incoming = if T::has_key() {
            instance.or_else(&key).unwrap_or([0; 16])
        } else {
            [0; 16]
        };
        let visible = || match replace {
            Replace::Always => true,
            Replace::Never => false,
            Replace::IfVisible { writer, seq } => {
                self.writer_instances.visible_ahead(writer, incoming, seq)
            }
        };
        if matches!(replace, Replace::Never) {
            return Err(Bound::Samples);
        }
        // The place of the sample replaced is handed to the incoming one,
        // never given back first: given back, another producer could take
        // it, or the gaps' owed places refuse it to the incoming sample,
        // after the value it replaces was dropped. Same place, same
        // instance: nothing another writer's gap is owed changes.
        if let Some(depth) = room.keep_last() {
            match self.replace_oldest(
                room,
                depth,
                incoming,
                source_ts_ns,
                incoming_writer,
                incoming_sn,
                &visible,
            ) {
                Replacement::Made(slot) => return Ok(Some(slot)),
                Replacement::NotVisible => return Ok(None),
                Replacement::NothingToReplace => {}
            }
        }
        // A BEST_EFFORT KEEP_ALL history discards its old values at its
        // limits (DDS v1.4 Sec.2.2.3.18): nothing of the incoming sample's
        // instance to replace, its ring, sized `max_samples + 1`, holds at
        // least `max_samples` samples newer than every cached one, and its
        // oldest is one it discards. Only for a sample that is visible, so
        // nothing is dropped for one that is not pushed. The oldest is of
        // another instance: its place goes back and is asked again (a
        // BEST_EFFORT sample refused then is a drop, reported).
        if room.discards_old() && visible() && self.drop_oldest(room) {
            return reserve();
        }
        Err(Bound::Samples)
    }

    /// Drop the oldest sample of the network ring of a history that
    /// discards its old values (`HistoryRoom::discards_old`), with its place
    /// and its instance count. Same consumer side as
    /// [`Self::drop_replaced`]. Returns whether one was dropped.
    fn drop_oldest(&self, room: &Arc<super::admission::HistoryRoom>) -> bool {
        let _consumer = room.consume();
        let _producer = match self.push_lock.lock() {
            Ok(guard) => guard,
            Err(e) => e.into_inner(),
        };
        let Some(entry) = self.ring.pop() else {
            return false;
        };
        let slab_pool = rt::get_slab_pool_ref();
        drop(room.adopt());
        if !entry.handle.is_empty() {
            if room.counts_instances() {
                if let Some(key) = super::admission::ring_entry_instance::<T>(&entry, slab_pool) {
                    room.release_instance(&key);
                }
            }
            slab_pool.release(entry.handle);
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
        if let Some(m) = telemetry::get_metrics_opt() {
            m.increment_dropped(1);
        }
        true
    }

    /// Drop from a full KEEP_LAST(`depth`) network ring every sample that
    /// `depth` newer samples of its instance replace, counting, when
    /// `incoming` names its instance, a sample about to be pushed; returns
    /// how many were dropped. What stays keeps its order.
    ///
    /// The ring is popped whole and what the history keeps pushed back, so
    /// this producer is the ring's consumer for the while: it holds the
    /// room's consumer guard, which every pop of the reader takes too, then
    /// the push lock. Cold: reached only when the application left a full
    /// ring untaken. Each entry of a keyed type is decoded for its key once
    /// per arrival at most: a pass that finds the ring as the previous pass
    /// left it (nothing pushed since, [`RingKeys`]) reuses its keys, and
    /// pops nothing when nothing is to be dropped. Every sample in the ring is newer than every sample of the
    /// reader's cache, which drops its own older ones as the ring is taken.
    fn drop_replaced(&self, room: &Arc<super::admission::HistoryRoom>, depth: usize) -> usize {
        self.compact(room, depth, None, None).0
    }

    /// Make room in a full KEEP_LAST(`depth`) ring for a sample of instance
    /// `incoming`, with source timestamp `incoming_ts`, writer GUID
    /// `incoming_writer` and writer SN `incoming_sn` (DDS v1.4
    /// Sec.2.2.3.17, all three irrelevant under BY_RECEPTION_TIMESTAMP or
    /// when the incoming sample carries no source timestamp), by
    /// dropping the oldest sample of that instance, whose place and
    /// instance count the incoming sample takes over
    /// ([`HistoryRoom::hand_over`]). `visible` is asked, once, only when
    /// there is such a sample: a sample not visible replaces nothing,
    /// and an EXCLUSIVE arbitration is recorded only for a sample that
    /// is then certain to be pushed. What newer samples in the ring
    /// replace is dropped on the way, as [`Self::drop_replaced`] does.
    ///
    /// [`HistoryRoom::hand_over`]: super::admission::HistoryRoom::hand_over
    #[allow(clippy::too_many_arguments)]
    fn replace_oldest(
        &self,
        room: &Arc<super::admission::HistoryRoom>,
        depth: usize,
        incoming: [u8; 16],
        incoming_ts: Option<u64>,
        incoming_writer: Option<[u8; 16]>,
        incoming_sn: u64,
        visible: &dyn Fn() -> bool,
    ) -> Replacement {
        self.compact(
            room,
            depth,
            Some(CompactIncoming {
                key: incoming,
                ts: incoming_ts,
                writer_guid: incoming_writer,
                sn: incoming_sn,
            }),
            Some(visible),
        )
        .1
    }

    /// [`Self::drop_replaced`], and with `visible` [`Self::replace_oldest`]:
    /// how many entries were dropped and, for the latter, its outcome.
    #[allow(clippy::type_complexity)]
    fn compact(
        &self,
        room: &Arc<super::admission::HistoryRoom>,
        depth: usize,
        incoming: Option<CompactIncoming>,
        visible: Option<&dyn Fn() -> bool>,
    ) -> (usize, Replacement) {
        let _consumer = room.consume();
        let mut producer = match self.push_lock.lock() {
            Ok(guard) => guard,
            Err(e) => e.into_inner(),
        };
        let slab_pool = rt::get_slab_pool_ref();
        let incoming_key = incoming.map(|inc| inc.key);
        // BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17): resolved once, not
        // per entry or per call -- `RingKeys` caches instance keys only,
        // never timestamps, so a BY_SOURCE_TIMESTAMP reader always takes
        // the full-decode path below (cold already: "reached only when
        // the application left a full ring untaken") instead of trusting
        // that cache. A BY_RECEPTION_TIMESTAMP reader's path is untouched:
        // same cache, same decode-once-per-arrival behaviour as before
        // this flag existed.
        let by_source = self.dispose_events.instances.by_source_timestamp();
        // Nothing pops the ring (the consumer guard) nor pushes into it (the
        // push lock) while this pass runs: its length is what it pops.
        let len = self.ring.len();
        // Per entry, when `by_source`: (source timestamp, `None` when the
        // entry has none; writer GUID from the GUID prefix already in the
        // slab buffer, no decode needed beyond what `ring_entry_instance`
        // already pays for the instance key; the writer's full SN from the
        // same prefix).
        // This must be the EXACT total order `InstanceTable::
        // admit_by_source` uses, or compaction can discard the
        // entry the gate would have kept.
        let (entries, keys, order): (
            Vec<rt::IndexEntry>,
            Vec<Option<[u8; 16]>>,
            Option<Vec<OrderTuple>>,
        ) = if by_source {
            let mut entries = Vec::with_capacity(len);
            let mut keys = Vec::with_capacity(len);
            let mut order = Vec::with_capacity(len);
            while let Some(entry) = self.ring.pop() {
                keys.push(super::admission::ring_entry_instance::<T>(
                    &entry, slab_pool,
                ));
                // The writer GUID and, from a BY_SOURCE_TIMESTAMP reader's
                // prefix, the writer's full sequence number
                // (`ReaderSubscriber::store`): the same 64 bits the
                // incoming sample and admission compare, never the ring's
                // 32-bit `seq`.
                let (guid, sn) = if entry.has_guid_prefix() {
                    let buf = slab_pool.get_buffer(entry.handle);
                    let guid = (entry.len as usize >= 16 && buf.len() >= 16).then(|| {
                        let mut guid = [0u8; 16];
                        guid.copy_from_slice(&buf[..16]);
                        guid
                    });
                    (guid, entry.writer_sn_in(&buf))
                } else {
                    (None, None)
                };
                // `None` timestamp for a sample with no genuine source
                // timestamp (a best-effort vendor that omitted INFO_TS):
                // nothing trustworthy to rank it by, so it sorts as the
                // oldest of its instance (`replaced_by_source_order`'s
                // doc) -- the same "no information, do not claim an
                // order" choice admission makes (`key: None`).
                order.push((
                    entry.has_source_ts().then_some(entry.timestamp_ns),
                    guid,
                    sn.unwrap_or(u64::from(entry.seq)),
                ));
                #[cfg(test)]
                self.compaction_decodes
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entries.push(entry);
            }
            (entries, keys, Some(order))
        } else {
            match producer.take(len) {
                Some(keys) => {
                    // Known: decide before popping, and leave a ring with
                    // nothing to drop untouched.
                    if !Self::replaced(&keys, depth, incoming_key).contains(&true) {
                        producer.record(keys);
                        return (0, Replacement::NothingToReplace);
                    }
                    let mut entries = Vec::with_capacity(len);
                    while let Some(entry) = self.ring.pop() {
                        entries.push(entry);
                    }
                    (entries, keys, None)
                }
                None => {
                    let mut entries = Vec::with_capacity(len);
                    let mut keys = Vec::with_capacity(len);
                    while let Some(entry) = self.ring.pop() {
                        keys.push(super::admission::ring_entry_instance::<T>(
                            &entry, slab_pool,
                        ));
                        #[cfg(test)]
                        self.compaction_decodes
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        entries.push(entry);
                    }
                    (entries, keys, None)
                }
            }
        };
        debug_assert_eq!(entries.len(), keys.len(), "a ring entry without its key");
        #[cfg(test)]
        if let Some(hook) = self
            .compaction_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            hook();
        }
        let compute_replaced = |incoming: Option<CompactIncoming>| match &order {
            Some(order) => Self::replaced_by_source_order(&keys, order, depth, incoming),
            None => Self::replaced(&keys, depth, incoming.map(|inc| inc.key)),
        };
        let mut replaced = compute_replaced(incoming);
        // Replacing for a sample that is not visible: what it would have
        // replaced stays.
        let mut outcome = Replacement::NothingToReplace;
        if let (Some(visible), Some(incoming_key)) = (visible, incoming_key) {
            let replaces = keys
                .iter()
                .zip(&replaced)
                .any(|(key, replaced)| *replaced && *key == Some(incoming_key));
            if replaces && !visible() {
                replaced = compute_replaced(None);
                outcome = Replacement::NotVisible;
            }
        }
        let mut handed = None;
        let mut dropped = 0usize;
        let mut survivors = Vec::with_capacity(keys.len());
        for ((entry, key), replaced) in entries.into_iter().zip(keys).zip(replaced) {
            if replaced || !self.ring.push(entry) {
                if visible.is_some() && handed.is_none() && key == incoming_key {
                    // Its place and instance count go to the incoming
                    // sample.
                    handed = Some(room.hand_over(key));
                } else {
                    // Its place goes back with it, and its instance count.
                    drop(room.adopt());
                    if let Some(key) = key.filter(|_| room.counts_instances()) {
                        room.release_instance(&key);
                    }
                }
                slab_pool.release(entry.handle);
                dropped += 1;
            } else {
                survivors.push(key);
            }
        }
        if let Some(slot) = handed {
            outcome = Replacement::Made(slot);
        }
        let kept = survivors.len();
        producer.record(survivors);
        // The ring was empty while this pass held it: a take in between
        // found no sample and cleared DATA_AVAILABLE (the reader's take
        // pops the network ring under this pass's guard, but its idle check
        // reads the ring without it). What was pushed back is announced
        // again, as a push is.
        if kept > 0 {
            self.status_condition
                .raise_data_available_shared(WakeWord::Network.index());
        }
        if dropped > 0 {
            self.dropped.fetch_add(dropped as u64, Ordering::Relaxed);
            if let Some(m) = telemetry::get_metrics_opt() {
                m.increment_dropped(dropped as u64);
            }
            log::debug!(
                "[READER-SUB] topic='{}': {} samples replaced by newer ones (KEEP_LAST {})",
                self.topic,
                dropped,
                depth
            );
        }
        (dropped, outcome)
    }

    /// For each ring entry of instance `keys[i]` (`None`: unknown, kept),
    /// oldest first, whether `depth` newer samples of its instance replace
    /// it, counting a sample of instance `incoming` about to be pushed when
    /// there is one.
    fn replaced(keys: &[Option<[u8; 16]>], depth: usize, incoming: Option<[u8; 16]>) -> Vec<bool> {
        // For each instance, how many of its samples from here on: the
        // entry under the cursor, every later one, and the incoming one.
        let mut from_here: HashMap<[u8; 16], usize> = HashMap::new();
        for key in keys.iter().flatten().chain(incoming.as_ref()) {
            *from_here.entry(*key).or_default() += 1;
        }
        keys.iter()
            .map(|key| {
                key.and_then(|key| from_here.get_mut(&key))
                    .is_some_and(|count| {
                        let replaced = *count > depth;
                        *count -= 1;
                        replaced
                    })
            })
            .collect()
    }

    /// [`Self::replaced`] for a reader whose DESTINATION_ORDER is
    /// BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17): a full ring must not
    /// keep a source-OLDER sample over a source-NEWER one of the same
    /// instance just because the older one happened to arrive later.
    /// `replaced`'s rule -- which `depth` entries of an instance survive
    /// -- picks them by ARRIVAL position (oldest position drops first);
    /// this one picks them by the EXACT SAME total order
    /// `InstanceTable::admit_by_source` uses -- `(timestamp,
    /// writer GUID, writer SN)` -- keeping the `depth` entries with the
    /// GREATEST key per instance regardless of where they sit in the
    /// ring. Comparing `(timestamp, position)` instead of the writer's
    /// identity would be wrong, even on the reasoning that "whatever
    /// survives still passes the gate's own acceptance check": a
    /// KEEP_LAST(1) ring that discards the higher-GUID sample here never
    /// lets the gate compare it at all, so a lower-GUID sample the gate
    /// would have refused survives instead, and two readers of the same
    /// writers in opposite arrival order can end up keeping different
    /// values. `order` is parallel to `keys`: `(timestamp, writer GUID,
    /// writer SN)`, timestamp `None` for an entry with no genuine source
    /// timestamp, which sorts as the oldest of its instance (nothing
    /// trustworthy says otherwise) -- the same "no information, do not
    /// claim an order" choice admission makes for such a sample.
    /// `incoming`, when given, is one more entry about to be pushed,
    /// position `keys.len()`.
    fn replaced_by_source_order(
        keys: &[Option<[u8; 16]>],
        order: &[OrderTuple],
        depth: usize,
        incoming: Option<CompactIncoming>,
    ) -> Vec<bool> {
        let mut by_instance: HashMap<[u8; 16], Vec<(usize, OrderTuple)>> = HashMap::new();
        for (pos, (key, &order)) in keys.iter().zip(order).enumerate() {
            if let Some(key) = key {
                by_instance.entry(*key).or_default().push((pos, order));
            }
        }
        if let Some(inc) = incoming {
            by_instance
                .entry(inc.key)
                .or_default()
                .push((keys.len(), (inc.ts, inc.writer_guid, inc.sn)));
        }
        let mut keep = std::collections::HashSet::new();
        for positions in by_instance.values_mut() {
            positions.sort_unstable_by_key(|&(pos, order)| (order, pos));
            for &(pos, _) in positions.iter().rev().take(depth) {
                keep.insert(pos);
            }
        }
        keys.iter()
            .enumerate()
            .map(|(pos, key)| key.is_some() && !keep.contains(&pos))
            .collect()
    }

    /// Refuse a sample the reader has no room for, leaving no trace
    /// of its receipt: it is not credited, and when `admitted_already` (the
    /// coherent dispatch admits before it passes a sample through) its
    /// admission is taken back so the copy the writer sends again is not
    /// dropped as a duplicate. A provisional coherent admission excludes
    /// concurrent copies until this withdrawal or successful storage ends.
    /// DDS v1.4 Sec.2.2.3.19: a RELIABLE service may "discard the sample at
    /// the DataReader in order not to lose existing samples", footnote 28:
    /// "So that the sample can be re-sent at a later time." A full history
    /// (`Refusal::ResourceLimit`) or slab pool (`Refusal::Storage`) is
    /// reported as REJECTED_BY_SAMPLES_LIMIT, with `instance`, the sample's
    /// instance when it is known. A BEST_EFFORT reader credits
    /// nothing: for it the refusal is a drop, reported the same way.
    fn refuse_unacknowledged(
        &self,
        writer_guid: [u8; 16],
        remote_seq: u64,
        admitted_already: bool,
        refusal: Refusal,
        instance: Option<InstanceHandle>,
    ) {
        self.finish_refusal(
            None,
            writer_guid,
            remote_seq,
            admitted_already,
            refusal,
            instance,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_refusal<'a>(
        &'a self,
        mut locked_gate: Option<std::sync::MutexGuard<'a, ReorderGate>>,
        writer_guid: [u8; 16],
        remote_seq: u64,
        admitted_already: bool,
        refusal: Refusal,
        instance: Option<InstanceHandle>,
    ) {
        let _delivering = super::notices::Delivering::enter();
        let ordinary_delivery = locked_gate.is_some() || !self.coherent_cfg.coherent_access;
        #[cfg(test)]
        {
            let hook = self
                .refusal_entry_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
        let delivery_lock = self.writer_delivery_lock(writer_guid);
        let mut release = Release::Nothing;
        let mut received_best_effort = false;
        let mut lost = 0;
        if self.ack_credit.is_none() {
            let mut gate = locked_gate
                .take()
                .unwrap_or_else(|| self.reorder.lock().unwrap_or_else(|e| e.into_inner()));
            if gate.is_best_effort() && !self.has_left(&writer_guid) {
                let mut seen = self
                    .seen_seqs_by_writer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let record = seen.entry(writer_guid).or_default();
                // Rejection means the DATA was received, although it could
                // not be stored. T2 still passes its older sequences, but
                // the rejected sample itself is not SAMPLE_LOST.
                if let Some(next) = gate
                    .next_seq(&writer_guid)
                    .filter(|&next| next < remote_seq)
                {
                    lost = record.report_unreceived_in(
                        [(next, remote_seq)],
                        &gate.filtered_ranges(&writer_guid),
                    );
                }
                record.record(remote_seq, Missed::Dropped);
                record.settle(remote_seq);
                drop(seen);
                let lifecycle = if ordinary_delivery {
                    crate::engine::router::route_inline_lifecycle(Some(writer_guid), remote_seq)
                } else {
                    crate::engine::router::route_unstaged_inline_lifecycle(
                        Some(writer_guid),
                        remote_seq,
                    )
                };
                if let Some((wire_key, kind)) = lifecycle {
                    // The value is rejected, but its lifecycle is received.
                    // It takes the same ordered delivery fence as DATA; if
                    // later DATA passed it meanwhile, its transition is old.
                    let key = instance.map_or(wire_key, |handle| *handle.as_bytes());
                    let payload = PendingPayload::lifecycle(
                        remote_seq,
                        key,
                        kind,
                        crate::engine::router::route_source_ts_ns(),
                    );
                    let released = gate.on_data(writer_guid, remote_seq, payload);
                    release = Release::from_gate(&mut gate, writer_guid, released, &delivery_lock);
                } else {
                    gate.observe(writer_guid, remote_seq, None);
                }
                received_best_effort = true;
            }
        }
        // A reliable refusal supplied with its admission guard releases it
        // before status callbacks, as the BEST_EFFORT block above does.
        drop(locked_gate);
        #[cfg(test)]
        {
            let hook = self
                .refusal_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
        if let Some(panic) = self.deliver_release(writer_guid, release) {
            std::panic::resume_unwind(panic);
        }
        self.report_sample_lost(lost);
        if admitted_already && !received_best_effort {
            let mut map = match self.seen_seqs_by_writer.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            if let Some(seen) = map.get_mut(&writer_guid) {
                seen.forget(remote_seq);
            }
        }
        log::debug!(
            "[READER-SUB] no room: refusing remote_seq={} writer={:02x?} topic='{}' unacknowledged",
            remote_seq,
            &writer_guid[..4],
            self.topic
        );
        if matches!(refusal, Refusal::GapUnknown | Refusal::Backlog) {
            return;
        }
        self.report_refusal(refusal, instance);
    }

    /// Cleartext payloads this reader refused because its topic's payload is
    /// protected (`decrypt_if_secured`).
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn cleartext_refused(&self) -> u64 {
        self.cleartext_refused
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many answers the protection cache has resolved (`protection`), so
    /// a test can tell a served answer from a recomputed one.
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn protection_resolutions(&self) -> u64 {
        self.protection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .resolutions()
    }

    /// Whether the governance protects the payload of this reader's topic.
    /// One flag test on a participant built without security; otherwise the
    /// cached answer (`protection`), which is dropped when the document
    /// generation moves. No access control (no governance) protects nothing,
    /// as before; a topic no rule matches - a reader this participant should
    /// not have created (Sec.9.4.1.2.7) - is treated as protected.
    #[cfg(feature = "security")]
    fn topic_payload_protected(&self) -> bool {
        self.security.is_some() && self.resolved_payload_protection() == Some(true)
    }

    /// The topic's payload protection as the governance document states it,
    /// `None` when no access-control plugin is there to state it.
    #[cfg(feature = "security")]
    fn resolve_topic_protection(
        suite: &crate::security::SecurityPluginSuite,
        topic: &str,
    ) -> Option<bool> {
        suite.access_control().map(|access| {
            access
                .endpoint_attributes(topic)
                .map_or(true, |attributes| attributes.is_payload_protected)
        })
    }

    /// `topic_payload_protected`, but telling apart an EXPLICIT governance
    /// verdict from having no governance to ask at all: `Some(true)` /
    /// `Some(false)` when an access-control plugin resolved the attribute,
    /// `None` when there is none (encryption used on its own, without a
    /// governance document) and so nothing resolved it either way.
    #[cfg(feature = "security")]
    fn resolved_payload_protection(&self) -> Option<bool> {
        let suite = self.security.as_ref()?;
        match self.protection_epoch() {
            Some(epoch) => self
                .protection
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .topic(epoch, || Self::resolve_topic_protection(suite, &self.topic)),
            None => Self::resolve_topic_protection(suite, &self.topic),
        }
    }

    /// Select protection from the writer's announcement, from the cache when
    /// it holds one (`protection`). Without a discovery registry, standalone
    /// readers use their explicitly configured attributes.
    ///
    /// The three answers are kept apart all the way to the caller: `None` when
    /// nothing resolved the writer yet (discovery is gone, or has not
    /// announced it), `Some(None)` when it is known and announced no
    /// `PID_ENDPOINT_SECURITY_INFO` (a settled answer: it speaks in the
    /// clear), `Some(Some(..))` when it announced attributes. Collapsing the
    /// middle one into the first makes a reader that holds a suite drop every
    /// sample of a plain writer for ever.
    #[cfg(feature = "security")]
    fn writer_payload_security(
        &self,
        writer: &[u8; 16],
    ) -> Option<Option<crate::protocol::discovery::EndpointSecurityInfo>> {
        let Some(epoch) = self.protection_epoch() else {
            // Discovery is gone: nothing can be resolved, and the cache must
            // not answer from an announcement nobody can vouch for.
            return None;
        };
        if let Some(resolved) = self
            .protection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .writer(epoch, writer)
        {
            return Some(resolved);
        }
        // Not filed yet: ask discovery, and file the answer only when it is
        // one. A writer discovery does not hold (yet) must be asked again.
        let resolved = self.resolve_writer_security(writer)?;
        self.protection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .file_writer(epoch, *writer, resolved);
        Some(resolved)
    }

    /// The epoch the protection cache is filed under: the DOCUMENTS'
    /// generation (a permissions overlay reload moves it) plus discovery's
    /// (every SEDP mutation moves it, so a writer that re-announces different
    /// security attributes is never served from an answer read off the
    /// announcement it replaced). Both only ever grow, so their sum does.
    ///
    /// `None` when discovery is gone: an answer resolved then would be filed
    /// under a generation that means nothing and could match a real one.
    #[cfg(feature = "security")]
    fn protection_epoch(&self) -> Option<u64> {
        let documents = self
            .security
            .as_ref()
            .map_or(0, |suite| suite.local_restriction_generation());
        let discovery = match &self.match_registry {
            Some(registry) => registry.discovery_generation()?,
            None => 0,
        };
        Some(documents.wrapping_add(discovery))
    }

    /// The discovery answer for `writer`, keeping apart a writer it does not
    /// hold (`None`: not announced yet, nothing to file) from one it holds
    /// and that announced no `PID_ENDPOINT_SECURITY_INFO` (`Some(None)`).
    #[cfg(feature = "security")]
    fn resolve_writer_security(
        &self,
        writer: &[u8; 16],
    ) -> Option<Option<crate::protocol::discovery::EndpointSecurityInfo>> {
        if let Some(registry) = &self.match_registry {
            return registry.resolve_writer_security_slot(&self.topic, writer);
        }
        self.security.as_ref().map(|suite| {
            crate::security::crypto::user_data::endpoint_security_info(suite, &self.topic).ok()
        })
    }

    /// Authenticate before decoding, sequence credit and coherent staging.
    ///
    /// The protection decision is made once, at the router
    /// (`router::route_payload_framing`), and can only turn a delivery into
    /// a drop here: a writer the router could not resolve is key-unknown
    /// whatever discovery says by now (its bytes were kept whole, so it is
    /// dropped unacknowledged and repaired), and bytes the router kept whole
    /// are never delivered as a plain sample. Otherwise the reader still
    /// runs its own `open_secured` to pick decrypt or MAC and the keys.
    #[cfg(feature = "security")]
    fn decrypt_if_secured(
        &self,
        writer_guid: &[u8; 16],
        remote_seq: u64,
        data: &[u8],
    ) -> SecuredIngest {
        use crate::engine::subscriber::PayloadFraming;
        let routed = crate::engine::router::route_payload_framing(writer_guid, remote_seq);
        if routed == Some(PayloadFraming::Unresolved) {
            return SecuredIngest::KeyUnknown;
        }
        match self.open_secured(writer_guid, remote_seq, data) {
            SecuredIngest::Plain if routed == Some(PayloadFraming::Sealed) => SecuredIngest::Drop,
            ingest => ingest,
        }
    }

    /// The reader's own reading of `data` against the writer's protection,
    /// for a sample the router did not frame (or framed as this reads it).
    #[cfg(feature = "security")]
    fn open_secured(&self, writer_guid: &[u8; 16], remote_seq: u64, data: &[u8]) -> SecuredIngest {
        use crate::security::crypto::user_data;
        let Some(slot) = self.writer_payload_security(writer_guid) else {
            // Nothing resolved this writer yet. With a suite, its key (or its
            // announcement) may still arrive: drop it unacknowledged so the
            // writer repairs it. Without one, nothing is ever protected.
            return if self.security.is_some() {
                SecuredIngest::KeyUnknown
            } else {
                SecuredIngest::Plain
            };
        };
        // A writer that is known and announced no payload protection speaks
        // in the clear; so does one that announced valid attributes without
        // the payload-protected flag. Neither is what a topic the governance
        // protects may carry (DDS-Security v1.1 Sec.9.4.1.2.7), so on such a
        // topic the sample is dropped rather than delivered unauthenticated.
        let Some(attributes) = slot.filter(|a| a.is_payload_protected()) else {
            return if self.topic_payload_protected() {
                SecuredIngest::Drop
            } else {
                SecuredIngest::Plain
            };
        };
        let expected = if attributes.is_payload_encrypted() {
            crate::security::crypto::secure_submessage::Transformation::Aes256Gcm
        } else {
            crate::security::crypto::secure_submessage::Transformation::Aes256Gmac
        };
        if data.len() < 40 || data[..4] != expected.kind() {
            self.cleartext_refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return SecuredIngest::Drop;
        }
        let Some(suite) = &self.security else {
            return SecuredIngest::Drop;
        };
        let Ok(id) = user_data::secured_payload_key_id(data) else {
            self.cleartext_refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return SecuredIngest::Drop;
        };
        let guid = crate::core::discovery::GUID::from_bytes(*writer_guid);
        let Some(material) = suite.data_keys.get_material(&guid, id) else {
            return SecuredIngest::KeyUnknown;
        };
        let encrypted = material.transformation
            == crate::security::crypto::secure_submessage::Transformation::Aes256Gcm;
        if encrypted != attributes.is_payload_encrypted() {
            return SecuredIngest::Drop;
        }
        match user_data::decode_serialized_payload(id, &material, data)
            .and_then(|p| user_data::serialized_body(&p))
        {
            Ok((body, version)) => SecuredIngest::Decrypted(body, version),
            Err(e) => {
                log::warn!("[READER-SUB] topic='{}': protected payload from writer={:02x?} seq={} failed to open: {}", self.topic, &writer_guid[..4], remote_seq, e);
                self.cleartext_refused
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                SecuredIngest::Drop
            }
        }
    }
    #[cfg(all(test, feature = "security"))]
    pub(super) fn decrypt_if_secured_for_test(
        &self,
        writer: &[u8; 16],
        seq: u64,
        data: &[u8],
    ) -> SecuredIngest {
        self.decrypt_if_secured(writer, seq, data)
    }
}

/// Outcome of the reader-side decrypt gate. See
/// [`ReaderSubscriber::decrypt_if_secured`].
#[cfg(feature = "security")]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub(super) enum SecuredIngest {
    Plain,
    Decrypted(Vec<u8>, crate::dds::CdrVersion),
    /// Its writer attributes or key have not arrived: dropped unacknowledged,
    /// the writer repairs it once discovery and key exchange complete. Owed to
    /// the reader if its writer sent it, but unauthenticated: it moves no
    /// join floor on its own (`ReorderGate::on_refused_unauthenticated`).
    KeyUnknown,
    /// Never decryptable here (no suite, malformed, failed to open):
    /// unauthenticated, it says nothing about where the writer's stream is.
    Drop,
}

impl<T: DDS> ReaderSubscriber<T> {
    /// Which matched writer holds this instance, if exactly one does.
    ///
    /// Ambiguity is reported as `None` rather than guessed: with two writers
    /// on one instance there is no single sequence stream to order against,
    /// and `None` makes the transition independent of the data around it,
    /// which is what DDS says about samples from different writers anyway.
    fn writer_of_instance(&self, key_hash: &[u8; 16]) -> Option<[u8; 16]> {
        self.writer_instances.lock().sole_holder(key_hash)
    }

    /// Queue one instance-state transition and wake whoever is waiting.
    fn queue_transition(
        &self,
        key_hash: [u8; 16],
        kind: DisposeKind,
        seq: u64,
        writer_guid: Option<[u8; 16]>,
        order_seq: u64,
        source_timestamp_ns: Option<u64>,
    ) {
        self.queue_transition_ordered(
            key_hash,
            kind,
            seq,
            writer_guid,
            order_seq,
            source_timestamp_ns,
            false,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn queue_transition_ordered(
        &self,
        key_hash: [u8; 16],
        kind: DisposeKind,
        seq: u64,
        writer_guid: Option<[u8; 16]>,
        order_seq: u64,
        source_timestamp_ns: Option<u64>,
        compound: bool,
    ) {
        self.dispose_events.push_ordered(
            DisposeEvent {
                key_hash,
                kind,
                seq,
                writer_guid,
                order_seq,
                announced: false,
                read: false,
                from_local_writer: false,
                disposed_generation_count: 0,
                no_writers_generation_count: 0, // overwritten by `push`
                source_timestamp_ns,
            },
            compound,
        );
        if let Some(guard) = &self.participant_guard {
            guard.set_trigger_value(true);
        }
    }

    /// Tests only: fill `writer_guid`'s record of missed runs as a reliable
    /// reader does that received a far sequence, then every other one
    /// below it, and return the next sequence the record refuses (`Full`).
    #[cfg(test)]
    pub(super) fn fill_missed_runs(&self, writer_guid: [u8; 16], from: u64) -> u64 {
        let mut map = self
            .seen_seqs_by_writer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let seen = map.entry(writer_guid).or_default();
        let bound = u64::try_from(SeenSeqs::MISSED_RUNS).expect("small");
        let far = from + SeenSeqs::WINDOW + 3 * bound;
        assert_eq!(seen.admit(far, Missed::All, || None), Seen::New);
        let mut seq = from + 1;
        while seen.missed.len() < SeenSeqs::MISSED_RUNS {
            assert_eq!(seen.admit(seq, Missed::All, || None), Seen::New);
            seq += 2;
        }
        assert_eq!(seen.judge(seq, Missed::All, || None), Seen::Full);
        seq
    }

    /// An END of a coherent set, from `on_coherent_end` (`marker_seq` is
    /// `None`: the END rode a sample) or `on_coherent_end_marker` (the END
    /// came as a standalone marker with its own sequence number).
    fn coherent_end(
        &self,
        writer_guid: [u8; 16],
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
        end_sn: Option<u64>,
        end_count: Option<u32>,
        marker_seq: Option<u64>,
    ) {
        let _delivering = super::notices::Delivering::enter();
        // A standalone END marker is a change of its own, with its own
        // sequence number (RTPS v2.5 Sec.8.7.5; e.g. sets 10..21, 23..34,
        // 36..47 with their markers at 22, 35 and 48): a reliable
        // reader acknowledges it like any change it received (Sec.8.4.12),
        // whatever it then does with it. Left unacknowledged, the writer
        // repairs it until it leaves the writer's history, for ever with
        // KEEP_ALL. A reader that does not read coherent sets takes it as a
        // change without a sample, like the ECS (`on_ecs`).
        if !self.coherent_cfg.coherent_access {
            if let Some(marker_seq) = marker_seq {
                crate::engine::Subscriber::on_writer_non_data(self, writer_guid, marker_seq);
            }
            return;
        }
        // GROUP scope: an HDDS-native ECS closes via on_ecs/close_group_set;
        // a GROUP set from a writer with vendor id 0x0101 may instead close
        // with a standalone end marker carrying PID_END_COHERENT_SET (0x8022 = the writer's
        // set-first SN) + PID_END_GROUP_COHERENT_SET (0x8023 = the group
        // set's first publisher-wide sample number, surfaced here as
        // `group_sn`) + PID_END_COHERENT_SET_SAMPLE_COUNT (0x8024), and
        // neither 0x0056 nor 0x0063. Route it
        // into the same close/flush machinery as the native path: this is
        // the writer's contribution-complete signal for the group set
        // identified by `group_sn`. Without it the samples staged by
        // stage_group_sample under (prefix, pub_eid, gsn) have no closing
        // event at all and pin the buffer forever, and the subscriber
        // delivers none of these sets.
        if self.coherent_cfg.is_group_scope && group_sn.is_some() && end_sn.is_some() {
            if let (Some(gsn), Some(set_first_sn)) = (group_sn, end_sn) {
                // The set occupies contiguous writer SNs
                // [set_first_sn .. set_first_sn + count - 1] and the
                // standalone marker burns the NEXT writer SN
                // (e.g. count 12: sets 10..21/23..34/36..47 with markers
                // at 22/35/48). Derive the per-writer ceiling
                // from the count; without a count, from the marker, which
                // follows its set; an END riding a sample has neither, and
                // every sample staged under this gsn key belongs to the set
                // (the key IS the set identity): the ceiling is unbounded.
                let ceiling = match (end_count, marker_seq) {
                    (Some(count), _) => set_first_sn
                        .saturating_add(u64::from(count))
                        .saturating_sub(1),
                    // A standalone marker comes right after its set.
                    (None, Some(marker)) => marker.saturating_sub(1),
                    (None, None) => u64::MAX,
                };
                self.close_group_set(
                    writer_guid,
                    marker_seq,
                    ceiling,
                    end_count,
                    gsn,
                    publisher_entity_id.unwrap_or([0; 4]),
                );
            }
            return;
        }
        if let Some(marker_seq) = marker_seq {
            let Some(receipt) = self.prepare_control_receipt(writer_guid, marker_seq) else {
                return;
            };
            let admitted = self
                .accept_best_effort_control(writer_guid, marker_seq)
                .unwrap_or_else(|| {
                    let mut map = match self.seen_seqs_by_writer.lock() {
                        Ok(lock) => lock,
                        Err(e) => e.into_inner(),
                    };
                    self.admit_seen(
                        map.entry(writer_guid).or_default(),
                        writer_guid,
                        marker_seq,
                        self.missed(),
                    )
                });
            match admitted {
                Seen::New => {
                    if !self.credit_control_receipt(writer_guid, marker_seq, &receipt) {
                        return;
                    }
                }
                // A repair of a marker already taken: it closed its set, and
                // closing again would leave behind an entry no sample fills.
                Seen::Duplicate => {
                    log::debug!(
                        "[READER-SUB] coherent END marker dup drop topic='{}' writer={:02x?} \
                         marker_seq={}",
                        self.topic,
                        &writer_guid[..4],
                        marker_seq
                    );
                    self.credit_control_receipt(writer_guid, marker_seq, &receipt);
                    return;
                }
                // A marker the record cannot take is refused like a sample,
                // unacknowledged: the writer sends it again, and it closes
                // its set then. Closing it now, unrecorded, would let that
                // copy close the set a second time, which leaves an entry
                // no sample fills.
                Seen::Full => return,
            }
        }
        if self.coherent_cfg.is_group_scope {
            if let Some(marker_seq) = marker_seq {
                self.step_gate_over(writer_guid, marker_seq);
            }
            return;
        }
        // TOPIC / INSTANCE access_scope: the END closes the set that starts
        // at `end_sn`. Its own sequence is a change of no set: it takes its
        // turn in the gate (and, for a reader with no gate, is recorded),
        // and with it the set's end is known; a sample count names that end
        // directly. The set commits once complete (`try_commit_sets`): an
        // END that overtook some of its own DATA waits for them. An END
        // that rides a sample (no marker, no count) closes what is staged
        // of its set.
        let counted = match (end_sn, end_count) {
            (Some(sn), Some(count)) => {
                Some((sn, sn.saturating_add(u64::from(count)).saturating_sub(1)))
            }
            (Some(sn), None) if marker_seq.is_none() => {
                let staged_last = self
                    .coherent_buffer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&writer_guid)
                    .and_then(|v| {
                        v.iter()
                            .filter(|s| s.coherent_sn == Some(sn))
                            .map(|s| s.remote_seq)
                            .max()
                    });
                staged_last.map(|last| (sn, last))
            }
            _ => None,
        };
        self.note_set_ends(writer_guid, None, marker_seq, counted);
        if let Some(marker_seq) = marker_seq {
            self.step_gate_over(writer_guid, marker_seq);
        }
        self.try_commit_sets(writer_guid, true);
    }

    /// The reorder gate takes `writer_guid`'s staged change `seq`, which
    /// delivers nothing (a sample of a discarded set): released as staged
    /// samples are (`ReorderGate::on_staged`), and what it held behind it
    /// delivered now.
    ///
    /// It is a sample lost (its set was discarded): reported, unless its
    /// set's discard reported it already (`note_reported`), as a staged
    /// member or one never received then.
    ///
    /// A writer that left meanwhile is given neither a fresh gate nor a
    /// fresh record here (a writer back under its GUID would find them);
    /// what its departure has not taken yet is used. The sample is reported
    /// lost all the same.
    fn step_gate_over_staged(&self, writer_guid: [u8; 16], seq: u64) {
        self.release_through_gate(writer_guid, |gate| {
            if self.has_left(&writer_guid) {
                return Vec::new();
            }
            gate.on_staged(writer_guid, seq, PendingPayload::nothing(seq))
        });
        let lost = {
            let mut map = self
                .seen_seqs_by_writer
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let record = if self.has_left(&writer_guid) {
                map.get_mut(&writer_guid)
            } else {
                Some(map.entry(writer_guid).or_default())
            };
            record.map_or(1, |record| {
                record.reported.report(seq, seq.saturating_add(1))
            })
        };
        self.report_sample_lost(lost);
    }

    /// `seqs` of `writer_guid`, staged members of a set discarded and
    /// reported lost, are recorded as reported: one that lands again is not
    /// reported twice. Only a writer's departure takes such a member back
    /// from its record (`on_writer_dispose`), so that its writer, back,
    /// sends it again; any other discard leaves it received, and a copy is
    /// a duplicate.
    fn note_reported(&self, writer_guid: [u8; 16], seqs: impl IntoIterator<Item = u64>) {
        let mut map = self
            .seen_seqs_by_writer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // A writer that left keeps the record its departure has not taken
        // yet, and is given no fresh one (`step_gate_over_staged`).
        let record = if self.has_left(&writer_guid) {
            match map.get_mut(&writer_guid) {
                Some(record) => record,
                None => return,
            }
        } else {
            map.entry(writer_guid).or_default()
        };
        for seq in seqs {
            let _ = record.reported.report(seq, seq.saturating_add(1));
        }
    }

    /// The reorder gate takes change `seq` of `writer_guid`, which
    /// delivers nothing (an end-of-set marker): it moves over it once it
    /// reaches it, and what it held behind it is delivered now.
    fn step_gate_over(&self, writer_guid: [u8; 16], seq: u64) {
        self.release_through_gate(writer_guid, |gate| gate.on_non_data(writer_guid, seq));
    }
}

impl<T: DDS> Drop for ReaderSubscriber<T> {
    fn drop(&mut self) {
        // Safety valve: deactivate this reader's barrier slot so a
        // torn-down coherent reader cannot stall its peers waiting for a
        // set it will never send (see coherent_barrier::forget_member).
        if let (Some(barrier), Some(member)) = (self.coherent_barrier.as_ref(), self.barrier_member)
        {
            barrier.forget_member(member);
        }
    }
}

impl<T: DDS> ReaderSubscriber<T> {
    /// The instance transition a dispose or unregister of `writer_guid`
    /// (change `seq`) makes, if it makes one.
    /// `source_timestamp_ns`: the change's source timestamp, for the
    /// `SampleInfo` of the NOT_ALIVE transition it queues
    /// (`DisposeEvent::source_timestamp_ns`). A synchronous caller reads it
    /// fresh (`crate::engine::router::route_source_ts_ns()`, set for the
    /// datagram currently being routed); a caller flushing a coherent
    /// member staged earlier (`process_admitted`'s `deferred` path) passes
    /// the value captured AT STAGING time instead -- by the time a staged
    /// member's set commits, the thread-local reflects whichever OTHER
    /// datagram is being routed now, not this change's own.
    fn apply_lifecycle(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        key_hash: [u8; 16],
        kind: DisposeKind,
        source_timestamp_ns: Option<u64>,
    ) {
        self.apply_lifecycle_ordered(writer_guid, seq, key_hash, kind, source_timestamp_ns, false);
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_lifecycle_ordered(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        key_hash: [u8; 16],
        kind: DisposeKind,
        source_timestamp_ns: Option<u64>,
        compound: bool,
    ) {
        // An unregister releases the instance for its sender only, a
        // dispose registers it, and under EXCLUSIVE ownership only the
        // owner's dispose moves the instance (`admit_lifecycle`). A writer
        // still holding the instance - another one, or the sender itself
        // through a sample it sent after this unregister - keeps it ALIVE:
        // no transition, so no notification and no new generation when that
        // writer writes again.
        let moves = self
            .writer_instances
            .admit_lifecycle(writer_guid, key_hash, seq, kind);
        if !moves {
            log::debug!(
                "[READER-SUB] {:?} topic='{}' writer={:02x?} key_hash={:02x?}: \
                 the instance's state does not move (a writer still holds it, \
                 or the sender does not own it)",
                kind,
                self.topic,
                &writer_guid[..4],
                &key_hash[..4]
            );
            return;
        }
        self.queue_transition_ordered(
            key_hash,
            kind,
            seq,
            Some(writer_guid),
            seq,
            source_timestamp_ns,
            compound,
        );
    }

    /// A coherent set's member `seq` of `writer_guid` (its set starting at
    /// `set_start`), refused unacknowledged before staging: the writer sends
    /// it again, so it is owed. A gate seeded by the first DATA (VOLATILE)
    /// takes the start of its set as the join floor, as for a staged member
    /// (`ReorderGate::observe`), and waits for the member itself
    /// (`ReorderGate::on_refused`): the writer's later changes are held
    /// until the repaired set commits. With the floor only, a plain DATA
    /// that came before the repair seeded the gate above the member: the
    /// gate passed it, its set could never be whole and was discarded, the
    /// repair with it, acknowledged.
    fn join_at_refused_member(&self, writer_guid: [u8; 16], seq: u64, set_start: Option<u64>) {
        let mut gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
        if !gate.is_best_effort() {
            gate.observe(writer_guid, seq, set_start);
            gate.on_refused(writer_guid, seq);
        }
    }

    /// `seq` of `writer_guid` (from `set_start` for a coherent set's
    /// member), dropped unacknowledged while discovery does not hold its
    /// writer: owed once the writer is discovered
    /// (`ReorderGate::on_dropped_undiscovered`).
    fn owe_dropped_before_discovery(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        set_start: Option<u64>,
    ) {
        self.reorder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .on_dropped_undiscovered(writer_guid, seq, set_start);
        self.recheck_discovered(&writer_guid);
    }

    /// After a DATA of a writer found undiscovered was filed as owed: the
    /// writer's announcement may have been taken since, its hook
    /// (`on_writer_qos_resolved`) run before the filing, which then counted
    /// a discovered writer among the states forgotten first. Discovery
    /// records the writer before it runs the hook, so one of the two sees
    /// the other.
    fn recheck_discovered(&self, writer_guid: &[u8; 16]) {
        if !self.writer_undiscovered(writer_guid) {
            self.reorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .writer_discovered(writer_guid);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn receive_writer(
        &self,
        _topic: &str,
        writer_guid: [u8; 16],
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        key_hash: Option<[u8; 16]>,
    ) {
        #[cfg(test)]
        let _arrival = self.group_arrival_scope(writer_guid, Some(remote_seq));
        if self.wire_context_pending(writer_guid, remote_seq, None) {
            return;
        }
        // A write, dispose or unregister asserts a MANUAL writer's
        // liveliness (RTPS v2.5 Sec.8.7.2.2).
        if let Some(ref liveliness) = self.liveliness {
            liveliness.on_data(&writer_guid);
        }
        // Read before the door: a departure past it moves the count, and the
        // delivery looks the writer up again under the gate (`Admit::Direct`).
        let epoch = self.departures.load(std::sync::atomic::Ordering::Acquire);
        if self.has_left(&writer_guid) {
            return;
        }
        // DDS Security v1.1 Sec.8.8.2.2, 8.8.7.1, 9.4.3: the data of a writer
        // the security plugins do not admit (`writer_not_admitted`), before
        // anything reads it: not decrypted, no reception bookkeeping.
        #[cfg(feature = "security")]
        if self.writer_not_admitted(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping writer={:02x?} topic='{}' seq={}: the security plugins \
                 do not admit it",
                &writer_guid[..4],
                self.topic,
                remote_seq
            );
            return;
        }
        // DDS-Security decrypt gate, FIRST: everything downstream of this
        // point (drop gates, ownership deferral, reorder buffering, coherent
        // staging via the non-coherent fallthrough) stores or inspects the
        // payload, and all of it must see plaintext. Crucially this runs
        // BEFORE any reception bookkeeping: a sample we cannot decrypt yet
        // (key still in flight on the volatile channel) is dropped WITHOUT
        // crediting its sequence number, so the reliable reader keeps NACKing
        // it and the writer's repair -- ciphertext from the history cache --
        // arrives after the key does. Crediting first would burn the SN and
        // lose the sample forever.
        #[cfg(feature = "security")]
        let mut version = version;
        #[cfg(feature = "security")]
        let decrypted_holder: Vec<u8>;
        #[cfg(feature = "security")]
        let data: &[u8] = match self.decrypt_if_secured(&writer_guid, remote_seq, data) {
            SecuredIngest::Plain => data,
            SecuredIngest::Decrypted(bytes, decoded_version) => {
                version = decoded_version;
                decrypted_holder = bytes;
                &decrypted_holder
            }
            SecuredIngest::KeyUnknown => {
                // Owed if its writer sent it, but unauthenticated: a
                // VOLATILE reader joins its writer there only once an
                // authenticated sample at or above it vouches for it, so
                // that the samples decrypted after the key wait for its
                // repair (`ReorderGate::on_refused_unauthenticated`).
                // Filed for a writer discovery does not hold yet too (its
                // DATA can come before its announcement), within a bound:
                // a GUID nobody announced never departs.
                let discovered = !self.writer_undiscovered(&writer_guid);
                self.reorder
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .on_refused_unauthenticated(writer_guid, remote_seq, None, discovered);
                if !discovered {
                    self.recheck_discovered(&writer_guid);
                }
                return;
            }
            SecuredIngest::Drop => return,
        };

        #[cfg(test)]
        {
            let hook = self
                .pair_gate_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
        // The pair gate (`writer_refused`): drop samples from a writer
        // whose type or QoS this reader's verdict refuses, before any
        // reception bookkeeping (no ACKNACK high-water advance, no reorder,
        // no application delivery).
        if self.writer_refused(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping refused (type or QoS) writer={:02x?} topic='{}' seq={}",
                &writer_guid[..4],
                self.topic,
                remote_seq
            );
            return;
        }
        // PARTITION RxO data-plane gate (DDS v1.4 Sec.2.2.3.13): drop samples from
        // a writer whose partition intersects no local reader on this topic.
        // HDDS routes DATA by topic name, so the writer's multicast reaches this
        // reader even though the matcher reported no match.
        if self.writer_partition_incompatible(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping partition-incompatible writer={:02x?} topic='{}' seq={}",
                &writer_guid[..4],
                self.topic,
                remote_seq
            );
            // Outside the default partition, the DATA of a writer discovery
            // does not hold yet is dropped here, its partition unknown: the
            // writer sends it again once it is discovered, and it is owed
            // (`ReorderGate::on_dropped_undiscovered`).
            if self.writer_undiscovered(&writer_guid) {
                self.owe_dropped_before_discovery(writer_guid, remote_seq, None);
            }
            return;
        }
        // DataRepresentation RxO data-plane gate (DDS-XTypes v1.3 Sec.7.6.3.1.2):
        // drop samples whose wire CDR version is not in this reader's explicit
        // accepted representation set, before any reception bookkeeping. An
        // `-x 2` reader rejecting an XCDR1 writer (and vice versa) must not
        // deliver the sample; the on_requested_incompatible_qos notification is
        // raised independently by the match-notification path.
        if self.data_repr_incompatible(version) {
            log::debug!(
                "[READER-SUB] dropping data-rep-incompatible sample writer={:02x?} topic='{}' seq={} version={:?} accepted={:?}",
                &writer_guid[..4],
                self.topic,
                remote_seq,
                version,
                self.accepted_data_repr
            );
            return;
        }
        let captured = T::capture_wire_data(data, key_hash);
        let data = captured.as_ref();

        // OWNERSHIP RxO data-plane gate (DDS v1.4 Sec.2.2.3.11), tri-state --
        // see `ownership_gate` for why this gate (not just the notification,
        // and not just the router-level block_writer check) is required to
        // close the race regardless of local-reader-vs-remote-SEDP
        // registration order. Runs LAST among the drop gates so a deferred
        // sample has already cleared every per-sample check and its flush
        // only needs the duplicate admit.
        let incarnation = match self.ownership_gate(&writer_guid) {
            OwnershipGate::Deliver => {
                // Flush anything deferred while this writer was unresolved
                // BEFORE the current sample, including a batch being
                // admitted on the discovery thread (RTPS 2.5 8.4.12.1 T2).
                match self.flush_ownership_pending(writer_guid, Some((remote_seq, data, version))) {
                    Some(incarnation) => incarnation,
                    None => return,
                }
            }
            OwnershipGate::Reject => {
                self.discard_ownership_pending(writer_guid);
                log::debug!(
                    "[READER-SUB] dropping ownership-incompatible writer={:02x?} topic='{}' seq={}",
                    &writer_guid[..4],
                    self.topic,
                    remote_seq
                );
                return;
            }
            OwnershipGate::Unresolved => {
                // Both this enqueue and SEDP's resolution flag use the
                // same mutex: either the callback takes this sample, or
                // this enqueue sees that callback's flag and flushes it.
                // This also covers BEST_EFFORT and refused pairings.
                if self.defer_ownership_pending(writer_guid, remote_seq, data, version) {
                    self.flush_resolved_ownership_pending(writer_guid);
                }
                return;
            }
        };

        self.receive_resolved(
            writer_guid,
            remote_seq,
            data,
            version,
            Admit::Direct(epoch, &incarnation),
        );
    }

    /// Finish a live DATA after the discovery gate, including when it was
    /// queued behind a flush. Keep its coherent-set and departure checks.
    fn receive_resolved(
        &self,
        writer_guid: [u8; 16],
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        admit: Admit<'_>,
    ) {
        if self.coherent_cfg.coherent_access {
            // A DATA with no coherent-set inline QoS closes the set staged
            // before it, if any (RTPS v2.5 Sec.8.7.6): the set commits
            // before the DATA is delivered. A best-effort gate passes the
            // DATA at once, and committed after it the set reached the
            // application behind the change that followed it.
            self.note_set_ends(writer_guid, None, Some(remote_seq), None);
            self.try_commit_sets(writer_guid, false);
            self.admit_and_deliver(writer_guid, remote_seq, data, version, admit);
            // A best-effort set it closed that waited for a member its end
            // overtook (`try_commit_sets`): the gate passed it now, the set
            // can never be whole.
            if self.ack_credit.is_none()
                && self
                    .best_effort_waiting
                    .load(std::sync::atomic::Ordering::Acquire)
                    != 0
            {
                self.try_commit_sets(writer_guid, false);
            }
            self.discard_group_sets_behind(writer_guid, remote_seq);
            // A set of this writer waiting for its gate (`try_commit_sets`)
            // may be deliverable now.
            if self.forget_wait_on_gate(&writer_guid) {
                self.try_commit_sets(writer_guid, false);
            }
            // A GROUP set waiting for a writer's gate to reach its part
            // (`try_flush_group_sets`) may be deliverable now.
            if self
                .group_sets_await_gate
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                self.try_flush_group_sets();
            }
            return;
        }
        self.admit_and_deliver(writer_guid, remote_seq, data, version, admit);
    }

    /// A change of a coherent set from `writer_guid`, staged until its set
    /// commits (`try_commit_sets`, `try_flush_group_sets`): a sample
    /// (`data`), or a dispose or unregister of the set (`lifecycle`, the
    /// instance key and kind, no sample: `on_lifecycle_coherent`). `tags` is
    /// (PID_COHERENT_SET, the group set number, PID_GROUP_ENTITY_ID).
    #[allow(clippy::too_many_arguments)]
    fn stage_coherent_change(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        tags: (Option<u64>, Option<u64>, Option<[u8; 4]>),
        lifecycle: Option<([u8; 16], DisposeKind)>,
        key_hash: Option<[u8; 16]>,
    ) {
        #[cfg(test)]
        let _arrival = self.group_arrival_scope(writer_guid, Some(seq));
        let _delivering = super::notices::Delivering::enter();
        if self.wire_context_pending(writer_guid, seq, tags.0) {
            return;
        }
        let (coherent_sn, group_sn, publisher_entity_id) = tags;
        // Epoch precedes decryption/capture: the terminal discard must not
        // credit a replacement writer under the same GUID.
        let ordered_epoch = self
            .capture_wire_order(writer_guid, seq)
            .map(|_| self.departures.load(std::sync::atomic::Ordering::Acquire));
        // The ordinary receive path performs authentication itself. Forward
        // the original protected bytes, so this leg never decrypts twice.
        if lifecycle.is_none()
            && (!self.coherent_cfg.coherent_access || (coherent_sn.is_none() && group_sn.is_none()))
        {
            self.receive_writer(topic, writer_guid, seq, data, version, key_hash);
            return;
        }

        if self.has_left(&writer_guid) {
            return;
        }
        // DDS Security v1.1 Sec.8.8.7.1, 9.4.3 (as on_data_with_writer), before
        // anything reads the change: not even decrypted for a writer refused.
        #[cfg(feature = "security")]
        if self.writer_not_admitted(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping coherent writer={:02x?} topic='{}' seq={}: the \
                 security plugins do not admit it",
                &writer_guid[..4],
                self.topic,
                seq
            );
            return;
        }
        // DDS-Security decrypt gate, FIRST -- same contract as
        // `on_data_with_writer`, duplicated here because coherent staging
        // buffers the payload and later flushes it through
        // `deliver_admitted_sample` directly, bypassing that entry point.
        // Buffering ciphertext would deliver ciphertext.
        #[cfg(feature = "security")]
        let mut version = version;
        #[cfg(feature = "security")]
        let decrypted_holder: Vec<u8>;
        #[cfg(feature = "security")]
        let data: &[u8] = match if lifecycle.is_some() {
            // No payload: the key travels in PID_KEY_HASH.
            SecuredIngest::Plain
        } else {
            self.decrypt_if_secured(&writer_guid, seq, data)
        } {
            SecuredIngest::Plain => data,
            SecuredIngest::Decrypted(bytes, decoded_version) => {
                version = decoded_version;
                decrypted_holder = bytes;
                &decrypted_holder
            }
            SecuredIngest::KeyUnknown => {
                // Owed if its writer sent it, as a sample refused at staging
                // is, but unauthenticated: it seeds nothing on its own
                // (`ReorderGate::on_refused_unauthenticated`), bounded for a
                // writer discovery does not hold yet, as in `receive_writer`.
                let discovered = !self.writer_undiscovered(&writer_guid);
                self.reorder
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .on_refused_unauthenticated(writer_guid, seq, coherent_sn, discovered);
                if !discovered {
                    self.recheck_discovered(&writer_guid);
                }
                return;
            }
            SecuredIngest::Drop => return,
        };

        // The pair gate (`writer_refused`, type or QoS), applied before any
        // coherent staging so a refused writer's samples never enter the
        // coherent/group buffers.
        if self.writer_refused(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping refused (type or QoS) coherent writer={:02x?} topic='{}' seq={}",
                &writer_guid[..4],
                self.topic,
                seq
            );
            return;
        }
        // Matched-writer-proxy gate (RTPS v2.5 sec. 8.4.15; DDS v1.4 sec. 2.2.2.5.x):
        // a writer this participant has never discovered via SEDP has no
        // matched writer proxy at all, so none of its samples may be staged,
        // let alone revive an instance this reader already saw NOT_ALIVE.
        // `on_data_with_writer` gets the same protection for free from
        // `ownership_gate`'s resolve-or-defer (an undiscovered writer is
        // `Unresolved`, so its sample is held, never pushed to the cache),
        // but coherent staging commits straight to the cache without ever
        // consulting that gate, and `writer_partition_incompatible` permits
        // unresolved DATA for a default-partition reader -- the combination
        // (default partition, coherent access) nothing else here closes.
        if self.writer_undiscovered(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping coherent change from undiscovered writer={:02x?} topic='{}' seq={}",
                &writer_guid[..4],
                self.topic,
                seq
            );
            // A writer that has discovered this reader sends it DATA before
            // this reader has discovered the writer: dropped unacknowledged,
            // it is sent again, and owed
            // (`ReorderGate::on_dropped_undiscovered`).
            self.owe_dropped_before_discovery(writer_guid, seq, coherent_sn);
            return;
        }
        // PARTITION RxO data-plane gate (DDS v1.4 sec. 2.2.3.13), applied before any
        // coherent staging so a partition-mismatched writer's samples never
        // enter the coherent/group buffers (same rule as on_data_with_writer).
        if self.writer_partition_incompatible(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping partition-incompatible coherent writer={:02x?} topic='{}' seq={}",
                &writer_guid[..4],
                self.topic,
                seq
            );
            return;
        }
        // DataRepresentation RxO data-plane gate (DDS-XTypes v1.3 sec. 7.6.3.1.2),
        // applied before any coherent staging so an incompatible writer's
        // samples never enter the coherent/group buffers (same rule as the
        // non-coherent path in on_data_with_writer).
        if lifecycle.is_none() && self.data_repr_incompatible(version) {
            log::debug!(
                "[READER-SUB] dropping data-rep-incompatible coherent sample writer={:02x?} topic='{}' seq={} version={:?}",
                &writer_guid[..4],
                self.topic,
                seq,
                version
            );
            return;
        }
        let lifecycle_receipt = if lifecycle.is_some() {
            let Some(receipt) = self.prepare_control_receipt(writer_guid, seq) else {
                return;
            };
            Some(receipt)
        } else {
            None
        };
        let captured = T::capture_wire_data(data, key_hash);
        let data = captured.as_ref();

        let ordered_incarnation = if let Some(epoch) = ordered_epoch {
            let mut pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.departures.load(Ordering::Acquire) != epoch || self.has_left(&writer_guid) {
                return;
            }
            Some(pending.incarnation(writer_guid))
        } else {
            None
        };
        let lost_unit = self
            .capture_wire_order(writer_guid, seq)
            .and_then(|change| {
                let first = group_sn.filter(|&first| first >= 1 && first <= change.gsn)?;
                let (barrier, member) = self.coherent_barrier.as_ref().zip(self.barrier_member)?;
                barrier
                    .wire_unit_lost(change.publisher, first)
                    .then_some((change, first, member))
            });
        if let Some((change, first, member)) = lost_unit {
            let Some(epoch) = ordered_epoch else { return };
            let Some(incarnation) = ordered_incarnation.as_ref() else {
                return;
            };
            let lost = if lifecycle.is_none() && self.stale_data_is_relevant(data, version) {
                let mut seen = self
                    .seen_seqs_by_writer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if self.judge_seen(
                    seen.entry(writer_guid).or_default(),
                    writer_guid,
                    seq,
                    self.missed(),
                ) == Seen::Duplicate
                {
                    0
                } else {
                    let count = self
                        .wire_loss_ledger(writer_guid, Some(incarnation.as_ref()))
                        .and_then(|ledger| ledger.try_record(seq));
                    let Some(count) = count else { return };
                    count
                }
            } else {
                let ticket = self
                    .wire_loss_ledger(writer_guid, Some(incarnation.as_ref()))
                    .and_then(|ledger| ledger.claim(seq, true));
                let Some(ticket) = ticket else { return };
                ticket.mark_delivered();
                0
            };
            // A valid fresh event can revoke an older availability proof.
            // Its terminal unit disposition is already independently proven.
            let _ = self.apply_group_arrival(writer_guid, Some(incarnation.as_ref()));
            if let Some(barrier) = &self.coherent_barrier {
                barrier.wire_discarded_copy(member, change);
                barrier.deposit(
                    member,
                    change.publisher,
                    CoherentSet::spec_part(Vec::new(), first, true),
                );
            }
            let _order = crate::engine::router::OrderedGroupScope::suppress(writer_guid, seq);
            self.deliver_prepared(
                writer_guid,
                seq,
                version,
                Admit::Direct(epoch, incarnation),
                Ok(super::admission::Prepared::Discard),
            );
            self.report_sample_lost(lost);
            return;
        }

        let stale_order = self.capture_wire_order(writer_guid, seq).filter(|change| {
            self.coherent_barrier
                .as_ref()
                .zip(self.barrier_member)
                .is_some_and(|(barrier, member)| barrier.wire_is_stale(*change, member))
        });
        let coherent_repair =
            stale_order.and_then(|change| self.coherent_history_repair(change, group_sn));
        if stale_order.is_some() && coherent_repair.is_none() {
            // A stale Publisher prefix is already settled for this member,
            // even if this writer SN is new. Consume it without staging,
            // resource refusal or a transition from the discarded sample.
            let Some(epoch) = ordered_epoch else { return };
            let incarnation = {
                let pending = self
                    .ownership_pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if self.departures.load(std::sync::atomic::Ordering::Acquire) != epoch
                    || self.has_left(&writer_guid)
                {
                    return;
                }
                let Some(incarnation) = ordered_incarnation.as_ref() else {
                    return;
                };
                if !pending
                    .incarnations
                    .get(&writer_guid)
                    .is_some_and(|current| Arc::ptr_eq(current, incarnation))
                {
                    return;
                }
                incarnation.clone()
            };
            let lost = if lifecycle.is_none() && self.stale_data_is_relevant(data, version) {
                let mut records = self
                    .seen_seqs_by_writer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let record = records.entry(writer_guid).or_default();
                if self.judge_seen(record, writer_guid, seq, self.missed()) == Seen::Duplicate {
                    0
                } else {
                    let count = self
                        .wire_loss_ledger(writer_guid, Some(incarnation.as_ref()))
                        .and_then(|ledger| ledger.try_record(seq));
                    let Some(count) = count else { return };
                    count
                }
            } else {
                0
            };
            self.deliver_prepared(
                writer_guid,
                seq,
                version,
                Admit::Direct(epoch, &incarnation),
                Ok(super::admission::Prepared::Discard),
            );
            self.report_sample_lost(lost);
            return;
        }

        let _admission = if self.ack_credit.is_some() {
            let key = (writer_guid, seq);
            if !self
                .coherent_admissions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key)
            {
                return;
            }
            Some(CoherentAdmission {
                pending: &self.coherent_admissions,
                key,
            })
        } else {
            None
        };

        // De-dup against the per-writer admission window so a coherent
        // sample that arrives twice (retransmit interleaved with the
        // ECS path) is staged only once.
        #[cfg(test)]
        if let Some(hook) = self
            .admission_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            hook();
        }
        let best_effort = self
            .reorder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_best_effort();
        {
            let mut map = match self.seen_seqs_by_writer.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            // The writer left since this DATA passed the door: its record
            // went under this lock (`on_writer_dispose`), and a fresh one
            // opened now is one the departure never saw.
            if self.has_left(&writer_guid) {
                return;
            }
            let seen = map.entry(writer_guid).or_default();
            // Keep holes until the gate observes this staged DATA. A
            // large jump must not erase them before SAMPLE_LOST counts it.
            let missed = if best_effort {
                Missed::All
            } else {
                self.missed()
            };
            let verdict = self.admit_seen(seen, writer_guid, seq, missed);
            if verdict == Seen::Full {
                // Unrecorded, unacknowledged: the writer sends it again.
                // Owed: the gate's lock is taken with the record's
                // released.
                drop(map);
                self.join_at_refused_member(writer_guid, seq, coherent_sn);
                return;
            }
            if verdict == Seen::Duplicate {
                log::debug!(
                    "[READER-SUB] coherent dup drop topic='{}' writer={:02x?} seq={}",
                    self.topic,
                    &writer_guid[..4],
                    seq
                );
                // This arrival owns the provisional guard. Any competing
                // unfinished DATA returned before judging the duplicate,
                // so this bit belongs to an earlier completed admission.
                drop(map);
                self.credit_receipt(writer_guid, seq);
                return;
            }
        }

        // A reliable gate already past it: delivered once (the record above
        // would have said duplicate), or stepped over, its writer having
        // given it up (a HEARTBEAT's firstSN, a GAP), and reported lost.
        // Received late, it is no change to deliver: staged, its set reached
        // the application behind the later changes the gate let through,
        // out of order (DDS v1.4 Sec.2.2.3.14). Credited, as a duplicate is.
        // A sample staged before the gate passed it is another matter:
        // released as received (`ReorderGate::on_staged`).
        if self.ack_credit.is_some() {
            let passed = {
                let gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
                !gate.is_best_effort() && gate.next_seq(&writer_guid).is_some_and(|next| seq < next)
            };
            if passed {
                log::debug!(
                    "[READER-SUB] coherent change below the gate dropped topic='{}' \
                     writer={:02x?} seq={}",
                    self.topic,
                    &writer_guid[..4],
                    seq
                );
                self.credit_receipt(writer_guid, seq);
                return;
            }
        }

        // Credit reliable receipt for coherent DATA, exactly as the
        // non-coherent path does (on_data_with_writer): advance the
        // WriterProxy so the ACKNACK base/bitmap reflects what we actually
        // received (RTPS v2.5 Sec.8.4.12). Coherent samples are staged
        // out-of-band below (coherent_buffer / group_coherent_buffer) and
        // would otherwise never be credited. Every writer, HDDS included:
        // leaving an HDDS writer's coherent samples uncredited would go
        // unseen only while the writer never learned acknowledgements over
        // UDP; once it does, a TRANSIENT_LOCAL coherent writer would wait on
        // sets its reader never acknowledged.
        //
        // An HDDS writer's sample with no GSN under GROUP scope is not
        // staged: it is passed straight through (see below), and that
        // delivery credits it once it has its storage and its slot in the
        // reader's history. Credited here first, it could be refused after its
        // acknowledgement and never sent again.
        let passed_through = self.coherent_cfg.is_group_scope
            && group_sn.is_none()
            && crate::engine::router::route_writer_is_hdds();
        // What a staged sample is staged with: set below, once it is known
        // to be staged.
        let mut prepared: Option<super::admission::Prepared> = None;
        let mut order_token: Option<super::wire_order::OrderToken> = None;
        // The set it is staged in, when it is.
        let mut staged_in: Option<StagedSet> = None;
        // Its charge on the reader's staging budget, once admitted.
        let mut charge: Option<super::staging_budget::StagedCharge> = None;
        if !passed_through {
            let staged_set = match group_sn.filter(|_| self.coherent_cfg.is_group_scope) {
                Some(gsn) => {
                    let prefix: [u8; 12] = writer_guid[..12].try_into().unwrap_or([0; 12]);
                    StagedSet::Group((prefix, publisher_entity_id.unwrap_or([0; 4]), gsn))
                }
                None => StagedSet::Writer(writer_guid, coherent_sn.unwrap_or(seq)),
            };
            staged_in = Some(staged_set);
            if self.ack_credit.is_some() && self.wire_bindings.is_some() {
                if let Some(((change, barrier), member)) = self
                    .capture_wire_order(writer_guid, seq)
                    .zip(self.coherent_barrier.as_ref())
                    .zip(self.barrier_member)
                {
                    if !barrier.wire_may_stage_unit(
                        writer_guid,
                        change,
                        member,
                        group_sn.unwrap_or(change.gsn),
                    ) {
                        self.join_at_refused_member(writer_guid, seq, coherent_sn);
                        self.refuse_unacknowledged(writer_guid, seq, true, Refusal::Backlog, None);
                        return;
                    }
                }
            }
            // A change of a set rejected for its storage (`reject_staged_set`):
            // no storage, no staging entry, one lookup. Staged, a set that
            // never closed grew one entry per member for good.
            if self.set_rejected(staged_set) {
                self.rejected_member_lands(
                    writer_guid,
                    seq,
                    coherent_sn,
                    staged_set,
                    lifecycle.is_none(),
                );
                return;
            }
            // Staged, it takes its place only when its set commits, and
            // cannot be refused then: while another writer's gap is open,
            // it is staged only if it leaves that gap its places.
            // In order (`staged_in_order`): its set is the earliest of its
            // writer's still to come, which every later set waits for.
            let in_order = self.staged_in_order(writer_guid, seq, staged_set, coherent_sn);
            // A writer's staging is bounded: a misbehaving publisher (or a
            // lost end of set) would otherwise grow it until the host runs
            // out of memory. At the bound a change is refused,
            // unacknowledged: dropping the oldest staged change instead
            // lost it, acknowledged, and its set could never be whole again.
            // Except a change of the writer's set in order, known so (the
            // gate has its baseline): refused for the bound the sets above
            // it hold, it was refused for good, and they waited for it. That
            // set is one at a time and counts at most `N` members
            // (`staging_budget`): a writer stages at most
            // `MAX_STAGED_PER_WRITER` changes and `N` more. A change merely
            // below one staged is no such exception: a peer staged one
            // change high, then any number below it.
            let head = in_order == Some(true);
            let mut group_refused = false;
            let full = match staged_set {
                StagedSet::Writer(..) => {
                    !head
                        && self
                            .coherent_buffer
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&writer_guid)
                            .is_some_and(|staged| staged.len() >= MAX_STAGED_PER_WRITER)
                }
                // A GROUP set is bounded likewise; at the bound it used to
                // be discarded whole, its samples acknowledged, unreported.
                // And so are the sets a writer opens: one more than
                // `MAX_OPEN_GROUP_SETS_PER_WRITER` is refused, but its set
                // in order's.
                StagedSet::Group(key) => {
                    self.retire_passed_group_announcers(writer_guid);
                    let routed_spec = crate::engine::router::route_group_is_spec(writer_guid, seq);
                    let spec = routed_spec.unwrap_or_else(|| {
                        self.topic_registry
                            .as_ref()
                            .is_some_and(|registry| registry.writer_speaks_spec_group(&writer_guid))
                    });
                    // RTPS v2.5 Sec.9.6.4.5 requires writer-group info
                    // on each DATA and the first DATA_FRAG of this class.
                    let inline_missing = routed_spec == Some(true)
                        && crate::engine::router::route_group_writer_set(writer_guid, seq)
                            .is_none();
                    let mut buf = self
                        .group_coherent_buffer
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let set = buf.get(&key);
                    let discarded = self.group_set_discarded(&key);
                    // A Dust DDS writer (`SpecReceive`) sends no PID_WRITER_GROUP_INFO
                    // on its members, only on the end of its part: its members
                    // are staged without it, and the set's writer set comes with
                    // that end (`router`, `extract_group_end_without_coherent_set`).
                    let spec_receive =
                        crate::engine::router::route_group_is_spec_receive(writer_guid, seq);
                    let missing_metadata = spec
                        && !spec_receive
                        && (inline_missing
                            || !set.is_some_and(|set| {
                                set.writer_set.is_some()
                                    && set.announcers.contains_key(&writer_guid)
                            }));
                    group_refused = !discarded
                        && (missing_metadata
                            || !Self::group_part_has_room(&buf, &key, &writer_guid, head));
                    let full = group_refused
                        || set.is_some_and(|set| set.total_samples() >= MAX_STAGED_PER_GROUP);
                    if !full && !discarded {
                        // Reserve under the counting lock before storage or
                        // receipt. Another DATA cannot race past the bound,
                        // and a refused part still has its known first SN.
                        let set = buf.entry(key).or_default();
                        set.per_writer.entry(writer_guid).or_default();
                        let first = coherent_sn.unwrap_or(seq).min(seq);
                        let known = set.announcers.entry(writer_guid).or_default();
                        *known = Some(known.map_or((first, seq), |(known, last)| {
                            (known.min(first), last.max(seq))
                        }));
                    }
                    full
                }
            };
            // A member of a set at the samples a set may stage rejects its
            // set (`staging_budget`) and is staged under it no more: refused
            // at the bound instead, it was refused for good, its set no
            // smaller when it is resent. A member that would take an entry
            // finds the bound applied, always.
            let full = group_refused || (full && !self.staging.set_is_full(&staged_set));
            if full {
                log::warn!(
                    "[READER-SUB] coherent staging full topic='{}' writer={:02x?} cap={} \
                     seq={} refused (likely lost end of set or runaway publisher)",
                    self.topic,
                    &writer_guid[..4],
                    MAX_STAGED_PER_WRITER,
                    seq
                );
            }
            // Staged, the change is acknowledged long before its set
            // commits: its storage is taken now, before its credit (RTPS
            // v2.5 Sec.8.4.12.2, T8), and kept until the commit (and the
            // gate) give it up. Stored only at the commit, it found none
            // there and was lost, or stored past the pool's ceiling.
            //
            // Staged storage is this reader's own: apart from the slab
            // pool's tiers, charged to the reader's staging budget, which no
            // other reader and no writer shares (`staging_budget` states
            // the rule and why one reader never waits on itself for good).
            // Every change staged is charged, its entry at least (a dispose
            // or unregister of the set, a sample with no storage). A
            // change the budget has no room for now is refused
            // unacknowledged, and its writer sends it again. A set that
            // alone would take more than a set may is rejected: this change
            // is acknowledged with no storage, the set's staged changes
            // give theirs back, and the set, once closed, is rejected
            // whole, reported (`never_holds`), as a set no history can hold
            // is.
            let refusal = if full || self.staging_would_take_owed_places(&writer_guid, seq) {
                Some((Refusal::Backlog, None))
            } else {
                let sample = lifecycle.is_none().then_some(data);
                match self.prepare_staged(
                    writer_guid,
                    seq,
                    sample,
                    version,
                    staged_set,
                    in_order.unwrap_or(true),
                ) {
                    Ok((stored, staged)) => {
                        prepared = Some(stored);
                        charge = Some(staged);
                        None
                    }
                    Err(NotStaged::Rejected) => {
                        // Its set rejected whole, this member with it: its
                        // storage given back already, taken as a later
                        // member of the set is.
                        self.reject_staged_set(staged_set);
                        if let Some(start) = coherent_sn.filter(|_| group_sn.is_none()) {
                            self.note_set_ends(writer_guid, Some(start), None, None);
                        }
                        self.rejected_member_lands(
                            writer_guid,
                            seq,
                            coherent_sn,
                            staged_set,
                            lifecycle.is_none(),
                        );
                        if coherent_sn.is_some() && group_sn.is_none() {
                            self.try_commit_sets(writer_guid, false);
                        }
                        return;
                    }
                    Err(NotStaged::NoStorage(instance) | NotStaged::NoRoom(instance)) => {
                        Some((Refusal::Storage, instance))
                    }
                }
            };
            if let Some((refusal, instance)) = refusal {
                // Refused, it is owed all the same.
                self.join_at_refused_member(writer_guid, seq, coherent_sn);
                self.refuse_unacknowledged(writer_guid, seq, true, refusal, instance);
                // Refused, it still says where the set before it ends.
                if let Some(start) = coherent_sn.filter(|_| group_sn.is_none()) {
                    self.note_set_ends(writer_guid, Some(start), None, None);
                    self.try_commit_sets(writer_guid, false);
                }
                return;
            }
            // Reserve Publisher order before receipt can let the writer
            // purge this admitted member and advertise a later join floor.
            order_token = prepared.as_ref().and_then(|prepared| {
                self.register_coherent_wire_order(
                    writer_guid,
                    seq,
                    prepared,
                    self.capture_wire_order(writer_guid, seq),
                    group_sn,
                    coherent_repair,
                    ordered_incarnation.as_deref(),
                )
            });
            if self.capture_wire_order(writer_guid, seq).is_some() && order_token.is_none() {
                self.join_at_refused_member(writer_guid, seq, coherent_sn);
                self.refuse_unacknowledged(writer_guid, seq, true, Refusal::Backlog, None);
                return;
            }
            // Staged, the sample never reaches the gate on arrival: a gate
            // whose join baseline is the first DATA observed learns it here,
            // from the start of its set, so that a staged sample is told from
            // older history at release (`ReorderGate::on_staged`). A sample
            // passed straight through takes the gate itself.
            //
            // A best-effort gate that passed a later change of the writer
            // refuses the sample (T2, RTPS v2.5 Sec.8.4.12.1), as it refuses
            // a DATA it does not stage: staged, its set reached the
            // application behind that later change.
            //
            // A reliable gate keeps the staged change's place
            // (`ReorderGate::hold_staged`), told before the change is
            // acknowledged: a writer purges an acknowledged change, and the
            // HEARTBEAT that says so no longer moves the gate past it, and
            // past it ahead of its set the gate released the writer's later
            // changes (DDS v1.4 Sec.2.2.3.14). A gate that passed it since
            // the look above (its writer gave it up) takes it as that look
            // does: no change to deliver, credited.
            //
            // So does a gate that crosses it ahead (a GAP declared it, or a
            // HEARTBEAT's firstSN passed it as never received while the gate
            // waited below, `ReorderGate::lost_ahead`): final, its set can
            // never be whole. A sample lost, reported once: admitted before
            // that step, it was read as received when the step counted what
            // it crossed. Where its set starts is known all the same.
            #[cfg(test)]
            if let Some(hook) = self
                .hold_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                hook();
            }
            let (behind, held, ahead, lost, skipped) = {
                let mut gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
                let behind = gate.is_behind(&writer_guid, seq);
                let (mut held, mut ahead, mut lost) = (true, false, false);
                let skipped = self.best_effort_gap_before(&gate, writer_guid, seq);
                if !behind {
                    gate.observe(
                        writer_guid,
                        seq,
                        // A Dust DDS member's set start is no floor of this reader.
                        coherent_sn.filter(|_| {
                            !crate::engine::router::route_group_is_spec_receive(writer_guid, seq)
                        }),
                    );
                    ahead = gate.next_seq(&writer_guid).is_none_or(|next| seq >= next);
                    lost = gate.lost_ahead(&writer_guid, seq);
                    held = gate.hold_staged(&writer_guid, seq);
                }
                (behind, held, ahead, lost, skipped)
            };
            self.report_sample_lost(skipped);
            self.credit_receipt(writer_guid, seq);
            if !held {
                log::debug!(
                    "[READER-SUB] coherent change the gate passed dropped topic='{}' \
                     writer={:02x?} seq={}",
                    self.topic,
                    &writer_guid[..4],
                    seq
                );
                if lost {
                    let count = {
                        let mut map = self
                            .seen_seqs_by_writer
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        map.get_mut(&writer_guid).map_or(0, |record| {
                            record.reported.report(seq, seq.saturating_add(1))
                        })
                    };
                    self.report_sample_lost(count);
                }
                if ahead {
                    if let Some(start) = coherent_sn.filter(|_| group_sn.is_none()) {
                        self.note_set_ends(writer_guid, Some(start), None, None);
                        self.try_commit_sets(writer_guid, false);
                    }
                }
                return;
            }
            if behind {
                if let Some(start) = coherent_sn.filter(|_| group_sn.is_none()) {
                    self.note_set_ends(writer_guid, Some(start), None, None);
                    self.try_commit_sets(writer_guid, false);
                }
                return;
            }
        }

        // A sample of a set already discarded (it could never be whole, a
        // sample of it GAPped or lost, its writer gone) is of a set that no
        // longer exists: received, credited above, stepped over by the gate,
        // never staged. Staged, it opened that set again, and the sequences
        // the discard had stepped over made it look closed and whole: the
        // set reached the application in part.
        if let Some(start) = coherent_sn {
            if !passed_through && self.discarded_member(&writer_guid, start, seq) {
                self.step_gate_over_staged(writer_guid, seq);
                return;
            }
        }

        // GROUP-scope sets aggregate across all writers in the same
        // Publisher (DDS v1.4 sec. 2.2.3.6). Route the sample into the
        // group buffer keyed by (participant_prefix, publisher_entity_id,
        // group_sn) and bail before touching the per-writer buffer;
        // TOPIC/INSTANCE-scope sets keep using the simpler per-writer
        // buffer below.
        if self.coherent_cfg.is_group_scope {
            if let Some(gsn) = group_sn {
                self.stage_group_sample(
                    writer_guid,
                    seq,
                    prepared
                        .take()
                        .unwrap_or(super::admission::Prepared::Discard),
                    version,
                    coherent_sn,
                    gsn,
                    publisher_entity_id.unwrap_or([0; 4]),
                    lifecycle,
                    charge.take(),
                    order_token.take(),
                );
                return;
            }
            // Group-scope reader, coherent sample with no GSN tag. A
            // classic-model GROUP writer that tags PID_COHERENT_SET per
            // DATA and does not emit PID_GROUP_COHERENT_SET leaves the group
            // buffer (which keys on GSN + waits for an ECS close) unable to
            // fire and the set is lost. For such a
            // non-HDDS writer, fall through to the classic per-writer
            // buffer+commit path below (the exact path TOPIC/INSTANCE scope
            // uses): each writer's set is
            // committed atomically when its set-SN advances, and a GROUP
            // publisher bursts all its writers together so a single take()
            // read cycle collects the full cross-topic group.
            //
            // An HDDS writer always tags a GSN under group scope, so a
            // missing GSN here is a genuinely non-coherent / pre-begin
            // sample: pass it straight through with the no-dedup helper (the
            // seq was already admitted into `seen_seqs_by_writer` above, so
            // re-entering `on_data_with_writer` would drop it as a dup).
            if passed_through {
                if let Some((key, kind)) = lifecycle {
                    // Admitted above: credited, and stepped over by its
                    // gate as a change with no sample.
                    if let Some(receipt) = lifecycle_receipt.as_ref() {
                        if !self.credit_control_receipt(writer_guid, seq, receipt) {
                            return;
                        }
                    }
                    self.step_gate_over(writer_guid, seq);
                    self.apply_lifecycle(
                        writer_guid,
                        seq,
                        key,
                        kind,
                        crate::engine::router::route_source_ts_ns(),
                    );
                    self.discard_group_sets_behind(writer_guid, seq);
                    return;
                }
                self.deliver_admitted_sample(writer_guid, seq, data, version);
                self.discard_group_sets_behind(writer_guid, seq);
                return;
            }
            // else: classic non-HDDS writer -> fall through to the per-writer
            // classic coherent path below.
        }

        // TOPIC / INSTANCE access_scope (and a GROUP reader's classic
        // writers): each writer's sets are staged here and committed, one
        // set at a time, once closed and complete (`try_commit_sets`),
        // whatever closes them: the next set, a plain DATA, an end marker,
        // an HDDS end-of-set DATA.
        // TOPIC / INSTANCE access_scope: each writer's set is committed
        // independently. Stage in the per-writer FIFO and wait for the
        // matching ECS.
        #[cfg(test)]
        if let Some(hook) = self
            .staging_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            hook();
        }
        let mut guard = match self.coherent_buffer.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        // Its writer said it left since it was admitted, and its departure
        // drained the staging already: the change is of a writer that is no
        // more, never staged.
        if self.refuses_staging(&writer_guid) {
            return;
        }
        // Its set rejected meanwhile, on another thread: the rejection
        // records it under this lock (`reject_staged_set`).
        if let Some(set) = staged_in.filter(|set| self.set_rejected(*set)) {
            drop(guard);
            drop(prepared);
            self.take_rejected_member(writer_guid, seq, set, lifecycle.is_none());
            return;
        }
        let entry = guard.entry(writer_guid).or_default();

        // Bounded by MAX_STAGED_PER_WRITER, checked before the sample was
        // acknowledged (see there).
        entry.push(BufferedCoherentSample {
            order: self.capture_wire_order(writer_guid, seq),
            order_token: order_token.take(),
            remote_seq: seq,
            prepared: prepared
                .take()
                .unwrap_or(super::admission::Prepared::Discard),
            version,
            group_sn,
            coherent_sn,
            from_vendor_0101: crate::engine::router::route_writer_is_connext(),
            lifecycle,
            charge: charge.take(),
            source_ts_ns: crate::engine::router::route_source_ts_ns(),
        });
        log::debug!(
            "[READER-SUB] coherent buffer topic='{}' writer={:02x?} seq={} group_sn={:?} buffered={}",
            self.topic,
            &writer_guid[..4],
            seq,
            group_sn,
            entry.len()
        );
        drop(guard);

        self.try_commit_sets(writer_guid, false);
    }
}

impl<T: DDS> super::staging_budget::StagedOwner for ReaderSubscriber<T> {
    fn may_reject(&self) -> bool {
        self.ack_credit.is_none() || self.wire_bindings.is_none()
    }

    fn reject_staged(&self, set: StagedSet) {
        self.reject_staged_set(set);
    }
}

impl<T: DDS> crate::engine::Subscriber for ReaderSubscriber<T> {
    fn requires_ordered_group(&self) -> bool {
        self.wire_bindings.is_some()
    }

    fn on_group_writer_departure(&self, writer: [u8; 16], publisher: [u8; 4]) {
        if self.wire_bindings.is_none() {
            return;
        }
        if let Some(barrier) = &self.coherent_barrier {
            let mut key = writer;
            key[12..].copy_from_slice(&publisher);
            barrier.wire_departure(key, writer);
        }
        self.try_flush_group_sets();
    }

    fn payload_protected_for_writer(&self, writer: &[u8; 16]) -> bool {
        self.payload_framing_for_writer(writer) != crate::engine::subscriber::PayloadFraming::Clear
    }

    fn payload_framing_for_writer(
        &self,
        writer: &[u8; 16],
    ) -> crate::engine::subscriber::PayloadFraming {
        use crate::engine::subscriber::PayloadFraming;
        #[cfg(feature = "security")]
        let framing = if self.topic_payload_protected() {
            PayloadFraming::Sealed
        } else {
            match self.writer_payload_security(writer) {
                // An unresolved writer with a suite may yet announce
                // protection: its bytes stay whole and the reader treats
                // the sample as key-unknown (`decrypt_if_secured`).
                None if self.security.is_some() => PayloadFraming::Unresolved,
                None => PayloadFraming::Clear,
                Some(slot) if slot.is_some_and(|a| a.is_payload_protected()) => {
                    PayloadFraming::Sealed
                }
                Some(_) => PayloadFraming::Clear,
            }
        };
        #[cfg(not(feature = "security"))]
        let framing = {
            let _ = writer;
            PayloadFraming::Clear
        };
        #[cfg(test)]
        if let Some(hook) = self
            .framing_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            hook();
        }
        framing
    }

    fn on_key_only(&self, writer: [u8; 16], seq: u64, payload: Option<&[u8]>) {
        if self.wire_context_pending(writer, seq, None) {
            return;
        }
        #[cfg(feature = "security")]
        if self.writer_not_admitted(&writer) {
            return;
        }
        #[cfg(feature = "security")]
        if self.payload_protected_for_writer(&writer) {
            let Some(payload) = payload else {
                return;
            };
            match self.decrypt_if_secured(&writer, seq, payload) {
                SecuredIngest::Plain | SecuredIngest::Decrypted(..) => {}
                SecuredIngest::KeyUnknown | SecuredIngest::Drop => return,
            }
        }
        let _ = payload;
        if self.capture_wire_order(writer, seq).is_some() {
            if self.writer_shut_out(&writer) {
                return;
            }
            self.deliver_prepared(
                writer,
                seq,
                crate::dds::CdrVersion::Xcdr2,
                Admit::Here(NO_EPOCH),
                Ok(super::admission::Prepared::Discard),
            );
            return;
        }
        self.on_writer_non_data(writer, seq);
    }

    fn resolve_lifecycle_key(
        &self,
        writer: Option<[u8; 16]>,
        seq: u64,
        payload: Option<&[u8]>,
        fallback: Option<[u8; 16]>,
    ) -> Option<[u8; 16]> {
        #[cfg(feature = "security")]
        if let Some(writer) = writer {
            if self.writer_not_admitted(&writer) {
                return None;
            }
            let slot = self.writer_payload_security(&writer);
            if let Some(attributes) = slot.flatten().filter(|a| a.is_payload_protected()) {
                use crate::security::crypto::user_data;
                let id = user_data::secured_payload_key_id(payload?).ok()?;
                let suite = self.security.as_ref()?;
                let guid = crate::core::discovery::GUID::from_bytes(writer);
                let material = suite.data_keys.get_material(&guid, id)?;
                let encrypted = material.transformation
                    == crate::security::crypto::secure_submessage::Transformation::Aes256Gcm;
                if encrypted != attributes.is_payload_encrypted() {
                    return None;
                }
                let plain = user_data::decode_serialized_payload(id, &material, payload?).ok()?;
                return T::key_hash_of_key_payload(&plain)
                    .or_else(|| (!T::has_key()).then_some([0; 16]))
                    .or(fallback.filter(|_| T::captures_wire_identity()));
            }
            if self.security.is_some() {
                // What the writer sends in the clear is readable here only
                // when the topic is not protected and the writer has settled:
                // an unresolved one may yet announce protection, and a
                // topic the governance protects carries no cleartext key.
                let cleartext = match slot {
                    Some(None) => true,
                    Some(Some(attributes)) => !attributes.is_payload_protected(),
                    None => false,
                };
                if !cleartext || self.topic_payload_protected() {
                    return None;
                }
            }
        } else if self.unattributed_refused() || self.topic_payload_protected() {
            return None;
        }
        let _ = (writer, seq);
        payload.and_then(T::key_hash_of_key_payload).or(fallback)
    }

    /// The instance the serialized key names, by the type's own reading of
    /// it (`DDS::key_hash_of_key_payload`), so a dispose or unregister
    /// reaches the instance its samples reach whatever PID_KEY_HASH the
    /// writer computed.
    fn instance_of_key_payload(&self, payload: &[u8]) -> Option<[u8; 16]> {
        if !T::has_key() {
            return None;
        }
        T::key_hash_of_key_payload(payload)
    }

    fn on_data(&self, topic: &str, remote_seq: u64, data: &[u8]) {
        // Fallback path: wire CDR version unknown at this entry point,
        // default to Xcdr2 to preserve pre-2.5-f behavior.
        self.on_data_with_version(topic, remote_seq, data, crate::dds::CdrVersion::Xcdr2);
    }

    fn on_data_with_version(
        &self,
        _topic: &str,
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) {
        // No writer to admit (`unattributed_refused`), and no writer to
        // credit: refused under the security plugins.
        #[cfg(feature = "security")]
        if self.unattributed_refused() {
            log::debug!(
                "[READER-SUB] topic='{}': a sample naming no writer (seq={}) under the security \
                 plugins -- refused, it cannot be admitted",
                self.topic,
                remote_seq
            );
            return;
        }
        // A topic whose payload the governance protects takes no cleartext
        // (`decrypt_if_secured`, Sec.9.4.1.2.6.7), and no ciphertext either
        // on this path (below): nothing.
        #[cfg(feature = "security")]
        if self.topic_payload_protected()
            || self
                .security
                .as_ref()
                .is_some_and(|s| s.cryptographic().is_some())
        {
            self.cleartext_refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::debug!(
                "[READER-SUB] topic='{}': a payload on the writer-less ingest path (seq={}) of a \
                 topic with payload protection configured -- refused",
                self.topic,
                remote_seq
            );
            return;
        }
        // Drop duplicate remote sequences. Per RTPS v2.5 sec. 8.4.2.2 a DataWriter
        // MUST assign a monotonically increasing sequence number per sample,
        // so repeats are retransmits that were already delivered. Without
        // this guard, a writer that resends a sample under the same seq
        // delivers the payload twice (breaks reliability tests).
        {
            let mut seen = match self.seen_seqs.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            if seen.admit(remote_seq, Missed::Dropped, || None) != Seen::New {
                log::debug!(
                    "[READER-SUB] dropping duplicate remote_seq={} topic='{}'",
                    remote_seq,
                    self.topic
                );
                return;
            }
        }
        // No writer GUID available on this path -- bypass the reorder gate
        // and ship straight through, matching pre-reorder behaviour for
        // intra-process / non-routed paths that never see a writer GUID.
        let captured = T::capture_wire_data(data, None);
        self.deliver_unattributed(remote_seq, &captured, version);
    }

    fn on_data_with_writer(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) {
        self.receive_writer(topic, writer_guid, seq, data, version, None);
    }

    fn on_data_keyed(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        key_hash: Option<[u8; 16]>,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) {
        if coherent_sn.is_some() || group_sn.is_some() {
            self.stage_coherent_change(
                topic,
                writer_guid,
                seq,
                data,
                version,
                (coherent_sn, group_sn, publisher_entity_id),
                None,
                key_hash,
            );
        } else {
            self.receive_writer(topic, writer_guid, seq, data, version, key_hash);
        }
    }

    fn reader_entity_id(&self) -> Option<[u8; 4]> {
        self.reader_entity_id
    }

    fn on_writer_heartbeat_liveliness(&self, writer_guid: [u8; 16]) {
        if let Some(ref liveliness) = self.liveliness {
            liveliness.on_heartbeat_liveliness(&writer_guid);
        }
    }

    fn on_writer_heartbeat_range(&self, writer_guid: [u8; 16], first_seq: u64, last_seq: u64) {
        #[cfg(test)]
        let _arrival = self.group_arrival_scope(writer_guid, None);
        if self.wire_bindings.is_some()
            && (self.writer_shut_out(&writer_guid) || !self.apply_group_arrival(writer_guid, None))
        {
            return;
        }
        if self
            .departed_count
            .load(std::sync::atomic::Ordering::Acquire)
            != 0
            && self.departed.read().contains_key(&writer_guid)
            && self.heartbeat_verdict(writer_guid, last_seq).is_none()
        {
            return;
        }
        self.on_writer_heartbeat(writer_guid, first_seq);
    }

    fn on_writer_heartbeat(&self, writer_guid: [u8; 16], first_seq: u64) {
        if self.has_left(&writer_guid) {
            return;
        }
        // A writer this reader is not matched with moves nothing of it
        // (`writer_refused`), its HEARTBEATs, GAPs and set ends no more than
        // its samples.
        if self.writer_refused(&writer_guid) {
            return;
        }
        // DDS Security v1.1 Sec.8.8.7.1, 9.4.3: a writer the security
        // plugins do not admit moves nothing of this reader, its HEARTBEATs
        // and GAPs no more than its samples (`writer_not_admitted`: the
        // cached admission verdict, one flag without security).
        #[cfg(feature = "security")]
        if self.writer_not_admitted(&writer_guid) {
            return;
        }
        // A HEARTBEAT whose firstSN is above where a reliable reader's
        // seeded gate is says the changes in between left the writer's
        // history: those this reader never received are samples lost (RTPS
        // v2.5 Sec.8.4.12.2, transition T7, `lost_changes_update(firstSN,
        // true)`; DDS v1.4 Sec.2.2.4.1, SAMPLE_LOST: "A sample has been lost
        // (never received)"), but those filtered for it. Each once
        // (`never_received_in`), as a GAP's are.
        //
        // Counted in the gate's critical section the HEARTBEAT takes anyway,
        // the duplicate record under it (the order a delivery takes them):
        // what the gate crossed as never received is final, a copy arriving
        // later dropped (`ReorderGate::on_data`), and a copy received after
        // the step but before the count, read as received, was dropped
        // unreported. A copy admitted before the step and handed to the gate
        // after it is reported when the gate refuses it (`lost_ahead`).
        let group_loss = self.wire_bindings.as_ref().and_then(|_| {
            let credit = self.ack_credit.as_ref()?;
            let ledger = self.wire_loss_ledger(writer_guid, None)?;
            self.refresh_order_gap(writer_guid, &ledger);
            let filtered = self
                .reorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .filtered_ranges(&writer_guid);
            Some(
                self.with_current_loss_frame(writer_guid, &ledger, || {
                    credit.group_heartbeat_loss(
                        &writer_guid,
                        &ledger.authority,
                        first_seq,
                        &filtered,
                    )
                })
                .flatten(),
            )
        });
        if group_loss.is_some_and(|count| count.is_none()) {
            return;
        }
        let group_loss = group_loss.flatten();
        let reliable = self.ack_credit.is_some();
        let mut lost = 0;
        self.release_through_gate(writer_guid, |gate| {
            // Below firstSN under a base a DATA dropped unconfirmed seeded
            // and nothing passed since: never shown owed, not lost
            // (`ReorderGate::at_hint_floor`).
            let skipped = reliable
                .then(|| gate.next_seq(&writer_guid))
                .flatten()
                .filter(|&next| first_seq > next && !gate.at_hint_floor(&writer_guid))
                .map(|next| (next, gate.filtered_ranges(&writer_guid)));
            let released = gate.on_heartbeat(writer_guid, first_seq);
            if let Some((owed_from, filtered)) = skipped.filter(|_| group_loss.is_none()) {
                lost = self.never_received_in(writer_guid, [(owed_from, first_seq)], &filtered);
            }
            released
        });
        self.report_sample_lost(group_loss.unwrap_or(lost));
        if self.wire_bindings.is_some() {
            if let Some(barrier) = &self.coherent_barrier {
                barrier.wire_proofs_changed();
            }
        }
        // A set of this writer that waits for places is tried again.
        if self.coherent_cfg.coherent_access {
            self.try_commit_sets(writer_guid, false);
            if self.coherent_cfg.is_group_scope {
                self.try_flush_group_sets();
            }
        }
    }

    fn on_writer_gap_filtered(
        &self,
        writer_guid: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: Vec<u64>,
        filtered_count: u64,
    ) {
        // A writer this reader is not matched with moves nothing of it
        // (`writer_refused`), its HEARTBEATs, GAPs and set ends no more than
        // its samples.
        if self.writer_refused(&writer_guid) {
            return;
        }
        // DDS Security v1.1 Sec.8.8.7.1, 9.4.3: a writer the security
        // plugins do not admit moves nothing of this reader, its HEARTBEATs
        // and GAPs no more than its samples (`writer_not_admitted`: the
        // cached admission verdict, one flag without security).
        #[cfg(feature = "security")]
        if self.writer_not_admitted(&writer_guid) {
            return;
        }
        // The changes a GAP declares (RTPS v2.5 Sec.8.3.8.4: [gapStart,
        // gapList.base - 1] and those gapList lists; gapStart alone at the
        // least, as the gate reads it). filteredCount says how many of them
        // are filtered, not which: only a count that covers them all says
        // of each that it is filtered. A writer that filters sends such a
        // GAP for what it filters (Sec.8.4.9.2, transition T4: a GAP of one
        // filtered change with filteredCount 1, a separate GAP with 0 for
        // what left its history). Otherwise none is
        // taken as filtered, and a coherent set missing one of them is
        // discarded rather than delivered incomplete.
        let listed: BTreeSet<u64> = gap_list_seqs
            .iter()
            .copied()
            .filter(|&seq| seq > 0 && !(gap_start..gap_list_base).contains(&seq))
            .collect();
        let declared = gap_list_base
            .saturating_sub(gap_start.max(1))
            .saturating_add(u64::try_from(listed.len()).unwrap_or(u64::MAX));
        if declared > 0 && filtered_count >= declared && !self.has_left(&writer_guid) {
            match self.reorder.lock() {
                Ok(mut gate) => {
                    gate.note_filtered(writer_guid, gap_start, gap_list_base, &gap_list_seqs)
                }
                Err(e) => e.into_inner().note_filtered(
                    writer_guid,
                    gap_start,
                    gap_list_base,
                    &gap_list_seqs,
                ),
            }
        }
        self.on_writer_gap(writer_guid, gap_start, gap_list_base, gap_list_seqs);
    }

    fn on_writer_gap(
        &self,
        writer_guid: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: Vec<u64>,
    ) {
        if self.has_left(&writer_guid) {
            return;
        }
        // A writer this reader is not matched with moves nothing of it
        // (`writer_refused`), its HEARTBEATs, GAPs and set ends no more than
        // its samples.
        if self.writer_refused(&writer_guid) {
            return;
        }
        // DDS Security v1.1 Sec.8.8.7.1, 9.4.3: a writer the security
        // plugins do not admit moves nothing of this reader, its HEARTBEATs
        // and GAPs no more than its samples (`writer_not_admitted`: the
        // cached admission verdict, one flag without security).
        #[cfg(feature = "security")]
        if self.writer_not_admitted(&writer_guid) {
            return;
        }
        // This reader stops requesting what the writer declared irrelevant
        // (RTPS v2.5 Sec.8.3.8.4): its WriterProxy takes the GAP whichever
        // door it came through. Only a reader tracking the writer has one.
        let mut group_loss = None;
        let mut ordered_gap = None;
        if let Some(ref credit) = self.ack_credit {
            if let (Ok(start), Ok(base)) = (i64::try_from(gap_start), i64::try_from(gap_list_base))
            {
                if let Some(ledger) = self
                    .wire_bindings
                    .as_ref()
                    .and_then(|_| self.wire_loss_ledger(writer_guid, None))
                {
                    let filtered = self
                        .reorder
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .filtered_ranges(&writer_guid);
                    self.refresh_order_gap(writer_guid, &ledger);
                    let context = crate::core::reader::GapOrderScope::captured(writer_guid);
                    if let Some((_, end)) = context {
                        ledger.authority.defer_order_gap(end);
                    }
                    group_loss = Some(
                        self.with_current_loss_frame(writer_guid, &ledger, || {
                            if context.is_none() && ledger.authority.order_gap_end() == 0 {
                                credit.group_gap_loss(
                                    &writer_guid,
                                    &ledger.authority,
                                    start,
                                    base,
                                    &gap_list_seqs,
                                    &filtered,
                                )
                            } else {
                                credit.group_gap_loss_with_order(
                                    &writer_guid,
                                    &ledger.authority,
                                    start,
                                    base,
                                    &gap_list_seqs,
                                    &filtered,
                                    false,
                                )
                            }
                        })
                        .flatten(),
                    );
                    if let Some((lo, hi)) = context {
                        ordered_gap = Some((ledger, lo, hi, start, base));
                    }
                } else {
                    credit.note_gap(&writer_guid, start, base, &gap_list_seqs);
                }
            }
        }

        if group_loss.is_some_and(|count| count.is_none()) {
            return;
        }
        let group_loss = group_loss.flatten();
        if let Some((ledger, lo, hi, start, base)) = ordered_gap {
            self.on_writer_group_gap(writer_guid, lo, hi);
            if self.order_gap_consumed(writer_guid, hi) {
                let _ = self.with_current_loss_frame(writer_guid, &ledger, || {
                    if let Some(credit) = &self.ack_credit {
                        credit.credit_ordered_gap(
                            &writer_guid,
                            &ledger.authority,
                            start,
                            base,
                            &gap_list_seqs,
                        );
                    }
                });
            }
            self.refresh_order_gap(writer_guid, &ledger);
            if let Some(credit) = &self.ack_credit {
                let _ = self.with_current_loss_frame(writer_guid, &ledger, || {
                    credit.set_group_order_pending(
                        &writer_guid,
                        ledger.authority.order_gap_end() != 0,
                    );
                });
            }
        }

        // The changes the GAP declares that this reader is owed (at or above
        // where its gate is, once it knows: a reliable reader's gate,
        // seeded) and never received are samples lost (DDS v1.4
        // Sec.2.2.4.1, SAMPLE_LOST: "A sample has been lost (never
        // received)"), but those filtered for it (RTPS v2.5 Sec.8.3.8.4:
        // "Filtered changes should not be treated as samples lost";
        // `on_writer_gap_filtered` records them first). Counted before the
        // gate moves past them, each once (`never_received`).

        // Advance the reorder gate past the sequences the remote writer
        // declared irrelevant (RTPS v2.5 sec 8.3.8.4): the contiguous
        // range [gap_start, gap_list_base) plus the bitmap-listed
        // gap_list_seqs. Any buffered live samples that are now unblocked
        // are released in order.
        let settled = self
            .gate_is_bounded()
            .then(|| self.settled(writer_guid))
            .flatten();
        // What the reader holds staged of the declared changes (a coherent
        // set waiting for its end) was received: the gate waits for it, not
        // past it (`ReorderGate::on_gap_keeping`). Read before the gate's
        // lock, never under it: a change staged in between is one the GAP
        // reached first, as if the GAP had come first on the wire.
        let staged: BTreeSet<u64> = if self.coherent_cfg.coherent_access {
            let mut staged: BTreeSet<u64> = self
                .coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&writer_guid)
                .map(|v| v.iter().map(|s| s.remote_seq).collect())
                .unwrap_or_default();
            if self.coherent_cfg.is_group_scope {
                staged.extend(
                    self.group_coherent_buffer
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .values()
                        .filter_map(|set| set.per_writer.get(&writer_guid))
                        .flatten()
                        .map(|s| s.remote_seq),
                );
            }
            staged
        } else {
            BTreeSet::new()
        };
        // Where the gate is before the GAP, and what it knows filtered: read
        // in the gate's critical section the GAP takes anyway.
        //
        // Counted in that section, after the gate's step, the duplicate
        // record under it, as a HEARTBEAT's are (`on_writer_heartbeat`): a
        // declared change the gate holds was received, and one arriving
        // after the step is dropped (`ReorderGate::on_data`). Counted after
        // the section, a copy received in between was read as received and
        // dropped unreported.
        let reliable = self.ack_credit.is_some();
        let mut lost = 0;
        // What gapList lists beyond [gapStart, gapList.base): the parser
        // materializes the range into the list too.
        let declared: Option<BTreeSet<u64>> = reliable.then(|| {
            gap_list_seqs
                .iter()
                .copied()
                .filter(|&seq| seq > 0 && !(gap_start..gap_list_base).contains(&seq))
                .collect()
        });
        self.release_through_gate(writer_guid, |gate| {
            let owed = reliable
                .then(|| gate.next_seq(&writer_guid))
                .flatten()
                .map(|next| (next, gate.filtered_ranges(&writer_guid)));
            let mut released = gate.on_gap_keeping(
                writer_guid,
                gap_start,
                gap_list_base,
                gap_list_seqs,
                &staged,
            );
            if let (Some((owed_from, filtered)), Some(declared)) =
                (owed.filter(|_| group_loss.is_none()), declared.as_ref())
            {
                lost = self.lost_to_gap(
                    writer_guid,
                    owed_from,
                    &filtered,
                    (gap_start, gap_list_base, declared),
                );
            }
            if let Some(settled) = settled {
                released.append(&mut gate.catch_up(writer_guid, settled));
            }
            released
        });
        self.report_sample_lost(group_loss.unwrap_or(lost));
        if self.wire_bindings.is_some() {
            if let Some(barrier) = &self.coherent_barrier {
                barrier.wire_proofs_changed();
            }
        }
        if self.coherent_cfg.coherent_access {
            self.try_commit_sets(writer_guid, false);
            if self.coherent_cfg.is_group_scope {
                self.try_flush_group_sets();
            }
        }
    }

    fn on_change_without_sample(&self, writer_guid: [u8; 16], seq: u64) {
        // Admitted as the writer's key-only change is (`on_key_only`): a
        // writer the security plugins do not admit moves nothing of this
        // reader, and where the writer's payload is protected a change that
        // carries none has nothing to authenticate (DDS-Security v1.1
        // Sec.8.5.1.9.4, Sec.9.5.3.3): whoever sent it under the writer's
        // GUID, it neither counts as received nor ends a set.
        #[cfg(feature = "security")]
        if self.writer_not_admitted(&writer_guid) || self.payload_protected_for_writer(&writer_guid)
        {
            return;
        }
        if !self.coherent_cfg.coherent_access {
            self.on_writer_non_data(writer_guid, seq);
            return;
        }
        let _delivering = super::notices::Delivering::enter();
        if let Some(ref liveliness) = self.liveliness {
            liveliness.on_data(&writer_guid);
        }
        if self.has_left(&writer_guid) {
            return;
        }
        // A writer that is no writer of this reader ends nothing of it
        // (`writer_shut_out`, as `on_ecs`).
        if self.writer_shut_out(&writer_guid) {
            return;
        }
        // Admitted once, before it closes anything: a repair of a change
        // received already (a member of the set, staged) closes nothing.
        if !self.admit_change_without_sample(writer_guid, seq) {
            return;
        }
        // A change of no coherent set ends the set staged before it, if
        // any (RTPS v2.5 Sec.8.7.6), as a plain DATA does: its sequence
        // number is no member of that set. Kept until its set is staged
        // when the gate does not keep it (`note_set_ends`).
        self.note_set_ends(writer_guid, None, Some(seq), None);
        self.pass_change_without_sample(writer_guid, seq);
        // Its gate passed it: the sets that waited for it, or that it
        // ends, may be deliverable now.
        self.try_commit_sets(writer_guid, false);
        if self
            .group_sets_await_gate
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.try_flush_group_sets();
        }
    }

    fn on_writer_non_data(&self, writer_guid: [u8; 16], seq: u64) {
        let _delivering = super::notices::Delivering::enter();
        // A write, dispose or unregister asserts a MANUAL writer's
        // liveliness (RTPS v2.5 Sec.8.7.2.2).
        if let Some(ref liveliness) = self.liveliness {
            liveliness.on_data(&writer_guid);
        }
        if self.has_left(&writer_guid) {
            return;
        }
        // A writer this reader is not matched with moves nothing of it
        // (`writer_refused`), its HEARTBEATs, GAPs and set ends no more than
        // its samples.
        if self.writer_refused(&writer_guid) {
            return;
        }
        if self.admit_change_without_sample(writer_guid, seq) {
            self.pass_change_without_sample(writer_guid, seq);
        }
    }

    fn on_group_change(
        &self,
        writer_guid: [u8; 16],
        change: crate::engine::subscriber::GroupChange,
    ) {
        if self.wire_context_pending(writer_guid, change.seq, None) {
            return;
        }
        if !(self.coherent_cfg.coherent_access && self.coherent_cfg.is_group_scope) {
            return;
        }
        // A writer that is no writer of this reader names nothing of its
        // GROUP sets: not their writer set, not their GSNs, not a set.
        if self.writer_shut_out(&writer_guid) {
            return;
        }
        let Ok(prefix) = <[u8; 12]>::try_from(&writer_guid[..12]) else {
            return;
        };
        self.note_group_change(
            (prefix, change.publisher_entity_id, change.group_sn),
            writer_guid,
            change,
        );
    }

    fn on_writer_group_heartbeat(
        &self,
        writer_guid: [u8; 16],
        current_gsn: u64,
        first_gsn: u64,
        last_gsn: u64,
    ) {
        #[cfg(test)]
        let _arrival = self.group_arrival_scope(writer_guid, None);
        if !(self.coherent_cfg.coherent_access && self.coherent_cfg.is_group_scope) {
            return;
        }
        // Nor its GroupInfo, recorded for no set, for any GUID.
        if self.writer_shut_out(&writer_guid) {
            return;
        }
        if self.wire_bindings.is_some() {
            if !self.apply_group_arrival(writer_guid, None) {
                return;
            }
            if self
                .wire_loss_ledger(writer_guid, None)
                .is_some_and(|ledger| ledger.authority.gap_deferred())
            {
                return;
            }
        }
        self.writer_gsns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(writer_guid)
            .or_default()
            .heartbeat = Some([current_gsn, first_gsn, last_gsn]);
        self.try_flush_group_sets();
    }

    fn on_writer_group_heartbeat_roster(
        &self,
        writer_guid: [u8; 16],
        info: [u64; 3],
        writer_set: Option<([u8; 4], [u8; 4])>,
    ) {
        #[cfg(test)]
        let _arrival = self.group_arrival_scope(writer_guid, None);
        let [current_gsn, first_gsn, last_gsn] = info;
        if self.wire_bindings.is_some() && !self.writer_shut_out(&writer_guid) {
            if !self.apply_group_arrival(writer_guid, None) {
                return;
            }
            if self
                .wire_loss_ledger(writer_guid, None)
                .is_some_and(|ledger| ledger.authority.gap_deferred())
            {
                return;
            }
            if let (Some(barrier), Some(entity)) = (
                self.coherent_barrier.as_ref(),
                self.topic_registry
                    .as_ref()
                    .and_then(|registry| registry.writer_spec_group(&writer_guid)),
            ) {
                let mut publisher = writer_guid;
                publisher[12..].copy_from_slice(&entity);
                barrier.wire_heartbeat(
                    publisher,
                    writer_guid,
                    [current_gsn, first_gsn, last_gsn],
                    writer_set.map(|(public, _)| public),
                );
            }
        }
    }

    fn on_writer_group_gap(&self, writer_guid: [u8; 16], start: u64, end: u64) {
        if self.wire_bindings.is_some() && !self.writer_shut_out(&writer_guid) {
            if self
                .wire_loss_ledger(writer_guid, None)
                .is_some_and(|ledger| ledger.authority.gap_deferred())
            {
                return;
            }
            if let (Some(barrier), Some(entity)) = (
                self.coherent_barrier.as_ref(),
                self.topic_registry
                    .as_ref()
                    .and_then(|registry| registry.writer_spec_group(&writer_guid)),
            ) {
                let mut publisher = writer_guid;
                publisher[12..].copy_from_slice(&entity);
                if let Some(member) = self.barrier_member {
                    barrier.wire_gap(publisher, writer_guid, start, end, member);
                }
            }
        }
    }

    fn on_dropped_before_discovery(&self, writer_guid: [u8; 16], seq: u64, dropped_at: u64) {
        // Dropped by the router unacknowledged, before discovery bound the
        // writer to this topic: the writer sends it again, and it is owed
        // (`ReorderGate::on_dropped_undiscovered`). Owed to a reader that
        // existed when it was dropped only. Nothing authenticates the DATA
        // the router dropped: a secured participant takes none of it, its
        // own refusals of DATA it cannot authenticate yet
        // (`ReorderGate::on_refused_unauthenticated`) owe what is owed.
        if dropped_at <= self.created_at {
            return;
        }
        #[cfg(feature = "security")]
        if self.security.is_some() {
            return;
        }
        self.owe_dropped_before_discovery(writer_guid, seq, None);
    }

    fn on_writer_qos_resolved(&self, writer_guid: [u8; 16]) {
        // PARTITION is mutable (DDS v1.4 Sec.2.2.3.13). A new SEDP offer
        // replaces the cached verdict before deferred samples are retried.
        self.partition_verdict.forget(&writer_guid);
        // Announced again: it is a writer of this reader once more, after
        // its first HEARTBEAT for a reliable reader that had received from
        // it (`heartbeat_verdict`).
        let forget = {
            let mut departed = self.departed.write();
            let parked = match departed.get_mut(&writer_guid) {
                None => None,
                Some(entry) => {
                    entry.announced = true;
                    Some(entry.parked.is_some())
                }
            };
            parked == Some(false)
        };
        if forget {
            self.forget_departure(&writer_guid, true);
        }
        // Announced again: the writer's new record judges its samples, not
        // the lifespan it left with.
        self.departed_lifespans.forget(&writer_guid);
        // Discovered: a DATA it sent before, dropped unconfirmed, is no
        // longer forgotten under the bound kept for unannounced GUIDs.
        self.reorder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .writer_discovered(&writer_guid);
        // Proactive re-evaluation of samples deferred by the OWNERSHIP gate:
        // the SEDP handler just processed this writer's announcement, so the
        // verdict is resolvable NOW. Without this hook a one-shot burst
        // (TRANSIENT_LOCAL history push racing its own SEDP) would sit in
        // the pending buffer until the writer's NEXT live sample -- which a
        // history-only writer may never send.
        self.ownership_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .resolved
            .insert(writer_guid);
        self.flush_resolved_ownership_pending(writer_guid);
    }

    fn on_data_coherent(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) {
        // A write, dispose or unregister asserts a MANUAL writer's
        // liveliness (RTPS v2.5 Sec.8.7.2.2).
        if let Some(ref liveliness) = self.liveliness {
            liveliness.on_data(&writer_guid);
        }
        self.stage_coherent_change(
            topic,
            writer_guid,
            seq,
            data,
            version,
            (coherent_sn, group_sn, publisher_entity_id),
            None,
            None,
        );
    }

    fn on_lifecycle_coherent(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        key_hash: [u8; 16],
        kind: DisposeKind,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) {
        if self.wire_context_pending(writer_guid, seq, coherent_sn) {
            return;
        }
        // A write, dispose or unregister asserts a MANUAL writer's
        // liveliness (RTPS v2.5 Sec.8.7.2.2).
        if let Some(ref liveliness) = self.liveliness {
            liveliness.on_data(&writer_guid);
        }
        // Nothing of a writer the security plugins do not admit, not even the
        // bookkeeping of its sequence number (`writer_not_admitted`).
        #[cfg(feature = "security")]
        if self.writer_not_admitted(&writer_guid) {
            return;
        }
        // A reader that does not read coherent sets, or a change with no set
        // tag after all: the lifecycle change of no set it is.
        if !self.coherent_cfg.coherent_access || (coherent_sn.is_none() && group_sn.is_none()) {
            if self.writer_shut_out(&writer_guid) {
                return;
            }
            self.deliver_prepared(
                writer_guid,
                seq,
                crate::dds::CdrVersion::Xcdr2,
                Admit::Here(NO_EPOCH),
                Ok(super::admission::Prepared::Lifecycle {
                    key: key_hash,
                    kind,
                }),
            );
            return;
        }
        self.stage_coherent_change(
            topic,
            writer_guid,
            seq,
            &[],
            crate::dds::CdrVersion::Xcdr2,
            (coherent_sn, group_sn, publisher_entity_id),
            Some((key_hash, kind)),
            None,
        );
    }

    fn on_ecs(
        &self,
        _topic: &str,
        writer_guid: [u8; 16],
        ecs_seq: u64,
        coherent_sn: u64,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) {
        if self.wire_context_pending(writer_guid, ecs_seq, Some(coherent_sn)) {
            return;
        }
        let _delivering = super::notices::Delivering::enter();
        if self.has_left(&writer_guid) {
            return;
        }
        // A writer this reader is not matched with moves nothing of it
        // (`writer_refused`), its HEARTBEATs, GAPs and set ends no more than
        // its samples; nor does one the security plugins do not admit
        // (`writer_shut_out`).
        if self.writer_shut_out(&writer_guid) {
            return;
        }
        // Only this D=0/K=0 marker has no payload. A D=1 DATA carrying
        // PID_END_COHERENT_SET follows the member-owned DATA path instead.
        // Bound proof metadata before duplicate admission or receipt credit;
        // a refused RELIABLE marker remains repairable after prefix progress.
        let order = self.capture_wire_order(writer_guid, ecs_seq);
        if let Some(change) = order {
            let Some((barrier, member)) = self.coherent_barrier.as_ref().zip(self.barrier_member)
            else {
                return;
            };
            if !barrier.wire_accounted(change, member) {
                return;
            }
        }
        // The marker is a change of its own, with its own sequence number
        // (RTPS v2.5 Sec.8.7.5): a reliable reader acknowledges it like any
        // change it received (Sec.8.4.12), whatever it then does with it and
        // whether or not it reads coherent sets. Left unacknowledged, the
        // writer repairs it for ever and never sees its set acknowledged.
        // A reader that does not read coherent sets takes it as a change
        // without a sample: its duplicate record and its gate pass it too.
        if !self.coherent_cfg.coherent_access {
            self.on_writer_non_data(writer_guid, ecs_seq);
            self.note_wire_control_prefix(writer_guid, ecs_seq, order);
            return;
        }
        // GROUP-scope: route through the publisher-wide barrier. Mark
        // this writer as closed for the given group_sn and atomically
        // flush the set only once every writer with buffered samples in
        // that set has sent its ECS (DDS v1.4 Sec.2.2.3.6).
        if self.coherent_cfg.is_group_scope && group_sn.is_some() {
            if let Some(gsn) = group_sn {
                self.close_group_set(
                    writer_guid,
                    Some(ecs_seq),
                    coherent_sn,
                    None,
                    gsn,
                    publisher_entity_id.unwrap_or([0; 4]),
                );
            }
            self.note_wire_control_prefix(writer_guid, ecs_seq, order);
            return;
        }

        let Some(receipt) = self.prepare_control_receipt(writer_guid, ecs_seq) else {
            return;
        };
        // Admitted into the same duplicate record as a DATA sample
        // (`SeenSeqs`), as the comment above promises: without this, a
        // HEARTBEAT that later purges past the marker's SN (its set
        // discarded, or just acknowledged and gone from the writer's
        // history) reads it back as a DATA sample never received
        // (`never_received_in`), and DDS v1.4 Sec.2.2.4.1 SAMPLE_LOST counts
        // only samples -- a coherent-set marker carries none. A repair of a
        // marker already admitted closes nothing again (its set, if still
        // open, waits for the member that completes it, not for a second
        // close); one the record cannot take without dropping something it
        // owes is refused unacknowledged, as a sample is.
        let admitted = self
            .accept_best_effort_control(writer_guid, ecs_seq)
            .unwrap_or_else(|| {
                let mut map = match self.seen_seqs_by_writer.lock() {
                    Ok(lock) => lock,
                    Err(e) => e.into_inner(),
                };
                self.admit_seen(
                    map.entry(writer_guid).or_default(),
                    writer_guid,
                    ecs_seq,
                    self.missed(),
                )
            });
        match admitted {
            Seen::New => {
                if !self.credit_control_receipt(writer_guid, ecs_seq, &receipt) {
                    return;
                }
            }
            Seen::Duplicate => {
                self.credit_control_receipt(writer_guid, ecs_seq, &receipt);
                return;
            }
            Seen::Full => return,
        }

        // RTPS v2.5 sec. 8.7.5 + DDS v1.4 sec. 2.2.3.6: under GROUP-scope
        // coherent_access an ECS marker MUST carry PID_GROUP_COHERENT_SET.
        // An ECS with only PID_COHERENT_SET is a TOPIC/INSTANCE-scope
        // closure and MUST NOT prematurely flush a GROUP-scope buffer
        // (a malformed or adversarial Q-only DATA carrying just
        // PID_COHERENT_SET could otherwise release samples whose group
        // set is still open).
        if self.coherent_cfg.is_group_scope && group_sn.is_none() {
            log::debug!(
                "[READER-SUB] ECS without group_sn ignored under GROUP scope topic='{}' writer={:02x?} coherent_sn={}",
                self.topic,
                &writer_guid[..4],
                coherent_sn
            );
            // Acknowledged all the same: the gate steps over it.
            self.skip_ecs_seq_in_gate(writer_guid, ecs_seq);
            return;
        }

        // TOPIC / INSTANCE access_scope: the marker is a change of no set,
        // after the set it closes (`coherent_sn`, the set's last sample).
        // It takes its turn in the gate, and with it the set's end is
        // known; the set commits once complete (`try_commit_sets`): an
        // end-of-set DATA that overtook a sample of its set waits for it,
        // where committing what was staged delivered the set in part and
        // left the late sample staged for good.
        self.note_set_ends(writer_guid, None, Some(ecs_seq), None);
        self.skip_ecs_seq_in_gate(writer_guid, ecs_seq);
        self.try_commit_sets(writer_guid, false);
    }

    fn on_coherent_end(
        &self,
        _topic: &str,
        writer_guid: [u8; 16],
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
        end_sn: Option<u64>,
        end_count: Option<u32>,
    ) {
        if self.has_left(&writer_guid) {
            return;
        }
        // A writer that is no writer of this reader ends nothing of it
        // (`writer_shut_out`, as `on_ecs`).
        if self.writer_shut_out(&writer_guid) {
            return;
        }
        self.coherent_end(
            writer_guid,
            group_sn,
            publisher_entity_id,
            end_sn,
            end_count,
            None,
        );
    }

    fn on_coherent_end_marker(
        &self,
        _topic: &str,
        writer_guid: [u8; 16],
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
        end_sn: u64,
        end_count: Option<u32>,
        marker_seq: u64,
    ) {
        if self.has_left(&writer_guid) {
            return;
        }
        // A writer that is no writer of this reader ends nothing of it
        // (`writer_shut_out`, as `on_ecs`).
        if self.writer_shut_out(&writer_guid) {
            return;
        }
        self.coherent_end(
            writer_guid,
            group_sn,
            publisher_entity_id,
            Some(end_sn),
            end_count,
            Some(marker_seq),
        );
    }

    fn on_dispose(&self, _topic: &str, seq: u64, key_hash: [u8; 16], kind: DisposeKind) {
        log::debug!(
            "[READER-SUB] on_dispose topic='{}' seq={} kind={:?} key_hash={:02x?}",
            self.topic,
            seq,
            kind,
            &key_hash[..4]
        );
        // A lifecycle change is data (Sec.8.8.7.1): one naming no writer
        // cannot be admitted under the security plugins.
        #[cfg(feature = "security")]
        if self.unattributed_refused() {
            log::debug!(
                "[READER-SUB] topic='{}': a lifecycle change naming no writer (seq={}) under the \
                 security plugins -- refused",
                self.topic,
                seq
            );
            return;
        }

        // Queue the event for DataReader::get_dispose_events; the queue
        // raises the dispose wake word and signals the WaitSets (see
        // DisposeQueue for why the word is written under its lock).
        // A transition off the wire sits at its own sequence number. The
        // sender is unknown on this path (the router passes it to
        // `on_dispose_from_writer` whenever it has it), so the transition is
        // ordered against the instance's writer when exactly one holds it,
        // and is applied as received.
        let writer_guid = self.writer_of_instance(&key_hash);
        self.queue_transition(
            key_hash,
            kind,
            seq,
            writer_guid,
            seq,
            crate::engine::router::route_source_ts_ns(),
        );
    }

    fn on_dispose_from_writer(
        &self,
        _topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        key_hash: [u8; 16],
        kind: DisposeKind,
    ) {
        // Routed D=1 changes carry this lifecycle with their stored DATA.
        // A direct legacy callback has no such scoped carrier.
        if crate::engine::router::route_inline_lifecycle(Some(writer_guid), seq).is_some() {
            return;
        }
        // A write, dispose or unregister asserts a MANUAL writer's
        // liveliness (RTPS v2.5 Sec.8.7.2.2).
        if let Some(ref liveliness) = self.liveliness {
            liveliness.on_data(&writer_guid);
        }
        log::debug!(
            "[READER-SUB] on_dispose topic='{}' writer={:02x?} seq={} kind={:?} key_hash={:02x?}",
            self.topic,
            &writer_guid[..4],
            seq,
            kind,
            &key_hash[..4]
        );
        // A dispose or unregister moves an instance as a sample does: the
        // writer must be admitted like the writer of a sample
        // (`writer_not_admitted`, Sec.8.8.7.1, 9.4.3).
        #[cfg(feature = "security")]
        if self.writer_not_admitted(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping lifecycle change of writer={:02x?} topic='{}' seq={}: the \
                 security plugins do not admit it",
                &writer_guid[..4],
                self.topic,
                seq
            );
            return;
        }
        // And a writer this reader is not matched with moves none of its
        // instances (`writer_refused`).
        if self.writer_refused(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping lifecycle change of refused (type or QoS) writer={:02x?} \
                 topic='{}' seq={}",
                &writer_guid[..4],
                self.topic,
                seq
            );
            return;
        }
        // `writer_refused` answers false for a writer this reader has
        // never judged at all, not only for one it matched: a plain DATA
        // (D=1/Q=1) carrying inline topic, KeyHash and a disposed
        // StatusInfo defers the SAMPLE value through OWNERSHIP, but
        // reaches here independently -- a writer never discovered via
        // SEDP has no matched writer proxy (RTPS v2.5 Sec.8.4.15) and
        // must not move this reader's instance state either.
        if self.writer_undiscovered(&writer_guid) {
            log::debug!(
                "[READER-SUB] dropping lifecycle change of undiscovered writer={:02x?} \
                 topic='{}' seq={}",
                &writer_guid[..4],
                self.topic,
                seq
            );
            return;
        }

        self.apply_lifecycle(
            writer_guid,
            seq,
            key_hash,
            kind,
            crate::engine::router::route_source_ts_ns(),
        );
    }

    fn on_writer_dispose(&self, topic: &str, writer_guid: [u8; 16], kind: DisposeKind) {
        self.on_writer_departure(
            topic,
            writer_guid,
            kind,
            crate::engine::WriterDeparture::Unheard,
        );
    }

    fn on_writer_departure(
        &self,
        _topic: &str,
        writer_guid: [u8; 16],
        kind: DisposeKind,
        cause: crate::engine::WriterDeparture,
    ) {
        let _delivering = super::notices::Delivering::enter();
        let loss_epoch = self.wire_bindings.as_ref().and_then(|_| {
            let mut pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let ledger = if pending.incarnations.contains_key(&writer_guid)
                || self
                    .ack_credit
                    .as_ref()
                    .is_some_and(|credit| credit.is_matched(&writer_guid))
            {
                pending.loss_ledger(writer_guid, None, self.ack_credit.as_ref())
            } else {
                pending.losses.get(&writer_guid).cloned()
            };
            if let Some(ledger) = &ledger {
                ledger.incarnation.store(false, Ordering::Release);
            }
            ledger
        });
        let mut lost_on_departure = self.ack_credit.as_ref().map_or(0, |credit| {
            let filtered = self
                .reorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .filtered_ranges(&writer_guid);
            if let Some(ledger) = &loss_epoch {
                return credit.close_group_loss(&writer_guid, &ledger.authority, &filtered);
            }
            let owed = credit.unreceived_ranges(&writer_guid);
            self.seen_seqs_by_writer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(writer_guid)
                .or_default()
                .report_owed_in(&owed, &filtered)
        });
        // The writer's proxy goes with it (the unmatch the discovery also
        // sends is then a no-op): a writer re-created under the same GUID is
        // matched again before it is heard, and a DATA the old one sent
        // before it left is told from it (`has_left`). Unmatched first: the
        // door takes a matched proxy for a writer back.
        if let Some(credit) = self.ack_credit.as_ref() {
            credit.unmatch_writer(&writer_guid);
        }
        // The door shuts first: nothing from the writer is admitted while
        // its state goes.
        {
            let mut departed = self.departed.write();
            // Bounded: a reader that has seen this many writers leave keeps
            // only those since.
            if departed.len() >= 4096 {
                departed.clear();
            }
            let left_at = std::time::Instant::now();
            departed.insert(
                writer_guid,
                Departed {
                    left_at,
                    announced: false,
                    awaiting_heartbeat: false,
                    parked: None,
                    deleted: cause == crate::engine::WriterDeparture::Deleted,
                    losses: loss_epoch.clone(),
                },
            );
            self.departed_count
                .store(departed.len(), std::sync::atomic::Ordering::Release);
            let keep = self
                .departed_keep_ms
                .load(std::sync::atomic::Ordering::Relaxed);
            self.departed_purge_due_ms.fetch_min(
                self.departed_ms(left_at).saturating_add(keep),
                std::sync::atomic::Ordering::AcqRel,
            );
            let count = self
                .departures
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
                + 1;
            self.record_left(writer_guid, count, left_at);
        }
        // What was received from it and is thrown away below, never
        // delivered: the samples its gate held above a hole, its staged
        // coherent samples, those deferred until its OWNERSHIP was known.
        let mut discarded: Vec<u64> = {
            let mut pending = self
                .ownership_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(incarnation) = pending.incarnations.remove(&writer_guid) {
                incarnation.store(false, std::sync::atomic::Ordering::Release);
            }
            pending.losses.remove(&writer_guid);
            pending.flushing.remove(&writer_guid);
            pending.resolved.remove(&writer_guid);
            // Its stall clock and its report belong to the writer that left:
            // one that comes back under the same GUID is held afresh.
            pending.unjudged_since.remove(&writer_guid);
            pending.unjudged_reports.remove(&writer_guid);
            pending
                .take(&writer_guid)
                .unwrap_or_default()
                .into_iter()
                .map(|sample| sample.remote_seq)
                .collect()
        };
        // The samples of the writer this reader still holds, or still
        // receives (a DATA sent before the departure may land after it),
        // expire by its lifespan, which leaves with it
        // (`TopicRegistry::notify_writer_dispose` drops its record after
        // this call): this reader keeps a copy (`DepartedLifespans`).
        if let Some(lifespan_ns) = self
            .topic_registry
            .as_ref()
            .and_then(|registry| registry.writer_lifespan(&writer_guid))
        {
            self.departed_lifespans.record(writer_guid, lifespan_ns);
        }
        // Snapshot the instance set under lock, then fire dispose events
        // outside to avoid holding the tracker mutex during status-condition
        // signalling (on_dispose tries to lock dispose_events itself).
        let handles: Vec<[u8; 16]> = {
            // Retire the writer so a future SEDP-W from the same writer GUID
            // (e.g. the writer endpoint is re-created with the same id) does
            // not double-fire on stale instances. Its departure unregisters
            // what it held (DDS v1.4 Sec.2.2.3.23.3); an instance another
            // writer still holds registered keeps its writers: it moves to
            // NOT_ALIVE_NO_WRITERS only when no DataWriter is left writing it
            // (Sec.2.2.2.4.2.7, Sec.2.2.2.5.1.3). An instance the writer
            // itself unregistered earlier is not its to release again.
            self.writer_instances.retire(&writer_guid)
        };

        // Drop any coherent-set samples staged for this writer. If the
        // writer disappears before its ECS
        // marker is delivered, the staged set is never going to commit
        // and would otherwise leak memory indefinitely (no other code
        // path drains a stale per-writer buffer).
        {
            let mut buf = match self.coherent_buffer.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(dropped) = buf.remove(&writer_guid) {
                // A best-effort reader never gets them back: lost, as a set
                // it discards is (`try_commit_sets`), its members received
                // and those its end said it had.
                if (self.ack_credit.is_none() || self.wire_bindings.is_some())
                    && !dropped.is_empty()
                {
                    for sample in &dropped {
                        lost_on_departure = lost_on_departure
                            .saturating_add(self.received_staged_lost(writer_guid, sample));
                    }
                    let (ends, mut starts, others) = self
                        .pending_coherent_end
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&writer_guid)
                        .map(|e| (e.ends.clone(), e.starts.clone(), e.others.clone()))
                        .unwrap_or_default();
                    let firsts: BTreeSet<u64> =
                        dropped.iter().filter_map(|s| s.coherent_sn).collect();
                    starts.extend(firsts.iter().copied());
                    // A set's end as `try_commit_sets` reads it: the change
                    // after it (its end of set, the next set, another).
                    for &first in &firsts {
                        let after = [
                            starts.range(first.saturating_add(1)..).next().copied(),
                            others.range(first.saturating_add(1)..).next().copied(),
                            ends.get(&first).map(|end| end.saturating_add(1)),
                        ];
                        if let Some(last) = after
                            .into_iter()
                            .flatten()
                            .min()
                            .and_then(|a| a.checked_sub(1))
                        {
                            lost_on_departure = lost_on_departure
                                .saturating_add(self.never_received(writer_guid, first, last));
                        }
                    }
                }
                discarded.extend(dropped.iter().map(|sample| sample.remote_seq));
                if !dropped.is_empty() {
                    log::debug!(
                        "[READER-SUB] coherent buffer drop on writer dispose topic='{}' \
                         writer={:02x?} dropped_samples={}",
                        self.topic,
                        &writer_guid[..4],
                        dropped.len()
                    );
                }
            }
        }
        // Its best-effort sets wait no more.
        if self
            .best_effort_waiting
            .load(std::sync::atomic::Ordering::Acquire)
            != 0
        {
            let mut waits = self
                .best_effort_waits
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            waits.retain(|(writer, _), _| *writer != writer_guid);
            self.best_effort_waiting
                .store(waits.len(), std::sync::atomic::Ordering::Release);
        }
        // Nor do its sets that waited for its gate (`try_commit_sets`).
        self.forget_wait_on_gate(&writer_guid);
        // Forget what the gone writer said of where its sets end, and the
        // sets of it discarded: a writer re-created with the same GUID
        // starts its sequences again.
        self.discarded_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&writer_guid);
        self.rejected_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .writers
            .remove(&writer_guid);
        {
            let mut pend = match self.pending_coherent_end.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            pend.remove(&writer_guid);
        }
        // GROUP-scope: also evict the writer from any per-(publisher,
        // gsn) sets it participated in so a dropped writer never pins
        // a set forever. May trigger flushes for sets whose remaining
        // contributors had already closed (atomic commit per DDS
        // v1.4 sec. 2.2.3.6 is preserved across the eviction).
        discarded.extend(
            self.group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .filter_map(|set| set.per_writer.get(&writer_guid))
                .flatten()
                .map(|sample| sample.remote_seq),
        );
        self.forget_writer_in_group_sets(writer_guid);
        // Its GSN record (`writer_gsns`), the spec-dialect GROUP checks for
        // its changes: forgotten when the writer said it left, so one
        // re-created under the same GUID announces its GSNs again from its
        // own start instead of being checked for "strictly monotonically
        // increasing" (RTPS v2.5 Sec.8.7.5) against the departed
        // incarnation's. Kept when it only fell silent (`Unheard`): the same
        // writer may come back with its GSNs going on, and a wiped record
        // would let it go backwards unchecked; the record goes when the
        // departure itself is forgotten (`has_left_slow`).
        if cause == crate::engine::WriterDeparture::Deleted {
            self.writer_gsns
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&writer_guid);
        }
        // Presentation barrier membership (discovery cold path): the writer
        // is gone, so this reader stops being required for the writer's
        // publisher once its last writer unmatches -- peers can then drain
        // that publisher's residual generations instead of stalling on a
        // set this reader will never receive.
        if let (Some(barrier), Some(member)) = (self.coherent_barrier.as_ref(), self.barrier_member)
        {
            barrier.unregister_matched_writer(member, writer_guid);
        }
        // Same for the per-writer dedup admission window; a reliable reader
        // keeps it for the writer's return (below). And for its reorder
        // gate: a writer re-created under this GUID starts again at sequence
        // 1 (RTPS v2.5 Sec.8.3.5.4), and a gate still holding the old
        // writer's high-water mark would drop every sample below it as
        // delivered - and credit it to the acknowledgement, so the writer
        // would never send it again. What the gate held above a hole goes
        // with it: the hole is never repaired now, and each held sample gives
        // its history slot back. What it released is not touched: that is
        // delivered.
        //
        // Both go in one section of the gate's lock, the record under it, in
        // the order a delivery takes them (`deliver_sample`): a DATA past
        // the door before it shut is admitted before, and goes with the
        // record, or after, and finds the door shut under the gate.
        let mut retained_payloads = Vec::new();
        let (record, reliable) = {
            let mut gate = self.reorder.lock().unwrap_or_else(|e| e.into_inner());
            let payloads = gate.forget_writer_payloads(&writer_guid);
            for payload in payloads {
                if self.wire_bindings.is_some()
                    && payload.order.is_some()
                    && payload.staged.is_none()
                {
                    retained_payloads.push(payload);
                } else {
                    lost_on_departure = lost_on_departure
                        .saturating_add(self.received_payload_lost(writer_guid, &payload));
                    discarded.push(payload.remote_seq);
                }
            }
            let record = self
                .seen_seqs_by_writer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&writer_guid);
            (record, self.ack_credit.is_some() && !gate.is_best_effort())
        };
        if let Some(ledger) = &loss_epoch {
            lost_on_departure = lost_on_departure.saturating_add(ledger.take_pending());
        }
        self.report_sample_lost(lost_on_departure);
        if !retained_payloads.is_empty() {
            let lock = self.writer_delivery_lock(writer_guid);
            let delivery = lock.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(panic) = self.deliver_in_order(writer_guid, retained_payloads, &delivery) {
                std::panic::resume_unwind(panic);
            }
        }
        // The PARTITION and OWNERSHIP verdicts were reached on this writer's
        // QoS: a successor under its GUID is judged on its own. Samples
        // deferred until its OWNERSHIP was known are the old writer's.
        self.partition_verdict.forget(&writer_guid);
        self.ownership_verdict
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&writer_guid);
        // A reliable reader keeps what it received from the writer, for the
        // writer's return (`heartbeat_verdict`), but what was thrown away
        // above: received, never delivered, it is to be received again,
        // and the acknowledgement must not credit what the reader does not
        // have. Not from a writer that said it left (its SEDP dispose, its
        // participant's): one seen again under its GUID is a new writer,
        // whose changes the old record would drop as delivered whenever its
        // first HEARTBEAT reaches the old one's highest.
        let returns = cause == crate::engine::WriterDeparture::Unheard;
        if let Some(mut record) = record.filter(|_| reliable && returns) {
            for seq in discarded {
                record.unmark(seq);
            }
            if let Some(high) = record.high {
                if let Some(entry) = self.departed.write().get_mut(&writer_guid) {
                    entry.parked = Some((record, high));
                    entry.awaiting_heartbeat = true;
                }
            }
        }
        // Its delivery lock: a writer that comes back under the GUID takes
        // a new one. A thread still delivering for the old writer keeps its
        // Arc until it is done.
        self.delivery_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&writer_guid);

        if handles.is_empty() {
            log::debug!(
                "[READER-SUB] on_writer_dispose topic='{}' writer={:02x?} kind={:?} \
                 no instances tracked -- no-op",
                self.topic,
                &writer_guid[..4],
                kind
            );
            return;
        }

        log::debug!(
            "[READER-SUB] on_writer_dispose topic='{}' writer={:02x?} kind={:?} \
             firing {} per-instance dispose events",
            self.topic,
            &writer_guid[..4],
            kind,
            handles.len()
        );

        // RTPS sequence number for synthesized events is 0: the SEDP-W
        // packet has its own writer SN tracked elsewhere; for the user-data
        // queue we have no meaningful per-sample seq to attach. That is what
        // the APPLICATION sees, and it is unchanged.
        //
        // For ORDERING it is the wrong end of the stream: this writer is gone,
        // so its transition happened after everything it ever sent, and a 0
        // would jump it ahead of the samples still queued. `u64::MAX` puts it
        // where it belongs. The writer is known here, so it is passed rather
        // than looked up - the tracker entry was just drained above, and a
        // lookup would find nothing.
        for key_hash in handles {
            // Synthesized, not received: no source timestamp exists for it
            // (see `DisposeEvent::source_timestamp_ns`).
            self.queue_transition(key_hash, kind, 0, Some(writer_guid), u64::MAX, None);
        }
    }

    fn topic_name(&self) -> &str {
        &self.topic
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ring_keys_cover_the_ring_until_a_push() {
        let key = |n: u8| Some([n; 16]);
        let mut keys = super::RingKeys::default();
        keys.record(vec![key(1), key(2), key(3)]);
        assert_eq!(
            keys.take(2),
            Some(vec![key(2), key(3)]),
            "the front was popped"
        );
        keys.record(vec![key(2), key(3)]);
        assert_eq!(keys.take(3), None, "more entries than keys");
        keys.record(vec![key(2), key(3)]);
        keys.pushed();
        assert_eq!(keys.take(1), None, "a push since");
        assert_eq!(keys.take(0), None, "taken once");
    }

    use super::{Missed, Seen, SeenSeqs, SeqWindow};

    fn nobody() -> Option<u64> {
        None
    }

    fn runs(seen: &SeenSeqs) -> Vec<(u64, u64)> {
        seen.missed.iter().map(|(&s, &e)| (s, e)).collect()
    }

    /// Admit every sequence of `seqs`, each new.
    fn admit_all(seen: &mut SeenSeqs, missed: Missed, seqs: impl IntoIterator<Item = u64>) {
        for seq in seqs {
            assert_eq!(seen.admit(seq, missed, nobody), Seen::New, "{seq}");
        }
    }

    const W: u64 = SeenSeqs::WINDOW;

    #[test]
    fn the_words_hold_the_window() {
        assert_eq!(u64::try_from(SeenSeqs::WORDS).expect("small") * 64, W);
    }

    #[test]
    fn a_forgotten_admission_is_admitted_again() {
        let mut seen = SeenSeqs::default();
        admit_all(&mut seen, Missed::All, [1, 5000]);
        seen.forget(5000);
        assert_eq!(seen.admit(5000, Missed::All, nobody), Seen::New, "resent");
        seen.forget(5000);
        // Refused, 5000 was never received: the window it moved up leaves
        // the sequences below it owed, not seen.
        assert_eq!(seen.admit(2, Missed::All, nobody), Seen::New);
        assert_eq!(seen.admit(2, Missed::All, nobody), Seen::Duplicate);
        assert_eq!(seen.admit(1, Missed::All, nobody), Seen::Duplicate);
    }

    /// After 1..=WINDOW+1 in order the floor is 1 itself, which
    /// was neither below the floor nor in the recent window: admitted twice.
    #[test]
    fn the_window_floor_is_seen_not_new() {
        for missed in [Missed::Dropped, Missed::All] {
            let mut seen = SeenSeqs::default();
            admit_all(&mut seen, missed, 1..=W + 1);
            assert_eq!(seen.admit(1, missed, nobody), Seen::Duplicate, "{missed:?}");
            assert_eq!(seen.admit(2, missed, nobody), Seen::Duplicate, "{missed:?}");
        }
    }

    /// A reliable reader missed 2 and received a whole window above
    /// it. The repair is not a duplicate: dropping it, and crediting it as
    /// received with every duplicate, lost it for good.
    #[test]
    fn a_repair_older_than_the_window_is_admitted_once() {
        let mut seen = SeenSeqs::default();
        admit_all(&mut seen, Missed::All, [1]);
        admit_all(&mut seen, Missed::All, 3..=3 * W);
        assert_eq!(seen.admit(2, Missed::All, nobody), Seen::New, "owed");
        assert_eq!(seen.admit(2, Missed::All, nobody), Seen::Duplicate);
        assert_eq!(seen.admit(3, Missed::All, nobody), Seen::Duplicate);
        assert_eq!(seen.admit(1, Missed::All, nobody), Seen::Duplicate);
        // The floor itself: its slot is the newest sequence's.
        let mut seen = SeenSeqs::default();
        admit_all(&mut seen, Missed::All, [1]);
        admit_all(&mut seen, Missed::All, 3..=W + 2);
        assert_eq!(seen.admit(2, Missed::All, nobody), Seen::New, "the floor");
    }

    /// Moving up by less than a window, the sequences entering it take the
    /// slots of those leaving it: they enter unadmitted.
    #[test]
    fn a_sequence_entering_the_window_is_not_one_that_left_it() {
        let mut seen = SeenSeqs::default();
        admit_all(&mut seen, Missed::All, 1..=W);
        admit_all(&mut seen, Missed::All, [W + 10]);
        admit_all(&mut seen, Missed::All, W + 1..W + 10);
        assert_eq!(seen.admit(10, Missed::All, nobody), Seen::Duplicate);
        assert_eq!(seen.admit(11, Missed::All, nobody), Seen::Duplicate);
    }

    /// A sequence is reported lost once, in or out of order, and past the
    /// range bound too (folded into the floor: never counted again).
    #[test]
    fn a_sequence_is_reported_lost_once() {
        let mut lost = super::LostReported::default();
        assert_eq!(lost.report(10, 12), 2);
        assert_eq!(lost.report(12, 13), 1, "appended at the back");
        assert_eq!(lost.report(5, 11), 5, "below and over the first range");
        assert_eq!(lost.report(4, 20), 8, "4, and 13..20");
        assert_eq!(lost.report(4, 20), 0);
        let mut capped = super::LostReported::default();
        for k in 0..2 * super::MAX_LOST_RANGES as u64 {
            assert_eq!(capped.report(2 * k, 2 * k + 1), 1);
        }
        for k in 0..2 * super::MAX_LOST_RANGES as u64 {
            assert_eq!(capped.report(2 * k, 2 * k + 1), 0, "{k}: reported twice");
        }
        assert!(capped.ranges.len() <= super::MAX_LOST_RANGES);
    }

    /// Reports near the top of the sequence space, and reports in
    /// decreasing order past the range bound: each sequence counted once.
    #[test]
    fn a_report_is_counted_once_in_any_order() {
        let mut lost = super::LostReported::default();
        assert_eq!(lost.report(u64::MAX - 2, u64::MAX), 2);
        assert_eq!(lost.report(u64::MAX - 3, u64::MAX), 1);
        let mut lost = super::LostReported::default();
        let mut total = 0;
        for k in (0..300u64).rev() {
            total += lost.report(10 * k, 10 * k + 1);
        }
        assert_eq!(total, 300, "a fold above the reports took the next ones");
        let again: u64 = (0..300u64).map(|k| lost.report(10 * k, 10 * k + 1)).sum();
        assert_eq!(again, 0, "reported twice");
        assert!(lost.ranges.len() <= super::MAX_LOST_RANGES);
    }

    /// The window's edges: the floor below it, its first and last slots.
    #[test]
    fn unreceived_runs_at_the_window_edges() {
        let mut seen = SeenSeqs::default();
        admit_all(
            &mut seen,
            Missed::All,
            (1..=5000u64).filter(|s| *s != 904 && *s != 905 && *s != 4999),
        );
        assert_eq!(SeenSeqs::floor(5000), 904);
        assert_eq!(seen.unreceived_in(900, 910), vec![(904, 906)]);
        assert_eq!(seen.unreceived_in(904, 905), vec![(904, 905)]);
        assert_eq!(seen.unreceived_in(905, 906), vec![(905, 906)]);
        assert_eq!(
            seen.unreceived_in(4998, 5002),
            vec![(4999, 5000), (5001, 5002)]
        );
    }

    /// A sequence taken back is not received any more, in the window and
    /// below it (a missed run takes it, joined with its neighbours).
    #[test]
    fn a_sequence_taken_back_is_not_received_any_more() {
        let mut seen = SeenSeqs::default();
        admit_all(&mut seen, Missed::All, 1..=5000);
        seen.unmark(4990);
        seen.unmark(100);
        seen.unmark(102);
        seen.unmark(101);
        assert_eq!(seen.unreceived_in(1, 5001), vec![(100, 103), (4990, 4991)]);
        assert_eq!(seen.missed.len(), 1, "one run, joined with both neighbours");
        assert_eq!(seen.admit(101, Missed::All, nobody), Seen::New);
    }

    /// The sequences never received, as ranges: the missed runs below the
    /// window, the unmarked bits within it, everything above it.
    #[test]
    fn unreceived_runs_are_read_below_within_and_above_the_window() {
        let mut seen = SeenSeqs::default();
        admit_all(
            &mut seen,
            Missed::All,
            (1..=10).filter(|s| *s != 4 && *s != 5),
        );
        admit_all(&mut seen, Missed::All, [5000]);
        assert_eq!(
            seen.unreceived_in(1, 6000),
            vec![(4, 6), (11, 5000), (5001, 6000)]
        );
        assert_eq!(seen.unreceived_in(5, 12), vec![(5, 6), (11, 12)]);
        assert_eq!(seen.unreceived_in(6, 11), Vec::<(u64, u64)>::new());
        assert_eq!(SeenSeqs::default().unreceived_in(3, 7), vec![(3, 7)]);
    }

    /// A best-effort reader is owed nothing: below its window it drops.
    #[test]
    fn a_best_effort_reader_drops_below_its_window() {
        let mut seen = SeenSeqs::default();
        admit_all(&mut seen, Missed::Dropped, [1]);
        admit_all(&mut seen, Missed::Dropped, 3..=2 * W);
        assert_eq!(seen.admit(2, Missed::Dropped, nobody), Seen::Duplicate);
        assert!(seen.missed.is_empty());
    }

    /// A reader joining a writer whose sequences already run high is owed
    /// what precedes its first sample, until its proxy settles it: what a
    /// VOLATILE reader must not deliver is its gate's call, where the join
    /// point is known (a GAP can set it before any DATA).
    #[test]
    fn a_late_joiner_is_owed_what_precedes_its_first_sample() {
        let floor = 10_000 - W;
        let mut seen = SeenSeqs::default();
        admit_all(&mut seen, Missed::All, [10_000]);
        for seq in [1, floor, floor + 1, 9_999] {
            assert_eq!(seen.admit(seq, Missed::All, nobody), Seen::New, "{seq}");
            assert_eq!(seen.admit(seq, Missed::All, nobody), Seen::Duplicate);
        }
        assert_eq!(
            seen.admit(2, Missed::All, || Some(3_000)),
            Seen::Duplicate,
            "settled"
        );
        assert_eq!(runs(&seen), vec![(3_001, floor - 1)]);
    }

    /// What the writer proxy no longer awaits (a GAP, a HEARTBEAT past it)
    /// is no longer owed: a copy of it is a duplicate, asked the moment it
    /// arrives.
    #[test]
    fn a_run_the_proxy_settled_is_no_longer_owed() {
        let mut seen = SeenSeqs::default();
        admit_all(&mut seen, Missed::All, [1]);
        admit_all(&mut seen, Missed::All, 4..=W + 10);
        assert_eq!(runs(&seen), vec![(2, 3)], "left one by one, one run");
        // The proxy now awaits nothing up to 2.
        assert_eq!(seen.admit(2, Missed::All, || Some(2)), Seen::Duplicate);
        assert_eq!(runs(&seen), vec![(3, 3)]);
        assert_eq!(seen.admit(3, Missed::All, || Some(2)), Seen::New);
        assert!(seen.missed.is_empty());
    }

    /// A repair admitted below the window and then refused is owed again,
    /// in the run it was taken from.
    #[test]
    fn a_refused_repair_below_the_window_is_owed_again() {
        let mut seen = SeenSeqs::default();
        admit_all(&mut seen, Missed::All, [1, 5]);
        admit_all(&mut seen, Missed::All, 6..=2 * W);
        for seq in [3, 2, 4] {
            assert_eq!(seen.admit(seq, Missed::All, nobody), Seen::New);
            seen.forget(seq);
        }
        assert_eq!(runs(&seen), vec![(2, 4)], "forgotten back into one run");
        admit_all(&mut seen, Missed::All, [2, 3, 4]);
        assert!(seen.missed.is_empty());
    }

    /// Every even sequence missed: one run each. Fill the record to its
    /// bound.
    fn full_record() -> (SeenSeqs, u64) {
        let mut seen = SeenSeqs::default();
        let bound = u64::try_from(SeenSeqs::MISSED_RUNS).expect("small");
        let top = W + 2 * bound + 1;
        admit_all(&mut seen, Missed::All, (1..=top).step_by(2));
        assert_eq!(seen.missed.len(), SeenSeqs::MISSED_RUNS);
        (seen, top)
    }

    /// The record of owed runs is bounded, and at its bound it refuses the
    /// sample that would push an owed run out; nothing owed is forgotten.
    #[test]
    fn a_full_record_refuses_rather_than_forgets() {
        let (mut seen, top) = full_record();
        assert_eq!(seen.admit(top + 2, Missed::All, nobody), Seen::Full);
        assert_eq!(seen.high, Some(top), "refused, nothing recorded");
        assert_eq!(seen.admit(2, Missed::All, nobody), Seen::New, "still owed");
        assert_eq!(
            seen.admit(top + 2, Missed::All, nobody),
            Seen::New,
            "room again"
        );
        assert_eq!(seen.missed.len(), SeenSeqs::MISSED_RUNS);
        assert_eq!(
            seen.admit(top + 1, Missed::All, nobody),
            Seen::New,
            "in window"
        );
    }

    /// At the bound, the proxy is asked before refusing: what it settled
    /// makes room.
    #[test]
    fn a_full_record_asks_the_proxy_before_refusing() {
        let (mut seen, top) = full_record();
        assert_eq!(seen.admit(top + 2, Missed::All, || Some(4)), Seen::New);
        assert_eq!(
            seen.admit(2, Missed::All, nobody),
            Seen::Duplicate,
            "settled"
        );
    }

    /// Taking a repair out of the middle of a run splits it in two: at the
    /// bound that is refused too.
    #[test]
    fn a_split_at_the_bound_is_refused() {
        let mut seen = SeenSeqs::default();
        let bound = u64::try_from(SeenSeqs::MISSED_RUNS).expect("small");
        // One run (1..=floor) below a late joiner's first sample.
        admit_all(&mut seen, Missed::All, [W + 3 * bound]);
        assert_eq!(runs(&seen).len(), 1);
        let mut seq = 2;
        while seen.missed.len() < SeenSeqs::MISSED_RUNS {
            assert_eq!(seen.admit(seq, Missed::All, nobody), Seen::New);
            seq += 2;
        }
        assert_eq!(seen.admit(seq, Missed::All, nobody), Seen::Full);
        assert_eq!(
            seen.admit(seq - 1, Missed::All, nobody),
            Seen::New,
            "an edge, no split"
        );
        assert_eq!(seen.missed.len(), SeenSeqs::MISSED_RUNS);
    }

    #[test]
    fn what_a_reader_is_owed_follows_its_qos() {
        assert_eq!(Missed::owed(false), Missed::Dropped);
        assert_eq!(Missed::owed(true), Missed::All);
    }

    /// At the bound, a sequence leaving the window next to the last owed
    /// run extends it: no new run, not refused.
    #[test]
    fn a_full_record_takes_what_extends_its_last_run() {
        let bound = u64::try_from(SeenSeqs::MISSED_RUNS).expect("small");
        let mut seen = SeenSeqs::default();
        // One run per even up to 2 * bound - 2, then 2 * bound and
        // 2 * bound + 1 missed too, the latter still in the window.
        admit_all(&mut seen, Missed::All, (1..2 * bound).step_by(2));
        admit_all(&mut seen, Missed::All, 2 * bound + 2..=2 * bound + W);
        assert_eq!(seen.missed.len(), SeenSeqs::MISSED_RUNS);
        assert_eq!(
            seen.admit(2 * bound + W + 1, Missed::All, nobody),
            Seen::New
        );
        assert_eq!(seen.missed.len(), SeenSeqs::MISSED_RUNS);
        assert_eq!(runs(&seen).last(), Some(&(2 * bound, 2 * bound + 1)));
    }

    /// A record past its bound (a refused repair taken back below the
    /// window) still takes a sample that leaves no new run behind.
    #[test]
    fn a_record_past_its_bound_takes_what_adds_no_run() {
        let bound = u64::try_from(SeenSeqs::MISSED_RUNS).expect("small");
        let mut seen = SeenSeqs::default();
        // 1..=10_000, then only odd sequences: one run per even one, the
        // bound reached exactly.
        let top = 10_001 + 2 * bound + W;
        admit_all(&mut seen, Missed::All, 1..=10_000);
        admit_all(&mut seen, Missed::All, (10_001..=top).step_by(2));
        assert_eq!(seen.missed.len(), SeenSeqs::MISSED_RUNS);
        // Admitted long ago, taken back: one run past the bound.
        seen.forget(5_000);
        assert_eq!(seen.missed.len(), SeenSeqs::MISSED_RUNS + 1);
        // The window moves up over an admitted sequence: nothing added.
        let floor = top - W;
        admit_all(&mut seen, Missed::All, [floor + 1]);
        assert_eq!(seen.admit(top + 1, Missed::All, nobody), Seen::New);
    }

    #[test]
    fn sequences_at_the_top_of_the_range() {
        let mut seen = SeenSeqs::default();
        let top = u64::MAX;
        admit_all(&mut seen, Missed::All, [top - 2 * W, top - 1]);
        assert_eq!(seen.admit(top, Missed::All, nobody), Seen::New);
        assert_eq!(seen.admit(top, Missed::All, nobody), Seen::Duplicate);
        assert_eq!(seen.admit(top - W, Missed::All, nobody), Seen::New, "owed");
        assert_eq!(
            seen.admit(top - 2 * W, Missed::All, nobody),
            Seen::Duplicate
        );
    }

    #[test]
    fn seq_window_maps_initial_and_monotonic_increase() {
        let mut window = SeqWindow::new();
        assert_eq!(window.map(100), Some(0));
        assert_eq!(window.map(101), Some(1));
        assert_eq!(window.map(110), Some(10));
    }

    #[test]
    fn seq_window_reinits_for_lower_seq() {
        // When a sequence < base arrives, it might be from a new writer.
        // The window re-initializes to accommodate.
        let mut window = SeqWindow::new();
        assert_eq!(window.map(50), Some(0));
        // Lower seq triggers re-init (possible new writer)
        assert_eq!(window.map(49), Some(0));
    }

    #[test]
    fn seq_window_handles_large_stride() {
        let mut window = SeqWindow::new();
        let base = 1u64 << 32;
        let second = 2 * base;
        let third = 3 * base;

        // First sequence initializes base at 2^32 -> local 0
        assert_eq!(window.map(base), Some(0));
        // Second sequence sets stride = 2^32 -> local 1
        assert_eq!(window.map(second), Some(1));
        // Third sequence uses same stride -> local 2
        assert_eq!(window.map(third), Some(2));
    }

    #[test]
    fn seq_window_rejects_non_aligned_large_seq() {
        let mut window = SeqWindow::new();
        let base = 1u64 << 32;
        let stride = 1u64 << 32;

        // Initialize base
        assert_eq!(window.map(base), Some(0));
        // Establish stride
        assert_eq!(window.map(base + stride), Some(1));
        // Non-aligned sequence should be dropped
        assert_eq!(window.map(base + stride + 1), None);
    }

    /// The end GSN follows every member GSN (RTPS v2.5 Sec.8.7.6, D2).
    /// Metadata can arrive repeatedly before refused DATA is admitted;
    /// retaining only the maximum validates this rule with fixed storage.
    #[test]
    fn group_metadata_keeps_the_greatest_member_gsn_with_fixed_storage() {
        use super::{CoherentConfig, MAX_STAGED_PER_GROUP};
        use crate::dds::reader::tests_history_limits::{Keyed, NetworkReader};
        let net = NetworkReader::<Keyed>::with_parts(
            "group-metadata-summary",
            crate::dds::QoS::reliable().keep_all(),
            super::super::reorder::ReorderGate::new(true, false),
            crate::qos::ownership::OwnershipKind::default(),
            CoherentConfig {
                coherent_access: true,
                is_group_scope: true,
            },
        );
        let writer = [0x53; 16];
        let publisher = [0, 0, 1, 8];
        let key = ([0x53; 12], publisher, 1);
        let top = 10 * MAX_STAGED_PER_GROUP as u64;
        // Arrive in reverse sequence order, with repairs of each metadata
        // change before its DATA is admitted: every (SN, GSN) is valid.
        for seq in (1..=top).rev() {
            for _ in 0..2 {
                net.subscriber.note_group_change(
                    key,
                    writer,
                    crate::engine::GroupChange {
                        seq,
                        group_sn: 1,
                        publisher_entity_id: publisher,
                        writer_set: [1; 4],
                        gsn: Some(seq),
                        part_first_sn: None,
                    },
                );
            }
        }
        {
            let sets = net.subscriber.group_coherent_buffer.lock().expect("sets");
            assert_eq!(sets.len(), 1);
            let set = sets.get(&key).expect("metadata");
            assert_eq!(set.max_member_gsn, Some(top));
            assert!(!set.gsn_broken, "reordered metadata and repairs are valid");
        }
        // An end equal to an earlier, greater member GSN is invalid even
        // though the most recently received member had a lower GSN.
        let mut idle = writer;
        idle[15] += 1;
        net.subscriber.note_group_change(
            key,
            idle,
            crate::engine::GroupChange {
                seq: 1,
                group_sn: 1,
                publisher_entity_id: publisher,
                writer_set: [1; 4],
                gsn: Some(top),
                part_first_sn: Some(1),
            },
        );
        assert!(
            net.subscriber
                .group_coherent_buffer
                .lock()
                .expect("sets")
                .get(&key)
                .expect("metadata")
                .gsn_broken
        );
    }

    /// A decided set's entry is removed before its final discard record
    /// is published. A member already admitted in that interval cannot
    /// create another buffer entry or deliver a second part of the set.
    #[test]
    fn group_member_retired_while_inflight_cannot_reopen_its_set() {
        use crate::dds::reader::tests_history_limits::{encoded, Keyed, NetworkReader};
        use crate::engine::Subscriber as _;
        let net = NetworkReader::<Keyed>::with_parts(
            "group-inflight-retirement",
            crate::dds::QoS::reliable().keep_all(),
            super::super::reorder::ReorderGate::new(true, false),
            crate::qos::ownership::OwnershipKind::default(),
            super::CoherentConfig {
                coherent_access: true,
                is_group_scope: true,
            },
        );
        let writer = [0x53; 16];
        let publisher = [0, 0, 1, 8];
        let key = ([0x53; 12], publisher, 1);
        net.subscriber.on_writer_heartbeat(writer, 1);
        net.subscriber
            .group_coherent_buffer
            .lock()
            .expect("sets")
            .entry(key)
            .or_default()
            .per_writer
            .entry(writer)
            .or_default();
        let data = encoded(&Keyed { id: 1, value: 1 });
        let (prepared, charge) = match net.subscriber.prepare_staged(
            writer,
            1,
            Some(&data),
            crate::dds::CdrVersion::Xcdr2,
            super::StagedSet::Group(key),
            true,
        ) {
            Ok(held) => held,
            Err(_) => panic!("fixture has room"),
        };
        // The deciding thread removes the reserved set, with its final
        // tombstone publication still pending outside the buffer lock.
        net.subscriber
            .group_coherent_buffer
            .lock()
            .expect("sets")
            .remove(&key);
        net.subscriber.stage_group_sample(
            writer,
            1,
            prepared,
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            1,
            publisher,
            None,
            Some(charge),
            None,
        );
        assert!(net
            .subscriber
            .group_coherent_buffer
            .lock()
            .expect("sets")
            .is_empty());
        assert!(net.take_all().is_empty());
        assert_eq!(
            net.lost(),
            1,
            "the admitted member is reported through normal discard"
        );
    }
}

#[cfg(test)]
mod deferred_wire_kind_tests {
    use super::*;

    #[test]
    fn a_deferred_frame_keeps_its_own_coherent_kind_across_a_later_route() {
        let writer = [0xA1; 16];
        let change = crate::engine::router::OrderedGroupChange {
            publisher: [0xA2; 16],
            gsn: 4,
            writer_set: [1; 4],
        };
        let sample = {
            let _scope = crate::engine::router::OrderedGroupScope::enter_with_set(
                writer,
                2,
                Some(change),
                Some(3),
            );
            PendingOwnershipSample::capture(
                writer,
                2,
                &[],
                crate::dds::CdrVersion::Xcdr2,
                true,
                Arc::new(crate::core::reader::AdmissionFrame::new(true)),
            )
        };
        let other = crate::engine::router::OrderedGroupChange { gsn: 100, ..change };
        let _later = crate::engine::router::OrderedGroupScope::enter_with_set(
            writer,
            99,
            Some(other),
            Some(90),
        );
        {
            let _restored = crate::engine::router::OrderedGroupScope::enter_with_set(
                writer,
                sample.remote_seq,
                sample.order,
                sample.set_first_gsn,
            );
            assert_eq!(
                crate::engine::router::route_ordered_group_set_first(change),
                Some(3),
                "deferred coherent DATA was reclassified as an ordinary header"
            );
        }
        assert_eq!(
            crate::engine::router::route_ordered_group_set_first(other),
            Some(90)
        );
    }
}
