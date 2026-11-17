// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Middleware-level match notification (DDS spec 2.2.2.4).
//!
//! Bridges discovery events to writer/reader listeners, firing
//! `on_publication_matched` and `on_subscription_matched` callbacks
//! when compatible remote endpoints are discovered.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

use crate::core::discovery::multicast::{
    DiscoveryFsm, DiscoveryListener, EndpointInfo, EndpointKind,
};
use crate::core::discovery::Matcher;
use crate::core::discovery::GUID;
use crate::dds::qos::{Durability, QoS, Reliability};
use crate::transport::shm::{select_transport, ShmPolicy, TransportSelection};
use crate::xtypes::CompleteTypeObject;

/// Type-erased match callback.
/// Args: (total_count, total_count_change, current_count, current_count_change, last_remote_guid)
type MatchCallback = Box<dyn Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync>;

/// A remote endpoint joining or leaving a local entry's match set, with
/// what the local endpoint needs to keep per-peer state: the RTPS
/// StatefulWriter keeps one ReaderProxy per matched reader, added by
/// `matched_reader_add` and dropped by `matched_reader_remove` (RTPS 2.5
/// 8.4.7.4), and only a reliable reader acknowledges anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerChange {
    /// The remote endpoint matched; `reliable` is its RELIABILITY kind,
    /// `volatile` whether its DURABILITY kind is VOLATILE: a VOLATILE reader
    /// is owed nothing written before it matched (DDS 1.4 2.2.3.4).
    Matched {
        guid: GUID,
        reliable: bool,
        volatile: bool,
    },
    /// The remote endpoint no longer matches.
    Unmatched { guid: GUID },
}

/// Type-erased per-peer callback, see [`PeerChange`].
pub(crate) type PeerCallback = Box<dyn Fn(PeerChange) + Send + Sync>;

/// A remote writer joining or leaving a local reader's match set, with the
/// LIVELINESS it offers (DDS v1.4 Sec.2.2.3.11): the reader keeps one lease
/// per matched writer. `local`: a writer of the reader's participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LivelinessPeer {
    Matched {
        guid: GUID,
        liveliness: crate::dds::qos::Liveliness,
        local: bool,
    },
    Unmatched {
        guid: GUID,
    },
}

/// Type-erased liveliness hook of a reader entry, see [`LivelinessPeer`].
pub(crate) type LivelinessHook = Box<dyn Fn(LivelinessPeer) + Send + Sync>;

/// Type-erased incompatible QoS callback.
/// Args: (total_count, total_count_change, last_policy_id)
type IncompatibleCallback = Box<dyn Fn(u32, i32, u32) + Send + Sync>;

/// Type-erased inconsistent-topic callback.
/// Args: (total_count, total_count_change)
/// Fired when a remote endpoint on the same topic carries a type that is
/// structurally incompatible with the local endpoint's type per
/// DDS-XTypes v1.3 sec. 7.6.3.4.3.
type InconsistentTopicCallback = Box<dyn Fn(u32, i32) + Send + Sync>;

/// A remote endpoint matched with an entry.
#[derive(Debug, Clone, Copy)]
struct MatchedRemote {
    /// The transport verdict, resolved once for the pairing.
    transport: TransportSelection,
    /// Identity of this match event, stable across repeat notices.
    #[cfg_attr(not(feature = "security"), allow(dead_code))]
    generation: u64,
    /// The incarnation of the remote's discovery record the match was made
    /// on (`EndpointInfo::incarnation`).
    incarnation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalKind {
    Writer,
    Reader,
}

/// Why a local reader refuses a remote writer in the data-plane gate
/// (`MatchNotificationRegistry::refused_pairs`): its type verdict, its QoS
/// verdict, or both. Each verdict is judged and lifted on its own events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refusal(u8);

impl Refusal {
    const NONE: Self = Self(0);
    /// The type verdict (`pairing_type_verdict`, DDS-XTypes v1.3
    /// Sec.7.6.3.4).
    const TYPE: Self = Self(1);
    /// The QoS verdict (`rxo_verdict`, DDS v1.4 Sec.2.2.3).
    const QOS: Self = Self(2);

    fn has(self, reason: Self) -> bool {
        self.0 & reason.0 != 0
    }

    fn with(self, reason: Self) -> Self {
        Self(self.0 | reason.0)
    }

    fn without(self, reason: Self) -> Self {
        Self(self.0 & !reason.0)
    }
}

/// A remote writer as the QoS verdict reads it
/// (`MatchNotificationRegistry::judged_writers`): the topic it announced and
/// its QoS as the verdict reads a remote announcement
/// (`remote_qos_for_verdict`).
struct JudgedWriter {
    topic: String,
    qos: QoS,
    /// The writer's type at its judgment, retained with its QoS when its
    /// announcement is held or its participant falls silent.
    type_object: Option<CompleteTypeObject>,
    /// The type name the writer announced (SEDP `type_name`), kept with its
    /// type for the Step 2 comparison.
    type_name: String,
    /// Whether the writer announced a type hash it has no TypeObject for yet
    /// (`TypeState::Pending`) at its judgment.
    type_pending: bool,
}

/// What a local endpoint hands the match registry about its type besides
/// the XCDR1 encoding it negotiates: the type name it announces on the wire,
/// which Step 2 of DDS-XTypes v1.3 Sec.7.6.3.4.2 compares exactly. Made from
/// a `TypeDescriptor` (its own name), or from an encoding alone (an empty
/// name, for a caller that carries no type).
#[derive(Debug)]
pub(crate) struct LocalType {
    encoding: crate::dds::cdr_negotiation::Xcdr1Encoding,
    type_name: String,
}

impl LocalType {
    /// A local type announcing `type_name`, negotiated as `encoding`. Pass
    /// the name the endpoint announces in SEDP (its override, if it has one).
    pub(crate) fn new(
        encoding: crate::dds::cdr_negotiation::Xcdr1Encoding,
        type_name: impl Into<String>,
    ) -> Self {
        Self {
            encoding,
            type_name: type_name.into(),
        }
    }
}

/// Test builds only, as `Xcdr1Encoding::from(&TypeDescriptor)` is: production
/// registers a type with `LocalType::new`, which carries its announced name.
#[cfg(test)]
impl From<&'static crate::core::types::TypeDescriptor> for LocalType {
    fn from(desc: &'static crate::core::types::TypeDescriptor) -> Self {
        Self::new(
            crate::dds::cdr_negotiation::Xcdr1Encoding::from(desc),
            desc.type_name,
        )
    }
}

impl From<crate::dds::cdr_negotiation::Xcdr1Encoding> for LocalType {
    fn from(encoding: crate::dds::cdr_negotiation::Xcdr1Encoding) -> Self {
        Self::new(encoding, "")
    }
}

/// Where a side of a pairing stands on its type, the three states the type
/// verdict distinguishes (`pairing_type_verdict_in`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeState {
    /// No TypeObject, and none announced by hash: the SEDP carried no
    /// TypeInformation the registry can ask a TypeObject for.
    Absent,
    /// A complete TypeIdentifier was announced and its TypeObject has not
    /// arrived (no TypeLookup reply yet, or none asked for).
    Pending,
    /// A TypeObject is available (inline, or resolved from the local store
    /// or a TypeLookup reply).
    Known,
}

/// One side of a pairing as the type verdict reads it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TypeSide<'a> {
    /// The side's TypeObject as discovery knows it now, if any.
    pub(crate) object: Option<&'a CompleteTypeObject>,
    /// The type name as announced on the wire, compared exactly by Step 2.
    pub(crate) name: &'a str,
    /// The side announced a complete TypeIdentifier it has no TypeObject for
    /// yet. Only meaningful when `object` is `None`.
    pub(crate) pending: bool,
}

impl TypeSide<'_> {
    /// The state of this side (see [`TypeState`]).
    pub(crate) fn state(&self) -> TypeState {
        if self.object.is_some() {
            TypeState::Known
        } else if self.pending {
            TypeState::Pending
        } else {
            TypeState::Absent
        }
    }
}

/// The local entry as a side of the verdict: its own TypeObject and the
/// name it announces. A local type is what its code declares, so it is
/// never Pending.
fn entry_side(entry: &MatchEntry) -> TypeSide<'_> {
    TypeSide {
        object: entry.type_object.as_ref(),
        name: &entry.type_name,
        pending: false,
    }
}

/// A remote endpoint as a side of the verdict, judged by `object` (its
/// `effective_type_object`). It is Pending when it announced a complete
/// TypeIdentifier and `object` is `None`.
fn remote_side<'a>(
    remote: &'a EndpointInfo,
    object: Option<&'a CompleteTypeObject>,
) -> TypeSide<'a> {
    TypeSide {
        object,
        name: &remote.type_name,
        pending: object.is_none() && remote.announced_complete_hash().is_some(),
    }
}

/// How Step 2 of DDS-XTypes v1.3 Sec.7.6.3.4.2 (the exact type-name
/// comparison for a pairing with a side that has no TypeObject) is applied.
/// Read once per process from `HDDS_TYPE_NAME_MATCH` (`type_name_match_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeNameMatch {
    /// No type-name comparison: such a pairing is judged as it was before
    /// Step 2 existed (matched, unless the reader forces type validation).
    Off,
    /// Matched exactly as `Off`. A pairing Step 2 would refuse is logged
    /// once per (topic, writer type name, reader type name) and counted
    /// (`type_name_warning_count`).
    Warn,
    /// Step 2 applied: the type names must be equal and the reader must not
    /// force type validation. A pairing it refuses is no match, and is
    /// reported as an inconsistent topic like any other type mismatch.
    Enforce,
}

impl TypeNameMatch {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "warn" => Some(Self::Warn),
            "enforce" => Some(Self::Enforce),
            _ => None,
        }
    }
}

/// The Step 2 mode of this process, from `HDDS_TYPE_NAME_MATCH`
/// (`off`, `warn` or `enforce`, case-insensitive), read once. Unset or empty
/// is `warn`, the default; an unknown value is `warn` as well, and logged.
pub(crate) fn type_name_match_mode() -> TypeNameMatch {
    static MODE: OnceLock<TypeNameMatch> = OnceLock::new();
    *MODE.get_or_init(|| {
        let Ok(raw) = std::env::var("HDDS_TYPE_NAME_MATCH") else {
            return TypeNameMatch::Warn;
        };
        if raw.trim().is_empty() {
            return TypeNameMatch::Warn;
        }
        TypeNameMatch::parse(&raw).unwrap_or_else(|| {
            log::warn!(
                "[match] HDDS_TYPE_NAME_MATCH='{}' is not off, warn or enforce: using warn",
                raw
            );
            TypeNameMatch::Warn
        })
    })
}

struct MatchEntry {
    id: u64,
    topic: String,
    qos: QoS,
    kind: LocalKind,
    /// Whether the local endpoint's type encodes XCDR1 natively, used at
    /// match time: a type that does not is refused when the pair negotiates
    /// XCDR1 (see `DDS::encodes_xcdr1_natively`).
    xcdr1: crate::dds::cdr_negotiation::Xcdr1Encoding,
    /// The type name the local endpoint announces in SEDP, for the Step 2
    /// comparison. Empty when the endpoint was registered without one.
    type_name: String,
    /// Complete type object for the local endpoint.
    ///
    /// When present, used by `notify_inconsistent_type_for_topic` to perform
    /// per-entry structural assignability checks so that fan-out notifications
    /// only reach entries whose type is actually incompatible with the remote's
    /// type per DDS-XTypes v1.3 sec. 7.6.3.4.3. Also used in `catch_up` to
    /// surface `inconsistent_topic` status for endpoints already cached at
    /// registration time.
    ///
    /// `None` for entries registered without an XTypes type object (e.g.
    /// generated types that have not yet been registered with the xtypes
    /// feature or user-created endpoints without `with_type_object`). Such an
    /// entry is a side with no TypeObject: Step 2 compares its type name.
    type_object: Option<CompleteTypeObject>,
    callback: MatchCallback,
    /// Told each remote endpoint that joins or leaves, before `callback`.
    peer_callback: Option<PeerCallback>,
    /// A reader's: told each writer that matches (with its LIVELINESS) or
    /// unmatches, before `callback`.
    liveliness_hook: Option<LivelinessHook>,
    incompatible_callback: Option<IncompatibleCallback>,
    /// Callback fired when a remote endpoint's type is structurally
    /// incompatible with the local type per DDS-XTypes v1.3 sec. 7.6.3.4.3.
    /// `None` when no listener is installed; the counter still accumulates.
    inconsistent_topic_callback: Option<InconsistentTopicCallback>,
    /// SHM-vs-UDP transport policy for this local endpoint, captured at
    /// registration time from the participant's configured `ShmPolicy`
    /// (the peer's dialect/capability is resolved
    /// EXACTLY ONCE at pairing). Used together with each remote endpoint's
    /// advertised `shm_capability` to compute the `TransportSelection` stored in
    /// `matched_remotes` the first time a given remote matches this entry.
    shm_policy: ShmPolicy,
    /// Matched remote endpoint GUIDs, each carrying the `TransportSelection`
    /// verdict computed exactly once for that (this entry, remote) pairing
    /// -- see `resolve_transport` -- and the incarnation of the record it was
    /// matched on. A key matched on the same or a newer incarnation is also
    /// the dedup gate against repeat match fires (see `dispatch_match` /
    /// `notify_entry`).
    matched_remotes: Mutex<HashMap<GUID, MatchedRemote>>,
    /// The record each per-peer proxy the peer hook holds was built for:
    /// remote GUID -> the incarnation of the record (`EndpointInfo::
    /// incarnation`) last told `Matched`. The hook keeps its proxies by GUID
    /// and takes a repeated `Matched` as a no-op, so a proxy built for one
    /// record (its watermark, what it received, what it is owed) would
    /// otherwise answer for the next record of the GUID. `tell_peer_matched`
    /// and `tell_peer_unmatched` keep each proxy with its record; held
    /// across the hook calls, so they never interleave for one entry.
    peer_records: Mutex<HashMap<GUID, u64>>,
    /// `(remote endpoint GUID, policy_id)` tuples that have already
    /// triggered an incompatible-QoS notification on this entry. Used
    /// to dedup repeated incompat fires when the split incompat/match
    /// paths (see `on_endpoint_discovered_incompat_only` /
    /// `on_endpoint_discovered`) both see the same endpoint over the
    /// lifetime of the registration. Without this set, an incompat
    /// could fire once when the SEDP arrives (immediate notification,
    /// no participant-confirmation gate) AND a second time when the
    /// gate eventually releases and the same SEDP is replayed through
    /// the match path.
    ///
    /// Keying on `(GUID, policy_id)` rather than `GUID` alone means
    /// that if the remote endpoint later becomes incompatible for a
    /// DIFFERENT policy (post-discovery QoS evolution, or a different
    /// local entry observing a different first-incompatible policy on
    /// the same remote), the new policy id fires its own notification
    /// -- matching DDS's `last_policy_id` status semantics. Without
    /// this, a remote that flipped from a Reliability mismatch to an
    /// Ownership mismatch would silently suppress the second event.
    incompat_remotes: Mutex<HashSet<(GUID, u32)>>,
    /// Remote endpoint GUIDs that have already triggered an
    /// inconsistent-topic notification on this entry. Deduplicates
    /// repeated notifications for the same (local, remote) pair
    /// across the SEDP replay and live discovery paths.
    inconsistent_type_remotes: Mutex<HashSet<GUID>>,
    total_count: AtomicU32,
    incompatible_count: AtomicU32,
    /// Cumulative count of inconsistent-type remote endpoints discovered.
    /// Maintained independently of whether a listener callback is installed
    /// so that `get_inconsistent_topic_status()` returns accurate data even
    /// without a listener (counter-only OMG test pattern).
    inconsistent_type_count: AtomicU32,
    /// Snapshot of `inconsistent_type_count` at the time of the most recent
    /// `get_inconsistent_topic_status()` call. Used to compute the
    /// `total_count_change` delta per DDS spec sec. 2.2.4.3.13: the change is
    /// relative to the previous read, not the cumulative total.
    #[allow(dead_code)]
    last_reported_inconsistent_type_count: AtomicU32,
    /// For local Readers: when a remote Writer with a finite Lifespan
    /// matches, tighten this atomic to `min(current, writer_lifespan_nanos)`
    /// so the reader filters samples using the writer-announced lifespan
    /// even when the reader did not request a lifespan of its own.
    reader_lifespan_nanos: Option<Arc<AtomicU64>>,
    /// Latched true the first time ANY remote on this entry resolves to
    /// `TransportSelection::Shm`. Shared with the local endpoint that
    /// registered the entry (a `DataWriter` today).
    ///
    /// This latch is why the writer's per-reader send loop stays O(1) in
    /// the overwhelmingly common all-UDP case: the writer reads one relaxed
    /// atomic per packet, and only pays for the per-reader verdict lookup
    /// (`MatchToken::transport_selection`, a registry read lock plus a map
    /// get) once this says at least one reader is reachable over shared
    /// memory. Never cleared: a writer that has spoken SHM once keeps the
    /// slower per-reader branch, which is correct and cheap.
    shm_selected: Option<Arc<AtomicBool>>,
    /// Every callback of this entry runs holding a pass of this gate, and
    /// `unregister` closes it. Callbacks run with no registry lock held (a
    /// listener may create or delete endpoints from inside one), so this gate
    /// is what still guarantees that none of them fires once `unregister`
    /// has returned.
    dispatch_gate: DispatchGate,
    /// The entry's application calls (its listener's), told in the order
    /// its dispatches made them, after the dispatch gate is left
    /// (`notices::Scope`): a match then an unmatch on two threads reach
    /// the listener in that order.
    notices: Arc<crate::dds::reader::notices::Ordered>,
}

impl MatchEntry {
    /// Hold the entry's dispatch gate for a callback; `None` once the entry
    /// is unregistered, or being unregistered (fire nothing).
    fn open_gate(&self) -> Option<GatePass<'_>> {
        self.dispatch_gate.enter()
    }
}

/// The dispatch gate of one entry: closed by `unregister`, entered by every
/// callback of the entry, and it can never block the thread that holds it.
///
/// A read-write lock did the job until a callback had to re-enter its own
/// entry: a listener creating an endpoint whose catch-up purges a zombie
/// whose departure unmatches this entry, or a listener deleting its own
/// endpoint. A writer-preferring read lock blocks the nested entry behind an
/// `unregister` waiting on another thread, which waits for the outer
/// callback; and an `unregister` from inside the entry's own callback waited
/// for its own thread. Here:
///
/// - entering a closed gate returns `None` at once (the nested dispatch is
///   skipped, as any dispatch of an entry being unregistered is);
/// - `close` waits for the passes held by OTHER threads only. An entry
///   unregistered from inside one of its own callbacks is closed at once:
///   that callback is still running (it is the caller), and no other
///   callback of the entry starts after `close` returns.
struct DispatchGate {
    state: Mutex<GateState>,
    drained: std::sync::Condvar,
}

struct GateState {
    closed: bool,
    /// The thread of every pass held, one element per pass.
    passes: Vec<std::thread::ThreadId>,
}

/// One callback's hold on an entry's `DispatchGate`.
struct GatePass<'a> {
    gate: &'a DispatchGate,
}

impl DispatchGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(GateState {
                closed: false,
                passes: Vec::new(),
            }),
            drained: std::sync::Condvar::new(),
        }
    }

    fn enter(&self) -> Option<GatePass<'_>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return None;
        }
        state.passes.push(std::thread::current().id());
        Some(GatePass { gate: self })
    }

    /// Close the gate and wait for the callbacks other threads are running.
    fn close(&self) {
        let me = std::thread::current().id();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        while state.passes.iter().any(|thread| *thread != me) {
            state = self.drained.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }
}

impl Drop for GatePass<'_> {
    fn drop(&mut self) {
        let me = std::thread::current().id();
        let mut state = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = state.passes.iter().position(|thread| *thread == me) {
            state.passes.swap_remove(at);
        }
        drop(state);
        self.gate.drained.notify_all();
    }
}

/// Token returned when registering a match callback.
/// Unregisters from the registry on drop.
pub(crate) struct MatchToken {
    registry: Weak<MatchNotificationRegistry>,
    id: u64,
}

impl MatchToken {
    /// The id of the entry this token holds registered.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn current_match_count(&self) -> u32 {
        self.registry
            .upgrade()
            .map_or(0, |registry| registry.current_match_count(self.id))
    }

    /// GUIDs of the remote endpoints currently matched with this entry
    /// (DDS v1.4 Sec.2.2.2.4.2.24 `get_matched_subscriptions` on a writer,
    /// or Sec.2.2.2.5.3.34 `get_matched_publications` on a reader). Empty
    /// once the entry is gone.
    pub(crate) fn matched_remote_guids(&self) -> Vec<GUID> {
        self.registry
            .upgrade()
            .map_or_else(Vec::new, |registry| registry.matched_remote_guids(self.id))
    }

    /// Name the local endpoint this entry stands for by its GUID, so the
    /// registry can answer [`MatchNotificationRegistry::local_endpoint_matches`]
    /// for it. The entry keeps the name until it is unregistered.
    pub(crate) fn bind_local_guid(&self, guid: GUID) {
        if let Some(registry) = self.registry.upgrade() {
            registry.bind_local_guid(self.id, guid);
        }
    }

    /// Read the SHM-vs-UDP transport verdict stored for `remote` on this
    /// entry, if that remote has matched. O(1) lookup -- the verdict was
    /// computed exactly once, at match time, by `resolve_transport`.
    /// Returns `None` if the remote never matched (or matching was refused,
    /// see `TransportSelectionError`), not "not yet computed".
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn transport_selection(&self, remote: &GUID) -> Option<TransportSelection> {
        self.registry
            .upgrade()
            .and_then(|registry| registry.transport_selection_for(self.id, remote))
    }
}

impl Drop for MatchToken {
    fn drop(&mut self) {
        if let Some(reg) = self.registry.upgrade() {
            reg.unregister(self.id);
        }
    }
}

impl std::fmt::Debug for MatchToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchToken").field("id", &self.id).finish()
    }
}

/// Registry for match notification callbacks.
///
/// Implements `DiscoveryListener` to receive remote endpoint discoveries
/// and fire `on_publication_matched` / `on_subscription_matched` callbacks
/// on local writers/readers with compatible QoS.
pub(crate) struct MatchNotificationRegistry {
    /// The registered local entries. Read under this lock, dispatched
    /// outside it: a callback runs on a clone of the entry's `Arc` after the
    /// lock is released, so a listener that creates an endpoint (which
    /// takes this lock for writing) from inside `on_publication_matched`
    /// does not deadlock against its own dispatch.
    entries: RwLock<Vec<Arc<MatchEntry>>>,
    /// The GUID of each registered local endpoint, to the id of its entry
    /// (`MatchToken::bind_local_guid`): the inverse of `entries`, which
    /// knows a local endpoint by its topic, never by its GUID. Kept with
    /// the entry: an entry that leaves (`unregister`) takes its GUID with
    /// it.
    local_endpoints: RwLock<HashMap<GUID, u64>>,
    discovery_fsm: Weak<DiscoveryFsm>,
    local_guid_prefix: [u8; 12],
    /// The Step 2 mode every verdict of this registry applies: the process
    /// mode (`type_name_match_mode`), read once when the registry is made.
    type_name_mode: TypeNameMatch,
    /// The (topic, writer type name, reader type name) pairs Step 2 refused in
    /// warn mode: one warning and one count per pair (`type_name_warning_count`).
    step2_warned: Mutex<BTreeSet<(String, String, String)>>,
    next_id: AtomicU64,
    next_match_generation: AtomicU64,
    /// The data-plane gate of every (remote writer, local reader) pair:
    /// for each remote writer, the local reader entries that refuse it, and
    /// why (`Refusal`). Consulted on the reader's delivery path, one lookup
    /// per sample (`is_writer_refused_by`), so a reader drops what a writer
    /// IT is not matched with sends, deterministically, independent of the
    /// notification-vs-data-arrival race.
    ///
    /// Keyed by the PAIR, as DDS matching is (DDS v1.4 Sec.2.2.3: "for the
    /// Subscriber to receive data the DataReader's requested value must be
    /// compatible with the DataWriter's offered value"): a writer one local
    /// reader refuses may be matched by another reader of the same topic,
    /// whose samples it must still receive, and the refused reader must
    /// receive none. Judged on the cold path only: a remote writer's every
    /// announcement (`judge_remote_writer_qos`, `judge_remote_types`), a
    /// local reader's registration (`catch_up`), a type learned later
    /// (`rejudge_remote_types`); forgotten with the reader (`unregister`),
    /// the writer's deletion, or its participant's announced departure.
    refused_pairs: dashmap::DashMap<[u8; 16], HashMap<u64, Refusal>>,
    /// Every remote writer whose samples the router may route to a local
    /// reader, as the QoS verdict reads it (`JudgedWriter`): the last
    /// announcement judged (`judge_remote_writer_qos`), whether discovery
    /// holds it, holds it back until its participant is known (a held
    /// announcement), or forgot it with a participant that fell silent (the
    /// router's record of its topic survives that purge). The one source a
    /// local reader registering is judged against (`catch_up`): what the
    /// router can route, a reader must be able to judge. Forgotten exactly
    /// when the writer's QoS verdicts are (`forget_remote_writer`,
    /// `on_participant_left`).
    ///
    /// Held across the read of a remote writer's record, its QoS verdict
    /// and the recording of that verdict (`record_pair_qos`), so that a
    /// verdict taken on an older record (a reader registering) never lands
    /// after one taken on a newer record (the writer announcing a new QoS).
    /// Cold path only.
    judged_writers: Mutex<HashMap<[u8; 16], JudgedWriter>>,
    /// Every remote reader as the QoS verdict last read it, its topic and
    /// QoS (`JudgedWriter`'s shape): the announcement a re-announcement is
    /// compared with (`judge_remote_reader_qos`), so that a pair whose
    /// verdict flipped is matched or unmatched. A local writer judges a
    /// remote reader on its announcement alone (no data-plane gate: what a
    /// writer sends a reader it is not matched with, the reader drops), so
    /// the record leaves with the reader (`on_endpoint_removed`) or its
    /// participant (`on_participant_left`). Cold path only.
    judged_readers: Mutex<HashMap<[u8; 16], JudgedWriter>>,
    /// Participant-level shared-memory receive leg, installed by
    /// `ParticipantBuilder::build()` after the receive plumbing exists.
    ///
    /// Lives here because THIS is where a pairing is resolved exactly once:
    /// when a local Reader entry resolves `TransportSelection::Shm` for a
    /// remote writer, that writer's ring has to be drained, and the decision
    /// and the plumbing must not drift apart. `None` when the participant
    /// has no discovery FSM (intra-process only) or on a platform without
    /// shared memory.
    #[cfg(target_os = "linux")]
    shm_receiver: RwLock<Option<Arc<crate::transport::shm::receiver::ShmReceiver>>>,
    /// Participant-level type-object store for structural assignability.
    ///
    /// Populated via `register_type_objects` from nested TypeObjects collected
    /// from each local endpoint's dynamic TypeDescriptor.  At match time, a
    /// `SnapshotResolver` backed by this store is passed to
    /// `Matcher::is_type_compatible_with_resolver` so that hash-keyed inner
    /// types (enum members, nested-struct members) can be resolved to their
    /// CompleteTypeObjects and compared structurally (DDS-XTypes v1.3 sec. 7.5.1).
    ///
    /// Keyed by Minimal EquivalenceHash (the hash emitted in member
    /// `TypeIdentifier::Minimal(_)` fields).  Thread-safe: written during
    /// participant setup (before endpoints match), read during match callbacks.
    #[cfg(feature = "xtypes-structural-assignability")]
    type_store: std::sync::RwLock<
        std::collections::HashMap<
            crate::xtypes::EquivalenceHash,
            crate::xtypes::CompleteTypeObject,
        >,
    >,
    /// Peers' TypeObjects, each verified against the COMPLETE hash a
    /// getTypes reply answered for (`register_remote_type_object`). Kept
    /// apart from `type_store`: they resolve hash references at match time
    /// (a peer's COMPLETE TypeObject names its member types by COMPLETE
    /// hash), and never stand in for a local type by name
    /// (`resolve_type_by_name` reads `type_store` only).
    #[cfg(feature = "xtypes-structural-assignability")]
    /// Bounded with least-recently-used eviction, and cleaned of what a
    /// departed participant alone served (`forget_remote_types_of`).
    remote_type_store: std::sync::RwLock<crate::core::discovery::matcher::type_cache::TypeCache>,
}

impl MatchNotificationRegistry {
    /// Whether `endpoint` is one of this participant's own.
    fn is_local(&self, endpoint: &EndpointInfo) -> bool {
        endpoint.endpoint_guid.prefix == self.local_guid_prefix
    }

    /// `endpoint`'s QoS as the verdict reads it: by the rules this
    /// participant applies to its own endpoints when it is one of them
    /// (`local_qos_for_verdict`), as a remote announcement otherwise
    /// (`remote_qos_for_verdict`).
    fn qos_for_verdict(&self, endpoint: &EndpointInfo) -> QoS {
        if self.is_local(endpoint) {
            local_qos_for_verdict(endpoint)
        } else {
            remote_qos_for_verdict(endpoint)
        }
    }

    pub fn new(fsm: &Arc<DiscoveryFsm>, local_guid_prefix: [u8; 12]) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            local_endpoints: RwLock::new(HashMap::new()),
            discovery_fsm: Arc::downgrade(fsm),
            local_guid_prefix,
            type_name_mode: type_name_match_mode(),
            step2_warned: Mutex::new(BTreeSet::new()),
            next_id: AtomicU64::new(1),
            next_match_generation: AtomicU64::new(1),
            refused_pairs: dashmap::DashMap::new(),
            judged_writers: Mutex::new(HashMap::new()),
            judged_readers: Mutex::new(HashMap::new()),
            #[cfg(target_os = "linux")]
            shm_receiver: RwLock::new(None),
            #[cfg(feature = "xtypes-structural-assignability")]
            type_store: std::sync::RwLock::new(std::collections::HashMap::new()),
            #[cfg(feature = "xtypes-structural-assignability")]
            remote_type_store: std::sync::RwLock::new(
                crate::core::discovery::matcher::type_cache::TypeCache::default(),
            ),
        }
    }

    /// Record a peer's TypeObject, served by `peer`, under the COMPLETE
    /// `hash` it was verified against, for hash resolution at match time.
    /// Bounded: a full store evicts its least recently used entry, it never
    /// refuses.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn register_remote_type_object(
        &self,
        hash: crate::xtypes::EquivalenceHash,
        type_object: crate::xtypes::CompleteTypeObject,
        peer: [u8; 12],
    ) {
        self.remote_type_store
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(hash, type_object, peer);
    }

    /// `peer` left: drop the peer types only it served.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn forget_remote_types_of(&self, peer: &[u8; 12]) {
        self.remote_type_store
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .forget_peer(peer);
    }

    /// Peer types stored (a bound, for tests and diagnostics).
    #[cfg(all(test, feature = "xtypes-structural-assignability"))]
    pub(crate) fn remote_type_count(&self) -> usize {
        self.remote_type_store
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// The hash references of `type_object` neither local types nor peer
    /// types resolve now, without cloning either store (the type verdict's
    /// own resolution: a local entry wins over a peer's under one hash).
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn unresolved_type_refs(
        &self,
        type_object: &crate::xtypes::CompleteTypeObject,
    ) -> Vec<crate::core::discovery::matcher::UnresolvedRef> {
        let local = self.type_store.read().unwrap_or_else(|e| e.into_inner());
        let remote = self
            .remote_type_store
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let both = crate::core::discovery::matcher::LayeredResolver {
            local: &local,
            remote: remote.objects(),
        };
        crate::core::discovery::matcher::unresolved_type_refs(type_object, &both)
    }

    /// Register nested TypeObjects for structural-assignability resolution.
    ///
    /// Typically called once per local endpoint registration, with the map
    /// returned by `hdds::dynamic::collect_nested_type_objects(type_desc)`.
    /// Multiple calls merge; last-write-wins on hash collision (safe: same
    /// hash == structurally identical TypeObjects).
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn register_type_objects(
        &self,
        types: std::collections::HashMap<
            crate::xtypes::EquivalenceHash,
            crate::xtypes::CompleteTypeObject,
        >,
    ) {
        let mut store = self.type_store.write().unwrap_or_else(|e| e.into_inner());
        store.extend(types);
    }

    /// Snapshot the current type store for use as a resolver.
    ///
    /// Exposed as `pub(crate)` so that `DiscoveryFsm` can obtain a resolver
    /// for the data-plane gate (the `mark_writer_incompatible` path) without
    /// duplicating the type store.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn snapshot_resolver(&self) -> crate::core::discovery::matcher::SnapshotResolver {
        let mut store = self
            .type_store
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // Peers' types resolve the hashes a peer's TypeObject references; a
        // local entry under the same hash wins (same hash, same type).
        for (hash, obj) in self
            .remote_type_store
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .objects()
            .iter()
        {
            store.entry(*hash).or_insert_with(|| obj.clone());
        }
        crate::core::discovery::matcher::SnapshotResolver::new(store)
    }

    /// Resolve a single announced equivalence hash to a locally registered
    /// `CompleteTypeObject`.
    ///
    /// Used by `DiscoveryFsm::handle_sedp` to materialize a remote peer's
    /// `PID_TYPE_INFORMATION` (hash-only) announcement into a concrete
    /// TypeObject when the same type is registered locally (content-addressed:
    /// equal minimal hash == equal type per DDS-XTypes v1.3 sec. 7.3.4.8).
    /// Targeted read-lock lookup -- deliberately NOT `snapshot_resolver()`,
    /// which clones the whole store.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn resolve_type_by_minimal_hash(
        &self,
        hash: &crate::xtypes::EquivalenceHash,
    ) -> Option<crate::xtypes::CompleteTypeObject> {
        self.type_store
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(hash)
            .cloned()
    }

    /// SECOND-RECOURSE name-based resolution for hash-divergent peers.
    ///
    /// A peer may announce a Minimal EquivalenceHash that differs from ours
    /// for the same type (the hash is an MD5 over the serialized TypeObject,
    /// so any divergence in it, e.g. member flags or ids, changes the hash),
    /// so the content-addressed lookup above misses. When the announced SEDP type
    /// name matches a locally registered TypeObject, resolve to that local
    /// object: assignability is still evaluated STRUCTURALLY on it, and a
    /// miss keeps the prior behavior (absent -> allow), so a remote type
    /// that legitimately differs from the same-named local copy is never
    /// treated worse than before this fallback existed.
    ///
    /// Match rule: exact qualified-name equality first; otherwise a match
    /// on the trailing `::` segment, accepted ONLY when unambiguous
    /// (exactly one candidate), to tolerate qualification drift between
    /// vendors without cross-module false positives.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn resolve_type_by_name(
        &self,
        type_name: &str,
    ) -> Option<crate::xtypes::CompleteTypeObject> {
        if type_name.is_empty() {
            return None;
        }
        let store = self.type_store.read().unwrap_or_else(|e| e.into_inner());

        if let Some(obj) = store.values().find(|o| o.type_name() == Some(type_name)) {
            return Some(obj.clone());
        }

        let tail = type_name.rsplit("::").next().unwrap_or(type_name);
        let mut candidates = store
            .values()
            .filter(|o| {
                o.type_name()
                    .map(|n| n.rsplit("::").next().unwrap_or(n) == tail)
                    .unwrap_or(false)
            })
            .take(2);
        let first = candidates.next().cloned();
        if candidates.next().is_some() {
            // Ambiguous tail match: refuse rather than guess.
            return None;
        }
        first
    }

    /// Substitution gate for LOSSY legacy TypeObject v1 objects: return the
    /// locally-registered `CompleteTypeObject` announced under the SAME
    /// FULLY-QUALIFIED name, but ONLY when it is v1-projection-equivalent
    /// to the decoded object (see
    /// `xtypes::v1_projection_equivalent` for the lossiness relation and
    /// its soundness rationale). Name equality alone is NOT sufficient: a
    /// same-named but structurally different remote type must keep its
    /// decoded object authoritative so the matcher rejects it, instead of
    /// silently mis-deserializing its data with the local type.
    ///
    /// The trigger deliberately refuses `resolve_type_by_name`'s
    /// unambiguous trailing-segment fallback: substitution requires exact
    /// qualified-name identity (`Test::foo` style, module path included).
    ///
    /// The local types are the type store's and the TypeObjects the local
    /// endpoints registered with: an endpoint's own root type is not in the
    /// type store (it holds the types other types reference), and it is the
    /// type a same-named remote endpoint is paired with.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn resolve_v1_substitute(
        &self,
        type_name: &str,
        decoded: &crate::xtypes::CompleteTypeObject,
    ) -> Option<crate::xtypes::CompleteTypeObject> {
        let resolve = |h: &crate::xtypes::EquivalenceHash| self.resolve_type_by_minimal_hash(h);
        let entries = self.entries_snapshot();
        let mut candidates = self
            .resolve_type_by_name(type_name)
            .into_iter()
            .chain(entries.iter().filter_map(|e| e.type_object.clone()))
            // Tail-segment resolution is not an exact qualified-name match,
            // never eligible for substitution.
            .filter(|local| local.type_name() == Some(type_name))
            .peekable();
        // No same-named local type: nothing to substitute, nothing to log.
        candidates.peek()?;
        let found = candidates
            .find(|local| crate::xtypes::v1_projection_equivalent(local, decoded, &resolve));
        if found.is_none() {
            log::debug!(
                "[SEDP] same-named local type '{}' is NOT v1-projection-equivalent to the decoded legacy TypeObject; keeping the decoded object authoritative",
                type_name
            );
        }
        found
    }

    /// Resolve an announced `PID_TYPE_INFORMATION` to a locally registered
    /// `CompleteTypeObject`, trying in order: minimal hash, complete hash,
    /// then the announced type NAME (second recourse for hash-divergent
    /// vendors -- see `resolve_type_by_name` for the safety argument).
    ///
    /// A miss returns `None`, which keeps the caller's "absent -> allow"
    /// behavior. Callable both at SEDP arrival time and lazily from the
    /// late-side compatibility checks, where the local endpoint may have
    /// registered its TypeObject AFTER the remote SEDP was cached.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn resolve_type_information(
        &self,
        ti: &crate::protocol::discovery::types::TypeInformation,
        type_name: &str,
    ) -> Option<crate::xtypes::CompleteTypeObject> {
        ti.minimal
            .as_ref()
            .and_then(|m| self.resolve_type_by_minimal_hash(&m.hash))
            .or_else(|| {
                ti.complete
                    .as_ref()
                    .and_then(|c| self.resolve_type_by_minimal_hash(&c.hash))
            })
            .or_else(|| self.resolve_type_by_name(type_name))
    }

    /// Clone the current type store as a raw `HashMap` for dep-hash computation.
    ///
    /// Used by `announce.rs` when building a SEDP announcement to pre-compute
    /// `TypeInformation.dependent_typeids` via `derive_type_information_with_deps`.
    /// Semantics mirror `snapshot_resolver` but return the raw map rather than
    /// a `SnapshotResolver` wrapper, since the dep-collection helper takes a
    /// `&HashMap` directly.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn snapshot_type_store(
        &self,
    ) -> std::collections::HashMap<crate::xtypes::EquivalenceHash, crate::xtypes::CompleteTypeObject>
    {
        self.type_store
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Record one verdict (`reason`) of the local reader entry
    /// `reader_entry` on a remote writer in the data-plane gate: `refused`
    /// arms it for that pair, `!refused` clears it; the pair stays refused
    /// while the other verdict refuses it. Returns whether that verdict
    /// refused the pair before.
    fn set_writer_refused_by(
        &self,
        writer_guid: [u8; 16],
        reader_entry: u64,
        reason: Refusal,
        refused: bool,
    ) -> bool {
        if refused {
            let mut refusing = self.refused_pairs.entry(writer_guid).or_default();
            let held = refusing.entry(reader_entry).or_insert(Refusal::NONE);
            let was = held.has(reason);
            *held = held.with(reason);
            return was;
        }
        let mut was = false;
        let emptied = self
            .refused_pairs
            .get_mut(&writer_guid)
            .is_some_and(|mut refusing| {
                if let Some(held) = refusing.get_mut(&reader_entry) {
                    was = held.has(reason);
                    *held = held.without(reason);
                    if *held == Refusal::NONE {
                        refusing.remove(&reader_entry);
                    }
                }
                refusing.is_empty()
            });
        if emptied {
            self.refused_pairs
                .remove_if(&writer_guid, |_, refusing| refusing.is_empty());
        }
        was
    }

    /// Clear the verdicts `reason` of every pair of the remote writer
    /// `writer_guid`.
    fn clear_writer_refusals(&self, writer_guid: &[u8; 16], reason: Refusal) {
        let emptied = self
            .refused_pairs
            .get_mut(writer_guid)
            .is_some_and(|mut refusing| {
                refusing.retain(|_, held| {
                    *held = held.without(reason);
                    *held != Refusal::NONE
                });
                refusing.is_empty()
            });
        if emptied {
            self.refused_pairs
                .remove_if(writer_guid, |_, refusing| refusing.is_empty());
        }
    }

    /// How many remote writers some local reader refuses, and how many
    /// (writer, reader) pairs are refused (tests: a record leaves with what
    /// it was about).
    #[cfg(test)]
    pub(crate) fn refused_pair_counts(&self) -> (usize, usize) {
        let pairs = self
            .refused_pairs
            .iter()
            .map(|refusing| refusing.value().len())
            .sum();
        (self.refused_pairs.len(), pairs)
    }

    /// How many local reader entries of `topic` are registered (tests: what
    /// a reader's announcement finds registered when it goes out).
    #[cfg(test)]
    pub(crate) fn reader_entries_of(&self, topic: &str) -> usize {
        self.entries_snapshot()
            .iter()
            .filter(|entry| entry.kind == LocalKind::Reader && entry.topic == topic)
            .count()
    }

    /// The QoS a remote writer is judged on now, from `judged` (the
    /// `judged_writers` table, its lock held): the record discovery holds of
    /// it, else the last announcement judged here (held, or its participant
    /// fell silent). `None` for a writer of another topic, or one neither
    /// knows.
    fn writer_qos_now(
        &self,
        judged: &HashMap<[u8; 16], JudgedWriter>,
        topic: &str,
        writer_guid: &GUID,
    ) -> Option<QoS> {
        self.discovery_fsm
            .upgrade()
            .and_then(|fsm| fsm.current_endpoint(topic, writer_guid))
            .map(|current| remote_qos_for_verdict(&current))
            .or_else(|| {
                judged
                    .get(&writer_guid.as_bytes())
                    .filter(|record| record.topic == topic)
                    .map(|record| record.qos.clone())
            })
    }

    /// The QoS verdict (`rxo_verdict`) of the local reader `entry` on the
    /// remote writer `writer_guid` of `topic`, whose QoS as the verdict
    /// reads it is `writer_qos`, recorded in the data-plane gate. Run with
    /// the `judged_writers` lock held. Returns whether the QoS verdict
    /// refused the pair before, and the verdict. `None` when the two are no
    /// pairing (another topic, not a reader entry).
    fn record_pair_qos(
        &self,
        entry: &MatchEntry,
        writer_guid: &GUID,
        topic: &str,
        writer_qos: &QoS,
    ) -> Option<(bool, Result<(), u32>)> {
        if entry.kind != LocalKind::Reader || entry.topic != topic {
            return None;
        }
        let verdict = rxo_verdict(
            writer_qos,
            &local_reader_qos_for_verdict(&entry.qos),
            entry.xcdr1,
            self.remote_vendor_of(writer_guid),
            self.local_type_contains_wchar(entry.type_object.as_ref()),
        );
        let was = self.set_writer_refused_by(
            writer_guid.as_bytes(),
            entry.id,
            Refusal::QOS,
            verdict.is_err(),
        );
        Some((was, verdict))
    }

    /// Judge the local reader `entry`, registering, against every remote
    /// writer of its topic the router may route to it: those discovery holds
    /// (`known`) and those it does not hold but whose announcement was judged
    /// here (`judged_writers`: held, or gone silent). Each verdict is
    /// recorded in the data-plane gate before any sample of the writer
    /// reaches the reader.
    fn judge_reader_qos(&self, entry: &MatchEntry, known: &[EndpointInfo]) {
        if entry.kind != LocalKind::Reader {
            return;
        }
        let judged = self
            .judged_writers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut writers: Vec<GUID> = known
            .iter()
            .filter(|w| w.kind == EndpointKind::Writer && !self.is_local(w))
            .map(|w| w.endpoint_guid)
            .collect();
        writers.extend(
            judged
                .iter()
                .filter(|(_, record)| record.topic == entry.topic)
                .map(|(guid, _)| GUID::from_bytes(*guid)),
        );
        writers.sort_unstable_by_key(GUID::as_bytes);
        writers.dedup();
        for writer in writers {
            if let Some(qos) = self.writer_qos_now(&judged, &entry.topic, &writer) {
                let _ = self.record_pair_qos(entry, &writer, &entry.topic, &qos);
            }
        }
    }

    /// Forget the remote writer `writer_guid`: it said it is gone (its SEDP
    /// dispose, whether discovery held it or held it back). Its QoS verdicts
    /// and its record leave together: a reader created after is not judged
    /// against it.
    pub(crate) fn forget_remote_writer(&self, writer_guid: &GUID) {
        let writer = writer_guid.as_bytes();
        let mut judged = self
            .judged_writers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        judged.remove(&writer);
        self.clear_writer_refusals(&writer, Refusal::QOS);
    }

    /// Judge a remote writer's announcement against every local reader of
    /// its topic with the one QoS verdict, and record each verdict in the
    /// data-plane gate before any of its samples can be delivered: a reader
    /// the verdict refuses drops them, its compatible siblings receive them.
    /// Called on EVERY announcement of the writer (its first, and each one
    /// after, which may carry a new QoS: DEADLINE, LATENCY_BUDGET and
    /// PARTITION are changeable, DDS v1.4 Sec.2.2.3), and for an announcement
    /// held until its participant is known. The writer is recorded
    /// (`judged_writers`) on the record discovery holds of it now, or this
    /// announcement when it holds none, so that a reader registering later
    /// is judged against it.
    ///
    /// On a re-announcement (`reannounced`), a pair whose verdict FLIPPED is
    /// matched or unmatched as discovery would have done on that QoS: a pair
    /// now refused is unmatched (`dispatch_unmatch`) and reported
    /// incompatible (`dispatch_incompat`); a pair now accepted is matched
    /// when `may_match` holds (the match path would surface the endpoint
    /// now) and the whole verdict accepts it (`evaluate_entries`). A first
    /// announcement is matched and reported by the discovery listener hooks
    /// that follow it.
    pub(crate) fn judge_remote_writer_qos(
        &self,
        writer: &EndpointInfo,
        reannounced: bool,
        may_match: bool,
    ) {
        if writer.kind != EndpointKind::Writer || self.is_local(writer) {
            return;
        }
        let mut refused_now: Vec<(Arc<MatchEntry>, u32)> = Vec::new();
        let mut lifted: Vec<Arc<MatchEntry>> = Vec::new();
        {
            let mut judged = self
                .judged_writers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let qos = self
                .discovery_fsm
                .upgrade()
                .and_then(|fsm| fsm.current_endpoint(&writer.topic_name, &writer.endpoint_guid))
                .map_or_else(
                    || remote_qos_for_verdict(writer),
                    |current| remote_qos_for_verdict(&current),
                );
            judged.insert(
                writer.endpoint_guid.as_bytes(),
                self.writer_record(writer, qos.clone()),
            );
            for entry in self.entries_snapshot() {
                let Some((was, verdict)) =
                    self.record_pair_qos(&entry, &writer.endpoint_guid, &writer.topic_name, &qos)
                else {
                    continue;
                };
                if !reannounced || was == verdict.is_err() {
                    continue;
                }
                match verdict {
                    Err(policy_id) => refused_now.push((entry, policy_id)),
                    Ok(()) => lifted.push(entry),
                }
            }
        }
        for (entry, policy_id) in refused_now {
            self.dispatch_unmatch(writer, &entry);
            if policy_id != 0 {
                self.dispatch_incompat(writer, &entry, policy_id);
            }
        }
        if !may_match || lifted.is_empty() {
            return;
        }
        for (entry_id, verdict) in self.evaluate_entries(writer) {
            if !matches!(verdict, EntryVerdict::Match) {
                continue;
            }
            if let Some(entry) = lifted.iter().find(|e| e.id == entry_id) {
                self.dispatch_match(writer, entry);
            }
        }
    }

    /// Judge a remote reader's announcement against every local writer of
    /// its topic with the one QoS verdict (`rxo_verdict`), as
    /// `judge_remote_writer_qos` judges a remote writer against the local
    /// readers. Called on EVERY announcement of the reader: its first
    /// records it (`judged_readers`; discovery's listener hooks match and
    /// report it), each one after may carry a new QoS (DEADLINE,
    /// LATENCY_BUDGET, PARTITION, TIME_BASED_FILTER are changeable, DDS v1.4
    /// Sec.2.2.3), and is judged against the announcement it follows.
    ///
    /// On a re-announcement (`reannounced`), a pair whose verdict FLIPPED is
    /// matched or unmatched as discovery would have done on that QoS: a pair
    /// now refused is unmatched (`dispatch_unmatch`: the callback with -1,
    /// the writer's proxy of the reader released) and reported incompatible
    /// (`dispatch_incompat`); a pair now accepted is matched when
    /// `may_match` holds and the whole verdict accepts it
    /// (`evaluate_entries`).
    pub(crate) fn judge_remote_reader_qos(
        &self,
        reader: &EndpointInfo,
        reannounced: bool,
        may_match: bool,
    ) {
        if reader.kind != EndpointKind::Reader || self.is_local(reader) {
            return;
        }
        let mut refused_now: Vec<(Arc<MatchEntry>, u32)> = Vec::new();
        let mut lifted: Vec<Arc<MatchEntry>> = Vec::new();
        {
            let mut judged = self
                .judged_readers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let qos = self
                .discovery_fsm
                .upgrade()
                .and_then(|fsm| fsm.current_endpoint(&reader.topic_name, &reader.endpoint_guid))
                .map_or_else(
                    || remote_qos_for_verdict(reader),
                    |current| remote_qos_for_verdict(&current),
                );
            let before = judged.insert(
                reader.endpoint_guid.as_bytes(),
                JudgedWriter {
                    topic: reader.topic_name.clone(),
                    qos: qos.clone(),
                    type_object: None,
                    type_name: reader.type_name.clone(),
                    type_pending: false,
                },
            );
            let Some(before) = before.filter(|before| before.topic == reader.topic_name) else {
                return;
            };
            if !reannounced {
                return;
            }
            let remote_vendor = self.remote_vendor_of(&reader.participant_guid);
            for entry in self.entries_snapshot() {
                if entry.kind != LocalKind::Writer || entry.topic != reader.topic_name {
                    continue;
                }
                let local_wchar = self.local_type_contains_wchar(entry.type_object.as_ref());
                let was = rxo_verdict(
                    &entry.qos,
                    &before.qos,
                    entry.xcdr1,
                    remote_vendor,
                    local_wchar,
                );
                let now = rxo_verdict(&entry.qos, &qos, entry.xcdr1, remote_vendor, local_wchar);
                if was.is_err() == now.is_err() {
                    continue;
                }
                match now {
                    Err(policy_id) => refused_now.push((entry, policy_id)),
                    Ok(()) => lifted.push(entry),
                }
            }
        }
        for (entry, policy_id) in refused_now {
            self.dispatch_unmatch(reader, &entry);
            if policy_id != 0 {
                self.dispatch_incompat(reader, &entry, policy_id);
            }
        }
        if !may_match || lifted.is_empty() {
            return;
        }
        for (entry_id, verdict) in self.evaluate_entries(reader) {
            if !matches!(verdict, EntryVerdict::Match) {
                continue;
            }
            if let Some(entry) = lifted.iter().find(|e| e.id == entry_id) {
                self.dispatch_match(reader, entry);
            }
        }
    }

    /// Record the QoS verdict of a remote writer the registry has none for,
    /// when it is installed after the writer's announcement was handled
    /// (`DiscoveryFsm::set_match_registry`). A writer with a record was judged
    /// by a live announcement, and that judgment is the newer one: it is left
    /// alone. A writer discovery no longer holds is not recorded. The check
    /// and the record are one step under the `judged_writers` lock, which the
    /// live judgment takes too. Only the data-plane gate is recorded here:
    /// the match of the writer is surfaced by the discovery listener hooks.
    /// Returns whether the verdict was recorded.
    pub(crate) fn judge_unrecorded_remote_writer(&self, writer: &EndpointInfo) -> bool {
        if writer.kind != EndpointKind::Writer || self.is_local(writer) {
            return false;
        }
        let guid = writer.endpoint_guid.as_bytes();
        let mut judged = self
            .judged_writers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if judged.contains_key(&guid) {
            return false;
        }
        let Some(current) = self
            .discovery_fsm
            .upgrade()
            .and_then(|fsm| fsm.current_endpoint(&writer.topic_name, &writer.endpoint_guid))
        else {
            return false;
        };
        let qos = remote_qos_for_verdict(&current);
        judged.insert(guid, self.writer_record(&current, qos.clone()));
        for entry in self.entries_snapshot() {
            let _ = self.record_pair_qos(&entry, &writer.endpoint_guid, &writer.topic_name, &qos);
        }
        true
    }

    /// Record the baseline of a remote reader the registry has none for,
    /// when it is installed after the reader's announcement was handled
    /// (`DiscoveryFsm::set_match_registry`). The rule of
    /// `judge_unrecorded_remote_writer` applies: a reader with a record is
    /// left alone, and one discovery no longer holds is not recorded. Returns
    /// whether the baseline was recorded.
    pub(crate) fn judge_unrecorded_remote_reader(&self, reader: &EndpointInfo) -> bool {
        if reader.kind != EndpointKind::Reader || self.is_local(reader) {
            return false;
        }
        let guid = reader.endpoint_guid.as_bytes();
        let mut judged = self
            .judged_readers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if judged.contains_key(&guid) {
            return false;
        }
        let Some(current) = self
            .discovery_fsm
            .upgrade()
            .and_then(|fsm| fsm.current_endpoint(&reader.topic_name, &reader.endpoint_guid))
        else {
            return false;
        };
        judged.insert(
            guid,
            JudgedWriter {
                topic: reader.topic_name.clone(),
                qos: remote_qos_for_verdict(&current),
                type_object: None,
                type_name: reader.type_name.clone(),
                type_pending: false,
            },
        );
        true
    }

    /// Whether discovery runs the security plugins that judge a remote
    /// writer (`DiscoveryFsm::admission_gate_active`). False once discovery
    /// is gone.
    #[cfg(feature = "security")]
    pub(crate) fn admission_gate_active(&self) -> bool {
        self.discovery_fsm
            .upgrade()
            .is_some_and(|fsm| fsm.admission_gate_active())
    }

    /// Whether a local reader of `topic` accepts the samples and lifecycle
    /// changes of the remote writer `writer_guid`: the admission discovery's
    /// match applies (`DiscoveryFsm::admits_remote_endpoint`). User data is
    /// routed to a reader by topic name, matched or not, so the refusal of
    /// the match is applied to what the writer sends as well. False once
    /// discovery is gone.
    #[cfg(feature = "security")]
    pub(crate) fn admits_remote_writer(&self, writer_guid: &[u8; 16], topic: &str) -> bool {
        self.discovery_fsm.upgrade().is_some_and(|fsm| {
            fsm.admits_remote_endpoint(
                topic,
                &crate::core::discovery::GUID::from_bytes(*writer_guid),
                true,
            )
        })
    }

    /// Whether the local reader entry `reader_entry` refuses the remote
    /// writer, on its type or on its QoS: the per-sample data-plane gate of
    /// that reader.
    #[inline]
    pub(crate) fn is_writer_refused_by(&self, writer_guid: &[u8; 16], reader_entry: u64) -> bool {
        self.refused_pairs
            .get(writer_guid)
            .is_some_and(|refusing| refusing.contains_key(&reader_entry))
    }

    /// Read a recorded pair verdict after the writer's announcement has
    /// been judged. TopicRegistry metadata is published before discovery
    /// reaches that judgment, so its presence alone cannot admit DATA.
    /// The lock is held by the QoS judgment through every pair's recording.
    /// Confirm the type verdict too: a held SEDP has its QoS judged before
    /// its participant is known, without reaching the usual type judgment.
    /// Used only before a reader has cached this writer's admission, never
    /// on its hot path.
    pub(crate) fn writer_pair_verdict(
        &self,
        writer_guid: &[u8; 16],
        reader_entry: u64,
        topic: &str,
    ) -> Option<bool> {
        let judged = self
            .judged_writers
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let writer = judged.get(writer_guid)?;
        let entry = self.entry(reader_entry)?;
        if writer.topic != topic || entry.topic != topic || entry.kind != LocalKind::Reader {
            return None;
        }
        let current = self
            .discovery_fsm
            .upgrade()
            .and_then(|fsm| fsm.current_endpoint(topic, &GUID::from_bytes(*writer_guid)));
        let current_type = current.as_ref().and_then(|w| self.effective_type_object(w));
        let writer_object = current_type.as_ref().or(writer.type_object.as_ref());
        let writer_side = match current.as_ref() {
            Some(now) => remote_side(now, writer_object),
            None => TypeSide {
                object: writer_object,
                name: &writer.type_name,
                pending: writer_object.is_none() && writer.type_pending,
            },
        };
        let type_ok = self.pairing_type_verdict(
            topic,
            writer_side,
            entry_side(&entry),
            entry.qos.type_consistency.as_ref(),
        );
        Some(type_ok && !self.is_writer_refused_by(writer_guid, reader_entry))
    }

    /// Whether discovery holds the remote writer `writer_guid` on `topic`
    /// while the verdict of the pair with the local reader entry
    /// `reader_entry` is not on record: exactly when `writer_pair_verdict`
    /// has nothing to read (no record of the writer, or one for another
    /// topic, or no such reader entry). Every remote writer discovery holds
    /// is judged when its announcement is handled and when the registry is
    /// installed, so this lasts only while an announcement is between its
    /// insertion and its judgment: the reader reports it when it lasts past
    /// the discovery lease (`ReaderSubscriber::ownership_gate`).
    pub(crate) fn writer_held_but_unjudged(
        &self,
        writer_guid: &[u8; 16],
        topic: &str,
        reader_entry: u64,
    ) -> bool {
        if self
            .writer_pair_verdict(writer_guid, reader_entry, topic)
            .is_some()
        {
            return false;
        }
        self.discovery_fsm.upgrade().is_some_and(|fsm| {
            fsm.current_endpoint(topic, &GUID::from_bytes(*writer_guid))
                .is_some()
        })
    }

    /// The discovery lease this participant runs with, in milliseconds
    /// (`u64::MAX` for a lease that never expires); `None` once discovery is
    /// gone.
    pub(crate) fn discovery_lease_ms(&self) -> Option<u64> {
        self.discovery_fsm
            .upgrade()
            .map(|fsm| fsm.local_lease_duration_ms())
    }

    /// Whether some local reader entry refuses the remote writer.
    #[cfg(test)]
    pub(crate) fn is_writer_refused_by_any(&self, writer_guid: &[u8; 16]) -> bool {
        self.refused_pairs.contains_key(writer_guid)
    }

    /// THE type verdict of a (writer, reader) pairing, DDS-XTypes v1.3
    /// Sec.7.6.3.4.2: whether the reader's type is assignable from the
    /// writer's under the READER's TypeConsistencyEnforcement.
    ///
    /// Every place that decides on types asks this one function: the match
    /// (`evaluate_entries`, `catch_up`), the reader's data-plane gate
    /// (`mark_writer_incompatible`, armed by `DiscoveryFsm::handle_sedp` and
    /// when a TypeLookup reply resolves a type), and `on_inconsistent_topic`.
    /// Keeping one decision (rather than a variant per call site, with or
    /// without the resolver, with or without the type names, with the
    /// arrival-time copy of the remote type or the registry's) guarantees a
    /// pairing marked incompatible on one path cannot be matched on another,
    /// and the outcome does not depend on which SEDP and which TypeLookup
    /// reply came first.
    ///
    /// Both TypeObjects known (`TypeState::Known` on both sides): structural
    /// assignability (Step 1), through the participant's type store when it
    /// holds anything, so hash-referenced member types are compared by
    /// structure. The type names are not compared.
    ///
    /// Otherwise one side has no TypeObject, and the verdict depends on its
    /// state (see `absent_side_verdict`, the one place Step 2 is applied):
    ///
    /// - Either side `Pending` (a complete TypeIdentifier announced, its
    ///   TypeObject not arrived yet): today's behaviour, whatever the mode,
    ///   and no Step 2 decision. Today's behaviour is the verdict of a
    ///   pairing with one side unknown before Step 2 existed: accepted unless
    ///   the reader forces type validation. It is kept during the pending
    ///   window so a pairing does not flap match, unmatch, match when the
    ///   TypeLookup reply lands. It also stays for good when no reply ever
    ///   comes.
    /// - Otherwise (one side `Absent`, the other `Absent` or `Known`): Step 2,
    ///   under the process mode (`type_name_match_mode`, `HDDS_TYPE_NAME_MATCH`).
    ///
    /// Every place that decides on types asks this one function: the match
    /// (`evaluate_entries`, `catch_up`), the reader's data-plane gate
    /// (`mark_writer_incompatible`, armed by `DiscoveryFsm::handle_sedp` and
    /// when a TypeLookup reply resolves a type), and `on_inconsistent_topic`.
    /// Keeping one decision (rather than a variant per call site, with or
    /// without the resolver, with or without the type names, with the
    /// arrival-time copy of the remote type or the registry's) guarantees a
    /// pairing marked incompatible on one path cannot be matched on another,
    /// and the outcome does not depend on which SEDP and which TypeLookup
    /// reply came first.
    /// `topic` is the topic of the pairing, for the warn-mode log.
    pub(crate) fn pairing_type_verdict(
        &self,
        topic: &str,
        writer: TypeSide<'_>,
        reader: TypeSide<'_>,
        reader_policy: Option<&crate::protocol::discovery::types::TypeConsistencyEnforcement>,
    ) -> bool {
        self.pairing_type_verdict_in(self.type_name_mode, topic, writer, reader, reader_policy)
    }

    /// Record a pairing Step 2 would refuse in warn mode. True the first
    /// time for this (topic, writer type name, reader type name): the caller
    /// logs then, and only then.
    fn record_step2_warning(&self, topic: &str, writer: &str, reader: &str) -> bool {
        self.step2_warned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((topic.to_string(), writer.to_string(), reader.to_string()))
    }

    /// How many distinct pairings on `topic` Step 2 has refused in warn mode
    /// through this registry: one per distinct (writer type name, reader type
    /// name), however often the pairing is judged.
    #[allow(dead_code)] // read by the tests; the counter is for diagnostics from Rust
    pub(crate) fn type_name_warning_count(&self, topic: &str) -> usize {
        self.step2_warned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(warned_topic, _, _)| warned_topic == topic)
            .count()
    }

    /// This registry built with Step 2 in `mode` instead of the process mode
    /// (tests drive each mode through the match path).
    #[cfg(test)]
    pub(crate) fn with_type_name_mode(mut self, mode: TypeNameMatch) -> Self {
        self.type_name_mode = mode;
        self
    }

    /// `pairing_type_verdict` under an explicit Step 2 `mode` (the process
    /// mode is read once; tests pass each mode here).
    pub(crate) fn pairing_type_verdict_in(
        &self,
        mode: TypeNameMatch,
        topic: &str,
        writer: TypeSide<'_>,
        reader: TypeSide<'_>,
        reader_policy: Option<&crate::protocol::discovery::types::TypeConsistencyEnforcement>,
    ) -> bool {
        match (writer.object, reader.object) {
            (Some(writer), Some(reader)) => {
                #[cfg(feature = "xtypes-structural-assignability")]
                {
                    let resolver = self.snapshot_resolver();
                    let resolver_ref: Option<
                        &dyn crate::core::discovery::matcher::TypeObjectResolver,
                    > = if resolver.is_empty() {
                        None
                    } else {
                        Some(&resolver)
                    };
                    Matcher::is_type_compatible_with_resolver(
                        Some(writer),
                        Some(reader),
                        "",
                        "",
                        reader_policy,
                        resolver_ref,
                    )
                }
                #[cfg(not(feature = "xtypes-structural-assignability"))]
                {
                    Matcher::is_type_compatible_with_policy(
                        Some(writer),
                        Some(reader),
                        "",
                        "",
                        reader_policy,
                    )
                }
            }
            _ => self.absent_side_verdict(mode, topic, writer, reader, reader_policy),
        }
    }

    /// The verdict of a pairing with a side that has no TypeObject (not both
    /// `Known`): Step 2 of DDS-XTypes v1.3 Sec.7.6.3.4.2, applied by `mode`.
    ///
    /// Step 2 passes only when the reader does not force type validation AND
    /// the two type names are equal, compared exactly as announced. A
    /// `Pending` side is never judged by Step 2: today's verdict stands
    /// (see `pairing_type_verdict_in`).
    ///
    /// - `Off`: today's verdict, accepted unless the reader forces type
    ///   validation. The names are not looked at.
    /// - `Warn`: today's verdict, so the match is the same as in `Off`. When
    ///   Step 2 would refuse, the pairing is logged once per (topic, writer
    ///   name, reader name) and counted (`type_name_warning_count`).
    /// - `Enforce`: Step 2 itself, so a refused pairing is not matched and is
    ///   reported as an inconsistent topic by the callers of this verdict.
    fn absent_side_verdict(
        &self,
        mode: TypeNameMatch,
        topic: &str,
        writer: TypeSide<'_>,
        reader: TypeSide<'_>,
        reader_policy: Option<&crate::protocol::discovery::types::TypeConsistencyEnforcement>,
    ) -> bool {
        let forced = reader_policy.is_some_and(|tc| tc.force_type_validation);
        if writer.state() == TypeState::Pending || reader.state() == TypeState::Pending {
            return !forced;
        }
        let names_equal = writer.name == reader.name;
        match mode {
            TypeNameMatch::Off => !forced,
            TypeNameMatch::Warn => {
                if (forced || !names_equal)
                    && self.record_step2_warning(topic, writer.name, reader.name)
                {
                    log::warn!(
                        "[match] type-name check (DDS-XTypes 7.6.3.4.2 Step 2) would refuse \
                         topic '{}': writer type '{}', reader type '{}', force_type_validation={} \
                         (HDDS_TYPE_NAME_MATCH=warn: matched anyway)",
                        topic,
                        writer.name,
                        reader.name,
                        forced
                    );
                }
                !forced
            }
            TypeNameMatch::Enforce => !forced && names_equal,
        }
    }

    /// The type an endpoint is judged by: its TypeObject, or, when it
    /// announced only a TypeInformation, the local TypeObject that
    /// TypeInformation resolves to (`resolve_type_information`), or none.
    ///
    /// A TypeObject decoded from a legacy v1 announcement is lossy (v1
    /// collapses IDL byte/uint8/int8 to one wire kind, see
    /// `SedpData::type_object_legacy_v1`): the same-named local type replaces
    /// it when the two are v1-projection-equivalent
    /// (`resolve_v1_substitute`), else the decoded object stays
    /// authoritative. Re-attempted here, at judgement time, because the
    /// arrival-time substitution misses when the local type registered after
    /// the remote SEDP.
    pub(crate) fn effective_type_object(
        &self,
        endpoint: &EndpointInfo,
    ) -> Option<CompleteTypeObject> {
        #[cfg(feature = "xtypes-structural-assignability")]
        {
            if endpoint.type_object_legacy_v1 {
                return endpoint
                    .type_object
                    .as_ref()
                    .and_then(|decoded| self.resolve_v1_substitute(&endpoint.type_name, decoded))
                    .or_else(|| endpoint.type_object.clone());
            }
            endpoint.type_object.clone().or_else(|| {
                endpoint
                    .type_information
                    .as_ref()
                    .and_then(|ti| self.resolve_type_information(ti, &endpoint.type_name))
            })
        }
        #[cfg(not(feature = "xtypes-structural-assignability"))]
        {
            endpoint.type_object.clone()
        }
    }

    /// The judged record of the remote writer `remote`, with `qos`: its type
    /// as discovery knows it now (`current_record`, else `remote` itself).
    fn writer_record(&self, remote: &EndpointInfo, qos: QoS) -> JudgedWriter {
        let current = self.current_record(remote);
        let judged_on = current.as_ref().unwrap_or(remote);
        let type_object = self.effective_type_object(judged_on);
        JudgedWriter {
            topic: remote.topic_name.clone(),
            qos,
            type_name: judged_on.type_name.clone(),
            type_pending: type_object.is_none() && judged_on.announced_complete_hash().is_some(),
            type_object,
        }
    }

    /// The registry's current record of `remote` (`DiscoveryFsm::current_endpoint`),
    /// `None` when discovery no longer holds it. The `EndpointInfo` a
    /// notification carries is a copy taken when its SEDP arrived; a
    /// TypeLookup reply resolved since then updated the topic registry, not
    /// that copy (a deferred discovery is replayed from it up to the end of
    /// our probation). A caller that judges by the record reads its type
    /// object, its type name and its Pending state from the same record,
    /// with `unwrap_or(remote)` as the fallback: an endpoint discovery no
    /// longer knows is judged by the copy.
    fn current_record(&self, remote: &EndpointInfo) -> Option<EndpointInfo> {
        self.discovery_fsm
            .upgrade()
            .and_then(|fsm| fsm.current_endpoint(&remote.topic_name, &remote.endpoint_guid))
    }

    /// The vendor of the participant at `participant_guid`, resolved once
    /// at pairing time from SPDP (`DiscoveryFsm::vendor_id_for_participant`
    /// -- the vendor zone, cold path: called only from `rxo_verdict`'s
    /// callers, never per message). `None` for a participant discovery does
    /// not (yet) know, or this process's own.
    fn remote_vendor_of(&self, participant_guid: &GUID) -> Option<u16> {
        self.discovery_fsm
            .upgrade()
            .and_then(|fsm| fsm.vendor_id_for_participant(participant_guid))
    }

    /// Whether `type_object` contains wchar/wstring per
    /// `cdr_negotiation::type_contains_wchar`, for the RTI XCDR1 wchar
    /// refusal (resolves a named nested type through the local type store,
    /// `resolve_type_by_minimal_hash`, under feature
    /// `xtypes-structural-assignability`; without it, only the type's own
    /// one-level description is read -- a hash it cannot resolve stops that
    /// branch, per `type_contains_wchar`'s doc, never guessed).
    fn local_type_contains_wchar(&self, type_object: Option<&CompleteTypeObject>) -> bool {
        // Without a description of its own type (a hand-written DDS
        // implementation, a build without xtypes) the endpoint cannot tell
        // whether it carries wchar: it is matched as before. Logged, so an
        // RTI pairing that may still decode XCDR1 wchar wrong is not silent.
        let Some(type_object) = type_object else {
            log::debug!(
                "[match] local type has no TypeObject: XCDR1 wchar width cannot be checked against an RTI peer"
            );
            return false;
        };
        #[cfg(feature = "xtypes-structural-assignability")]
        let resolve = |h: &crate::xtypes::EquivalenceHash| self.resolve_type_by_minimal_hash(h);
        #[cfg(not(feature = "xtypes-structural-assignability"))]
        let resolve = |_: &crate::xtypes::EquivalenceHash| None;
        crate::dds::cdr_negotiation::type_contains_wchar(type_object, &resolve)
    }

    /// Judge a remote endpoint just discovered against this participant's
    /// registered endpoints of the opposite kind on its topic, with the one
    /// type verdict. Gates a refused remote writer's samples off
    /// (`mark_writer_incompatible`) and returns whether any local endpoint
    /// refuses it, for the caller to queue `on_inconsistent_topic`
    /// (`notify_inconsistent_type_for_topic`, which asks the verdict again per
    /// entry). The match itself is refused by `evaluate_entries`.
    pub(crate) fn judge_remote_types(&self, remote: &EndpointInfo) -> bool {
        if remote.endpoint_guid.prefix == self.local_guid_prefix {
            return false;
        }
        let remote_type = self.effective_type_object(remote);
        let mut any_refused = false;
        for entry in self.entries_snapshot() {
            let Some(refused) = self.entry_refuses(&entry, remote, remote_type.as_ref()) else {
                continue;
            };
            if remote.kind == EndpointKind::Writer {
                self.set_writer_refused_by(
                    remote.endpoint_guid.as_bytes(),
                    entry.id,
                    Refusal::TYPE,
                    refused,
                );
            }
            any_refused |= refused;
        }
        any_refused
    }

    /// The type verdict of `entry` on `remote` (whose effective type is
    /// `remote_type`): `Some(true)` when the pairing is refused,
    /// `Some(false)` when accepted, `None` when they are no pairing (another
    /// topic, or the same kind).
    fn entry_refuses(
        &self,
        entry: &MatchEntry,
        remote: &EndpointInfo,
        remote_type: Option<&CompleteTypeObject>,
    ) -> Option<bool> {
        if entry.topic != remote.topic_name {
            return None;
        }
        match (entry.kind, remote.kind) {
            (LocalKind::Reader, EndpointKind::Writer) => Some(!self.pairing_type_verdict(
                &remote.topic_name,
                remote_side(remote, remote_type),
                entry_side(entry),
                entry.qos.type_consistency.as_ref(),
            )),
            (LocalKind::Writer, EndpointKind::Reader) => Some(!self.pairing_type_verdict(
                &remote.topic_name,
                entry_side(entry),
                remote_side(remote, remote_type),
                remote.qos.type_consistency.as_ref(),
            )),
            _ => None,
        }
    }

    /// A remote endpoint's TypeObject was learned after its discovery (a
    /// TypeLookup reply, `DiscoveryFsm::update_type_object_for_hash`): judge
    /// every local entry on its topic again with the one verdict, and undo
    /// what a pairing it now refuses was given while the type was unknown.
    ///
    /// For each local entry of the opposite kind the pairing refuses: the
    /// match is withdrawn (`dispatch_unmatch`: the callback with -1, the
    /// proxies released; nothing when it was never matched) and
    /// `on_inconsistent_topic` fires when `notify` holds. A remote writer's
    /// data-plane gate is set to what the local readers now say: armed when
    /// one refuses it, cleared when none does - a refusal made while its type
    /// was unknown (force_type_validation) is lifted once the type is known
    /// and accepted, and the pairing is matched when `may_match` holds (the
    /// match path would surface the endpoint now) and its QoS accept it
    /// (`evaluate_entries`). Only a pairing whose verdict FLIPPED from refused
    /// to accepted is matched here: one accepted already was matched at
    /// discovery, and is left as it is.
    pub(crate) fn rejudge_remote_types(
        &self,
        remote: &EndpointInfo,
        notify: bool,
        may_match: bool,
    ) {
        if remote.endpoint_guid.prefix == self.local_guid_prefix {
            return;
        }
        let remote_type = self.effective_type_object(remote);
        if remote.kind == EndpointKind::Writer {
            if let Some(writer) = self
                .judged_writers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&remote.endpoint_guid.as_bytes())
            {
                writer.type_object = remote_type.clone();
                writer.type_name = remote.type_name.clone();
                writer.type_pending =
                    remote_type.is_none() && remote.announced_complete_hash().is_some();
            }
        }
        // What the verdict said before the type was learned: the same
        // endpoint, its learned TypeObject not yet there.
        let type_before = self.effective_type_object(&EndpointInfo {
            type_object: None,
            ..remote.clone()
        });
        let mut lifted: Vec<Arc<MatchEntry>> = Vec::new();
        for entry in self.entries_snapshot() {
            let Some(refused) = self.entry_refuses(&entry, remote, remote_type.as_ref()) else {
                continue;
            };
            if remote.kind == EndpointKind::Writer {
                self.set_writer_refused_by(
                    remote.endpoint_guid.as_bytes(),
                    entry.id,
                    Refusal::TYPE,
                    refused,
                );
            }
            if !refused {
                if self.entry_refuses(&entry, remote, type_before.as_ref()) == Some(true) {
                    lifted.push(entry);
                }
                continue;
            }
            self.dispatch_unmatch(remote, &entry);
            if notify {
                self.notify_inconsistent_type(entry.id, remote.endpoint_guid);
            }
        }
        if !may_match || lifted.is_empty() {
            return;
        }
        for (entry_id, verdict) in self.evaluate_entries(remote) {
            if !matches!(verdict, EntryVerdict::Match) {
                continue;
            }
            if let Some(entry) = lifted.iter().find(|e| e.id == entry_id) {
                self.dispatch_match(remote, entry);
            }
        }
    }

    /// Resolve the PARTITION QoS of a remote writer on `topic` by GUID, from
    /// the SEDP discovery cache. Returns `None` when the writer has not yet
    /// been discovered (its SEDP DATA(w) has not been processed).
    ///
    /// Consulted by the reader user-data delivery path to decide, per sample,
    /// whether the source writer's partition intersects the reader's partition
    /// (DDS v1.4 sec. 2.2.3.13). Resolving at delivery time (rather than pre-arming
    /// a deny set at SEDP time) makes the gate race-free: HDDS routes user DATA
    /// by topic name, so a writer's multicast can reach a reader before the
    /// writer's SEDP is processed; a partitioned reader treats an as-yet
    /// unresolved writer as not-matched and drops the sample until discovery
    /// confirms a compatible partition.
    pub(crate) fn resolve_writer_partition(
        &self,
        topic: &str,
        writer_guid: &[u8; 16],
    ) -> Option<crate::qos::partition::Partition> {
        let fsm = self.discovery_fsm.upgrade()?;
        fsm.find_writers_for_topic(topic)
            .into_iter()
            .find(|w| &w.endpoint_guid.as_bytes() == writer_guid)
            .map(|w| w.qos.partition.clone())
    }

    /// The SEDP registry's generation (`DiscoveryFsm::topic_registry_generation`):
    /// it moves on every endpoint mutation, a re-announcement included, so an
    /// answer a reader files per writer cannot outlive the announcement it
    /// was read from. `None` once the discovery FSM is gone: nothing can be
    /// resolved then, and a caller must not file under a generation that
    /// would match a real one.
    #[cfg(feature = "security")]
    pub(crate) fn discovery_generation(&self) -> Option<u64> {
        self.discovery_fsm
            .upgrade()
            .map(|fsm| fsm.topic_registry_generation())
    }

    /// A remote writer's announced endpoint security attributes, keeping
    /// apart the two reasons the answer can be absent: `None` when discovery
    /// holds no such writer (not announced yet, so the question must be
    /// asked again later), and `Some(None)` when it holds the writer and the
    /// announcement carried no `PID_ENDPOINT_SECURITY_INFO` (a settled
    /// answer). A caller caching the answer per writer
    /// (`ReaderSubscriber::writer_payload_security`) may file the second
    /// kind, never the first.
    #[cfg(feature = "security")]
    pub(crate) fn resolve_writer_security_slot(
        &self,
        topic: &str,
        writer: &[u8; 16],
    ) -> Option<Option<crate::protocol::discovery::EndpointSecurityInfo>> {
        Some(
            self.discovery_fsm
                .upgrade()?
                .find_writers_for_topic(topic)
                .into_iter()
                .find(|w| &w.endpoint_guid.as_bytes() == writer)?
                .endpoint_security_info,
        )
    }

    /// Resolve a remote writer's effective OWNERSHIP kind from its cached
    /// SEDP announcement (DDS v1.4 sec. 2.2.3.11 RxO: kinds must match exactly).
    /// Applies the same PID-presence inference `evaluate_entries()` uses:
    /// PID_OWNERSHIP present -> use it; absent + PID_OWNERSHIP_STRENGTH
    /// present -> EXCLUSIVE; both absent -> SHARED. Returns `None` when the
    /// writer has not been discovered via SEDP yet (or the discovery FSM has
    /// already been torn down), which the caller treats as "not yet
    /// resolved" rather than "compatible" -- see
    /// `ReaderSubscriber::writer_ownership_incompatible`.
    pub(crate) fn resolve_writer_ownership(
        &self,
        topic: &str,
        writer_guid: &[u8; 16],
    ) -> Option<crate::qos::ownership::OwnershipKind> {
        let fsm = self.discovery_fsm.upgrade()?;
        fsm.find_writers_for_topic(topic)
            .into_iter()
            .find(|w| &w.endpoint_guid.as_bytes() == writer_guid)
            .map(|w| {
                crate::qos::ownership::OwnershipKind::announced(
                    w.has_explicit_ownership.then_some(w.qos.ownership.kind),
                    w.has_ownership_strength,
                )
            })
    }

    /// Register a local writer for match notifications without an
    /// INCOMPATIBLE_QoS callback. Convenience wrapper over
    /// [`Self::register_writer_with_incompatible`] for callers that only
    /// want match-success events.
    #[allow(dead_code)]
    pub fn register_writer(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_encoding: impl Into<LocalType>,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
    ) -> MatchToken {
        self.register_writer_with_incompatible(topic, qos, type_encoding, callback, None)
    }

    /// Register a local writer with both match and incompatible QoS callbacks.
    pub fn register_writer_with_incompatible(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_encoding: impl Into<LocalType>,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
        incompatible_callback: Option<IncompatibleCallback>,
    ) -> MatchToken {
        self.register_writer_full(
            topic,
            qos,
            type_encoding,
            None,
            callback,
            incompatible_callback,
            None,
            ShmPolicy::default(),
            None,
        )
    }

    /// Register a local writer with all three notification channels: match,
    /// incompatible QoS, and inconsistent topic type.
    ///
    /// `type_object` is the local writer's XTypes complete type object.
    /// When present, `notify_inconsistent_type_for_topic` performs per-entry
    /// structural assignability checks so fan-out only reaches entries whose
    /// type is actually incompatible with the discovered remote's type
    /// (DDS-XTypes v1.3 sec. 7.6.3.4.3). The counter is always maintained
    /// regardless of whether a callback or type object is installed.
    ///
    /// `shm_policy` is the local participant's configured `ShmPolicy`
    /// (`Participant::shm_policy()`), captured on the entry so the SHM-vs-UDP
    /// transport verdict for each matched remote can be resolved once, at
    /// match time, without re-reading participant state on every SEDP event.
    ///
    /// `shm_selected` is the writer's own latch (see `MatchEntry`): set to
    /// true the first time a remote on this entry resolves to shared memory,
    /// so the writer's send loop can stay a single relaxed atomic load per
    /// packet while no reader is reachable that way.
    #[allow(clippy::too_many_arguments)]
    pub fn register_writer_full(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_encoding: impl Into<LocalType>,
        type_object: Option<CompleteTypeObject>,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
        incompatible_callback: Option<IncompatibleCallback>,
        inconsistent_topic_callback: Option<InconsistentTopicCallback>,
        shm_policy: ShmPolicy,
        shm_selected: Option<Arc<AtomicBool>>,
    ) -> MatchToken {
        self.register_writer_with_peers(
            topic,
            qos,
            type_encoding,
            type_object,
            callback,
            None,
            incompatible_callback,
            inconsistent_topic_callback,
            shm_policy,
            shm_selected,
        )
    }

    /// [`register_writer_full`](Self::register_writer_full) with a
    /// per-peer callback, told of each remote reader that matches (with its
    /// reliability) or unmatches before `callback` fires. It is installed
    /// before the catch-up below, so readers already discovered reach it
    /// too.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_writer_with_peers(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_encoding: impl Into<LocalType>,
        type_object: Option<CompleteTypeObject>,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
        peer_callback: Option<PeerCallback>,
        incompatible_callback: Option<IncompatibleCallback>,
        inconsistent_topic_callback: Option<InconsistentTopicCallback>,
        shm_policy: ShmPolicy,
        shm_selected: Option<Arc<AtomicBool>>,
    ) -> MatchToken {
        let LocalType {
            encoding: xcdr1,
            type_name,
        } = type_encoding.into();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = MatchEntry {
            id,
            topic: topic.clone(),
            qos: qos.clone(),
            kind: LocalKind::Writer,
            xcdr1,
            type_name,
            type_object,
            callback: Box::new(callback),
            peer_callback,
            liveliness_hook: None,
            incompatible_callback,
            inconsistent_topic_callback,
            shm_policy,
            matched_remotes: Mutex::new(HashMap::new()),
            peer_records: Mutex::new(HashMap::new()),
            incompat_remotes: Mutex::new(HashSet::new()),
            inconsistent_type_remotes: Mutex::new(HashSet::new()),
            total_count: AtomicU32::new(0),
            incompatible_count: AtomicU32::new(0),
            inconsistent_type_count: AtomicU32::new(0),
            last_reported_inconsistent_type_count: AtomicU32::new(0),
            reader_lifespan_nanos: None,
            shm_selected,
            dispatch_gate: DispatchGate::new(),
            notices: Arc::default(),
        };
        {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            entries.push(Arc::new(entry));
        }
        self.catch_up(id, LocalKind::Writer, &topic, &qos, xcdr1);
        MatchToken {
            registry: Arc::downgrade(self),
            id,
        }
    }

    /// Register a local reader and additionally hand in an `AtomicU64` that
    /// will be tightened (min) whenever a compatible remote writer announces
    /// a finite Lifespan via SEDP. Used by the DataReader runtime so that
    /// writer-announced lifespans filter samples even when the reader did
    /// not request a lifespan of its own.
    ///
    /// `inconsistent_cb` is fired (at most once per distinct remote writer GUID)
    /// when a remote writer on the same topic carries a type that is structurally
    /// incompatible with the local reader's type per DDS-XTypes v1.3 sec. 7.6.3.4.3.
    /// The counter is incremented regardless of whether a callback is installed.
    ///
    /// `peer_callback` is told of each remote writer that matches (with its
    /// reliability) or unmatches, before `callback` fires. It is installed
    /// before the catch-up, so writers already discovered reach it too.
    ///
    /// `shm_policy` is the local participant's configured `ShmPolicy`; see
    /// `register_writer_full` for why it is captured on the entry.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn register_reader_with_lifespan(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_encoding: impl Into<LocalType>,
        type_object: Option<CompleteTypeObject>,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
        peer_callback: Option<PeerCallback>,
        incompatible_callback: Option<IncompatibleCallback>,
        inconsistent_cb: Option<InconsistentTopicCallback>,
        reader_lifespan_nanos: Arc<AtomicU64>,
        shm_policy: ShmPolicy,
    ) -> MatchToken {
        self.register_reader_full(
            topic,
            qos,
            type_encoding,
            type_object,
            callback,
            peer_callback,
            incompatible_callback,
            inconsistent_cb,
            Some(reader_lifespan_nanos),
            shm_policy,
            None,
        )
    }

    /// [`Self::register_reader_with_lifespan`] for a reader that keeps the
    /// liveliness of the writers it matches: `liveliness_hook` is told each
    /// writer that matches or unmatches, before `callback`, from the
    /// catch-up on.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_reader_with_liveliness(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_encoding: impl Into<LocalType>,
        type_object: Option<CompleteTypeObject>,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
        peer_callback: Option<PeerCallback>,
        incompatible_callback: Option<IncompatibleCallback>,
        inconsistent_cb: Option<InconsistentTopicCallback>,
        reader_lifespan_nanos: Arc<AtomicU64>,
        shm_policy: ShmPolicy,
        liveliness_hook: Option<LivelinessHook>,
    ) -> MatchToken {
        self.register_reader_full(
            topic,
            qos,
            type_encoding,
            type_object,
            callback,
            peer_callback,
            incompatible_callback,
            inconsistent_cb,
            Some(reader_lifespan_nanos),
            shm_policy,
            liveliness_hook,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_reader_full(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_encoding: impl Into<LocalType>,
        type_object: Option<CompleteTypeObject>,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
        peer_callback: Option<PeerCallback>,
        incompatible_callback: Option<IncompatibleCallback>,
        inconsistent_cb: Option<InconsistentTopicCallback>,
        reader_lifespan_nanos: Option<Arc<AtomicU64>>,
        shm_policy: ShmPolicy,
        liveliness_hook: Option<LivelinessHook>,
    ) -> MatchToken {
        let LocalType {
            encoding: xcdr1,
            type_name,
        } = type_encoding.into();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = MatchEntry {
            id,
            topic: topic.clone(),
            qos: qos.clone(),
            kind: LocalKind::Reader,
            xcdr1,
            type_name,
            type_object,
            callback: Box::new(callback),
            peer_callback,
            liveliness_hook,
            incompatible_callback,
            inconsistent_topic_callback: inconsistent_cb,
            shm_policy,
            matched_remotes: Mutex::new(HashMap::new()),
            peer_records: Mutex::new(HashMap::new()),
            incompat_remotes: Mutex::new(HashSet::new()),
            inconsistent_type_remotes: Mutex::new(HashSet::new()),
            total_count: AtomicU32::new(0),
            incompatible_count: AtomicU32::new(0),
            inconsistent_type_count: AtomicU32::new(0),
            last_reported_inconsistent_type_count: AtomicU32::new(0),
            reader_lifespan_nanos,
            shm_selected: None,
            dispatch_gate: DispatchGate::new(),
            notices: Arc::default(),
        };
        {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            entries.push(Arc::new(entry));
        }
        self.catch_up(id, LocalKind::Reader, &topic, &qos, xcdr1);
        MatchToken {
            registry: Arc::downgrade(self),
            id,
        }
    }

    /// Remove the entry, then close its dispatch gate: waits for a callback
    /// of this entry running on another thread, so none fires once this has
    /// returned. Called from inside one of the entry's own callbacks, it
    /// does not wait for that callback (see `DispatchGate`).
    fn unregister(&self, id: u64) {
        self.local_endpoints
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, entry| *entry != id);
        let removed: Vec<Arc<MatchEntry>> = {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            let (removed, kept) = entries.drain(..).partition(|e| e.id == id);
            *entries = kept;
            removed
        };
        for entry in removed {
            entry.dispatch_gate.close();
            // Nothing more of it reaches its listener.
            entry.notices.close();
        }
        // An entry that leaves takes its verdicts with it.
        self.refused_pairs.retain(|_, refusing| {
            refusing.remove(&id);
            !refusing.is_empty()
        });
    }

    /// The registered entry `id`, for a dispatch outside the registry lock.
    fn entry(&self, id: u64) -> Option<Arc<MatchEntry>> {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries.iter().find(|e| e.id == id).cloned()
    }

    /// Every registered entry, for a dispatch outside the registry lock.
    fn entries_snapshot(&self) -> Vec<Arc<MatchEntry>> {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Refresh the internal proxy of an existing reader match after SPDP
    /// resolves its wire dialect. This is not a new publication match and
    /// must not change the application's match counters or callbacks.
    pub(crate) fn refresh_reader_dialect(&self, endpoint: &EndpointInfo) -> bool {
        if endpoint.kind != EndpointKind::Reader {
            return false;
        }
        let mut refreshed = false;
        for entry in self.entries_snapshot() {
            if entry.kind != LocalKind::Writer || entry.topic != endpoint.topic_name {
                continue;
            }
            let Some(_gate) = entry.open_gate() else {
                continue;
            };
            // A proxy can already exist while probation still withholds
            // the application match notification.
            let paired = entry.peer_records.lock().unwrap_or_else(|e| e.into_inner());
            let current = paired
                .get(&endpoint.endpoint_guid)
                .is_some_and(|held| *held == endpoint.incarnation);
            drop(paired);
            if current {
                Self::tell_peer_matched(&entry, endpoint);
                refreshed = true;
            }
        }
        refreshed
    }

    fn current_match_count(&self, id: u64) -> u32 {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries
            .iter()
            .find(|entry| entry.id == id)
            .map_or(0, |entry| {
                let matched = entry
                    .matched_remotes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .len();
                u32::try_from(matched).unwrap_or(u32::MAX)
            })
    }

    /// Record that entry `id` stands for the local endpoint `guid`
    /// (`MatchToken::bind_local_guid`). An entry already gone is not
    /// recorded: nothing would ever remove it.
    fn bind_local_guid(&self, id: u64, guid: GUID) {
        let mut local = self
            .local_endpoints
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if self.entry(id).is_some() {
            local.insert(guid, id);
        }
    }

    /// The remote endpoints the local endpoint `local` is matched with, or
    /// `None` when `local` is no endpoint registered here (never
    /// registered, or since deleted). The match set is the one
    /// `get_matched_subscriptions` / `get_matched_publications` report.
    /// Read by the security plugins only (`DiscoveryFsm::
    /// local_endpoint_matches`).
    #[cfg_attr(not(feature = "security"), allow(dead_code))]
    pub(crate) fn local_endpoint_matches(&self, local: &GUID) -> Option<Vec<GUID>> {
        let id = *self
            .local_endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(local)?;
        let entry = self.entry(id)?;
        let matched = entry
            .matched_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect();
        Some(matched)
    }

    /// Identity of the current match event, including a rematch of the same
    /// endpoints before a token-distribution sweep can observe the unmatch.
    #[cfg(feature = "security")]
    pub(crate) fn local_endpoint_match_generation(
        &self,
        local: &GUID,
        remote: &GUID,
    ) -> Option<u64> {
        let id = *self
            .local_endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(local)?;
        let entry = self.entry(id)?;
        let matched = entry
            .matched_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Some(matched.get(remote)?.generation)
    }

    /// Local endpoints named by their GUID (`bind_local_guid`) still held.
    #[cfg(test)]
    pub(crate) fn named_local_endpoints(&self) -> usize {
        self.local_endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// GUIDs of the remote endpoints currently matched with entry `id`
    /// (DDS v1.4 Sec.2.2.2.4.2.24 `get_matched_subscriptions` on a writer,
    /// or Sec.2.2.2.5.3.34 `get_matched_publications` on a reader). Empty
    /// for an unknown id.
    fn matched_remote_guids(&self, id: u64) -> Vec<GUID> {
        self.entry(id)
            .map(|entry| {
                entry
                    .matched_remotes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .keys()
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// O(1) read of the transport verdict stored for `(entry_id, remote)`.
    /// Never recomputes: the verdict is a snapshot of whatever
    /// `dispatch_match` / `notify_entry` stored the one time this remote
    /// matched this entry.
    fn transport_selection_for(&self, entry_id: u64, remote: &GUID) -> Option<TransportSelection> {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        entries
            .iter()
            .find(|entry| entry.id == entry_id)
            .and_then(|entry| {
                entry
                    .matched_remotes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(remote)
                    .map(|matched| matched.transport)
            })
    }

    /// Catch-up: scan existing remote endpoints for matches with a newly registered entry.
    ///
    /// Called immediately after the entry is pushed into `entries` so that remote
    /// endpoints already cached in the FSM at registration time are not silently
    /// invisible to the new entry. Runs the same QoS / DataRepresentation checks
    /// as the live SEDP path.
    ///
    /// Additionally runs a structural type-compatibility check (XTypes v1.3 sec. 7.6.3.4.3)
    /// using the local entry's `type_object` against the cached remote's `type_object`.
    /// This closes the bootstrap window where a remote endpoint arrived and was cached
    /// BEFORE the local entry registered: without this check the `inconsistent_topic`
    /// status would never be surfaced for that remote/entry pair.
    fn catch_up(
        &self,
        entry_id: u64,
        kind: LocalKind,
        topic: &str,
        local_qos: &QoS,
        xcdr1: crate::dds::cdr_negotiation::Xcdr1Encoding,
    ) {
        let fsm = match self.discovery_fsm.upgrade() {
            Some(fsm) => fsm,
            None => return,
        };

        // Fetch local type object and announced type name from the entry that
        // was just pushed.
        let (local_type_object, local_type_name): (Option<CompleteTypeObject>, String) = {
            let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
            entries.iter().find(|e| e.id == entry_id).map_or_else(
                || (None, String::new()),
                |e| (e.type_object.clone(), e.type_name.clone()),
            )
        };

        // During the startup probation window the remote set may contain zombie
        // entries from recently-killed prior-test processes (same domain). We
        // still run the catch-up scan (after the zombie purge below) so that
        // QoS-incompatibility surfaces IMMEDIATELY for a late-joining local entry
        // whose incompatible remote was discovered BEFORE registration: the OMG
        // harness reads the FIRST status line, and a QoS-incompat fired only
        // after the 250 ms probation drain loses to sample data that arrives in
        // ~10 ms (the submitted reference fires on_requested_incompatible_qos
        // before the first sample for exactly this reason). QoS-incompat is
        // zombie-safe -- a false incompat for a dead participant is harmless and
        // matches the ungated live path (notify_endpoint_discovered_incompat_only
        // fires with zero participant-confirmation gate). Match and type-incompat
        // notifications stay SUPPRESSED during probation (gated on
        // `probation_active` below) to avoid false on_subscription_matched
        // for zombies. A match skipped here surfaces through the replay of
        // the participant's deferred discovery once probation ends
        // (`replay_pending_for_participant`). A type-incompat is reported at
        // once, as `handle_sedp` reports it (it has no replay to wait for).
        let probation_active = !fsm.is_probation_done();

        // Purge zombie-confirmed participants (spdp_count==2, last_seen > 300 ms)
        // before scanning remote endpoints. Zombies from a prior test run can
        // reach spdp_count==2 before the 250 ms unconfirmed purge fires; they
        // stay in the DB with a stale last_seen because dead processes cannot
        // send a third SPDP. Without this pre-purge a new local writer's
        // catch-up scan matches the zombie reader and fires on_publication_matched
        // before the real subscriber's type-incompatibility notification arrives,
        // causing the OMG harness to record OK instead of INCONSISTENT_TOPIC for
        // tests that depend on on_inconsistent_topic reaching the publisher first.
        fsm.purge_zombie_confirmed_participants();

        let remote_endpoints = match kind {
            // Every reader discovery holds: this path judges each one
            // (`admits_endpoint` below), and a reader refused by the
            // security plugins is still a reader whose QoS is compared.
            LocalKind::Writer => fsm.registered_readers_for_topic(topic),
            LocalKind::Reader => fsm.find_writers_for_topic(topic),
        };

        // A local READER registering is judged here on QoS against every
        // remote writer the router may route to it, discovery's and those
        // it holds back or forgot (`judge_reader_qos`): the data-plane gate
        // of each pair is set before any sample of the writer reaches this
        // reader. Its type verdicts are taken below.
        if kind == LocalKind::Reader {
            if let Some(entry) = self.entry(entry_id) {
                self.judge_reader_qos(&entry, &remote_endpoints);
            }
        }
        for remote in &remote_endpoints {
            // An endpoint of this participant is matched too (see
            // `on_endpoint_discovered`), with no zombie to fear and no proxy.
            let local = self.is_local(remote);
            // The one QoS verdict (`rxo_verdict`), on the other end's QoS as
            // it reads it (`qos_for_verdict`) and a local reader as it
            // announces itself (`local_reader_qos_for_verdict`), as the live
            // discovery path judges it (`evaluate_entries`).
            let remote_qos = self.qos_for_verdict(remote);
            let remote_vendor = self.remote_vendor_of(&remote.participant_guid);
            let local_wchar = self.local_type_contains_wchar(local_type_object.as_ref());
            let verdict = match kind {
                LocalKind::Writer => {
                    rxo_verdict(local_qos, &remote_qos, xcdr1, remote_vendor, local_wchar)
                }
                LocalKind::Reader => rxo_verdict(
                    &remote_qos,
                    &local_reader_qos_for_verdict(local_qos),
                    xcdr1,
                    remote_vendor,
                    local_wchar,
                ),
            };
            // Per DDS spec sec. 2.2.4.3.12, INCONSISTENT_TOPIC and
            // SUBSCRIPTION_MATCHED / PUBLICATION_MATCHED are orthogonal.
            // Match fires whenever QoS and DataRepresentation are compatible,
            // regardless of structural type assignability. The INCONSISTENT_TOPIC
            // status is reported independently via notify_inconsistent_type, which
            // is called here when both TypeObjects are present and incompatible,
            // or when force_type_validation=true and either TypeObject is absent.
            {
                // The one type verdict (`pairing_type_verdict`). `remote` is
                // the registry's current record, so a type a TypeLookup reply
                // resolved is seen; `effective_type_object` also resolves a
                // TypeInformation the local entry made resolvable by
                // registering (the peer never re-announces once reliable
                // SEDP is ACKed).
                let remote_type_object = self.effective_type_object(remote);
                let local_side = TypeSide {
                    object: local_type_object.as_ref(),
                    name: &local_type_name,
                    pending: false,
                };
                let remote_side = remote_side(remote, remote_type_object.as_ref());
                let type_ok = match kind {
                    // TypeConsistencyEnforcement is the reader's (Sec.7.6.3.4).
                    LocalKind::Writer => self.pairing_type_verdict(
                        topic,
                        local_side,
                        remote_side,
                        remote.qos.type_consistency.as_ref(),
                    ),
                    LocalKind::Reader => self.pairing_type_verdict(
                        topic,
                        remote_side,
                        local_side,
                        local_qos.type_consistency.as_ref(),
                    ),
                };
                // A refused pairing reports INCONSISTENT_TOPIC.
                //
                // A local READER registering is judged here against every
                // remote writer already known, and this is the one place that
                // judges it: the remote writer's samples are gated off
                // (`mark_writer_incompatible`) and the notification fires at
                // once, ungated, to beat the samples the writer is about to
                // send (with RELIABLE QoS a HEARTBEAT-driven repair lands
                // 10-25 ms after it discovers this reader). This is what the
                // reader's own SEDP did in `handle_sedp` before the verdict was
                // one, with the same exposure to a zombie writer: a false
                // on_inconsistent_topic, as QoS-incompat accepts.
                //
                // A local WRITER registering notifies once the remote reader's
                // participant is known, inside our probation too, the rule
                // `handle_sedp` applies to the same mismatch announced the
                // other way round (the reader's SEDP after the writer). Held
                // for the end of the probation, it was never told: nothing
                // replays a catch-up's notification, and the reader's
                // participant, kept by the probation, announces nothing again.
                // Two endpoints of one participant share its Topic, bound to
                // one type (DDS v1.4 Sec.2.2.2.2.1.5): a refused pairing of
                // them is not matched, and not reported here, as before.
                if !type_ok && !local {
                    if kind == LocalKind::Reader && remote.kind == EndpointKind::Writer {
                        self.set_writer_refused_by(
                            remote.endpoint_guid.as_bytes(),
                            entry_id,
                            Refusal::TYPE,
                            true,
                        );
                        self.notify_inconsistent_type(entry_id, remote.endpoint_guid);
                    } else if fsm.is_participant_known(&remote.endpoint_guid.prefix) {
                        self.notify_inconsistent_type(entry_id, remote.endpoint_guid);
                    }
                }
                // Gate the match on structural type compatibility (XTypes v1.3 sec. 7.6.3.4.3).
                // When both TypeObjects are present and types are incompatible, block the
                // match entirely so on_subscription_matched / on_publication_matched does
                // not fire. The OMG harness expects INCONSISTENT_TOPIC when types differ,
                // not a successful match followed by on_inconsistent_topic.
                if !type_ok {
                    continue;
                }
            }

            let compatible = verdict.is_ok();
            // An endpoint the security plugins do not admit (its participant
            // not yet authenticated, or refused on this topic) pairs with
            // nothing, here as on the live path (`DiscoveryFsm::admits_endpoint`).
            if compatible && !local && !fsm.admits_endpoint(remote) {
                continue;
            }
            if compatible {
                // Gate on participant liveness: stale SEDP cache entries from
                // recently-terminated participants (zombies) must not surface
                // as matched endpoints to a newly-registered local entry. The
                // gate is the one every surfacing path applies
                // (`DiscoveryFsm::may_surface_matches`: a participant first
                // heard during our probation surfaces once match eligible, one
                // heard after it from its first announcement). Without it a
                // zombie whose TypeObject matches the local type fires
                // on_publication_matched / on_subscription_matched before the
                // harness's target sub/pub arrives, causing pexpect to read
                // the zombie's OK code instead of the real result.
                //
                // is_participant_matchable_and_recent also rejects stale
                // participants: those whose last_seen has not been refreshed
                // within the freshness window (400 ms for an HDDS peer in its
                // burst phase, its lease otherwise). The catch-up reads cached
                // state, where the live path reacts to a fresh emission; this
                // keeps zombies from prior tests (which sent 3+ SPDPs during
                // their brief lifetime) out of the next test's catch-up scans.
                if !local
                    && (probation_active
                        || !fsm.is_participant_matchable_and_recent(&remote.endpoint_guid.prefix))
                {
                    log::debug!(
                        "[CATCH-UP] skipping match (probation_active={}) or unconfirmed/stale participant for remote guid={:?} topic={}",
                        probation_active,
                        remote.endpoint_guid,
                        topic
                    );
                    // The match waits for the gate; the proxies do not
                    // (RTPS 2.5 8.4.12 and 8.4.7.4, see `pair_at_discovery`).
                    self.pair_entry_at_discovery(entry_id, remote);
                    // Inside probation the endpoint already waits in the
                    // FSM's deferred list (its SEDP was deferred there) and
                    // the drain or the replay surfaces it against every
                    // entry, this one included. After the boundary nothing
                    // would: it joins that list, unless its participant
                    // became matchable meanwhile.
                    if probation_active || fsm.defer_catch_up_match(remote) {
                        continue;
                    }
                }
                self.notify_entry(entry_id, remote);
            } else {
                // Incompatible QoS discovered during catch-up (the remote
                // endpoint was cached BEFORE the local entry registered).
                // Fire on_requested_incompatible_qos / on_offered_incompatible_qos
                // so listeners see the mismatch even in this ordering.
                let policy_id = verdict.err().unwrap_or(0);
                if policy_id != 0 {
                    log::warn!(
                        "[MATCH] incompatible QoS on topic='{}' policy_id={}",
                        topic,
                        policy_id
                    );
                    self.fire_incompat(entry_id, remote.endpoint_guid, policy_id);
                }
            }
        }
    }

    fn fire_incompat(&self, entry_id: u64, endpoint_guid: GUID, policy_id: u32) {
        let Some(entry) = self.entry(entry_id) else {
            return;
        };
        // The entry's listener is called once its gate is left, in the
        // order of its dispatches (`notices::Scope`).
        let _notices = crate::dds::reader::notices::Scope::enter(&entry.notices);
        let Some(_gate) = entry.open_gate() else {
            return;
        };
        // Dedup against the same `incompat_remotes` set the
        // split-path `dispatch_incompat` uses. catch_up runs at
        // entry-registration time and may see the same remote that
        // a later `handle_sedp` -> `dispatch_incompat` re-evaluates
        // -- without this dedup we'd fire the callback twice.
        let mut already = entry
            .incompat_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !already.insert((endpoint_guid, policy_id)) {
            return;
        }
        drop(already);
        if let Some(ref cb) = entry.incompatible_callback {
            let total = entry.incompatible_count.fetch_add(1, Ordering::Relaxed) + 1;
            cb(total, 1, policy_id);
        }
    }

    /// Notify a specific entry that a remote endpoint on the same topic
    /// has a type that is structurally incompatible with the local type
    /// per DDS-XTypes v1.3 sec. 7.6.3.4.3.
    ///
    /// The `inconsistent_type_count` is incremented unconditionally so
    /// that status polling works even without a listener callback. The
    /// callback (if any) is fired once per distinct `remote_guid`.
    pub(crate) fn notify_inconsistent_type(&self, entry_id: u64, remote_guid: GUID) {
        let Some(entry) = self.entry(entry_id) else {
            return;
        };
        // The entry's listener is called once its gate is left, in the
        // order of its dispatches (`notices::Scope`).
        let _notices = crate::dds::reader::notices::Scope::enter(&entry.notices);
        let Some(_gate) = entry.open_gate() else {
            return;
        };
        let mut seen = entry
            .inconsistent_type_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !seen.insert(remote_guid) {
            // Already counted this remote; skip to avoid double-firing.
            return;
        }
        drop(seen);
        let total = entry
            .inconsistent_type_count
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        if let Some(ref cb) = entry.inconsistent_topic_callback {
            cb(total, 1);
        }
    }

    /// Fire `notify_inconsistent_type` for local entries on `topic` whose
    /// kind is opposite to `remote_is_writer` AND whose local type is
    /// structurally incompatible with `remote_type_object`.
    ///
    /// Per-entry type filtering (DDS-XTypes v1.3 sec. 7.6.3.4.3): when both the
    /// local entry and the remote endpoint carry a `CompleteTypeObject`, only
    /// entries whose type is NOT assignable from the remote writer's type (or
    /// the local writer is not assignable to the remote reader's type) are
    /// notified. This prevents false-positive `inconsistent_topic` callbacks
    /// on entries whose type IS actually compatible with the remote, which
    /// would otherwise occur when multiple local endpoints of the same kind
    /// share a topic but carry heterogeneous types.
    ///
    /// The filter is the one type verdict (`pairing_type_verdict`): an entry
    /// is notified exactly when the pairing is refused for its types, the
    /// same verdict that refuses the match and gates the data. A side without
    /// a type object is judged by Step 2 (type names, `TypeNameMatch`), and a
    /// `Pending` side by today's rule (`absent_side_verdict`).
    ///
    /// The per-entry `inconsistent_type_remotes` dedup set makes repeated
    /// calls idempotent for the same `(entry, remote_guid)` pair.
    ///
    /// Used by `DiscoveryFsm::handle_sedp` (called with ALL locks dropped).
    ///
    /// `remote` is the remote endpoint as discovery announced it (the copy
    /// `handle_sedp` holds): its topic, GUID, kind, type name, TypeObject
    /// (`effective_type_object`) and QoS. When the remote endpoint is a
    /// Reader, its `TypeConsistencyEnforcement` is the policy the verdict
    /// reads; TypeConsistencyEnforcement is a READER-side QoS per XTypes v1.3
    /// sec. 7.6.3.4.
    pub(crate) fn notify_inconsistent_type_for_topic(&self, remote: &EndpointInfo) {
        let topic = remote.topic_name.as_str();
        let remote_is_writer = remote.kind == EndpointKind::Writer;
        // The remote as the verdict judges it (`effective_type_object`, the
        // same reading `judge_remote_types` refused it by), with its name and
        // Pending state.
        let remote_type_object = self.effective_type_object(remote);
        // Collect (entry_id, local_type_object, local_type_name, local_policy)
        // under a single read lock. User callbacks are then fired outside any
        // registry lock. The local TypeConsistencyEnforcement policy is
        // included for the case where the local endpoint is a Reader
        // (policy is reader-side per sec. 7.6.3.4).
        use crate::protocol::discovery::types::TypeConsistencyEnforcement;
        let candidates: Vec<(
            u64,
            Option<CompleteTypeObject>,
            String,
            Option<TypeConsistencyEnforcement>,
        )> = {
            let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
            entries
                .iter()
                .filter(|e| {
                    e.topic == topic
                        && matches!(
                            (remote_is_writer, e.kind),
                            (true, LocalKind::Reader) | (false, LocalKind::Writer)
                        )
                })
                .map(|e| {
                    (
                        e.id,
                        e.type_object.clone(),
                        e.type_name.clone(),
                        e.qos.type_consistency.clone(),
                    )
                })
                .collect()
        };
        // Locks are dropped here before any user callback can run.
        for (id, local_type_object, local_type_name, local_policy) in candidates {
            let local_side = TypeSide {
                object: local_type_object.as_ref(),
                name: &local_type_name,
                pending: false,
            };
            let remote_side = remote_side(remote, remote_type_object.as_ref());
            // Per-entry filter: the one verdict, writer first, under the
            // READER's TypeConsistencyEnforcement (sec. 7.6.3.4) whichever side
            // is local.
            let compatible = if remote_is_writer {
                // Remote is writer, local is reader: local_policy is the reader's.
                self.pairing_type_verdict(topic, remote_side, local_side, local_policy.as_ref())
            } else {
                // Remote is reader, local is writer: the remote reader's own
                // policy (its SEDP QoS) governs.
                self.pairing_type_verdict(
                    topic,
                    local_side,
                    remote_side,
                    remote.qos.type_consistency.as_ref(),
                )
            };
            if !compatible {
                self.notify_inconsistent_type(id, remote.endpoint_guid);
            }
        }
    }

    /// Returns the current inconsistent-topic status for the entry with
    /// the given id. Returns `None` when no entry with that id exists.
    ///
    /// The count is a snapshot and may advance concurrently; callers
    /// should treat it as a lower bound if they query outside a lock.
    #[allow(dead_code)]
    pub(crate) fn get_inconsistent_topic_status(
        &self,
        entry_id: u64,
    ) -> Option<crate::dds::listener::InconsistentTopicStatus> {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        for entry in entries.iter() {
            if entry.id == entry_id {
                // Load the current cumulative total, then swap the last-reported
                // snapshot atomically. `wrapping_sub` handles the unlikely but
                // possible wrap of the u32 counter across the polling interval
                // without panicking. The result is cast to i32 because the DDS
                // spec sec. 2.2.4.3.13 defines `total_count_change` as a signed delta.
                let total = entry.inconsistent_type_count.load(Ordering::Acquire);
                let last = entry
                    .last_reported_inconsistent_type_count
                    .swap(total, Ordering::AcqRel);
                let delta = total.wrapping_sub(last) as i32;
                return Some(crate::dds::listener::InconsistentTopicStatus {
                    total_count: total,
                    total_count_change: delta,
                });
            }
        }
        None
    }

    /// Catch-up counterpart of `on_endpoint_discovered`: fires when a remote
    /// endpoint was already cached BEFORE this local entry registered. The
    /// match itself is `dispatch_match`, the one door every surfaced match
    /// goes through (transport verdict resolved once, lifespan propagation,
    /// the undo for an endpoint removed meanwhile).
    fn notify_entry(&self, entry_id: u64, remote: &EndpointInfo) {
        if let Some(entry) = self.entry(entry_id) {
            self.dispatch_match(remote, &entry);
        }
    }
}

impl MatchNotificationRegistry {
    /// Install the participant's shared-memory receive leg. Called once, at
    /// participant build time, before any endpoint can register.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_shm_receiver(
        &self,
        receiver: Arc<crate::transport::shm::receiver::ShmReceiver>,
    ) {
        *self.shm_receiver.write().unwrap_or_else(|e| e.into_inner()) = Some(receiver);
    }

    /// Act on a pairing that resolved to shared memory. Cold path: runs at
    /// most once per (local entry, remote endpoint) pair, gated by the same
    /// `matched_remotes` dedup that gates `resolve_transport` itself.
    ///
    /// Two effects, one per side of the pairing:
    ///
    /// * Any local entry: latch `shm_selected`, which is what lets the
    ///   writer's send loop skip the per-reader verdict lookup entirely
    ///   until at least one reader is actually reachable over SHM.
    /// * A local Reader: hand the remote writer's GUID to the participant's
    ///   SHM poller so it starts draining that writer's ring. The poller
    ///   retries the attach, so being told before the writer has created its
    ///   segment is expected and harmless.
    fn note_shm_pairing(
        &self,
        entry: &MatchEntry,
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] endpoint: &EndpointInfo,
        transport: TransportSelection,
    ) {
        if transport == TransportSelection::Udp {
            return;
        }
        if let Some(ref latch) = entry.shm_selected {
            latch.store(true, Ordering::Release);
        }
        #[cfg(target_os = "linux")]
        if entry.kind == LocalKind::Reader {
            let guard = self.shm_receiver.read().unwrap_or_else(|e| e.into_inner());
            let Some(receiver) = guard.as_ref() else {
                return;
            };
            match self.peer_unicast_locator(endpoint) {
                Some(peer) => {
                    // The nonce the remote participant announced alongside its
                    // host id. Without it the reader refuses the segment: the
                    // name is derivable from discovery, so an unauthenticated
                    // segment could have been planted by any local process.
                    let peer_nonce = endpoint
                        .shm_capability
                        .as_deref()
                        .and_then(crate::transport::shm::parse_shm_nonce);
                    receiver.attach_writer(endpoint.endpoint_guid, &entry.topic, peer, peer_nonce);
                }
                None => log::debug!(
                    "[MATCH-SHM] topic='{}' remote={:?} resolved to SHM but discovery has no \
                     unicast locator for it yet -- staying on UDP for this pairing",
                    entry.topic,
                    endpoint.endpoint_guid
                ),
            }
        }
    }

    /// The peer's REAL UDP unicast locator, as resolved by discovery. Never
    /// a fabricated address: it is stamped into `RxMeta::sock` for every
    /// sample that crosses over shared memory, and the Router uses that
    /// field to answer "which peer sent this and where does a reply go".
    /// Since the control plane stays on UDP, the UDP locator is the correct
    /// answer.
    #[cfg(target_os = "linux")]
    fn peer_unicast_locator(&self, endpoint: &EndpointInfo) -> Option<std::net::SocketAddr> {
        let fsm = self.discovery_fsm.upgrade()?;
        let registry = fsm.endpoint_registry();
        registry
            .get_writer_locator(&endpoint.endpoint_guid)
            .or_else(|| {
                let mut participant_key = [0u8; 16];
                participant_key[..12].copy_from_slice(&endpoint.participant_guid.as_bytes()[..12]);
                participant_key[12..16]
                    .copy_from_slice(&crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT);
                registry.get(&GUID::from_bytes(participant_key))
            })
    }
}

/// Resolve the SHM-vs-UDP transport verdict for a (local entry, remote
/// endpoint) pairing. Cold-path only: called exactly once per pairing, from
/// `dispatch_match` (live SEDP path) and `notify_entry` (catch-up /
/// registration-ordering path), both of which gate the call behind a
/// `contains_key` check on `matched_remotes` so a replayed SEDP or a repeat
/// catch-up scan never recomputes it.
///
/// Per DDS v1.4 Sec.2.2.3 semantics honoured by `select_transport`, both
/// sides' actual (not requested) BestEffort-ness matters, so this reads
/// `entry.qos.reliability` (the local endpoint actually being matched) and
/// `endpoint.qos.reliability` (the specific remote in this pairing) rather
/// than any cached or aggregate value.
fn resolve_transport(
    entry: &MatchEntry,
    endpoint: &EndpointInfo,
) -> Result<TransportSelection, crate::transport::shm::TransportSelectionError> {
    let local_best_effort = entry.qos.reliability == Reliability::BestEffort;
    let remote_best_effort = endpoint.qos.reliability == Reliability::BestEffort;
    // `shm_capability`, not `user_data`: the hint travels in the HDDS
    // vendor PID 0x8031, because PID_USER_DATA is UserDataQosPolicy and
    // belongs to the application. Reading `user_data` here would resolve
    // the transport from whatever bytes an application happened to set.
    select_transport(
        entry.shm_policy,
        endpoint.shm_capability.as_deref(),
        local_best_effort,
        remote_best_effort,
    )
}

/// The one requested/offered verdict of a (writer, reader) pair on QoS
/// alone (DDS v1.4 Sec.2.2.3, the RxO policies and PARTITION; DDS-XTypes
/// v1.3 Sec.7.6.3.1, DATA_REPRESENTATION). `Err(policy_id)` when the pair
/// does not match: the first incompatible policy, ownership then data
/// representation then the others, or 0 when nothing is incompatible
/// (a PARTITION mismatch, silently not matched). `xcdr1` is the local
/// type's: a pair that negotiates XCDR1 for a type that does not encode it
/// natively is refused.
///
/// Both QoS are taken as they are: a REMOTE endpoint's QoS is completed
/// first (`remote_qos_for_verdict`), a LOCAL reader's read as it announces
/// itself (`local_reader_qos_for_verdict`). Every pairing decision reads this, the
/// discovery match, the registration catch-up and the in-process binding
/// (`domain_registry::qos_verdict`): one rule, so a pair is never matched
/// on one path and refused, or fed, on another.
///
/// `remote_vendor` and `local_contains_wchar` feed the RTI XCDR1 wchar
/// refusal (`cdr_negotiation::rti_xcdr1_wchar_incompatible`): a remote of vendor
/// RTI negotiating XCDR1 whose local type contains wchar/wstring is
/// refused on DATA_REPRESENTATION, the same policy id as any other
/// representation mismatch, so the existing OFFERED/REQUESTED_INCOMPATIBLE_QOS
/// dispatch and counters apply unchanged; `None`/`false` (the in-process
/// bind, same-process, never RTI) makes this a no-op.
pub(crate) fn rxo_verdict(
    writer: &QoS,
    reader: &QoS,
    xcdr1: crate::dds::cdr_negotiation::Xcdr1Encoding,
    remote_vendor: Option<u16>,
    local_contains_wchar: bool,
) -> Result<(), u32> {
    let compatible_policies = Matcher::is_compatible(reader, writer);
    let effective_version = crate::dds::cdr_negotiation::pair_effective_cdr_version(
        &writer.data_representation,
        &reader.data_representation,
    );
    let rti_wchar_blocked = match effective_version {
        Ok(version) => crate::dds::cdr_negotiation::rti_xcdr1_wchar_incompatible(
            remote_vendor,
            version,
            local_contains_wchar,
        ),
        Err(_) => false,
    };
    if rti_wchar_blocked {
        crate::dds::cdr_negotiation::note_rti_xcdr1_wchar_refusal(remote_vendor);
    }
    let data_rep_ok = match effective_version {
        Ok(crate::dds::CdrVersion::Xcdr1) => !xcdr1.refuses_xcdr1() && !rti_wchar_blocked,
        Ok(_) => true,
        Err(_) => false,
    };
    let ownership_ok = writer.ownership.kind == reader.ownership.kind;
    if compatible_policies && data_rep_ok && ownership_ok {
        return Ok(());
    }
    Err(if !ownership_ok {
        crate::dds::qos::policy_id::OWNERSHIP
    } else if !data_rep_ok {
        crate::dds::cdr_negotiation::POLICY_ID_DATA_REPRESENTATION
    } else {
        Matcher::first_incompatible_policy(reader, writer)
    })
}

/// A remote endpoint's QoS as the verdict reads it (`rxo_verdict`): its
/// OWNERSHIP kind as announced (PID_OWNERSHIP, else EXCLUSIVE when it
/// announced a strength, else SHARED), and an empty DATA_REPRESENTATION as
/// the spec default `[XCDR1]` (DDS-XTypes v1.3 Sec.7.6.3.1.1: an announcement
/// that carries no list). An endpoint of THIS participant is read by
/// `local_qos_for_verdict` instead.
fn remote_qos_for_verdict(endpoint: &EndpointInfo) -> QoS {
    remote_announcement_for_verdict(
        &endpoint.qos,
        endpoint.has_explicit_ownership,
        endpoint.has_ownership_strength,
    )
}

/// `remote_qos_for_verdict` on the facts of one SEDP announcement, for a
/// caller that holds the announcement before discovery records it (the
/// SEDP writer-blocking gate): the announced QoS and whether it carried
/// PID_OWNERSHIP and PID_OWNERSHIP_STRENGTH.
pub(crate) fn remote_announcement_for_verdict(
    qos: &QoS,
    has_explicit_ownership: bool,
    has_ownership_strength: bool,
) -> QoS {
    let mut qos = with_announced_ownership(qos, has_explicit_ownership, has_ownership_strength);
    if qos.data_representation.is_empty() {
        qos.data_representation = vec![0x0000]; // XCDR_DATA_REPRESENTATION (XCDR1)
    }
    qos
}

/// A LOCAL reader's QoS as the verdict reads it (`rxo_verdict`): its
/// DATA_REPRESENTATION as it announces it
/// (`cdr_negotiation::announced_data_representation`, `[XCDR, XCDR2]` when
/// it set none), so that we judge the pair on the list the peer judges it
/// on. Borrowed unchanged when the reader set a list.
pub(crate) fn local_reader_qos_for_verdict(qos: &QoS) -> std::borrow::Cow<'_, QoS> {
    if qos.data_representation.is_empty() {
        let mut announced = qos.clone();
        announced.data_representation =
            crate::dds::cdr_negotiation::announced_data_representation(EndpointKind::Reader, &[])
                .to_vec();
        std::borrow::Cow::Owned(announced)
    } else {
        std::borrow::Cow::Borrowed(qos)
    }
}

/// The record discovery keeps of an endpoint of THIS participant, as the
/// verdict reads it: the QoS the endpoint was created with (its OWNERSHIP
/// flags are explicit, `announce`), a reader's DATA_REPRESENTATION as it
/// announces it (`local_reader_qos_for_verdict`), a writer's as it was
/// resolved at creation (`resolve_writer_data_representation`, never empty;
/// its first element is its offer). Both ends of a
/// pair of this participant are thus judged by the rules each end applies
/// to itself.
fn local_qos_for_verdict(endpoint: &EndpointInfo) -> QoS {
    let mut qos = with_announced_ownership(
        &endpoint.qos,
        endpoint.has_explicit_ownership,
        endpoint.has_ownership_strength,
    );
    if endpoint.kind == EndpointKind::Reader {
        qos = local_reader_qos_for_verdict(&qos).into_owned();
    }
    qos
}

/// `qos` with its OWNERSHIP kind as announced (PID_OWNERSHIP, else
/// EXCLUSIVE when a strength was announced, else SHARED), nothing else
/// completed.
fn with_announced_ownership(
    qos: &QoS,
    has_explicit_ownership: bool,
    has_ownership_strength: bool,
) -> QoS {
    let mut qos = qos.clone();
    qos.ownership.kind = crate::qos::ownership::OwnershipKind::announced(
        has_explicit_ownership.then_some(qos.ownership.kind),
        has_ownership_strength,
    );
    qos
}

/// Per-entry verdict produced by `MatchNotificationRegistry::evaluate`.
/// `policy_id == 0` for `Incompat` would mean "partition or unknown
/// reason" which is silently no-matched per DDS spec; only the `Match`
/// and `Incompat(policy)` variants reach the dispatch layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryVerdict {
    /// Endpoint is a cross-kind match candidate AND QoS is fully
    /// compatible. The match dispatch may update `matched_remotes` and
    /// fire `on_publication_matched` / `on_subscription_matched`.
    Match,
    /// Endpoint is a cross-kind candidate but QoS is incompatible on the
    /// carried policy. The incompat dispatch may fire
    /// `on_offered_incompatible_qos` / `on_requested_incompatible_qos`.
    Incompat(u32),
    /// Endpoint is not a candidate (same-kind, wrong topic, partition
    /// mismatch, etc.). No dispatch.
    Skip,
}

impl MatchNotificationRegistry {
    /// Common helper for the two `DiscoveryListener` hooks
    /// (`on_endpoint_discovered` for the match path,
    /// `on_endpoint_discovered_incompat_only` for the always-on
    /// QoS-incompat path). Returns one verdict per local entry on the
    /// same topic. The split exists so the SEDP confirmation gate in
    /// `discovery::handle_sedp` can publish QoS mismatches immediately
    /// (no gate) while still gating the match-status side against
    /// stale-test SPDP/SEDP contamination.
    /// Whether local entry `entry_id` pairs with `endpoint`: the verdict the
    /// match dispatch applies to the two (QoS, DataRepresentation,
    /// OWNERSHIP kind, type, `evaluate_entries`), for a consumer that needs
    /// to know which remote endpoints the entry is matched with.
    pub(crate) fn pairs_with(&self, entry_id: u64, endpoint: &EndpointInfo) -> bool {
        self.evaluate_entries(endpoint)
            .iter()
            .any(|(id, verdict)| *id == entry_id && matches!(verdict, EntryVerdict::Match))
    }

    fn evaluate_entries(&self, endpoint: &EndpointInfo) -> Vec<(u64, EntryVerdict)> {
        // The other end's QoS as the one verdict reads it
        // (`qos_for_verdict`; for a remote, its announced OWNERSHIP kind, an
        // absent DATA_REPRESENTATION as the spec default `[XCDR1]`: a
        // `-x 1` writer that announces none must not match an HDDS `-x 2`
        // reader as XCDR2).
        let remote_qos_for_compat = self.qos_for_verdict(endpoint);

        // Read before the entries lock: it takes the discovery registry's.
        // The remote as discovery knows it now: its record, else the copy.
        let remote_now = self.current_record(endpoint);
        let remote_judged = remote_now.as_ref().unwrap_or(endpoint);
        let remote_type_object = self.effective_type_object(remote_judged);
        // The vendor zone, resolved once per endpoint, not per entry
        // (RTI XCDR1 wchar refusal).
        let remote_vendor = self.remote_vendor_of(&endpoint.participant_guid);

        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let mut verdicts = Vec::with_capacity(entries.len());
        for entry in entries.iter() {
            if entry.topic != endpoint.topic_name {
                verdicts.push((entry.id, EntryVerdict::Skip));
                continue;
            }
            // DDS matching is strictly cross-kind: writers match readers
            // and vice versa. Same-kind pairs are silently irrelevant.
            let is_match_candidate = matches!(
                (entry.kind, endpoint.kind),
                (LocalKind::Writer, EndpointKind::Reader)
                    | (LocalKind::Reader, EndpointKind::Writer)
            );
            if !is_match_candidate {
                verdicts.push((entry.id, EntryVerdict::Skip));
                continue;
            }

            // The one QoS verdict (`rxo_verdict`).
            let local_wchar = self.local_type_contains_wchar(entry.type_object.as_ref());
            let verdict = match entry.kind {
                LocalKind::Writer => rxo_verdict(
                    &entry.qos,
                    &remote_qos_for_compat,
                    entry.xcdr1,
                    remote_vendor,
                    local_wchar,
                ),
                LocalKind::Reader => rxo_verdict(
                    &remote_qos_for_compat,
                    &local_reader_qos_for_verdict(&entry.qos),
                    entry.xcdr1,
                    remote_vendor,
                    local_wchar,
                ),
            };
            if verdict.is_ok() {
                // When both TypeObjects are present, enforce structural type
                // assignability per XTypes v1.3 sec. 7.6.3.4.3. Incompatible types
                // block the match (no on_publication_matched /
                // on_subscription_matched fires) and are reported via
                // on_inconsistent_topic through the separate discovery-FSM path
                // (notify_inconsistent_type_for_topic). Without this gate, the
                // subscriber matches the writer, receives samples, and the
                // harness catches sample_received() before on_inconsistent_topic,
                // yielding OK instead of INCONSISTENT_TOPIC.
                // The one type verdict (`pairing_type_verdict`), on the remote
                // type as discovery knows it now (`current_record`).
                let type_compatible = match entry.kind {
                    LocalKind::Writer => self.pairing_type_verdict(
                        &endpoint.topic_name,
                        entry_side(entry),
                        remote_side(remote_judged, remote_type_object.as_ref()),
                        endpoint.qos.type_consistency.as_ref(),
                    ),
                    LocalKind::Reader => self.pairing_type_verdict(
                        &endpoint.topic_name,
                        remote_side(remote_judged, remote_type_object.as_ref()),
                        entry_side(entry),
                        entry.qos.type_consistency.as_ref(),
                    ),
                };
                if !type_compatible {
                    // Structural type mismatch: suppress match, let the FSM's
                    // notify_inconsistent_type_for_topic fire on_inconsistent_topic.
                    verdicts.push((entry.id, EntryVerdict::Skip));
                    continue;
                }
                verdicts.push((entry.id, EntryVerdict::Match));
                continue;
            }

            // `policy_id == 0`: no real QoS incompatibility (a partition
            // mismatch, silently not matched per DDS spec).
            let policy_id = verdict.err().unwrap_or(0);
            if policy_id == 0 {
                verdicts.push((entry.id, EntryVerdict::Skip));
            } else {
                verdicts.push((entry.id, EntryVerdict::Incompat(policy_id)));
            }
        }
        verdicts
    }

    /// Dispatch the match outcome for an entry. Updates
    /// `matched_remotes` (dedup against repeat fires) and tightens
    /// the reader's effective lifespan from the writer's announced
    /// value. Idempotent against the same `(entry_id, endpoint_guid)`
    /// pair so the deferred replay path doesn't double-fire.
    ///
    /// Also resolves the SHM-vs-UDP `TransportSelection` for this pairing
    /// exactly once (see `resolve_transport`) and stores it alongside the
    /// GUID in `matched_remotes`. When `entry.shm_policy` is `Require` and
    /// the pairing cannot satisfy it (`resolve_transport` returns `Err`),
    /// the match is refused outright: nothing is inserted, no callback
    /// fires, and this pairing behaves exactly as if it had never matched
    /// (same as a QoS-incompatible pair) other than the error log line.
    ///
    /// The remote endpoint may have been removed while the notification was
    /// in flight (a replay or the drain took it out of the deferred list, then
    /// a dispose or a lease expiry removed it, and the removal's
    /// `on_endpoint_removed` found nothing to unmatch). Matched after that,
    /// it would stay matched for good, and a writer's ReaderProxy would hold
    /// a KEEP_ALL history back for a reader that is gone. So once the match
    /// is applied, it is undone (matched_remotes, `PeerChange::Unmatched`,
    /// the callback with -1) when discovery no longer knows the endpoint.
    /// Checked after, not before: a removal takes the endpoint out of the
    /// topic registry before it announces the departure, so either this
    /// check sees it gone, or the departure comes after the insert and
    /// undoes it. In that race the listener sees the match and its end.
    ///
    /// "Knows" is about the record, not the GUID: the endpoint may also have
    /// been removed and announced again under the same GUID meanwhile, and
    /// the record discovery holds now is not the one this match was decided
    /// on (`EndpointInfo::incarnation`). That match is undone too; the new
    /// record is matched, or not, by its own notification. A match already
    /// held for an older record of the GUID, whose removal has not reached
    /// this entry yet, ends here and gives way to this one.
    fn dispatch_match(&self, endpoint: &EndpointInfo, entry: &MatchEntry) {
        // The entry's listener is called once its gate is left, in the
        // order of its dispatches (`notices::Scope`).
        let _notices = crate::dds::reader::notices::Scope::enter(&entry.notices);
        let Some(_gate) = entry.open_gate() else {
            return;
        };
        let mut matched = entry
            .matched_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let replaces_older = match matched.get(&endpoint.endpoint_guid) {
            // Matched on this record, or on a newer one: nothing to add.
            Some(held) if held.incarnation >= endpoint.incarnation => return,
            Some(_) => true,
            None => false,
        };
        // A pairing of two endpoints of this participant moves its samples
        // through the writer's merger, in process (`DomainState`): no
        // transport to choose, no shared-memory ring to drain, no RTPS
        // proxy on either side. Reliable admission is acknowledged by the
        // merger binding, independently of this discovery notification.
        let local = self.is_local(endpoint);
        let transport = match if local {
            Ok(TransportSelection::Udp)
        } else {
            resolve_transport(entry, endpoint)
        } {
            Ok(sel) => sel,
            Err(err) => {
                drop(matched);
                log::error!(
                    "[MATCH-SHM] SHM required but unavailable for topic='{}' remote={:?}: {} -- refusing match",
                    entry.topic,
                    endpoint.endpoint_guid,
                    err
                );
                return;
            }
        };
        let total = entry.total_count.fetch_add(1, Ordering::Relaxed) + 1;
        matched.insert(
            endpoint.endpoint_guid,
            MatchedRemote {
                transport,
                generation: self.next_match_generation.fetch_add(1, Ordering::Relaxed),
                incarnation: endpoint.incarnation,
            },
        );
        let current = u32::try_from(matched.len()).unwrap_or(u32::MAX);
        drop(matched);
        if replaces_older {
            // The older record's match ends; its proxy is replaced by this
            // record's below (`tell_peer_matched`).
            Self::tell_liveliness(
                entry,
                endpoint,
                LivelinessPeer::Unmatched {
                    guid: endpoint.endpoint_guid,
                },
            );
            (entry.callback)(
                total - 1,
                0,
                current.saturating_sub(1),
                -1,
                Some(endpoint.endpoint_guid),
            );
        }
        self.note_shm_pairing(entry, endpoint, transport);
        // Lifespan propagation: a local Reader matched with a remote
        // Writer announcing a finite Lifespan -- tighten this reader's
        // effective lifespan so samples are filtered even when the
        // reader did not set one itself. A writer of this participant
        // stamps its own samples (DDS v1.4 Sec.2.2.3.16).
        if entry.kind == LocalKind::Reader && !local {
            if let Some(ref nanos_cell) = entry.reader_lifespan_nanos {
                if !endpoint.qos.lifespan.is_infinite() {
                    let writer_nanos = u64::try_from(endpoint.qos.lifespan.duration.as_nanos())
                        .unwrap_or(u64::MAX);
                    let mut cur = nanos_cell.load(Ordering::Relaxed);
                    while writer_nanos < cur {
                        match nanos_cell.compare_exchange_weak(
                            cur,
                            writer_nanos,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(observed) => cur = observed,
                        }
                    }
                }
            }
        }
        if !local {
            Self::tell_peer_matched(entry, endpoint);
        }
        Self::tell_liveliness(
            entry,
            endpoint,
            LivelinessPeer::Matched {
                guid: endpoint.endpoint_guid,
                liveliness: endpoint.qos.liveliness,
                local,
            },
        );
        (entry.callback)(total, 1, current, 1, Some(endpoint.endpoint_guid));
        // Checked after, as `still_known` is: a TypeLookup reply can resolve
        // the remote's type between the verdict that let this match through
        // and the insert above, and `rejudge_remote_types` then found no
        // match to withdraw. Judged again on the type known now, the pairing
        // the verdict refuses is undone here.
        if !self.still_known(endpoint) || !self.types_accepted_now(endpoint, entry) {
            Self::unmatch_in_gate(endpoint, entry, local);
        }
    }

    /// The one type verdict for `entry` and the remote `endpoint` as
    /// discovery knows it now (`current_record`).
    fn types_accepted_now(&self, endpoint: &EndpointInfo, entry: &MatchEntry) -> bool {
        let now = self.current_record(endpoint);
        let judged = now.as_ref().unwrap_or(endpoint);
        let remote_type = self.effective_type_object(judged);
        let remote = remote_side(judged, remote_type.as_ref());
        match entry.kind {
            LocalKind::Writer => self.pairing_type_verdict(
                &endpoint.topic_name,
                entry_side(entry),
                remote,
                endpoint.qos.type_consistency.as_ref(),
            ),
            LocalKind::Reader => self.pairing_type_verdict(
                &endpoint.topic_name,
                remote,
                entry_side(entry),
                entry.qos.type_consistency.as_ref(),
            ),
        }
    }

    /// Whether discovery still holds the record `endpoint` is a copy of: the
    /// same GUID under the same incarnation (`EndpointInfo::incarnation`; a
    /// copy that never went through the registry, incarnation 0, is held
    /// while its GUID is). True when the discovery FSM is gone (nothing to
    /// compare against).
    fn still_known(&self, endpoint: &EndpointInfo) -> bool {
        self.discovery_fsm.upgrade().is_none_or(|fsm| {
            fsm.endpoint_incarnation(&endpoint.topic_name, &endpoint.endpoint_guid)
                .is_some_and(|held| endpoint.incarnation == 0 || held == endpoint.incarnation)
        })
    }

    /// RTPS 2.5 8.4.12 `matched_writer_add`: a reliable reader keeps a
    /// WriterProxy for every compatible writer discovery pairs it with, from
    /// the moment of discovery. The DDS-level match notification
    /// (`on_subscription_matched`) stays behind the participant-confirmation
    /// and probation gates, because a zombie's SEDP must not reach the
    /// application; the proxy does not wait for them. A proxy for a writer
    /// that turns out dead answers nothing (a dead writer sends no
    /// HEARTBEAT) and goes with the writer's removal or with the reader.
    ///
    /// Without this, a writer whose SEDP arrives inside our probation window
    /// and whose participant then announces only rarely (a few SPDPs at
    /// startup, then a long resend period) is never acknowledged: its match sits in
    /// the FSM's deferred list until the peer's next SPDP, and a reliable
    /// reader with no proxy answers no HEARTBEAT, so the reorder gate holds
    /// everything above the first hole forever.
    fn pair_reader_with_writer(entry: &MatchEntry, endpoint: &EndpointInfo) -> bool {
        if entry.kind != LocalKind::Reader || endpoint.kind != EndpointKind::Writer {
            return false;
        }
        // A pairing `ShmPolicy::Require` refuses never matches
        // (`dispatch_match`): no proxy for it either.
        if resolve_transport(entry, endpoint).is_err() {
            return false;
        }
        Self::tell_peer_matched(entry, endpoint)
    }

    /// RTPS 2.5 8.4.7.4 `matched_reader_add`, the writer-side twin of
    /// `pair_reader_with_writer`: a writer keeps a ReaderProxy for every
    /// compatible reader discovery pairs it with (`track_reader_proxy` keeps
    /// one per RELIABLE reader), from the moment of discovery, while the
    /// DDS-level `on_publication_matched` stays behind the confirmation and
    /// probation gates.
    ///
    /// Without it, while a reliable reader's match is deferred the writer
    /// ignores its ACKNACKs (`nack::discovered_but_unpaired`), and, tracking
    /// no reliable reader, counts its whole history as acknowledged by all
    /// (`acked_floor` over an empty table, RTPS 2.5 8.4.7.4 `is_acked_by_all`
    /// over `matched_readers`): a KEEP_ALL writer frees what it owes that
    /// reader before the reader ever asked. The proxy's watermark is taken
    /// now, so what a VOLATILE pairing is owed starts at discovery.
    ///
    /// A zombie's reader holds the history back only until the probation
    /// verdict purges its participant (on our own clock: the control
    /// thread fires it), and its proxy goes with it (`dispatch_unmatch`).
    /// A participant the verdict keeps spoke after its first 100 ms; until
    /// it is match eligible it is also purged after one second of silence
    /// (`DiscoveryFsm::fails_probation`), so one that dies unconfirmed
    /// does not hold the history back for its whole lease. Once eligible it
    /// leaves by its dispose or its lease like any matched peer.
    fn pair_writer_with_reader(entry: &MatchEntry, endpoint: &EndpointInfo) -> bool {
        if entry.kind != LocalKind::Writer || endpoint.kind != EndpointKind::Reader {
            return false;
        }
        // A pairing `ShmPolicy::Require` refuses never matches: no proxy.
        if resolve_transport(entry, endpoint).is_err() {
            return false;
        }
        Self::tell_peer_matched(entry, endpoint)
    }

    /// Tell a reader entry's liveliness hook that the writer `endpoint`
    /// matched or unmatched.
    fn tell_liveliness(entry: &MatchEntry, endpoint: &EndpointInfo, change: LivelinessPeer) {
        if entry.kind != LocalKind::Reader || endpoint.kind != EndpointKind::Writer {
            return;
        }
        if let Some(ref hook) = entry.liveliness_hook {
            hook(change);
        }
    }

    /// Tell the entry's peer hook that `endpoint` matched; whether it has one.
    ///
    /// The proxy belongs to the record it was built for (`peer_records`):
    /// for a newer record of a GUID whose proxy was built for an older one,
    /// the old proxy is dropped (`Unmatched`) and this record's built
    /// (`Matched`), so nothing the old one received, acknowledged or was
    /// owed answers for the new one. A record older than the one the proxy
    /// was built for touches nothing. Incarnation 0 (a copy that never went
    /// through the registry) is taken as the record the proxy has.
    fn tell_peer_matched(entry: &MatchEntry, endpoint: &EndpointInfo) -> bool {
        let Some(ref peer) = entry.peer_callback else {
            return false;
        };
        let mut records = entry.peer_records.lock().unwrap_or_else(|e| e.into_inner());
        let incarnation = endpoint.incarnation;
        match records.get(&endpoint.endpoint_guid).copied() {
            Some(held) if incarnation != 0 && held > incarnation => return true,
            Some(held) if incarnation != 0 && held != 0 && held < incarnation => {
                peer(PeerChange::Unmatched {
                    guid: endpoint.endpoint_guid,
                });
            }
            _ => {}
        }
        if incarnation != 0 || !records.contains_key(&endpoint.endpoint_guid) {
            records.insert(endpoint.endpoint_guid, incarnation);
        }
        peer(PeerChange::Matched {
            guid: endpoint.endpoint_guid,
            reliable: endpoint.qos.reliability != Reliability::BestEffort,
            volatile: endpoint.qos.durability == Durability::Volatile,
        });
        true
    }

    /// Tell the entry's peer hook that the record `endpoint` is a copy of
    /// ended: its proxy goes, unless the proxy was built for a newer record
    /// of the GUID (`peer_records`), which this end does not concern.
    fn tell_peer_unmatched(entry: &MatchEntry, endpoint: &EndpointInfo) {
        let Some(ref peer) = entry.peer_callback else {
            return;
        };
        let mut records = entry.peer_records.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&held) = records.get(&endpoint.endpoint_guid) {
            if endpoint.incarnation != 0 && held > endpoint.incarnation {
                return;
            }
        }
        records.remove(&endpoint.endpoint_guid);
        peer(PeerChange::Unmatched {
            guid: endpoint.endpoint_guid,
        });
    }

    /// The proxies discovery pairs, whichever side is local: the reader's
    /// WriterProxy (`pair_reader_with_writer`) and the writer's ReaderProxy
    /// (`pair_writer_with_reader`). Each ignores the other kind.
    ///
    /// The remote endpoint may have been removed while a notification about
    /// it was in flight (the drain or a replay took it out of the deferred
    /// list just before its removal): a proxy taken then would outlive it,
    /// and a writer's ReaderProxy would hold the history back for a reader
    /// that is gone. So the pairing is undone when discovery no longer knows
    /// the endpoint. The check comes AFTER the pairing: a removal takes the
    /// endpoint out of the topic registry before it announces the departure,
    /// so either this check sees it gone, or the departure comes after the
    /// pairing and undoes it. No lock is held across the peer callbacks.
    fn pair_at_discovery(&self, entry: &MatchEntry, endpoint: &EndpointInfo) {
        // The entry's listener is called once its gate is left, in the
        // order of its dispatches (`notices::Scope`).
        let _notices = crate::dds::reader::notices::Scope::enter(&entry.notices);
        let Some(_gate) = entry.open_gate() else {
            return;
        };
        // At most one applies (they pair opposite kinds); both are asked.
        let paired = Self::pair_reader_with_writer(entry, endpoint)
            | Self::pair_writer_with_reader(entry, endpoint);
        let still_known = self
            .discovery_fsm
            .upgrade()
            .is_some_and(|fsm| fsm.knows_remote_endpoint(endpoint));
        if paired && !still_known {
            Self::tell_peer_unmatched(entry, endpoint);
        }
    }

    /// The catch-up counterpart of `pair_at_discovery`, for an entry named
    /// by id.
    fn pair_entry_at_discovery(&self, entry_id: u64, remote: &EndpointInfo) {
        if let Some(entry) = self.entry(entry_id) {
            self.pair_at_discovery(&entry, remote);
        }
    }

    fn dispatch_unmatch(&self, endpoint: &EndpointInfo, entry: &MatchEntry) {
        // The entry's listener is called once its gate is left, in the
        // order of its dispatches (`notices::Scope`).
        let _notices = crate::dds::reader::notices::Scope::enter(&entry.notices);
        let Some(_gate) = entry.open_gate() else {
            return;
        };
        Self::unmatch_in_gate(endpoint, entry, self.is_local(endpoint));
    }

    /// `dispatch_unmatch` for a caller already holding the entry's gate.
    ///
    /// The record `endpoint` is a copy of ends: a match made on it (or on an
    /// older record of the GUID) is removed, one made on a newer record of
    /// the GUID is not (`EndpointInfo::incarnation`; incarnation 0 ends any).
    /// Its proxy goes the same way (`tell_peer_unmatched`): a proxy already
    /// built for a newer record of the GUID stays.
    ///
    /// `local`: `endpoint` is of this participant, and no proxy was ever
    /// built for it (`dispatch_match`).
    fn unmatch_in_gate(endpoint: &EndpointInfo, entry: &MatchEntry, local: bool) {
        let mut matched = entry
            .matched_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(held) = matched.get(&endpoint.endpoint_guid) {
            if endpoint.incarnation != 0 && held.incarnation > endpoint.incarnation {
                return;
            }
        }
        if matched.remove(&endpoint.endpoint_guid).is_none() {
            drop(matched);
            // A remote endpoint paired with this entry at discovery but never
            // surfaced as matched (`pair_at_discovery`): its proxy goes with
            // it all the same, the reader's WriterProxy as the writer's
            // ReaderProxy (which would otherwise hold the history back for
            // a reader that is gone).
            let paired_at_discovery = matches!(
                (entry.kind, endpoint.kind),
                (LocalKind::Reader, EndpointKind::Writer)
                    | (LocalKind::Writer, EndpointKind::Reader)
            );
            if paired_at_discovery && entry.topic == endpoint.topic_name && !local {
                Self::tell_peer_unmatched(entry, endpoint);
            }
            return;
        }
        let current = u32::try_from(matched.len()).unwrap_or(u32::MAX);
        drop(matched);
        let total = entry.total_count.load(Ordering::Relaxed);
        if !local {
            Self::tell_peer_unmatched(entry, endpoint);
        }
        Self::tell_liveliness(
            entry,
            endpoint,
            LivelinessPeer::Unmatched {
                guid: endpoint.endpoint_guid,
            },
        );
        (entry.callback)(total, 0, current, -1, Some(endpoint.endpoint_guid));
    }

    /// Dispatch the incompat outcome for an entry. Dedups against
    /// `incompat_remotes` so the same `(entry_id, endpoint_guid)` pair
    /// fires the callback at most once over the entry's lifetime --
    /// important because the split incompat / match paths both see
    /// every new SEDP and would otherwise double-count.
    fn dispatch_incompat(&self, endpoint: &EndpointInfo, entry: &MatchEntry, policy_id: u32) {
        let Some(ref incompat_cb) = entry.incompatible_callback else {
            return;
        };
        // The entry's listener is called once its gate is left, in the
        // order of its dispatches (`notices::Scope`).
        let _notices = crate::dds::reader::notices::Scope::enter(&entry.notices);
        let Some(_gate) = entry.open_gate() else {
            return;
        };
        let mut already = entry
            .incompat_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !already.insert((endpoint.endpoint_guid, policy_id)) {
            return;
        }
        drop(already);
        log::warn!(
            "[MATCH] incompatible QoS on topic='{}' policy_id={}",
            entry.topic,
            policy_id
        );
        if crate::config::env_flags::interop_diagnostics() {
            eprintln!(
                "[MATCH-INCOMPAT] topic='{}' policy={} has_expl_own={} has_own_str={} remote_own={:?} local_own={:?}",
                entry.topic,
                policy_id,
                endpoint.has_explicit_ownership,
                endpoint.has_ownership_strength,
                endpoint.qos.ownership.kind,
                entry.qos.ownership.kind,
            );
        }
        let total = entry.incompatible_count.fetch_add(1, Ordering::Relaxed) + 1;
        incompat_cb(total, 1, policy_id);
    }
}

impl DiscoveryListener for MatchNotificationRegistry {
    /// A participant that said it left (its SPDP dispose, its lease-0
    /// farewell) takes the verdicts on its writers, and their records, with
    /// it. One that fell silent does not (`on_endpoint_removed`).
    fn on_participant_left(&self, participant: GUID, announced: bool) {
        if announced {
            let prefix = participant.prefix;
            let mut judged = self
                .judged_writers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            judged.retain(|writer, _| writer[..12] != prefix[..]);
            self.refused_pairs
                .retain(|writer, _| writer[..12] != prefix[..]);
        }
        self.judged_readers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|reader, _| reader[..12] != participant.prefix[..]);
    }

    /// Match path. Called by `discovery::handle_sedp` only AFTER the
    /// SEDP confirmation gate has released (participant is confirmed,
    /// or FSM uptime is past the probation window, or this is a local
    /// endpoint). Fires `on_publication_matched` /
    /// `on_subscription_matched` for compatible pairs. Incompat
    /// notifications are NOT fired here; they go through the
    /// always-on `on_endpoint_discovered_incompat_only` hook below.
    ///
    /// An endpoint of this participant is matched as a remote one is,
    /// without the proxies (`dispatch_match`): DDS v1.4 Sec.2.2.4.1 defines
    /// PUBLICATION_MATCHED (SUBSCRIPTION_MATCHED) as the DataWriter having
    /// found a DataReader (DataWriter) that matches the Topic with compatible
    /// QoS, wherever that endpoint lives.
    fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
        let verdicts = self.evaluate_entries(&endpoint);
        if verdicts.is_empty() {
            return;
        }
        let entries = self.entries_snapshot();
        for (entry_id, verdict) in verdicts {
            if !matches!(verdict, EntryVerdict::Match) {
                continue;
            }
            if let Some(entry) = entries.iter().find(|e| e.id == entry_id) {
                self.dispatch_match(&endpoint, entry);
            }
        }
    }

    /// Incompat path. Called by `discovery::handle_sedp` IMMEDIATELY,
    /// before the confirmation gate, so QoS mismatches surface to the
    /// application without waiting for SPDP participant confirmation
    /// (which can take up to a steady-state SPDP interval, ~3 s -- long
    /// enough to miss the OMG harness 5 s check window). The
    /// `incompat_remotes` dedup makes this idempotent against the
    /// match path: when the gate eventually releases and the same
    /// endpoint is replayed, we don't double-fire.
    fn on_endpoint_discovered_incompat_only(&self, endpoint: EndpointInfo) {
        let local = self.is_local(&endpoint);
        let verdicts = self.evaluate_entries(&endpoint);
        if verdicts.is_empty() {
            return;
        }
        let entries = self.entries_snapshot();
        for (entry_id, verdict) in verdicts {
            let Some(entry) = entries.iter().find(|e| e.id == entry_id) else {
                continue;
            };
            match verdict {
                EntryVerdict::Incompat(policy_id) => {
                    self.dispatch_incompat(&endpoint, entry, policy_id);
                }
                // The proxies are created here, on the path the confirmation
                // gate does not hold, once the security plugins admit the
                // endpoint; the match itself is surfaced by
                // `on_endpoint_discovered` once the gate releases.
                EntryVerdict::Match => {
                    if !local
                        && self
                            .discovery_fsm
                            .upgrade()
                            .is_some_and(|fsm| fsm.admits_endpoint(&endpoint))
                    {
                        self.pair_at_discovery(entry, &endpoint);
                    }
                }
                EntryVerdict::Skip => {}
            }
        }
    }

    fn on_endpoint_removed(&self, endpoint: EndpointInfo) {
        if endpoint.kind == EndpointKind::Reader {
            self.judged_readers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&endpoint.endpoint_guid.as_bytes());
        }
        if endpoint.kind == EndpointKind::Writer {
            let writer = endpoint.endpoint_guid.as_bytes();
            self.clear_writer_refusals(&writer, Refusal::TYPE);
            // Its QoS verdicts and its record go when the writer said it is
            // gone (its SEDP dispose: its participant is still known) or
            // discovery is. Not when it went with a participant that fell
            // silent (a lease expiry, a probation purge): it may come back
            // as the same writer without announcing it again, the router
            // still routes its samples, and the readers that refuse it, the
            // existing ones and those created after (`catch_up`), must still
            // drop them. A participant that said it left takes them with it
            // (`on_participant_left`).
            let participant_gone = self
                .discovery_fsm
                .upgrade()
                .is_some_and(|fsm| !fsm.is_participant_known(&writer[..12]));
            if !participant_gone {
                self.forget_remote_writer(&endpoint.endpoint_guid);
            }
        }

        for entry in self.entries_snapshot().iter() {
            self.dispatch_unmatch(&endpoint, entry);
            entry
                .incompat_remotes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|(guid, _)| *guid != endpoint.endpoint_guid);
            entry
                .inconsistent_type_remotes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&endpoint.endpoint_guid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "xtypes-structural-assignability")]
    use crate::protocol::discovery::types::TypeConsistencyEnforcement;
    use std::sync::atomic::AtomicU32;

    fn test_qos() -> QoS {
        QoS::best_effort()
    }

    // Simple fixed-size type descriptor (alignment=4, is_variable_size=false):
    // triggers the XCDR1 guard-rail only when alignment>=8 && is_variable_size.
    static SIMPLE_DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
        type_id: 0,
        type_name: "Simple",
        size_bytes: 8,
        alignment: 4,
        is_variable_size: false,
        fields: &[],
    };

    // Container type descriptor (alignment=8 + is_variable_size=true): the
    // descriptor-only guess (`type_requires_native_xcdr1`) says it does not
    // encode the XCDR1 layout (sec. 7.4.3.2.2 Table 37). Triggers the guard-rail.
    static CONTAINER_DESC: crate::core::types::TypeDescriptor =
        crate::core::types::TypeDescriptor {
            type_id: 0,
            type_name: "Container",
            size_bytes: 0,
            alignment: 8,
            is_variable_size: true,
            fields: &[],
        };

    // Remote reader with an explicit data_representation sequence. Used to
    // exercise the DDS-XTypes v1.3 sec. 7.6.3.1 match-time gate.
    fn remote_reader(data_rep: Vec<u16>) -> EndpointInfo {
        remote_reader_of(&SIMPLE_DESC, data_rep)
    }

    // The same reader, announcing the name of `desc`, the type it reads.
    fn remote_reader_of(
        desc: &'static crate::core::types::TypeDescriptor,
        data_rep: Vec<u16>,
    ) -> EndpointInfo {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        // GUID with a non-zero prefix so it is not skipped as local.
        let guid = GUID::from_bytes([
            0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0x04,
        ]);
        let qos = QoS {
            data_representation: data_rep,
            ..QoS::best_effort()
        };
        EndpointInfo {
            endpoint_guid: guid,
            participant_guid: guid,
            topic_name: "topic".into(),
            type_name: desc.type_name.into(),
            qos,
            kind: EndpointKind::Reader,
            type_object: None,
            type_object_legacy_v1: false,
            type_information: None,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            shm_capability: None,
            incarnation: 0,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    #[test]
    fn data_rep_mismatch_fires_incompat_with_policy_23_and_skips_match() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_policy = Arc::new(AtomicU32::new(0));
        let ip = Arc::clone(&incompat_policy);

        let writer_qos = QoS {
            data_representation: vec![0x0002], // offered XCDR2 only
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &SIMPLE_DESC,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, policy_id| {
                ip.store(policy_id, Ordering::Relaxed);
            })),
        );

        // Reader accepts only XCDR1 -> mismatch.
        // After the split:
        //   - The match path (`on_endpoint_discovered`) MUST NOT fire
        //     either match or incompat for this endpoint;
        //   - The incompat path (`on_endpoint_discovered_incompat_only`)
        //     MUST fire incompat with policy 23.
        let remote = remote_reader(vec![0x0000]);
        fsm.insert_remote_endpoint_for_test(remote.clone().clone());
        reg.on_endpoint_discovered(remote.clone());
        assert_eq!(
            match_count.load(Ordering::Relaxed),
            0,
            "match path must not fire match on incompatible pair"
        );
        assert_eq!(
            incompat_policy.load(Ordering::Relaxed),
            0,
            "match path must not fire incompat (that's the other hook's job)"
        );

        reg.on_endpoint_discovered_incompat_only(remote);
        assert_eq!(
            incompat_policy.load(Ordering::Relaxed),
            crate::dds::cdr_negotiation::POLICY_ID_DATA_REPRESENTATION
        );
    }

    #[test]
    fn data_rep_match_proceeds_and_does_not_fire_incompat() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        let writer_qos = QoS {
            data_representation: vec![0x0002],
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &SIMPLE_DESC,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
        );

        // Reader accepts XCDR2 -> intersection non-empty -> match fires.
        fsm.insert_remote_endpoint_for_test(remote_reader(vec![0x0002]).clone());
        reg.on_endpoint_discovered(remote_reader(vec![0x0002]));

        assert_eq!(match_count.load(Ordering::Relaxed), 1);
        assert_eq!(incompat_count.load(Ordering::Relaxed), 0);
    }

    // ------------------------------------------------------------------
    // RTI XCDR1 wchar refusal: a remote of vendor RTI negotiating XCDR1
    // whose local type contains wchar is refused, both directions; HDDS,
    // other vendors, and an RTI peer that negotiates XCDR2 are unaffected.
    // The remote's SPDP is built from the OMG vendor registry rule
    // (vendorId 0x0101), never from captured Connext bytes.
    // ------------------------------------------------------------------

    /// A struct with one wchar member.
    fn wchar_type_object() -> CompleteTypeObject {
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, MemberFlag, StructTypeFlag, TypeIdentifier,
            TypeKind,
        };
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Test::HasWchar"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::Primitive(TypeKind::TK_CHAR16),
                },
                detail: CompleteMemberDetail::new("w"),
            }],
        })
    }

    /// An SPDP announcement of a synthetic participant of `vendor_id`,
    /// built from the rules (OMG vendor registry: RTI is 0x0101), as
    /// dialect tests do -- never from captured bytes.
    fn vendor_spdp(
        participant: GUID,
        vendor_id: Option<u16>,
    ) -> crate::protocol::discovery::SpdpData {
        crate::protocol::discovery::SpdpData {
            participant_guid: participant,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        }
    }

    /// A remote endpoint of `kind` under participant `participant`,
    /// announcing `data_representation`.
    fn vendor_remote_endpoint(
        participant: GUID,
        kind: crate::core::discovery::multicast::fsm::EndpointKind,
        data_representation: Vec<u16>,
    ) -> EndpointInfo {
        use crate::core::discovery::multicast::fsm::EndpointKind as EK;
        let entity_id = match kind {
            EK::Writer => [0x00, 0x00, 0x01, 0x02],
            EK::Reader => [0x00, 0x00, 0x01, 0x04],
        };
        EndpointInfo {
            endpoint_guid: GUID::new(participant.prefix, entity_id),
            participant_guid: participant,
            topic_name: "topic".into(),
            type_name: "Test::HasWchar".into(),
            qos: QoS {
                data_representation,
                ..QoS::best_effort()
            },
            kind,
            type_object: None,
            type_object_legacy_v1: false,
            type_information: None,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            shm_capability: None,
            incarnation: 0,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// A local writer of a wchar type, offering only XCDR1, refuses a
    /// remote RTI reader that requests XCDR1: OFFERED_INCOMPATIBLE_QOS
    /// fires with the DATA_REPRESENTATION policy id, never a match.
    #[test]
    fn rti_xcdr1_wchar_writer_refuses_rti_reader() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let rti_participant = GUID::new([0x51; 12], [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(vendor_spdp(rti_participant, Some(0x0101)));

        let before = crate::dds::cdr_negotiation::rti_xcdr1_wchar_refusals();
        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_policy = Arc::new(AtomicU32::new(0));
        let ip = Arc::clone(&incompat_policy);
        let _token = reg.register_writer_with_peers(
            "topic".into(),
            xcdr1_only(),
            crate::dds::match_notification::LocalType::new(
                crate::dds::cdr_negotiation::Xcdr1Encoding::native(),
                "Test::HasWchar",
            ),
            Some(wchar_type_object()),
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            None,
            Some(Box::new(move |_, _, policy_id| {
                ip.store(policy_id, Ordering::Relaxed);
            })),
            None,
            ShmPolicy::default(),
            None,
        );

        let remote = vendor_remote_endpoint(rti_participant, EndpointKind::Reader, vec![0x0000]);
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote.clone());
        reg.on_endpoint_discovered_incompat_only(remote);

        assert_eq!(
            match_count.load(Ordering::Relaxed),
            0,
            "refused, never matched"
        );
        assert_eq!(
            incompat_policy.load(Ordering::Relaxed),
            crate::dds::cdr_negotiation::POLICY_ID_DATA_REPRESENTATION
        );
        // `>`, not `== before + 1`: the counter is process-global and
        // parallel test threads may add their own refusals concurrently.
        assert!(
            crate::dds::cdr_negotiation::rti_xcdr1_wchar_refusals() > before,
            "this pairing's refusal must have counted"
        );
    }

    /// The same rule in the other direction: a local reader of a wchar
    /// type, requesting only XCDR1, refuses a remote RTI writer that
    /// offers XCDR1.
    #[test]
    fn rti_xcdr1_wchar_reader_refuses_rti_writer() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let rti_participant = GUID::new([0x52; 12], [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(vendor_spdp(rti_participant, Some(0x0101)));

        let before = crate::dds::cdr_negotiation::rti_xcdr1_wchar_refusals();
        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_policy = Arc::new(AtomicU32::new(0));
        let ip = Arc::clone(&incompat_policy);
        let _token = reg.register_reader_full(
            "topic".into(),
            xcdr1_only(),
            crate::dds::match_notification::LocalType::new(
                crate::dds::cdr_negotiation::Xcdr1Encoding::native(),
                "Test::HasWchar",
            ),
            Some(wchar_type_object()),
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            None,
            Some(Box::new(move |_, _, policy_id| {
                ip.store(policy_id, Ordering::Relaxed);
            })),
            None,
            None,
            ShmPolicy::default(),
            None,
        );

        let remote = vendor_remote_endpoint(rti_participant, EndpointKind::Writer, vec![0x0000]);
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote.clone());
        reg.on_endpoint_discovered_incompat_only(remote);

        assert_eq!(
            match_count.load(Ordering::Relaxed),
            0,
            "refused, never matched"
        );
        assert_eq!(
            incompat_policy.load(Ordering::Relaxed),
            crate::dds::cdr_negotiation::POLICY_ID_DATA_REPRESENTATION
        );
        // `>`, not `== before + 1`: the counter is process-global and
        // parallel test threads may add their own refusals concurrently.
        assert!(
            crate::dds::cdr_negotiation::rti_xcdr1_wchar_refusals() > before,
            "this pairing's refusal must have counted"
        );
    }

    /// An RTI peer that negotiates XCDR2 (both sides offer/accept it) is
    /// matched on XCDR2, never refused by the item-1 rule: "prefer XCDR2
    /// over refusing".
    #[test]
    fn rti_vendor_xcdr2_wchar_pair_is_not_refused() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let rti_participant = GUID::new([0x53; 12], [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(vendor_spdp(rti_participant, Some(0x0101)));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);
        let writer_qos = QoS {
            data_representation: vec![0x0002],
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_peers(
            "topic".into(),
            writer_qos,
            crate::dds::match_notification::LocalType::new(
                crate::dds::cdr_negotiation::Xcdr1Encoding::native(),
                "Test::HasWchar",
            ),
            Some(wchar_type_object()),
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            None,
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
            None,
            ShmPolicy::default(),
            None,
        );

        let remote = vendor_remote_endpoint(rti_participant, EndpointKind::Reader, vec![0x0002]);
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);

        assert_eq!(match_count.load(Ordering::Relaxed), 1, "XCDR2 pair matches");
        assert_eq!(incompat_count.load(Ordering::Relaxed), 0);
    }

    /// A non-RTI vendor negotiating XCDR1 with a wchar type is unaffected
    /// (RTI's documented 4-byte XCDR1 wchar width is RTI-specific).
    #[test]
    fn non_rti_vendor_xcdr1_wchar_pair_is_not_refused() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        const CYCLONE_VENDOR_ID: u16 = 0x0110;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let cyclone_participant = GUID::new([0x54; 12], [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(vendor_spdp(cyclone_participant, Some(CYCLONE_VENDOR_ID)));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);
        let _token = reg.register_writer_with_peers(
            "topic".into(),
            xcdr1_only(),
            crate::dds::match_notification::LocalType::new(
                crate::dds::cdr_negotiation::Xcdr1Encoding::native(),
                "Test::HasWchar",
            ),
            Some(wchar_type_object()),
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            None,
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
            None,
            ShmPolicy::default(),
            None,
        );

        let remote =
            vendor_remote_endpoint(cyclone_participant, EndpointKind::Reader, vec![0x0000]);
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);

        assert_eq!(
            match_count.load(Ordering::Relaxed),
            1,
            "non-RTI XCDR1 still matches"
        );
        assert_eq!(incompat_count.load(Ordering::Relaxed), 0);
    }

    /// HDDS<->HDDS (no announced vendor is resolved as HDDS's own) with a
    /// wchar type under XCDR1 is unaffected: the rule names RTI, not XCDR1
    /// generally.
    #[test]
    fn hdds_xcdr1_wchar_pair_is_not_refused() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);
        let _token = reg.register_writer_with_peers(
            "topic".into(),
            xcdr1_only(),
            crate::dds::match_notification::LocalType::new(
                crate::dds::cdr_negotiation::Xcdr1Encoding::native(),
                "Test::HasWchar",
            ),
            Some(wchar_type_object()),
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            None,
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
            None,
            ShmPolicy::default(),
            None,
        );

        // No participant SPDP registered at all: vendor resolves to None,
        // exactly like a plain HDDS peer discovery has not yet classified.
        let mut remote = remote_reader(vec![0x0000]);
        remote.type_name = "Test::HasWchar".into();
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);

        assert_eq!(
            match_count.load(Ordering::Relaxed),
            1,
            "unresolved/HDDS vendor still matches"
        );
        assert_eq!(incompat_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn endpoint_removal_decrements_current_match_once() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&events);

        let token = reg.register_writer(
            "topic".into(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::best_effort()
            },
            &SIMPLE_DESC,
            move |total, total_change, current, current_change, guid| {
                captured.lock().unwrap_or_else(|e| e.into_inner()).push((
                    total,
                    total_change,
                    current,
                    current_change,
                    guid,
                ));
            },
        );
        let remote = remote_reader(vec![0x0002]);

        fsm.insert_remote_endpoint_for_test(remote.clone().clone());
        reg.on_endpoint_discovered(remote.clone());
        assert_eq!(token.current_match_count(), 1);

        reg.on_endpoint_removed(remote.clone());
        assert_eq!(token.current_match_count(), 0);
        reg.on_endpoint_removed(remote.clone());

        let events = events.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(events.len(), 2, "duplicate removal must not double-fire");
        assert_eq!(events[0], (1, 1, 1, 1, Some(remote.endpoint_guid)));
        assert_eq!(events[1], (1, 0, 0, -1, Some(remote.endpoint_guid)));
    }

    #[test]
    fn xcdr1_rejected_for_container_type_fires_policy_23() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_policy = Arc::new(AtomicU32::new(0));
        let ip = Arc::clone(&incompat_policy);

        let writer_qos = QoS {
            data_representation: vec![0x0000], // XCDR1 only
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &CONTAINER_DESC, // alignment=8 + is_variable_size
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, policy_id| {
                ip.store(policy_id, Ordering::Relaxed);
            })),
        );

        // Reader also accepts only XCDR1 -> intersection non-empty,
        // but the container type requires native XCDR1 which is not
        // implemented: the guard-rail fires policy 23 via the incompat
        // path. The match path stays silent on both sides.
        let remote = remote_reader_of(&CONTAINER_DESC, vec![0x0000]);
        fsm.insert_remote_endpoint_for_test(remote.clone().clone());
        reg.on_endpoint_discovered(remote.clone());
        assert_eq!(match_count.load(Ordering::Relaxed), 0);
        assert_eq!(incompat_policy.load(Ordering::Relaxed), 0);

        reg.on_endpoint_discovered_incompat_only(remote);
        assert_eq!(
            incompat_policy.load(Ordering::Relaxed),
            crate::dds::cdr_negotiation::POLICY_ID_DATA_REPRESENTATION
        );
    }

    #[test]
    fn xcdr2_proceeds_for_container_type() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        let writer_qos = QoS {
            data_representation: vec![0x0002], // XCDR2 only
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &CONTAINER_DESC,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
        );

        // Reader accepts XCDR2 -> negotiation resolves to XCDR2, which the
        // codegen path supports natively on container types; guard-rail
        // does not fire.
        fsm.insert_remote_endpoint_for_test(
            remote_reader_of(&CONTAINER_DESC, vec![0x0002]).clone(),
        );
        reg.on_endpoint_discovered(remote_reader_of(&CONTAINER_DESC, vec![0x0002]));

        assert_eq!(match_count.load(Ordering::Relaxed), 1);
        assert_eq!(incompat_count.load(Ordering::Relaxed), 0);
    }

    /// A derived `{ String, i64 }`: variable size, 8-byte member, the shape
    /// the descriptor-only guess refuses under XCDR1. Its derived encoder
    /// aligns the i64 by the version, so it says XCDR1 is native.
    #[derive(crate::DDS, Debug, Clone, PartialEq)]
    struct DerivedStrI64 {
        s: String,
        b: i64,
    }

    /// The same shape, written by hand, saying nothing: the default guess.
    struct HandWrittenStrI64;

    static HAND_WRITTEN_STR_I64_DESC: crate::core::types::TypeDescriptor =
        crate::core::types::TypeDescriptor {
            type_id: 0,
            type_name: "HandWrittenStrI64",
            size_bytes: 0,
            alignment: 8,
            is_variable_size: true,
            fields: &[],
        };

    impl crate::dds::DDS for HandWrittenStrI64 {
        fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
            &HAND_WRITTEN_STR_I64_DESC
        }
        fn encode(
            &self,
            _buf: &mut [u8],
            _version: crate::dds::CdrVersion,
        ) -> crate::dds::Result<usize> {
            Ok(0)
        }
        fn decode(_buf: &[u8], _version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
            Ok(Self)
        }
    }

    fn xcdr1_only() -> QoS {
        QoS {
            data_representation: vec![0x0000],
            ..QoS::best_effort()
        }
    }

    /// (matches, incompatibilities) of a local writer of the given encoding
    /// against a remote XCDR1 reader discovered after it (the live path).
    fn local_xcdr1_writer_meets_a_later_reader(
        desc: &'static crate::core::types::TypeDescriptor,
        encoding: crate::dds::cdr_negotiation::Xcdr1Encoding,
    ) -> (u32, u32) {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let matches = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&matches);
        let incompat = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat);
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            xcdr1_only(),
            crate::dds::match_notification::LocalType::new(encoding, desc.type_name),
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
        );
        let remote = remote_reader_of(desc, vec![0x0000]);
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote.clone());
        reg.on_endpoint_discovered_incompat_only(remote);
        (
            matches.load(Ordering::Relaxed),
            incompat.load(Ordering::Relaxed),
        )
    }

    /// (matches, incompatibilities) of a local XCDR1 reader of the given
    /// encoding and a remote XCDR1 writer. `writer_first`: the writer was
    /// cached before the reader registered (the catch-up path, which reports
    /// an incompatibility at once but holds a match back while discovery is
    /// in probation); otherwise it is discovered after (the live path).
    fn local_xcdr1_reader_meets_a_writer(
        desc: &'static crate::core::types::TypeDescriptor,
        encoding: crate::dds::cdr_negotiation::Xcdr1Encoding,
        writer_first: bool,
    ) -> (u32, u32) {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let mut remote = remote_endpoint(EndpointKind::Writer);
        remote.type_name = desc.type_name.into();
        remote.qos.data_representation = vec![0x0000];
        if writer_first {
            fsm.insert_remote_endpoint_for_test(remote.clone());
        }
        let matches = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&matches);
        let incompat = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat);
        let _token = reg.register_reader_with_lifespan(
            "topic".into(),
            xcdr1_only(),
            crate::dds::match_notification::LocalType::new(encoding, desc.type_name),
            None,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            None,
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
            None,
            Arc::new(AtomicU64::new(u64::MAX)),
            ShmPolicy::default(),
        );
        if !writer_first {
            fsm.insert_remote_endpoint_for_test(remote.clone());
            reg.on_endpoint_discovered(remote.clone());
            reg.on_endpoint_discovered_incompat_only(remote);
        }
        (
            matches.load(Ordering::Relaxed),
            incompat.load(Ordering::Relaxed),
        )
    }

    /// A derived `{ String, i64 }` matches under XCDR1 as a writer and as a
    /// reader, and the catch-up path does not refuse it. Its descriptor
    /// alone would have refused it: that is the guess the declaration
    /// overrides.
    #[test]
    fn a_derived_string_i64_type_matches_under_xcdr1_on_both_sides() {
        assert!(crate::dds::cdr_negotiation::type_requires_native_xcdr1(
            <DerivedStrI64 as crate::dds::DDS>::type_descriptor()
        ));
        let derived = crate::dds::cdr_negotiation::Xcdr1Encoding::of::<DerivedStrI64>();
        let desc = <DerivedStrI64 as crate::dds::DDS>::type_descriptor();
        assert_eq!(
            local_xcdr1_writer_meets_a_later_reader(desc, derived),
            (1, 0)
        );
        assert_eq!(
            local_xcdr1_reader_meets_a_writer(desc, derived, false),
            (1, 0)
        );
        // Catch-up: no refusal reported (the match itself waits for the
        // end of probation, for every type).
        assert_eq!(
            local_xcdr1_reader_meets_a_writer(desc, derived, true),
            (0, 0)
        );
    }

    /// A type that declares nothing keeps the guess, on both sides.
    #[test]
    fn a_hand_written_string_i64_type_is_still_refused_under_xcdr1() {
        let guessed = crate::dds::cdr_negotiation::Xcdr1Encoding::of::<HandWrittenStrI64>();
        let desc = &HAND_WRITTEN_STR_I64_DESC;
        assert_eq!(
            local_xcdr1_writer_meets_a_later_reader(desc, guessed),
            (0, 1)
        );
        assert_eq!(
            local_xcdr1_reader_meets_a_writer(desc, guessed, false),
            (0, 1)
        );
        assert_eq!(
            local_xcdr1_reader_meets_a_writer(desc, guessed, true),
            (0, 1)
        );
    }

    #[test]
    fn xcdr1_accepted_for_simple_type() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        let writer_qos = QoS {
            data_representation: vec![0x0000], // XCDR1 only
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &SIMPLE_DESC, // alignment=4, is_variable_size=false
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
        );

        // Simple type: XCDR1 natively supported (primitive types have
        // identical XCDR1/XCDR2 layout at 4-byte alignment or finer).
        fsm.insert_remote_endpoint_for_test(remote_reader(vec![0x0000]).clone());
        reg.on_endpoint_discovered(remote_reader(vec![0x0000]));

        assert_eq!(match_count.load(Ordering::Relaxed), 1);
        assert_eq!(incompat_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn register_and_unregister() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);
        let token = reg.register_writer(
            "test".into(),
            test_qos(),
            &SIMPLE_DESC,
            move |_, _, _, _, _| {
                cc.fetch_add(1, Ordering::Relaxed);
            },
        );

        // Should have 1 entry
        assert_eq!(
            reg.entries.read().unwrap_or_else(|e| e.into_inner()).len(),
            1
        );

        // Drop token -> unregisters
        drop(token);
        assert_eq!(
            reg.entries.read().unwrap_or_else(|e| e.into_inner()).len(),
            0
        );
    }

    /// Build a remote endpoint of a chosen kind with a default-best-effort QoS.
    /// Used to exercise the same-kind / opposite-kind routing in
    /// `on_endpoint_discovered`.
    fn remote_endpoint(kind: crate::core::discovery::multicast::fsm::EndpointKind) -> EndpointInfo {
        let guid = GUID::from_bytes([
            0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0x04,
        ]);
        let qos = QoS {
            // As a writer it offers XCDR2, which a local reader that set
            // no list requests; as a reader it requests XCDR2 and XCDR, so a
            // local writer that set none (XCDR, Sec.7.6.3.1.1) matches it
            // too. A same-kind pair must rely solely on the same-kind
            // guard, not on any compatibility coincidence.
            data_representation: vec![0x0002, 0x0000],
            ..QoS::best_effort()
        };
        EndpointInfo {
            endpoint_guid: guid,
            participant_guid: guid,
            topic_name: "topic".into(),
            type_name: SIMPLE_DESC.type_name.into(),
            qos,
            kind,
            type_object: None,
            type_object_legacy_v1: false,
            type_information: None,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            shm_capability: None,
            incarnation: 0,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// A local Writer that discovers a remote Writer on the same topic must
    /// NOT fire `on_offered_incompatible_qos`. DDS matching is strictly
    /// cross-kind (DDS v1.4 sec. 2.2.3.8 OFFERED_INCOMPATIBLE_QOS is defined
    /// only for Writer<->Reader). Without the same-kind guard, the
    /// `_ => false` arm in the compatibility match would label Writer-Writer
    /// pairs as INCOMPATIBLE and force `data_rep_ok` false (because
    /// `cdr_result` defaults to `None`), firing a false-positive
    /// `INCOMPATIBLE_QOS` event with policy_id = 23 (DataRepresentation)
    /// whenever two publishers (or two subscribers) co-exist on the same
    /// topic.
    #[test]
    fn same_kind_writer_pair_does_not_fire_incompat() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
        );

        fsm.insert_remote_endpoint_for_test(remote_endpoint(EndpointKind::Writer).clone());
        reg.on_endpoint_discovered(remote_endpoint(EndpointKind::Writer));

        assert_eq!(
            match_count.load(Ordering::Relaxed),
            0,
            "Writer-Writer pair must not produce a publication-matched event"
        );
        assert_eq!(
            incompat_count.load(Ordering::Relaxed),
            0,
            "Writer-Writer pair must not fire on_offered_incompatible_qos"
        );
    }

    /// Symmetric case: a local Reader that discovers a remote Reader
    /// on the same topic must NOT fire `on_requested_incompatible_qos`.
    #[test]
    fn same_kind_reader_pair_does_not_fire_incompat() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        // `register_reader_with_lifespan` is the only public reader hook;
        // an effectively-infinite lifespan cell makes it equivalent to a
        // plain reader registration for the purpose of this test.
        let lifespan = Arc::new(AtomicU64::new(u64::MAX));
        let _token = reg.register_reader_with_lifespan(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None, // type_object: not needed for same-kind guard test
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            None,
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
            None,
            lifespan,
            ShmPolicy::default(),
        );

        fsm.insert_remote_endpoint_for_test(remote_endpoint(EndpointKind::Reader).clone());
        reg.on_endpoint_discovered(remote_endpoint(EndpointKind::Reader));

        assert_eq!(
            match_count.load(Ordering::Relaxed),
            0,
            "Reader-Reader pair must not produce a subscription-matched event"
        );
        assert_eq!(
            incompat_count.load(Ordering::Relaxed),
            0,
            "Reader-Reader pair must not fire on_requested_incompatible_qos"
        );
    }

    /// `notify_inconsistent_type` increments the counter and fires the
    /// callback on the first call; deduplicates on repeated calls for
    /// the same remote GUID.
    #[test]
    fn notify_inconsistent_type_fires_callback_and_deduplicates() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let cb_fires = Arc::new(AtomicU32::new(0));
        let cb_fires_clone = Arc::clone(&cb_fires);
        let last_total = Arc::new(AtomicU32::new(0));
        let last_total_clone = Arc::clone(&last_total);

        let token = reg.register_writer_full(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None, // type_object: not needed for dedup test
            |_, _, _, _, _| {},
            None,
            Some(Box::new(move |total, _change| {
                cb_fires_clone.fetch_add(1, Ordering::SeqCst);
                last_total_clone.store(total, Ordering::SeqCst);
            })),
            ShmPolicy::default(),
            None,
        );
        let entry_id = token.id;

        let remote_a = GUID::from_bytes([0xA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]);
        let remote_b = GUID::from_bytes([0xB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]);

        // First remote fires.
        reg.notify_inconsistent_type(entry_id, remote_a);
        assert_eq!(cb_fires.load(Ordering::SeqCst), 1);
        assert_eq!(last_total.load(Ordering::SeqCst), 1);

        // Same remote again -- deduped, counter stays at 1.
        reg.notify_inconsistent_type(entry_id, remote_a);
        assert_eq!(cb_fires.load(Ordering::SeqCst), 1);

        // New distinct remote fires again.
        reg.notify_inconsistent_type(entry_id, remote_b);
        assert_eq!(cb_fires.load(Ordering::SeqCst), 2);
        assert_eq!(last_total.load(Ordering::SeqCst), 2);

        // Status query reflects cumulative count.
        let status = reg.get_inconsistent_topic_status(entry_id);
        assert!(status.is_some());
        assert_eq!(status.unwrap().total_count, 2);
    }

    /// Counter is maintained even with no listener callback installed
    /// (counter-only test pattern used by the OMG harness).
    #[test]
    fn notify_inconsistent_type_increments_counter_without_callback() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let token = reg.register_writer_full(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None, // type_object: not needed for counter-only test
            |_, _, _, _, _| {},
            None,
            None, // no listener
            ShmPolicy::default(),
            None,
        );
        let entry_id = token.id;

        let remote = GUID::from_bytes([0xC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]);
        reg.notify_inconsistent_type(entry_id, remote);
        reg.notify_inconsistent_type(entry_id, remote); // dedup

        let status = reg
            .get_inconsistent_topic_status(entry_id)
            .expect("entry must exist");
        assert_eq!(
            status.total_count, 1,
            "counter must be 1 despite no callback"
        );
    }

    /// A side of the verdict that holds `object` (`Known`), named as the
    /// struct tests name it.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn known_side(object: &CompleteTypeObject) -> TypeSide<'_> {
        TypeSide {
            object: Some(object),
            name: "",
            pending: false,
        }
    }

    /// A side of the verdict with no TypeObject: `Absent`, or `Pending` when
    /// it announced a complete TypeIdentifier and has none yet.
    fn bare_side(name: &str, pending: bool) -> TypeSide<'_> {
        TypeSide {
            object: None,
            name,
            pending,
        }
    }

    /// The side of a verdict in `state`: `Known` holds `object`.
    fn side_in<'a>(
        state: TypeState,
        object: &'a CompleteTypeObject,
        name: &'a str,
    ) -> TypeSide<'a> {
        match state {
            TypeState::Known => TypeSide {
                object: Some(object),
                name,
                pending: false,
            },
            TypeState::Pending => bare_side(name, true),
            TypeState::Absent => bare_side(name, false),
        }
    }

    /// A struct TypeObject with no members, named `name`.
    fn struct_object(name: &str) -> CompleteTypeObject {
        CompleteTypeObject::Struct(crate::xtypes::CompleteStructType {
            struct_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: crate::xtypes::CompleteStructHeader {
                base_type: None,
                detail: crate::xtypes::CompleteTypeDetail::new(name),
            },
            member_seq: Vec::new(),
        })
    }

    /// The verdict table of DDS-XTypes v1.3 Sec.7.6.3.4.2 as the tests read
    /// it, for a writer in `writer` and a reader in `reader`: Step 1 when both
    /// sides are `Known` (names not compared); a `Pending` side keeps today's
    /// rule (accepted unless the reader forces validation); otherwise Step 2
    /// is the decision in `enforce` and today's rule in `off` and `warn`.
    fn expected_verdict(
        writer: TypeState,
        reader: TypeState,
        names_equal: bool,
        forced: bool,
        mode: TypeNameMatch,
    ) -> bool {
        match (writer, reader) {
            (TypeState::Known, TypeState::Known) => true,
            (TypeState::Pending, _) | (_, TypeState::Pending) => !forced,
            _ => match mode {
                TypeNameMatch::Off | TypeNameMatch::Warn => !forced,
                TypeNameMatch::Enforce => !forced && names_equal,
            },
        }
    }

    /// Every state pair, both name relations, force false and true, and each
    /// mode: the verdict is the table's. The writer and reader sides are both
    /// varied, so the writer-side and reader-side readings of Step 2 are each
    /// covered.
    #[test]
    fn type_verdict_table_covers_states_names_force_and_mode() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = MatchNotificationRegistry::new(&fsm, [0; 12]);
        let object = struct_object("Test::Shared");
        let states = [TypeState::Absent, TypeState::Pending, TypeState::Known];
        let mut cases = 0;
        for writer_state in states {
            for reader_state in states {
                for names_equal in [true, false] {
                    let reader_name = if names_equal { "Simple" } else { "T" };
                    for forced in [false, true] {
                        let policy =
                            crate::protocol::discovery::types::TypeConsistencyEnforcement {
                                force_type_validation: forced,
                                ..Default::default()
                            };
                        for mode in [
                            TypeNameMatch::Off,
                            TypeNameMatch::Warn,
                            TypeNameMatch::Enforce,
                        ] {
                            let got = reg.pairing_type_verdict_in(
                                mode,
                                "step2-table",
                                side_in(writer_state, &object, "Simple"),
                                side_in(reader_state, &object, reader_name),
                                Some(&policy),
                            );
                            let want = expected_verdict(
                                writer_state,
                                reader_state,
                                names_equal,
                                forced,
                                mode,
                            );
                            assert_eq!(
                                got, want,
                                "writer {writer_state:?}, reader {reader_state:?}, names equal \
                                 {names_equal}, force {forced}, mode {mode:?}"
                            );
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(
            cases, 108,
            "3 x 3 states, 2 name relations, 2 force, 3 modes"
        );
    }

    /// A `Pending` side is never a Step 2 decision: in every mode, with names
    /// that differ and force either way, the verdict is today's rule and the
    /// warn counter does not move.
    #[test]
    fn a_pending_side_is_never_judged_by_step_2() {
        let topic = "step2-pending";
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = MatchNotificationRegistry::new(&fsm, [0; 12]);
        let object = struct_object("Test::Shared");
        for mode in [
            TypeNameMatch::Off,
            TypeNameMatch::Warn,
            TypeNameMatch::Enforce,
        ] {
            for forced in [false, true] {
                let policy = crate::protocol::discovery::types::TypeConsistencyEnforcement {
                    force_type_validation: forced,
                    ..Default::default()
                };
                for (writer, reader) in [
                    (bare_side("Simple", true), bare_side("T", false)),
                    (bare_side("Simple", false), bare_side("T", true)),
                    (
                        side_in(TypeState::Pending, &object, "Simple"),
                        side_in(TypeState::Known, &object, "T"),
                    ),
                ] {
                    let got =
                        reg.pairing_type_verdict_in(mode, topic, writer, reader, Some(&policy));
                    assert_eq!(got, !forced, "mode {mode:?}, force {forced}");
                }
            }
        }
        assert_eq!(
            reg.type_name_warning_count(topic),
            0,
            "no Step 2 warning for a pending pairing"
        );
    }

    /// The warn counter is one per distinct (topic, writer type name, reader
    /// type name), however often the pairing is judged, whatever force says
    /// (force is not part of the pair), and only in warn mode.
    #[test]
    fn the_warn_counter_increments_once_per_distinct_pair() {
        let topic = "step2-counter";
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = MatchNotificationRegistry::new(&fsm, [0; 12]);
        let plain = crate::protocol::discovery::types::TypeConsistencyEnforcement::default();
        let forced = crate::protocol::discovery::types::TypeConsistencyEnforcement {
            force_type_validation: true,
            ..Default::default()
        };
        assert_eq!(reg.type_name_warning_count(topic), 0);

        for _ in 0..3 {
            assert!(reg.pairing_type_verdict_in(
                TypeNameMatch::Warn,
                topic,
                bare_side("A", false),
                bare_side("B", false),
                Some(&plain),
            ));
        }
        assert_eq!(
            reg.type_name_warning_count(topic),
            1,
            "A/B judged three times"
        );

        assert!(!reg.pairing_type_verdict_in(
            TypeNameMatch::Warn,
            topic,
            bare_side("A", false),
            bare_side("B", false),
            Some(&forced),
        ));
        assert_eq!(
            reg.type_name_warning_count(topic),
            1,
            "A/B forced is the same pair"
        );

        reg.pairing_type_verdict_in(
            TypeNameMatch::Warn,
            topic,
            bare_side("A", false),
            bare_side("C", false),
            Some(&plain),
        );
        assert_eq!(
            reg.type_name_warning_count(topic),
            2,
            "A/C is a second pair"
        );

        reg.pairing_type_verdict_in(
            TypeNameMatch::Warn,
            topic,
            bare_side("A", false),
            bare_side("A", false),
            Some(&plain),
        );
        assert_eq!(
            reg.type_name_warning_count(topic),
            2,
            "equal names pass Step 2"
        );

        reg.pairing_type_verdict_in(
            TypeNameMatch::Enforce,
            topic,
            bare_side("A", false),
            bare_side("D", false),
            Some(&plain),
        );
        reg.pairing_type_verdict_in(
            TypeNameMatch::Off,
            topic,
            bare_side("A", false),
            bare_side("E", false),
            Some(&plain),
        );
        assert_eq!(
            reg.type_name_warning_count(topic),
            2,
            "only warn mode counts: enforce and off do not"
        );
    }

    /// `HDDS_TYPE_NAME_MATCH` values, case-insensitive; anything else has no
    /// mode (the process then runs warn).
    #[test]
    fn the_type_name_match_values_parse() {
        assert_eq!(TypeNameMatch::parse("off"), Some(TypeNameMatch::Off));
        assert_eq!(TypeNameMatch::parse(" WARN "), Some(TypeNameMatch::Warn));
        assert_eq!(
            TypeNameMatch::parse("Enforce"),
            Some(TypeNameMatch::Enforce)
        );
        assert_eq!(TypeNameMatch::parse("strict"), None);
        assert_eq!(TypeNameMatch::parse(""), None);
    }

    /// A remote endpoint of `kind` on `topic`, announcing `type_name`, with
    /// no TypeObject, the given TypeInformation, and force_type_validation
    /// on its policy when `forced`.
    fn absent_remote(
        kind: EndpointKind,
        topic: &str,
        type_name: &str,
        type_information: Option<crate::protocol::discovery::types::TypeInformation>,
        forced: bool,
    ) -> EndpointInfo {
        EndpointInfo {
            endpoint_guid: GUID::from_bytes([
                0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0x04,
            ]),
            participant_guid: GUID::from_bytes([
                0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0x04,
            ]),
            topic_name: topic.into(),
            type_name: type_name.into(),
            qos: QoS {
                data_representation: vec![0x0002],
                type_consistency: forced.then(|| {
                    crate::protocol::discovery::types::TypeConsistencyEnforcement {
                        force_type_validation: true,
                        ..Default::default()
                    }
                }),
                ..QoS::best_effort()
            },
            kind,
            type_object: None,
            type_object_legacy_v1: false,
            type_information,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            shm_capability: None,
            incarnation: 0,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// Discovery's judgment of `remote` (a reader) against a local writer
    /// of type "Simple" with no TypeObject, under `mode`. Returns how many
    /// times the pairing matched, how many times it was reported as an
    /// inconsistent topic, and how many distinct pairs this registry counted
    /// as warnings. Judged as `handle_sedp` judges it: the refusal is judged
    /// and reported, then the match path runs.
    fn judged_pairing(mode: TypeNameMatch, remote: EndpointInfo) -> (u32, u32, usize) {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]).with_type_name_mode(mode));
        let matches = Arc::new(AtomicU32::new(0));
        let matched = Arc::clone(&matches);
        let reports = Arc::new(AtomicU32::new(0));
        let reported = Arc::clone(&reports);
        let _token = reg.register_writer_full(
            remote.topic_name.clone(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::best_effort()
            },
            &SIMPLE_DESC,
            None,
            move |_, _, _, _, _| {
                matched.fetch_add(1, Ordering::Relaxed);
            },
            None,
            Some(Box::new(move |_, _| {
                reported.fetch_add(1, Ordering::Relaxed);
            })),
            ShmPolicy::default(),
            None,
        );
        fsm.insert_remote_endpoint_for_test(remote.clone());
        if reg.judge_remote_types(&remote) {
            reg.notify_inconsistent_type_for_topic(&remote);
        }
        reg.on_endpoint_discovered(remote.clone());
        let warned = reg.type_name_warning_count(&remote.topic_name);
        (
            matches.load(Ordering::Relaxed),
            reports.load(Ordering::Relaxed),
            warned,
        )
    }

    /// The pinned absent-TypeObject pairing with EQUAL type names (local
    /// "Simple", remote "Simple", neither with a TypeObject): Step 2 passes
    /// in every mode, so the pairing matches, nothing is reported, and
    /// nothing is counted.
    #[test]
    fn equal_type_names_match_in_every_mode() {
        for mode in [
            TypeNameMatch::Off,
            TypeNameMatch::Warn,
            TypeNameMatch::Enforce,
        ] {
            let remote = absent_remote(EndpointKind::Reader, "tn-equal", "Simple", None, false);
            assert_eq!(
                judged_pairing(mode, remote),
                (1, 0, 0),
                "mode {mode:?}: equal names are never a refused pair"
            );
        }
    }

    /// The pinned absent-TypeObject pairing with DIFFERENT type names (local
    /// "Simple", remote "T"): matched in off and warn, as before Step 2 (warn
    /// logs the pair and counts it once); in enforce it is not matched, and
    /// is reported as an inconsistent topic like any other type mismatch.
    #[test]
    fn different_type_names_match_in_off_and_warn_and_not_in_enforce() {
        let remote = || absent_remote(EndpointKind::Reader, "tn-different", "T", None, false);
        assert_eq!(
            judged_pairing(TypeNameMatch::Off, remote()),
            (1, 0, 0),
            "off: matched as before, nothing counted"
        );
        assert_eq!(
            judged_pairing(TypeNameMatch::Warn, remote()),
            (1, 0, 1),
            "warn: matched as before, the refused pair counted once though judged twice"
        );
        assert_eq!(
            judged_pairing(TypeNameMatch::Enforce, remote()),
            (0, 1, 0),
            "enforce: no match, one inconsistent-topic report, nothing counted"
        );
    }

    /// A reader that announced a complete TypeIdentifier whose TypeObject has
    /// not arrived is Pending: today's rule holds in every mode, so it
    /// matches even in enforce with a different name; when it forces type
    /// validation, it is refused as before, and reported. Never counted.
    #[test]
    fn a_pending_remote_keeps_todays_verdict_in_every_mode() {
        use crate::protocol::discovery::types::{TypeIdentifierWithDependencies, TypeInformation};
        let announced = || {
            Some(TypeInformation {
                minimal: None,
                complete: Some(TypeIdentifierWithDependencies {
                    hash: crate::xtypes::EquivalenceHash::from_bytes([0x5A; 14]),
                    typeobject_serialized_size: 0,
                    dependent_typeids: Vec::new(),
                }),
            })
        };
        for mode in [
            TypeNameMatch::Off,
            TypeNameMatch::Warn,
            TypeNameMatch::Enforce,
        ] {
            let remote = absent_remote(EndpointKind::Reader, "tn-pending", "T", announced(), false);
            assert_eq!(
                judged_pairing(mode, remote),
                (1, 0, 0),
                "mode {mode:?}: a pending pairing keeps today's match, and is not a Step 2 decision"
            );
        }
        let forced = absent_remote(EndpointKind::Reader, "tn-pending", "T", announced(), true);
        assert_eq!(
            judged_pairing(TypeNameMatch::Enforce, forced),
            (0, 1, 0),
            "pending and forced: refused as before, and reported"
        );
    }

    /// Regression: evaluate_entries must emit Match (not Skip) when the local
    /// entry carries no TypeObject but the remote does. Mirrors the above but
    /// from the reader side: local type_object=None, remote writer type_object=None
    /// (same reasoning -- absent type info falls through to name-based matching).
    #[test]
    fn match_fires_when_both_type_objects_absent() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);

        let lifespan = Arc::new(AtomicU64::new(u64::MAX));
        let _token = reg.register_reader_with_lifespan(
            "topic".into(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::best_effort()
            },
            &SIMPLE_DESC,
            None, // local type_object absent
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            None,
            None,
            None,
            lifespan,
            ShmPolicy::default(),
        );

        // Remote writer: no TypeObject, XCDR2 offered -- must Match.
        let remote = EndpointInfo {
            endpoint_guid: GUID::from_bytes([
                0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0x07,
            ]),
            participant_guid: GUID::from_bytes([
                0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0x07,
            ]),
            topic_name: "topic".into(),
            type_name: SIMPLE_DESC.type_name.into(),
            qos: QoS {
                data_representation: vec![0x0002],
                ..QoS::best_effort()
            },
            kind: EndpointKind::Writer,
            type_object: None,
            type_object_legacy_v1: false,
            type_information: None,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            shm_capability: None,
            incarnation: 0,
            group_entity_id: None,
            endpoint_security_info: None,
        };
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);
        assert_eq!(
            match_count.load(Ordering::Relaxed),
            1,
            "Match must fire when both TypeObjects are absent"
        );
    }

    /// `get_inconsistent_topic_status` must return the delta since the previous
    /// call, not the cumulative total. Successive polls with no new events in
    /// between must return `total_count_change == 0`.
    ///
    /// DDS spec sec. 2.2.4.3.13: `total_count_change` is reset to zero on each
    /// read -- i.e. it represents the number of new inconsistent types since
    /// the last status read, not since the endpoint was created.
    #[test]
    fn get_inconsistent_topic_status_returns_delta_not_cumulative() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let token = reg.register_writer_full(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        let entry_id = token.id;

        let remote_a = GUID::from_bytes([0xD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]);
        let remote_b = GUID::from_bytes([0xE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]);

        // First event: one remote becomes inconsistent.
        reg.notify_inconsistent_type(entry_id, remote_a);

        let s1 = reg.get_inconsistent_topic_status(entry_id).unwrap();
        assert_eq!(s1.total_count, 1, "total must be 1 after first event");
        assert_eq!(s1.total_count_change, 1, "delta must be 1 on first poll");

        // Second poll with no new events: delta must be zero.
        let s2 = reg.get_inconsistent_topic_status(entry_id).unwrap();
        assert_eq!(s2.total_count, 1, "total is still 1 (no new events)");
        assert_eq!(
            s2.total_count_change, 0,
            "delta must be 0 when no new events"
        );

        // A second distinct remote fires: delta for this poll is 1, total is 2.
        reg.notify_inconsistent_type(entry_id, remote_b);

        let s3 = reg.get_inconsistent_topic_status(entry_id).unwrap();
        assert_eq!(s3.total_count, 2, "total must be 2 after second event");
        assert_eq!(
            s3.total_count_change, 1,
            "delta must be 1 for the new event only"
        );

        // Final poll with no new events again: delta resets to zero.
        let s4 = reg.get_inconsistent_topic_status(entry_id).unwrap();
        assert_eq!(s4.total_count, 2);
        assert_eq!(
            s4.total_count_change, 0,
            "delta must be 0 when no new events since last poll"
        );
    }

    /// Lazy TypeInformation resolution: a remote SEDP cached with
    /// type_object=None (arrival-time resolution missed because the local
    /// type store was still empty) must become resolvable once the local
    /// endpoint registers its TypeObject. Exercises the 3-recourse chain
    /// (minimal hash, complete hash, name fallback) that the late-side
    /// compatibility checks call through `resolve_type_information`.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn resolve_type_information_resolves_after_local_registration() {
        use crate::protocol::discovery::types::{TypeIdentifierWithDependencies, TypeInformation};
        use crate::xtypes::{
            CompleteStructHeader, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
            EquivalenceHash, StructTypeFlag,
        };

        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let local_hash = EquivalenceHash::from_bytes([1; 14]);
        let local_obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Test::struct_lazy"),
            },
            member_seq: vec![],
        });
        let ti_with = |hash: EquivalenceHash| TypeInformation {
            minimal: Some(TypeIdentifierWithDependencies {
                hash,
                typeobject_serialized_size: 0,
                dependent_typeids: vec![],
            }),
            complete: None,
        };

        // Store empty (remote-before-local ordering): resolution misses.
        assert!(
            reg.resolve_type_information(&ti_with(local_hash), "Test::struct_lazy")
                .is_none(),
            "must miss while the local type store is empty"
        );

        // Local endpoint registers its TypeObject.
        let mut types = std::collections::HashMap::new();
        types.insert(local_hash, local_obj);
        reg.register_type_objects(types);

        // Recourse 1: minimal hash hit.
        assert!(
            reg.resolve_type_information(&ti_with(local_hash), "Test::struct_lazy")
                .is_some(),
            "minimal-hash recourse must resolve after registration"
        );
        // Recourse 3: hash-divergent peer (wrong hash), name fallback hit.
        assert!(
            reg.resolve_type_information(
                &ti_with(EquivalenceHash::from_bytes([9; 14])),
                "Test::struct_lazy"
            )
            .is_some(),
            "name recourse must resolve a hash-divergent announcement"
        );
        // Total miss (wrong hash AND wrong name) keeps "absent -> allow".
        assert!(
            reg.resolve_type_information(
                &ti_with(EquivalenceHash::from_bytes([9; 14])),
                "Test::struct_other"
            )
            .is_none(),
            "unknown hash and name must keep resolving to None"
        );
    }

    // ------------------------------------------------------------------
    // SHM-vs-UDP transport verdict (cold-path pairing resolution).
    //
    // These tests feed `on_endpoint_discovered` a hand-built `EndpointInfo`
    // with an explicit `shm_capability`, exactly like `match_fires_when_remote_type_object_absent`
    // and friends already do above. This is the production match entry
    // point (`DiscoveryListener::on_endpoint_discovered`, called by
    // `DiscoveryFsm::handle_sedp`); the only difference from a real remote
    // peer is that the `SedpData` did not travel over a wire. The SEDP
    // encoder does serialize PID_USER_DATA, so this seam only keeps the
    // tests deterministic: it needs no second process and no real transport.
    // ------------------------------------------------------------------

    fn remote_with_shm_capability(
        kind: crate::core::discovery::multicast::fsm::EndpointKind,
        reliability: Reliability,
        shm_capability: Option<String>,
        entity_byte: u8,
    ) -> EndpointInfo {
        let guid = GUID::from_bytes([
            0x5,
            0x5,
            0x5,
            0x5,
            0x5,
            0x5,
            1,
            2,
            3,
            4,
            5,
            6,
            0,
            0,
            0,
            entity_byte,
        ]);
        let qos = QoS {
            reliability,
            data_representation: vec![0x0002],
            ..QoS::best_effort()
        };
        EndpointInfo {
            endpoint_guid: guid,
            participant_guid: guid,
            topic_name: "shm-topic".into(),
            type_name: SIMPLE_DESC.type_name.into(),
            qos,
            kind,
            type_object: None,
            type_object_legacy_v1: false,
            type_information: None,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            shm_capability,
            incarnation: 0,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    fn shm_topic_qos() -> QoS {
        QoS {
            data_representation: vec![0x0002],
            ..QoS::best_effort()
        }
    }

    /// (a) Two same-host BestEffort endpoints, with the remote advertising a
    /// valid SHM hint for this host, resolve to `Shm` on Linux. On the
    /// non-Linux stub `can_use_shm_transport` always returns `None` (see
    /// `transport/mod.rs`), so the honest expectation there is `Udp`.
    #[test]
    fn shm_prefer_same_host_best_effort_resolves_per_platform() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let token = reg.register_writer_full(
            "shm-topic".into(),
            shm_topic_qos(),
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            None,
            None,
            ShmPolicy::Prefer,
            None,
        );

        let hint = crate::transport::shm::format_shm_user_data();
        let remote = remote_with_shm_capability(
            EndpointKind::Reader,
            Reliability::BestEffort,
            Some(hint),
            0x04,
        );
        let remote_guid = remote.endpoint_guid;
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);

        let selection = token.transport_selection(&remote_guid);
        // `cfg!()` is a runtime boolean, not `#[cfg]` -- both arms of a plain
        // `if` still have to type-check on every platform. The non-Linux
        // stub's `TransportSelection::Shm` is a unit variant (no `host_id`
        // field), so the struct pattern used below is only valid inside a
        // `#[cfg(target_os = "linux")]`-gated block, never behind a runtime
        // `if cfg!(...)`.
        #[cfg(target_os = "linux")]
        assert!(
            matches!(selection, Some(TransportSelection::Shm { .. })),
            "same-host BestEffort pair with a valid SHM hint must resolve to Shm on Linux, got {selection:?}"
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            selection,
            Some(TransportSelection::Udp),
            "non-Linux stub never grants SHM"
        );
    }

    /// (b) The remote advertises SHM on a different host_id: must resolve to
    /// `Udp` under `Prefer` on every platform.
    #[test]
    fn shm_prefer_different_host_resolves_to_udp() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        // @audit-ok: guard against the unlikely collision with the test sentinel,
        // same pattern as transport/shm/policy.rs's own unit tests.
        if crate::transport::shm::host_id() == 0xDEAD_BEEF {
            return;
        }
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let token = reg.register_writer_full(
            "shm-topic".into(),
            shm_topic_qos(),
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            None,
            None,
            ShmPolicy::Prefer,
            None,
        );

        let remote = remote_with_shm_capability(
            EndpointKind::Reader,
            Reliability::BestEffort,
            Some("shm=1;host_id=deadbeef;v=1".to_string()),
            0x04,
        );
        let remote_guid = remote.endpoint_guid;
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);

        assert_eq!(
            token.transport_selection(&remote_guid),
            Some(TransportSelection::Udp),
            "a different host_id must fall back to Udp under Prefer"
        );
    }

    /// (c) A Reliable local writer resolves to `Udp` under `Prefer` even
    /// when the remote reader is BestEffort and advertises a valid same-host
    /// SHM hint -- SHM never carries Reliable traffic.
    #[test]
    fn shm_prefer_reliable_local_endpoint_resolves_to_udp() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let reliable_qos = QoS {
            reliability: Reliability::Reliable,
            data_representation: vec![0x0002],
            ..QoS::best_effort()
        };
        let token = reg.register_writer_full(
            "shm-topic".into(),
            reliable_qos,
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            None,
            None,
            ShmPolicy::Prefer,
            None,
        );

        let hint = crate::transport::shm::format_shm_user_data();
        let remote = remote_with_shm_capability(
            EndpointKind::Reader,
            Reliability::BestEffort,
            Some(hint),
            0x04,
        );
        let remote_guid = remote.endpoint_guid;
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);

        assert_eq!(
            token.transport_selection(&remote_guid),
            Some(TransportSelection::Udp),
            "a Reliable local endpoint must never select Shm"
        );
    }

    /// Pins today's end-to-end truth (2026-09): the wire SEDP encoder does
    /// not yet serialize PID_USER_DATA, so every real remote arrives with
    /// `shm_capability == None`. Under `Prefer` that must resolve to `Udp`. This
    /// test must keep passing unmodified once the emitter is wired -- it
    /// documents the `None` case, not the absence of the hint.
    #[test]
    fn shm_prefer_no_capability_resolves_to_udp() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let token = reg.register_writer_full(
            "shm-topic".into(),
            shm_topic_qos(),
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            None,
            None,
            ShmPolicy::Prefer,
            None,
        );

        let remote =
            remote_with_shm_capability(EndpointKind::Reader, Reliability::BestEffort, None, 0x04);
        let remote_guid = remote.endpoint_guid;
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);

        assert_eq!(
            token.transport_selection(&remote_guid),
            Some(TransportSelection::Udp),
            "no shm_capability (today's real-world case) must resolve to Udp"
        );
    }

    /// (d) The verdict is resolved exactly once, by construction: replaying
    /// the same SEDP announcement (as `handle_sedp` does for a retransmitted
    /// or duplicate PDU) must not change the stored verdict nor double-count
    /// the match. `dispatch_match` gates the `resolve_transport` call behind
    /// a `contains_key` check on `matched_remotes`, so on replay the branch
    /// that calls `resolve_transport` is never reached again -- this test
    /// observes that outcome; the "exactly once" guarantee itself is a
    /// structural property of `dispatch_match`, not something a black-box
    /// call-count assertion could prove on its own.
    #[test]
    fn shm_verdict_is_stored_not_recomputed_on_sedp_replay() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let token = reg.register_writer_full(
            "shm-topic".into(),
            shm_topic_qos(),
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            None,
            None,
            ShmPolicy::Prefer,
            None,
        );

        let hint = crate::transport::shm::format_shm_user_data();
        let remote = remote_with_shm_capability(
            EndpointKind::Reader,
            Reliability::BestEffort,
            Some(hint),
            0x04,
        );
        let remote_guid = remote.endpoint_guid;

        fsm.insert_remote_endpoint_for_test(remote.clone().clone());
        reg.on_endpoint_discovered(remote.clone());
        let first = token.transport_selection(&remote_guid);
        assert!(first.is_some(), "first match must store a verdict");
        assert_eq!(token.current_match_count(), 1);

        // Replay: same remote endpoint discovered again.
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);
        let second = token.transport_selection(&remote_guid);
        assert_eq!(first, second, "replay must not alter the stored verdict");
        assert_eq!(
            token.current_match_count(),
            1,
            "replay must not double-count the match"
        );
    }

    /// (4) `ShmPolicy::Require` refuses the match outright when the pairing
    /// cannot satisfy it (here: no shm_capability at all -> `NoUserData`). The
    /// remote must NOT be treated as matched: no `on_publication_matched`
    /// fire, no entry in `matched_remotes`, no stored `TransportSelection`.
    #[test]
    fn shm_require_refuses_match_instead_of_matching_anyway() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let token = reg.register_writer_full(
            "shm-topic".into(),
            shm_topic_qos(),
            &SIMPLE_DESC,
            None,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            None,
            None,
            ShmPolicy::Require,
            None,
        );

        let remote =
            remote_with_shm_capability(EndpointKind::Reader, Reliability::BestEffort, None, 0x04);
        let remote_guid = remote.endpoint_guid;
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote);

        assert_eq!(
            match_count.load(Ordering::Relaxed),
            0,
            "Require must refuse the match, not fire on_publication_matched anyway"
        );
        assert_eq!(
            token.current_match_count(),
            0,
            "refused pairing must not count as matched"
        );
        assert_eq!(
            token.transport_selection(&remote_guid),
            None,
            "a refused pairing must not store a verdict"
        );
    }

    /// The per-peer hook sees each remote reader that matches, with its
    /// reliability, and each one that leaves - before the counting callback.
    /// A writer keeps a ReaderProxy per RELIABLE reader on it (RTPS 2.5
    /// 8.4.7.4); without the kind, a best-effort reader, which never
    /// acknowledges, would hold the writer's history back for good.
    #[test]
    fn the_peer_hook_is_told_each_reader_its_reliability_and_its_departure() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let seen: Arc<Mutex<Vec<PeerChange>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let _token = reg.register_writer_with_peers(
            "topic".into(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::reliable()
            },
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            Some(Box::new(move |change| {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(change);
            })),
            None,
            None,
            ShmPolicy::default(),
            None,
        );

        let mut reliable_reader = remote_endpoint(EndpointKind::Reader);
        reliable_reader.qos.reliability = Reliability::Reliable;
        let mut best_effort_reader = remote_endpoint(EndpointKind::Reader);
        best_effort_reader.endpoint_guid = GUID::from_bytes([
            0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 0, 0, 0x01, 0x04,
        ]);

        fsm.insert_remote_endpoint_for_test(reliable_reader.clone().clone());
        reg.on_endpoint_discovered(reliable_reader.clone());
        fsm.insert_remote_endpoint_for_test(best_effort_reader.clone().clone());
        reg.on_endpoint_discovered(best_effort_reader.clone());
        reg.on_endpoint_removed(reliable_reader.clone());

        let seen = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            seen,
            vec![
                PeerChange::Matched {
                    guid: reliable_reader.endpoint_guid,
                    reliable: true,
                    volatile: reliable_reader.qos.durability == Durability::Volatile,
                },
                PeerChange::Matched {
                    guid: best_effort_reader.endpoint_guid,
                    reliable: false,
                    volatile: best_effort_reader.qos.durability == Durability::Volatile,
                },
                PeerChange::Unmatched {
                    guid: reliable_reader.endpoint_guid,
                },
            ]
        );
    }

    /// A writer takes its ReaderProxy for a reader at discovery, before the
    /// match surfaces (RTPS 2.5 8.4.7.4), as a reader takes its WriterProxy,
    /// and drops it when the reader goes although the match never surfaced:
    /// a proxy left behind would hold the writer's history back for good.
    #[test]
    fn a_writer_takes_its_reader_proxy_at_discovery_and_drops_it_with_the_reader() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let seen: Arc<Mutex<Vec<PeerChange>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let _token = reg.register_writer_with_peers(
            "topic".into(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::reliable()
            },
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            Some(Box::new(move |change| {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(change);
            })),
            None,
            None,
            ShmPolicy::default(),
            None,
        );

        let mut reader = remote_endpoint(EndpointKind::Reader);
        reader.qos.reliability = Reliability::Reliable;
        fsm.insert_remote_endpoint_for_test(reader.clone());
        reg.on_endpoint_discovered_incompat_only(reader.clone());
        reg.on_endpoint_removed(reader.clone());

        assert_eq!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            vec![
                PeerChange::Matched {
                    guid: reader.endpoint_guid,
                    reliable: true,
                    volatile: reader.qos.durability == Durability::Volatile,
                },
                PeerChange::Unmatched {
                    guid: reader.endpoint_guid,
                },
            ],
            "paired at discovery, retired with the reader"
        );
    }

    /// The registration catch-up pairs the same way: a writer created while
    /// a known reader's match is still deferred (inside probation) takes its
    /// ReaderProxy for it at once.
    #[test]
    fn a_writer_registered_inside_probation_takes_a_proxy_for_a_known_reader() {
        use crate::protocol::discovery::{SedpData, SpdpData};
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let remote_prefix = [0x0B; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let reader = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x04]);
        fsm.handle_spdp(SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        fsm.handle_sedp(SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: reader,
            qos_hash: 1,
            qos: Some(QoS {
                data_representation: vec![0x0002],
                ..QoS::reliable()
            }),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        assert!(!fsm.is_probation_done(), "fixture: inside probation");
        assert_eq!(fsm.find_readers_for_topic("topic").len(), 1, "reader known");

        let seen: Arc<Mutex<Vec<PeerChange>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let token = reg.register_writer_with_peers(
            "topic".into(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::reliable()
            },
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            Some(Box::new(move |change| {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(change);
            })),
            None,
            None,
            ShmPolicy::default(),
            None,
        );

        assert_eq!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            vec![PeerChange::Matched {
                guid: reader,
                reliable: true,
                volatile: true,
            }],
            "the catch-up pairs the writer with the deferred reader"
        );
        assert_eq!(token.current_match_count(), 0, "the match itself waits");
    }

    fn reader_with_peer_hook(
        reg: &Arc<MatchNotificationRegistry>,
        shm_policy: ShmPolicy,
    ) -> (MatchToken, Arc<Mutex<Vec<PeerChange>>>) {
        let seen: Arc<Mutex<Vec<PeerChange>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let token = reg.register_reader_with_lifespan(
            "topic".into(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::best_effort()
            },
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            Some(Box::new(move |change| {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(change);
            })),
            None,
            None,
            Arc::new(AtomicU64::new(0)),
            shm_policy,
        );
        (token, seen)
    }

    /// A reader takes its WriterProxy at discovery only for a pairing that
    /// can match: one `ShmPolicy::Require` refuses never matches, and gets no
    /// proxy either.
    #[test]
    fn a_reader_takes_no_proxy_for_a_pairing_it_would_refuse() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let (_admitted, admitted_seen) = reader_with_peer_hook(&reg, ShmPolicy::default());
        let (_refused, refused_seen) = reader_with_peer_hook(&reg, ShmPolicy::Require);

        let writer = remote_endpoint(EndpointKind::Writer);
        fsm.insert_remote_endpoint_for_test(writer.clone());
        reg.on_endpoint_discovered_incompat_only(writer);

        assert_eq!(
            admitted_seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            1,
            "a pairing that can match is tracked at discovery"
        );
        assert!(
            refused_seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "a pairing ShmPolicy::Require refuses is not"
        );
    }

    /// DDS Security v1.1 Sec.9.3.4: an endpoint of a participant whose
    /// handshake has not completed is not surfaced; a reader takes no
    /// WriterProxy for it at discovery either.
    #[cfg(feature = "security")]
    #[test]
    fn a_reader_takes_no_proxy_for_a_writer_of_an_unauthenticated_peer() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let cert = crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec();
        let key = crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec();
        let local = GUID::new([0xFF; 12], [0x00, 0x00, 0x01, 0xC1]);
        let writer = remote_endpoint(EndpointKind::Writer);
        let remote = GUID::new(writer.endpoint_guid.prefix, [0x00, 0x00, 0x01, 0xC1]);
        let machine = Arc::new(crate::security::handshake::HandshakeMachine::new());
        let _ = machine
            .start(local, remote, &cert, &key)
            .expect("handshake start");
        assert!(machine.has_session(&remote), "a session is pending");
        let mut fsm = DiscoveryFsm::new(local, 30_000);
        fsm.set_handshake_machine(Arc::clone(&machine), cert, key);
        let fsm = Arc::new(fsm);
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let (_token, seen) = reader_with_peer_hook(&reg, ShmPolicy::default());

        reg.on_endpoint_discovered_incompat_only(writer);

        assert!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "no proxy before the peer authenticates"
        );
    }

    /// The registration catch-up asks the same question: a reader created
    /// after an unauthenticated peer's writer was discovered pairs with it
    /// neither as a proxy nor as a match.
    #[cfg(feature = "security")]
    #[test]
    fn a_reader_registered_later_takes_no_proxy_for_an_unauthenticated_peer() {
        use crate::protocol::discovery::{SedpData, SpdpData};
        let cert = crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec();
        let key = crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec();
        let local = GUID::new([0xFF; 12], [0x00, 0x00, 0x01, 0xC1]);
        let remote_prefix = [0x0A; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let machine = Arc::new(crate::security::handshake::HandshakeMachine::new());
        let _ = machine
            .start(local, remote, &cert, &key)
            .expect("handshake start");
        assert!(machine.has_session(&remote), "a session is pending");
        let mut fsm = DiscoveryFsm::new(local, 30_000);
        fsm.set_handshake_machine(Arc::clone(&machine), cert, key);
        let fsm = Arc::new(fsm);
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let spdp = || SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        fsm.handle_spdp(spdp());
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x02]),
            qos_hash: 1,
            qos: Some(QoS {
                data_representation: vec![0x0002],
                ..QoS::best_effort()
            }),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        assert_eq!(fsm.find_writers_for_topic("topic").len(), 1, "writer known");

        let (_token, seen) = reader_with_peer_hook(&reg, ShmPolicy::default());

        assert!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "no proxy before the peer authenticates"
        );
    }

    fn reliable_xcdr2() -> QoS {
        QoS {
            data_representation: vec![0x0002],
            ..QoS::reliable()
        }
    }

    /// A user listener may create an endpoint from inside
    /// `on_publication_matched`, here surfaced by a late liveness mark (the
    /// peer confirmed past the probation boundary). The dispatch runs with no
    /// registry lock held: holding the entries read lock while the
    /// listener's registration takes the write lock, on the same thread,
    /// would never return.
    #[test]
    fn a_listener_that_creates_an_endpoint_inside_a_late_match_does_not_deadlock() {
        use crate::protocol::discovery::{SedpData, SpdpData};
        use std::time::{Duration, Instant};
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        fsm.register_listener(reg.clone());
        let remote_prefix = [0x0C; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        std::thread::sleep(Duration::from_millis(110));
        fsm.handle_sedp(SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x04]),
            qos_hash: 1,
            qos: Some(reliable_xcdr2()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        let first_mark = Instant::now();

        let created: Arc<Mutex<Vec<MatchToken>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&created);
        let registry = Arc::downgrade(&reg);
        let token = reg.register_writer_with_peers(
            "topic".into(),
            reliable_xcdr2(),
            &SIMPLE_DESC,
            None,
            move |_, _, current, _, _| {
                let Some(reg) = registry.upgrade() else {
                    return;
                };
                if current > 0 {
                    let other = reg.register_writer_with_peers(
                        "created_in_the_listener".into(),
                        reliable_xcdr2(),
                        &SIMPLE_DESC,
                        None,
                        |_, _, _, _, _| {},
                        None,
                        None,
                        None,
                        ShmPolicy::default(),
                        None,
                    );
                    sink.lock().unwrap_or_else(|e| e.into_inner()).push(other);
                }
            },
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );

        let uptime = fsm.uptime();
        if uptime < Duration::from_millis(260) {
            std::thread::sleep(Duration::from_millis(260) - uptime);
        }
        fsm.maybe_complete_probation();
        assert_eq!(token.current_match_count(), 0, "fixture: match deferred");
        let mark_due = first_mark + Duration::from_millis(110);
        if let Some(left) = mark_due.checked_duration_since(Instant::now()) {
            std::thread::sleep(left);
        }

        let (done, finished) = std::sync::mpsc::channel();
        let marker = Arc::clone(&fsm);
        std::thread::spawn(move || {
            marker.touch_participant_by_prefix(&remote_prefix);
            let _ = done.send(());
        });
        if finished.recv_timeout(Duration::from_secs(5)).is_err() {
            // The thread is stuck holding the registry lock: dropping the
            // token (unregister) would hang this thread too, and the test
            // would never report.
            std::mem::forget(token);
            panic!("the late match never returned: the dispatch deadlocked");
        }
        assert_eq!(token.current_match_count(), 1);
        assert_eq!(
            created.lock().unwrap_or_else(|e| e.into_inner()).len(),
            1,
            "the listener created its endpoint"
        );
    }

    /// Callbacks run outside the registry lock, but none of an entry fires
    /// once its `unregister` has returned: `unregister` waits for a callback
    /// of that entry already running on another thread, and a dispatch that
    /// took its snapshot before an entry was unregistered skips that entry.
    #[test]
    fn unregister_waits_for_a_callback_of_its_entry_in_flight() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        use std::sync::mpsc;
        use std::time::Duration;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let (entered, in_callback) = mpsc::channel::<()>();
        let (release, released) = mpsc::channel::<()>();
        let entered = Mutex::new(entered);
        let released = Mutex::new(released);
        let token = reg.register_writer_with_peers(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None,
            move |_, _, _, _, _| {
                let _ = entered.lock().unwrap_or_else(|e| e.into_inner()).send(());
                let _ = released
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .recv_timeout(Duration::from_secs(5));
            },
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        // Registered after the first one: the dispatch reaches it second.
        let late_fired = Arc::new(AtomicU32::new(0));
        let late_counter = Arc::clone(&late_fired);
        let late = reg.register_writer_with_peers(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None,
            move |_, _, _, _, _| {
                late_counter.fetch_add(1, Ordering::Relaxed);
            },
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        let reader = remote_endpoint(EndpointKind::Reader);
        fsm.insert_remote_endpoint_for_test(reader.clone());
        let dispatcher = {
            let reg = Arc::clone(&reg);
            std::thread::spawn(move || reg.on_endpoint_discovered(reader))
        };
        in_callback
            .recv_timeout(Duration::from_secs(5))
            .expect("the match callback runs");
        // Not running a callback: its unregister returns at once, and the
        // dispatch in flight must not reach it afterwards.
        drop(late);

        let (dropped, unregistered) = mpsc::channel::<()>();
        let dropper = std::thread::spawn(move || {
            drop(token);
            let _ = dropped.send(());
        });
        assert!(
            unregistered
                .recv_timeout(Duration::from_millis(200))
                .is_err(),
            "unregister returned while a callback of its entry was running"
        );
        let _ = release.send(());
        unregistered
            .recv_timeout(Duration::from_secs(5))
            .expect("unregister returns once the callback has");
        dispatcher.join().expect("dispatcher");
        dropper.join().expect("dropper");
        assert_eq!(
            late_fired.load(Ordering::Relaxed),
            0,
            "no callback of an entry after its unregister returned"
        );
    }

    /// A local writer registered after the probation boundary, for a reader
    /// whose participant (heard during the probation, its one mark earned
    /// before the boundary) may not surface its matches yet: the catch-up
    /// defers the match, nothing is matched at registration, and the
    /// participant's next mark (control traffic, after the boundary) surfaces
    /// it. The catch-up must queue the deferred pairing: skipping it would
    /// leave the replay nothing to find, and the reader would never be
    /// matched.
    #[test]
    fn a_writer_registered_after_the_boundary_is_matched_once_its_reader_is_confirmed() {
        use crate::protocol::discovery::{SedpData, SpdpData};
        use std::time::{Duration, Instant};
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        fsm.register_listener(reg.clone());

        let remote_prefix = [0x0D; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        std::thread::sleep(Duration::from_millis(110));
        fsm.handle_sedp(SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x04]),
            qos_hash: 1,
            qos: Some(reliable_xcdr2()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        let first_mark = Instant::now();
        assert!(
            fsm.uptime() < Duration::from_millis(250),
            "fixture: its one mark lands before the boundary"
        );
        let uptime = fsm.uptime();
        if uptime < Duration::from_millis(260) {
            std::thread::sleep(Duration::from_millis(260) - uptime);
        }
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done(), "fixture: past the boundary");

        let token = reg.register_writer_with_peers(
            "topic".into(),
            reliable_xcdr2(),
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        assert_eq!(
            token.current_match_count(),
            0,
            "the catch-up defers the match of a participant that may not surface"
        );

        let mark_due = first_mark + Duration::from_millis(110);
        if let Some(left) = mark_due.checked_duration_since(Instant::now()) {
            std::thread::sleep(left);
        }
        fsm.touch_participant_by_prefix(&remote_prefix);
        assert_eq!(token.current_match_count(), 1, "the reader is matched");
    }

    /// The registration catch-up applies the rule the live path applies: a
    /// participant first heard after the boundary surfaces its matches from
    /// its first announcement, so a local writer registered after its
    /// reader's SEDP is matched at once. The catch-up does not require a
    /// confirmed participant (two SPDPs or two marks) where the live path
    /// does not, so the writer does not wait for the peer's control traffic.
    /// A one-member FINAL struct `T { x }` with `x` of type `x_type`.
    fn one_member_struct(x_type: crate::xtypes::TypeIdentifier) -> CompleteTypeObject {
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, MemberFlag, StructTypeFlag,
        };
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("T"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: x_type,
                },
                detail: CompleteMemberDetail::new("x"),
            }],
        })
    }

    /// A reader entry's verdicts leave the data-plane gate with it: the gate
    /// is per (writer, reader) pair, and a pair whose reader is gone gates
    /// nothing - nor does it outlive the reader to gate a later one.
    #[test]
    fn a_reader_entry_leaving_takes_its_type_verdicts_with_it() {
        use crate::protocol::discovery::{SedpData, SpdpData};
        use crate::xtypes::TypeIdentifier;
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        fsm.set_match_registry(reg.clone());
        let remote_prefix = [0x0E; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let writer = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x02]);
        fsm.handle_sedp(SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: writer,
            qos_hash: 1,
            qos: Some(reliable_xcdr2()),
            type_object: Some(one_member_struct(TypeIdentifier::TK_FLOAT64)),
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        let token = reg.register_reader_with_lifespan(
            "topic".into(),
            reliable_xcdr2(),
            &SIMPLE_DESC,
            Some(one_member_struct(TypeIdentifier::TK_INT32)),
            |_, _, _, _, _| {},
            None,
            None,
            None,
            Arc::new(AtomicU64::new(u64::MAX)),
            ShmPolicy::default(),
        );
        let entry = token.id();
        assert!(
            reg.is_writer_refused_by(&writer.as_bytes(), entry),
            "fixture: the reader refuses the float64 writer"
        );
        drop(token);
        assert!(
            !reg.is_writer_refused_by_any(&writer.as_bytes()),
            "no reader left to refuse it"
        );
    }

    /// A writer announced before the match registry is installed is judged
    /// on its type at the pair verdict, as one announced after it would be:
    /// the verdict of each pair reads the writer's type from discovery and
    /// its QoS from the installation's judgment. A reader registered later
    /// with an incompatible type refuses it, and one with a compatible type
    /// accepts it.
    #[test]
    fn a_writer_announced_before_the_registry_is_installed_is_judged_on_its_type() {
        use crate::protocol::discovery::{SedpData, SpdpData};
        use crate::xtypes::TypeIdentifier;
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let remote_prefix = [0x0E; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let writer = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x02]);
        fsm.handle_sedp(SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: writer,
            qos_hash: 1,
            qos: Some(reliable_xcdr2()),
            type_object: Some(one_member_struct(TypeIdentifier::TK_FLOAT64)),
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        fsm.set_match_registry(reg.clone());
        fsm.register_listener(reg.clone());
        let register = |type_object| {
            reg.register_reader_with_lifespan(
                "topic".into(),
                reliable_xcdr2(),
                &SIMPLE_DESC,
                Some(type_object),
                |_, _, _, _, _| {},
                None,
                None,
                None,
                Arc::new(AtomicU64::new(u64::MAX)),
                ShmPolicy::default(),
            )
        };
        let refusing = register(one_member_struct(TypeIdentifier::TK_INT32));
        assert_eq!(
            reg.writer_pair_verdict(&writer.as_bytes(), refusing.id(), "topic"),
            Some(false),
            "an int32 reader refuses the float64 writer announced before the install"
        );
        let accepting = register(one_member_struct(TypeIdentifier::TK_FLOAT64));
        assert_eq!(
            reg.writer_pair_verdict(&writer.as_bytes(), accepting.id(), "topic"),
            Some(true),
            "a reader of the writer's own type accepts it"
        );
    }

    /// The match path judges a remote on what discovery knows when it
    /// judges; a TypeLookup answer can resolve the remote's type between that
    /// verdict and the match being applied, and `rejudge_remote_types` then
    /// finds no match to withdraw. The match applied on the copy older than
    /// the type is judged again once applied, on the type known now, and
    /// undone when the verdict refuses it.
    #[test]
    fn a_match_applied_on_a_copy_older_than_the_learned_type_is_undone() {
        use crate::protocol::discovery::{SedpData, SpdpData};
        use crate::xtypes::TypeIdentifier;
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        fsm.set_match_registry(reg.clone());
        let token = reg.register_writer_full(
            "topic".into(),
            reliable_xcdr2(),
            &SIMPLE_DESC,
            Some(one_member_struct(TypeIdentifier::TK_INT32)),
            |_, _, _, _, _| {},
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        let remote_prefix = [0x0E; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let reader = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x07]);
        fsm.handle_sedp(SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: reader,
            qos_hash: 1,
            qos: Some(reliable_xcdr2()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        // The copy a match decision was made on, before the type was known.
        let copy = fsm
            .current_endpoint("topic", &reader)
            .expect("the remote reader is known");
        assert!(copy.type_object.is_none(), "fixture: type unknown");
        fsm.update_type_object_for_type(
            SIMPLE_DESC.type_name,
            one_member_struct(TypeIdentifier::TK_FLOAT64),
        );
        assert_eq!(token.current_match_count(), 0, "fixture: not matched");

        let entry = reg.entry(token.id()).expect("the writer's entry");
        reg.dispatch_match(&copy, &entry);
        assert_eq!(
            token.current_match_count(),
            0,
            "a float64 x is not assignable from an int32 x: the match is undone"
        );
    }

    #[test]
    fn the_catch_up_matches_a_participant_first_heard_after_the_boundary_at_once() {
        use crate::protocol::discovery::{SedpData, SpdpData};
        use std::time::Duration;
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        fsm.register_listener(reg.clone());
        let uptime = fsm.uptime();
        if uptime < Duration::from_millis(260) {
            std::thread::sleep(Duration::from_millis(260) - uptime);
        }
        fsm.maybe_complete_probation();
        let remote_prefix = [0x0E; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        fsm.handle_spdp(SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        fsm.handle_sedp(SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x04]),
            qos_hash: 1,
            qos: Some(reliable_xcdr2()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        let token = reg.register_writer_with_peers(
            "topic".into(),
            reliable_xcdr2(),
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        assert!(!fsm.is_participant_confirmed(&remote_prefix), "fixture");
        assert_eq!(token.current_match_count(), 1, "matched at registration");
    }

    /// A writer registered with a reliable peer hook on "topic".
    fn writer_with_peer_hook(
        reg: &Arc<MatchNotificationRegistry>,
        shm_policy: ShmPolicy,
    ) -> (MatchToken, Arc<Mutex<Vec<PeerChange>>>) {
        let seen: Arc<Mutex<Vec<PeerChange>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let token = reg.register_writer_with_peers(
            "topic".into(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::best_effort()
            },
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            Some(Box::new(move |change| {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(change);
            })),
            None,
            None,
            shm_policy,
            None,
        );
        (token, seen)
    }

    /// A writer takes its ReaderProxy at discovery only for a pairing that
    /// can match: one `ShmPolicy::Require` refuses never matches, and gets no
    /// proxy that would hold its history back.
    #[test]
    fn a_writer_takes_no_proxy_for_a_pairing_it_would_refuse() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let (_admitted, admitted_seen) = writer_with_peer_hook(&reg, ShmPolicy::default());
        let (_refused, refused_seen) = writer_with_peer_hook(&reg, ShmPolicy::Require);

        let reader = remote_endpoint(EndpointKind::Reader);
        fsm.insert_remote_endpoint_for_test(reader.clone());
        reg.on_endpoint_discovered_incompat_only(reader);

        assert_eq!(
            admitted_seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            1,
            "fixture: a pairing that can match is tracked at discovery"
        );
        assert!(
            refused_seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "a pairing ShmPolicy::Require refuses is not"
        );
    }

    /// A notification can reach the registry after its endpoint was removed
    /// (the drain or a replay took it out of the deferred list just before
    /// the removal): the pairing it makes is undone, so no proxy outlives
    /// the endpoint (a writer's proxy would hold its history back for a
    /// reader that is gone).
    #[test]
    fn a_pairing_for_an_endpoint_removed_meanwhile_is_undone() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let (_writer, writer_seen) = writer_with_peer_hook(&reg, ShmPolicy::default());
        let (_reader, reader_seen) = reader_with_peer_hook(&reg, ShmPolicy::default());

        // Neither is in discovery's topic registry any more.
        let gone_reader = remote_endpoint(EndpointKind::Reader);
        let gone_writer = remote_endpoint(EndpointKind::Writer);
        reg.on_endpoint_discovered_incompat_only(gone_reader.clone());
        reg.on_endpoint_discovered_incompat_only(gone_writer.clone());

        for (seen, guid) in [
            (writer_seen, gone_reader.endpoint_guid),
            (reader_seen, gone_writer.endpoint_guid),
        ] {
            assert_eq!(
                seen.lock().unwrap_or_else(|e| e.into_inner()).last(),
                Some(&PeerChange::Unmatched { guid }),
                "the pairing is undone"
            );
        }
    }

    /// A replay can drain an endpoint, and the endpoint be removed (a dispose
    /// or a lease expiry, on another thread) before the replay dispatches its
    /// match: the removal finds nothing matched to undo. The match applied
    /// after it is undone, so the writer's ReaderProxy and its match count do
    /// not outlive the reader (otherwise current_count would stay 1 and the
    /// proxy would hold a KEEP_ALL writer's history back for good).
    #[test]
    fn a_match_dispatched_after_its_endpoint_was_removed_is_undone() {
        use crate::protocol::discovery::{SedpData, SpdpData};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        fsm.register_listener(reg.clone());
        let remote_prefix = [0x0F; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let reader_guid = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x04]);
        fsm.handle_spdp(SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        std::thread::sleep(Duration::from_millis(110));
        fsm.handle_sedp(SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: reader_guid,
            qos_hash: 1,
            qos: Some(reliable_xcdr2()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        let first_mark = Instant::now();
        let uptime = fsm.uptime();
        if uptime < Duration::from_millis(260) {
            std::thread::sleep(Duration::from_millis(260) - uptime);
        }
        fsm.maybe_complete_probation();

        let peers: Arc<Mutex<Vec<PeerChange>>> = Arc::new(Mutex::new(Vec::new()));
        let currents: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let (peer_sink, current_sink) = (Arc::clone(&peers), Arc::clone(&currents));
        let token = reg.register_writer_with_peers(
            "topic".into(),
            reliable_xcdr2(),
            &SIMPLE_DESC,
            None,
            move |_, _, current, _, _| {
                current_sink
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(current);
            },
            Some(Box::new(move |change| {
                peer_sink
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(change);
            })),
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        assert_eq!(token.current_match_count(), 0, "fixture: match deferred");

        let (parked, is_parked) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let (parked, released) = (Mutex::new(parked), Mutex::new(released));
        fsm.set_replay_parked_hook(Box::new(move || {
            let _ = parked.lock().unwrap_or_else(|e| e.into_inner()).send(());
            let _ = released
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv_timeout(Duration::from_secs(5));
        }));
        let mark_due = first_mark + Duration::from_millis(110);
        if let Some(left) = mark_due.checked_duration_since(Instant::now()) {
            std::thread::sleep(left);
        }
        let marker = {
            let fsm = Arc::clone(&fsm);
            std::thread::spawn(move || fsm.touch_participant_by_prefix(&remote_prefix))
        };
        is_parked
            .recv_timeout(Duration::from_secs(5))
            .expect("the replay drained the endpoint and parked");
        fsm.remove_participant(remote);
        let _ = release.send(());
        marker.join().expect("marker thread");

        assert_eq!(
            token.current_match_count(),
            0,
            "no match outlives the reader"
        );
        assert_eq!(
            peers.lock().unwrap_or_else(|e| e.into_inner()).last(),
            Some(&PeerChange::Unmatched { guid: reader_guid }),
            "the ReaderProxy goes with it"
        );
        assert_eq!(
            currents.lock().unwrap_or_else(|e| e.into_inner()).last(),
            Some(&0),
            "the listener is told the match ended"
        );
    }

    /// An SPDP announcement of the remote participant `remote`.
    fn remote_spdp(remote: GUID) -> crate::protocol::discovery::SpdpData {
        crate::protocol::discovery::SpdpData {
            participant_guid: remote,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        }
    }

    /// An SEDP announcement of the remote reader `reader` on "topic".
    fn remote_reader_sedp(
        remote: GUID,
        reader: GUID,
        qos: QoS,
    ) -> crate::protocol::discovery::SedpData {
        crate::protocol::discovery::SedpData {
            topic_name: "topic".to_string(),
            type_name: SIMPLE_DESC.type_name.to_string(),
            participant_guid: remote,
            endpoint_guid: reader,
            qos_hash: 1,
            qos: Some(qos),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// The replay drains a reader's deferred match, and while that match is
    /// in flight the reader is removed and announced again under the same
    /// GUID, now asking for TRANSIENT_LOCAL from a VOLATILE writer: the new
    /// record does not match. The match the replay then applies was decided
    /// on the old record, and is undone. The undo must not ask only whether
    /// discovery knows the GUID (it does: the new record), or the writer
    /// would stay matched with a reader that does not match it.
    #[test]
    fn a_match_in_flight_for_a_record_replaced_meanwhile_is_undone() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        fsm.register_listener(reg.clone());
        let remote_prefix = [0x1E; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let reader_guid = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x04]);
        fsm.handle_spdp(remote_spdp(remote));
        std::thread::sleep(Duration::from_millis(110));
        fsm.handle_sedp(remote_reader_sedp(remote, reader_guid, reliable_xcdr2()));
        let first_mark = Instant::now();
        let uptime = fsm.uptime();
        if uptime < Duration::from_millis(260) {
            std::thread::sleep(Duration::from_millis(260) - uptime);
        }
        fsm.maybe_complete_probation();

        let currents: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let current_sink = Arc::clone(&currents);
        let token = reg.register_writer_with_peers(
            "topic".into(),
            reliable_xcdr2(),
            &SIMPLE_DESC,
            None,
            move |_, _, current, _, _| {
                current_sink
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(current);
            },
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        assert_eq!(token.current_match_count(), 0, "fixture: match deferred");

        let (parked, is_parked) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let (parked, released) = (Mutex::new(parked), Mutex::new(released));
        fsm.set_replay_parked_hook(Box::new(move || {
            let _ = parked.lock().unwrap_or_else(|e| e.into_inner()).send(());
            let _ = released
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv_timeout(Duration::from_secs(5));
        }));
        let mark_due = first_mark + Duration::from_millis(110);
        if let Some(left) = mark_due.checked_duration_since(Instant::now()) {
            std::thread::sleep(left);
        }
        let marker = {
            let fsm = Arc::clone(&fsm);
            std::thread::spawn(move || fsm.touch_participant_by_prefix(&remote_prefix))
        };
        is_parked
            .recv_timeout(Duration::from_secs(5))
            .expect("the replay drained the reader and parked");
        // Meanwhile: removed, and announced again under the same GUID.
        fsm.remove_participant(remote);
        fsm.handle_spdp(remote_spdp(remote));
        fsm.handle_sedp(remote_reader_sedp(
            remote,
            reader_guid,
            reliable_xcdr2().transient_local(),
        ));
        let record = fsm
            .current_endpoint("topic", &reader_guid)
            .expect("fixture: the new record is known");
        assert_eq!(
            record.qos.durability,
            crate::dds::qos::Durability::TransientLocal,
            "fixture: discovery holds the new record"
        );
        let _ = release.send(());
        marker.join().expect("marker thread");

        assert_eq!(
            token.current_match_count(),
            0,
            "the writer is not matched with a record that does not match it"
        );
        assert_eq!(
            currents
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .last()
                .copied()
                .unwrap_or(0),
            0,
            "and its listener was told so"
        );
    }

    /// The removal of a reader reaches the match registry after the reader
    /// was announced again under the same GUID and matched again (a removal
    /// notified late, behind the new record's match): it ends nothing, the
    /// match is the new record's. Ending the match by GUID would leave the
    /// writer unmatched from a reader that is there.
    #[test]
    fn a_late_removal_of_an_older_record_ends_nothing() {
        use std::time::Duration;
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        fsm.register_listener(reg.clone());
        // A participant first heard past the probation is trusted from that
        // announcement.
        if let Some(rest) = Duration::from_millis(300).checked_sub(fsm.uptime()) {
            std::thread::sleep(rest);
        }
        fsm.maybe_complete_probation();
        let remote_prefix = [0x1F; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let reader_guid = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x04]);
        fsm.handle_spdp(remote_spdp(remote));
        let token = reg.register_writer(
            "topic".into(),
            reliable_xcdr2(),
            &SIMPLE_DESC,
            |_, _, _, _, _| {},
        );
        fsm.handle_sedp(remote_reader_sedp(remote, reader_guid, reliable_xcdr2()));
        assert_eq!(token.current_match_count(), 1, "fixture: matched");
        let old = fsm
            .current_endpoint("topic", &reader_guid)
            .expect("fixture: known");

        assert!(fsm.remove_remote_endpoint(reader_guid), "fixture: removed");
        assert_eq!(token.current_match_count(), 0, "fixture: unmatched");
        fsm.handle_sedp(remote_reader_sedp(remote, reader_guid, reliable_xcdr2()));
        assert_eq!(token.current_match_count(), 1, "fixture: matched again");

        reg.on_endpoint_removed(old);
        assert_eq!(
            token.current_match_count(),
            1,
            "the old record's removal does not end the new record's match"
        );
    }

    /// A match held for an older record of a GUID, whose removal has not
    /// reached the entry yet when the newer record's match does, gives way
    /// to the newer one; the older record's removal, when it comes, ends
    /// nothing. The newer record's match must not be dropped as a repeat
    /// (the GUID was matched) with the older record's removal then ending
    /// the GUID's match, which would leave the writer unmatched from a reader
    /// that is there. The registry is not the discovery's listener here, so each
    /// notification is delivered when the test says.
    #[test]
    fn a_match_held_for_an_older_record_gives_way_to_the_newer_one() {
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        let remote_prefix = [0x2E; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let reader_guid = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x04]);
        fsm.handle_spdp(remote_spdp(remote));
        let changes: Arc<Mutex<Vec<(u32, i32)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&changes);
        let token = reg.register_writer(
            "topic".into(),
            reliable_xcdr2(),
            &SIMPLE_DESC,
            move |_, _, current, current_change, _| {
                sink.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((current, current_change));
            },
        );
        let record = |fsm: &DiscoveryFsm| {
            fsm.current_endpoint("topic", &reader_guid)
                .expect("fixture: the reader is known")
        };

        fsm.handle_sedp(remote_reader_sedp(remote, reader_guid, reliable_xcdr2()));
        let old = record(&fsm);
        reg.on_endpoint_discovered(old.clone());
        assert_eq!(token.current_match_count(), 1, "fixture: matched");

        // Removed and announced again; the removal is not delivered yet.
        assert!(fsm.remove_remote_endpoint(reader_guid), "fixture: removed");
        fsm.handle_sedp(remote_reader_sedp(remote, reader_guid, reliable_xcdr2()));
        reg.on_endpoint_discovered(record(&fsm));
        reg.on_endpoint_removed(old);

        assert_eq!(
            token.current_match_count(),
            1,
            "the newer record is matched, and the older one's removal ends nothing"
        );
        assert_eq!(
            changes.lock().unwrap_or_else(|e| e.into_inner()).as_slice(),
            &[(1, 1), (0, -1), (1, 1)],
            "the older record's match ended, the newer one's began"
        );
    }

    /// The per-peer state a writer keeps by GUID (its ReaderProxy) belongs
    /// to the record it was built for. A VOLATILE reader is removed and
    /// announced again under its GUID as TRANSIENT_LOCAL, and the new record
    /// pairs with the writer before the old one's end arrives: the old
    /// proxy (owed nothing written before it joined) is dropped and the new
    /// record's built, owed the history; the old record's end then leaves
    /// the new proxy alone. (Taking the second `Matched` as a no-op and
    /// suppressing the old record's end would leave the VOLATILE proxy
    /// answering for the TRANSIENT_LOCAL reader, whose NACKs for the history
    /// would get GAPs.) A record that does not pair takes the proxy
    /// away when the one before it ends.
    #[test]
    fn a_readers_proxy_belongs_to_the_record_it_was_built_for() {
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        let remote_prefix = [0x2F; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let reader_guid = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x04]);
        fsm.handle_spdp(remote_spdp(remote));
        let seen: Arc<Mutex<Vec<PeerChange>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let durable_xcdr2 = QoS {
            data_representation: vec![0x0002],
            ..QoS::best_effort().transient_local()
        };
        let token = reg.register_writer_with_peers(
            "topic".into(),
            durable_xcdr2.clone(),
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            Some(Box::new(move |change| {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(change);
            })),
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        let volatile = QoS {
            data_representation: vec![0x0002],
            ..QoS::best_effort()
        };
        let record = |fsm: &DiscoveryFsm| {
            fsm.current_endpoint("topic", &reader_guid)
                .expect("fixture: the reader is known")
        };
        let told = || seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let matched = |volatile| PeerChange::Matched {
            guid: reader_guid,
            reliable: false,
            volatile,
        };
        let unmatched = PeerChange::Unmatched { guid: reader_guid };

        fsm.handle_sedp(remote_reader_sedp(remote, reader_guid, volatile));
        let first = record(&fsm);
        reg.on_endpoint_discovered(first.clone());
        assert_eq!(told(), vec![matched(true)], "fixture: the VOLATILE proxy");
        assert!(fsm.remove_remote_endpoint(reader_guid), "fixture: removed");
        fsm.handle_sedp(remote_reader_sedp(remote, reader_guid, durable_xcdr2));
        // Paired at discovery, its match not surfaced yet.
        let second = record(&fsm);
        reg.on_endpoint_discovered_incompat_only(second.clone());
        assert_eq!(
            told(),
            vec![matched(true), unmatched, matched(false)],
            "the VOLATILE proxy is dropped and the TRANSIENT_LOCAL one built"
        );
        reg.on_endpoint_removed(first);
        assert_eq!(
            told(),
            vec![matched(true), unmatched, matched(false)],
            "the end of the first record leaves the second record's proxy alone"
        );
        assert_eq!(
            token.current_match_count(),
            0,
            "the first record's match ended"
        );

        // A third record asks for RELIABLE from a BEST_EFFORT writer: it does
        // not pair, and the second record's end takes the proxy.
        assert!(fsm.remove_remote_endpoint(reader_guid), "fixture: removed");
        fsm.handle_sedp(remote_reader_sedp(remote, reader_guid, reliable_xcdr2()));
        reg.on_endpoint_removed(second);
        assert_eq!(
            told().last(),
            Some(&unmatched),
            "a newer record that does not pair leaves no proxy behind"
        );
        assert_eq!(token.current_match_count(), 0);
    }

    /// The reader side: a writer re-created under the GUID of one that left
    /// is paired before the old one's end arrives. The reader's WriterProxy
    /// must be the new writer's, which has sent nothing yet: a proxy that
    /// had received the old writer's 1..=5 would answer for the new one,
    /// whose own 1..=5 would then be acknowledged unreceived.
    #[test]
    fn a_writers_proxy_belongs_to_the_record_it_was_built_for() {
        use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0x01; 12]));
        let remote_prefix = [0x2D; 12];
        let remote = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let writer_guid = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x02]);
        fsm.handle_spdp(remote_spdp(remote));
        let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
        let hook = credit.clone();
        let token = reg.register_reader_with_lifespan(
            "topic".into(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::best_effort()
            },
            &SIMPLE_DESC,
            None,
            |_, _, _, _, _| {},
            Some(Box::new(move |change| match change {
                PeerChange::Matched { guid, .. } => hook.match_writer(guid.as_bytes()),
                PeerChange::Unmatched { guid } => hook.unmatch_writer(&guid.as_bytes()),
            })),
            None,
            None,
            Arc::new(AtomicU64::new(0)),
            ShmPolicy::default(),
        );
        let pairs = QoS {
            data_representation: vec![0x0002],
            ..QoS::best_effort()
        };
        let record = |fsm: &DiscoveryFsm| {
            fsm.current_endpoint("topic", &writer_guid)
                .expect("fixture: the writer is known")
        };
        let w = writer_guid.as_bytes();

        fsm.handle_sedp(remote_reader_sedp(remote, writer_guid, pairs.clone()));
        let first = record(&fsm);
        reg.on_endpoint_discovered(first.clone());
        for seq in 1..=5 {
            credit.on_data(w, seq);
        }
        assert_eq!(credit.settled(&w), Some(5), "fixture: 1..=5 received");

        assert!(fsm.remove_remote_endpoint(writer_guid), "fixture: removed");
        fsm.handle_sedp(remote_reader_sedp(remote, writer_guid, pairs));
        reg.on_endpoint_discovered_incompat_only(record(&fsm));
        assert_eq!(
            credit.settled(&w),
            Some(0),
            "the re-created writer's proxy has received nothing"
        );
        credit.on_data(w, 1);
        // A pairing of the old record still in flight (a catch-up that took
        // its copy before the removal) lands late: it touches nothing of the
        // new writer's proxy.
        reg.pair_entry_at_discovery(token.id(), &first);
        assert_eq!(
            credit.settled(&w),
            Some(1),
            "a late match of the old record leaves the new writer's proxy"
        );
        reg.on_endpoint_removed(first);
        assert_eq!(
            credit.settled(&w),
            Some(1),
            "the old writer's end leaves the new writer's proxy"
        );
    }

    /// Wait up to five seconds for `done`; on a timeout, leak `keep` (a stuck
    /// thread still holds what it would need to drop it) and fail.
    fn finishes_or_leak<T>(done: &std::sync::mpsc::Receiver<()>, keep: T, what: &str) {
        if done
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_err()
        {
            std::mem::forget(keep);
            panic!("{what} never returned: deadlock");
        }
    }

    /// A callback may re-enter its own entry (a listener creates an endpoint,
    /// whose catch-up purges a zombie, whose departure unmatches this entry)
    /// with a snapshot of the entries taken before another thread began to
    /// unregister that entry, and reach it after that thread waits on the
    /// entry's gate. The nested dispatch is skipped, not blocked: the outer
    /// callback returns, and the unregister completes. (A writer-preferring
    /// read lock would block the nested dispatch behind the waiting
    /// unregister, which waits for the outer callback: neither would return.)
    #[test]
    fn a_callback_reentering_its_entry_while_it_is_unregistered_does_not_deadlock() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        use std::sync::atomic::AtomicU32;
        use std::sync::mpsc;
        use std::time::Duration;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let reader = remote_endpoint(EndpointKind::Reader);
        fsm.insert_remote_endpoint_for_test(reader.clone());

        // F, registered first: its second callback (the nested unmatch)
        // parks until the other thread waits in E's unregister.
        let (f_parked, f_in_nested) = mpsc::channel::<()>();
        let (go, gone) = mpsc::channel::<()>();
        let (f_parked, gone) = (Mutex::new(f_parked), Mutex::new(gone));
        let f_calls = AtomicU32::new(0);
        let _f = reg.register_writer_with_peers(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None,
            move |_, _, _, _, _| {
                if f_calls.fetch_add(1, Ordering::SeqCst) == 1 {
                    let _ = f_parked.lock().unwrap_or_else(|e| e.into_inner()).send(());
                    let _ = gone
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .recv_timeout(Duration::from_secs(5));
                }
            },
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        // E: its first callback re-enters the registry (the nested unmatch
        // reaches F, then E).
        let e_calls = AtomicU32::new(0);
        let registry = Arc::downgrade(&reg);
        let nested = reader.clone();
        let token = reg.register_writer_with_peers(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None,
            move |_, _, _, _, _| {
                if e_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    if let Some(reg) = registry.upgrade() {
                        reg.on_endpoint_removed(nested.clone());
                    }
                }
            },
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );

        let (dispatched, dispatch_done) = mpsc::channel::<()>();
        let dispatcher = {
            let reg = Arc::clone(&reg);
            std::thread::spawn(move || {
                reg.on_endpoint_discovered(reader);
                let _ = dispatched.send(());
            })
        };
        f_in_nested
            .recv_timeout(Duration::from_secs(5))
            .expect("the nested dispatch reached F");
        let (unregistered, unregister_done) = mpsc::channel::<()>();
        let unregisterer = std::thread::spawn(move || {
            drop(token);
            let _ = unregistered.send(());
        });
        std::thread::sleep(Duration::from_millis(100));
        let _ = go.send(());

        finishes_or_leak(
            &dispatch_done,
            (dispatcher, Arc::clone(&reg)),
            "the callback",
        );
        finishes_or_leak(&unregister_done, (unregisterer, reg), "the unregister");
    }

    /// A callback may unregister its own entry (a listener deletes its
    /// endpoint from inside `on_publication_matched`): `unregister` does not
    /// wait for the callback that called it (it would wait forever for its
    /// own thread's read lock).
    #[test]
    fn a_callback_unregistering_its_own_entry_does_not_deadlock() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        use std::sync::mpsc;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let reader = remote_endpoint(EndpointKind::Reader);
        fsm.insert_remote_endpoint_for_test(reader.clone());
        let own: Arc<Mutex<Option<MatchToken>>> = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&own);
        let token = reg.register_writer_with_peers(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None,
            move |_, _, _, _, _| {
                let token = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                drop(token);
            },
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        *own.lock().unwrap_or_else(|e| e.into_inner()) = Some(token);

        let (dispatched, dispatch_done) = mpsc::channel::<()>();
        let dispatcher = {
            let reg = Arc::clone(&reg);
            std::thread::spawn(move || {
                reg.on_endpoint_discovered(reader);
                let _ = dispatched.send(());
            })
        };
        finishes_or_leak(&dispatch_done, (dispatcher, reg.clone()), "the callback");
        assert!(
            reg.entries
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "the entry is unregistered"
        );
    }

    /// The application's match listener is called once the entry's
    /// dispatch gate is left (`notices`): a listener that deletes its
    /// endpoint on another thread and waits for it (that `unregister` waits
    /// for the passes of other threads) returns. Called under the gate, it
    /// waited for its own pass.
    #[test]
    fn a_listener_waiting_on_an_unregister_elsewhere_does_not_deadlock() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        use std::sync::mpsc;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let reader = remote_endpoint(EndpointKind::Reader);
        fsm.insert_remote_endpoint_for_test(reader.clone());
        let own: Arc<Mutex<Option<MatchToken>>> = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&own);
        let token = reg.register_writer_with_peers(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None,
            move |_, _, _, _, _| {
                let slot = Arc::clone(&slot);
                // The writer's listener, as `DataWriter`'s match callback
                // calls it.
                crate::dds::reader::notices::notify(move || {
                    let token = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    let _ = std::thread::spawn(move || drop(token)).join();
                });
            },
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        *own.lock().unwrap_or_else(|e| e.into_inner()) = Some(token);

        let (dispatched, dispatch_done) = mpsc::channel::<()>();
        let dispatcher = {
            let reg = Arc::clone(&reg);
            std::thread::spawn(move || {
                reg.on_endpoint_discovered(reader);
                let _ = dispatched.send(());
            })
        };
        finishes_or_leak(&dispatch_done, (dispatcher, reg.clone()), "the listener");
    }

    /// A struct `S { E x; }` as a local endpoint registers it (member type by
    /// MINIMAL hash, the enum in the type store) and as a peer's getTypes
    /// reply carries it (member type by COMPLETE hash, DDS-XTypes v1.3
    /// 7.3.4.5), plus the enum itself and its COMPLETE hash.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn local_and_peer_struct_of_enum() -> (
        crate::xtypes::CompleteTypeObject,
        crate::xtypes::CompleteTypeObject,
        crate::xtypes::CompleteTypeObject,
        crate::xtypes::EquivalenceHash,
        crate::xtypes::EquivalenceHash,
    ) {
        use crate::xtypes::{
            CommonEnumeratedLiteral, CommonStructMember, CompleteEnumeratedHeader,
            CompleteEnumeratedLiteral, CompleteEnumeratedType, CompleteMemberDetail,
            CompleteStructHeader, CompleteStructMember, CompleteStructType, CompleteTypeDetail,
            CompleteTypeObject, EnumeratedLiteralFlag, MemberFlag, StructTypeFlag, TypeIdentifier,
        };
        let literal = |value: i32, name: &str| CompleteEnumeratedLiteral {
            common: CommonEnumeratedLiteral {
                value,
                flags: EnumeratedLiteralFlag::empty(),
            },
            detail: CompleteMemberDetail::new(name),
        };
        let enum_obj = CompleteTypeObject::Enumerated(CompleteEnumeratedType {
            enum_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteEnumeratedHeader {
                bit_bound: 32,
                detail: CompleteTypeDetail::new("Test::E"),
            },
            literal_seq: vec![literal(0, "A"), literal(1, "B")],
        });
        let minimal = crate::dynamic::complete_to_minimal_type_object(&enum_obj)
            .expect("an enum has a minimal form")
            .compute_equivalence_hash()
            .expect("hashable");
        let complete = enum_obj.compute_equivalence_hash().expect("hashable");
        let with_member = |member_type_id: TypeIdentifier| {
            CompleteTypeObject::Struct(CompleteStructType {
                struct_flags: StructTypeFlag::IS_APPENDABLE,
                header: CompleteStructHeader {
                    base_type: None,
                    detail: CompleteTypeDetail::new("Test::S"),
                },
                member_seq: vec![CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id,
                    },
                    detail: CompleteMemberDetail::new("x"),
                }],
            })
        };
        (
            with_member(TypeIdentifier::Minimal(minimal)),
            with_member(TypeIdentifier::Complete(complete)),
            enum_obj,
            minimal,
            complete,
        )
    }

    /// A peer's TypeObject names its member type by COMPLETE hash, the local
    /// one by MINIMAL hash. Two identifiers of different kinds; one TYPE
    /// (DDS-XTypes v1.3 7.6.3.4.2 Step 1 compares types): once the peer's
    /// enum is learned, the pairing is judged on the types and accepted,
    /// both ways round. It is not refused as a cross-variant pair (a refusal
    /// there would be final).
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_complete_reference_and_a_minimal_reference_to_one_type_are_assignable() {
        let (local, peer, enum_obj, minimal, complete) = local_and_peer_struct_of_enum();
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let mut types = std::collections::HashMap::new();
        types.insert(minimal, enum_obj.clone());
        reg.register_type_objects(types);
        let forcing = TypeConsistencyEnforcement {
            force_type_validation: true,
            ..TypeConsistencyEnforcement::default()
        };

        reg.register_remote_type_object(complete, enum_obj, [0x0A; 12]);
        assert!(
            reg.pairing_type_verdict(
                "topic",
                known_side(&peer),
                known_side(&local),
                Some(&forcing)
            ),
            "the enum is known: the types are judged, and they are the same"
        );
        assert!(
            reg.pairing_type_verdict(
                "topic",
                known_side(&local),
                known_side(&peer),
                Some(&forcing)
            ),
            "and the other way round"
        );
    }

    /// The same struct whose peer member type, once learned, is NOT the
    /// local one: the refusal rests on the types and stands, whatever
    /// force_type_validation says.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_refusal_on_known_member_types_stands() {
        let (local, peer, enum_obj, minimal, complete) = local_and_peer_struct_of_enum();
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let mut types = std::collections::HashMap::new();
        types.insert(minimal, enum_obj);
        reg.register_type_objects(types);
        // The peer's COMPLETE hash names a struct, not an enum.
        reg.register_remote_type_object(
            complete,
            crate::xtypes::CompleteTypeObject::Struct(crate::xtypes::CompleteStructType {
                struct_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
                header: crate::xtypes::CompleteStructHeader {
                    base_type: None,
                    detail: crate::xtypes::CompleteTypeDetail::new("Test::E"),
                },
                member_seq: Vec::new(),
            }),
            [0x0A; 12],
        );
        assert!(!reg.pairing_type_verdict(
            "topic",
            known_side(&peer),
            known_side(&local),
            Some(&TypeConsistencyEnforcement::default())
        ));
    }

    /// Under one hash, a local type wins over a peer's, for both resolvers
    /// the verdict uses; the peer store is bounded and forgets a departed
    /// peer's types.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_local_type_wins_over_a_peer_type_and_the_peer_store_is_bounded() {
        use crate::core::discovery::matcher::type_cache::TYPE_CACHE_CAPACITY;
        use crate::core::discovery::matcher::TypeObjectResolver;
        let (local, peer, enum_obj, minimal, _) = local_and_peer_struct_of_enum();
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let mut types = std::collections::HashMap::new();
        types.insert(minimal, enum_obj.clone());
        reg.register_type_objects(types);
        reg.register_remote_type_object(minimal, peer.clone(), [0x0A; 12]);
        assert_eq!(
            reg.snapshot_resolver().resolve_minimal(&minimal),
            Some(&enum_obj)
        );
        // The borrowing resolver: the local enum resolves the local struct's
        // reference, so nothing is unresolved.
        assert!(reg.unresolved_type_refs(&local).is_empty());

        for i in 0..TYPE_CACHE_CAPACITY + 5 {
            let mut bytes = [0u8; 14];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            reg.register_remote_type_object(
                crate::xtypes::EquivalenceHash::from_bytes(bytes),
                enum_obj.clone(),
                [0x0B; 12],
            );
        }
        assert_eq!(reg.remote_type_count(), TYPE_CACHE_CAPACITY);
        reg.forget_remote_types_of(&[0x0B; 12]);
        assert_eq!(reg.remote_type_count(), 0);
    }

    /// Match then unmatch of one entry on two threads: the
    /// gate orders the status computation, the deferred listener call no
    /// longer follows it. A preemption between the gate exit and the tell
    /// is modelled by a notice held before the listener's (any other held
    /// notice of that thread, or the scheduler, does the same).
    #[test]
    fn verify_matched_status_reaches_the_listener_out_of_gate_order() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        use std::sync::mpsc;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        let reader = remote_endpoint(EndpointKind::Reader);
        fsm.insert_remote_endpoint_for_test(reader.clone());
        let seen: Arc<Mutex<Vec<(u32, i32)>>> = Arc::new(Mutex::new(Vec::new()));
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let go_tx = Arc::new(Mutex::new(Some(go_tx)));
        let done_rx = Arc::new(Mutex::new(Some(done_rx)));
        let rec = Arc::clone(&seen);
        let _token = reg.register_writer_with_peers(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            None,
            move |_total, _tc, current, cc, _| {
                if cc > 0 {
                    let go = go_tx.lock().unwrap().take();
                    let done = done_rx.lock().unwrap().take();
                    // "preemption" after the gate, before the listener.
                    crate::dds::reader::notices::notify(move || {
                        if let (Some(go), Some(done)) = (go, done) {
                            let _ = go.send(());
                            let _ = done.recv_timeout(std::time::Duration::from_secs(2));
                        }
                    });
                }
                let rec = Arc::clone(&rec);
                crate::dds::reader::notices::notify(move || {
                    rec.lock().unwrap().push((current, cc));
                });
            },
            None,
            None,
            None,
            ShmPolicy::default(),
            None,
        );
        let remover = {
            let reg = Arc::clone(&reg);
            let reader = reader.clone();
            std::thread::spawn(move || {
                // Bounded: a pairing that is never matched never reaches the
                // listener, so this point is never reached and must not hang.
                go_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .expect("the listener never reached its preemption point");
                reg.on_endpoint_removed(reader);
                let _ = done_tx.send(());
            })
        };
        reg.on_endpoint_discovered(reader);
        remover.join().unwrap();
        let seen = seen.lock().unwrap().clone();
        eprintln!("listener saw (current_count, current_count_change): {seen:?}");
        let mut expect = 0i64;
        for (cur, cc) in &seen {
            expect += i64::from(*cc);
            assert_eq!(
                i64::from(*cur),
                expect,
                "listener saw current_count {cur} with change {cc} after {seen:?}: \
                 out of order; its last view is current_count={} while the writer has 0 matched",
                seen.last().unwrap().0
            );
        }
    }
    /// DDS Security 8.5.1.8.3 owes tokens on each new endpoint match. The
    /// event survives a complete unmatch/rematch between writer sweeps.
    #[cfg(feature = "security")]
    #[test]
    fn a_rematch_changes_its_generation_but_a_repeat_notice_does_not() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));
        fsm.set_match_registry(Arc::clone(&reg));
        let local = GUID::new([0; 12], [0, 0, 7, 0x02]);
        let token = reg.register_writer_with_incompatible(
            "topic".into(),
            QoS {
                data_representation: vec![0x0002],
                ..QoS::best_effort()
            },
            &SIMPLE_DESC,
            |_, _, _, _, _| {},
            None,
        );
        token.bind_local_guid(local);
        let remote = remote_reader(vec![0x0002]);
        fsm.insert_remote_endpoint_for_test(remote.clone());
        reg.on_endpoint_discovered(remote.clone());
        let first = fsm
            .local_endpoint_match_generation(&local, &remote.endpoint_guid)
            .unwrap();
        reg.on_endpoint_discovered(remote.clone());
        assert_eq!(
            fsm.local_endpoint_match_generation(&local, &remote.endpoint_guid),
            Some(first)
        );
        reg.on_endpoint_removed(remote.clone());
        assert_eq!(
            fsm.local_endpoint_match_generation(&local, &remote.endpoint_guid),
            None
        );
        reg.on_endpoint_discovered(remote.clone());
        let second = fsm
            .local_endpoint_match_generation(&local, &remote.endpoint_guid)
            .unwrap();
        assert_ne!(first, second);
    }
}

#[cfg(test)]
#[path = "match_notification_pair_tests.rs"]
mod pair_tests;
