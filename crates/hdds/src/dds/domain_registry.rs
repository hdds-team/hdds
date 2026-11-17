// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Domain Registry for Intra-Process Auto-Binding
//!
//!
//! This module provides automatic endpoint matching within the same process.
//! When a Reader and Writer share the same (topic, type_id), they are
//! automatically bound for zero-copy intra-process communication.
//!
//! # Architecture
//!
//! ```text
//! DomainRegistry (static global)
//! +-- domains: Mutex<HashMap<DomainId, Weak<DomainState>>>
//!
//! DomainState (one per domain, per process)
//! +-- domain_id: u32
//! +-- endpoints: RwLock<HashMap<MatchKey, Vec<LocalEndpointEntry>>>
//! +-- [strong ref held by Participant]
//!
//! MatchKey
//! +-- topic_name: Arc<str>
//! +-- type_id: TypeId  (MD5-14 or simple hash)
//! ```
//!
//! # Auto-Binding Flow
//!
//! 1. Writer created -> registers in DomainState
//! 2. Reader created -> registers, finds matching Writers, auto-binds
//! 3. Reader destroyed -> unbinds, unregisters
//! 4. Writer destroyed -> unbinds all readers, unregisters
//!
//! # Thread Safety
//!
//! - DomainRegistry: Mutex for domain map access
//! - DomainState.endpoints: RwLock (many readers, few writers)
//! - All operations are lock-free for the data path (only registration/lookup locks)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::core::discovery::GUID;
use crate::core::rt::{IndexRing, TopicMerger};
use crate::dds::qos::Reliability;

/// Domain ID type (0-232 per DDS spec)
pub type DomainId = u32;

/// Type identifier for matching endpoints
///
/// For intra-process, we use a simple approach:
/// - MD5 hash of type_name (14 bytes, truncated for EquivalenceHash compat)
/// - Stored as [u8; 14] for HashMap key efficiency
///
/// This is simpler than full XTypes TypeIdentifier for intra-process use.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeId([u8; 14]);

impl TypeId {
    /// Create TypeId from type name using MD5
    pub fn from_type_name(type_name: &str) -> Self {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(type_name.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 14];
        bytes.copy_from_slice(&result[..14]);
        Self(bytes)
    }

    /// Create from raw bytes
    pub const fn from_bytes(bytes: [u8; 14]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub const fn as_bytes(&self) -> &[u8; 14] {
        &self.0
    }

    /// Zero TypeId (for testing)
    pub const fn zero() -> Self {
        Self([0u8; 14])
    }
}

impl std::fmt::Debug for TypeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TypeId(")?;
        for byte in &self.0[..4] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "...)")
    }
}

impl std::fmt::Display for TypeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Match key for endpoint lookup
///
/// Two endpoints match if they have the same (topic_name, type_id).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MatchKey {
    /// Topic name
    pub topic_name: Arc<str>,
    /// Type identifier (MD5 of type name)
    pub type_id: TypeId,
}

impl MatchKey {
    /// Create new match key
    pub fn new(topic_name: impl Into<Arc<str>>, type_id: TypeId) -> Self {
        Self {
            topic_name: topic_name.into(),
            type_id,
        }
    }

    /// Create match key from topic and type names
    pub fn from_names(topic_name: &str, type_name: &str) -> Self {
        Self {
            topic_name: Arc::from(topic_name),
            type_id: TypeId::from_type_name(type_name),
        }
    }
}

impl std::fmt::Debug for MatchKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchKey")
            .field("topic", &self.topic_name)
            .field("type_id", &self.type_id)
            .finish()
    }
}

/// Kind of local endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Reader,
    Writer,
}

/// Process-unique identity of a DomainParticipant.
///
/// This is deliberately distinct from the RTPS participant id/GUID prefix:
/// all `IntraProcess` participants use RTPS participant id 0, while the
/// local registry must still distinguish their ownership boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParticipantToken(u64);

impl ParticipantToken {
    pub(crate) fn mint() -> Self {
        static NEXT_PARTICIPANT_TOKEN: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);

        Self(NEXT_PARTICIPANT_TOKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    /// The token as a number (the owner mark of the participant's threads,
    /// `core::rt::shutdown`).
    pub(crate) fn raw(self) -> u64 {
        self.0
    }
}

/// Non-QoS facts used to choose the local delivery path for an endpoint.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct EndpointContext {
    participant: Option<ParticipantToken>,
    wire_capable: bool,
}

impl EndpointContext {
    pub(crate) fn new(participant: Option<ParticipantToken>, wire_capable: bool) -> Self {
        Self {
            participant,
            wire_capable,
        }
    }
}

/// Local endpoint entry in the registry
pub struct LocalEndpointEntry {
    /// Process-unique registration identity.
    ///
    /// This -- not the GUID -- is what `unregister` matches on. It cannot be
    /// the GUID: every intra-bound reader registers as `GUID::zero()`
    /// (`reader/builder.rs`), writers built without an RTPS endpoint too, so
    /// GUID-keyed removal purged EVERY zero-GUID endpoint on the (topic,
    /// type) the moment ONE of them dropped. Survivors kept their existing
    /// merger bindings but never auto-bound to any writer created afterwards.
    /// Minted from a process-global counter at registration; never reused.
    pub endpoint_id: u64,
    /// Endpoint GUID
    pub guid: GUID,
    /// Endpoint kind
    pub kind: EndpointKind,
    /// Participant ownership and wire reachability for delivery-path choice.
    pub(crate) context: EndpointContext,
    /// QoS the auto-bind predicate matches on (see [`EndpointQos`]).
    pub qos: EndpointQos,
    /// TopicMerger (writers only) - used by readers to bind
    pub merger: Option<Arc<TopicMerger>>,
    /// IndexRing (readers only) - receives data from merger
    pub ring: Option<Arc<IndexRing>>,
    /// Callback to bind reader to writer's merger
    ///
    /// For readers: called when a matching writer is found
    /// For writers: None
    pub bind_callback: Option<Box<dyn Fn(Arc<TopicMerger>) + Send + Sync>>,
    /// PUBLICATION_MATCHED / SUBSCRIPTION_MATCHED / OFFERED or
    /// REQUESTED_INCOMPATIBLE_QOS bookkeeping for this endpoint, `Some` only
    /// when the owning participant has no `MatchNotificationRegistry` of
    /// its own to report through (`TransportMode::IntraProcess`: see
    /// [`LocalMatchStatus`]). `None` for a wire-capable participant (its
    /// `match_registry` already reports the pairing through SEDP, including
    /// for an endpoint of this same participant, loopback-discovered) and
    /// for an endpoint built with no participant at all (no listener to
    /// reach either way).
    pub(crate) match_status: Option<Arc<LocalMatchStatus>>,
}

/// The QoS a registered endpoint exposes to the intra auto-bind predicate.
///
/// The whole QoS, and the type's XCDR1 capability, so that the intra path
/// and the wire path agree about WHICH pairs deliver: they are judged by
/// the one verdict (`match_notification::rxo_verdict`). Auto-binding checks
/// the whole QoS, not Reliability alone: two co-located participants with
/// disjoint partitions must not deliver through the slab while the identical
/// pair over UDP is dropped by the reader's PARTITION gate, and a VOLATILE
/// writer must not feed a TRANSIENT_LOCAL reader the match registry reports
/// incompatible.
#[derive(Debug, Clone)]
pub struct EndpointQos {
    pub(crate) qos: Arc<crate::dds::qos::QoS>,
    pub(crate) xcdr1: crate::dds::cdr_negotiation::Xcdr1Encoding,
}

impl EndpointQos {
    /// The registration QoS of an endpoint of QoS `qos`, of a type that
    /// encodes XCDR1 as `xcdr1` says.
    pub(crate) fn new(
        qos: &crate::dds::qos::QoS,
        xcdr1: crate::dds::cdr_negotiation::Xcdr1Encoding,
    ) -> Self {
        Self {
            qos: Arc::new(qos.clone()),
            xcdr1,
        }
    }

    /// Registration QoS with every policy at its default but `reliability`,
    /// for tests and callers without a full QoS.
    pub fn from_reliability(reliability: Reliability) -> Self {
        Self::new(
            &crate::dds::qos::QoS {
                reliability,
                ..crate::dds::qos::QoS::default()
            },
            crate::dds::cdr_negotiation::Xcdr1Encoding::native(),
        )
    }
}

/// The ONE pair predicate of the intra auto-bind: a pair is delivered (and,
/// via `LocalMatchStatus` below, matched) when it is in scope
/// (`scope_allows`) AND the one QoS verdict (`qos_verdict`: `rxo_verdict`,
/// the RxO policies, PARTITION, OWNERSHIP kind and DATA_REPRESENTATION, DDS
/// v1.4 Sec.2.2.3; the reader read as it announces itself,
/// `local_reader_qos_for_verdict`) accepts it, decided once, at bind time;
/// the write path reads nothing of it. A pair the verdict refuses is not
/// matched, and an endpoint not matched receives nothing from the other
/// (DDS v1.4 Sec.2.2.3: "If the two policies are not compatible, the
/// Service will not establish communications between the two Entity
/// objects"). `register_writer_with_match`/`register_reader_with_match`
/// read `qos_verdict` and `scope_allows` directly (never a `bool`-only
/// wrapper) because a refusal must still name its policy, for
/// OFFERED/REQUESTED_INCOMPATIBLE_QOS.
///
/// EXCLUSIVE strength arbitration happens per sample at the reader, through
/// the gate a binding carries (`ReaderBindings::bind`).
///
/// Type compatibility is enforced structurally by the `MatchKey` (exact
/// type-id equality), which is stricter than the wire's assignability rules,
/// never looser; it is not stricter about XCDR1-native encoding, which is a
/// property of the actual Rust type behind each end, not of its name, so
/// both ends' `xcdr1` are read (`Xcdr1Encoding::either_refuses`): a pair is
/// refused if EITHER end's type refuses XCDR1, not only the reader's.
///
/// The ONE QoS verdict (`rxo_verdict`, DDS v1.4 Sec.2.2.3), shared by the
/// data-path predicate above and by the match-status bookkeeping below
/// (`LocalMatchStatus`): never duplicate the rxo rules to decide whether a
/// pair counts as PUBLICATION_MATCHED/SUBSCRIPTION_MATCHED. `Err(policy_id)`
/// names the refusing policy (0 when `rxo_verdict` itself does not name
/// one), for OFFERED/REQUESTED_INCOMPATIBLE_QOS.
fn qos_verdict(writer: &EndpointQos, reader: &EndpointQos) -> Result<(), u32> {
    let xcdr1 =
        crate::dds::cdr_negotiation::Xcdr1Encoding::either_refuses(writer.xcdr1, reader.xcdr1);
    crate::dds::match_notification::rxo_verdict(
        &writer.qos,
        &crate::dds::match_notification::local_reader_qos_for_verdict(&reader.qos),
        xcdr1,
        // In-process: both ends are this participant's own Rust types, never
        // a remote vendor (the remote-vendor wchar refusal never applies here).
        None,
        false,
    )
}

/// Whether domain_registry.rs is even the right place to decide this pair at
/// all. A wire-capable pair serving different co-located participants is
/// RTPS's to deliver and to report (`MatchNotificationRegistry`, fed by this
/// process's own SEDP loopback): keeping the intra binding as well would
/// deliver the same sample through two independent paths, and reporting the
/// match here too would double-count it. If either endpoint has no wire
/// path, local delivery -- and, per `local_status_applies` below, local
/// match-status reporting -- is the only route.
fn scope_allows(writer_context: EndpointContext, reader_context: EndpointContext) -> bool {
    !writer_context.wire_capable
        || !reader_context.wire_capable
        || writer_context.participant == reader_context.participant
}

/// Whether a pair's PUBLICATION_MATCHED/SUBSCRIPTION_MATCHED/
/// OFFERED-or-REQUESTED_INCOMPATIBLE_QOS status belongs to THIS registry's
/// `LocalMatchStatus`, as opposed to `MatchNotificationRegistry` (SEDP,
/// including a same-participant pair's loopback self-announce) alone.
///
/// Narrower than `scope_allows`: a same-participant pair where BOTH
/// endpoints are wire-capable is in `scope_allows`'s scope too (the data
/// path still binds through the merger for zero-copy delivery), but SEDP's
/// loopback already reports that exact pair -- firing it here too would
/// double-count it. A pair where EITHER endpoint has no wire path at all
/// can never reach SEDP: nothing is ever announced for an endpoint with no
/// transport, on EITHER side of the pairing, so this registry is the ONLY
/// route for it, regardless of whether the OTHER endpoint's own
/// participant happens to have a `match_registry` for its (other,
/// wire-reachable) peers. This is what makes a writer/reader builder give
/// EVERY endpoint with a participant a `LocalMatchStatus`, not only one
/// with no `match_registry`: a wire-capable reader matched, through this
/// registry, with an IntraProcess writer that SEDP will never hear of was
/// otherwise left at current_count=0 forever (the mixed-transport gap).
fn local_status_applies(writer_context: EndpointContext, reader_context: EndpointContext) -> bool {
    !writer_context.wire_capable || !reader_context.wire_capable
}

/// Callback shape mirroring `MatchNotificationRegistry`'s match callback:
/// `(total_count, total_count_change, current_count, current_count_change,
/// last_handle)` (DDS v1.4 Sec.2.2.4.1), so a writer/reader builder can
/// build it once and hand it to whichever registry ends up driving it.
pub(crate) type LocalMatchCallback = Box<dyn Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync>;
/// Callback shape mirroring the incompatible-QoS callback:
/// `(total_count, total_count_change, policy_id)`.
pub(crate) type LocalIncompatCallback = Box<dyn Fn(u32, i32, u32) + Send + Sync>;

/// PUBLICATION_MATCHED / SUBSCRIPTION_MATCHED and OFFERED /
/// REQUESTED_INCOMPATIBLE_QOS bookkeeping for ONE local endpoint whose
/// participant has no `MatchNotificationRegistry` to report through
/// (`TransportMode::IntraProcess`, where `Participant::match_registry` is
/// `None` because there is no `discovery_fsm` to feed SEDP into). Driven
/// from the SAME pair verdict as the data-path bind (`pair_delivers`'s
/// `qos_verdict`/`scope_allows`), at the SAME registration/unregistration
/// events (`DomainState::register_writer_with_match`,
/// `register_reader_with_match`, `unregister`): there is one notion of
/// "matched" for an intra-process pair, not a second copy of the rxo rules.
pub(crate) struct LocalMatchStatus {
    /// This endpoint's own identity, reported to the PEER as its
    /// last_publication_handle / last_subscription_handle when this
    /// endpoint (un)matches it. Independent of `LocalEndpointEntry::guid`
    /// (a reader always registers that as `GUID::zero()`, see its doc): a
    /// real GUID when the owning builder has a participant, `GUID::zero()`
    /// otherwise -- the same fallback `PublicationMatchedStatus`'s
    /// `last_subscription_handle` already uses on a peer with no identity
    /// of its own.
    identity: GUID,
    incompatible_count: AtomicU32,
    /// Peers (by `LocalEndpointEntry::endpoint_id`) currently matched with
    /// this endpoint, and the identity reported for each -- current_count
    /// is this map's length; an unmatch names the departing peer by the
    /// identity recorded when it matched, never a stale `GUID::zero()`.
    matches: Mutex<LocalMatches>,
    #[cfg(test)]
    before_match_publish: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    on_match: LocalMatchCallback,
    on_incompat: Option<LocalIncompatCallback>,
}

/// Membership, counters and pending publication share one serialization point.
#[derive(Default)]
struct LocalMatches {
    peers: HashMap<u64, GUID>,
    total: u32,
    total_change: i32,
    current_change: i32,
    last_handle: Option<GUID>,
    pending: bool,
    publishing: bool,
}

/// Keep a callback panic from permanently suppressing later statuses.
struct MatchPublicationReset<'a> {
    matches: &'a Mutex<LocalMatches>,
    armed: bool,
}

impl Drop for MatchPublicationReset<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.matches
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .publishing = false;
        }
    }
}

impl LocalMatchStatus {
    pub(crate) fn new(
        identity: GUID,
        on_match: LocalMatchCallback,
        on_incompat: Option<LocalIncompatCallback>,
    ) -> Arc<Self> {
        Arc::new(Self {
            identity,
            incompatible_count: AtomicU32::new(0),
            matches: Mutex::new(LocalMatches::default()),
            #[cfg(test)]
            before_match_publish: Mutex::new(None),
            on_match,
            on_incompat,
        })
    }

    /// `peer_id` just matched (DDS v1.4 Sec.2.2.4.1: total_count_change = 1,
    /// current_count_change = 1). Idempotent: a peer already matched is a
    /// no-op, since every call site visits each (new entry, existing entry)
    /// pair exactly once.
    fn fire_match(&self, peer_id: u64, peer_identity: Option<GUID>) {
        let mut matches = self.matches.lock().unwrap_or_else(|e| e.into_inner());
        if matches.peers.contains_key(&peer_id) {
            return;
        }
        matches
            .peers
            .insert(peer_id, peer_identity.unwrap_or_else(GUID::zero));
        matches.total = matches.total.saturating_add(1);
        matches.total_change = matches.total_change.saturating_add(1);
        matches.current_change = matches.current_change.saturating_add(1);
        matches.last_handle = peer_identity;
        self.publish_matches(matches);
    }

    /// A departure changes current_count only (DDS v1.4 Sec.2.2.4.1).
    fn fire_unmatch(&self, peer_id: u64) {
        let mut matches = self.matches.lock().unwrap_or_else(|e| e.into_inner());
        let Some(identity) = matches.peers.remove(&peer_id) else {
            return;
        };
        matches.current_change = matches.current_change.saturating_sub(1);
        matches.last_handle = Some(identity);
        self.publish_matches(matches);
    }

    /// One publisher drains the latest state outside the membership lock.
    /// Concurrent or reentrant changes are accumulated for its next call,
    /// so an older callback can never overwrite the final newer snapshot.
    fn publish_matches<'a>(&'a self, mut matches: std::sync::MutexGuard<'a, LocalMatches>) {
        matches.pending = true;
        if matches.publishing {
            return;
        }
        matches.publishing = true;
        let mut reset = MatchPublicationReset {
            matches: &self.matches,
            armed: true,
        };
        loop {
            let snapshot = (
                matches.total,
                matches.total_change,
                u32::try_from(matches.peers.len()).unwrap_or(u32::MAX),
                matches.current_change,
                matches.last_handle,
            );
            matches.total_change = 0;
            matches.current_change = 0;
            matches.pending = false;
            drop(matches);
            #[cfg(test)]
            {
                let hook = self
                    .before_match_publish
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(hook) = hook {
                    hook();
                }
            }
            (self.on_match)(snapshot.0, snapshot.1, snapshot.2, snapshot.3, snapshot.4);
            matches = self.matches.lock().unwrap_or_else(|e| e.into_inner());
            if !matches.pending {
                matches.publishing = false;
                reset.armed = false;
                return;
            }
        }
    }

    /// This pair is QoS-incompatible (`qos_verdict`'s `Err(policy_id)`),
    /// `policy_id == 0` meaning `rxo_verdict` refused without naming one
    /// (nothing to report: DDS v1.4 Sec.2.2.4.1's `last_policy_id` names a
    /// real policy). No dedup: domain_registry.rs evaluates a (writer,
    /// reader) pair exactly once, at whichever of the two registers second.
    fn fire_incompat(&self, policy_id: u32) {
        if policy_id == 0 {
            return;
        }
        let Some(ref on_incompat) = self.on_incompat else {
            return;
        };
        let total = self.incompatible_count.fetch_add(1, Ordering::Relaxed) + 1;
        on_incompat(total, 1, policy_id);
    }

    /// This endpoint's identity, for a peer's `fire_match`/`fire_unmatch`.
    fn identity(&self) -> GUID {
        self.identity
    }

    /// The current_count a status getter reads (DDS v1.4 Sec.2.2.4.1):
    /// `DataWriter::matched_reader_count` for a writer with no
    /// `MatchNotificationRegistry` `MatchToken` to read it from instead.
    pub(crate) fn current_count(&self) -> u32 {
        u32::try_from(
            self.matches
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .peers
                .len(),
        )
        .unwrap_or(u32::MAX)
    }

    /// Identities of the peers currently matched (DDS v1.4
    /// Sec.2.2.2.4.2.24 `get_matched_subscriptions` on a writer, or
    /// Sec.2.2.2.5.3.34 `get_matched_publications` on a reader): the GUIDs
    /// recorded for this entity's half of the pairs `domain_registry.rs`
    /// matched with no wire path on either side (see the type docs).
    pub(crate) fn matched_guids(&self) -> Vec<GUID> {
        self.matches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .peers
            .values()
            .copied()
            .collect()
    }
}

impl std::fmt::Debug for LocalEndpointEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalEndpointEntry")
            .field("endpoint_id", &self.endpoint_id)
            .field("guid", &self.guid)
            .field("kind", &self.kind)
            .field("context", &self.context)
            .field("qos", &self.qos)
            .field("has_merger", &self.merger.is_some())
            .field("has_ring", &self.ring.is_some())
            .field("has_bind_callback", &self.bind_callback.is_some())
            .field("has_match_status", &self.match_status.is_some())
            .finish()
    }
}

/// Token returned when registering an endpoint
///
/// When dropped, automatically unregisters the endpoint from the domain.
/// This ensures cleanup even on panic/early return.
pub struct BindToken {
    domain: Weak<DomainState>,
    key: MatchKey,
    /// The registration this token owns. Removal matches on THIS, never on
    /// the GUID -- see `LocalEndpointEntry::endpoint_id` for why.
    endpoint_id: u64,
}

impl BindToken {
    /// Create new bind token (internal)
    fn new(domain: &Arc<DomainState>, key: MatchKey, endpoint_id: u64) -> Self {
        Self {
            domain: Arc::downgrade(domain),
            key,
            endpoint_id,
        }
    }
}

impl Drop for BindToken {
    fn drop(&mut self) {
        if let Some(domain) = self.domain.upgrade() {
            domain.unregister(&self.key, self.endpoint_id);
        }
    }
}

impl std::fmt::Debug for BindToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BindToken")
            .field("key", &self.key)
            .field("endpoint_id", &self.endpoint_id)
            .finish()
    }
}

/// Process-global endpoint-id mint. Starts at 1 so 0 can never collide with
/// a real registration (and a zeroed struct is visibly unregistered).
static NEXT_ENDPOINT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn mint_endpoint_id() -> u64 {
    NEXT_ENDPOINT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Domain state - holds all endpoints for a single domain
pub struct DomainState {
    /// Domain ID
    pub domain_id: DomainId,
    /// Endpoints grouped by (topic, type_id)
    endpoints: RwLock<HashMap<MatchKey, Vec<LocalEndpointEntry>>>,
}

impl DomainState {
    /// Create new domain state
    pub fn new(domain_id: DomainId) -> Self {
        Self {
            domain_id,
            endpoints: RwLock::new(HashMap::new()),
        }
    }

    /// Register a writer endpoint
    ///
    /// Returns a BindToken that unregisters on drop.
    /// Also triggers auto-binding with any existing matching readers (QoS compatible only).
    pub fn register_writer(
        self: &Arc<Self>,
        key: MatchKey,
        guid: GUID,
        merger: Arc<TopicMerger>,
        qos: EndpointQos,
    ) -> BindToken {
        self.register_writer_with_context(key, guid, merger, qos, EndpointContext::default())
    }

    pub(crate) fn register_writer_with_context(
        self: &Arc<Self>,
        key: MatchKey,
        guid: GUID,
        merger: Arc<TopicMerger>,
        qos: EndpointQos,
        context: EndpointContext,
    ) -> BindToken {
        self.register_writer_with_match(key, guid, merger, qos, context, None)
    }

    /// [`register_writer_with_context`](Self::register_writer_with_context)
    /// plus `match_status`: this writer's PUBLICATION_MATCHED /
    /// OFFERED_INCOMPATIBLE_QOS bookkeeping, `Some` only for a participant
    /// with no `MatchNotificationRegistry` of its own (see
    /// [`LocalMatchStatus`]'s doc). For each existing reader in scope
    /// (`scope_allows`) of this key, the one QoS verdict (`qos_verdict`,
    /// the SAME one `pair_delivers` reads) decides: `Err` fires
    /// OFFERED/REQUESTED_INCOMPATIBLE_QOS on whichever side has a status to
    /// report it, `Ok` fires PUBLICATION_MATCHED/SUBSCRIPTION_MATCHED on
    /// both sides BEFORE the data-path bind below, so a late writer's
    /// TRANSIENT_LOCAL history replay to an existing reader's
    /// `bind_callback` is announced to the application first (DDS v1.4
    /// Sec.2.2.4.1).
    pub(crate) fn register_writer_with_match(
        self: &Arc<Self>,
        key: MatchKey,
        guid: GUID,
        merger: Arc<TopicMerger>,
        qos: EndpointQos,
        context: EndpointContext,
        match_status: Option<Arc<LocalMatchStatus>>,
    ) -> BindToken {
        // Declared BEFORE `endpoints` below: local variables drop in
        // reverse declaration order, so the write lock (declared after)
        // is released FIRST, and only then does this guard's own `Drop`
        // run -- telling any listener a status fired below reached
        // through `notices::notify` only once the lock is already
        // gone. Without this, `fire_match`/`fire_incompat` (reached
        // through `match_status`/`existing.match_status` in the loop
        // below) call straight into the application while `endpoints` is
        // still held: a listener that creates or deletes an endpoint on
        // this same domain re-takes the same non-reentrant `RwLock` and
        // deadlocks the thread against itself (for example a
        // reader's `on_subscription_matched` builds a writer when its
        // matched writer is dropped).
        let _delivering = crate::dds::reader::notices::Delivering::enter();
        let mut endpoints = self.endpoints.write().unwrap_or_else(|e| e.into_inner());

        let endpoint_id = mint_endpoint_id();
        let entry = LocalEndpointEntry {
            endpoint_id,
            guid,
            kind: EndpointKind::Writer,
            context,
            qos: qos.clone(),
            merger: Some(merger.clone()),
            ring: None,
            bind_callback: None,
            match_status: match_status.clone(),
        };

        // Get or create endpoint list for this key
        let entries = endpoints.entry(key.clone()).or_default();

        // Auto-bind: notify all existing compatible readers about this new
        // writer. The predicate is the SAME one the wire enforces (13.3).
        for existing in entries.iter() {
            if existing.kind != EndpointKind::Reader {
                continue;
            }
            if !scope_allows(context, existing.context) {
                continue;
            }
            // Status (match or incompatible) belongs here only when SEDP
            // can never report this exact pair (`local_status_applies`);
            // a same-participant, both-wire-capable pair is `scope_allows`
            // for the data bind but SEDP's loopback already reports it.
            let report_status = local_status_applies(context, existing.context);
            if let Err(policy_id) = qos_verdict(&qos, &existing.qos) {
                log::debug!(
                    "[DomainRegistry] Skipping local bind: writer {:?}/{:?}, reader {:?}/{:?}",
                    qos,
                    context,
                    existing.qos,
                    existing.context
                );
                if report_status {
                    if let Some(ref status) = match_status {
                        status.fire_incompat(policy_id);
                    }
                    if let Some(ref status) = existing.match_status {
                        status.fire_incompat(policy_id);
                    }
                }
                continue;
            }
            // Match status before the data bind: a late writer's history
            // replays into the reader's ring from inside `callback` below.
            if report_status {
                if let Some(ref status) = match_status {
                    status.fire_match(
                        existing.endpoint_id,
                        existing.match_status.as_ref().map(|s| s.identity()),
                    );
                }
                if let Some(ref status) = existing.match_status {
                    status.fire_match(endpoint_id, match_status.as_ref().map(|s| s.identity()));
                }
            }
            if let Some(ref callback) = existing.bind_callback {
                log::debug!(
                    "[DomainRegistry] Auto-binding reader {} to new writer {}",
                    existing.guid,
                    guid
                );
                callback(merger.clone());
            }
        }

        entries.push(entry);

        BindToken::new(self, key, endpoint_id)
    }

    /// Register a reader endpoint
    ///
    /// Returns a BindToken that unregisters on drop.
    /// Also triggers auto-binding with any existing matching writers (QoS compatible only).
    pub fn register_reader<F>(
        self: &Arc<Self>,
        key: MatchKey,
        guid: GUID,
        ring: Arc<IndexRing>,
        qos: EndpointQos,
        bind_callback: F,
    ) -> BindToken
    where
        F: Fn(Arc<TopicMerger>) + Send + Sync + 'static,
    {
        self.register_reader_with_context(
            key,
            guid,
            ring,
            qos,
            EndpointContext::default(),
            bind_callback,
        )
    }

    pub(crate) fn register_reader_with_context<F>(
        self: &Arc<Self>,
        key: MatchKey,
        guid: GUID,
        ring: Arc<IndexRing>,
        qos: EndpointQos,
        context: EndpointContext,
        bind_callback: F,
    ) -> BindToken
    where
        F: Fn(Arc<TopicMerger>) + Send + Sync + 'static,
    {
        self.register_reader_with_match(key, guid, ring, qos, context, None, bind_callback)
    }

    /// [`register_reader_with_context`](Self::register_reader_with_context)
    /// plus `match_status`, mirroring
    /// [`register_writer_with_match`](Self::register_writer_with_match) --
    /// see its doc for the ordering and the `Err`/`Ok` split.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_reader_with_match<F>(
        self: &Arc<Self>,
        key: MatchKey,
        guid: GUID,
        ring: Arc<IndexRing>,
        qos: EndpointQos,
        context: EndpointContext,
        match_status: Option<Arc<LocalMatchStatus>>,
        bind_callback: F,
    ) -> BindToken
    where
        F: Fn(Arc<TopicMerger>) + Send + Sync + 'static,
    {
        // See `register_writer_with_match`'s matching guard: declared
        // before the write lock, so it drops (and tells any listener
        // reached below) only AFTER the lock is released.
        let _delivering = crate::dds::reader::notices::Delivering::enter();
        let mut endpoints = self.endpoints.write().unwrap_or_else(|e| e.into_inner());

        // Get or create endpoint list for this key
        let entries = endpoints.entry(key.clone()).or_default();
        let endpoint_id = mint_endpoint_id();

        // Auto-bind: find all existing compatible writers and bind to them.
        // Same predicate as register_writer, mirrored direction.
        for existing in entries.iter() {
            if existing.kind != EndpointKind::Writer {
                continue;
            }
            if !scope_allows(existing.context, context) {
                continue;
            }
            // See `register_writer_with_match`: status belongs here only
            // when SEDP can never report this exact pair.
            let report_status = local_status_applies(existing.context, context);
            if let Err(policy_id) = qos_verdict(&existing.qos, &qos) {
                log::debug!(
                    "[DomainRegistry] Skipping local bind: writer {:?}/{:?}, reader {:?}/{:?}",
                    existing.qos,
                    existing.context,
                    qos,
                    context
                );
                if report_status {
                    if let Some(ref status) = existing.match_status {
                        status.fire_incompat(policy_id);
                    }
                    if let Some(ref status) = match_status {
                        status.fire_incompat(policy_id);
                    }
                }
                continue;
            }
            // Match status before the data bind: a late reader catching up
            // to an existing TRANSIENT_LOCAL writer is told of the match
            // before `bind_callback` replays that writer's history into it.
            if report_status {
                if let Some(ref status) = existing.match_status {
                    status.fire_match(endpoint_id, match_status.as_ref().map(|s| s.identity()));
                }
                if let Some(ref status) = match_status {
                    status.fire_match(
                        existing.endpoint_id,
                        existing.match_status.as_ref().map(|s| s.identity()),
                    );
                }
            }
            if let Some(ref merger) = existing.merger {
                log::debug!(
                    "[DomainRegistry] Auto-binding new reader {} to writer {}",
                    guid,
                    existing.guid
                );
                bind_callback(merger.clone());
            }
        }

        let entry = LocalEndpointEntry {
            endpoint_id,
            guid,
            kind: EndpointKind::Reader,
            context,
            qos,
            merger: None,
            ring: Some(ring),
            bind_callback: Some(Box::new(bind_callback)),
            match_status,
        };

        entries.push(entry);

        BindToken::new(self, key, endpoint_id)
    }

    /// Unregister an endpoint (called by BindToken::drop)
    ///
    /// Matches on the process-unique `endpoint_id`, never on the GUID: with
    /// GUID matching, dropping one `GUID::zero()` reader would purge every
    /// zero-GUID endpoint on the key.
    fn unregister(&self, key: &MatchKey, endpoint_id: u64) {
        // See `register_writer_with_match`'s matching guard: declared
        // before the write lock, so a `fire_unmatch` below -- reached
        // through a surviving peer's listener via `notices::notify` --
        // is told only AFTER the lock drops, never while this (or any
        // caller re-entering the registry from that listener) still
        // holds it. `BindToken::drop` runs with no `Delivering`/`Scope`
        // of its own (a `DataReader`/`DataWriter` dropping, or a
        // listener deleting its own matched peer), so this is the only
        // place that guarantees it for unregistration.
        let _delivering = crate::dds::reader::notices::Delivering::enter();
        let mut endpoints = self.endpoints.write().unwrap_or_else(|e| e.into_inner());

        if let Some(entries) = endpoints.get_mut(key) {
            if let Some(idx) = entries.iter().position(|e| e.endpoint_id == endpoint_id) {
                entries.remove(idx);
                // current_count must also go down when a matched peer is
                // deleted (DDS v1.4 Sec.2.2.4.1): tell every SURVIVING
                // entry on this key -- a no-op (`fire_unmatch`) for one
                // that was never matched with `endpoint_id`, so this never
                // needs to know which entries were this one's peers.
                for remaining in entries.iter() {
                    if let Some(ref status) = remaining.match_status {
                        status.fire_unmatch(endpoint_id);
                    }
                }
            }

            // Clean up empty entry lists
            if entries.is_empty() {
                endpoints.remove(key);
            }
        }

        log::debug!(
            "[DomainRegistry] Unregistered endpoint id={} from topic '{}'",
            endpoint_id,
            key.topic_name
        );
    }

    /// Find all writers matching a key
    pub fn find_writers(&self, key: &MatchKey) -> Vec<Arc<TopicMerger>> {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());

        endpoints
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.kind == EndpointKind::Writer)
                    .filter_map(|e| e.merger.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find all readers matching a key
    pub fn find_readers(&self, key: &MatchKey) -> Vec<Arc<IndexRing>> {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());

        endpoints
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.kind == EndpointKind::Reader)
                    .filter_map(|e| e.ring.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get count of endpoints
    pub fn endpoint_count(&self) -> usize {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());
        endpoints.values().map(|v| v.len()).sum()
    }

    /// Get count of endpoints for a specific key
    pub fn endpoint_count_for_key(&self, key: &MatchKey) -> usize {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());
        endpoints.get(key).map(|v| v.len()).unwrap_or(0)
    }
}

impl std::fmt::Debug for DomainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainState")
            .field("domain_id", &self.domain_id)
            .field("endpoint_count", &self.endpoint_count())
            .finish()
    }
}

/// Global domain registry (singleton)
///
/// Thread-safe access to domain states across the process.
pub struct DomainRegistry {
    domains: Mutex<HashMap<DomainId, Weak<DomainState>>>,
}

impl DomainRegistry {
    /// Create new registry
    fn new() -> Self {
        Self {
            domains: Mutex::new(HashMap::new()),
        }
    }

    /// Get the global registry instance
    pub fn global() -> &'static DomainRegistry {
        use std::sync::OnceLock;
        static REGISTRY: OnceLock<DomainRegistry> = OnceLock::new();
        REGISTRY.get_or_init(DomainRegistry::new)
    }

    /// Get or create domain state for a domain ID
    ///
    /// Returns an Arc to the DomainState. The caller (Participant) should
    /// hold this Arc to keep the domain alive.
    pub fn get_or_create(&self, domain_id: DomainId) -> Arc<DomainState> {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());

        // Check if domain exists and is still alive
        if let Some(weak) = domains.get(&domain_id) {
            if let Some(strong) = weak.upgrade() {
                return strong;
            }
        }

        // Create new domain state
        let state = Arc::new(DomainState::new(domain_id));
        domains.insert(domain_id, Arc::downgrade(&state));

        log::info!(
            "[DomainRegistry] Created domain state for domain_id={}",
            domain_id
        );

        state
    }

    /// Try to get existing domain state (for testing/debugging)
    pub fn get(&self, domain_id: DomainId) -> Option<Arc<DomainState>> {
        let domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        domains.get(&domain_id).and_then(|w| w.upgrade())
    }

    /// Clean up expired domain references (for testing)
    pub fn cleanup_expired(&self) {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        domains.retain(|_, weak| weak.strong_count() > 0);
    }

    /// Get count of active domains (for testing)
    pub fn active_domain_count(&self) -> usize {
        let domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        domains.values().filter(|w| w.strong_count() > 0).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `register_reader_with_match`'s OWN deferral guard, exercised
    /// directly on a `DomainState` (bypassing `reader/builder.rs`'s own
    /// `Delivering::enter()` wrap around its call to this function, which
    /// would otherwise mask a defect here: an integration test going
    /// through the builder stays protected by that OUTER wrap alone).
    /// A reentrant `on_match` callback registers another reader on the
    /// SAME domain from inside this reader's own registration, which
    /// still holds `endpoints` at the moment the match would otherwise be
    /// told synchronously. The reentrant call is made through
    /// `notices::notify`, exactly as every REAL `on_match`/`on_incompat`
    /// closure built in `writer/builder.rs` and `reader/builder.rs` does
    /// (`crate::dds::reader::notices::notify(move || l.on_..._matched(..))`):
    /// `Delivering` only defers calls that go through `notify`, so a
    /// fixture that re-enters directly, bypassing `notify`, would not
    /// exercise the guard this test is for.
    /// DDS 1.4 2.2.4.1: total_count never decreases and current_count
    /// describes the final membership, even if publication is delayed.
    #[test]
    fn local_match_publication_can_run_during_entity_unwind() {
        use std::sync::mpsc;
        use std::time::Duration;
        struct DepartOnDrop(Arc<LocalMatchStatus>);
        impl Drop for DepartOnDrop {
            fn drop(&mut self) {
                self.0.fire_unmatch(1);
            }
        }
        let status = LocalMatchStatus::new(GUID::zero(), Box::new(|_, _, _, _, _| {}), None);
        status.fire_match(1, None);
        let (done, received) = mpsc::channel();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _departing = DepartOnDrop(status.clone());
                panic!("entity teardown");
            }));
            assert!(result.is_err());
            done.send(status.current_count()).unwrap();
        });
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(5))
                .expect("unwind completed"),
            0
        );
    }

    #[test]
    fn local_match_publication_resumes_after_a_callback_panics() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called = calls.clone();
        let status = LocalMatchStatus::new(
            GUID::zero(),
            Box::new(move |_, _, _, _, _| {
                if called.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("listener failure");
                }
            }),
            None,
        );
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            status.fire_match(1, None);
        }))
        .is_err());
        status.fire_unmatch(1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(status.current_count(), 0);
    }

    #[test]
    fn local_match_publication_cannot_overwrite_a_concurrent_departure() {
        use std::sync::{mpsc, Barrier};
        use std::time::Duration;

        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let received = snapshots.clone();
        let status = LocalMatchStatus::new(
            GUID::zero(),
            Box::new(move |total, tc, current, cc, handle| {
                received
                    .lock()
                    .unwrap()
                    .push((total, tc, current, cc, handle));
            }),
            None,
        );
        let (paused_tx, paused_rx) = mpsc::channel();
        let resume = Arc::new(Barrier::new(2));
        let resume_hook = resume.clone();
        let once = std::sync::atomic::AtomicBool::new(false);
        *status.before_match_publish.lock().unwrap() = Some(Arc::new(move || {
            if !once.swap(true, Ordering::SeqCst) {
                paused_tx.send(()).unwrap();
                resume_hook.wait();
            }
        }));
        let peer = GUID::new([1; 12], [0, 0, 1, 7]);
        let matching = status.clone();
        let thread = std::thread::spawn(move || matching.fire_match(1, Some(peer)));
        paused_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        // This completes while the earlier match publication is paused:
        // callbacks hold no membership lock and a second publisher cannot pass.
        status.fire_unmatch(1);
        assert_eq!(status.current_count(), 0);
        resume.wait();
        thread.join().unwrap();
        assert_eq!(
            *snapshots.lock().unwrap(),
            vec![(1, 1, 1, 1, Some(peer)), (1, 0, 0, -1, Some(peer))]
        );
        assert!(status.matched_guids().is_empty());
    }

    #[test]
    fn register_reader_with_match_defers_its_own_listener() {
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("reentrant/reader-registration", "ReentrantType");

        // A pre-existing writer for the new reader to match against.
        let _writer_token = domain.register_writer(
            key.clone(),
            GUID::zero(),
            Arc::new(TopicMerger::new()),
            EndpointQos::from_reliability(Reliability::BestEffort),
        );

        let domain2 = Arc::clone(&domain);
        let key2 = key.clone();
        let reentered = Arc::new(AtomicBool::new(false));
        let reentered2 = Arc::clone(&reentered);
        let on_match: LocalMatchCallback = Box::new(move |_total, _tc, current, _cc, _lh| {
            if current > 0 && !reentered2.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let domain3 = Arc::clone(&domain2);
                let key3 = key2.clone();
                // Reentrant: registers ANOTHER reader on the same domain
                // from inside this reader's own match callback, through
                // `notify` -- exactly like a real listener dispatch.
                crate::dds::reader::notices::notify(move || {
                    let _ = domain3.register_reader(
                        key3,
                        GUID::zero(),
                        Arc::new(IndexRing::with_capacity(16)),
                        EndpointQos::from_reliability(Reliability::BestEffort),
                        |_merger| {},
                    );
                });
            }
        });
        let status = LocalMatchStatus::new(GUID::zero(), on_match, None);

        let (tx, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _token = domain.register_reader_with_match(
                key,
                GUID::zero(),
                Arc::new(IndexRing::with_capacity(16)),
                EndpointQos::from_reliability(Reliability::BestEffort),
                EndpointContext::default(),
                Some(status),
                |_merger| {},
            );
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(10)).is_ok(),
            "register_reader_with_match deadlocked: its own listener, \
             fired while this call still held `endpoints`, re-entered \
             the registry"
        );
    }

    #[test]
    fn test_type_id_from_name() {
        let id1 = TypeId::from_type_name("Temperature");
        let id2 = TypeId::from_type_name("Temperature");
        let id3 = TypeId::from_type_name("Humidity");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_match_key() {
        let key1 = MatchKey::from_names("sensor/temp", "Temperature");
        let key2 = MatchKey::from_names("sensor/temp", "Temperature");
        let key3 = MatchKey::from_names("sensor/temp", "Humidity");
        let key4 = MatchKey::from_names("sensor/humidity", "Temperature");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3); // different type
        assert_ne!(key1, key4); // different topic
    }

    /// Dropping ONE zero-GUID reader must not purge the others.
    ///
    /// Every intra-bound reader registers as `GUID::zero()`
    /// (`reader/builder.rs`), so unregister must not match on the GUID:
    /// `retain(|e| e.guid != guid)` would remove EVERY zero-GUID endpoint on
    /// the key the moment one of them dropped. Survivors would keep their
    /// existing merger bindings but never auto-bind to any writer created
    /// afterwards -- silent, and shaped like flakiness in any multi-reader
    /// single-process topology (rmw_hdds, demos).
    ///
    /// The assertion that catches it is the LAST one: after dropping reader
    /// A, a NEW writer must still auto-bind to reader B.
    #[test]
    fn dropping_one_zero_guid_reader_keeps_the_others_bindable() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        let binds_a = Arc::new(AtomicUsize::new(0));
        let binds_b = Arc::new(AtomicUsize::new(0));

        let token_a = {
            let binds = Arc::clone(&binds_a);
            domain.register_reader(
                key.clone(),
                GUID::zero(),
                Arc::new(IndexRing::with_capacity(16)),
                EndpointQos::from_reliability(Reliability::BestEffort),
                move |_merger| {
                    binds.fetch_add(1, Ordering::SeqCst);
                },
            )
        };
        let _token_b = {
            let binds = Arc::clone(&binds_b);
            domain.register_reader(
                key.clone(),
                GUID::zero(),
                Arc::new(IndexRing::with_capacity(16)),
                EndpointQos::from_reliability(Reliability::BestEffort),
                move |_merger| {
                    binds.fetch_add(1, Ordering::SeqCst);
                },
            )
        };
        assert_eq!(domain.find_readers(&key).len(), 2);

        // Reader A goes away. ONLY reader A.
        drop(token_a);
        assert_eq!(
            domain.find_readers(&key).len(),
            1,
            "dropping one zero-GUID reader removed {} endpoints instead of 1",
            2 - domain.find_readers(&key).len()
        );

        // A writer created AFTER the drop must still find reader B.
        let _writer_token = domain.register_writer(
            key.clone(),
            GUID::zero(),
            Arc::new(TopicMerger::new()),
            EndpointQos::from_reliability(Reliability::BestEffort),
        );
        assert_eq!(
            binds_b.load(Ordering::SeqCst),
            1,
            "the surviving reader was never auto-bound to the new writer: its \
             registry entry was purged along with the dropped reader's"
        );
        assert_eq!(
            binds_a.load(Ordering::SeqCst),
            0,
            "the DROPPED reader was bound to the new writer"
        );
    }

    #[test]
    fn wire_writer_does_not_bind_cross_participant_reader_writer_first() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/wire-scope", "TestType");
        let writer_token = ParticipantToken(1);
        let other_token = ParticipantToken(2);
        let merger = Arc::new(TopicMerger::new());

        let _writer = domain.register_writer_with_context(
            key.clone(),
            GUID::zero(),
            Arc::clone(&merger),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(writer_token), true),
        );

        let cross_binds = Arc::new(AtomicUsize::new(0));
        let cross_binds_cb = Arc::clone(&cross_binds);
        let _cross_reader = domain.register_reader_with_context(
            key.clone(),
            GUID::zero(),
            Arc::new(IndexRing::with_capacity(16)),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(other_token), true),
            move |_| {
                cross_binds_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        let same_binds = Arc::new(AtomicUsize::new(0));
        let same_binds_cb = Arc::clone(&same_binds);
        let _same_reader = domain.register_reader_with_context(
            key,
            GUID::zero(),
            Arc::new(IndexRing::with_capacity(16)),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(writer_token), true),
            move |_| {
                same_binds_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        assert_eq!(cross_binds.load(Ordering::SeqCst), 0);
        assert_eq!(same_binds.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wire_writer_does_not_bind_cross_participant_reader_reader_first() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/wire-scope", "TestType");
        let writer_token = ParticipantToken(1);
        let other_token = ParticipantToken(2);

        let cross_binds = Arc::new(AtomicUsize::new(0));
        let cross_binds_cb = Arc::clone(&cross_binds);
        let _cross_reader = domain.register_reader_with_context(
            key.clone(),
            GUID::zero(),
            Arc::new(IndexRing::with_capacity(16)),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(other_token), true),
            move |_| {
                cross_binds_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        let same_binds = Arc::new(AtomicUsize::new(0));
        let same_binds_cb = Arc::clone(&same_binds);
        let _same_reader = domain.register_reader_with_context(
            key.clone(),
            GUID::zero(),
            Arc::new(IndexRing::with_capacity(16)),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(writer_token), true),
            move |_| {
                same_binds_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        let _writer = domain.register_writer_with_context(
            key,
            GUID::zero(),
            Arc::new(TopicMerger::new()),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(writer_token), true),
        );

        assert_eq!(cross_binds.load(Ordering::SeqCst), 0);
        assert_eq!(same_binds.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn intra_only_writer_still_binds_cross_participant_reader() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/intra-scope", "TestType");
        let binds = Arc::new(AtomicUsize::new(0));
        let binds_cb = Arc::clone(&binds);
        let _reader = domain.register_reader_with_context(
            key.clone(),
            GUID::zero(),
            Arc::new(IndexRing::with_capacity(16)),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(ParticipantToken(2)), false),
            move |_| {
                binds_cb.fetch_add(1, Ordering::SeqCst);
            },
        );
        let _writer = domain.register_writer_with_context(
            key,
            GUID::zero(),
            Arc::new(TopicMerger::new()),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(ParticipantToken(1)), false),
        );

        assert_eq!(binds.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wire_writer_still_binds_intra_only_cross_participant_reader() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/mixed-transport-scope", "TestType");
        let binds = Arc::new(AtomicUsize::new(0));
        let binds_cb = Arc::clone(&binds);
        let _reader = domain.register_reader_with_context(
            key.clone(),
            GUID::zero(),
            Arc::new(IndexRing::with_capacity(16)),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(ParticipantToken(2)), false),
            move |_| {
                binds_cb.fetch_add(1, Ordering::SeqCst);
            },
        );
        let _writer = domain.register_writer_with_context(
            key,
            GUID::zero(),
            Arc::new(TopicMerger::new()),
            EndpointQos::from_reliability(Reliability::BestEffort),
            EndpointContext::new(Some(ParticipantToken(1)), true),
        );

        assert_eq!(binds.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_domain_state_register_writer() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");
        let guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());

        let token = domain.register_writer(
            key.clone(),
            guid,
            merger,
            EndpointQos::from_reliability(Reliability::BestEffort),
        );

        assert_eq!(domain.endpoint_count(), 1);
        assert_eq!(domain.endpoint_count_for_key(&key), 1);
        assert_eq!(domain.find_writers(&key).len(), 1);
        assert_eq!(domain.find_readers(&key).len(), 0);

        drop(token);

        assert_eq!(domain.endpoint_count(), 0);
    }

    #[test]
    fn test_domain_state_register_reader() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");
        let guid = GUID::zero();
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let token = domain.register_reader(
            key.clone(),
            guid,
            ring,
            EndpointQos::from_reliability(Reliability::BestEffort),
            |_merger| {
                // Bind callback (not called since no writers)
            },
        );

        assert_eq!(domain.endpoint_count(), 1);
        assert_eq!(domain.endpoint_count_for_key(&key), 1);
        assert_eq!(domain.find_writers(&key).len(), 0);
        assert_eq!(domain.find_readers(&key).len(), 1);

        drop(token);

        assert_eq!(domain.endpoint_count(), 0);
    }

    #[test]
    fn test_auto_bind_writer_first() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register writer first (Reliable)
        let writer_guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());
        let _writer_token = domain.register_writer(
            key.clone(),
            writer_guid,
            merger,
            EndpointQos::from_reliability(Reliability::Reliable),
        );

        // Register reader (BestEffort) - should auto-bind (Reliable writer -> any reader OK)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            EndpointQos::from_reliability(Reliability::BestEffort),
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            bound.load(Ordering::SeqCst),
            "Reader should auto-bind to existing writer"
        );
    }

    #[test]
    fn test_auto_bind_reader_first() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register reader first (BestEffort)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::zero();
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            EndpointQos::from_reliability(Reliability::BestEffort),
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            !bound.load(Ordering::SeqCst),
            "Reader should not bind yet (no writer)"
        );

        // Register writer (BestEffort) - should trigger auto-bind callback
        let writer_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let merger = Arc::new(TopicMerger::new());
        let _writer_token = domain.register_writer(
            key.clone(),
            writer_guid,
            merger,
            EndpointQos::from_reliability(Reliability::BestEffort),
        );

        assert!(
            bound.load(Ordering::SeqCst),
            "Reader should auto-bind when writer appears"
        );
    }

    /// Test: BestEffort writer + Reliable reader = NO BIND (QoS incompatible)
    #[test]
    fn test_qos_besteffort_writer_reliable_reader_no_bind() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register BestEffort writer first
        let writer_guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());
        let _writer_token = domain.register_writer(
            key.clone(),
            writer_guid,
            merger,
            EndpointQos::from_reliability(Reliability::BestEffort),
        );

        // Register Reliable reader - should NOT auto-bind (incompatible QoS)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            EndpointQos::from_reliability(Reliability::Reliable),
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            !bound.load(Ordering::SeqCst),
            "Reliable reader should NOT bind to BestEffort writer"
        );
    }

    /// The in-process binding follows the one QoS verdict (`rxo_verdict`),
    /// whichever endpoint registers first: a pair it refuses on DURABILITY,
    /// DEADLINE or DATA_REPRESENTATION is not bound (DDS v1.4 Sec.2.2.3: no
    /// communication between incompatible endpoints), a pair it accepts is.
    /// Only RELIABILITY, PARTITION and the OWNERSHIP kind were judged: a
    /// VOLATILE writer fed a TRANSIENT_LOCAL reader both ends reported
    /// incompatible.
    #[test]
    fn the_binding_follows_the_one_qos_verdict() {
        use crate::dds::qos::QoS;
        use std::sync::atomic::{AtomicBool, Ordering};

        let cases = [
            (
                "volatile -> transient-local",
                QoS::reliable(),
                QoS::reliable().transient_local(),
                false,
            ),
            (
                "transient-local -> volatile",
                QoS::reliable().transient_local(),
                QoS::reliable(),
                true,
            ),
            (
                "deadline 200 -> 100",
                QoS::reliable().deadline_millis(200),
                QoS::reliable().deadline_millis(100),
                false,
            ),
            (
                "deadline 100 -> 200",
                QoS::reliable().deadline_millis(100),
                QoS::reliable().deadline_millis(200),
                true,
            ),
            (
                "xcdr1 -> xcdr2",
                QoS::reliable().data_representation_xcdr1(),
                QoS::reliable().data_representation_xcdr2(),
                false,
            ),
        ];
        let native = crate::dds::cdr_negotiation::Xcdr1Encoding::native();
        for (label, writer_qos, reader_qos, binds) in cases {
            for reader_first in [false, true] {
                let domain = Arc::new(DomainState::new(0));
                let key = MatchKey::from_names("verdict/topic", "VerdictType");
                let bound = Arc::new(AtomicBool::new(false));
                let register_writer = || {
                    domain.register_writer(
                        key.clone(),
                        GUID::zero(),
                        Arc::new(TopicMerger::new()),
                        EndpointQos::new(&writer_qos, native),
                    )
                };
                let register_reader = || {
                    let flag = Arc::clone(&bound);
                    domain.register_reader(
                        key.clone(),
                        GUID::new([0; 12], [0, 0, 0, 1]),
                        Arc::new(IndexRing::with_capacity(16)),
                        EndpointQos::new(&reader_qos, native),
                        move |_| flag.store(true, Ordering::SeqCst),
                    )
                };
                let _tokens = if reader_first {
                    let reader = register_reader();
                    (register_writer(), reader)
                } else {
                    let writer = register_writer();
                    (writer, register_reader())
                };
                assert_eq!(
                    bound.load(Ordering::SeqCst),
                    binds,
                    "{label} (reader first: {reader_first})"
                );
            }
        }
    }

    /// Both ends of an in-process (intra) pair are a real Rust type in
    /// THIS process, not a remote peer whose type is unknowable over the
    /// wire -- so a pair must be refused if EITHER end's type refuses
    /// XCDR1, not only the reader's (`Xcdr1Encoding::either_refuses`).
    /// Regression for `pair_delivers` reading only `reader.xcdr1`: two
    /// Rust types sharing a `MatchKey` (same topic/type name) but
    /// compiled with different `encodes_xcdr1_natively()` answers (the
    /// task's "two Rust types with the same name, different XCDR1
    /// capability") must not bind merely because the READER's type
    /// happens to be XCDR1-native.
    #[test]
    fn the_binding_refuses_xcdr1_if_either_side_refuses_it() {
        use crate::core::types::TypeDescriptor;
        use crate::dds::qos::QoS;
        use std::sync::atomic::{AtomicBool, Ordering};

        // A descriptor that makes `Xcdr1Encoding::from` compute "refuses
        // XCDR1" (`type_requires_native_xcdr1`: variable-size AND aligned
        // >= 8), standing in for a type whose encoder serializes a
        // variable-size member under the XCDR2 alignment even when asked
        // for XCDR1 (hdds_gen's guess for a `sequence` of 8-byte elements).
        static REFUSING: TypeDescriptor =
            TypeDescriptor::new(0xDEAD_BEEF, "RefusesXcdr1", 16, 8, true, &[]);
        let refusing = crate::dds::cdr_negotiation::Xcdr1Encoding::from(&REFUSING);
        let native = crate::dds::cdr_negotiation::Xcdr1Encoding::native();
        assert!(
            refusing.refuses_xcdr1(),
            "fixture sanity: REFUSING must actually refuse XCDR1"
        );
        assert!(
            !native.refuses_xcdr1(),
            "fixture sanity: native() must not refuse XCDR1"
        );

        // A writer offering XCDR1 and a reader that set no
        // DATA_REPRESENTATION (it announces, and is judged as requesting,
        // `[XCDR, XCDR2]`, `local_reader_qos_for_verdict`) negotiate XCDR1,
        // which is exactly the case `rxo_verdict`'s `xcdr1` parameter gates.
        let writer_qos = QoS::default().data_representation_xcdr1();
        let qos = QoS::default();

        for (label, writer_xcdr1, reader_xcdr1, binds) in [
            ("both native", native, native, true),
            ("writer refuses, reader native", refusing, native, false),
            ("writer native, reader refuses", native, refusing, false),
            ("both refuse", refusing, refusing, false),
        ] {
            let domain = Arc::new(DomainState::new(0));
            let key = MatchKey::from_names("verdict/xcdr1-topic", "VerdictXcdr1Type");
            let bound = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&bound);
            let _writer = domain.register_writer(
                key.clone(),
                GUID::zero(),
                Arc::new(TopicMerger::new()),
                EndpointQos::new(&writer_qos, writer_xcdr1),
            );
            let _reader = domain.register_reader(
                key,
                GUID::new([0; 12], [0, 0, 0, 1]),
                Arc::new(IndexRing::with_capacity(16)),
                EndpointQos::new(&qos, reader_xcdr1),
                move |_| flag.store(true, Ordering::SeqCst),
            );
            assert_eq!(bound.load(Ordering::SeqCst), binds, "{label}");
        }
    }

    /// A reader that set no DATA_REPRESENTATION requests `[XCDR, XCDR2]` as
    /// it announces (`local_reader_qos_for_verdict`). A writer that set none
    /// is resolved at creation (`resolve_writer_data_representation`): XCDR,
    /// or XCDR2 for a type that refuses XCDR. Either binds to such a reader,
    /// and so does an XCDR2 writer, with no refusal on XCDR1 grounds the
    /// pair does not negotiate.
    #[test]
    fn a_reader_that_set_no_representation_binds_as_it_announces() {
        use crate::core::types::TypeDescriptor;
        use crate::dds::cdr_negotiation::{resolve_writer_data_representation, Xcdr1Encoding};
        use crate::dds::qos::QoS;
        use std::sync::atomic::{AtomicBool, Ordering};

        static REFUSING: TypeDescriptor =
            TypeDescriptor::new(0xDEAD_BEE0, "RefusesXcdr1Too", 16, 8, true, &[]);
        let refusing = Xcdr1Encoding::from(&REFUSING);
        assert!(refusing.refuses_xcdr1(), "fixture sanity");
        let native = Xcdr1Encoding::native();
        let resolved = |xcdr1| {
            let mut qos = QoS::default();
            resolve_writer_data_representation(&mut qos, xcdr1).expect("resolved");
            qos
        };

        for (label, writer_qos, xcdr1) in [
            ("refusing writer set none", resolved(refusing), refusing),
            ("native writer set none", resolved(native), native),
            (
                "writer offers XCDR2",
                QoS::default().data_representation_xcdr2(),
                refusing,
            ),
        ] {
            let domain = Arc::new(DomainState::new(0));
            let key = MatchKey::from_names("verdict/default-rep", "DefaultRepType");
            let bound = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&bound);
            let _writer = domain.register_writer(
                key.clone(),
                GUID::zero(),
                Arc::new(TopicMerger::new()),
                EndpointQos::new(&writer_qos, xcdr1),
            );
            let _reader = domain.register_reader(
                key,
                GUID::new([0; 12], [0, 0, 0, 1]),
                Arc::new(IndexRing::with_capacity(16)),
                EndpointQos::new(&QoS::default(), xcdr1),
                move |_| flag.store(true, Ordering::SeqCst),
            );
            assert!(bound.load(Ordering::SeqCst), "{label}");
        }
    }

    /// Test: Reliable writer + BestEffort reader = BIND (QoS compatible)
    #[test]
    fn test_qos_reliable_writer_besteffort_reader_binds() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register Reliable writer first
        let writer_guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());
        let _writer_token = domain.register_writer(
            key.clone(),
            writer_guid,
            merger,
            EndpointQos::from_reliability(Reliability::Reliable),
        );

        // Register BestEffort reader - should auto-bind (Reliable writer compatible with any reader)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            EndpointQos::from_reliability(Reliability::BestEffort),
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            bound.load(Ordering::SeqCst),
            "BestEffort reader should bind to Reliable writer"
        );
    }

    /// Test: Reader first, then BestEffort writer - Reliable reader should NOT bind
    #[test]
    fn test_qos_reader_first_besteffort_writer_no_bind() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register Reliable reader first
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::zero();
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            EndpointQos::from_reliability(Reliability::Reliable),
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        // Register BestEffort writer - should NOT trigger auto-bind (incompatible QoS)
        let writer_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let merger = Arc::new(TopicMerger::new());
        let _writer_token = domain.register_writer(
            key.clone(),
            writer_guid,
            merger,
            EndpointQos::from_reliability(Reliability::BestEffort),
        );

        assert!(
            !bound.load(Ordering::SeqCst),
            "Reliable reader should NOT bind when BestEffort writer appears"
        );
    }

    #[test]
    fn test_domain_registry_get_or_create() {
        let registry = DomainRegistry::global();

        let domain1 = registry.get_or_create(42);
        let domain2 = registry.get_or_create(42);

        assert!(Arc::ptr_eq(&domain1, &domain2));
        assert_eq!(domain1.domain_id, 42);
    }

    #[test]
    fn test_domain_registry_cleanup() {
        // Use a local registry for isolated test
        let registry = DomainRegistry::new();

        {
            let _domain = registry.get_or_create(99);
            assert_eq!(registry.active_domain_count(), 1);
        }

        // Domain dropped, weak ref should be dead
        registry.cleanup_expired();
        assert_eq!(registry.active_domain_count(), 0);
    }

    #[test]
    fn test_bind_token_unregisters_on_drop() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");
        let guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());

        {
            let _token = domain.register_writer(
                key.clone(),
                guid,
                merger,
                EndpointQos::from_reliability(Reliability::BestEffort),
            );
            assert_eq!(domain.endpoint_count(), 1);
        }

        // Token dropped - endpoint should be unregistered
        assert_eq!(domain.endpoint_count(), 0);
    }

    #[test]
    fn test_multiple_writers_same_topic() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        let guid1 = GUID::zero();
        let guid2 = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let merger1 = Arc::new(TopicMerger::new());
        let merger2 = Arc::new(TopicMerger::new());

        let _token1 = domain.register_writer(
            key.clone(),
            guid1,
            merger1,
            EndpointQos::from_reliability(Reliability::BestEffort),
        );
        let _token2 = domain.register_writer(
            key.clone(),
            guid2,
            merger2,
            EndpointQos::from_reliability(Reliability::Reliable),
        );

        assert_eq!(domain.endpoint_count_for_key(&key), 2);
        assert_eq!(domain.find_writers(&key).len(), 2);
    }

    /// Integration test: verify end-to-end intra-process data flow
    ///
    /// This test verifies that:
    /// 1. Writer registration populates the merger
    /// 2. Reader auto-binds to writer via callback
    /// 3. Data written to merger reaches the reader's ring
    #[test]
    fn test_intra_process_data_flow() {
        use crate::core::rt::{get_slab_pool, IndexEntry};

        // Initialize slab pool for data allocation
        let _ = crate::core::rt::init_slab_pool();

        let domain = Arc::new(DomainState::new(42));
        let key = MatchKey::from_names("sensor/temp", "Temperature");

        // Create writer's merger
        let writer_merger = Arc::new(TopicMerger::new());
        let writer_guid = GUID::zero();

        // Register writer (Reliable for this test)
        let _writer_token = domain.register_writer(
            key.clone(),
            writer_guid,
            writer_merger.clone(),
            EndpointQos::from_reliability(Reliability::Reliable),
        );

        // Create reader's ring
        let reader_ring = Arc::new(IndexRing::with_capacity(16));
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);

        // Track binding
        use std::sync::atomic::{AtomicUsize, Ordering};
        let bind_count = Arc::new(AtomicUsize::new(0));
        let bind_count_clone = bind_count.clone();

        // Clone ring for callback
        let ring_for_callback = reader_ring.clone();

        // Register reader (BestEffort) - should auto-bind to existing Reliable writer
        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            reader_ring.clone(),
            EndpointQos::from_reliability(Reliability::BestEffort),
            move |merger| {
                bind_count_clone.fetch_add(1, Ordering::SeqCst);

                // Create notification (no-op for test)
                let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});

                // Register with merger
                let registration =
                    crate::core::rt::MergerReader::new(ring_for_callback.clone(), notify);
                merger.add_reader(registration);
            },
        );

        assert_eq!(
            bind_count.load(Ordering::SeqCst),
            1,
            "Reader should bind once to writer"
        );
        assert_eq!(
            writer_merger.reader_count(),
            1,
            "Writer merger should have 1 reader"
        );

        // Write data through merger
        let slab_pool = get_slab_pool();
        let data = b"Hello intra-process!";
        let (handle, _metric) = slab_pool
            .reserve_and_write(data, crate::core::rt::Claim::Reader)
            .expect("slab reserve");

        let entry = IndexEntry {
            seq: 1,
            handle,
            len: data.len() as u32,
            flags: 0x01,
            timestamp_ns: 0,
            cdr_version: crate::dds::CdrVersion::Xcdr2,
        };

        let push_ok = writer_merger.push(entry, &slab_pool);
        assert!(push_ok, "Merger push should succeed");

        // Read data from reader's ring
        let received = reader_ring.pop();
        assert!(received.is_some(), "Reader should receive data");

        let received_entry = received.unwrap();
        assert_eq!(received_entry.seq, 1);
        assert_eq!(received_entry.len, data.len() as u32);

        // Verify data content
        let received_buf = slab_pool.get_buffer(received_entry.handle);
        assert_eq!(&received_buf[..data.len()], data);

        // Cleanup
        slab_pool.release(received_entry.handle);
    }
}
