// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery FSM core: participant database and SPDP/SEDP handlers.
//!
//!
//! Implements `DiscoveryFsm` which maintains `ParticipantDB` and processes
//! incoming discovery packets from the multicast listener thread.

use super::endpoint::{EndpointInfo, EndpointKind};
use super::metrics::DiscoveryMetrics;
use super::registry::TopicRegistry;
#[cfg(feature = "security")]
use super::withheld::{WithheldReplay, WithheldReplays};
use crate::core::discovery::multicast::ParticipantInfo;
use crate::core::discovery::{EndpointRegistry, ReplayRegistry, GUID};
use crate::dds::qos::Durability;
use crate::protocol::dialect::Dialect;
use crate::protocol::discovery::{SedpData, SpdpData};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

/// One reader of a topic as a writer routes a packet to it
/// ([`DiscoveryFsm::reader_routes_for_topic`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReaderRoute {
    /// The reader's GUID.
    pub(crate) endpoint_guid: GUID,
    /// Its participant's GUID, as `EndpointInfo::participant_guid` holds it.
    pub(crate) participant_guid: GUID,
    /// Whether its QoS is compatible with the writer's PARTITION.
    pub(crate) compatible: bool,
}

fn participant_lease_expired(elapsed_ms: u64, lease_duration_ms: u64) -> bool {
    lease_duration_ms != u64::MAX && elapsed_ms >= lease_duration_ms
}

/// Listener for discovery events (endpoints only).
pub trait DiscoveryListener: Send + Sync {
    /// Called when a new endpoint is discovered AND the local
    /// participant has decided it is a real match candidate (the
    /// owning remote participant has been confirmed alive). Listeners
    /// should fire `on_publication_matched` /
    /// `on_subscription_matched` from this hook -- NOT incompatible
    /// QoS events; those are fired from
    /// `on_endpoint_discovered_incompat_only` so that QoS mismatches
    /// surface immediately even while the surfacing-gate is still
    /// holding the endpoint back for participant-confirmation reasons.
    fn on_endpoint_discovered(&self, endpoint: EndpointInfo);

    /// Called for every newly discovered endpoint regardless of
    /// participant confirmation status. Listeners should fire
    /// `on_offered_incompatible_qos` /
    /// `on_requested_incompatible_qos` from this hook when the
    /// remote QoS does not match the local entry's offered/requested
    /// values. The split exists because participant-confirmation
    /// gating (`handle_sedp`'s deferral against stale-test SPDP/SEDP
    /// contamination) would withhold legitimate incompat events
    /// long enough to miss a conformance harness's 5 s check window;
    /// QoS-compat verdicts are participant-local and safe to publish
    /// immediately, only the "match-status" side actually needs the
    /// gate. Default implementation drops the endpoint so listeners
    /// that don't care about incompat events don't have to react --
    /// the `drop` is explicit so the body is not empty.
    fn on_endpoint_discovered_incompat_only(&self, endpoint: EndpointInfo) {
        drop(endpoint);
    }

    /// Called after an endpoint has been removed from the discovery
    /// registries. Discovery locks are released before this hook runs so a
    /// listener may query discovery state without deadlocking.
    fn on_endpoint_removed(&self, endpoint: EndpointInfo) {
        drop(endpoint);
    }

    /// Called once when a remote participant left: on every removal from
    /// discovery - it disposed its SPDP instance or said a lease-0
    /// farewell, its lease expired, a probation or zombie purge (one that
    /// fell silent may have delivered samples), an explicit removal - and
    /// when a participant that authenticates again over a completed session
    /// loses its old endpoint records (it may be a new process under the
    /// same prefix). Its writers are gone, so the instances they wrote lose
    /// their writers (DDS v1.4 Sec.2.2.2.5.1.3). Runs before
    /// `on_endpoint_removed` for its endpoints, with no discovery lock held.
    fn on_participant_departed(&self, participant: GUID) {
        let _ = participant;
    }

    /// [`on_participant_departed`](Self::on_participant_departed), with
    /// whether the participant announced its departure (its SPDP dispose or
    /// lease-0 farewell: `announced`) or was removed without a word (lease
    /// expiry, probation or zombie purge, a new authentication). Default:
    /// `on_participant_departed`.
    fn on_participant_left(&self, participant: GUID, announced: bool) {
        let _ = announced;
        self.on_participant_departed(participant);
    }

    /// Called once when a remote participant was removed from discovery -
    /// its lease expired, a probation or zombie purge, a departure in the
    /// dispose form, an explicit removal - right after
    /// `on_participant_departed` and with no discovery lock held. Not for a
    /// lease-0 farewell (the 1.4.x form), whose announcement the SPDP handler
    /// still goes on to answer: forgetting there would re-announce to a
    /// participant that is leaving.
    ///
    /// What a participant records about a peer to avoid repeating itself (an
    /// answered announcement, a completed SEDP re-announcement) must not
    /// outlive the peer: one that comes back under the same prefix is a new
    /// peer.
    fn on_participant_forgotten(&self, participant: GUID) {
        let _ = participant;
    }

    /// Called when the GROUP dialect spoken with a known participant changed
    /// (an SPDP brought or changed its capabilities), with the dialect now
    /// spoken (`group_dialect_of`) and the participant's writers discovery
    /// knows, each with its Publisher: what was decided of them at their
    /// discovery no longer holds. No discovery lock held.
    fn on_participant_dialect_changed(
        &self,
        dialect: crate::protocol::group::GroupDialect,
        writers: &[([u8; 16], Option<[u8; 4]>)],
    ) {
        let _ = (dialect, writers);
    }

    /// Called with the legacy key-hash flag of a known participant
    /// (`DiscoveryFsm::legacy_key_hash_known`: HDDS without
    /// `CAP_CONFORMANT_KEY_HASH`) and the GUIDs of its writers discovery
    /// knows, each time their vendor-level decisions are taken again: with
    /// every `on_participant_dialect_changed`, and once the participant is
    /// discovered. No discovery lock held.
    fn on_participant_key_hash_decided(&self, legacy_key_hash: bool, writers: &[[u8; 16]]) {
        let _ = (legacy_key_hash, writers);
    }
}

/// Security validator for participant authentication (DDS Security v1.1).
///
/// Implement this trait to add security validation to discovery.
/// When a participant announces with an identity_token, this validator
/// is called to verify the certificate before allowing the participant.
pub trait SecurityValidator: Send + Sync {
    /// Validate a remote participant's identity token.
    ///
    /// # Arguments
    /// - `participant_guid`: GUID of the remote participant
    /// - `identity_token`: X.509 certificate (PEM-encoded) from SPDP data
    ///
    /// # Returns
    /// - `Ok(())` if the identity is valid and trusted
    /// - `Err(reason)` if the identity should be rejected
    fn validate_identity(
        &self,
        participant_guid: GUID,
        identity_token: &[u8],
    ) -> Result<(), String>;
}

/// Participant database type.
///
/// Maps participant GUID to participant metadata.
/// Wrapped in `Arc<RwLock<...>>` for concurrent access.
pub type ParticipantDB = HashMap<GUID, ParticipantInfo>;

/// An IPv4 subnet we are on: one of our own addresses and its prefix length.
type LocalSubnet = (std::net::Ipv4Addr, u8);

/// Our own IPv4 subnets, as (address, prefix length) pairs.
///
/// Cached behind a short TTL: this is consulted once per discovery message and
/// `getifaddrs` is a syscall, but the answer is not constant either - addresses
/// change under IP mobility, so capturing once at startup would answer with a
/// topology that no longer exists.
fn local_subnets() -> Vec<LocalSubnet> {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    /// The captured set, with the instant it was captured.
    type Cache = Mutex<Option<(Instant, Vec<LocalSubnet>)>>;

    const TTL: Duration = Duration::from_secs(2);
    static CACHE: OnceLock<Cache> = OnceLock::new();

    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let mut slot = match cache.lock() {
        Ok(slot) => slot,
        // A poisoned cache is not a reason to mis-route: fall back to a fresh
        // capture rather than propagating a panic into the discovery thread.
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some((captured_at, subnets)) = slot.as_ref() {
        if captured_at.elapsed() < TTL {
            return subnets.clone();
        }
    }

    let subnets: Vec<LocalSubnet> =
        crate::transport::ifaddrs::InterfaceSnapshot::capture_or_empty()
            .addresses()
            .iter()
            .filter(|entry| !entry.loopback)
            .filter_map(|entry| match (entry.addr, entry.prefix_len) {
                (std::net::IpAddr::V4(addr), Some(prefix)) if prefix <= 32 => Some((addr, prefix)),
                _ => None,
            })
            .collect();

    *slot = Some((Instant::now(), subnets.clone()));
    subnets
}

/// True when `addr` sits in the subnet `(network, prefix)`.
fn in_subnet(addr: std::net::Ipv4Addr, network: std::net::Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        // A default route is not a subnet membership claim: treating it as one
        // would make every address "local".
        return false;
    }
    let shift = 32 - u32::from(prefix);
    let mask = u32::MAX.checked_shl(shift).unwrap_or(u32::MAX);
    (u32::from(addr) & mask) == (u32::from(network) & mask)
}

/// True when the public Internet can route to `addr`.
///
/// `Ipv4Addr::is_global` is still unstable, and the exact set matters here: a
/// carrier-grade NAT address (100.64/10) is NOT reachable from outside the
/// carrier, so it belongs with the private ranges rather than the routable
/// ones. Getting that wrong would make us prefer an address that answers for
/// somebody else's subscriber.
fn is_globally_routable(addr: std::net::Ipv4Addr) -> bool {
    let octets = addr.octets();
    !(addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_unspecified()
        || addr.is_documentation()
        || octets[0] == 0
        // 100.64/10, carrier-grade NAT
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        // 240/4, reserved
        || octets[0] >= 240)
}

/// The Docker default bridge, which every host runs and no two hosts share.
fn is_docker_bridge(addr: std::net::Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 172 && octets[1] == 17
}

/// Select the locator to send to, from what a peer announced.
///
/// **The choice belongs to the receiver**, because only the receiver knows its
/// own topology. A private address is not an identity: `192.168.1.50` names a
/// different machine on every LAN that uses that prefix. The announcing peer
/// cannot know which of its addresses we can reach; we can.
///
/// Preference order:
/// 1. An address inside one of OUR OWN subnets - reachable directly, no router.
/// 2. A globally routable address - reachable across the Internet, and what a
///    relay or a NAT mapping looks like.
/// 3. Any other non-Docker, non-loopback address. This stays as a
///    fallback: routed private networks
///    (192.168.1.0/24 to 192.168.2.0/24 through a router) are real and must
///    keep working.
/// 4. Any non-unspecified address.
///
/// Passes 1 and 2 come before pass 3: otherwise pass 3 would make a foreign
/// private address the PREFERRED choice. With a Discovery Server
/// reachable over the WAN - a configuration this product documents - two
/// participants behind different NATs each learn the other's private addresses,
/// and send their data to whatever machine happens to answer at that address on
/// their own LAN. Preferring our own subnet first keeps every LAN deployment on
/// exactly the address it used before.
fn select_best_locator(locators: &[std::net::SocketAddr]) -> Option<&std::net::SocketAddr> {
    select_best_locator_among(locators, &local_subnets())
}

/// A locator this host can reach without anyone's help, if there is one.
///
/// These are passes 1 and 2 of [`select_best_locator_among`], named because a
/// second caller needs the same answer to a different question: the Discovery
/// Server relay has to know whether a peer is reachable AT ALL before it
/// spends a synthetic locator on it. Two copies of this rule would drift, and
/// the drift would be invisible - one of them would quietly relay traffic
/// that had a perfectly good direct route, or leave a peer unreachable that
/// the other considered handled.
///
/// 1. One of our own subnets - except the Docker default bridge.
///
///    EVERY host that runs Docker has 172.17.0.0/16, so sharing it proves
///    nothing: a peer announcing 172.17.0.2 names a container on ITS host,
///    and if we are on that bridge too we would send to one of OUR OWN
///    containers. The first pass excludes this range
///    for the same reason.
/// 2. Reachable across the Internet.
fn direct_route_among<'a>(
    locators: &'a [std::net::SocketAddr],
    local_subnets: &[LocalSubnet],
) -> Option<&'a std::net::SocketAddr> {
    use std::net::IpAddr;

    let usable_v4 = |addr: &&'a std::net::SocketAddr| -> Option<std::net::Ipv4Addr> {
        match addr.ip() {
            IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
            _ => None,
        }
    };

    let same_subnet = locators.iter().find(|addr| {
        usable_v4(addr).is_some_and(|v4| {
            !is_docker_bridge(v4)
                && local_subnets
                    .iter()
                    .any(|&(network, prefix)| in_subnet(v4, network, prefix))
        })
    });
    if same_subnet.is_some() {
        return same_subnet;
    }

    locators
        .iter()
        .find(|addr| usable_v4(addr).is_some_and(is_globally_routable))
}

/// Whether any of `locators` can be reached from this host without a relay.
///
/// The question the Discovery Server relay asks of every peer it learns
/// about. `false` means every address the peer announced is either on a
/// private network that is not ours or on a range nothing routes - so no
/// datagram we send it can arrive, and only a relay can carry one.
pub(crate) fn has_direct_route(locators: &[std::net::SocketAddr]) -> bool {
    direct_route_among(locators, &local_subnets()).is_some()
}

/// [`select_best_locator`] against an explicit view of our own subnets.
///
/// Split out so the ranking can be tested without depending on the addresses
/// of the machine running the test.
fn select_best_locator_among<'a>(
    locators: &'a [std::net::SocketAddr],
    local_subnets: &[LocalSubnet],
) -> Option<&'a std::net::SocketAddr> {
    use std::net::IpAddr;

    let usable_v4 = |addr: &&'a std::net::SocketAddr| -> Option<std::net::Ipv4Addr> {
        match addr.ip() {
            IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
            // IPv6 is not selected: the transport binds IPv4 sockets, so an
            // IPv6 locator would fail on every send.
            _ => None,
        }
    };

    // Passes 1 and 2: an address we can reach without help.
    if let Some(direct) = direct_route_among(locators, local_subnets) {
        return Some(direct);
    }

    // 3. Fallback: any non-Docker, non-loopback address.
    let fallback = locators
        .iter()
        .find(|addr| usable_v4(addr).is_some_and(|v4| !is_docker_bridge(v4) && !v4.is_loopback()));
    if fallback.is_some() {
        return fallback;
    }

    // 4. Last resort.
    locators.iter().find(|addr| !addr.ip().is_unspecified())
}

/// Discovery Finite State Machine.
///
/// Manages participant database and handles SPDP/SEDP discovery packets.
///
/// # Architecture
/// - Concurrent access via `Arc<RwLock<ParticipantDB>>`
/// - Self-discovery prevention (ignores `local_guid`)
/// - Automatic participant insertion/refresh
///
/// # Thread Safety
/// - `handle_spdp` and `handle_sedp` can be called concurrently
/// - DB reads are lock-free (`RwLock::read`)
/// - DB writes are serialized (`RwLock::write`)
pub struct DiscoveryFsm {
    /// The HDDS capabilities this participant announces and speaks
    /// (`protocol::group::LOCAL_CAPABILITIES` but in tests).
    local_capabilities: std::sync::atomic::AtomicU32,
    /// The participants this one speaks the spec GROUP dialect with
    /// (`group_dialect_of` == Spec), by GUID prefix: decided at each SPDP
    /// that changes a participant's vendor or capabilities, read lock-free
    /// by the send paths per reader per packet (`speaks_spec_group`).
    spec_group_peers: arc_swap::ArcSwap<std::collections::HashSet<[u8; 12]>>,
    /// The participants that read only per-writer coherent sets and want
    /// plain DATA from a GROUP Publisher (`GroupDialect::SpecReceive`), by
    /// GUID prefix: decided at the same SPDP as `spec_group_peers`, read
    /// lock-free per reader per packet (`speaks_plain_group`).
    plain_group_peers: arc_swap::ArcSwap<std::collections::HashSet<[u8; 12]>>,
    classic_window_peers: arc_swap::ArcSwap<std::collections::HashSet<[u8; 12]>>,
    /// The PID_VENDORID of each discovered participant, by GUID prefix: what
    /// `vendor_id_for_participant` answers, read lock-free per packet and per
    /// reader. Kept in step with `db` under the same write lock by every
    /// change to its membership or vendor (`handle_spdp`, `remove_participant`):
    /// see `sync_vendor_of`. A prefix with no vendor is absent.
    vendor_by_prefix: arc_swap::ArcSwap<std::collections::HashMap<[u8; 12], u16>>,
    /// Participant database (GUID -> ParticipantInfo).
    db: Arc<RwLock<ParticipantDB>>,
    /// Topic registry (topic_name -> `Vec<EndpointInfo>`).
    topic_registry: Arc<RwLock<TopicRegistry>>,
    /// Monotonic generation counter for `topic_registry` mutations.
    ///
    /// Incremented with `Release` ordering after every write-lock
    /// mutation of the registry (SEDP endpoint insert/update in
    /// `handle_sedp`, TypeObject refresh in
    /// `update_type_object_for_type`, endpoint removal in
    /// `remove_participant`). Writer runtimes cache their negotiated
    /// CDR version tagged with this generation and re-run the
    /// matched-reader lookup only when the generation moves, replacing
    /// a per-write registry walk with a single atomic load on the hot
    /// write path. An `Acquire` load that observes generation G is
    /// guaranteed to observe every registry mutation performed before
    /// the bump to G (bump strictly follows the mutation in program
    /// order; the RwLock release provides the store-side ordering).
    topic_registry_generation: AtomicU64,
    /// Endpoint registry for discovered participant unicast locators (v0.5.1+).
    /// Connects discovery -> writer for unicast DATA routing.
    endpoint_registry: EndpointRegistry,
    /// Replay registry for transient-local durability (late joiners).
    replay_registry: ReplayRegistry,
    /// Local participant GUID (for self-discovery filtering).
    local_guid: GUID,
    /// Lease duration advertised by this local participant.
    lease_duration_ms: u64,
    /// Authenticated participants that authenticated again and whose next
    /// announcement must be answered with our endpoints
    /// (`owe_reannouncement`).
    reannouncements_owed: RwLock<std::collections::HashSet<[u8; 12]>>,
    /// The lease each participant with a pending handshake declared, while
    /// it is held to a bounded one (`admitted_lease_ms`).
    declared_leases: RwLock<HashMap<[u8; 12], u64>>,
    /// The highest sequence number received so far from each peer's
    /// BuiltinParticipantMessageWriter (RTPS v2.5 Sec.8.4.13), by that
    /// peer's GUID prefix. KEEP_LAST(1) on both ends of this endpoint pair
    /// means only the highest ever matters: it is what a HEARTBEAT from
    /// that writer is answered against
    /// (`note_participant_message_received`, `participant_message_received`).
    participant_message_received: RwLock<HashMap<[u8; 12], u64>>,
    /// SEDP datagrams received from a participant while its keys change
    /// here, held until they settle (`park_sedp`).
    #[cfg(feature = "security")]
    parked_sedp: std::sync::Mutex<ParkedSedpQueue>,
    /// The discovery side of the governance document, when the participant
    /// runs one (`set_discovery_governance`): its discovery protection kind
    /// and each topic's `enable_discovery_protection`.
    #[cfg(feature = "security")]
    discovery_governance: Option<crate::security::access::DiscoveryGovernance>,
    /// The remote endpoints whose announcement was applied from a secure
    /// SEDP topic (`ignores_plain_sedp_about`). Forgotten with their
    /// participant or on endpoint dispose/unregister. Bounded per participant
    /// prefix by SECURE_ENDPOINTS_CAP_PER_PREFIX.
    #[cfg(feature = "security")]
    secure_endpoints: std::sync::Mutex<std::collections::HashSet<GUID>>,
    /// The history replays withheld from late-joining readers the security
    /// plugins did not admit when they were discovered
    /// (`replay_withheld_for`), by participant and reader. Bounded per
    /// participant and overall, in entries and bytes (`WithheldReplays`).
    #[cfg(feature = "security")]
    withheld_replays: std::sync::Mutex<WithheldReplays>,
    /// The writer sequence number of the last change applied about each
    /// remote endpoint, per builtin topic (`admits_sedp_change`), and whether
    /// that endpoint was retired since.
    sedp_change_order: std::sync::Mutex<HashMap<(SedpChannel, GUID), SedpChangeRecord>>,
    /// Where a parked secure SEDP datagram is handed back once the handshake
    /// of its sender completes: the participant's discovery dispatch.
    #[cfg(feature = "security")]
    secure_sedp_replay: std::sync::OnceLock<SecureSedpReplay>,
    /// Missing secure discovery changes, owed until the reliable reader
    /// synchronizes. Two writer bits and one retry timestamp per peer.
    #[cfg(feature = "security")]
    secure_sedp_repairs: std::sync::Mutex<HashMap<[u8; 12], PendingSedpRepair>>,
    #[cfg(feature = "security")]
    secure_sedp_repair: std::sync::OnceLock<SecureSedpRepair>,

    /// Whether this local participant has started leaving (`depart`). Set
    /// once, before its departure goes out, and never cleared. An SPDP
    /// handler holds the read side for as long as it may answer
    /// (`still_here`), so setting it waits for every handler in flight.
    departed: RwLock<bool>,
    /// The same fact for the checks that only read it (`has_departed`):
    /// set inside `depart`'s write section, read without the lock. Those
    /// checks run inside SPDP handlers that already hold `departed`'s read
    /// side, and a second read of a std `RwLock` queues behind a writer
    /// waiting in `depart`, which waits for the first read: the handler and
    /// the dropping participant deadlocked.
    departed_flag: AtomicBool,
    /// When a tracking refusal was last logged, in whole milliseconds of the
    /// system clock, so that a change retransmitted on every HEARTBEAT of a
    /// full table cannot flood the log (`log_sedp_tracking_refusal`). The
    /// count itself stays exact, in `sedp_tracking_refused`.
    sedp_refusal_logged_at: AtomicU64,
    /// Discovery metrics.
    pub metrics: DiscoveryMetrics,
    /// Locked dialect for vendor-specific QoS defaults (set by dialect detector).
    /// Uses AtomicU8 for lock-free thread-safe access.
    /// Value 0 = not set (use Hybrid defaults), 1+ = Dialect enum ordinal + 1.
    locked_dialect: AtomicU8,
    /// Registered discovery listeners.
    listeners: Arc<RwLock<Vec<Arc<dyn DiscoveryListener>>>>,
    /// Optional security validator for participant authentication (DDS Security v1.1).
    ///
    /// When set, incoming SPDP participants with identity_token are validated.
    /// Participants failing validation are rejected (not added to DB).
    security_validator: Option<Arc<dyn SecurityValidator>>,
    /// Whether to require security (reject participants without identity_token).
    require_authentication: bool,
    /// PKI-DH handshake machine (DDS Security v1.1 sec. 9.3.4).
    ///
    /// When set, a handshake is initiated toward each admitted remote
    /// participant immediately after identity validation succeeds in
    /// `handle_spdp`. The `is_authenticated` predicate from this machine
    /// gates `handle_sedp` / `notify_endpoint_discovered` so that secure
    /// endpoints are only surfaced after the 3-message exchange completes.
    #[cfg(feature = "security")]
    handshake_machine: Option<Arc<crate::security::handshake::HandshakeMachine>>,
    /// The writer key store of the participant's security suite: this
    /// participant's secure builtin writers' key material and each
    /// authenticated peer's, announced as DatawriterCryptoTokens
    /// (`register_builtin_writer_keys`).
    #[cfg(feature = "security")]
    writer_keys: Option<Arc<crate::security::crypto::data_keys::DataKeyStore>>,
    /// Token lifecycle bookkeeping, independent of optional access policy.
    #[cfg(feature = "security")]
    volatile_suite: Option<std::sync::Weak<crate::security::SecurityPluginSuite>>,
    /// Secure SEDP datagrams received from a participant under a key
    /// material whose DatawriterCryptoTokens have not arrived yet, held until
    /// a key from that participant is installed (`park_sedp_awaiting_key`).
    #[cfg(feature = "security")]
    awaiting_key_sedp: std::sync::Mutex<ParkedSedpQueue>,
    /// Access control for a remote peer's endpoints (DDS Security v1.1 9.4.3).
    ///
    /// When set, `notify_endpoint_discovered` asks it whether the peer's own
    /// signed permissions document lets it own this endpoint, immediately
    /// after the authentication gate has established that the peer finished
    /// its handshake. `None` for a participant configured without access
    /// control, and the gate is then inert.
    #[cfg(feature = "security")]
    remote_access_control: Option<Arc<crate::security::access::RemoteAccessControl>>,
    /// This participant's own local restriction overlay (DDS-Security v1.1
    /// 9.4.1.3's signed documents stay the only thing that GRANTS anything;
    /// this is the unsigned, hot-reloadable file that can only narrow what
    /// THEY granted, `security::permissions::dynamic`).
    ///
    /// Consulted by `judge_admission` for BOTH directions: a remote writer
    /// is judged against our own subscribe rules, a remote reader against
    /// our own publish rules. `None` for a participant configured without
    /// one, and the gate is then inert for it. A reload that narrows what
    /// it allows moves `admission_epoch` (via its generation counter), so
    /// an already-matched pair this now refuses is judged again at the
    /// next packet rather than kept on a verdict from before the reload.
    #[cfg(feature = "security")]
    local_restriction: Option<Arc<crate::security::SecurityPluginSuite>>,
    /// Moved by every change of what an admission verdict reads that the
    /// handshake machine and the topic registry do not count themselves: a
    /// participant's departure, a completed authentication, the bootstrap
    /// setters (`admission_epoch`).
    #[cfg(feature = "security")]
    admission_changes: AtomicU64,
    /// The admission verdicts reached since the epoch last moved
    /// (`admission`).
    #[cfg(feature = "security")]
    admission_cache: RwLock<AdmissionCache>,
    /// DER-encoded local identity certificate supplied to the handshake.
    /// Populated when `set_handshake_machine` is called.
    #[cfg(feature = "security")]
    local_cert_der: Vec<u8>,
    /// PEM-encoded local private key supplied to the handshake.
    /// Populated when `set_handshake_machine` is called.
    #[cfg(feature = "security")]
    local_key_pem: zeroize::Zeroizing<Vec<u8>>,
    /// Outbound stateless channel for emitting HandshakeAction tokens
    /// (AuthRequest/Reply/Final) on the BuiltinParticipantStatelessMessageWriter
    /// (entity 0x000201C3). Populated by `set_stateless_channel` from the
    /// participant builder once the writer is built.
    #[cfg(feature = "security")]
    stateless_channel: Option<crate::security::stateless::StatelessChannel>,
    /// FSM creation timestamp for startup probation window.
    created_at: Instant,
    /// Pending endpoint notifications for unconfirmed participants.
    ///
    /// When SEDP discovers an endpoint for a participant that is not yet
    /// confirmed alive (`ParticipantInfo::is_confirmed_alive`), the endpoint
    /// is stored here instead of being immediately notified. When the participant
    /// transitions to confirmed (via handle_spdp refresh), all pending
    /// endpoints for that participant are replayed.
    ///
    /// This prevents stale SPDP/SEDP packets from killed processes from
    /// triggering false on_endpoint_discovered notifications.
    pending_notifications: Arc<RwLock<Vec<EndpointInfo>>>,
    /// Buffered SEDP data from participants not yet in the DB.
    ///
    /// When SEDP arrives before SPDP (a common race with some peers),
    /// the SedpData is buffered here. When handle_spdp registers the
    /// new participant, all matching entries are replayed through handle_sedp.
    /// Capped at 64 entries to prevent unbounded growth.
    pending_sedp: Arc<RwLock<Vec<SedpData>>>,
    /// Remote SEDP retained for the duration of the probation window so that
    /// `purge_unconfirmed_participants` can be undone if the participant turns
    /// out to be alive.
    ///
    /// The probation purge drops every participant not confirmed and never
    /// heard from after its entry's first 100 ms (`survives_probation`) at
    /// the 250 ms mark, together with all of its topic-registry endpoints. That
    /// liveness proxy holds for a peer that starts alongside us (200 ms burst
    /// phase reaches count 2 well inside the window) but NOT for a peer already
    /// running in its steady-state announcement phase: at a 3 s SPDP period a
    /// live late-joined publisher is still at count 1 when the purge fires, and
    /// gets wiped. Its SEDP is never re-sent (we already ACKed it), so the
    /// topic registry stays permanently blind to that writer even though data
    /// keeps flowing through the demux path: `find_writers_for_topic` then
    /// reports no writer for that topic.
    ///
    /// Retaining the raw SedpData lets the purge push it back onto
    /// `pending_sedp`, where the existing replay-on-SPDP path rebuilds the
    /// endpoint (and its match notifications) the moment the participant
    /// announces again. A genuinely dead zombie never announces again, so the
    /// zombie guard keeps its exact semantics.
    ///
    /// Only the SEDP of a participant the probation heuristics may still
    /// purge is retained (first heard during our probation, not match
    /// eligible yet). Cleared once every such participant is settled
    /// (`probation_cohort_settled`): nothing else can be purged by this path,
    /// so the retention is strictly bounded.
    probation_sedp: Arc<RwLock<Vec<SedpData>>>,
    /// One-shot flag for probation purge.
    /// After the startup probation window (250 ms), unconfirmed participants
    /// and their endpoints are purged from the registry. This flag ensures
    /// the purge runs exactly once.
    probation_purge_done: AtomicBool,
    /// Single-run claim for the probation boundary, taken by CAS on entry to
    /// `maybe_complete_probation`.
    ///
    /// Distinct from `probation_purge_done`, which is published only at the END
    /// of the drain because the deferral protocol needs "purge finished" as its
    /// observable. Serialising entry needs its own flag: without it two handler
    /// threads both pass the `probation_purge_done == false` check and the loser
    /// can run the purge after the winner has already completed, deleting
    /// participants that were discovered in between.
    probation_purge_claimed: AtomicBool,
    /// Set once every participant first heard during our probation has had
    /// its verdict (`fails_probation`): from then on the probation
    /// heuristics have nothing left to judge and `maybe_complete_probation`
    /// is one atomic load.
    probation_cohort_settled: AtomicBool,
    /// Test hook run by the boundary's drain right after its eligibility
    /// snapshot, still holding the `pending_notifications` write lock: lets
    /// a test park the real drain at the point a concurrent liveness mark
    /// races it.
    #[cfg(test)]
    drain_parked_hook: std::sync::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// Test hook run by `replay_pending_for_participant` right after it took
    /// the participant's deferred endpoints out of `pending_notifications`
    /// and before it notifies them: lets a test remove an endpoint in that
    /// window.
    #[cfg(test)]
    replay_parked_hook: std::sync::Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// Test hook run once by `handle_sedp_on` right after it admitted a
    /// remote announcement (its participant known): lets a test remove the
    /// participant while its announcement is being handled.
    #[cfg(test)]
    sedp_admitted_hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send + Sync>>>,
    /// Test hook run once right after an admission check read the copy of a
    /// remote endpoint it judges from the registry (`find_readers_for_topic`,
    /// `admits_remote_endpoint`): lets a test re-announce the endpoint
    /// between the read and the verdict (`admission_epoch`).
    #[cfg(all(test, feature = "security"))]
    endpoint_read_hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send + Sync>>>,
    /// Test hook run once by `withhold_replay` right before it withholds a
    /// replay refused earlier: lets a test complete the reader's
    /// authentication between the refusal and the withholding.
    #[cfg(all(test, feature = "security"))]
    replay_withheld_hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send + Sync>>>,
    /// Registry for inconsistent-type notifications (DDS-XTypes v1.3 sec. 7.6.3.4.3).
    ///
    /// When set, `handle_sedp` fires `on_inconsistent_topic` on all local
    /// entries whose topic matches a newly discovered remote endpoint whose
    /// type is structurally incompatible with the local type.  Uses
    /// `OnceLock` so `set_match_registry` can be called through `&self`
    /// (the FSM is already behind `Arc` by the time the registry exists).
    /// Initialized once during participant setup via `set_match_registry`,
    /// before any thread that receives announcements starts.
    match_registry:
        std::sync::OnceLock<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
}

/// Cap on `pending_notifications` to bound memory. Sized to cover bursty
/// SEDP traffic during the 250 ms probation window even under adversarial
/// multicast (~1 KB/packet x ~1 Gb saturated ~ 30 k packets / 250 ms; 16 k
/// is the practical knee where any further entries are surfaced directly
/// instead of dropped silently -- SEDP is reliable and non-periodic, so a
/// drop would lose a legitimate endpoint permanently).
const PENDING_NOTIFICATIONS_CAP: usize = 16384;

/// Our startup probation span. The boundary (purge + drain) fires this long
/// after the FSM is created, and a participant first heard during it is
/// judged this long after we first heard it (`DiscoveryFsm::fails_probation`):
/// every participant of the probation gets the span a participant heard at
/// our start gets, to speak again after its entry's first 100 ms.
const PROBATION_SPAN_MS: u64 = 250;

/// How long a participant first heard during our probation may stay silent
/// before it is match eligible (`DiscoveryFsm::fails_probation`): five periods
/// of a quiet peer's 200 ms HEARTBEAT, ten
/// of our own writers' (100 ms). Bounds how long a peer that died before it
/// was confirmed holds a reliable writer's history back.
const PROBATION_SILENCE_MS: u64 = 1_000;

/// Cap on the SEDP replay buffers (`pending_sedp` and `probation_sedp`).
/// Both hold at most one entry per remote endpoint observed before its
/// participant is usable, which is bounded by the peer count in any sane
/// deployment; 64 covers the OMG interop matrix with a wide margin.
const PENDING_SEDP_CAPACITY: usize = 64;

/// What `DiscoveryFsm::admit_spdp` did with an announcement, and therefore
/// what the SPDP handlers may do because of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpdpVerdict {
    /// Our own announcement, heard back.
    Own,
    /// Refused by the security policy (an identity token the validator
    /// rejects, or none where authentication is required). Nothing of it
    /// was applied, and nothing may be sent because of it: no SPDP
    /// destination, no discovery handshake, no immediate SPDP reply, no SEDP.
    Rejected,
    /// A departure (lease 0) of a participant that never authenticated with
    /// us, applied.
    Departed,
    /// A departure on the plain DCPSParticipants topic of a participant that
    /// authenticated with us: ignored, nothing applied (DDS Security v1.1
    /// Sec.7.4.1.6).
    DepartureIgnored,
    /// An announcement on the plain DCPSParticipants topic of a participant
    /// that authenticated with us: only its liveliness was taken (DDS
    /// Security v1.1 Sec.7.4.1.6). Its lease, locators and vendor id stay
    /// what they were when it authenticated, and nothing may be sent to the
    /// addresses it carries.
    LivelinessOnly,
    /// `LivelinessOnly`, from an authenticated participant whose handshake
    /// has just completed - for the first time, or again over a completed
    /// session (re-created under the same prefix, or re-keyed): the SPDP
    /// handler sends it our endpoints again, sealed, at the locators it was
    /// admitted with (`DiscoveryFsm::peer_authenticated`).
    Reauthenticated,
    /// A participant not known before, now known.
    New,
    /// A known participant's announcement, applied.
    Refreshed,
}

/// The builtin topic an endpoint announcement arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SedpChannel {
    /// DCPSPublications / DCPSSubscriptions, in the clear: anybody can send
    /// one under any prefix.
    Plain,
    /// DCPSPublicationsSecure / DCPSSubscriptionsSecure, decrypted with the
    /// sender's metatraffic key: only the authenticated peer could have
    /// sealed it. Built only by the secure SEDP path, which exists with the
    /// `security` feature.
    #[cfg_attr(not(feature = "security"), allow(dead_code))]
    Secure,
}

/// Tracking admission keeps stale duplicates distinct from changes refused
/// without receipt, so the reliable reader can acknowledge the former.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SedpChangeAdmission {
    Apply,
    Stale,
    Refused,
}

/// Each participant prefix may hold up to this many identities in each
/// tracking table (live secure memberships, sequence-order records). The
/// limit is per prefix, never global: one peer announcing a large endpoint
/// set must not spend the room another peer needs. Identities are
/// (builtin topic, endpoint) pairs, so an endpoint announced on both the
/// plain and the secure SEDP topics counts twice. 300 participants with 16
/// endpoints each, 4800 identities, stay far below it.
///
/// New identities are refused at capacity; existing identities keep
/// progressing, so a full table never stops a known endpoint's changes.
const SEDP_CHANGE_ORDER_CAP_PER_PREFIX: usize = 1024;
#[cfg(feature = "security")]
const SECURE_ENDPOINTS_CAP_PER_PREFIX: usize = 1024;

/// The last change applied about a remote endpoint on a builtin SEDP topic
/// (`admit_sedp_change`), and whether its endpoint has been retired since
/// (dispose, unregister).
///
/// A retired record still refuses an older announcement of the same
/// endpoint: that is what keeps a replayed protected announcement from
/// resurrecting a disposed endpoint (DDSI-RTPS v2.5 Sec.8.4.12). It is
/// reclaimed when its prefix is at capacity and a new identity would
/// otherwise be refused, and leaves with its participant
/// (`forget_sedp_change_order`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct SedpChangeRecord {
    last: u64,
    retired: bool,
}

/// An SEDP datagram held for replay: its kind (plain or sealed), the
/// datagram, its payload offset, where it came from.
#[cfg(feature = "security")]
type ParkedSedp = (
    crate::core::discovery::multicast::PacketKind,
    Vec<u8>,
    usize,
    crate::core::discovery::multicast::Origin,
);

/// Tests: key material for two secure SEDP writers under `transformation`,
/// as a sender mints it: what it seals with, and what it announces (writer
/// entity id, key id, material) in its DatawriterCryptoTokens.
#[cfg(all(test, feature = "security"))]
pub(crate) fn mint_sedp_writer_keys_for_tests(
    transformation: crate::security::crypto::secure_submessage::Transformation,
) -> (
    crate::security::crypto::secure_sedp::SedpWriterKeys,
    Vec<([u8; 4], u64, crate::security::crypto::data_keys::WriterKey)>,
) {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
    };
    use crate::security::crypto::data_keys::WriterKey;
    let mut announced = Vec::new();
    let mut mint = |writer: [u8; 4]| {
        let (key_id, material) = WriterKey::mint().expect("mint");
        let material = material.with_transformation(transformation);
        let sealing = material.submessage_material(key_id);
        announced.push((writer, u64::from(key_id), material));
        sealing
    };
    let keys = crate::security::crypto::secure_sedp::SedpWriterKeys {
        publications: mint(RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER),
        subscriptions: mint(RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER),
    };
    // The production participant registers three protected builtin writers.
    let (id, material) = WriterKey::mint().expect("mint participant writer");
    announced.push((
        crate::core::rtps_constants::RTPS_ENTITYID_SPDP_SECURE_WRITER,
        u64::from(id),
        material,
    ));
    (keys, announced)
}

/// The participant's dispose/unregister on DCPSParticipantsSecure
/// (DDS Security v1.1 Sec.7.4.1.6). The complete DATA, including its inline
/// status and key, is protected according to discovery_protection_kind.
#[cfg(feature = "security")]
pub(crate) fn sealed_departure_datagram(
    material: &crate::security::crypto::secure_submessage::WriterKeyMaterial,
    departing: GUID,
    kind: crate::security::access::ProtectionKind,
) -> Option<Vec<u8>> {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_SPDP_SECURE_READER, RTPS_ENTITYID_SPDP_SECURE_WRITER,
    };
    use crate::security::crypto::secure_submessage::{
        encode_datawriter_submessage, Transformation,
    };
    if kind.is_origin_authenticated() {
        return None;
    }
    let packet = crate::core::discovery::multicast::rtps_packet::build_participant_dispose_packet(
        &departing,
        1,
        RTPS_ENTITYID_SPDP_SECURE_READER,
        RTPS_ENTITYID_SPDP_SECURE_WRITER,
    );
    let at = crate::protocol::builder::helpers::find_data_submsg_offset(&packet)?;
    let data = packet.get(at..)?;
    let wire = if kind.is_protected() {
        let expected = if kind.is_encrypted() {
            Transformation::Aes256Gcm
        } else {
            Transformation::Aes256Gmac
        };
        if material.transformation() != expected {
            return None;
        }
        encode_datawriter_submessage(material, data).ok()?
    } else {
        data.to_vec()
    };
    // The context preceding DATA is not needed for a participant status change.
    let mut out = packet[..20].to_vec();
    out.extend_from_slice(&wire);
    Some(out)
}

/// Hands a parked SEDP datagram back to the discovery dispatch.
#[cfg(feature = "security")]
pub(crate) type SecureSedpReplay = Box<
    dyn Fn(
            crate::core::discovery::multicast::PacketKind,
            &[u8],
            usize,
            crate::core::discovery::multicast::Origin,
        ) + Send
        + Sync,
>;

#[cfg(feature = "security")]
type SecureSedpRepair = Box<dyn Fn([u8; 12], u8) + Send + Sync>;

#[cfg(feature = "security")]
struct PendingSedpRepair {
    writers: u8,
    last: Option<std::time::Instant>,
}

/// How many SEDP datagrams are held per participant whose keys are changing
/// (`DiscoveryFsm::park_sedp`); later ones are dropped, as they all were
/// before.
#[cfg(feature = "security")]
const PARKED_SECURE_SEDP_PER_PEER: usize = 16;

/// How many participants may have SEDP datagrams held at once, in each of
/// the two queues (`ParkedSedpQueue`). A participant whose handshake is in
/// progress has proven nothing: its prefix and the datagrams it parks cost
/// an attacker one plain announcement each.
#[cfg(feature = "security")]
const PARKED_SECURE_SEDP_PREFIXES: usize = 256;

/// How many bytes each of the two queues of held SEDP datagrams may hold in
/// total, every participant together (`ParkedSedpQueue::cost`).
#[cfg(feature = "security")]
const PARKED_SECURE_SEDP_BYTES: usize = 4 * 1024 * 1024;

/// SEDP datagrams held per participant, bounded per participant, in
/// participants and in bytes overall. A datagram refused here is one the
/// reliable reader never acknowledged: its writer sends it again.
#[cfg(feature = "security")]
#[derive(Default)]
struct ParkedSedpQueue {
    by_prefix: HashMap<[u8; 12], Vec<ParkedSedp>>,
    bytes: usize,
}

#[cfg(feature = "security")]
impl ParkedSedpQueue {
    /// What one held datagram counts against `PARKED_SECURE_SEDP_BYTES`:
    /// its bytes and its slot, so that empty datagrams are not free.
    fn cost(datagram_len: usize) -> usize {
        datagram_len.saturating_add(std::mem::size_of::<ParkedSedp>())
    }

    fn contains(&self, prefix: &[u8; 12]) -> bool {
        self.by_prefix.contains_key(prefix)
    }

    fn prefixes(&self) -> Vec<[u8; 12]> {
        self.by_prefix.keys().copied().collect()
    }

    /// Whether a datagram of `datagram_len` bytes from `prefix` fits every
    /// bound.
    fn fits(&self, prefix: &[u8; 12], datagram_len: usize) -> bool {
        let held = self.by_prefix.get(prefix).map_or(0, Vec::len);
        if held >= PARKED_SECURE_SEDP_PER_PEER {
            return false;
        }
        if held == 0 && self.by_prefix.len() >= PARKED_SECURE_SEDP_PREFIXES {
            return false;
        }
        self.bytes.saturating_add(Self::cost(datagram_len)) <= PARKED_SECURE_SEDP_BYTES
    }

    /// Hold `parked` behind what is held for `prefix`, if it fits.
    fn push(&mut self, prefix: [u8; 12], parked: ParkedSedp) -> bool {
        if !self.fits(&prefix, parked.1.len()) {
            return false;
        }
        self.bytes += Self::cost(parked.1.len());
        self.by_prefix.entry(prefix).or_default().push(parked);
        true
    }

    /// Everything held for `prefix`, in order, no longer held.
    fn take(&mut self, prefix: &[u8; 12]) -> Vec<ParkedSedp> {
        let held = self.by_prefix.remove(prefix).unwrap_or_default();
        let freed: usize = held.iter().map(|p| Self::cost(p.1.len())).sum();
        self.bytes = self.bytes.saturating_sub(freed);
        held
    }

    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    fn participants(&self) -> usize {
        self.by_prefix.len()
    }
}

/// The longest lease a participant whose handshake is PENDING is held to: the
/// RTPS default lease duration, 100 s (DDSI-RTPS v2.5 Table 9.19, the default
/// of `SPDPdiscoveredParticipantData::leaseDuration`).
///
/// No text lets a receiver shorten the lease a participant declares, and an
/// authenticated participant keeps the one it declared (the announcement
/// current when its handshake completed; `restore_declared_lease`). Before
/// completion, though, the declared lease came in a plain announcement anyone
/// can forge under the participant's prefix, and an infinite one would keep a
/// participant that never completes - or a forger's - for ever: its plain
/// departures are ignored once it authenticates, and nothing else would
/// remove it. Bounded while pending, a participant that stops announcing
/// leaves. A deviation from the declared value, limited to the time no
/// handshake has vouched for the announcement.
#[cfg(feature = "security")]
const PENDING_AUTHENTICATION_LEASE_BOUND_MS: u64 = 100_000;

/// What the security plugins let a remote participant's endpoint of a topic
/// do (`DiscoveryFsm::admission`).
#[cfg(feature = "security")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Not paired, not sent to, not heard.
    Refused,
    /// The permissions document decides by the endpoint's partitions and
    /// data tags (`DiscoveryFsm::judge_endpoint`, DDS-Security v1.1
    /// Sec.9.4.1.3.2.3.1.4, 9.4.1.3.2.3.1.5).
    PerEndpoint,
    /// Admitted, whatever its partitions and data tags.
    Admitted,
}

/// Why `DiscoveryFsm::judge_admission` refused, for the match's log; `loud`
/// for a refusal by access control (warn, a policy being enforced), not for
/// an authentication still in progress.
#[cfg(feature = "security")]
struct Refusal {
    reason: String,
    loud: bool,
}

/// The admission verdicts reached under one `admission_epoch`.
#[cfg(feature = "security")]
#[derive(Default)]
struct AdmissionCache {
    epoch: u64,
    /// Participant prefix -> topic -> [reader, writer] verdict.
    verdicts: HashMap<[u8; 12], HashMap<String, [Option<Admission>; 2]>>,
    /// Remote endpoint -> topic -> [as a reader, as a writer] verdict, for
    /// those judged under `Admission::PerEndpoint` (`judge_endpoint`, from
    /// the partitions and data tags it announced). Keyed by the topic too:
    /// one GUID announced on two topics (a forger's, or a peer reusing an
    /// entity id) is two endpoints, each with its own partitions; and by the
    /// kind it was announced as, so that a reader's verdict never answers
    /// for a writer of the same GUID.
    endpoint_verdicts: HashMap<GUID, HashMap<String, [Option<bool>; 2]>>,
    /// Entries filed since the cache last started over.
    entries: usize,
}

#[cfg(feature = "security")]
impl AdmissionCache {
    fn clear(&mut self) {
        self.verdicts.clear();
        self.endpoint_verdicts.clear();
        self.entries = 0;
    }
}

/// The admission cache starts over past this many entries: participant
/// prefixes nobody announced cost a recomputation each, never memory.
#[cfg(feature = "security")]
const ADMISSION_CACHE_CAP: usize = 4096;

impl DiscoveryFsm {
    /// Create new `DiscoveryFsm`.
    ///
    /// # Arguments
    /// - `local_guid`: Local participant GUID (to filter self-discovery)
    /// - `lease_duration_ms`: Default lease duration for participants (typically 100_000 ms)
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::GUID;
    /// use hdds::core::discovery::multicast::DiscoveryFsm;
    ///
    /// let local_guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    /// let fsm = DiscoveryFsm::new(local_guid, 100_000);
    /// assert_eq!(fsm.metrics.snapshot().0, 0);
    /// ```
    #[must_use]
    pub fn new(local_guid: GUID, lease_duration_ms: u64) -> Self {
        crate::trace_fn!("DiscoveryFsm::new");
        Self {
            local_capabilities: std::sync::atomic::AtomicU32::new(
                crate::protocol::group::LOCAL_CAPABILITIES,
            ),
            spec_group_peers: arc_swap::ArcSwap::from_pointee(std::collections::HashSet::new()),
            plain_group_peers: arc_swap::ArcSwap::from_pointee(std::collections::HashSet::new()),
            classic_window_peers: arc_swap::ArcSwap::from_pointee(std::collections::HashSet::new()),
            vendor_by_prefix: arc_swap::ArcSwap::from_pointee(std::collections::HashMap::new()),
            db: Arc::new(RwLock::new(HashMap::new())),
            topic_registry: Arc::new(RwLock::new(TopicRegistry::new())),
            topic_registry_generation: AtomicU64::new(0),
            endpoint_registry: EndpointRegistry::new(),
            replay_registry: ReplayRegistry::new(),
            local_guid,
            lease_duration_ms,
            reannouncements_owed: RwLock::new(std::collections::HashSet::new()),
            declared_leases: RwLock::new(HashMap::new()),
            participant_message_received: RwLock::new(HashMap::new()),
            #[cfg(feature = "security")]
            parked_sedp: std::sync::Mutex::new(ParkedSedpQueue::default()),
            #[cfg(feature = "security")]
            discovery_governance: None,
            #[cfg(feature = "security")]
            secure_endpoints: std::sync::Mutex::new(std::collections::HashSet::new()),
            #[cfg(feature = "security")]
            withheld_replays: std::sync::Mutex::new(WithheldReplays::default()),
            sedp_change_order: std::sync::Mutex::new(HashMap::new()),
            #[cfg(feature = "security")]
            secure_sedp_replay: std::sync::OnceLock::new(),
            #[cfg(feature = "security")]
            secure_sedp_repairs: std::sync::Mutex::new(HashMap::new()),
            #[cfg(feature = "security")]
            secure_sedp_repair: std::sync::OnceLock::new(),
            departed: RwLock::new(false),
            departed_flag: AtomicBool::new(false),
            sedp_refusal_logged_at: AtomicU64::new(0),
            metrics: DiscoveryMetrics::new(),
            locked_dialect: AtomicU8::new(0), // 0 = not set, use Hybrid defaults
            listeners: Arc::new(RwLock::new(Vec::new())),
            security_validator: None,
            require_authentication: false,
            #[cfg(feature = "security")]
            handshake_machine: None,
            #[cfg(feature = "security")]
            writer_keys: None,
            #[cfg(feature = "security")]
            volatile_suite: None,
            #[cfg(feature = "security")]
            awaiting_key_sedp: std::sync::Mutex::new(ParkedSedpQueue::default()),
            #[cfg(feature = "security")]
            remote_access_control: None,
            #[cfg(feature = "security")]
            local_restriction: None,
            #[cfg(feature = "security")]
            admission_changes: AtomicU64::new(0),
            #[cfg(feature = "security")]
            admission_cache: RwLock::new(AdmissionCache::default()),
            #[cfg(feature = "security")]
            local_cert_der: Vec::new(),
            #[cfg(feature = "security")]
            local_key_pem: zeroize::Zeroizing::new(Vec::new()),
            #[cfg(feature = "security")]
            stateless_channel: None,
            created_at: Instant::now(),
            pending_notifications: Arc::new(RwLock::new(Vec::new())),
            pending_sedp: Arc::new(RwLock::new(Vec::new())),
            probation_sedp: Arc::new(RwLock::new(Vec::new())),
            probation_purge_done: AtomicBool::new(false),
            probation_purge_claimed: AtomicBool::new(false),
            probation_cohort_settled: AtomicBool::new(false),
            #[cfg(test)]
            drain_parked_hook: std::sync::Mutex::new(None),
            #[cfg(test)]
            replay_parked_hook: std::sync::Mutex::new(None),
            #[cfg(test)]
            sedp_admitted_hook: std::sync::Mutex::new(None),
            #[cfg(all(test, feature = "security"))]
            endpoint_read_hook: std::sync::Mutex::new(None),
            #[cfg(all(test, feature = "security"))]
            replay_withheld_hook: std::sync::Mutex::new(None),
            match_registry: std::sync::OnceLock::new(),
        }
    }

    /// Lease duration advertised by this local participant in SPDP.
    #[must_use]
    pub(crate) fn local_lease_duration_ms(&self) -> u64 {
        self.lease_duration_ms
    }

    /// Set security validator for participant authentication.
    ///
    /// When set, incoming SPDP participants will have their identity_token
    /// validated before being added to the participant database.
    ///
    /// # Arguments
    /// - `validator`: Implementation of SecurityValidator trait
    /// - `require_authentication`: If true, reject participants without identity_token
    pub fn set_security_validator(
        &mut self,
        validator: Arc<dyn SecurityValidator>,
        require_authentication: bool,
    ) {
        self.security_validator = Some(validator);
        self.require_authentication = require_authentication;
    }

    /// Register the PKI-DH handshake machine (DDS Security v1.1 sec. 9.3.4).
    ///
    /// When set, `handle_spdp` initiates a handshake toward every newly
    /// admitted remote participant whose identity was successfully validated.
    /// `handle_sedp` / `notify_endpoint_discovered` gate on
    /// `is_authenticated` so secure endpoints are only surfaced after the
    /// 3-message exchange completes.
    ///
    /// - `machine`: the shared handshake driver
    /// - `local_cert_der`: DER bytes of the local identity certificate
    /// - `local_key_pem`: PEM bytes of the local private key
    ///
    /// Must be called AFTER `set_security_validator` and BEFORE the first
    /// `handle_spdp` call (i.e. during participant bootstrap).
    #[cfg(feature = "security")]
    pub fn set_handshake_machine(
        &mut self,
        machine: Arc<crate::security::handshake::HandshakeMachine>,
        local_cert_der: Vec<u8>,
        local_key_pem: Vec<u8>,
    ) {
        self.handshake_machine = Some(machine);
        self.admission_changes.fetch_add(1, Ordering::Release);
        self.local_cert_der = local_cert_der;
        // Wiped when this FSM drops; the caller's own buffer was moved in, not copied.
        self.local_key_pem = zeroize::Zeroizing::new(local_key_pem);
    }

    /// Register the remote access-control evaluator (DDS Security v1.1 9.4.3).
    ///
    /// When set, `notify_endpoint_discovered` refuses to surface an endpoint
    /// whose owner's signed permissions document does not grant it. Passing
    /// `None` leaves the gate inert, which is what a participant configured
    /// without governance and permissions must get: unchanged behaviour.
    ///
    /// Must be called BEFORE the first `handle_sedp` call, i.e. during
    /// participant bootstrap, for the same reason as
    /// [`Self::set_handshake_machine`].
    #[cfg(feature = "security")]
    pub(crate) fn set_remote_access_control(
        &mut self,
        control: Option<Arc<crate::security::access::RemoteAccessControl>>,
    ) {
        self.remote_access_control = control;
        self.admission_changes.fetch_add(1, Ordering::Release);
    }

    /// Register this participant's own local restriction overlay
    /// (`local_restriction`), consulted by `judge_admission` for every
    /// remote endpoint from now on. `None` leaves the gate inert for it,
    /// unchanged behaviour for a participant configured without one.
    ///
    /// Must be called BEFORE the first `handle_sedp` call, i.e. during
    /// participant bootstrap, for the same reason as
    /// [`Self::set_handshake_machine`].
    #[cfg(feature = "security")]
    pub(crate) fn set_local_restriction(
        &mut self,
        suite: Option<Arc<crate::security::SecurityPluginSuite>>,
    ) {
        self.local_restriction = suite;
        self.admission_changes.fetch_add(1, Ordering::Release);
    }

    /// Register what the governance document says about discovery (DDS
    /// Security v1.1 Sec.9.4.1.2.5.4, 9.4.1.2.6.2). `None` - no governance -
    /// keeps the behaviour of a participant without one: every SEDP change
    /// sealed to an authenticated participant, in clear to any other.
    ///
    /// Must be called during participant bootstrap, before the first SEDP is
    /// sent or received.
    #[cfg(feature = "security")]
    pub(crate) fn set_discovery_governance(
        &mut self,
        governance: Option<crate::security::access::DiscoveryGovernance>,
    ) {
        self.discovery_governance = governance;
        self.admission_changes.fetch_add(1, Ordering::Release);
    }

    /// Whether a governance document rules this participant's discovery at
    /// all (`set_discovery_governance`). Without one an endpoint's announced
    /// security attributes say nothing of discovery
    /// (`secure_sedp::governed_discovery_protected`).
    #[cfg(feature = "security")]
    pub(crate) fn discovery_governed(&self) -> bool {
        self.discovery_governance.is_some()
    }

    /// The protection kind of this participant's secure discovery writers,
    /// `None` without a governance document.
    #[cfg(feature = "security")]
    pub(crate) fn discovery_protection_kind(
        &self,
    ) -> Option<crate::security::access::ProtectionKind> {
        self.discovery_governance
            .as_ref()
            .map(crate::security::access::DiscoveryGovernance::discovery_protection_kind)
    }

    /// The protection kind of this participant's ParticipantMessageSecure
    /// builtin endpoints (Sec.9.4.1.2.5.5), `None` without a governance
    /// document. A DIFFERENT governance field than
    /// [`Self::discovery_protection_kind`]: the
    /// ParticipantMessageSecure reader key is minted under this kind,
    /// not under the DISCOVERY protection kind, which names SPDP/SEDP and
    /// not liveliness.
    #[cfg(feature = "security")]
    pub(crate) fn liveliness_protection_kind(
        &self,
    ) -> Option<crate::security::access::ProtectionKind> {
        self.discovery_governance
            .as_ref()
            .map(crate::security::access::DiscoveryGovernance::liveliness_protection_kind)
    }

    /// Whether our governance says the endpoints of `topic` are announced on
    /// the secure SEDP topics: `None` without a governance document,
    /// `Some(true)` too when no topic rule matches `topic` - such an endpoint
    /// is refused locally (Sec.9.4.1.2.7) and is not taken from the regular
    /// topics either.
    #[cfg(feature = "security")]
    pub(crate) fn topic_is_discovery_protected(&self, topic: &str) -> Option<bool> {
        self.discovery_governance.as_ref().map(|governance| {
            governance
                .topic_is_discovery_protected(topic)
                .unwrap_or(true)
        })
    }

    /// Whether our TypeLookup service (DDS-XTypes v1.3 Sec.7.6.3.3; the OMG
    /// getTypes service and HDDS's own) answers the participant `requester`
    /// (`None`: unknown) with the TypeObject our endpoints of type
    /// `type_name` announce.
    ///
    /// DDS Security v1.1 says nothing of the TypeLookup service; it says
    /// where the type information of an endpoint travels. An endpoint's
    /// announcement, its type information included, goes on the secure SEDP
    /// topics, to authenticated participants only, when its topic is
    /// "considered sensitive" (Sec.7.4.1.7, 7.4.1.8), which the governance's
    /// `enable_discovery_protection` decides (Sec.9.4.1.2.6.2). A service
    /// that hands the same TypeObject to whoever asks would undo that. So,
    /// under the security plugins (`admission_gate_active`), a participant
    /// that has not authenticated with us is answered only for a type one of
    /// our endpoints announces on the regular SEDP topics - one whose topic
    /// is not discovery protected; an authenticated one, as before. Always
    /// true without the `security` feature or without security configured.
    pub(crate) fn type_lookup_serves(&self, requester: Option<&[u8; 12]>, type_name: &str) -> bool {
        #[cfg(not(feature = "security"))]
        let _ = (requester, type_name);
        #[cfg(feature = "security")]
        if self.admission_gate_active()
            && !requester.is_some_and(|prefix| self.is_authenticated_participant(prefix))
        {
            let announced_in_the_clear = recover_read(
                Arc::as_ref(&self.topic_registry),
                "DiscoveryFsm::type_lookup_serves",
            )
            .find_endpoints_by_prefix(&self.local_guid.prefix)
            .iter()
            .any(|endpoint| {
                endpoint.type_name == type_name
                    && self.topic_is_discovery_protected(&endpoint.topic_name) != Some(true)
            });
            if !announced_in_the_clear {
                log::debug!(
                    "[security] TypeLookup for '{}' from {:02x?}: not answered, the type is \
                     announced on discovery-protected topics only and the requester has not \
                     authenticated",
                    type_name,
                    requester
                );
            }
            return announced_in_the_clear;
        }
        true
    }

    /// Return the MasterSharedSecret for a remote participant that has completed
    /// the PKI-DH handshake, or `None` if unauthenticated.
    ///
    /// Root key material. It is the oracle the end-to-end test uses to
    /// assert that both sides of a pair agreed on the identical secret,
    /// which no derived key can substitute for.
    ///
    /// # Arguments
    ///
    /// - `remote_prefix`: the 12-byte GUID prefix of the remote participant.
    #[cfg(feature = "security")]
    pub fn shared_secret_for_remote(
        &self,
        remote_prefix: &[u8; 12],
    ) -> Option<crate::security::handshake::SharedSecret> {
        let machine = self.handshake_machine.as_ref()?;
        let participant_guid = crate::core::discovery::GUID::new(
            *remote_prefix,
            [0x00, 0x00, 0x01, 0xC1], // ENTITYID_PARTICIPANT
        );
        machine.shared_secret_for(&participant_guid)
    }

    /// Whether the participant `prefix` has completed the PKI-DH handshake.
    #[cfg(feature = "security")]
    pub(crate) fn is_peer_authenticated(&self, prefix: &[u8; 12]) -> bool {
        self.handshake_machine.as_ref().is_some_and(|machine| {
            machine.is_authenticated(&GUID::new(
                *prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ))
        })
    }

    /// Mint the key material of this participant's secure builtin writers
    /// and file it in `store`, the security suite's writer key store, which
    /// announces it to every authenticated participant as
    /// DatawriterCryptoTokens (Sec.8.8.9.2) and receives theirs.
    ///
    /// DDS Security v1.1 Sec.8.8.8.3: every builtin secure writer except the
    /// volatile one is registered with `register_local_datawriter`, which
    /// creates its key material (Table 70). Here: the two secure SEDP writers,
    /// under the transformation the discovery protection kind names (Table
    /// 59 `is_discovery_encrypted`: AES256_GCM for ENCRYPT, AES256_GMAC for
    /// SIGN; AES256_GCM without a governance document, which seals SEDP
    /// encrypted), and the secure participant writer, under the same discovery policy.
    ///
    /// Must be called during participant bootstrap, after
    /// `set_discovery_governance`, before the first SEDP is sent or received.
    #[cfg(feature = "security")]
    pub(crate) fn register_builtin_writer_keys(
        &mut self,
        store: Arc<crate::security::crypto::data_keys::DataKeyStore>,
    ) -> Result<(), crate::security::SecurityError> {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER, RTPS_ENTITYID_SPDP_SECURE_WRITER,
        };
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::secure_submessage::Transformation;
        let discovery = match self.discovery_protection_kind() {
            Some(kind) if kind.is_protected() && !kind.is_encrypted() => Transformation::Aes256Gmac,
            _ => Transformation::Aes256Gcm,
        };
        for (writer, transformation) in [
            (RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER, discovery),
            (RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER, discovery),
            (RTPS_ENTITYID_SPDP_SECURE_WRITER, discovery),
        ] {
            let (key_id, material) = WriterKey::mint()?;
            store.insert(
                GUID::new(self.local_guid.prefix, writer),
                u64::from(key_id),
                material.with_transformation(transformation),
            )?;
        }
        self.writer_keys = Some(store);
        Ok(())
    }

    /// Mint the key material of this participant's secure builtin READERS
    /// and file it in `store` -- the SAME store `register_builtin_writer_keys`
    /// files writer keys in (`data_keys::DataKeyStore` is keyed by GUID, not
    /// by role) -- which announces it to every authenticated participant as
    /// DatareaderCryptoTokens (Sec.8.8.9.3) and receives theirs.
    ///
    /// DDS Security v1.1 Sec.8.8.8.3: a reader of a protected topic protects
    /// its own ACKNACK and NACK_FRAG with the key `register_local_datareader`
    /// creates (Table 71), never the matching writer's key -- the two
    /// protect opposite directions. Here: the two secure SEDP readers,
    /// under the discovery protection kind (`discovery_protection_kind`,
    /// the same one their mirrored writer uses), and the
    /// ParticipantMessageSecure reader, under its OWN liveliness
    /// protection kind (`liveliness_protection_kind`, Sec.9.4.1.2.5.5 --
    /// a DIFFERENT governance field than discovery's).
    ///
    /// The SPDP secure reader is not keyed here, but NOT because SPDP is
    /// best-effort: DCPSParticipantsSecure is RELIABLE (Sec.7.4.1.6), so
    /// an ACKNACK is exactly what a conforming implementation of it would
    /// protect. HDDS simply does not advertise or serve that builtin
    /// endpoint at all yet (`setup_secure_builtins`'s SPDP-secure tunnel
    /// carries only the writer half, used for the sealed-departure DATA);
    /// there is no reader here to key because there is no reader, not
    /// because its traffic would be unprotectable.
    ///
    /// Must be called during participant bootstrap, alongside
    /// `register_builtin_writer_keys`.
    #[cfg(feature = "security")]
    pub(crate) fn register_builtin_reader_keys(
        &mut self,
        store: Arc<crate::security::crypto::data_keys::DataKeyStore>,
    ) -> Result<(), crate::security::SecurityError> {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
        };
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::secure_submessage::Transformation;
        // Table 59 `is_*_encrypted`: SIGN protection transforms with
        // AES256_GMAC, everything else (ENCRYPT, or no governance at all)
        // with AES256_GCM. A `Some(NONE)` governance ("no cryptographic
        // transformation" for that channel, Sec.9.4.1.2.1) still mints
        // AES256_GCM material here. This is not inert:
        // `local_builtin_reader_material_for`
        // is what actually enforces NONE, refusing to hand this material
        // out at all while governance says so; the transformation minted
        // here is simply never the one read in that case, because no
        // material reaches the caller to read it from.
        let transformation_for = |kind: Option<crate::security::access::ProtectionKind>| match kind
        {
            Some(kind) if kind.is_protected() && !kind.is_encrypted() => Transformation::Aes256Gmac,
            _ => Transformation::Aes256Gcm,
        };
        let discovery = transformation_for(self.discovery_protection_kind());
        for reader in [
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
        ] {
            let (key_id, material) = WriterKey::mint()?;
            store.insert(
                GUID::new(self.local_guid.prefix, reader),
                u64::from(key_id),
                material.with_transformation(discovery),
            )?;
        }
        // ParticipantMessageSecure is liveliness traffic, governed by
        // Sec.9.4.1.2.5.5's OWN field, not the discovery one above.
        let liveliness = transformation_for(self.liveliness_protection_kind());
        let (key_id, material) = WriterKey::mint()?;
        store.insert(
            GUID::new(
                self.local_guid.prefix,
                RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,
            ),
            u64::from(key_id),
            material.with_transformation(liveliness),
        )?;
        Ok(())
    }

    /// Tests: this participant's secure builtin reader keys, in a store of
    /// its own (`register_builtin_reader_keys`).
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn register_builtin_reader_keys_for_tests(&mut self) {
        // Production always calls `register_builtin_writer_keys` first
        // (`discovery_setup::mod`), so `self.writer_keys` is already
        // `Some`; a test calling only this helper would otherwise mint a
        // store that is never filed back into `self.writer_keys`, leaving
        // every other reader-key lookup helper unable to find what was
        // just minted (`material_for_writer` would return `None` right
        // after this call).
        let store = self
            .writer_keys
            .clone()
            .unwrap_or_else(|| Arc::new(crate::security::crypto::data_keys::DataKeyStore::new()));
        self.register_builtin_reader_keys(store.clone())
            .expect("mint the builtin reader keys");
        self.writer_keys = Some(store);
    }

    /// The key material of this participant's own secure builtin reader
    /// `reader` (`register_builtin_reader_keys`), ready for
    /// `encode_datareader_submessage`.
    #[cfg(feature = "security")]
    fn local_builtin_reader_material(
        &self,
        reader: [u8; 4],
    ) -> Option<crate::security::crypto::secure_submessage::WriterKeyMaterial> {
        let (key_id, material) = self
            .writer_keys
            .as_ref()?
            .material_for_writer(&GUID::new(self.local_guid.prefix, reader))?;
        Some(material.submessage_material(u32::try_from(key_id).ok()?))
    }

    /// The key materials the participant `sender_prefix` announced for its
    /// secure builtin READERS (DatareaderCryptoTokens, Sec.8.8.9.3) under
    /// the key id `key_id`, with each reader's entity id: the mirror image
    /// of [`Self::remote_builtin_writer_materials`], same reasons. What
    /// decodes a protected ACKNACK or NACK_FRAG of that participant's
    /// matching reader.
    #[cfg(feature = "security")]
    pub(crate) fn remote_builtin_reader_materials(
        &self,
        sender_prefix: &[u8; 12],
        key_id: u64,
    ) -> Vec<(
        [u8; 4],
        crate::security::crypto::secure_submessage::WriterKeyMaterial,
    )> {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
        };
        let (Some(store), Ok(wire_id)) = (self.writer_keys.as_ref(), u32::try_from(key_id)) else {
            return Vec::new();
        };
        if *sender_prefix == self.local_guid.prefix {
            return Vec::new();
        }
        [
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,
        ]
        .into_iter()
        .filter_map(|reader| {
            store
                .get_material(&GUID::new(*sender_prefix, reader), key_id)
                .map(|material| (reader, material.submessage_material(wire_id)))
        })
        .collect()
    }

    /// This participant's own builtin secure reader material for the
    /// matched peer writer `their_writer_id`, ready for
    /// `encode_datareader_submessage` -- what OUR ACKNACK to that writer is
    /// protected with. `their_writer_id` and our matching reader's entity
    /// id pair 1:1 (`volatile::builtin_peer_entity_id`); `None` when
    /// `their_writer_id` is not a builtin writer, the peer has not
    /// authenticated, or no key has been minted for our reader (should not
    /// happen once `register_builtin_reader_keys` ran, but a caller that
    /// races bootstrap must not panic).
    #[cfg(feature = "security")]
    pub(crate) fn local_builtin_reader_material_for(
        &self,
        peer_prefix: &[u8; 12],
        their_writer_id: &[u8; 4],
    ) -> Option<crate::security::crypto::secure_submessage::WriterKeyMaterial> {
        if !self.is_peer_authenticated(peer_prefix) {
            return None;
        }
        // Sec.9.4.1.2.1: NONE means "no cryptographic transformation is
        // applied" to this topic's discovery traffic. The reader's key is
        // minted unconditionally at bootstrap (`register_builtin_reader_
        // keys`) so it is ready the instant governance asks for
        // protection, but USING it while governance currently says NONE
        // produces a GCM-protected ACKNACK/repair where the writer's own
        // DATA goes out in clear -- the two ends of one tunnel disagreeing
        // about whether this traffic is protected at all (`send_sedp_acknack`
        // and `request_secure_sedp_repair` both call this function
        // unconditionally once a key exists).
        // `None` governance (no document at all) is unaffected: every
        // other caller of `discovery_protection_kind` in this tree
        // defaults a missing governance to ENCRYPT, not NONE.
        if self.discovery_protection_kind() == Some(crate::security::access::ProtectionKind::None) {
            return None;
        }
        let our_reader_id =
            crate::security::crypto::volatile::builtin_peer_entity_id(*their_writer_id)?;
        self.local_builtin_reader_material(our_reader_id)
    }

    /// The key material of this participant's own secure builtin writer
    /// `writer` (`register_builtin_writer_keys`), ready for
    /// `encode_datawriter_submessage`.
    #[cfg(feature = "security")]
    fn local_builtin_writer_material(
        &self,
        writer: [u8; 4],
    ) -> Option<crate::security::crypto::secure_submessage::WriterKeyMaterial> {
        let (key_id, material) = self
            .writer_keys
            .as_ref()?
            .material_for_writer(&GUID::new(self.local_guid.prefix, writer))?;
        Some(material.submessage_material(u32::try_from(key_id).ok()?))
    }

    /// Tests: this participant's secure builtin writer keys, in a store of
    /// its own (`register_builtin_writer_keys`).
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn register_builtin_writer_keys_for_tests(&mut self) {
        self.register_builtin_writer_keys(Arc::new(
            crate::security::crypto::data_keys::DataKeyStore::new(),
        ))
        .expect("mint the builtin writer keys");
    }

    /// Tests: the key material of this participant's own secure builtin
    /// writer `writer`, as its DatawriterCryptoTokens announce it.
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn local_builtin_writer_key_for_tests(
        &self,
        writer: [u8; 4],
    ) -> (u64, crate::security::crypto::data_keys::WriterKey) {
        self.writer_keys
            .as_ref()
            .expect("register_builtin_writer_keys first")
            .material_for_writer(&GUID::new(self.local_guid.prefix, writer))
            .expect("minted")
    }

    /// Tests: the key material of the secure SEDP writers of the participant
    /// `sender`, minted under `transformation`, filed here as if its
    /// DatawriterCryptoTokens had arrived, and returned so that the test
    /// seals as `sender` does.
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn receive_sedp_writer_keys_for_tests(
        &self,
        sender: [u8; 12],
        transformation: crate::security::crypto::secure_submessage::Transformation,
    ) -> crate::security::crypto::secure_sedp::SedpWriterKeys {
        let (keys, announced) = mint_sedp_writer_keys_for_tests(transformation);
        for (writer, key_id, material) in announced {
            self.receive_writer_key_for_tests(sender, writer, key_id, material);
        }
        keys
    }

    /// Tests: file `material`, key id `key_id`, as the key material the
    /// participant `sender` announced for its writer `writer` (what the
    /// volatile channel installs on receipt).
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn receive_writer_key_for_tests(
        &self,
        sender: [u8; 12],
        writer: [u8; 4],
        key_id: u64,
        material: crate::security::crypto::data_keys::WriterKey,
    ) {
        self.writer_keys
            .as_ref()
            .expect("register_builtin_writer_keys first")
            .insert(GUID::new(sender, writer), key_id, material)
            .expect("install");
    }

    /// Tests: the sender's secure SEDP writer material as received in its
    /// DatawriterCryptoTokens, under an encrypting transformation.
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn sender_sedp_keys_for_tests(
        &self,
        sender: [u8; 12],
    ) -> crate::security::crypto::secure_sedp::SedpWriterKeys {
        self.receive_sedp_writer_keys_for_tests(
            sender,
            crate::security::crypto::secure_submessage::Transformation::Aes256Gcm,
        )
    }

    /// Our secure SEDP writers' material for an authenticated peer.
    /// DDS-Security v1.1 Sec.8.8.8.3: OUR material encodes what we send;
    /// the peer decodes with the copy received in our DatawriterCryptoTokens.
    #[cfg(feature = "security")]
    pub(crate) fn sedp_keys_for(
        &self,
        peer_prefix: &[u8; 12],
    ) -> Option<crate::security::crypto::secure_sedp::SedpWriterKeys> {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
        };
        use crate::security::crypto::secure_sedp::SedpWriterKeys;
        if !self.is_peer_authenticated(peer_prefix) {
            return None;
        }
        Some(SedpWriterKeys {
            publications: self
                .local_builtin_writer_material(RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER)?,
            subscriptions: self
                .local_builtin_writer_material(RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER)?,
        })
    }

    /// The key materials the participant `sender_prefix` announced for its
    /// secure builtin writers (DatawriterCryptoTokens, Sec.8.8.9.2) under the
    /// key id `key_id` a CryptoHeader names, with each writer's entity id:
    /// what decodes a protected submessage of that participant
    /// (`preprocess_secure_submsg`, Sec.8.5.1.9.6, finds the sending
    /// endpoint from the key material it holds). Empty when none is held:
    /// its tokens have not arrived (`park_sedp_awaiting_key`), or it is not a
    /// key of a secure builtin writer of that participant. Never our own key
    /// material: a peer's datagram is decoded only with what the peer sent.
    #[cfg(feature = "security")]
    pub(crate) fn remote_builtin_writer_materials(
        &self,
        sender_prefix: &[u8; 12],
        key_id: u64,
    ) -> Vec<(
        [u8; 4],
        crate::security::crypto::secure_submessage::WriterKeyMaterial,
    )> {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER, RTPS_ENTITYID_SPDP_SECURE_WRITER,
        };
        let (Some(store), Ok(wire_id)) = (self.writer_keys.as_ref(), u32::try_from(key_id)) else {
            return Vec::new();
        };
        if *sender_prefix == self.local_guid.prefix {
            return Vec::new();
        }
        [
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
            RTPS_ENTITYID_SPDP_SECURE_WRITER,
        ]
        .into_iter()
        .filter_map(|writer| {
            store
                .get_material(&GUID::new(*sender_prefix, writer), key_id)
                .map(|material| (writer, material.submessage_material(wire_id)))
        })
        .collect()
    }

    /// Whether a change about the remote endpoint `endpoint`, of writer
    /// sequence number `sn`, received on `channel`, is to be applied, and,
    /// when it is, record it.
    ///
    /// A builtin SEDP writer gives each change a new number: an endpoint's
    /// announcement, its re-announcement and its dispose come in increasing
    /// order (`SedpHistory`, DDSI-RTPS v2.5 Sec.8.4.2.2.1 for the reliable
    /// writer, KEEP_LAST builtin history). A reliable reader delivers each
    /// change once and in order (Sec.8.4.12), so a change older than the
    /// last one applied about the same endpoint is stale: a delayed or
    /// replayed announcement must not bring back an endpoint its later
    /// dispose removed. On the secure topic this is what keeps a replayed
    /// protected announcement - which still authenticates, under the same
    /// keys - from resurrecting a disposed endpoint. The same number again
    /// is a retransmission of the change applied and passes: what it
    /// carries is what was applied.
    ///
    /// Per endpoint, not per writer: the history retransmits each live
    /// endpoint's announcement under its own number, older than later
    /// changes about other endpoints. Per topic: the secure and the plain
    /// writers number their changes apart. Forgotten with the participant,
    /// and with its endpoints when it authenticates again (a new process
    /// numbers from 1). A number below 1 is no valid writer sequence number
    /// (Sec.8.3.5.4): refused.
    ///
    /// A prefix holds at most `SEDP_CHANGE_ORDER_CAP_PER_PREFIX` identities,
    /// its own share and nobody else's. At capacity the records of its
    /// retired endpoints are reclaimed first
    /// (`evict_retired_sedp_identities`); only then is a new identity
    /// refused and counted.
    pub(crate) fn admits_sedp_change(
        &self,
        channel: SedpChannel,
        endpoint: &GUID,
        sn: i64,
    ) -> bool {
        self.admit_sedp_change(channel, endpoint, sn) == SedpChangeAdmission::Apply
    }

    /// The admission result, including whether a refused change was already
    /// accounted for and can be acknowledged as a stale duplicate.
    pub(crate) fn admit_sedp_change(
        &self,
        channel: SedpChannel,
        endpoint: &GUID,
        sn: i64,
    ) -> SedpChangeAdmission {
        let Ok(sn) = u64::try_from(sn) else {
            return SedpChangeAdmission::Refused;
        };
        if sn == 0 {
            return SedpChangeAdmission::Refused;
        }
        let key = (channel, *endpoint);
        let mut order = self
            .sedp_change_order
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !order.contains_key(&key)
            && Self::sedp_identities_of(&order, &endpoint.prefix)
                >= SEDP_CHANGE_ORDER_CAP_PER_PREFIX
        {
            drop(order);
            self.evict_retired_sedp_identities(&endpoint.prefix);
            order = self
                .sedp_change_order
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if Self::sedp_identities_of(&order, &endpoint.prefix)
                >= SEDP_CHANGE_ORDER_CAP_PER_PREFIX
            {
                self.metrics
                    .sedp_tracking_refused
                    .fetch_add(1, Ordering::Relaxed);
                drop(order);
                self.log_sedp_tracking_refusal("a change", &endpoint.prefix);
                return SedpChangeAdmission::Refused;
            }
        }
        let record = order.entry(key).or_insert(SedpChangeRecord {
            last: 0,
            retired: false,
        });
        if sn < record.last {
            log::debug!(
                "[sedp] change {} about {:?} on {:?} is older than the one applied ({}): \
                 not applied",
                sn,
                endpoint,
                channel,
                record.last
            );
            return SedpChangeAdmission::Stale;
        }
        record.last = sn;
        record.retired = false;
        SedpChangeAdmission::Apply
    }

    /// How many tracking identities `prefix` holds in `order`.
    fn sedp_identities_of(
        order: &HashMap<(SedpChannel, GUID), SedpChangeRecord>,
        prefix: &[u8; 12],
    ) -> usize {
        order
            .keys()
            .filter(|(_, endpoint)| endpoint.prefix == *prefix)
            .count()
    }

    /// Reclaim the tracking identities of `prefix` that no longer describe a
    /// live endpoint, before a new identity is refused: those of endpoints
    /// retired with a dispose or an unregister. A participant that leaves
    /// takes every record it left with it (`forget_sedp_change_order`, at
    /// every removal door), so nothing of a gone participant is left here.
    /// Called only at capacity, so a prefix below its share never loses
    /// replay protection.
    fn evict_retired_sedp_identities(&self, prefix: &[u8; 12]) {
        let mut order = self
            .sedp_change_order
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let before = order.len();
        order.retain(|(_, endpoint), record| endpoint.prefix != *prefix || !record.retired);
        let reclaimed = before - order.len();
        if reclaimed > 0 {
            log::debug!(
                "[sedp] {:02x?} at its tracking capacity: {} identity record(s) reclaimed",
                prefix,
                reclaimed
            );
        }
    }

    /// Report a tracking identity refused for `prefix`, at most one line
    /// every few seconds.
    ///
    /// A refused change is retransmitted on every HEARTBEAT of its reliable
    /// writer until it is acknowledged, so one line per refusal would be the
    /// whole log; the exact count is `sedp_tracking_refused`, which the
    /// metrics snapshot publishes. `what` names the refused thing.
    fn log_sedp_tracking_refusal(&self, what: &str, prefix: &[u8; 12]) {
        const INTERVAL_MS: u64 = 5_000;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        let last = self.sedp_refusal_logged_at.load(Ordering::Relaxed);
        if now.saturating_sub(last) < INTERVAL_MS
            || self
                .sedp_refusal_logged_at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        log::warn!(
            "[sedp] {:02x?} is at its tracking share: {} about one more endpoint refused; \
             the peer will retry on its HEARTBEAT ({} refused so far)",
            prefix,
            what,
            self.metrics.sedp_tracking_refused.load(Ordering::Relaxed)
        );
    }

    /// Remember that an endpoint uses a secure discovery topic. The live
    /// membership is removed on endpoint retirement, and with its
    /// participant, so a prefix at `SECURE_ENDPOINTS_CAP_PER_PREFIX` holds
    /// that many live secure endpoints: only its own share can refuse it.
    /// Sequence tombstones remain separately, within
    /// `SEDP_CHANGE_ORDER_CAP_PER_PREFIX`, to refuse old replays
    /// (DDSI-RTPS v2.5 Sec.8.4.12).
    #[cfg(feature = "security")]
    pub(crate) fn track_secure_endpoint(&self, endpoint: GUID) -> bool {
        if endpoint.prefix == self.local_guid.prefix {
            return true;
        }
        let mut endpoints = self
            .secure_endpoints
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !endpoints.contains(&endpoint)
            && endpoints
                .iter()
                .filter(|known| known.prefix == endpoint.prefix)
                .count()
                >= SECURE_ENDPOINTS_CAP_PER_PREFIX
        {
            self.metrics
                .sedp_tracking_refused
                .fetch_add(1, Ordering::Relaxed);
            drop(endpoints);
            self.log_sedp_tracking_refusal("the announcement", &endpoint.prefix);
            return false;
        }
        endpoints.insert(endpoint);
        true
    }

    /// Whether `endpoint` is a live secure SEDP membership
    /// (`track_secure_endpoint`). A retired endpoint's sequence tombstone is
    /// not one.
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn is_secure_endpoint_member(&self, endpoint: &GUID) -> bool {
        self.secure_endpoints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(endpoint)
    }

    /// Forget the change order of every endpoint of `prefix`, and which of
    /// them were announced on the secure topics.
    fn forget_sedp_change_order(&self, prefix: &[u8; 12]) {
        self.sedp_change_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, endpoint), _| endpoint.prefix != *prefix);
        #[cfg(feature = "security")]
        self.secure_endpoints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|endpoint| endpoint.prefix != *prefix);
    }

    /// Whether a plain announcement about `topic` is refused because our
    /// governance puts that topic's endpoints on the secure SEDP topics
    /// (DDS Security v1.1 Table 29) - or matches it with no topic rule
    /// (Sec.9.4.1.2.7). Such an announcement is not one a conforming
    /// participant sends, and taking it would let anybody announce, under
    /// any participant's prefix, an endpoint of a topic whose discovery the
    /// operator protected.
    pub(crate) fn refuses_plain_announcement_of(&self, endpoint: &GUID, topic: &str) -> bool {
        #[cfg(feature = "security")]
        if endpoint.prefix != self.local_guid.prefix
            && self.topic_is_discovery_protected(topic) == Some(true)
        {
            log::debug!(
                "[security] plain SEDP announcement of an endpoint of topic '{}': refused, \
                 our governance announces that topic on the secure SEDP topics",
                topic
            );
            return true;
        }
        #[cfg(not(feature = "security"))]
        let _ = (endpoint, topic);
        false
    }

    /// The SEDP datagram `packet`, about an endpoint whose
    /// `is_discovery_protected` is `discovery_protected` (`None`: this
    /// participant runs no governance document), as it is to be sent to the
    /// participant `peer_prefix` (`secure_sedp::sedp_datagram_for`): on the
    /// secure SEDP topic, protected as the governance and that participant's
    /// sealing say, or on the regular one in clear. `None` when that
    /// participant is to get the change's sequence number as a GAP on the
    /// regular writer instead: a protected endpoint is not announced to a
    /// participant that has not authenticated (DDS Security v1.1 Sec.8.8.2.1),
    /// and a change that had to be sealed and could not be is not sent in the
    /// clear.
    ///
    /// A datagram with no DATA (a GAP) is sent as it is: it carries no
    /// endpoint data, and the receiver reads it against the plaintext writer,
    /// as it reads the HEARTBEAT that follows a sealed DATA. Seal a DATA
    /// before appending a HEARTBEAT to it: everything after the DATA's
    /// payload is sealed with it.
    pub(crate) fn sedp_for_peer(
        &self,
        peer_prefix: &[u8; 12],
        packet: Vec<u8>,
        discovery_protected: Option<bool>,
    ) -> Option<Vec<u8>> {
        #[cfg(feature = "security")]
        {
            let keys = self.sedp_keys_for(peer_prefix);
            crate::security::crypto::secure_sedp::sedp_datagram_for(
                packet,
                discovery_protected,
                self.discovery_governed(),
                keys.as_ref(),
                self.discovery_protection_kind()
                    .unwrap_or(crate::security::access::ProtectionKind::Encrypt),
                peer_prefix,
            )
        }
        #[cfg(not(feature = "security"))]
        {
            let _ = (peer_prefix, discovery_protected);
            Some(packet)
        }
    }

    /// The status change of `departing`, protected for the authenticated participant
    /// `peer_prefix` ([`sealed_departure_datagram`]) under the key material
    /// of our SPDPbuiltinParticipantsSecureWriter, which that participant
    /// received in our DatawriterCryptoTokens (Sec.8.8.8.3, Sec.8.8.9.2).
    /// `None` when it has not authenticated, or the material is not there.
    ///
    /// DDS Security v1.1 Sec.7.4.1.6: "The deletion of a DomainParticipant
    /// shall also be sent using the DCPSParticipantsSecure builtin Topic",
    /// and an authenticated participant ignores a dispose received on the
    /// plain topic. This path sends the topic's status change.
    #[cfg(feature = "security")]
    pub(crate) fn sealed_departure_for(
        &self,
        peer_prefix: &[u8; 12],
        departing: GUID,
    ) -> Option<Vec<u8>> {
        if !self.is_peer_authenticated(peer_prefix) {
            return None;
        }
        let material = self.local_builtin_writer_material(
            crate::core::rtps_constants::RTPS_ENTITYID_SPDP_SECURE_WRITER,
        )?;
        sealed_departure_datagram(
            &material,
            departing,
            self.discovery_protection_kind()
                .unwrap_or(crate::security::access::ProtectionKind::Encrypt),
        )
    }

    /// Every secure departure `departing` owes as it leaves, with where to
    /// send it: one per authenticated participant, to the
    /// locators SEDP goes to. The plain dispose still goes to everyone: a
    /// participant that has not authenticated with us, or does not run
    /// security, reads that one.
    #[cfg(feature = "security")]
    pub(crate) fn sealed_departures(
        &self,
        departing: GUID,
    ) -> Vec<(Vec<u8>, Vec<std::net::SocketAddr>)> {
        self.get_participants()
            .into_iter()
            .filter(|peer| !peer.endpoints.is_empty())
            .filter_map(|peer| {
                let sealed = self.sealed_departure_for(&peer.guid.prefix, departing)?;
                Some((sealed, peer.endpoints))
            })
            .collect()
    }

    /// The participant whose departure the datagram `datagram` announces,
    /// its SEC_PREFIX at `prefix_at`, decoded with `material`, the key
    /// material the sender announced for its secure participant writer
    /// (`remote_builtin_writer_materials`); `None` when it is not one: it
    /// does not decode under that material, what it protects is not a DATA
    /// of the secure participant writer, its payload is not a departure, or
    /// it names another participant than the one whose prefix its header
    /// carries.
    #[cfg(feature = "security")]
    pub(crate) fn open_sealed_departure(
        datagram: &[u8],
        prefix_at: usize,
        material: &crate::security::crypto::secure_submessage::WriterKeyMaterial,
        required: crate::security::access::ProtectionKind,
    ) -> Option<GUID> {
        let decoded = crate::security::crypto::secure_submessage::decode_datawriter_submessage(
            material, datagram, prefix_at,
        )
        .ok()?;
        use crate::security::{access::ProtectionKind, crypto::secure_submessage::Transformation};
        let observed = match decoded.transformation {
            Transformation::Aes256Gcm => ProtectionKind::Encrypt,
            Transformation::Aes256Gmac => ProtectionKind::Sign,
        };
        if !crate::security::crypto::secure_sedp::protection_satisfies(observed, required) {
            return None;
        }
        let mut alone = datagram.get(..20)?.to_vec();
        alone.extend_from_slice(&decoded.submessage);
        crate::protocol::builder::extract_participant_dispose_at(
            &alone,
            20,
            crate::core::rtps_constants::RTPS_ENTITYID_SPDP_SECURE_WRITER,
        )
    }

    /// Register the outbound stateless channel for emitting HandshakeAction
    /// tokens (DDS Security v1.1 sec. 7.4.5). When set, `handle_spdp` enqueues
    /// the `SendRequest` returned by `HandshakeMachine::start()` onto this
    /// channel, where the BuiltinParticipantStatelessMessageWriter background
    /// drain thread serializes and sends it on entity 0x000201C3.
    #[cfg(feature = "security")]
    pub(crate) fn set_stateless_channel(
        &mut self,
        ch: crate::security::stateless::StatelessChannel,
    ) {
        self.stateless_channel = Some(ch);
    }

    /// Register the match-notification registry for inconsistent-type events.
    ///
    /// When set, `handle_sedp` calls
    /// `MatchNotificationRegistry::notify_inconsistent_type_for_topic` whenever
    /// a newly announced remote endpoint carries a type that fails the
    /// structural assignability check (`is_assignable_to`) against local
    /// endpoints on the same topic (DDS-XTypes v1.3 sec. 7.6.3.4.3).
    ///
    /// Participant setup installs it before any discovery thread starts. An
    /// installation after announcements were handled is still correct for the
    /// data-plane gate: the QoS verdict of each remote endpoint the topic
    /// registry holds and that has none on record is recorded here
    /// (`judge_known_remote_endpoints`). No match is surfaced by this call:
    /// matches come from the discovery listener hooks, so the registry must
    /// be registered as a listener, as participant setup does, for the
    /// announcements handled from then on to be matched. Returns the remote
    /// writers whose verdict was recorded here, so that the caller can wake
    /// the samples deferred for them (`TopicRegistry::notify_writer_qos_resolved`).
    /// Calls past the first are silently ignored (`OnceLock` semantics).
    pub(crate) fn set_match_registry(
        &self,
        registry: Arc<crate::dds::match_notification::MatchNotificationRegistry>,
    ) -> Vec<[u8; 16]> {
        // OnceLock::set returns Err(value) if already set; silently ignore
        // because this setter is called once during bootstrap.
        if self.match_registry.set(registry).is_err() {
            return Vec::new();
        }
        // An announcement handled before this install was judged by no one,
        // and a peer does not repeat one it saw accepted. Record the verdicts
        // the topic registry's endpoints lack: the QoS record of each remote
        // writer gates its samples (`writer_pair_verdict`), and that of each
        // remote reader is the baseline its next announcement is compared
        // with. Types need no step here: a type verdict is read from the FSM
        // record when a pair is judged, and the only local entries that could
        // refuse a type are registered after this install.
        self.judge_known_remote_endpoints()
    }

    /// Record the QoS verdict of every remote endpoint the topic registry holds
    /// that has none on record (`judge_unrecorded_remote_writer`,
    /// `judge_unrecorded_remote_reader`). Returns the writers recorded.
    fn judge_known_remote_endpoints(&self) -> Vec<[u8; 16]> {
        let Some(reg) = self.match_registry.get() else {
            return Vec::new();
        };
        let mut recorded = Vec::new();
        for (writers, readers) in self.get_all_topics().values() {
            for writer in writers {
                if reg.judge_unrecorded_remote_writer(writer) {
                    recorded.push(writer.endpoint_guid.as_bytes());
                }
            }
            for reader in readers {
                reg.judge_unrecorded_remote_reader(reader);
            }
        }
        recorded
    }

    /// The remote endpoints the local endpoint `local` is matched with, or
    /// `None` when it is no endpoint of this participant
    /// (`MatchNotificationRegistry::local_endpoint_matches`; `None` too
    /// before the registry is set). Read by the security plugins only.
    #[cfg_attr(not(feature = "security"), allow(dead_code))]
    pub(crate) fn local_endpoint_matches(&self, local: &GUID) -> Option<Vec<GUID>> {
        self.match_registry.get()?.local_endpoint_matches(local)
    }

    /// Bind token lifecycle handling without enabling an access policy.
    #[cfg(feature = "security")]
    pub(crate) fn set_volatile_suite(&mut self, suite: &Arc<crate::security::SecurityPluginSuite>) {
        self.volatile_suite = Some(Arc::downgrade(suite));
    }

    /// The event that established this endpoint pair's current match.
    #[cfg(feature = "security")]
    pub(crate) fn local_endpoint_match_generation(
        &self,
        local: &GUID,
        remote: &GUID,
    ) -> Option<u64> {
        self.match_registry
            .get()?
            .local_endpoint_match_generation(local, remote)
    }

    /// Get reference to participant database (for LeaseTracker).
    #[must_use]
    pub fn db(&self) -> Arc<RwLock<ParticipantDB>> {
        crate::trace_fn!("DiscoveryFsm::db");
        Arc::clone(&self.db)
    }

    /// The first metatraffic unicast locator SPDP/SEDP recorded for the
    /// participant named by `guid_prefix`, or `None` if this participant has
    /// never been discovered.
    ///
    /// For a consumer that has no reply locator to prefer (RTPS 2.5 8.3.8.10:
    /// behind an INFO_SRC the datagram's address is the forwarder's, never a
    /// locator of the participant it names). See `metatraffic_locator_for`.
    #[must_use]
    pub fn first_metatraffic_locator(
        &self,
        guid_prefix: &[u8; 12],
    ) -> Option<std::net::SocketAddr> {
        crate::trace_fn!("DiscoveryFsm::first_metatraffic_locator");
        self.metatraffic_locator_preferring(guid_prefix, None)
    }

    /// The metatraffic unicast locator to answer the participant named by
    /// `guid_prefix` at, for a message that came from `origin`: the one on
    /// the reply address's IP when there is such a locator, else the first
    /// one recorded, else `None` (never discovered).
    ///
    /// The ONE place a peer's recorded address is chosen by GUID prefix.
    /// The reply address only picks among the peer's own locators; it is
    /// never one itself here, and behind an INFO_SRC there is none (RTPS
    /// 2.5 8.3.4, 8.3.8.10). A caller that falls back to the reply address
    /// for a peer not yet discovered does so explicitly.
    #[must_use]
    pub fn metatraffic_locator_for(
        &self,
        guid_prefix: &[u8; 12],
        origin: crate::core::discovery::multicast::Origin,
    ) -> Option<std::net::SocketAddr> {
        crate::trace_fn!("DiscoveryFsm::metatraffic_locator_for");
        self.metatraffic_locator_preferring(guid_prefix, origin.reply().map(|reply| reply.ip()))
    }

    fn metatraffic_locator_preferring(
        &self,
        guid_prefix: &[u8; 12],
        preferred_ip: Option<std::net::IpAddr>,
    ) -> Option<std::net::SocketAddr> {
        let guard = self.db.read().ok()?;
        guard.iter().find_map(|(guid, info)| {
            if &guid.as_bytes()[..12] != guid_prefix {
                return None;
            }
            // `preferred_ip` is `None` exactly when there is no reply
            // address to prefer among the peer's own locators
            // (`first_metatraffic_locator`, or `metatraffic_locator_for`
            // behind an INFO_SRC, RTPS 2.5 8.3.4 / 8.3.8.10) -- the relayed
            // case. The SPDP parser accepts an unspecified IP (0.0.0.0 /
            // ::) or port 0 in a locator (spdp/parse/locators.rs), which a
            // DIRECT reply can still correct for because the datagram's own
            // address sits right there to pair with it
            // (`router.rs::resolve_nack_frag_dest` does the same for
            // NACK_FRAG). Relayed has no such address to fall back on, so
            // an unusable locator must be skipped here rather than handed
            // to a caller that can only send it exactly as recorded. The
            // direct path falls back to the first endpoint, usable or not:
            // its IP always comes from the datagram, never from this
            // locator.
            preferred_ip
                .and_then(|ip| info.endpoints.iter().find(|ep| ep.ip() == ip))
                .or_else(|| {
                    if preferred_ip.is_some() {
                        info.endpoints.first()
                    } else {
                        info.endpoints
                            .iter()
                            .find(|ep| !ep.ip().is_unspecified() && ep.port() != 0)
                    }
                })
                .copied()
        })
    }

    /// Get reference to endpoint registry (for Writer unicast routing, v0.5.1+).
    ///
    /// Returns clone of `EndpointRegistry` for passing to `DataWriter`.
    /// Writer uses this to send DATA packets to discovered unicast endpoints
    /// instead of blind multicast.
    #[must_use]
    pub fn endpoint_registry(&self) -> EndpointRegistry {
        crate::trace_fn!("DiscoveryFsm::endpoint_registry");
        self.endpoint_registry.clone()
    }

    /// Get reference to replay registry (for transient-local late joiners).
    #[must_use]
    pub fn replay_registry(&self) -> ReplayRegistry {
        crate::trace_fn!("DiscoveryFsm::replay_registry");
        self.replay_registry.clone()
    }

    /// Register a static peer endpoint for unicast DATA routing.
    ///
    /// Use this when the remote peer doesn't participate in SPDP discovery
    /// (e.g., hdds-micro, embedded devices, or manual network configuration).
    ///
    /// The synthetic GUID is derived from the socket address to ensure consistency
    /// across multiple calls with the same endpoint.
    ///
    /// # Arguments
    /// - `endpoint`: Socket address of the remote peer (IP:port for user data)
    ///
    /// # Example
    /// ```no_run
    /// use hdds::core::discovery::multicast::DiscoveryFsm;
    /// use hdds::core::discovery::GUID;
    ///
    /// let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
    /// fsm.register_static_peer("192.168.1.100:7411".parse().unwrap());
    /// ```
    pub fn register_static_peer(&self, endpoint: std::net::SocketAddr) {
        crate::trace_fn!("DiscoveryFsm::register_static_peer");
        // Generate a synthetic GUID from the endpoint address
        // This ensures the same endpoint always gets the same GUID
        let synthetic_guid = GUID::from_socket_addr(&endpoint);
        self.endpoint_registry.register(synthetic_guid, endpoint);
        log::info!(
            "[discovery] Registered static peer: {} (synthetic GUID: {})",
            endpoint,
            synthetic_guid
        );
    }

    /// Set the locked dialect for vendor-specific QoS defaults.
    ///
    /// Called by dialect detector when vendor is identified from SPDP.
    /// Once set, all subsequent SEDP endpoints use this dialect's default QoS
    /// when no explicit QoS PIDs are present.
    ///
    /// # Arguments
    /// - `dialect`: Detected vendor dialect (RTI, FastDDS, etc.)
    pub fn set_locked_dialect(&self, dialect: Dialect) {
        crate::trace_fn!("DiscoveryFsm::set_locked_dialect");
        // Store dialect as ordinal + 1 (0 = not set)
        let value = (dialect as u8).saturating_add(1);
        self.locked_dialect.store(value, Ordering::Release);
        log::debug!("[discovery] Locked dialect set to {:?}", dialect);
    }

    /// Get the locked dialect (if set).
    ///
    /// Returns `Some(Dialect)` if dialect has been set, `None` otherwise.
    pub fn get_locked_dialect(&self) -> Option<Dialect> {
        let value = self.locked_dialect.load(Ordering::Acquire);
        if value == 0 {
            None
        } else {
            Dialect::from_ordinal(value.saturating_sub(1))
        }
    }

    /// Register a discovery listener for new endpoint events.
    pub fn register_listener(&self, listener: Arc<dyn DiscoveryListener>) {
        let mut listeners = recover_write(
            Arc::as_ref(&self.listeners),
            "DiscoveryFsm::register_listener",
        );
        listeners.push(listener);
    }

    /// Record that this local participant is leaving, BEFORE its departure
    /// goes out (`SpdpAnnouncer`'s farewell). Waits for every SPDP handler
    /// already running: each holds [`Self::still_here`] for as long as it
    /// may answer, so none of them announces us after the farewell (an
    /// immediate SPDP reply would make the receiver take us back for a
    /// whole lease).
    pub(crate) fn depart(&self) {
        let mut departed = recover_write(&self.departed, "DiscoveryFsm::depart");
        *departed = true;
        self.departed_flag.store(true, Ordering::Release);
    }

    /// Whether [`Self::depart`] has run: the participant has said its
    /// farewell. Lock-free, so it may be asked while holding
    /// [`Self::still_here`]: a `depart` still waiting for the handlers in
    /// flight reads as not departed yet, which is when it is.
    pub(crate) fn has_departed(&self) -> bool {
        self.departed_flag.load(Ordering::Acquire)
    }

    /// Held by an SPDP handler for as long as it may answer the participant
    /// that announced itself; `None` once [`Self::depart`] has run. A
    /// participant that has said its farewell answers nobody.
    pub(crate) fn still_here(&self) -> Option<RwLockReadGuard<'_, bool>> {
        let departed = recover_read(&self.departed, "DiscoveryFsm::still_here");
        if *departed {
            None
        } else {
            Some(departed)
        }
    }

    /// Whether a departure of the participant `prefix` received on the plain
    /// DCPSParticipants topic is to be ignored: true when that participant
    /// has completed authentication with us.
    ///
    /// DDS Security v1.1 Sec.7.4.1.6: after authentication has completed, a
    /// participant "shall ignore any changes to the
    /// ParticipantBuiltinTopicData (including dispose messages) received on
    /// the DCPSParticipants builtin Topic from the authenticated
    /// DomainParticipant"; a deletion is to be sent, and processed, on
    /// DCPSParticipantsSecure. Anyone can put a departure on the plain topic
    /// under an authenticated peer's prefix, so honouring it there let one
    /// unauthenticated datagram remove that peer.
    ///
    /// The departure that is applied is the status change on the secure
    /// participant endpoints (`sealed_departure_for`, `open_sealed_departure`),
    /// protected as governance requires. A participant that crashes leaves
    /// when its lease expires; with an infinite lease, never.
    ///
    /// False without the `security` feature, without a handshake machine,
    /// and for a peer that never authenticated: their departures apply as
    /// before.
    pub(crate) fn ignores_plain_departure_of(&self, prefix: &[u8; 12]) -> bool {
        if self.is_authenticated_participant(prefix) {
            log::debug!(
                "[security] departure of authenticated participant {:02x?} received on \
                     the plain DCPSParticipants topic: ignored (DDS Security v1.1 Sec.7.4.1.6)",
                prefix
            );
            return true;
        }
        false
    }

    /// Have the handshake machine tell this FSM of every session that
    /// completes (`surface_authenticated_peer`). Holds the FSM weakly: the
    /// machine outlives nothing it should keep alive. A no-op without a
    /// handshake machine.
    #[cfg(feature = "security")]
    pub(crate) fn arm_surfacing_on_authentication(self: &Arc<Self>) {
        if let Some(ref machine) = self.handshake_machine {
            let preparing = Arc::downgrade(self);
            machine.set_before_reauthentication(Box::new(move |participant| {
                if let Some(fsm) = preparing.upgrade() {
                    fsm.prepare_peer_key_replacement(participant)?;
                }
                Ok(())
            }));
            let fsm = Arc::downgrade(self);
            machine.set_on_authenticated(Box::new(move |participant, replaced_complete| {
                if let Some(fsm) = fsm.upgrade() {
                    fsm.finish_peer_authenticated(participant, replaced_complete);
                }
            }));
            // A completed session torn down because its peer certificate expired
            // (`HandshakeMachine::tick_at`): the peer's keys go with it, so what it
            // still sends is unreadable, as it would be after any failed session.
            let torn = Arc::downgrade(self);
            machine.set_on_torn_down(Box::new(move |participant| {
                if let Some(fsm) = torn.upgrade() {
                    fsm.release_remote_writer_keys(participant.prefix);
                }
            }));
        }
    }

    /// What a completed handshake with `participant` changes in discovery.
    ///
    /// - its lease becomes the one it declared (`restore_declared_lease`);
    /// - when the session replaced a completed one, the participant may be a
    ///   new process under the same prefix, whose endpoints reuse the old
    ///   entity ids: the records of its old endpoints go
    ///   (`forget_endpoints_of`), or a plain announcement of a new endpoint
    ///   under a reused GUID would be ignored as a known one, for as long as
    ///   its lease runs;
    /// - its next announcement is answered with our endpoints, sealed
    ///   (`owe_reannouncement`): what it learned before - in the clear, or
    ///   under the replaced session - it may not hold, and for a participant
    ///   that has just authenticated for the first time it is what makes our
    ///   announcements reach it on the secure topic;
    /// - what it sent while its keys were changing is handed back
    ///   (`replay_parked_sedp`), after the old records went;
    /// - what it announced during the handshake surfaces.
    ///
    /// And before any of it, the access-control verdict reached for an
    /// earlier session of the participant goes (`forget_peer`): the
    /// permissions this session presented are judged at its own instant -
    /// renewed, they admit what the expired ones refused; expired or
    /// replaced, they refuse what the old ones admitted. On every
    /// completion, the first included: no verdict can predate a first
    /// session, but nothing that drops a session without removing the
    /// participant (an abandoned or a failed one) is a removal, so a
    /// "first" completion may follow a verdict all the same.
    #[cfg(feature = "security")]
    fn finish_peer_authenticated(&self, participant: GUID, replaced_complete: bool) {
        if let Some(ref access) = self.remote_access_control {
            access.forget_peer(&GUID::new(
                participant.prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ));
        }
        // After the verdict went: an admission reached from it is judged
        // again (`admission_epoch`).
        self.admission_changes.fetch_add(1, Ordering::Release);
        self.restore_declared_lease(participant.prefix);
        if replaced_complete {
            // Retire prior-session ciphertext before resetting sequence
            // high-water marks. No key-id overlap across authentication.
            self.parked_sedp
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(&participant.prefix);
            self.awaiting_key_sedp
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(&participant.prefix);
            self.forget_endpoints_of(participant.prefix);
            self.owe_secure_sedp_repair(participant.prefix);
        }
        self.owe_reannouncement(participant.prefix);
        self.replay_parked_sedp(participant.prefix);
        self.surface_authenticated_peer(participant);
        self.replay_withheld_for(participant.prefix);
    }

    /// Secure builtin writers get fresh material before the replacement session
    /// is published. Only then retire the remote generation. A failed local
    /// mint leaves the old remote session usable.
    #[cfg(feature = "security")]
    fn prepare_peer_key_replacement(
        &self,
        participant: GUID,
    ) -> Result<(), crate::security::SecurityError> {
        if let Some(store) = &self.writer_keys {
            for (writer, old_id, old) in store.entries_with_prefix(&self.local_guid.prefix) {
                if writer.entity_id[3] & 0xc0 != 0xc0 {
                    continue;
                }
                let (id, material) = loop {
                    let candidate = crate::security::crypto::data_keys::WriterKey::mint()?;
                    if u64::from(candidate.0) != old_id {
                        break candidate;
                    }
                };
                store.insert(
                    writer,
                    u64::from(id),
                    material.with_transformation(old.transformation),
                )?;
            }
            store.retire_participant(&participant.prefix);
        }
        Ok(())
    }

    /// Drive the same preparation and completion steps without a wire pump.
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn peer_authenticated(&self, participant: GUID, replaced_complete: bool) {
        if replaced_complete {
            self.prepare_peer_key_replacement(participant)
                .expect("replace keys");
        }
        self.finish_peer_authenticated(participant, replaced_complete);
    }

    #[cfg(feature = "security")]
    fn release_remote_writer_keys(&self, prefix: [u8; 12]) {
        if prefix != self.local_guid.prefix {
            if let Some(store) = &self.writer_keys {
                store.remove_participant(&prefix);
            }
        }
    }

    /// Forget every endpoint of `prefix`, keeping the participant: the
    /// per-endpoint part of a removal (`remove_participant_inner`), its
    /// writers departing with it.
    #[cfg(feature = "security")]
    fn forget_endpoints_of(&self, prefix: [u8; 12]) {
        // A new process numbers its changes from 1 again.
        self.forget_sedp_change_order(&prefix);
        let removed = self.forget_endpoints(|guid| guid.prefix == prefix);
        self.endpoint_registry
            .remove_endpoint_locators(|guid| guid.prefix == prefix);
        let mut dropped: Vec<GUID> = Vec::new();
        for buffer in [&self.pending_sedp, &self.probation_sedp] {
            recover_write(
                Arc::as_ref(buffer),
                "DiscoveryFsm::forget_endpoints_of buffered sedp",
            )
            .retain(|sd| {
                let gone = sd.endpoint_guid.prefix == prefix;
                if gone {
                    dropped.push(sd.endpoint_guid);
                }
                !gone
            });
        }
        // A held writer's announcement dropped takes its QoS verdicts with
        // it (`handle_sedp`).
        if let Some(reg) = self.match_registry.get() {
            for writer in dropped
                .iter()
                .filter(|guid| EndpointKind::from_guid(guid) == EndpointKind::Writer)
            {
                reg.forget_remote_writer(writer);
            }
        }
        if removed.is_empty() {
            return;
        }
        log::debug!(
            "[security] {:02x?} authenticated again: its {} endpoint record(s) forgotten",
            prefix,
            removed.len()
        );
        let listeners = recover_read(
            Arc::as_ref(&self.listeners),
            "DiscoveryFsm::forget_endpoints_of",
        )
        .clone();
        let participant = GUID::new(
            prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        for listener in &listeners {
            listener.on_participant_left(participant, false);
        }
        for endpoint in &removed {
            self.notify_endpoint_removed(endpoint);
        }
    }

    /// Hold an SEDP datagram from `prefix` while its keys are changing here,
    /// and hand it back when its handshake completes
    /// (`set_secure_sedp_replay`). Returns whether it was held.
    ///
    /// A sealed datagram that cannot be read yet: the initiator completes on
    /// the AuthReply, the responder only on the AuthFinal that follows, so
    /// for that one message the initiator holds the new metatraffic key and
    /// the responder does not - none at all on a first handshake, the old
    /// one during a re-authentication (a parallel session in flight). What
    /// the initiator seals in that window reaches the responder as something
    /// it cannot read, and would be dropped; reliable SEDP would not recover
    /// it, the sender having sent it. Two secure participants creating their
    /// endpoints before discovery would therefore intermittently fail to
    /// match.
    ///
    /// And, from the dispatch, anything from `prefix` once something of it is
    /// held, plain or sealed, so that the datagrams are applied in the order
    /// they came: a held announcement handed back after a later dispose of
    /// the same endpoint would bring it back. The dispatch settles first
    /// (`settle_parked_sedp`): what is held is handed back as soon as the
    /// keys are no longer changing.
    ///
    /// Held only while the window is open - a session that has not
    /// completed, or a parallel one, never a failed one; at most
    /// `PARKED_SECURE_SEDP_PER_PEER` datagrams each, within the overall
    /// bounds of `ParkedSedpQueue`, and dropped with the participant. When
    /// an overall bound is reached, what is held for participants whose
    /// keys stopped changing without a completion handing it back (a failed
    /// session) is handed back first, and the datagram is refused only if it
    /// still does not fit.
    #[cfg(feature = "security")]
    pub(crate) fn park_sedp(
        &self,
        prefix: [u8; 12],
        kind: crate::core::discovery::multicast::PacketKind,
        datagram: &[u8],
        cdr_offset: usize,
        origin: crate::core::discovery::multicast::Origin,
    ) -> bool {
        if !self.keys_changing(prefix) {
            return false;
        }
        let full = {
            let parked = self.parked_sedp.lock().unwrap_or_else(|e| e.into_inner());
            (!parked.fits(&prefix, datagram.len())).then(|| parked.prefixes())
        };
        if let Some(held_for) = full {
            // Read with the queue unlocked: the handshake machine calls back
            // into discovery, which takes the queue, under its own lock.
            for settled in held_for
                .into_iter()
                .filter(|p| *p != prefix && !self.keys_changing(*p))
            {
                self.replay_parked_sedp(settled);
            }
        }
        let held = self
            .parked_sedp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(prefix, (kind, datagram.to_vec(), cdr_offset, origin));
        if !held {
            self.owe_secure_sedp_repair(prefix);
            self.metrics
                .secure_sedp_queue_overflow
                .fetch_add(1, Ordering::Relaxed);
        }
        held
    }

    /// Whether something is held for `prefix` (`park_sedp`).
    #[cfg(feature = "security")]
    pub(crate) fn has_parked_sedp(&self, prefix: &[u8; 12]) -> bool {
        self.parked_sedp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(prefix)
    }

    /// Whether this authenticated participant still owes tokens for any of
    /// its registered secure builtin writers (DDS Security v1.1 Sec.8.8.9.2).
    /// Before those tokens arrive the encrypted header cannot identify the
    /// writer. Once all slots are filled, an unknown id is unresolvable;
    /// it must not be parked behind known-key traffic (Sec.8.5.1.9.6).
    #[cfg(feature = "security")]
    fn expects_builtin_writer_tokens(&self, prefix: &[u8; 12]) -> bool {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER, RTPS_ENTITYID_SPDP_SECURE_WRITER,
        };
        self.is_peer_authenticated(prefix)
            && self.writer_keys.as_ref().is_some_and(|store| {
                [
                    RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
                    RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
                    RTPS_ENTITYID_SPDP_SECURE_WRITER,
                ]
                .iter()
                .any(|id| !store.has_writer(&GUID::new(*prefix, *id)))
            })
    }

    /// Hold only traffic that can become decodable while an authenticated
    /// peer's builtin writer tokens are pending. Known-key packets bypass
    /// this queue. Per-endpoint sequence admission rejects stale replays,
    /// so a delayed announcement cannot undo a later authenticated dispose.
    /// Bounded per peer and removed with its participant.
    #[cfg(feature = "security")]
    pub(crate) fn park_sedp_awaiting_key(
        &self,
        prefix: [u8; 12],
        datagram: &[u8],
        cdr_offset: usize,
        origin: crate::core::discovery::multicast::Origin,
    ) -> bool {
        if !self.expects_builtin_writer_tokens(&prefix) {
            if self.is_peer_authenticated(&prefix) {
                self.owe_secure_sedp_repair(prefix);
            }
            self.metrics
                .secure_sedp_undecodable
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let held = self
            .awaiting_key_sedp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(
                prefix,
                (
                    crate::core::discovery::multicast::PacketKind::SecureSEDP,
                    datagram.to_vec(),
                    cdr_offset,
                    origin,
                ),
            );
        if !held {
            self.owe_secure_sedp_repair(prefix);
            self.metrics
                .secure_sedp_queue_overflow
                .fetch_add(1, Ordering::Relaxed);
        }
        held
    }

    /// Whether a secure SEDP datagram of `prefix` waits for its key
    /// (`park_sedp_awaiting_key`).
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn has_sedp_awaiting_key(&self, prefix: &[u8; 12]) -> bool {
        self.awaiting_key_sedp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(prefix)
    }

    /// Hand back, in order, what waits for a key of `prefix`
    /// (`park_sedp_awaiting_key`): called when a key material from that
    /// participant was installed. A datagram whose key is still not held is
    /// held again by the dispatch it is handed to.
    #[cfg(feature = "security")]
    pub(crate) fn replay_sedp_awaiting_key(&self, prefix: [u8; 12]) {
        self.retry_secure_sedp_repairs(std::time::Instant::now());
        let held = self
            .awaiting_key_sedp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(&prefix);
        if held.is_empty() {
            return;
        }
        let Some(replay) = self.secure_sedp_replay.get() else {
            return;
        };
        log::debug!(
            "[secure-sedp] {:02x?}: {} datagram(s) that waited for its key material handed back",
            prefix,
            held.len()
        );
        for (kind, datagram, cdr_offset, origin) in held {
            replay(kind, &datagram, cdr_offset, origin);
        }
    }

    /// DDS-Security v1.1 Sec.7.4.1.7-8 gives secure SEDP the reliable builtin
    /// QoS. Dropping ciphertext to honor a resource bound never acknowledges
    /// its writer: ask for history once tokens permit decoding it.
    #[cfg(feature = "security")]
    fn owe_secure_sedp_repair(&self, prefix: [u8; 12]) {
        self.secure_sedp_repairs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(prefix)
            .and_modify(|pending| pending.writers |= 3)
            .or_insert(PendingSedpRepair {
                writers: 3,
                last: None,
            });
    }

    #[cfg(feature = "security")]
    pub(crate) fn set_secure_sedp_repair(&self, repair: SecureSedpRepair) {
        let _ = self.secure_sedp_repair.set(repair);
    }

    /// Retransmission requests persist across lost requests and lost replies
    /// until a reader is synchronized (RTPS v2.5 Sec.8.4.2.2-3). The caller
    /// supplies time so retry tests need no sleeping.
    #[cfg(feature = "security")]
    pub(crate) fn retry_secure_sedp_repairs(&self, now: std::time::Instant) {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
        };
        let (Some(repair), Some(store)) =
            (self.secure_sedp_repair.get(), self.writer_keys.as_ref())
        else {
            return;
        };
        let mut due = Vec::new();
        {
            let mut pending = self
                .secure_sedp_repairs
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for (prefix, progress) in pending.iter_mut() {
                if !self.is_peer_authenticated(prefix)
                    || progress.last.is_some_and(|at| {
                        now.saturating_duration_since(at) < std::time::Duration::from_secs(1)
                    })
                {
                    continue;
                }
                let mut ready = 0;
                for (bit, writer) in [
                    (1, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER),
                    (2, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER),
                ] {
                    if progress.writers & bit != 0 && store.has_writer(&GUID::new(*prefix, writer))
                    {
                        ready |= bit;
                    }
                }
                if ready != 0 {
                    progress.last = Some(now);
                    due.push((*prefix, ready));
                }
            }
        }
        for (prefix, mask) in due {
            repair(prefix, mask);
        }
    }

    #[cfg(feature = "security")]
    pub(crate) fn finish_secure_sedp_repair(&self, prefix: &[u8; 12], writer: &[u8; 4]) {
        let bit = match *writer {
            crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER => 1,
            crate::core::rtps_constants::RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER => 2,
            _ => return,
        };
        let mut pending = self
            .secure_sedp_repairs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(progress) = pending.get_mut(prefix) {
            progress.writers &= !bit;
            if progress.writers == 0 {
                pending.remove(prefix);
            }
        }
    }

    /// Whether the keys of `prefix` are changing here: a session that has
    /// neither completed nor failed, or one running next to a completed one.
    /// A failed session changes nothing until a new one begins: what its
    /// participant sends meanwhile can never be read.
    #[cfg(feature = "security")]
    fn keys_changing(&self, prefix: [u8; 12]) -> bool {
        let Some(ref machine) = self.handshake_machine else {
            return false;
        };
        let participant = GUID::new(
            prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        (machine.has_session(&participant)
            && !machine.is_authenticated(&participant)
            && !machine.has_failed_session(&participant))
            || machine.has_parallel_session(&participant)
    }

    /// Hand back what is held for `prefix` when its keys are no longer
    /// changing although no completion did it (a parallel session abandoned
    /// at its deadline): held for ever, it would hold everything after it.
    #[cfg(feature = "security")]
    pub(crate) fn settle_parked_sedp(&self, prefix: [u8; 12]) {
        if self.has_parked_sedp(&prefix) && !self.keys_changing(prefix) {
            self.replay_parked_sedp(prefix);
        }
    }

    /// Set where parked SEDP datagrams are handed back. Set once.
    #[cfg(feature = "security")]
    pub(crate) fn set_secure_sedp_replay(&self, replay: SecureSedpReplay) {
        if self.secure_sedp_replay.set(replay).is_err() {
            log::debug!("[secure-sedp] replay already set; kept the first");
        }
    }

    /// Hand back what was parked for `prefix` (`park_sedp`), in order.
    #[cfg(feature = "security")]
    fn replay_parked_sedp(&self, prefix: [u8; 12]) {
        let held = self
            .parked_sedp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(&prefix);
        if held.is_empty() {
            return;
        }
        let Some(replay) = self.secure_sedp_replay.get() else {
            return;
        };
        log::debug!(
            "[secure-sedp] {:02x?}: {} parked datagram(s) handed back",
            prefix,
            held.len()
        );
        for (kind, datagram, cdr_offset, origin) in held {
            replay(kind, &datagram, cdr_offset, origin);
        }
    }

    /// Record that the handshake of `prefix` has just completed (for the
    /// first time, or again over a completed session: a participant
    /// re-created under the same prefix within its lease, which discovery
    /// cannot tell from the one before it, or a pair made to re-key). What it
    /// learned about our endpoints before it may not hold, and our records
    /// may say it has them: its next announcement gets our endpoints again,
    /// sealed (`SpdpVerdict::Reauthenticated`).
    #[cfg(feature = "security")]
    pub(crate) fn owe_reannouncement(&self, prefix: [u8; 12]) {
        recover_write(
            &self.reannouncements_owed,
            "DiscoveryFsm::owe_reannouncement",
        )
        .insert(prefix);
    }

    /// Surface the endpoints `participant` announced while its handshake was
    /// in progress, now that it has completed.
    ///
    /// `admits_endpoint` refuses the endpoints of a peer that holds a session
    /// and has not authenticated (DDS Security v1.1 Sec.9.3.4), and a refused
    /// endpoint stays in the topic registry with nothing to offer it again: a
    /// re-announcement of a known endpoint is not new, so `handle_sedp` does
    /// not surface it. A participant that joined after our startup probation
    /// and announced its endpoints before the handshake completed - which is
    /// the ordinary order, its SEDP follows its SPDP at once - would never
    /// be matched. Its endpoints are offered again here, through the same gate,
    /// once it may surface; one the probation still holds is surfaced by the
    /// deferral path, which finds the peer authenticated. A listener
    /// already told of an endpoint ignores it the second time.
    #[cfg(feature = "security")]
    pub(crate) fn surface_authenticated_peer(&self, participant: GUID) {
        // Checked, not held (`has_departed`: no read of `departed` taken
        // again under a handler's own).
        if self.has_departed() {
            return;
        }
        let prefix = participant.prefix;
        let probation_done = {
            let _pending = recover_read(
                Arc::as_ref(&self.pending_notifications),
                "DiscoveryFsm::surface_authenticated_peer",
            );
            self.probation_purge_done.load(Ordering::Acquire)
        };
        if !probation_done || !self.participant_may_surface_matches(&prefix) {
            return;
        }
        let endpoints = recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::surface_authenticated_peer registry",
        )
        .find_endpoints_by_prefix(&prefix);
        log::debug!(
            "[security::handshake] {:?} authenticated: offering its {} endpoint(s) again",
            participant,
            endpoints.len()
        );
        for endpoint in &endpoints {
            self.notify_endpoint_discovered(endpoint);
        }
    }

    /// Whether the security plugins let `endpoint` through: its participant,
    /// when it holds a handshake session, has authenticated, access control
    /// admits it on its topic in its partitions, and the governance does not
    /// refuse it as unauthenticated (`judge_admission`). Always true without
    /// the `security` feature or without security configured. The one gate
    /// every path that pairs a local entry with a remote endpoint consults:
    /// the surfaced match, a reader's WriterProxy at discovery, the
    /// registry's catch-up. The data plane reads the same verdict, cached
    /// (`admission`).
    pub(crate) fn admits_endpoint(&self, endpoint: &EndpointInfo) -> bool {
        #[cfg(not(feature = "security"))]
        let _ = endpoint;
        #[cfg(feature = "security")]
        if let Some(refusal) = self.endpoint_refusal(endpoint) {
            if refusal.loud {
                // Warn, not error: a peer we refuse is a configuration
                // statement being enforced, not a local fault. The session
                // stays up -- the peer may legitimately own other endpoints
                // we do admit.
                log::warn!(
                    "[security::access] refusing endpoint {:?} on topic '{}': {}",
                    endpoint.endpoint_guid,
                    endpoint.topic_name,
                    refusal.reason
                );
            } else {
                log::debug!(
                    "[security] refusing endpoint {:?} on topic '{}': {}",
                    endpoint.endpoint_guid,
                    endpoint.topic_name,
                    refusal.reason
                );
            }
            return false;
        }
        true
    }

    /// Why the security plugins refuse `endpoint` (`admits_endpoint`), or
    /// `None` when they admit it. Logs nothing.
    #[cfg(feature = "security")]
    fn endpoint_refusal(&self, endpoint: &EndpointInfo) -> Option<Refusal> {
        if self.admission_gate_active() {
            let remote_is_writer = matches!(endpoint.kind, EndpointKind::Writer);
            return match self.judge_admission(
                &endpoint.endpoint_guid.prefix,
                &endpoint.topic_name,
                remote_is_writer,
            ) {
                Ok(Admission::Admitted) => self.endpoint_security_info_refusal(endpoint),
                Ok(Admission::PerEndpoint) => self.judge_endpoint(endpoint).err(),
                Ok(Admission::Refused) => Some(Refusal {
                    reason: "refused".to_string(),
                    loud: true,
                }),
                Err(refusal) => Some(refusal),
            };
        }
        None
    }

    /// Whether the late-joiner history replay goes to the reader `endpoint`
    /// just discovered: the door every path to a remote reader takes
    /// (`endpoint_refusal`, `judge_admission`). DDS Security v1.1
    /// Sec.8.8.7.1 and 9.4.3: a reader the plugins do not match gets none of
    /// the writer's data, and the replay is all of it. Always true without
    /// the `security` feature. Refused, the replay is withheld
    /// (`withhold_replay`) until the reader's participant authenticates.
    fn replay_admitted(&self, endpoint: &EndpointInfo) -> bool {
        #[cfg(feature = "security")]
        if let Some(refusal) = self.endpoint_refusal(endpoint) {
            log::debug!(
                "[security] history replay to reader {:?} on topic '{}' withheld: {}",
                endpoint.endpoint_guid,
                endpoint.topic_name,
                refusal.reason
            );
            return false;
        }
        #[cfg(not(feature = "security"))]
        let _ = endpoint;
        true
    }

    /// Remember the history replay withheld from the reader `reader`
    /// (`replay_admitted`), to be judged again when its participant
    /// authenticates (`replay_withheld_for`). `judged_at` is the admission
    /// epoch loaded before the refusal was reached (`admission_epoch`).
    ///
    /// An authentication completing between the refusal and the insertion
    /// looked for the entry before it was there (`replay_withheld_for`), and
    /// the replay would wait for the next one. So after inserting, the epoch
    /// is read again: moved, the entry is taken back and judged again - once
    /// taken out, by this thread or by `replay_withheld_for`, it is
    /// replayed or withheld by whoever took it, exactly once. The lock
    /// orders the two: an authentication whose look came before the
    /// insertion moved the epoch before it, and the read after the
    /// insertion sees that.
    #[cfg(feature = "security")]
    fn withhold_replay(&self, reader: GUID, replay: WithheldReplay, judged_at: u64) {
        /// Judged again at most this many times while the epoch keeps
        /// moving; then left withheld (no replay, never a wrong one).
        const REJUDGE_BOUND: usize = 8;
        let mut judged_at = judged_at;
        let mut replay = replay;
        for _ in 0..REJUDGE_BOUND {
            #[cfg(test)]
            self.run_replay_withheld_hook();
            let holds_session = !self.is_unauthenticated_participant(&reader.prefix);
            if !self
                .withheld_replays
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(reader, replay, holds_session)
            {
                log::debug!(
                    "[security] history replay withheld from reader {:?} not kept: the \
                     withheld replays are at their bound",
                    reader
                );
                return;
            }
            let now = self.admission_epoch();
            if now == judged_at {
                return;
            }
            let Some(taken) = self
                .withheld_replays
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(&reader)
            else {
                // `replay_withheld_for` took it, and judges it.
                return;
            };
            judged_at = now;
            let Some(endpoint) = self.current_endpoint(&taken.topic, &reader) else {
                return;
            };
            if !matches!(endpoint.kind, EndpointKind::Reader) {
                return;
            }
            if self.replay_admitted(&endpoint) {
                self.replay_registry.replay_for(
                    &taken.topic,
                    &taken.type_name,
                    taken.dest,
                    Some(reader.as_bytes()),
                );
                return;
            }
            replay = taken;
        }
    }

    /// Replay the history withheld from the readers of `prefix` that the
    /// security plugins admit now (`replay_admitted`), once its participant
    /// has authenticated. A reader discovery no longer holds is forgotten;
    /// one still refused stays withheld (a later authentication, with other
    /// permissions, judges it again).
    #[cfg(feature = "security")]
    fn replay_withheld_for(&self, prefix: [u8; 12]) {
        let candidates = self
            .withheld_replays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take_peer(&prefix);
        for (guid, replay) in candidates {
            // Before anything the verdict reads (`admission_epoch`).
            let judged_at = self.admission_epoch();
            let Some(reader) = self.current_endpoint(&replay.topic, &guid) else {
                continue;
            };
            if !matches!(reader.kind, EndpointKind::Reader) {
                continue;
            }
            if self.replay_admitted(&reader) {
                self.replay_registry.replay_for(
                    &replay.topic,
                    &replay.type_name,
                    replay.dest,
                    Some(guid.as_bytes()),
                );
            } else {
                self.withhold_replay(guid, replay, judged_at);
            }
        }
    }

    /// The endpoint `endpoint_guid` on `topic_name` as discovery knows it now
    /// (the topic registry's record, with any TypeObject a TypeLookup reply
    /// resolved since its SEDP), or `None` when it is not known.
    pub(crate) fn current_endpoint(
        &self,
        topic_name: &str,
        endpoint_guid: &GUID,
    ) -> Option<EndpointInfo> {
        let registry = recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::current_endpoint",
        );
        registry.endpoint(topic_name, endpoint_guid).cloned()
    }

    fn notify_endpoint_discovered(&self, endpoint: &EndpointInfo) {
        if !self.admits_endpoint(endpoint) {
            return;
        }
        let listeners = recover_read(
            Arc::as_ref(&self.listeners),
            "DiscoveryFsm::notify_endpoint_discovered",
        );
        for listener in listeners.iter() {
            listener.on_endpoint_discovered(endpoint.clone());
        }
    }

    /// Fire the "QoS incompat" hook on every registered listener
    /// without gating against participant confirmation. Used by
    /// `handle_sedp` so that QoS mismatches surface immediately to
    /// the application even when the surfacing-gate is still holding
    /// the endpoint back for confirmation reasons.
    fn notify_endpoint_discovered_incompat_only(&self, endpoint: &EndpointInfo) {
        let listeners = recover_read(
            Arc::as_ref(&self.listeners),
            "DiscoveryFsm::notify_endpoint_discovered_incompat_only",
        );
        for listener in listeners.iter() {
            listener.on_endpoint_discovered_incompat_only(endpoint.clone());
        }
    }

    fn notify_endpoint_removed(&self, endpoint: &EndpointInfo) {
        let listeners = {
            let listeners = recover_read(
                Arc::as_ref(&self.listeners),
                "DiscoveryFsm::notify_endpoint_removed",
            );
            listeners.clone()
        };
        for listener in &listeners {
            listener.on_endpoint_removed(endpoint.clone());
        }
    }

    /// Give a TypeObject a TypeLookup answered BY NAME (the HDDS-only HTLK
    /// exchange) to the remote endpoints of `type_name` that announced none,
    /// and judge their pairings again (`learn_remote_type_objects`).
    ///
    /// An endpoint that announced a COMPLETE hash in its TypeInformation is
    /// given only the object with that hash: a name is not an identity, and
    /// two peers may publish different types under one name.
    ///
    /// Returns the number of endpoints updated.
    pub fn update_type_object_for_type(
        &self,
        type_name: &str,
        type_object: crate::xtypes::CompleteTypeObject,
    ) -> usize {
        let hash = type_object.compute_equivalence_hash().ok();
        self.learn_remote_type_objects(
            |endpoint| {
                endpoint.type_name == type_name
                    && endpoint
                        .announced_complete_hash()
                        .is_none_or(|h| Some(h) == hash)
            },
            type_object,
        )
    }

    /// Record a peer's TypeObject, served by `peer` and verified against the
    /// COMPLETE `hash` a getTypes reply answered for, so the type verdict can
    /// resolve the hash references of another peer TypeObject that names it.
    /// No-op before the match registry is set.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn register_remote_type_object(
        &self,
        hash: crate::xtypes::EquivalenceHash,
        type_object: crate::xtypes::CompleteTypeObject,
        peer: [u8; 12],
    ) {
        if let Some(reg) = self.match_registry.get() {
            reg.register_remote_type_object(hash, type_object, peer);
        }
    }

    /// `peer` left: the type verdict forgets the peer types only it served.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn forget_remote_types_of(&self, peer: &[u8; 12]) {
        if let Some(reg) = self.match_registry.get() {
            reg.forget_remote_types_of(peer);
        }
    }

    /// The hash references of `type_object` the type verdict could not
    /// resolve now (local types and peers' types learned so far). Empty
    /// before the match registry is set: there is no verdict to wait for.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn unresolved_type_refs(
        &self,
        type_object: &crate::xtypes::CompleteTypeObject,
    ) -> Vec<crate::core::discovery::matcher::UnresolvedRef> {
        self.match_registry
            .get()
            .map_or_else(Vec::new, |reg| reg.unresolved_type_refs(type_object))
    }

    /// Give the TypeObject an OMG getTypes reply resolved for the COMPLETE
    /// `hash` to the remote endpoints whose TypeInformation announced that
    /// hash, and judge their pairings again (`learn_remote_type_objects`).
    ///
    /// Content-addressed (DDS-XTypes v1.3 Sec.7.3.4.8): the reply answers a
    /// hash, so it resolves exactly the endpoints that named that hash,
    /// whichever peer they belong to and whatever their type name.
    ///
    /// Returns the number of endpoints updated.
    pub(crate) fn update_type_object_for_hash(
        &self,
        hash: &crate::xtypes::EquivalenceHash,
        type_object: crate::xtypes::CompleteTypeObject,
    ) -> usize {
        self.learn_remote_type_objects(
            |endpoint| endpoint.announced_complete_hash() == Some(*hash),
            type_object,
        )
    }

    /// Give `type_object` to the REMOTE endpoints `applies` selects that
    /// announced none, and judge every pairing of theirs again with the one
    /// type verdict.
    ///
    /// A remote endpoint discovered by TypeInformation alone was paired, or
    /// not, while its type was unknown; the reply can land before or after a
    /// local endpoint of the topic registers. Judged only at registration,
    /// the outcome depended on that order: a reader registered after the
    /// reply refused the writer and dropped its samples, one registered
    /// before matched it and delivered them. Judged here as well, both end
    /// the same: the match registry judges the pairing again
    /// (`MatchNotificationRegistry::rejudge_remote_types`), and a pairing the
    /// learned type turns from refused to accepted is matched there, so a
    /// refusal made while the type was unknown (force_type_validation) is
    /// lifted.
    ///
    /// Local endpoints are not touched: their type is the one their code
    /// declares, never a peer's.
    fn learn_remote_type_objects(
        &self,
        applies: impl Fn(&EndpointInfo) -> bool,
        type_object: crate::xtypes::CompleteTypeObject,
    ) -> usize {
        let mut local_prefix = [0u8; 12];
        local_prefix.copy_from_slice(&self.local_guid.as_bytes()[..12]);
        let mut registry = recover_write(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::learn_remote_type_objects",
        );
        let updated = registry.update_remote_type_objects(&local_prefix, applies, &type_object);
        drop(registry);
        // Registry content changed: invalidate writer-side caches keyed
        // on the topic-registry generation (see field doc).
        self.topic_registry_generation
            .fetch_add(1, Ordering::Release);
        // Judge again, outside the registry lock (listener callbacks).
        if let Some(reg) = self.match_registry.get() {
            let probation_done = self.probation_purge_done.load(Ordering::Acquire);
            for endpoint in &updated {
                let prefix = &endpoint.endpoint_guid.prefix;
                // Notified when the participant is known, the gate
                // `handle_sedp` applies to its own notification, or once our
                // probation is over. (A TypeLookup is asked of a participant
                // in `db`; one purged before its answer took its endpoints
                // with it.)
                let notify = probation_done || self.is_participant_known(prefix);
                // A pairing the learned type turns from refused to accepted is
                // matched by the registry where the match path would match it
                // now; a participant not yet allowed to surface keeps its
                // deferred discovery, judged on the type known at its replay.
                // The endpoint is NOT surfaced to the listeners again: they
                // heard of it at its SEDP, and a second on_endpoint_discovered
                // would make every listener report a foreign writer typed by
                // TypeLookup twice.
                let may_match = probation_done
                    && self.participant_may_surface_matches(prefix)
                    && self.admits_endpoint(endpoint);
                reg.rejudge_remote_types(endpoint, notify, may_match);
            }
        }
        updated.len()
    }

    /// Current generation of the topic registry. Bumped after every
    /// registry mutation; see the `topic_registry_generation` field doc.
    /// Used by writer runtimes to cache the negotiated CDR version
    /// without a per-write registry lookup.
    #[inline]
    #[must_use]
    pub fn topic_registry_generation(&self) -> u64 {
        self.topic_registry_generation.load(Ordering::Acquire)
    }

    /// Register the participant's unicast address, user-data locator first.
    ///
    /// RTPS v2.3 Sec.8.5.3.1 sends user data to `default_unicast_locators`;
    /// the metatraffic locator is the fallback for peers that announce none.
    /// `select_best_locator` drops 0.0.0.0 (an unspecified address names no
    /// destination) and prefers an address on our own subnet over a
    /// container bridge one.
    ///
    /// Called from BOTH doors a participant walks through, not from the
    /// insert branch alone: an entry created without an address would keep
    /// none for its whole life, since the peer's own announcement arriving
    /// second takes the refresh branch. End to end: one DATA that no builtin
    /// endpoint claims, carrying a ParameterList with PID_PARTICIPANT_GUID,
    /// creates that entry, and the real SPDP behind it takes the refresh
    /// branch, so without this call the registry stays empty and the
    /// participant is deaf.
    fn register_best_unicast(&self, data: &SpdpData) -> bool {
        let valid_default_unicast = select_best_locator(&data.default_unicast_locators);
        let valid_metatraffic_unicast = select_best_locator(&data.metatraffic_unicast_locators);

        if let Some(&endpoint) = valid_default_unicast {
            self.endpoint_registry
                .register(data.participant_guid, endpoint);
            log::debug!(
                "[discovery] Registered USER DATA endpoint for {:?}: {}",
                data.participant_guid,
                endpoint
            );
            true
        } else if let Some(&fallback_endpoint) = valid_metatraffic_unicast {
            self.endpoint_registry
                .register(data.participant_guid, fallback_endpoint);
            log::debug!(
                "[discovery] FALLBACK - using metatraffic endpoint for {:?}: {}",
                data.participant_guid,
                fallback_endpoint
            );
            true
        } else {
            false
        }
    }

    /// Handle SPDP (participant discovery) packet.
    ///
    /// Inserts new participant or refreshes existing one.
    /// Ignores self-discovery (`local_guid`).
    ///
    /// # Returns
    /// - `true` if this was a refresh (participant already known), or a
    ///   departure
    /// - `false` if this was a new participant, self-discovery, or an
    ///   announcement the security policy refused
    ///
    /// The SPDP handlers use [`Self::admit_spdp`], whose verdict says what
    /// they may send because of the announcement.
    pub fn handle_spdp(&self, data: SpdpData) -> bool {
        match self.admit_spdp(data) {
            SpdpVerdict::Refreshed
            | SpdpVerdict::LivelinessOnly
            | SpdpVerdict::Reauthenticated
            | SpdpVerdict::Departed
            | SpdpVerdict::DepartureIgnored => true,
            SpdpVerdict::Own | SpdpVerdict::Rejected | SpdpVerdict::New => false,
        }
    }

    /// Take in one SPDP announcement received on the plain DCPSParticipants
    /// topic, and say what was done with it ([`SpdpVerdict`]).
    ///
    /// DDS Security v1.1 Sec.7.4.1.6: after authentication a participant
    /// "shall ignore any changes to the ParticipantBuiltinTopicData
    /// (including dispose messages) received on the DCPSParticipants builtin
    /// Topic from the authenticated DomainParticipant. It may, however, rely
    /// on these messages to maintain the liveliness of the remote
    /// DomainParticipant". An announcement from a participant whose
    /// handshake is `Complete` therefore refreshes its liveliness and nothing
    /// else ([`SpdpVerdict::LivelinessOnly`]): its lease, metatraffic
    /// locators, unicast locator in the endpoint registry and vendor id stay
    /// those it held when it authenticated. Before, every one of them was
    /// rewritten by any datagram carrying its prefix, so one unauthenticated
    /// datagram could redirect the handshake, the keys and the user data
    /// sent to an authenticated peer, or make it immortal with an infinite
    /// lease.
    ///
    /// What is frozen is the participant record as it stood when its
    /// handshake completed. It is not bound to the handshake itself: the
    /// signatures cover hash_c1/hash_c2 and so `c.pdata` (DDS Security v1.1
    /// Sec.9.3.2.5), but the `c.pdata` this release sends and reads carries
    /// the participant's GUID only (`security::handshake::pdata`), so the
    /// rest of the record is whatever the plain announcements before
    /// completion said. A change after completion would have to arrive on
    /// DCPSParticipantsSecure, which this release does not serve: an
    /// authenticated peer's locators are not followed, and it leaves by the
    /// lease it declared in the announcement current when its handshake
    /// completed (bounded only while the handshake is pending,
    /// `PENDING_AUTHENTICATION_LEASE_BOUND_MS`).
    ///
    /// While that handshake is in progress, the locators stay those of the
    /// announcement that began it (or the first that carried any): one
    /// unauthenticated datagram under the
    /// participant's prefix, received just before the handshake completes,
    /// would otherwise be the record frozen at completion, and the
    /// participant unreachable for as long as it lives. A handshake begun
    /// toward a wrong address fails at its deadline; the announcement that
    /// follows a failed session is taken whole, and begins the next one.
    pub(crate) fn admit_spdp(&self, data: SpdpData) -> SpdpVerdict {
        crate::trace_fn!("DiscoveryFsm::handle_spdp");
        self.metrics.spdp_received.fetch_add(1, Ordering::Relaxed);

        // Ignore self-discovery.
        if data.participant_guid == self.local_guid {
            return SpdpVerdict::Own;
        }

        // Probation completion. See `maybe_complete_probation` for the
        // CAS-protected purge + drain. We trigger it from both
        // `handle_spdp` and `handle_sedp` so the boundary fires even
        // in workloads where SPDPs are sparse and only SEDP traffic
        // crosses the 250 ms mark.
        self.maybe_complete_probation();
        // DDS Security v1.1: Validate identity token if security is enabled
        if let Some(ref validator) = self.security_validator {
            match &data.identity_token {
                Some(token) => {
                    // Validate the identity token
                    if let Err(reason) = validator.validate_identity(data.participant_guid, token) {
                        log::warn!(
                            "[discovery] Security: Rejected participant {:?} - {}",
                            data.participant_guid,
                            reason
                        );
                        self.metrics.security_errors.fetch_add(1, Ordering::Relaxed);
                        return SpdpVerdict::Rejected;
                    }
                    log::debug!(
                        "[discovery] Security: Authenticated participant {:?}",
                        data.participant_guid
                    );
                }
                None if self.require_authentication => {
                    // Reject participants without identity token when authentication is required
                    log::warn!(
                        "[discovery] Security: Rejected unauthenticated participant {:?}",
                        data.participant_guid
                    );
                    self.metrics.security_errors.fetch_add(1, Ordering::Relaxed);
                    return SpdpVerdict::Rejected;
                }
                None => {
                    // No identity token, but not required (permissive mode)
                    log::debug!(
                        "[discovery] Security: Allowing unauthenticated participant {:?} (permissive mode)",
                        data.participant_guid
                    );
                }
            }
        }

        // DDS Security v1.1 Sec.8.8.2.2: with allow_unauthenticated_participants
        // FALSE, "Discovered DomainParticipant entities that do not implement
        // the DDS Security specification or do not contain compatible Security
        // Plugins shall be rejected without the DomainParticipant attempting
        // to authenticate them." The governance decides, whatever
        // SecurityConfig::require_authentication says. A departure is not an
        // admission and keeps its own path.
        #[cfg(feature = "security")]
        if data.identity_token.is_none()
            && data.lease_duration_ms > 0
            && self
                .discovery_governance
                .as_ref()
                .is_some_and(|governance| !governance.allows_unauthenticated())
            && self.is_unauthenticated_participant(&data.participant_guid.prefix)
        {
            log::warn!(
                "[discovery] Security: Rejected participant {:?} - no identity token, and the \
                 governance does not allow unauthenticated participants",
                data.participant_guid
            );
            self.metrics.security_errors.fetch_add(1, Ordering::Relaxed);
            return SpdpVerdict::Rejected;
        }

        // DDS Security v1.1 Sec.9.4.2.4: "in order to communicate, two
        // DomainParticipants need to have the same ParticipantSecurityInfo."
        // `PID_PARTICIPANT_SECURITY_INFO` is parsed into `data` above and
        // compared here: a peer announcing different protections than ours
        // is not admitted. Checked only when THIS participant
        // runs a governance document (no attributes of our own to compare
        // against otherwise), for a real announcement (not a departure,
        // `lease_duration_ms` 0), and only for a peer that presented an
        // identity token: Sec.9.4.2.4 is a property of the two
        // DomainParticipants' DDS-Security configuration, reached through
        // the PKI-DH handshake this token starts. A peer with none is, by
        // definition, outside that pathway (`allow_unauthenticated_participants`
        // is the governance's own escape valve for exactly that peer, and
        // this unsigned SPDP field proves nothing about an unauthenticated
        // one anyway -- comparing it would only penalize a peer the
        // governance already chose to admit without it).
        #[cfg(feature = "security")]
        if data.lease_duration_ms > 0 && data.identity_token.is_some() {
            if let Some(ref governance) = self.discovery_governance {
                let local_info = governance.participant_attributes().security_info();
                let remote_info = data
                    .participant_security_info
                    .map(crate::protocol::discovery::ParticipantSecurityInfo::from_le_bytes)
                    .unwrap_or_default();
                if !local_info.matches(&remote_info) {
                    log::warn!(
                        "[discovery] Security: Rejected participant {:?} - its \
                         PID_PARTICIPANT_SECURITY_INFO ({:?}) does not match ours ({:?})",
                        data.participant_guid,
                        remote_info,
                        local_info
                    );
                    self.metrics.security_errors.fetch_add(1, Ordering::Relaxed);
                    return SpdpVerdict::Rejected;
                }
            }
        }

        // Read before this announcement begins a session (see the doc
        // above): only a session already in progress holds the locators.
        #[cfg(feature = "security")]
        let locators_held = self.keys_changing(data.participant_guid.prefix);
        #[cfg(not(feature = "security"))]
        let locators_held = false;

        // DDS Security v1.1 sec. 9.3.4: initiate PKI-DH handshake toward newly
        // admitted participants that carry an identity token.
        #[cfg(feature = "security")]
        if let (Some(ref machine), true) = (
            &self.handshake_machine,
            data.identity_token.is_some() && data.lease_duration_ms > 0,
        ) {
            machine.note_peer_capabilities(
                data.participant_guid,
                data.vendor_id,
                data.hdds_capabilities,
            );
            match machine.start_and_announce(
                self.local_guid,
                data.participant_guid,
                &self.local_cert_der,
                &self.local_key_pem,
            ) {
                Ok(actions) if !actions.is_empty() => {
                    log::debug!(
                        "[security::handshake] initiated toward {:?}: queuing {} outgoing \
                         action(s)",
                        data.participant_guid,
                        actions.len(),
                    );
                    if let Some(ref ch) = self.stateless_channel {
                        for action in actions {
                            crate::security::pump::enqueue_action(action, ch);
                        }
                    }
                }
                Ok(_) => {
                    // Responder role or session already in progress; no action.
                }
                Err(e) => {
                    log::warn!(
                        "[security::handshake] start failed for {:?}: {}",
                        data.participant_guid,
                        e
                    );
                }
            }
        }

        // SPDP dispose: lease_duration_ms == 0 means participant is leaving
        if data.lease_duration_ms == 0 {
            log::debug!(
                "[SPDP] Dispose received for participant {:?}",
                data.participant_guid
            );
            if self.ignores_plain_departure_of(&data.participant_guid.prefix) {
                return SpdpVerdict::DepartureIgnored;
            }
            self.remove_participant_inner(
                data.participant_guid,
                ParticipantRemovalCondition::Farewell,
            );
            return SpdpVerdict::Departed;
        }

        // DDS Security v1.1 Sec.7.4.1.6: liveliness only, see the doc above.
        let liveliness_only = self.is_authenticated_participant(&data.participant_guid.prefix);
        let lease_duration_ms = self.admitted_lease_ms(&data);

        // Check if participant exists (read lock) and guard against poison.
        let exists = {
            let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::handle_spdp exists");
            db.contains_key(&data.participant_guid)
        };

        if exists {
            // Refresh existing participant (write lock).
            let mut dialect_changed = false;
            let mut db = recover_write(Arc::as_ref(&self.db), "DiscoveryFsm::handle_spdp refresh");
            let may_surface = if let Some(info) = db.get_mut(&data.participant_guid) {
                info.refresh();
                let legacy_key_hash_before =
                    Self::legacy_key_hash_decision(info.vendor_id, info.hdds_capabilities);
                if liveliness_only {
                    // The lease it authenticated with stays: liveliness only.
                } else {
                    info.lease_duration_ms = lease_duration_ms;
                    // The address this announcement carries, when it carries
                    // one. SEDP is addressed from this list, so an entry that
                    // never gets one is a peer we can see and never answer -
                    // and the refresh branch writes it too, not the insert
                    // branch alone: otherwise whoever created the entry would
                    // own its address for the entry's life. An announcement
                    // that carries NOTHING
                    // changes nothing, which is the opposite failure and just
                    // as silent. While a handshake is in progress, only into
                    // a record that has none (see the doc above).
                    if (!locators_held || info.endpoints.is_empty())
                        && !data.metatraffic_unicast_locators.is_empty()
                    {
                        info.endpoints = data.metatraffic_unicast_locators.clone();
                        log::debug!(
                            "[discovery] metatraffic locators for {:?} on refresh: {:?}",
                            data.participant_guid,
                            info.endpoints
                        );
                    }
                    // Capture the vendor id on refresh too: the first SPDP
                    // entry may have predated vendor-id availability. Only
                    // overwrite when the new SPDP actually carries one, so a
                    // later vendor-less SPDP never clobbers a known id.
                    let vendor_resolved = info.vendor_id.is_none() && data.vendor_id.is_some();
                    if data.vendor_id.is_some() {
                        info.vendor_id = data.vendor_id;
                    }
                    // Same for the capabilities, which travel with it.
                    if data.hdds_capabilities.is_some() {
                        info.hdds_capabilities = data.hdds_capabilities;
                    }
                    if data.builtin_endpoint_set.is_some() {
                        info.builtin_endpoint_set = data.builtin_endpoint_set;
                    }
                    // The legacy key-hash decision of the writers moves with the
                    // vendor or the capabilities too: they are decided again.
                    let legacy_key_hash_changed = legacy_key_hash_before
                        != Self::legacy_key_hash_decision(info.vendor_id, info.hdds_capabilities);
                    dialect_changed = self.note_group_dialect(
                        info.guid.prefix,
                        info.vendor_id,
                        info.hdds_capabilities,
                    ) || vendor_resolved
                        || legacy_key_hash_changed;
                }
                self.may_surface_matches(info)
            } else {
                false
            };
            self.sync_vendor_of(&db, data.participant_guid.prefix);
            drop(db); // Release lock before replaying
            if dialect_changed {
                self.notify_dialect_changed(&data.participant_guid.prefix);
            }

            // Same rule for the send-side registry, which the insert branch
            // was otherwise the only writer of. No guard is needed: an
            // announcement carrying no usable locator registers nothing, so
            // the call is a no-op exactly when it should be. Not from an
            // authenticated peer's plain announcement: this is the address
            // its handshake, its keys and its user data are sent to.
            if !liveliness_only
                && (!locators_held || self.endpoint_registry.get(&data.participant_guid).is_none())
            {
                self.register_best_unicast(&data);
            }

            // When a participant transitions from unconfirmed to confirmed,
            // replay deferred SEDP endpoint notifications -- but only AFTER the
            // probation window has closed (probation_purge_done == true). During
            // probation, deferring the replay means ALL deferred events (incompat
            // AND match) fire together at the probation boundary via
            // drain_pending_post_probation, where structural-type incompat
            // notifications are guaranteed to appear before match notifications.
            // Without this gate, a zombie confirmed early (spdp_count >= 2) could
            // fire on_publication_matched before the real subscriber's incompat.
            //
            // The flag is read under the `pending_notifications` lock, as
            // `replay_after_late_eligibility` reads it: the drain takes its
            // eligibility snapshot and publishes the flag under that lock,
            // so an SPDP whose mark makes the participant eligible between
            // the two (put back as not eligible, flag still false) waits for
            // the publication here and replays what the drain put back. Read
            // without it, the flag could still be false and the entry would
            // wait for the next SPDP (possibly tens of seconds away).
            let probation_done_now = {
                let _pending = recover_read(
                    Arc::as_ref(&self.pending_notifications),
                    "DiscoveryFsm::handle_spdp probation flag",
                );
                self.probation_purge_done.load(Ordering::Acquire)
            };
            // Also drain any SEDP requeued by the probation purge: the peer is
            // back in the DB via this refresh path, so the insert path that
            // normally drives the replay will never run again for it.
            self.replay_pending_sedp(&data.participant_guid);
            if probation_done_now {
                // Match-notification replay is still gated on probation, and on
                // the one rule every surfacing path applies
                // (`may_surface_matches`): a participant first heard during the
                // probation surfaces only once match eligible, whichever SPDP
                // made it so (this one, or one before it).
                if may_surface {
                    self.replay_pending_for_participant(data.participant_guid);
                }
                // Lazy zombie-confirmed purge: an HDDS participant that still has
                // spdp_count == 2 and has been silent for 300 ms is treated as a
                // zombie that survived purge_unconfirmed_participants (see the
                // Tier 1 doc of purge_zombie_confirmed_participants: a tier kept
                // for safety, not a measured arrival pattern).
                // This call is idempotent and cheap (single read lock + age
                // filter). It removes the zombie's db entry AND its topic-registry
                // endpoints, preventing spurious on_inconsistent_topic callbacks
                // when the next test's local writer scans remote endpoints via
                // catch_up().
                self.purge_zombie_confirmed_participants();
            }

            return if !liveliness_only {
                SpdpVerdict::Refreshed
            } else if recover_write(
                &self.reannouncements_owed,
                "DiscoveryFsm::handle_spdp reannouncement",
            )
            .remove(&data.participant_guid.prefix)
            {
                SpdpVerdict::Reauthenticated
            } else {
                SpdpVerdict::LivelinessOnly
            };
        }

        // Insert new participant (write lock).
        let mut info = ParticipantInfo::new(
            data.participant_guid,
            data.metatraffic_unicast_locators.clone(), // use metatraffic for SEDP
            lease_duration_ms,
        );
        // Capture the SPDP-advertised vendor id (RTPS PID_VENDORID 0x0016) so
        // the send path can query it for per-vendor interop adaptation.
        info.vendor_id = data.vendor_id;
        info.hdds_capabilities = data.hdds_capabilities;
        info.builtin_endpoint_set = data.builtin_endpoint_set;

        let mut db = recover_write(Arc::as_ref(&self.db), "DiscoveryFsm::handle_spdp insert");
        db.insert(data.participant_guid, info);
        self.sync_vendor_of(&db, data.participant_guid.prefix);
        // After the entry: the send paths' class (`speaks_spec_group`) and
        // the receive side's (`group_dialect_of`, the entry) agree from the
        // first moment either says spec.
        self.note_group_dialect(
            data.participant_guid.prefix,
            data.vendor_id,
            data.hdds_capabilities,
        );

        if !self.register_best_unicast(&data) {
            log::warn!(
                "[discovery] No valid unicast locator found for participant {:?}",
                data.participant_guid
            );
        }

        self.metrics
            .participants_discovered
            .fetch_add(1, Ordering::Relaxed);

        // CRITICAL: Release the db write lock BEFORE replaying buffered SEDP.
        // replay_pending_sedp() -> handle_sedp() acquires a read lock on self.db
        // to check participant existence. Holding the write lock here would deadlock
        // on the same thread (std::sync::RwLock is not reentrant on Linux/pthreads).
        drop(db);

        // The participant is known from here on: the writers of it discovery
        // already holds were decided while it was not (`sedp_handler`), and
        // are decided again now.
        self.notify_writers_dialect(&data.participant_guid.prefix);

        // Replay any SEDP that arrived before this SPDP (SEDP can overtake it).
        self.replay_pending_sedp(&data.participant_guid);

        SpdpVerdict::New
    }

    /// Whether a plain endpoint announcement - or dispose - of `endpoint_guid`
    /// is to be ignored: it names an endpoint that a participant which has
    /// authenticated with us already announced.
    ///
    /// The plain DCPSPublications and DCPSSubscriptions topics are anybody's.
    /// What an authenticated participant announced was admitted; a change to
    /// it is taken from the secure SEDP topics (DDS Security v1.1
    /// Sec.7.4.1.7, 7.4.1.8), which only that participant can seal, and HDDS
    /// sends its own changes there (`sedp_for_peer`): an announcement of a
    /// new endpoint, the dispose of a deleted one, a repair. The same rule as
    /// for its participant announcements (Sec.7.4.1.6), applied to its
    /// endpoints, whole: one datagram re-announcing an admitted reader with
    /// another locator redirected the samples our writers send it; with
    /// another QoS it changed what the data plane does (an OWNERSHIP_STRENGTH
    /// blocked the writer for good, a LIFESPAN expired samples); a dispose
    /// unmatched it.
    ///
    /// Not refused here: a plain announcement of an endpoint not known yet,
    /// and everything from a participant that has not authenticated. A plain
    /// announcement of a topic our governance announces on the secure topics
    /// is refused by `refuses_plain_announcement_of`, whoever sends it. A
    /// plain re-announcement that changes nothing is ignored too, and loses
    /// nothing.
    ///
    /// Under a governance document the rule narrows to the endpoints that
    /// participant announced on a secure SEDP topic: the others are its
    /// endpoints of topics whose discovery is not protected (Table 29), and it
    /// changes them on the regular topics, where it announced them. Without
    /// one, nothing designates a topic as not sensitive - Sec.7.4.1.7 and
    /// 7.4.1.8 leave that to the AccessControl plugin - so every change of an
    /// authenticated participant's known endpoint is taken from the secure
    /// topics only.
    ///
    /// An endpoint admitted without a unicast locator does not learn one from
    /// a plain re-announcement either. Taking the first one offered would be
    /// first-come: a forger that is quicker than a peer which never sends one
    /// would install its address. Refusing costs nothing: samples for an
    /// endpoint with no locator of its own go to its participant's admitted
    /// default locator.
    ///
    /// A retired secure endpoint is ignored too: its live membership is gone
    /// with its disposal, and what still designates it is the sequence
    /// tombstone of the secure topic ([`Self::announced_on_secure_sedp`]).
    /// Without that, a plain announcement would bring back an endpoint a
    /// protected dispose removed, everywhere our own governance does not
    /// cover the topic.
    ///
    /// Read by the doors a plain announcement takes: the SEDP handler, before
    /// its own registrations and before applying a dispose, its reassembly
    /// path, and `handle_sedp_on`.
    pub(crate) fn ignores_plain_sedp_about(&self, endpoint_guid: &GUID) -> bool {
        let prefix = endpoint_guid.prefix;
        if prefix == self.local_guid.prefix || !self.is_authenticated_participant(&prefix) {
            return false;
        }
        // Under a governance document an authenticated participant announces
        // on the regular topics every endpoint whose topic is not discovery
        // protected (Table 29), and changes it there too. What it announced
        // on a secure topic is changed only there.
        #[cfg(feature = "security")]
        if self.discovery_governance.is_some() {
            let secure = self.announced_on_secure_sedp(endpoint_guid);
            if secure {
                log::debug!(
                    "[security] plain SEDP about endpoint {:?} of authenticated participant \
                     {:02x?}: ignored, it was announced on the secure SEDP topics",
                    endpoint_guid,
                    prefix
                );
            }
            return secure;
        }
        #[cfg(feature = "security")]
        let announced_securely = self.announced_on_secure_sedp(endpoint_guid);
        #[cfg(not(feature = "security"))]
        let announced_securely = false;
        let known = announced_securely
            || recover_read(
                Arc::as_ref(&self.topic_registry),
                "DiscoveryFsm::ignores_plain_sedp_about",
            )
            .find_endpoints_by_prefix(&prefix)
            .iter()
            .any(|endpoint| endpoint.endpoint_guid == *endpoint_guid);
        if known {
            log::debug!(
                "[security] plain SEDP about endpoint {:?} of authenticated participant \
                 {:02x?}: ignored, a change is taken only from the secure SEDP topics",
                endpoint_guid,
                prefix
            );
        }
        known
    }

    /// Whether `endpoint_guid` was announced on the secure SEDP topics: its
    /// live membership
    /// ([`Self::track_secure_endpoint`]), or, once the endpoint has been
    /// retired, the sequence tombstone its dispose left. The tombstone is
    /// what keeps the deletion final: it outlives the membership until the
    /// participant goes or a prefix at capacity reclaims it.
    #[cfg(feature = "security")]
    fn announced_on_secure_sedp(&self, endpoint_guid: &GUID) -> bool {
        if self
            .secure_endpoints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(endpoint_guid)
        {
            return true;
        }
        self.sedp_change_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&(SedpChannel::Secure, *endpoint_guid))
    }

    /// Whether the participant `prefix` has completed authentication with
    /// us. False without the `security` feature or a handshake machine.
    fn is_authenticated_participant(&self, prefix: &[u8; 12]) -> bool {
        #[cfg(not(feature = "security"))]
        let _ = prefix;
        #[cfg(feature = "security")]
        if let Some(ref machine) = self.handshake_machine {
            // The handshake map keys on the participant entity id.
            return machine.is_authenticated(&GUID::new(
                *prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ));
        }
        false
    }

    /// Whether our governance refuses to pair an endpoint of topic `topic`
    /// owned by the remote participant `prefix` because that participant is
    /// "Unauthenticated": it holds no handshake session with us, having
    /// presented no identity token (DDS Security v1.1 Sec.8.8.2.1). A
    /// participant whose session is in progress or failed is not this case:
    /// `admits_endpoint` holds its endpoints back until it completes.
    ///
    /// Sec.8.8.2.2: with `allow_unauthenticated_participants` FALSE the
    /// participant "shall reject remote DomainParticipant entities that are
    /// not able to authenticate": every endpoint is refused.
    ///
    /// Sec.8.8.7.1: with it TRUE, of endpoints discovered from an
    /// "Unauthenticated" participant it "shall: Reject (do not try to match)
    /// local endpoints for which the related TopicSecurityAttributes have the
    /// attribute is_read_protected or is_write_protected set to TRUE." A
    /// remote endpoint pairs only with local endpoints of its own topic, so
    /// the topic decides.
    ///
    /// False without a governance document, and for this participant's own
    /// endpoints.
    #[cfg(feature = "security")]
    pub(crate) fn refuses_unauthenticated(&self, prefix: &[u8; 12], topic: &str) -> bool {
        let Some(ref governance) = self.discovery_governance else {
            return false;
        };
        if *prefix == self.local_guid.prefix || !self.is_unauthenticated_participant(prefix) {
            return false;
        }
        !governance.allows_unauthenticated() || governance.topic_is_access_protected(topic)
    }

    /// Whether an "Unauthenticated" participant - one we know nothing of
    /// included - is refused on `topic` (`refuses_unauthenticated`): a
    /// governance document that refuses unauthenticated participants, or
    /// protects the topic's access. A writer of such a topic sends nothing to
    /// an audience it does not know (the multicast fallback).
    #[cfg(feature = "security")]
    pub(crate) fn unauthenticated_gate_applies(&self, topic: &str) -> bool {
        self.discovery_governance
            .as_ref()
            .is_some_and(|governance| {
                !governance.allows_unauthenticated() || governance.topic_is_access_protected(topic)
            })
    }

    /// Whether this participant runs the security plugins that judge a
    /// remote participant's endpoints: a handshake machine, a governance
    /// document, or a local restriction overlay. Without any of the three
    /// every admission is `Admitted` and the data plane skips the gate (one
    /// flag, resolved once by its readers).
    #[cfg(feature = "security")]
    pub(crate) fn admission_gate_active(&self) -> bool {
        self.handshake_machine.is_some()
            || self.discovery_governance.is_some()
            || self.local_restriction.is_some()
    }

    /// The value the admission verdicts are filed under: it moves with every
    /// change of anything `judge_admission` and `judge_endpoint` read - the
    /// sessions (`HandshakeMachine::state_epoch`), the topic registry (an
    /// endpoint's partitions and data tags, `topic_registry_generation`), a
    /// departure, a completed authentication and the setters
    /// (`admission_changes`). Each counter only grows, and each is moved
    /// after the change it counts.
    ///
    /// The invariant every cache fill keeps: the epoch a verdict is filed
    /// under is loaded BEFORE any input of that verdict is read - the
    /// registry copy of the endpoint included. Then every input is at least
    /// as new as the epoch says, a change landing in between moves the epoch
    /// past the filed one, and the verdict is never read again. Loaded after
    /// an input, the epoch can describe a change the verdict never saw: a
    /// verdict on the old partitions filed under the new epoch, stale until
    /// the epoch next moves. A verdict filed under an older value than the
    /// cache's is dropped (`file_admission`).
    #[cfg(feature = "security")]
    fn admission_epoch(&self) -> u64 {
        self.admission_changes
            .load(Ordering::Acquire)
            .wrapping_add(self.topic_registry_generation.load(Ordering::Acquire))
            .wrapping_add(
                self.handshake_machine
                    .as_ref()
                    .map_or(0, |machine| machine.state_epoch()),
            )
            .wrapping_add(
                self.local_restriction
                    .as_ref()
                    .map_or(0, |suite| suite.local_restriction_generation()),
            )
    }

    /// THE admission verdict of a remote participant's endpoint of `topic`
    /// (a writer when `remote_is_writer`): what discovery's match decides
    /// (`admits_endpoint`) and what every data path applies - the list our
    /// writers send data, heartbeats and repairs to, the participant
    /// fallback, the ACKNACKs a writer answers, the samples and lifecycle
    /// changes a reader accepts.
    ///
    /// Reached at most once per (participant, topic, kind) between two
    /// changes of what it reads (`admission_epoch`), at the first packet that
    /// asks: the credentials are copied and the permissions evaluated then,
    /// never per packet. Then one cache lookup. Bounded: at
    /// `ADMISSION_CACHE_CAP` entries the cache starts over, so participant
    /// prefixes nobody announced cost a recomputation, never memory.
    #[cfg(feature = "security")]
    fn admission(&self, prefix: &[u8; 12], topic: &str, remote_is_writer: bool) -> Admission {
        if !self.admission_gate_active() || *prefix == self.local_guid.prefix {
            return Admission::Admitted;
        }
        let kind = usize::from(remote_is_writer);
        let epoch = self.admission_epoch();
        {
            let cache = recover_read(&self.admission_cache, "DiscoveryFsm::admission");
            if cache.epoch == epoch {
                if let Some(admission) = cache
                    .verdicts
                    .get(prefix)
                    .and_then(|topics| topics.get(topic))
                    .and_then(|kinds| kinds[kind])
                {
                    return admission;
                }
            }
        }
        let admission = self
            .judge_admission(prefix, topic, remote_is_writer)
            .unwrap_or(Admission::Refused);
        self.file_admission(epoch, |cache| {
            cache
                .verdicts
                .entry(*prefix)
                .or_default()
                .entry(topic.to_string())
                .or_default()[kind] = Some(admission);
        });
        admission
    }

    /// File something in the admission cache, reached under `epoch`: the
    /// cache starts over when `epoch` is newer than its own, and nothing
    /// reached under an older one is filed.
    #[cfg(feature = "security")]
    fn file_admission(&self, epoch: u64, file: impl FnOnce(&mut AdmissionCache)) {
        let mut cache = recover_write(&self.admission_cache, "DiscoveryFsm::file_admission");
        if epoch > cache.epoch {
            cache.clear();
            cache.epoch = epoch;
        }
        if epoch != cache.epoch {
            return;
        }
        if cache.entries >= ADMISSION_CACHE_CAP {
            cache.clear();
        }
        cache.entries += 1;
        file(&mut cache);
    }

    /// The admission rules, uncached (`admission` caches them):
    ///
    /// 1. DDS Security v1.1 Sec.8.8.2.2, 8.8.7.1 (`refuses_unauthenticated`):
    ///    an "Unauthenticated" participant is refused on a domain that does
    ///    not allow such participants, and on a read or write protected
    ///    topic.
    /// 2. Sec.9.3.4: a participant holding a session is refused until the
    ///    session completes, and for good if it fails. A participant that
    ///    never advertised an identity token holds no session and passes,
    ///    as rule 1 decides for it.
    /// 3. Sec.9.4.3 (check_remote_datawriter / check_remote_datareader): the
    ///    permissions document the peer presented in its handshake (`c.perm`)
    ///    decides, by the topic alone or by each endpoint's partitions and
    ///    data tags (`Admission::PerEndpoint`, `judge_endpoint`,
    ///    Sec.9.4.1.3.2.3).
    ///
    /// 4. The local restriction overlay (`local_restriction`): our OWN
    ///    rules, narrowing what the signed documents above granted. A
    ///    remote writer is judged against our subscribe rules (we would be
    ///    the reader of it), a remote reader against our publish rules (we
    ///    would be the writer sending to it). Probed against the default
    ///    partition here (this pass has no endpoint, so no announced
    ///    partitions to probe with): an unconditional refusal (a rule with
    ///    no `partitions=` clause, which applies to every partition
    ///    including the default) is decided outright. Otherwise, when the
    ///    overlay carries any rule SCOPED to a partition
    ///    (`local_restriction_is_partition_scoped`), the default-partition
    ///    probe is not authoritative for every partition a remote endpoint
    ///    might announce, and the verdict defers to `Admission::PerEndpoint`
    ///    so `judge_endpoint` re-checks it against the endpoint's OWN
    ///    announced partitions once they are known.
    ///
    /// `Err` carries the reason, for the match's log.
    #[cfg(feature = "security")]
    fn judge_admission(
        &self,
        prefix: &[u8; 12],
        topic: &str,
        remote_is_writer: bool,
    ) -> Result<Admission, Refusal> {
        let mut needs_per_endpoint = false;
        if let Some(ref suite) = self.local_restriction {
            let action = if remote_is_writer {
                crate::security::permissions::RuleAction::Subscribe
            } else {
                crate::security::permissions::RuleAction::Publish
            };
            if let Err(reason) = suite.check_local_restriction(action, topic, &[]) {
                return Err(Refusal {
                    reason: reason.to_string(),
                    loud: true,
                });
            }
            if suite.local_restriction_is_partition_scoped(action, topic) {
                needs_per_endpoint = true;
            }
        }
        if self.refuses_unauthenticated(prefix, topic) {
            return Err(Refusal {
                reason: "its participant is not authenticated, and our governance protects the \
                         topic or refuses such participants"
                    .to_string(),
                loud: false,
            });
        }
        let Some(ref machine) = self.handshake_machine else {
            return Ok(Self::admitted_or_per_endpoint(needs_per_endpoint));
        };
        // The handshake map keys on ENTITYID_PARTICIPANT; a key built with
        // any other entity id never hits (`EndpointInfo::participant_guid`
        // carries [0,0,0,0]), and the gates below would be shut, or open,
        // for every peer.
        let participant = GUID::new(
            *prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        if machine.has_session(&participant) && !machine.is_authenticated(&participant) {
            return Err(Refusal {
                reason: "its participant has not completed authentication".to_string(),
                loud: false,
            });
        }
        // Authentication settled WHO the peer is; this settles what it may
        // do. The two credentials come in one piece (`peer_credentials`).
        if let Some(ref access) = self.remote_access_control {
            if let Some((peer_cert, peer_permissions)) = machine.peer_credentials(&participant) {
                return match access.check_remote_endpoint(
                    &participant,
                    &peer_cert,
                    peer_permissions.as_deref(),
                    topic,
                    remote_is_writer,
                ) {
                    Ok(crate::security::access::TopicScope::Any) => {
                        Ok(Self::admitted_or_per_endpoint(needs_per_endpoint))
                    }
                    Ok(crate::security::access::TopicScope::PerEndpoint) => {
                        Ok(Admission::PerEndpoint)
                    }
                    Err(reason) => Err(Refusal {
                        reason: format!("peer {:?}: {}", participant, reason),
                        loud: true,
                    }),
                };
            }
        }
        Ok(Self::admitted_or_per_endpoint(needs_per_endpoint))
    }

    /// `Admission::PerEndpoint` when `needs_per_endpoint`, else
    /// `Admission::Admitted`: the three exit points of `judge_admission`
    /// that would otherwise all say `Admitted` outright, since the local
    /// restriction overlay alone can demand the endpoint's own partitions.
    #[cfg(feature = "security")]
    fn admitted_or_per_endpoint(needs_per_endpoint: bool) -> Admission {
        if needs_per_endpoint {
            Admission::PerEndpoint
        } else {
            Admission::Admitted
        }
    }

    /// `check_remote_datawriter` / `check_remote_datareader` (DDS-Security
    /// v1.1 Sec.8.4.2.9.10, 8.4.2.9.11) for the remote `endpoint` as its
    /// announcement describes it: the permissions document its participant
    /// presented, rules in document order, on the endpoint's partitions and
    /// data tags (Sec.9.4.1.3.2.3). Uncached; reached under
    /// `Admission::PerEndpoint` only, and cached by its callers
    /// (`endpoint_admitted`).
    ///
    /// Fails closed: when the signed documents are what demanded
    /// `Admission::PerEndpoint`, credentials or access control missing
    /// here mean they went in between `judge_admission` and here (the
    /// session dropped, the participant removed), and nothing is left to
    /// judge the endpoint by. `Admission::PerEndpoint` can also be reached
    /// purely from the local restriction overlay below, with neither a
    /// handshake machine nor a signed access control plugin configured at
    /// all; that is not a credential loss, so it is not refused here - the
    /// overlay check above already decided everything there was to decide.
    #[cfg(feature = "security")]
    fn judge_endpoint(&self, endpoint: &EndpointInfo) -> Result<(), Refusal> {
        let remote_is_writer = matches!(endpoint.kind, EndpointKind::Writer);

        // The local restriction overlay, against the partitions the
        // endpoint actually announced (`judge_admission`'s topic-level pass
        // only had the default partition to probe with).
        if let Some(ref suite) = self.local_restriction {
            let action = if remote_is_writer {
                crate::security::permissions::RuleAction::Subscribe
            } else {
                crate::security::permissions::RuleAction::Publish
            };
            if let Err(reason) = suite.check_local_restriction(
                action,
                &endpoint.topic_name,
                &endpoint.qos.partition.names,
            ) {
                return Err(Refusal {
                    reason: reason.to_string(),
                    loud: true,
                });
            }
        }

        // PID_ENDPOINT_SECURITY_INFO: see `endpoint_security_info_refusal`.
        // Run here too (not only from its other two callers) so a pair
        // `Admission::PerEndpoint` reaches for an UNRELATED reason
        // (partitions, a signed document) is judged by it as well.
        if let Some(refusal) = self.endpoint_security_info_refusal(endpoint) {
            return Err(refusal);
        }

        let participant = GUID::new(
            endpoint.endpoint_guid.prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let (Some(machine), Some(access)) = (
            self.handshake_machine.as_ref(),
            self.remote_access_control.as_ref(),
        ) else {
            // NEITHER half of the signed-document pathway was ever
            // configured: the overlay above was the only possible reason
            // `Admission::PerEndpoint` was reached, and it has already
            // decided. Either half present alone (a handshake machine with
            // no access control plugin, or the reverse) is the ORIGINAL
            // fail-closed case below, unchanged: a participant that
            // intended signed-document security but is missing half of it,
            // or whose peer's session went between `judge_admission` and
            // here, judges nothing by it and refuses.
            if self.handshake_machine.is_none() && self.remote_access_control.is_none() {
                return Ok(());
            }
            return Err(Refusal {
                reason: format!(
                    "peer {:?}: no credentials to judge its endpoint by (its session went)",
                    participant
                ),
                loud: false,
            });
        };
        let Some((peer_cert, peer_permissions)) = machine.peer_credentials(&participant) else {
            return Err(Refusal {
                reason: format!(
                    "peer {:?}: no credentials to judge its endpoint by (its session went)",
                    participant
                ),
                loud: false,
            });
        };
        access
            .check_remote_endpoint_qualified(
                &participant,
                &peer_cert,
                peer_permissions.as_deref(),
                &endpoint.topic_name,
                remote_is_writer,
                &endpoint.qos.partition.names,
                &endpoint.qos.data_tags.tags,
            )
            .map_err(|reason| Refusal {
                reason: format!("peer {:?}: {}", participant, reason),
                loud: true,
            })
    }

    /// PID_ENDPOINT_SECURITY_INFO (DDS-Security v1.1 Sec.7.2.8, 7.4.1.5):
    /// the remote endpoint's own announced protections against the local
    /// topic's `EndpointSecurityAttributes`, attribute by attribute
    /// (`EndpointSecurityInfo::matches`). `None` from
    /// `topic_endpoint_attributes` (no governance, or no topic rule matches
    /// this one) leaves this undecided -- `None` here too.
    ///
    /// Deliberately independent of the signed-document pathway
    /// (`handshake_machine`/`remote_access_control`): it is a plain wire
    /// comparison, so it is consulted from all three doors an endpoint is
    /// judged through -- `judge_endpoint` (an `Admission::PerEndpoint`
    /// reached for another reason), and the `Admission::Admitted` arms of
    /// `endpoint_refusal` and `admits_remote_endpoint` -- rather than
    /// folded into `judge_admission`'s `needs_per_endpoint`, which would
    /// route a topic with nothing but this check through `judge_endpoint`'s
    /// OWN fail-closed rule above for a reason that has nothing to do with
    /// it (a topic with no access control and no signed documents would
    /// start refusing every peer whose handshake machine had no matching
    /// access control plugin).
    #[cfg(feature = "security")]
    fn endpoint_security_info_refusal(&self, endpoint: &EndpointInfo) -> Option<Refusal> {
        let local_attributes = self
            .discovery_governance
            .as_ref()
            .and_then(|governance| governance.topic_endpoint_attributes(&endpoint.topic_name))?;
        let local_info = local_attributes.security_info();
        let remote_info = endpoint.endpoint_security_info.unwrap_or_default();
        if local_info.matches(&remote_info) {
            None
        } else {
            Some(Refusal {
                reason: format!(
                    "its PID_ENDPOINT_SECURITY_INFO ({:?}) does not match the local topic's \
                     EndpointSecurityAttributes ({:?})",
                    remote_info, local_info
                ),
                loud: true,
            })
        }
    }

    /// The verdict of `judge_endpoint` for `endpoint`, cached per (GUID,
    /// topic, kind) under the admission epoch: one lookup per packet.
    /// `epoch` is the admission epoch the caller loaded BEFORE it read
    /// `endpoint` from the registry (`admission_epoch`).
    #[cfg(feature = "security")]
    fn endpoint_admitted(&self, endpoint: &EndpointInfo, epoch: u64) -> bool {
        let remote_is_writer = matches!(endpoint.kind, EndpointKind::Writer);
        if let Some(admitted) = self.cached_endpoint_verdict(
            epoch,
            &endpoint.endpoint_guid,
            &endpoint.topic_name,
            remote_is_writer,
        ) {
            return admitted;
        }
        let admitted = self.judge_endpoint(endpoint).is_ok();
        self.file_endpoint_verdict(epoch, endpoint, remote_is_writer, admitted);
        admitted
    }

    /// `endpoint_security_info_refusal` for `endpoint`, cached the same way
    /// as `endpoint_admitted` (same cache, same slot: the two are never
    /// both filled for the same (GUID, topic, kind) under one epoch, since
    /// `admission` already decided which of `Admission::Admitted` or
    /// `Admission::PerEndpoint` applies before either is called). Reached
    /// when the topic-level pass found no OTHER reason to look at this
    /// endpoint's own partitions or data tags, but PID_ENDPOINT_SECURITY_INFO
    /// is still a per-endpoint field that `judge_admission` cannot read.
    #[cfg(feature = "security")]
    fn endpoint_security_info_admitted(&self, endpoint: &EndpointInfo, epoch: u64) -> bool {
        let remote_is_writer = matches!(endpoint.kind, EndpointKind::Writer);
        if let Some(admitted) = self.cached_endpoint_verdict(
            epoch,
            &endpoint.endpoint_guid,
            &endpoint.topic_name,
            remote_is_writer,
        ) {
            return admitted;
        }
        let admitted = self.endpoint_security_info_refusal(endpoint).is_none();
        self.file_endpoint_verdict(epoch, endpoint, remote_is_writer, admitted);
        admitted
    }

    /// File `admitted` for `endpoint` under `epoch` (`endpoint_admitted`,
    /// `endpoint_security_info_admitted`).
    #[cfg(feature = "security")]
    fn file_endpoint_verdict(
        &self,
        epoch: u64,
        endpoint: &EndpointInfo,
        remote_is_writer: bool,
        admitted: bool,
    ) {
        self.file_admission(epoch, |cache| {
            cache
                .endpoint_verdicts
                .entry(endpoint.endpoint_guid)
                .or_default()
                .entry(endpoint.topic_name.clone())
                .or_default()[usize::from(remote_is_writer)] = Some(admitted);
        });
    }

    /// The verdict cached for the remote endpoint `guid` of `topic` as a
    /// writer (`remote_is_writer`) or a reader, under `epoch`.
    #[cfg(feature = "security")]
    fn cached_endpoint_verdict(
        &self,
        epoch: u64,
        guid: &GUID,
        topic: &str,
        remote_is_writer: bool,
    ) -> Option<bool> {
        let cache = recover_read(&self.admission_cache, "DiscoveryFsm::endpoint_admitted");
        if cache.epoch != epoch {
            return None;
        }
        cache
            .endpoint_verdicts
            .get(guid)
            .and_then(|topics| topics.get(topic))
            .and_then(|kinds| kinds[usize::from(remote_is_writer)])
    }

    /// Whether the remote endpoint `endpoint_guid` of `topic` (a writer when
    /// `remote_is_writer`) is admitted (`admission`): the data plane's door,
    /// for a reader's samples and lifecycle changes and a writer's ACKNACKs.
    /// When the permissions decide per endpoint, its partitions and data tags
    /// are read from its announcement (`endpoint_admitted`), once per
    /// admission epoch; one discovery has not announced, or announced as the
    /// other kind, is refused.
    #[cfg(feature = "security")]
    pub(crate) fn admits_remote_endpoint(
        &self,
        topic: &str,
        endpoint_guid: &GUID,
        remote_is_writer: bool,
    ) -> bool {
        match self.admission(&endpoint_guid.prefix, topic, remote_is_writer) {
            Admission::Admitted => {
                // Before the registry read (`admission_epoch`).
                let epoch = self.admission_epoch();
                if let Some(admitted) =
                    self.cached_endpoint_verdict(epoch, endpoint_guid, topic, remote_is_writer)
                {
                    return admitted;
                }
                let Some(endpoint) = recover_read(
                    Arc::as_ref(&self.topic_registry),
                    "DiscoveryFsm::admits_remote_endpoint registry",
                )
                .endpoint(topic, endpoint_guid)
                .cloned() else {
                    // Admitted at the topic level and the endpoint not even
                    // known: nothing to compare PID_ENDPOINT_SECURITY_INFO
                    // against, so this check admits.
                    return true;
                };
                self.endpoint_security_info_admitted(&endpoint, epoch)
            }
            Admission::Refused => false,
            Admission::PerEndpoint => {
                // Before the registry read (`admission_epoch`).
                let epoch = self.admission_epoch();
                if let Some(admitted) =
                    self.cached_endpoint_verdict(epoch, endpoint_guid, topic, remote_is_writer)
                {
                    return admitted;
                }
                let Some(endpoint) = recover_read(
                    Arc::as_ref(&self.topic_registry),
                    "DiscoveryFsm::admits_remote_endpoint registry",
                )
                .endpoint(topic, endpoint_guid)
                .cloned() else {
                    return false;
                };
                #[cfg(test)]
                self.run_endpoint_read_hook();
                matches!(endpoint.kind, EndpointKind::Writer) == remote_is_writer
                    && self.endpoint_admitted(&endpoint, epoch)
            }
        }
    }

    /// Run, once, the hook a test set on the endpoint read
    /// (`endpoint_read_hook`).
    #[cfg(all(test, feature = "security"))]
    fn run_endpoint_read_hook(&self) {
        let hook = self
            .endpoint_read_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Run, once, the hook a test set on the withholding
    /// (`replay_withheld_hook`).
    #[cfg(all(test, feature = "security"))]
    fn run_replay_withheld_hook(&self) {
        let hook = self
            .replay_withheld_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Tests only: how many replays are withheld for the readers of
    /// `prefix`.
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn withheld_replays_of(&self, prefix: &[u8; 12]) -> usize {
        self.withheld_replays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len_of(prefix)
    }

    /// Tests only: run `hook` once, right before the next replay is
    /// withheld (`replay_withheld_hook`).
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn set_replay_withheld_hook(&self, hook: impl FnOnce() + Send + Sync + 'static) {
        *self
            .replay_withheld_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(hook));
    }

    /// Tests only: run `hook` once, right after the next admission check
    /// read the endpoint copy it judges (`endpoint_read_hook`).
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn set_endpoint_read_hook(&self, hook: impl FnOnce() + Send + Sync + 'static) {
        *self
            .endpoint_read_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(hook));
    }

    /// Whether our writer of `reader.topic_name` sends to the remote reader
    /// `reader` (`admission`, with the partitions and data tags it
    /// announced). `epoch` was loaded before `reader` was read from the
    /// registry (`admission_epoch`).
    #[cfg(feature = "security")]
    fn admits_remote_reader(&self, reader: &EndpointInfo, epoch: u64) -> bool {
        match self.admission(&reader.endpoint_guid.prefix, &reader.topic_name, false) {
            Admission::Admitted => self.endpoint_security_info_admitted(reader, epoch),
            Admission::Refused => false,
            Admission::PerEndpoint => self.endpoint_admitted(reader, epoch),
        }
    }

    /// Whether our writer of `topic` sends to the participant `prefix`
    /// before any reader of it is known (the participant fallback): only
    /// when its readers of the topic are admitted in every partition, as
    /// their partitions are not known yet.
    #[cfg(feature = "security")]
    pub(crate) fn admits_participant_fallback(&self, prefix: &[u8; 12], topic: &str) -> bool {
        self.admission(prefix, topic, false) == Admission::Admitted
    }

    /// Whether the remote participant `prefix` is "Unauthenticated" (DDS
    /// Security v1.1 Sec.8.8.2.1): it holds no handshake session here, in
    /// any state. Every remote participant is, without a handshake machine.
    #[cfg(feature = "security")]
    fn is_unauthenticated_participant(&self, prefix: &[u8; 12]) -> bool {
        self.handshake_machine.as_ref().is_none_or(|machine| {
            !machine.has_session(&GUID::new(
                *prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ))
        })
    }

    /// The lease an announcement is admitted with: the one it carries,
    /// bounded by `PENDING_AUTHENTICATION_LEASE_BOUND_MS` while the
    /// participant's handshake is pending - it holds a session that has not
    /// completed. The declared lease is kept aside (`declared_leases`) and
    /// restored when the handshake completes.
    fn admitted_lease_ms(&self, data: &SpdpData) -> u64 {
        #[cfg(feature = "security")]
        if let Some(ref machine) = self.handshake_machine {
            let participant = GUID::new(
                data.participant_guid.prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            );
            if machine.has_session(&participant) && !machine.is_authenticated(&participant) {
                recover_write(&self.declared_leases, "DiscoveryFsm::admitted_lease_ms")
                    .entry(data.participant_guid.prefix)
                    .and_modify(|declared| *declared = (*declared).min(data.lease_duration_ms))
                    .or_insert(data.lease_duration_ms);
                return data
                    .lease_duration_ms
                    .min(PENDING_AUTHENTICATION_LEASE_BOUND_MS);
            }
        }
        data.lease_duration_ms
    }

    /// The handshake of `prefix` completed: it holds the lease it declared
    /// while the handshake was pending, unbounded
    /// (`PENDING_AUTHENTICATION_LEASE_BOUND_MS`) - the SHORTEST it declared.
    /// Later plain announcements cannot change it (liveliness only).
    ///
    /// Why the shortest. None of those announcements is authenticated: the
    /// handshake's `c.pdata` carries the GUID only, so it vouches for none of
    /// them,
    /// and taking the last let a forger who sent an infinite lease during the
    /// handshake window make the participant immortal once it authenticated.
    /// A legitimate participant declares the same lease in every
    /// announcement, so the shortest is its lease; a forger can only make it
    /// shorter, which costs a participant that keeps announcing nothing, and
    /// can never make it longer. The first announcement instead would be the
    /// forger's too, if sent before the participant's own.
    #[cfg(feature = "security")]
    fn restore_declared_lease(&self, prefix: [u8; 12]) {
        let Some(declared) = recover_write(
            &self.declared_leases,
            "DiscoveryFsm::restore_declared_lease",
        )
        .remove(&prefix) else {
            return;
        };
        let mut db = recover_write(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::restore_declared_lease",
        );
        if let Some(info) = db.values_mut().find(|info| info.guid.prefix == prefix) {
            info.lease_duration_ms = declared;
        }
    }

    /// The metatraffic locators and the lease the participant `prefix` is
    /// known by, as admitted: what an SPDP handler addresses its
    /// announcements to for an authenticated peer, whose plain announcements
    /// carry nothing it may act on ([`SpdpVerdict::LivelinessOnly`]).
    pub(crate) fn admitted_locators_and_lease(
        &self,
        prefix: &[u8; 12],
    ) -> Option<(Vec<std::net::SocketAddr>, u64)> {
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::admitted_locators_and_lease",
        );
        db.values()
            .find(|info| info.guid.prefix == *prefix)
            .map(|info| (info.endpoints.clone(), info.lease_duration_ms))
    }

    /// Handle SEDP (endpoint discovery) packet.
    ///
    /// Inserts or updates endpoint in topic registry.
    /// Validates that participant exists before inserting endpoint.
    /// Performs automatic endpoint matching (Phase 1.4).
    pub fn handle_sedp(&self, data: SedpData) {
        self.handle_sedp_on(data, SedpChannel::Plain);
    }

    /// [`Self::handle_sedp`], for an announcement that arrived on `channel`.
    ///
    /// A plain announcement of an endpoint an authenticated participant
    /// already announced is ignored ([`Self::ignores_plain_sedp_about`]).
    pub(crate) fn handle_sedp_on(&self, data: SedpData, channel: SedpChannel) {
        crate::trace_fn!("DiscoveryFsm::handle_sedp");
        self.metrics.sedp_received.fetch_add(1, Ordering::Relaxed);
        if channel == SedpChannel::Plain && self.ignores_plain_sedp_about(&data.endpoint_guid) {
            return;
        }
        #[cfg(feature = "security")]
        if channel == SedpChannel::Secure && !self.track_secure_endpoint(data.endpoint_guid) {
            return;
        }

        // Probation completion. We call this from both `handle_spdp`
        // and `handle_sedp` so the boundary fires even if no SPDP
        // arrives between probation start and the next SEDP. Without
        // this, entries deferred during probation could remain in
        // `pending_notifications` indefinitely under SPDP-sparse
        // workloads. The helper is one-shot via CAS, so concurrent
        // calls are safe.
        self.maybe_complete_probation();

        // Extract participant prefix from endpoint GUID (first 12 bytes).
        let endpoint_prefix = &data.endpoint_guid.as_bytes()[..12];
        let local_prefix = &self.local_guid.as_bytes()[..12];

        // Check if endpoint is local (Phase 1.4)
        let is_local_endpoint = endpoint_prefix == local_prefix;

        // Find participant with matching prefix (read lock).
        // Skip check for local endpoints (they're not in ParticipantDB)
        let participant_exists = is_local_endpoint || {
            let db = recover_read(
                Arc::as_ref(&self.db),
                "DiscoveryFsm::handle_sedp participant",
            );
            db.keys()
                .any(|participant_guid| &participant_guid.as_bytes()[..12] == endpoint_prefix)
        };

        if !participant_exists {
            // Buffer SEDP from unknown participants (SPDP not yet processed).
            // A peer may send SEDP on unicast before its SPDP arrives on
            // multicast. Replay when handle_spdp registers it.
            let held = {
                let mut pending = recover_write(
                    Arc::as_ref(&self.pending_sedp),
                    "DiscoveryFsm::handle_sedp pending_sedp",
                );
                if pending.len() < PENDING_SEDP_CAPACITY {
                    log::debug!(
                        "[SEDP] Buffering SEDP from unknown participant (prefix={:02x?}), will replay on SPDP",
                        &endpoint_prefix[..4]
                    );
                    pending.push(data.clone());
                    true
                } else {
                    log::warn!(
                        "[SEDP] Pending SEDP buffer full (64), dropping from prefix={:02x?}",
                        &endpoint_prefix[..4]
                    );
                    false
                }
            };
            // A held writer's samples are routed by the topic its
            // announcement names from the moment it arrives: each local
            // reader's QoS verdict on it is recorded now, so that a reader it
            // does not match drops them (`judge_remote_writer_qos`; judged
            // again when the announcement is replayed). Only an announcement
            // held: one the full buffer drops is as if never received, and
            // the verdicts on held writers are bounded by the buffer and
            // leave with their announcement (`remove_remote_endpoint`,
            // `forget_endpoints_of`).
            if held && EndpointKind::from_guid(&data.endpoint_guid) == EndpointKind::Writer {
                if let Some(reg) = self.match_registry.get() {
                    let held = EndpointInfo::from_sedp(data, self.get_locked_dialect());
                    reg.judge_remote_writer_qos(&held, false, false);
                }
            }
            return;
        }
        #[cfg(test)]
        if !is_local_endpoint {
            let hook = self
                .sedp_admitted_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }

        // A remote SEDP is the participant speaking: a liveness mark, counted
        // only at a distinct instant (`ParticipantInfo::mark_alive`). A SEDP
        // replayed from `pending_sedp` runs right after the SPDP that drives
        // the replay, inside the same instant, and so counts nothing more.
        let may_be_purged = !is_local_endpoint && self.note_participant_liveness(endpoint_prefix);

        // Retain the remote SEDP of a participant the probation heuristics
        // may still purge, so that a purge of a live participant can be
        // replayed when it announces again (see the `probation_sedp` field
        // doc).
        if may_be_purged && !self.probation_cohort_settled.load(Ordering::Acquire) {
            let mut retained = recover_write(
                Arc::as_ref(&self.probation_sedp),
                "DiscoveryFsm::handle_sedp probation_sedp",
            );
            if retained.len() < PENDING_SEDP_CAPACITY {
                retained.push(data.clone());
            }
        }

        // Cross-vendor type resolution: vendors announce only
        // PID_TYPE_INFORMATION (equivalence hashes), never an inline
        // PID_TYPE_OBJECT. Resolve the announced minimal hash against the
        // local type store so every downstream type-compatibility gate
        // (match blocking, on_inconsistent_topic, mark_writer_incompatible)
        // receives a concrete CompleteTypeObject. Resolution MISS leaves
        // `type_object` as None = today's "absent -> allow" behavior, so
        // unknown or hash-divergent peers are never falsely rejected.
        // HDDS peers announce PID_TYPE_OBJECT directly (type_object already
        // Some) and skip this entirely; `--disable-type-info` endpoints
        // announce neither, so they also skip it.
        #[cfg(feature = "xtypes-structural-assignability")]
        let data = {
            let mut data = data;
            // Register the dependents the legacy TypeObject v1 decoder
            // produced (xtypes::decode_type_object_v1, SedpData::dependents):
            // the named types `data.type_object` references by
            // TypeIdentifier::Minimal(hash). Unregistered, those hashes do
            // not resolve and the structural verdict on any member typed
            // that way cannot be reached. Always empty for CDR2 payloads.
            if !data.dependents.is_empty() {
                if let Some(reg) = self.match_registry.get() {
                    reg.register_type_objects(data.dependents.drain(..).collect());
                }
            }
            if data.type_object.is_none() {
                if let (Some(ti), Some(reg)) =
                    (data.type_information.as_ref(), self.match_registry.get())
                {
                    // 3-recourse chain (minimal hash, complete hash, name):
                    // see MatchNotificationRegistry::resolve_type_information.
                    let resolved = reg.resolve_type_information(ti, &data.type_name);
                    if let Some(obj) = resolved {
                        log::debug!(
                            "[SEDP] resolved remote TypeInformation to local TypeObject for topic '{}' (remote_name='{}' resolved_name={:?})",
                            data.topic_name,
                            data.type_name,
                            obj.type_name()
                        );
                        data.type_object = Some(obj);
                    }
                }
            }
            data
        };

        // Create endpoint info (auto-detects Writer vs Reader from GUID).
        // Uses locked dialect for vendor-specific QoS defaults when no PIDs present.
        let endpoint_unicast_locators = data.unicast_locators.clone();
        let dialect = self.get_locked_dialect();
        let mut endpoint = EndpointInfo::from_sedp(data, dialect);

        // ABSENT-PID rule, XTypes v1.3 Sec 7.6.3.4.1: a REMOTE READER whose SEDP
        // omits PID_TYPE_CONSISTENCY_ENFORCEMENT (the PID is optional) gets
        // the SPEC default policy: ALLOW_TYPE_COERCION, ignore_sequence_bounds=true,
        // ignore_string_bounds=true, ignore_member_names=FALSE,
        // prevent_type_widening=false, force_type_validation=false. Without this,
        // the matcher's permissive None-fallback (ignore_member_names=true) makes
        // HDDS-as-writer MATCH readers it must reject (member names differ), and
        // the harness sees OK where INCONSISTENT_TOPIC is expected.
        //
        // Scoped to REMOTE readers ONLY (is_local_endpoint known here, not in
        // from_sedp): LOCAL endpoints that never set the policy keep the
        // permissive matcher fallback (struct_different_ids_ok expects a local
        // reader with unset policy to accept id-divergent writer types).
        if !is_local_endpoint
            && endpoint.kind == EndpointKind::Reader
            && endpoint.qos.type_consistency.is_none()
        {
            endpoint.qos.type_consistency =
                Some(crate::protocol::discovery::types::TypeConsistencyEnforcement::default());
        }

        let topic_name = endpoint.topic_name.clone();
        let type_name = endpoint.type_name.clone();
        let endpoint_kind = endpoint.kind;
        let endpoint_durability = endpoint.qos.durability;
        let endpoint_participant = endpoint.participant_guid;

        // Register reader's SEDP unicast locator for per-reader DATA routing.
        // Remote readers announce their user-data port in PID_UNICAST_LOCATOR,
        // which may differ from the participant's SPDP default_unicast (e.g. an
        // ephemeral port rather than the participant default port 7411).
        if endpoint_kind == EndpointKind::Reader {
            log::debug!(
                "[SEDP-READER] topic='{}' kind={:?} locators={:?} guid={}",
                topic_name,
                endpoint_kind,
                endpoint_unicast_locators,
                endpoint.endpoint_guid
            );
            if let Some(&locator) = select_best_locator(&endpoint_unicast_locators) {
                self.endpoint_registry
                    .register_reader_locator(endpoint.endpoint_guid, locator);
            } else {
                log::debug!(
                    "[SEDP-READER] NO locator for reader {} on topic '{}'",
                    endpoint.endpoint_guid,
                    topic_name
                );
            }
        }

        // Register writer's SEDP unicast locator for user ACKNACK routing.
        // Remote writers announce their user-session port in PID_UNICAST_LOCATOR;
        // for some vendor ids the control handler aims user ACKNACKs at that port
        // rather than the metatraffic port (see `resolve_user_acknack_port`), and
        // resolves this locator to do so.
        if endpoint_kind == EndpointKind::Writer {
            if let Some(&locator) = select_best_locator(&endpoint_unicast_locators) {
                self.endpoint_registry
                    .register_writer_locator(endpoint.endpoint_guid, locator);
            } else {
                log::debug!(
                    "[SEDP-WRITER] NO locator for writer {} on topic '{}'",
                    endpoint.endpoint_guid,
                    topic_name
                );
            }
        }

        // Parameters for a deferred inconsistent-type notification.
        // Populated inside the topic_registry write lock, fired after the
        // lock is released to avoid holding the registry lock across user
        // callbacks (which may re-enter discovery or participant code).
        // `remote_is_writer` == true when the newly discovered endpoint is a
        // Writer (notifies opposite-kind local Readers); false for Reader.
        // The fourth element carries the remote endpoint's TypeConsistencyEnforcement
        // policy so that notify_inconsistent_type_for_topic can apply the reader's
        // policy regardless of which side is local (sec. 7.6.3.4).
        let mut pending_type_incompat: Option<EndpointInfo> = None;

        // TRANSIENT_LOCAL/TRANSIENT/PERSISTENT late-joiner history replay:
        // `replay_for` synchronously sends UDP datagrams for the
        // writer's ENTIRE history, one per cached change. Collected here
        // (under the topic_registry write lock) instead of fired inline,
        // then drained AFTER the lock is released AND after the match is
        // published to callbacks below (`notify_endpoint_discovered` /
        // `notify_endpoint_discovered_incompat_only`) -- preserving "match
        // published, then replay" without blocking every OTHER
        // discovery operation on this participant's UDP sends for the
        // duration of one late joiner's full history replay.
        let mut pending_replay: Vec<(String, String, std::net::SocketAddr, Option<[u8; 16]>)> =
            Vec::new();

        let is_new = {
            // Insert into topic registry (write lock).
            let mut registry = recover_write(
                Arc::as_ref(&self.topic_registry),
                "DiscoveryFsm::handle_sedp insert_endpoint",
            );
            // A re-announcement (a QoS refresh, a repair, the same SEDP sent
            // again) carries the TypeInformation alone, as the first did: it
            // keeps the TypeObject a TypeLookup answer resolved for the hash
            // it announces again, and is judged on it. Overwriting the record
            // would forget the type: the writer would be judged again as of
            // unknown type and gated off from a reader forcing type validation
            // that had matched it. A re-announcement naming another hash is another
            // type and starts unresolved.
            registry.keep_learned_type_object(&mut endpoint, EndpointInfo::announced_complete_hash);
            // Every copy notified or deferred from here names the record it
            // was made from (`EndpointInfo::incarnation`).
            let (is_new, incarnation) = registry.insert_with_incarnation(endpoint.clone());
            endpoint.incarnation = incarnation;
            // Bump the registry generation while the write lock is still
            // held: readers of the generation either see the bump (and
            // then block on the read lock until this mutation is
            // published) or see the old generation and recompute on
            // their next call. Either way no cache can go permanently
            // stale (see `topic_registry_generation` field doc).
            self.topic_registry_generation
                .fetch_add(1, Ordering::Release);

            // Phase 1.4: Automatic endpoint matching
            // After insertion, check for compatible opposite endpoints
            log::debug!(
                "[SEDP] handle_sedp topic='{}' type='{}' kind={:?} is_local={} is_new={}",
                topic_name,
                type_name,
                endpoint_kind,
                is_local_endpoint,
                is_new
            );
            // The match itself is decided by the match registry, with the
            // one type verdict (`pairing_type_verdict`), not here. No count of
            // "compatible" endpoints is logged from
            // `TopicRegistry::find_compatible_*`: it would be a second type
            // decision on other inputs (no type store, the remote's
            // arrival-time type) that decides nothing and could say "0
            // compatible" and "Structural type incompatibility" for pairings
            // that matched.
            if endpoint_kind == EndpointKind::Reader
                && is_new
                && matches!(
                    endpoint_durability,
                    Durability::TransientLocal | Durability::Transient | Durability::Persistent
                )
            {
                // Destination resolution order:
                // 1. The reader's OWN SEDP-registered unicast locator
                //    (registered a few lines above, in this same
                //    `handle_sedp` call, when this is a Reader) --
                //    the most specific: some readers listen on a
                //    different port than their participant's SPDP
                //    default_unicast (e.g. an ephemeral port).
                // 2. The participant's SPDP default_unicast_locator,
                //    keyed by `GUID::new(prefix, RTPS_ENTITYID_
                //    PARTICIPANT)` -- NOT `endpoint_participant`
                //    itself, which `EndpointInfo::from_sedp` builds
                //    with a ZERO entity id (see that function's doc)
                //    while `EndpointRegistry` keys participant
                //    locators by the real `RTPS_ENTITYID_PARTICIPANT`
                //    GUID (registered via SPDP). Looking up the raw
                //    zero-entity GUID here could never hit, silently
                //    falling straight through to (3) every time --
                //    the same locality-vs-lookup-key mismatch the security
                //    handshake gate in `notify_endpoint_discovered`
                //    accounts for.
                // 3. The SEDP-announced unicast locator(s), via the
                //    same `select_best_locator` heuristic used
                //    elsewhere in this function (never index
                //    `.first()` directly: an unordered locator list
                //    can put an unreachable/Docker-internal address
                //    first).
                let real_participant_guid = GUID::new(
                    endpoint_participant.prefix,
                    crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                );
                let replay_dest = self
                    .endpoint_registry
                    .get_reader_locator(&endpoint.endpoint_guid)
                    .or_else(|| self.endpoint_registry.get(&real_participant_guid))
                    .or_else(|| select_best_locator(&endpoint_unicast_locators).copied());
                if let Some(dest) = replay_dest {
                    // `endpoint` here is the just-discovered READER
                    // (we are inside the EndpointKind::Reader match
                    // arm): its GUID lets the writer-side replay
                    // callback resolve the reader's wire profile
                    // (entity id, RTPS vendor id). Deferred (see
                    // `pending_replay`'s declaration): pushed
                    // here under the write lock, fired after it
                    // drops and after the match publishes below.
                    pending_replay.push((
                        topic_name.clone(),
                        type_name.clone(),
                        dest,
                        Some(endpoint.endpoint_guid.as_bytes()),
                    ));
                } else {
                    log::debug!(
                                "[SEDP Match] No unicast endpoint for participant {:?}, skipping history replay",
                                endpoint_participant
                            );
                }
            }

            is_new
        };
        // topic_registry write lock is released here.

        // The history replay collected above goes through the door
        // (`replay_admitted`), judged here, outside the registry lock, under
        // an epoch loaded first (`withhold_replay`).
        #[cfg(feature = "security")]
        let replay_judged_at = self.admission_epoch();
        let replay_admitted = pending_replay.is_empty() || self.replay_admitted(&endpoint);

        // The participant may have been removed while this announcement was
        // handled (a departure, an expiry, a purge on another thread): its
        // removal takes its endpoints out of the topic registry, and one
        // inserted after that stayed for good, orphaned, matched by every
        // local endpoint of its topic. Checked after the insert, never
        // before: a removal takes the participant out of `db` before it
        // forgets its endpoints, so either it forgets this one, or `db`
        // already says it is gone here. The endpoint then goes again, with
        // its locators, and anything that matched it meanwhile (a local
        // endpoint's catch-up) hears it leave.
        if !is_local_endpoint && !self.is_participant_known(endpoint_prefix) {
            let endpoint_guid = endpoint.endpoint_guid;
            let removed = self.forget_endpoints(|guid| *guid == endpoint_guid);
            self.endpoint_registry
                .remove_endpoint_locators(|guid| *guid == endpoint_guid);
            for gone in &removed {
                self.notify_endpoint_removed(gone);
            }
            log::debug!(
                "[SEDP] {:?} on topic '{}': its participant was removed while its \
                 announcement was handled, not kept",
                endpoint_guid,
                topic_name
            );
            return;
        }
        let endpoint = endpoint;

        // XTypes v1.3 sec. 7.6.3.4.3: a remote endpoint is judged against this
        // participant's endpoints of the opposite kind on its topic, with the
        // one type verdict and on the type each local endpoint registered in
        // the match registry (`MatchNotificationRegistry::judge_remote_types`):
        // a refused remote writer's samples are gated off synchronously here,
        // beating the on_inconsistent_topic-vs-data race, and the
        // notification below is queued. A local endpoint that registers later
        // is judged at its registration (`catch_up`), and a remote type a
        // TypeLookup reply resolves later is judged then
        // (`update_type_object_for_type`): the three events that can change a
        // verdict, each judged by the same function on the same inputs.
        if !is_local_endpoint {
            if let Some(reg) = self.match_registry.get() {
                if reg.judge_remote_types(&endpoint) {
                    log::debug!(
                        "[SEDP-INCOMPAT-TYPE] remote {:?} type='{}' refused on topic '{}'",
                        endpoint_kind,
                        type_name,
                        topic_name
                    );
                    // The notification judges the endpoint again, on its own
                    // name, TypeObject and policy (sec. 7.6.3.4: the reader's
                    // policy governs, the local one for a remote writer).
                    pending_type_incompat = Some(endpoint.clone());
                }
            }
        }

        // The one QoS verdict of each (this writer, local reader) pair,
        // recorded in the data-plane gate before the writer's samples are
        // delivered, on every announcement: the first, and each one after,
        // which may carry a new QoS (`judge_remote_writer_qos`).
        if !is_local_endpoint && endpoint_kind == EndpointKind::Writer {
            if let Some(reg) = self.match_registry.get() {
                reg.judge_remote_writer_qos(
                    &endpoint,
                    !is_new,
                    !is_new && self.participant_may_surface_matches(endpoint_prefix),
                );
            }
        }
        // The same for this reader and each local writer: a re-announced
        // reader may carry a new QoS (`judge_remote_reader_qos`).
        if !is_local_endpoint && endpoint_kind == EndpointKind::Reader {
            if let Some(reg) = self.match_registry.get() {
                reg.judge_remote_reader_qos(
                    &endpoint,
                    !is_new,
                    !is_new && self.participant_may_surface_matches(endpoint_prefix),
                );
            }
        }

        // Compute the match-surfacing gate once, for the path in `if is_new`
        // (`may_surface_matches`, the rule every surfacing path applies).
        // Computing it here (outside the write-lock block above) is safe:
        // `participant_may_surface_matches` and `is_participant_known` only
        // take read locks, and the probation flag is an atomic load.
        let probation_done = self.probation_purge_done.load(Ordering::Acquire);
        let optimistic_confirmed =
            is_local_endpoint || self.participant_may_surface_matches(endpoint_prefix);

        // Inconsistent-type notification: fire the match-registry callback
        // now that no topic_registry lock is held. Firing it inside the
        // write-lock block above would allow a user-supplied listener callback
        // to re-enter discovery or participant code and deadlock. Per-entry
        // type filtering inside notify_inconsistent_type_for_topic ensures
        // only entries whose local type is structurally incompatible with the
        // remote type are notified (DDS-XTypes v1.3 Sec.7.6.3.4.3).
        //
        // Fired at once, never held for a confirmation: with RELIABLE QoS the
        // writer retransmits via HEARTBEAT within ~10-25 ms of discovering
        // the reader, so data reaches the reader long before a second SPDP
        // (~200 ms) or our probation boundary (250 ms); a notification held
        // until then would reach the application after the very samples it
        // is about, so it is raised before them. A false
        // positive for a zombie participant (one SPDP drained from a socket
        // buffer) is harmless: it mirrors QoS-incompat, which fires
        // immediately in notify_endpoint_discovered_incompat_only with no
        // confirmation gate at all.
        //
        // What is checked is that the participant is still known. Its
        // announcement was admitted only because it was (the SEDP of a
        // participant not known yet is buffered in `pending_sedp` above and
        // handled once its SPDP arrives), so it is unknown here only when it
        // was removed meanwhile: a departure, an expiry, a purge on another
        // thread. Nothing is reported then; the endpoint went with its
        // participant. Deferring "until the participant is known" and
        // replaying for whatever announced under the prefix next would report
        // a successor inconsistent with a type it never announced, under the
        // GUID of an endpoint it never had. A purged
        // participant that was alive after all is rebuilt from its requeued
        // SEDP when it announces again (`requeue_purged_sedp`), and is
        // reported then.
        if let Some(remote) = pending_type_incompat {
            if self.is_participant_known(endpoint_prefix) {
                if let Some(mr) = self.match_registry.get() {
                    mr.notify_inconsistent_type_for_topic(&remote);
                }
            } else {
                log::debug!(
                    "[SEDP-INCOMPAT-TYPE] {:?} on topic '{}': its participant was removed while \
                     its announcement was handled, not reported",
                    remote.endpoint_guid,
                    remote.topic_name
                );
            }
        }

        if is_new {
            // Phase 1 -- IMMEDIATE QoS incompat fire (no gate).
            // QoS compatibility is a function of the local entry's QoS
            // and the remote endpoint's QoS as advertised in this SEDP
            // alone; it does not depend on the participant having been
            // confirmed via SPDP. Firing it here, before the
            // surfacing-gate, ensures the OMG harness (which often
            // checks `on_offered_incompatible_qos` /
            // `on_requested_incompatible_qos` within a 5 s window) sees
            // the mismatch immediately -- instead of waiting up to the
            // steady-state SPDP interval (~3 s) for participant
            // confirmation. The `dispatch_incompat` path in
            // `MatchNotificationRegistry` dedups against
            // `incompat_remotes` so the eventual gate-released
            // `notify_endpoint_discovered` call below cannot fire it a
            // second time for the same `(entry, endpoint)` pair.
            self.notify_endpoint_discovered_incompat_only(&endpoint);

            // Phase 2 -- MATCH surfacing, gated on participant confirmation.
            //
            // Surface the discovery to listeners ONLY when the owning
            // participant has been confirmed alive (`is_confirmed_alive`). Stale
            // SPDP/SEDP packets from previously-killed processes on the same
            // domain land in the new participant's discovery cache during
            // the first ~250 ms; if we surface them straight away, the
            // MatchNotifier sees them as legitimate remotes and runs the
            // full QoS compatibility check against zombie endpoints whose
            // owning participant will never reach `is_confirmed_alive()`.
            // That is the cause of "passes in isolation, fails after prior
            // tests" symptoms: a harness that restarts its process between
            // tests within milliseconds leaks zombies from test N into test
            // N+1's discovery view and fires false
            // `on_offered_incompatible_qos` events.
            //
            // The deferral path is `pending_notifications` +
            // `replay_pending_for_participant` (called on the SPDP
            // confirmation transition in handle_spdp).
            //
            // Local endpoints (no participant in `db`) bypass the gate:
            // they are co-owned by the running participant and are always
            // safe to surface.
            //
            // Stale SPDP/SEDP packets from previous-test processes arrive
            // within the first ~50 ms of this participant's lifetime; the
            // probation window (`probation_purge_done`, fired at 250 ms in
            // `handle_spdp`) is the cut-off after which any newly observed
            // participant must be live -- stale bursts cannot land that
            // late. So once probation is over, a participant first heard
            // after it surfaces immediately, regardless of `spdp_count`,
            // while one first heard during it surfaces once match eligible:
            // the one rule every surfacing path applies
            // (`may_surface_matches`). This
            // keeps `on_requested_incompatible_qos` /
            // `on_offered_incompatible_qos` firing promptly for tests where
            // the remote pubs/subs start *after* this participant's burst
            // phase (most interoperability harness scenarios) -- without that
            // fast path a subscriber that joined after the publisher's
            // aggressive SPDP window had ended would need to wait up to 3 s
            // (steady-state SPDP interval) for confirmation, missing the
            // harness's incompat-detection window.
            //
            // Race-safety on the in-probation path: the naive "check db,
            // then push to pending" sequence has a window where
            // handle_spdp confirms the participant AND drains the pending
            // list BETWEEN our db read and our pending push -- leaving the
            // endpoint stranded forever because `just_confirmed` only
            // fires once. We close the race with a double-check under the
            // pending write lock: optimistic notify if db says confirmed;
            // otherwise take the pending lock, re-read db (so any
            // concurrent SPDP transition has either run before us -- in
            // which case we notify directly -- or will run after us and
            // drain our push).
            // Trust raw wall-clock time only as a TRIGGER for
            // `maybe_complete_probation` (called at the top of
            // `handle_sedp`). The fast-path itself keys on
            // `probation_purge_done`, which is published only AFTER
            // purge + drain finish, so observing it `true` is a real
            // contract: db has no zombies, deferred entries have been
            // surfaced. Using raw elapsed time here would surface
            // endpoints while another thread is still mid-purge,
            // surfacing stale endpoints.
            //
            // `optimistic_confirmed` and `probation_done` were computed before
            // this `is_new` block (shared with the incompat-type gate above).
            //
            // A LOCAL endpoint surfaces at once, inside the probation too: the
            // gate guards against packets of dead processes, and our own
            // endpoint is not one. Held to `probation_done`, it would be
            // queued as "unconfirmed participant" (our own prefix, which `db`
            // never holds) and dropped as a zombie at the probation drain, so
            // a listener would never hear of an endpoint this participant
            // created in its first 250 ms.
            if is_local_endpoint || (optimistic_confirmed && probation_done) {
                self.notify_endpoint_discovered(&endpoint);
            } else {
                // Lock ordering note (no deadlock with `handle_spdp`):
                // `handle_spdp` takes its `db` write lock, releases it
                // (line ~451: `drop(db)`), and only then calls
                // `replay_pending_for_participant`, which acquires the
                // `pending_notifications` write lock without re-touching
                // `db`. Here we acquire `pending_notifications` first and
                // only re-acquire a *read* on `db` via
                // `is_participant_confirmed`. The two paths therefore
                // never hold both locks at the same time, so the
                // pending->db read here cannot cycle against a
                // db->pending writer.
                let mut pending = recover_write(
                    Arc::as_ref(&self.pending_notifications),
                    "DiscoveryFsm::handle_sedp pending_notifications",
                );
                // Re-check under the pending lock to close the
                // SPDP-confirms-between-our-checks race. If SPDP confirmed
                // the participant after our optimistic check (or the
                // probation window ended), its
                // `replay_pending_for_participant` is either pending on
                // this write lock (will drain after we release) or has
                // already run with an empty pending list (we must notify
                // directly because no future replay is scheduled).
                let probation_done_recheck = self.probation_purge_done.load(Ordering::Acquire);
                if probation_done_recheck && self.participant_may_surface_matches(endpoint_prefix) {
                    drop(pending);
                    self.notify_endpoint_discovered(&endpoint);
                } else if pending.len() < PENDING_NOTIFICATIONS_CAP {
                    log::debug!(
                        "[SEDP] Deferring notify_endpoint_discovered for unconfirmed participant (prefix={:02x?})",
                        &endpoint_prefix[..4]
                    );
                    pending.push(endpoint);
                } else {
                    // Cap is sized for adversarial scenarios where a
                    // hostile multicast source spams SEDP during the
                    // 250 ms probation window -- at the typical 1 KB/SEDP
                    // and a saturated 1 Gb link, 250 ms = ~30 k packets,
                    // so PENDING_NOTIFICATIONS_CAP=16384 covers normal
                    // bursty discovery while still bounding memory.
                    // Overflow surfaces the endpoint directly rather than
                    // dropping it: SEDP is reliable and not periodic, so
                    // a silent drop here would lose a legitimate remote
                    // endpoint permanently from this participant's view.
                    // The trade-off is that the gate becomes best-effort
                    // for the few endpoints past the cap, which is
                    // acceptable because reaching the cap requires
                    // unusual traffic; an attacker who can saturate
                    // discovery already has bigger leverage at the
                    // transport layer.
                    log::warn!(
                        "[SEDP] pending_notifications cap ({}) reached for unconfirmed participant prefix={:02x?} -- surfacing endpoint directly, gate degraded to best-effort for this entry",
                        PENDING_NOTIFICATIONS_CAP,
                        &endpoint_prefix[..4]
                    );
                    self.metrics
                        .sedp_pending_cap_surfaced
                        .fetch_add(1, Ordering::Relaxed);
                    drop(pending);
                    self.notify_endpoint_discovered(&endpoint);
                }
            }
        }

        // Fire the history replay(s) collected above: the
        // topic_registry write lock is long since released, and the match
        // has already been published to callbacks in the `if is_new` block
        // just above (immediately via `notify_endpoint_discovered[_incompat_only]`,
        // or deferred into `pending_notifications` for later replay at
        // confirmation -- either way, this SEDP call's own match-publish
        // work is done). `replay_for`'s synchronous UDP sends -- one per
        // cached change in the writer's ENTIRE history -- therefore no
        // longer block any other discovery operation for their duration.
        //
        // Through the door (`replay_admitted`): the replay is the writer's
        // whole history, and a reader the security plugins do not admit gets
        // none of it. It must not go to every late joiner: a
        // TRANSIENT_LOCAL reader of an unauthenticated participant received
        // the history of a read-protected topic.
        for (topic, type_name, dest, reader_guid) in pending_replay {
            if !replay_admitted {
                #[cfg(feature = "security")]
                self.withhold_replay(
                    GUID::from_bytes(reader_guid.unwrap_or_default()),
                    WithheldReplay {
                        topic,
                        type_name,
                        dest,
                    },
                    replay_judged_at,
                );
                continue;
            }
            self.replay_registry
                .replay_for(&topic, &type_name, dest, reader_guid);
        }
    }

    /// Look up whether a participant (identified by its 12-byte GUID prefix)
    /// has been confirmed alive (`ParticipantInfo::is_confirmed_alive`: two
    /// counted SPDPs or two liveness marks). Returns false if the
    /// participant is absent from `db`, which is the safe default for the
    /// SEDP deferral path -- the endpoint is held back until SPDP either
    /// registers + confirms the participant or the probation purge evicts it.
    /// Returns true once the startup probation window (250 ms) has expired and
    /// the one-shot purge + drain have completed. After this point, any new
    /// SPDP/SEDP arrivals are from live participants only.
    pub(crate) fn is_probation_done(&self) -> bool {
        self.probation_purge_done.load(Ordering::Acquire)
    }

    /// Time since this FSM was created, the origin of its probation window.
    /// Lets a test place a peer's emissions relative to the boundary rather
    /// than to the end of a participant build of unknown duration.
    #[cfg(test)]
    pub(crate) fn uptime(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Complete startup admission for a known test peer without waiting for
    /// wall-clock SPDP intervals. Endpoint notifications still use the real
    /// probation drain and match dispatch.
    #[cfg(test)]
    pub(crate) fn confirm_participant_for_test(&self, participant: GUID) {
        recover_write(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::confirm_participant_for_test",
        )
        .get_mut(&participant)
        .expect("known test participant")
        .spdp_count = 3;
        self.drain_pending_post_probation();
    }

    /// Whether the participant is confirmed alive. Tests only: no decision
    /// of the engine reads it any more.
    #[cfg(test)]
    pub(crate) fn is_participant_confirmed(&self, participant_prefix: &[u8]) -> bool {
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::is_participant_confirmed",
        );
        db.iter()
            .find(|(guid, _)| &guid.as_bytes()[..12] == participant_prefix)
            .map(|(_, info)| info.is_confirmed_alive())
            .unwrap_or(false)
    }

    /// Check whether a participant may surface its matches
    /// (`may_surface_matches`, the rule every surfacing path applies) and is
    /// recently alive, applying a freshness gate to suppress stale zombie
    /// entries during catch-up scans: the catch-up reads cached state, where
    /// the live path reacts to a fresh emission.
    ///
    /// Uses a two-tier threshold based on whether the participant is still in
    /// its aggressive SPDP burst phase (first 5 s of life):
    ///
    /// - **HDDS aggressive phase** (`created_at.elapsed() < 5 s`): threshold =
    ///   the lesser of 400 ms and the advertised lease. A live HDDS participant
    ///   in burst mode refreshes `last_seen` every 200 ms.
    ///
    /// - **Normal phase**, and every non-HDDS participant: threshold = the
    ///   participant's advertised lease. This is shared with the confirmed-
    ///   participant purge predicate. An infinite lease expires only through
    ///   an explicit dispose or administrative removal.
    ///
    /// Returns false if the participant is absent or may not surface yet.
    pub(crate) fn is_participant_matchable_and_recent(&self, participant_prefix: &[u8]) -> bool {
        // Aggressive-phase burst interval (ms) -- matches spdp_announcer.rs.
        const AGGRESSIVE_INTERVAL_MS: u64 = 200;
        // Duration of the aggressive burst phase (ms) -- matches spdp_announcer.rs.
        const AGGRESSIVE_WINDOW_MS: u64 = 5_000;
        // Freshness threshold in aggressive phase: 2x burst interval.
        const FRESH_AGGRESSIVE_MS: u64 = AGGRESSIVE_INTERVAL_MS * 2; // 400 ms
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::is_participant_matchable_and_recent",
        );
        db.iter()
            .find(|(guid, _)| &guid.as_bytes()[..12] == participant_prefix)
            .map(|(_, info)| {
                if !self.may_surface_matches(info) {
                    return false;
                }
                let elapsed_ms = info.last_seen.elapsed().as_millis() as u64;
                let created_elapsed_ms = info.created_at.elapsed().as_millis() as u64;
                let is_hdds =
                    info.vendor_id == Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
                if is_hdds && created_elapsed_ms < AGGRESSIVE_WINDOW_MS {
                    elapsed_ms < FRESH_AGGRESSIVE_MS
                        && !participant_lease_expired(elapsed_ms, info.lease_duration_ms)
                } else {
                    !participant_lease_expired(elapsed_ms, info.lease_duration_ms)
                }
            })
            .unwrap_or(false)
    }

    /// The registration catch-up's side of the deferral. A local entry
    /// registered after the boundary pairs with a remote endpoint whose
    /// participant may not surface its matches yet; nothing else would ever
    /// surface that pairing (the replay drains `pending_notifications` only,
    /// and the peer does not re-send a SEDP it already sent), so the endpoint
    /// joins `pending_notifications`, where the replay that surfaces the
    /// participant's deferred matches (its eligibility mark, its SPDP)
    /// surfaces it with them; `matched_remotes` dedups a pairing surfaced
    /// twice.
    ///
    /// Re-checked under the pending lock, as the SEDP path does: returns
    /// false when the participant became matchable in between (its replay
    /// may already have run), and when the list is full; the caller then
    /// surfaces the match itself. True when the endpoint is deferred.
    pub(crate) fn defer_catch_up_match(&self, endpoint: &EndpointInfo) -> bool {
        let mut pending = recover_write(
            Arc::as_ref(&self.pending_notifications),
            "DiscoveryFsm::defer_catch_up_match",
        );
        if self.is_participant_matchable_and_recent(&endpoint.endpoint_guid.prefix) {
            return false;
        }
        if pending
            .iter()
            .any(|ep| ep.endpoint_guid == endpoint.endpoint_guid)
        {
            return true;
        }
        if pending.len() >= PENDING_NOTIFICATIONS_CAP {
            return false;
        }
        pending.push(endpoint.clone());
        true
    }

    /// Check whether a participant (identified by its 12-byte GUID prefix)
    /// is present in the discovery database regardless of confirmation state.
    ///
    /// Used by the inconsistent-type gates to distinguish a participant with
    /// at least one SPDP observed from a zombie endpoint whose participant was
    /// purged and whose late-arriving SEDP has no `db` entry. The match gate
    /// is `participant_may_surface_matches`, which also holds back a
    /// participant first heard during our probation until it is match
    /// eligible.
    pub(crate) fn is_participant_known(&self, participant_prefix: &[u8]) -> bool {
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::is_participant_known");
        db.iter()
            .any(|(guid, _)| &guid.as_bytes()[..12] == participant_prefix)
    }

    /// The incarnation of the record discovery holds for `endpoint_guid` on
    /// `topic_name` (`EndpointInfo::incarnation`), `None` when it holds none.
    pub(crate) fn endpoint_incarnation(
        &self,
        topic_name: &str,
        endpoint_guid: &GUID,
    ) -> Option<u64> {
        recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::endpoint_incarnation",
        )
        .endpoint(topic_name, endpoint_guid)
        .map(|record| record.incarnation)
    }

    /// Whether discovery still knows the remote endpoint `endpoint` (it is in
    /// the topic registry): false once its participant or the endpoint
    /// itself has been removed.
    pub(crate) fn knows_remote_endpoint(&self, endpoint: &EndpointInfo) -> bool {
        recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::knows_remote_endpoint",
        )
        .contains(&endpoint.topic_name, &endpoint.endpoint_guid)
    }

    /// Install `sedp_admitted_hook`.
    #[cfg(test)]
    pub(crate) fn set_sedp_admitted_hook(&self, hook: Box<dyn FnOnce() + Send + Sync>) {
        *self
            .sedp_admitted_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(hook);
    }

    /// Install `replay_parked_hook`.
    #[cfg(test)]
    pub(crate) fn set_replay_parked_hook(&self, hook: Box<dyn Fn() + Send + Sync>) {
        *self
            .replay_parked_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(hook);
    }

    /// Register a remote endpoint in the topic registry directly, as
    /// `handle_sedp` would, for tests that drive the match registry alone.
    #[cfg(test)]
    pub(crate) fn insert_remote_endpoint_for_test(&self, endpoint: EndpointInfo) {
        recover_write(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::insert_remote_endpoint_for_test",
        )
        .insert(endpoint);
    }

    /// Find all writers for a topic.
    #[must_use]
    pub fn find_writers_for_topic(&self, topic_name: &str) -> Vec<EndpointInfo> {
        crate::trace_fn!("DiscoveryFsm::find_writers_for_topic");
        let registry = recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::find_writers_for_topic registry.read()",
        );
        registry.find_writers(topic_name)
    }

    /// The writers of the remote Publisher `group` of participant `prefix`
    /// that discovery knows (`TopicRegistry::publisher_roster`).
    #[must_use]
    pub fn publisher_roster(&self, prefix: &[u8; 12], group: [u8; 4]) -> Vec<[u8; 4]> {
        recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::publisher_roster registry.read()",
        )
        .publisher_roster(prefix, group)
    }

    /// The `GroupDigest_t` of the writers of the remote Publisher `group`
    /// discovery knows (RTPS v2.5 Sec.8.7.5: what a `writerSet` received
    /// from that Publisher must match before the reader may tell a GSN it
    /// never received from one that does not exist).
    #[must_use]
    pub fn publisher_digest(&self, prefix: &[u8; 12], group: [u8; 4]) -> [u8; 4] {
        crate::protocol::group::group_digest(self.publisher_roster(prefix, group))
    }

    /// Find all readers for a topic that a writer of it may send to.
    ///
    /// This is the list the writers walk to send data, heartbeats and
    /// repairs: it does not go through the match. A reader the security
    /// plugins do not admit (`admits_remote_reader`: its participant not
    /// authenticated where the governance requires it, its handshake not
    /// complete, its permissions not granting the topic in its partitions)
    /// is left out of it, so that no path sends it anything. The match
    /// itself, and the ACKNACK door, read the registry
    /// (`registered_readers_for_topic`) and judge each reader.
    #[must_use]
    pub fn find_readers_for_topic(&self, topic_name: &str) -> Vec<EndpointInfo> {
        crate::trace_fn!("DiscoveryFsm::find_readers_for_topic");
        // The verdicts on this snapshot are filed under an epoch loaded
        // before it is taken (`admission_epoch`).
        #[cfg(feature = "security")]
        let gate = self.admission_gate_active().then(|| self.admission_epoch());
        #[allow(unused_mut)]
        let mut readers = self.registered_readers_for_topic(topic_name);
        // Outside the registry lock: the check reads the handshake map.
        #[cfg(feature = "security")]
        if let Some(epoch) = gate {
            #[cfg(test)]
            self.run_endpoint_read_hook();
            readers.retain(|reader| self.admits_remote_reader(reader, epoch));
        }
        readers
    }

    /// The routing view of [`Self::find_readers_for_topic`] a writer reads
    /// for every packet it sends: the same readers, in the same order, each
    /// reduced to its two GUIDs and whether it is compatible with
    /// `partition_of` (a writer QoS with a non-default PARTITION; `None`
    /// counts every reader compatible). Without an admission gate the
    /// readers are read in place, under the registry lock, rather than
    /// cloned whole per packet; with one, the admitted list is the one
    /// `find_readers_for_topic` returns.
    #[must_use]
    pub(crate) fn reader_routes_for_topic(
        &self,
        topic_name: &str,
        partition_of: Option<&crate::dds::qos::QoS>,
    ) -> Vec<ReaderRoute> {
        let route = |reader: &EndpointInfo| ReaderRoute {
            endpoint_guid: reader.endpoint_guid,
            participant_guid: reader.participant_guid,
            compatible: partition_of.is_none_or(|writer_qos| {
                crate::core::discovery::Matcher::is_compatible(&reader.qos, writer_qos)
            }),
        };
        #[cfg(feature = "security")]
        if self.admission_gate_active() {
            return self
                .find_readers_for_topic(topic_name)
                .iter()
                .map(route)
                .collect();
        }
        recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::reader_routes_for_topic registry.read()",
        )
        .readers(topic_name)
        .map(route)
        .collect()
    }

    /// Every reader of `topic_name` discovery holds, admitted or not.
    #[must_use]
    pub(crate) fn registered_readers_for_topic(&self, topic_name: &str) -> Vec<EndpointInfo> {
        recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::find_readers_for_topic registry.read()",
        )
        .find_readers(topic_name)
    }

    /// Get snapshot of all participants.
    ///
    /// Returns cloned `Vec` for iteration without holding locks.
    #[must_use]
    pub fn get_participants(&self) -> Vec<ParticipantInfo> {
        crate::trace_fn!("DiscoveryFsm::get_participants");
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::get_participants");
        db.values().cloned().collect()
    }

    /// Check if a participant is known in the SPDP database.
    #[must_use]
    pub fn has_participant(&self, guid: &GUID) -> bool {
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::has_participant");
        db.contains_key(guid)
    }

    /// Whether a participant of GUID prefix `prefix` is in the SPDP
    /// database, whatever entity id its announcement carried.
    #[cfg(feature = "security")]
    #[must_use]
    pub(crate) fn knows_participant_prefix(&self, prefix: &[u8; 12]) -> bool {
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::knows_participant_prefix",
        );
        db.contains_key(&GUID::new(
            *prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        )) || db.keys().any(|guid| guid.prefix == *prefix)
    }

    /// Check if the participant owning this endpoint is confirmed alive.
    ///
    /// Looks up the participant by matching the first 12 bytes (GUID prefix)
    /// of the endpoint GUID against participant GUIDs in the database.
    /// Returns `false` if the participant is not found or not yet confirmed
    /// (`ParticipantInfo::is_confirmed_alive`), indicating it may be a stale
    /// entry from a killed process.
    #[must_use]
    pub fn is_endpoint_participant_confirmed(&self, endpoint_guid: &GUID) -> bool {
        let prefix = &endpoint_guid.as_bytes()[..12];
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::is_endpoint_participant_confirmed",
        );
        db.values()
            .any(|p| &p.guid.as_bytes()[..12] == prefix && p.is_confirmed_alive())
    }

    /// Look up the RTPS vendor id (PID_VENDORID 0x0016) of a discovered
    /// participant.
    ///
    /// Only the 12-byte GUID prefix of `participant_guid` is used, so the
    /// answer does not depend on the entity id the caller's GUID carries.
    /// Returns `None` if the participant is unknown or did not advertise a
    /// vendor id.
    ///
    /// One lock-free O(1) read of `vendor_by_prefix`, which every change to
    /// the participant database keeps in step (`sync_vendor_of`). The send
    /// paths call this per packet and per reader.
    #[must_use]
    pub fn vendor_id_for_participant(&self, participant_guid: &GUID) -> Option<u16> {
        self.vendor_by_prefix
            .load()
            .get(&participant_guid.prefix)
            .copied()
    }

    /// Bring `vendor_by_prefix` in line with `db` for the participant(s) of
    /// `prefix`. Called under the database write lock by every change to the
    /// entries under `prefix` (SPDP insert, SPDP refresh, removal), so a
    /// removed participant's vendor never outlives it.
    ///
    /// The rule is the one the lookup always applied: the entry filed under
    /// the participant entity id, else the first entry with the prefix (more
    /// than one only for a malformed announcement).
    fn sync_vendor_of(&self, db: &ParticipantDB, prefix: [u8; 12]) {
        let key = GUID::new(
            prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let vendor = db
            .get(&key)
            .or_else(|| db.values().find(|p| p.guid.prefix == prefix))
            .and_then(|p| p.vendor_id);
        if self.vendor_by_prefix.load().get(&prefix).copied() == vendor {
            return;
        }
        self.vendor_by_prefix.rcu(|map| {
            let mut map = std::collections::HashMap::clone(map);
            match vendor {
                Some(vendor) => {
                    map.insert(prefix, vendor);
                }
                None => {
                    map.remove(&prefix);
                }
            }
            map
        });
    }

    /// Look up the `PID_HDDS_CAPABILITIES` a discovered participant
    /// announced, by its GUID prefix. `None` for an unknown participant or
    /// one that did not announce any (every HDDS release before the bit it
    /// is being consulted for existed, or a non-HDDS vendor).
    ///
    /// Same lookup shape as [`Self::vendor_id_for_participant`]: called once
    /// per SEDP writer discovery (`sedp_handler::record_writer_vendor`), not
    /// on any per-sample path.
    #[must_use]
    pub fn hdds_capabilities_for_participant(&self, prefix: &[u8; 12]) -> Option<u32> {
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::hdds_capabilities_for_participant",
        );
        db.values()
            .find(|p| &p.guid.as_bytes()[..12] == prefix)
            .and_then(|p| p.hdds_capabilities)
    }

    /// The HDDS capabilities this participant announces and speaks
    /// (`PID_HDDS_CAPABILITIES`).
    #[must_use]
    pub fn local_capabilities(&self) -> u32 {
        self.local_capabilities
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Tests only: announce and speak `caps` instead of this build's (set
    /// before the participant's threads start).
    #[cfg(test)]
    pub(crate) fn set_local_capabilities(&self, caps: u32) {
        self.local_capabilities
            .store(caps, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether this participant speaks the spec GROUP dialect with the
    /// participant of `prefix` (`group_dialect_of` == Spec): one lock-free
    /// load and a set lookup, for the send paths' per-reader choice (D18).
    #[inline]
    #[must_use]
    pub fn speaks_spec_group(&self, prefix: &[u8; 12]) -> bool {
        let peers = self.spec_group_peers.load();
        !peers.is_empty() && peers.contains(prefix)
    }

    /// Whether the participant of `prefix` reads per-writer sets only and
    /// takes plain DATA from a GROUP Publisher (`GroupDialect::SpecReceive`):
    /// one lock-free load and a set lookup, for the send paths' per-reader
    /// choice (plain form, no end-of-set marker, GAP for the close SN).
    #[inline]
    #[must_use]
    pub fn speaks_plain_group(&self, prefix: &[u8; 12]) -> bool {
        let peers = self.plain_group_peers.load();
        !peers.is_empty() && peers.contains(prefix)
    }

    /// Whether any participant this one knows takes plain DATA from a GROUP
    /// Publisher. A GROUP change is then kept off the multicast fallback,
    /// whose audience is not known (see `speaks_plain_group`).
    #[must_use]
    pub fn any_plain_group_peer(&self) -> bool {
        !self.plain_group_peers.load().is_empty()
    }

    /// Cached vendor-zone sequence-space requirement for this participant.
    pub(crate) fn needs_classic_sequence_window(&self, prefix: &[u8; 12]) -> bool {
        let peers = self.classic_window_peers.load();
        !peers.is_empty() && peers.contains(prefix)
    }

    /// Only positively identified classic vendors require translated SNs.
    /// Unknown vendors use native sequence identity and normal reliability.
    pub(crate) fn requires_group_window(&self, prefix: &[u8; 12]) -> bool {
        self.needs_classic_sequence_window(prefix)
    }

    /// Whether this participant speaks the spec GROUP dialect with any
    /// participant it knows.
    #[must_use]
    pub fn any_spec_group_peer(&self) -> bool {
        !self.spec_group_peers.load().is_empty()
    }

    /// Record the dialect of the participant of `prefix` for
    /// `speaks_spec_group`, from what its SPDP announced. Returns whether it
    /// changed.
    fn note_group_dialect(
        &self,
        prefix: [u8; 12],
        vendor_id: Option<u16>,
        caps: Option<u32>,
    ) -> bool {
        let classic = crate::protocol::group::GroupDialect::needs_sequence_window(vendor_id);
        let classic_changed = self.needs_classic_sequence_window(&prefix) != classic;
        if classic_changed {
            self.classic_window_peers.rcu(|peers| {
                let mut peers = std::collections::HashSet::clone(peers);
                if classic {
                    peers.insert(prefix);
                } else {
                    peers.remove(&prefix);
                }
                peers
            });
        }
        let dialect = crate::protocol::group::GroupDialect::of(
            vendor_id,
            caps.map(|theirs| theirs & self.local_capabilities()),
        );
        let spec = dialect == crate::protocol::group::GroupDialect::Spec;
        // Plain DATA from a GROUP Publisher: a peer that reads per-writer sets
        // only (`SpecReceive`, vendor 0x0114). Decided here, once per SPDP,
        // like `spec`; the send paths read it per reader (`speaks_plain_group`).
        let plain = dialect == crate::protocol::group::GroupDialect::SpecReceive;
        let plain_changed = plain != self.speaks_plain_group(&prefix);
        if plain_changed {
            self.plain_group_peers.rcu(|peers| {
                let mut peers = std::collections::HashSet::clone(peers);
                if plain {
                    peers.insert(prefix);
                } else {
                    peers.remove(&prefix);
                }
                peers
            });
        }
        if spec == self.speaks_spec_group(&prefix) {
            return classic_changed || plain_changed;
        }
        self.spec_group_peers.rcu(|peers| {
            let mut peers = std::collections::HashSet::clone(peers);
            if spec {
                peers.insert(prefix);
            } else {
                peers.remove(&prefix);
            }
            peers
        });
        true
    }

    /// Tell the listeners the GROUP dialect spoken with the participant of
    /// `prefix` changed (`on_participant_dialect_changed`), with its writers
    /// discovery knows.
    fn notify_dialect_changed(&self, prefix: &[u8; 12]) {
        let endpoints = recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::notify_dialect_changed",
        )
        .find_endpoints_by_prefix(prefix);
        if let Some(registry) = self.match_registry.get() {
            for endpoint in &endpoints {
                if registry.refresh_reader_dialect(endpoint)
                    && endpoint.qos.durability != Durability::Volatile
                    && self.replay_admitted(endpoint)
                {
                    let participant = GUID::new(
                        endpoint.endpoint_guid.prefix,
                        crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                    );
                    if let Some(dest) = self
                        .endpoint_registry
                        .get_reader_locator(&endpoint.endpoint_guid)
                        .or_else(|| self.endpoint_registry.get(&participant))
                    {
                        // Classification can make a previously unencodable
                        // durable close available. BEST_EFFORT has no repair.
                        self.replay_registry.replay_for(
                            &endpoint.topic_name,
                            &endpoint.type_name,
                            dest,
                            Some(endpoint.endpoint_guid.as_bytes()),
                        );
                    }
                }
            }
        }
        self.notify_writers_of(prefix, &endpoints);
    }

    /// Tell the listeners the GROUP dialect and the legacy key-hash decision
    /// of the participant of `prefix` (`on_participant_dialect_changed`,
    /// `on_participant_key_hash_decided`), with the writers discovery knows
    /// of it now: each is decided again from them, for every dialect, the
    /// same way its announcement decided it (`sedp_handler`).
    fn notify_writers_dialect(&self, prefix: &[u8; 12]) {
        let endpoints = recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::notify_writers_dialect",
        )
        .find_endpoints_by_prefix(prefix);
        self.notify_writers_of(prefix, &endpoints);
    }

    /// `notify_writers_dialect`, for the endpoints already read.
    fn notify_writers_of(&self, prefix: &[u8; 12], endpoints: &[EndpointInfo]) {
        let dialect = self.group_dialect_of(prefix);
        let legacy_key_hash = self.legacy_key_hash_known(prefix);
        let writers: Vec<([u8; 16], Option<[u8; 4]>)> = endpoints
            .iter()
            .filter(|endpoint| endpoint.kind == EndpointKind::Writer)
            .map(|endpoint| (endpoint.endpoint_guid.as_bytes(), endpoint.group_entity_id))
            .collect();
        let guids: Vec<[u8; 16]> = writers.iter().map(|(guid, _)| *guid).collect();
        let listeners = recover_read(
            Arc::as_ref(&self.listeners),
            "DiscoveryFsm::notify_dialect_changed listeners",
        )
        .clone();
        for listener in &listeners {
            listener.on_participant_dialect_changed(dialect, &writers);
            if let Some(legacy) = legacy_key_hash {
                listener.on_participant_key_hash_decided(legacy, &guids);
            }
        }
    }

    /// The legacy key-hash decision for a participant announcing `vendor_id`
    /// and `caps`: HDDS without `CAP_CONFORMANT_KEY_HASH` (a 1.4.x peer, or a
    /// pre-bit 1.5.0 snapshot), whose writers' PID_KEY_HASH is the pre-1.5.0
    /// FNV form (`TopicRegistry::writer_uses_legacy_key_hash`).
    fn legacy_key_hash_decision(vendor_id: Option<u16>, caps: Option<u32>) -> bool {
        vendor_id == Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16)
            && caps.is_none_or(|caps| caps & crate::protocol::group::CAP_CONFORMANT_KEY_HASH == 0)
    }

    /// Whether the participant of `prefix` takes the legacy key-hash decision
    /// (`legacy_key_hash_decision`), from what its SPDP announced; `None` for
    /// a participant discovery does not know.
    pub(crate) fn legacy_key_hash_known(&self, prefix: &[u8; 12]) -> Option<bool> {
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::legacy_key_hash_known");
        let key = GUID::new(
            *prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        db.get(&key)
            .or_else(|| db.values().find(|p| p.guid.prefix == *prefix))
            .map(|p| Self::legacy_key_hash_decision(p.vendor_id, p.hdds_capabilities))
    }

    /// The participant of `prefix` left: no dialect for it any more.
    fn forget_group_dialect(&self, prefix: &[u8; 12]) {
        self.classic_window_peers.rcu(|peers| {
            let mut peers = std::collections::HashSet::clone(peers);
            peers.remove(prefix);
            peers
        });
        if self.speaks_spec_group(prefix) {
            self.spec_group_peers.rcu(|peers| {
                let mut peers = std::collections::HashSet::clone(peers);
                peers.remove(prefix);
                peers
            });
        }
        if self.speaks_plain_group(prefix) {
            self.plain_group_peers.rcu(|peers| {
                let mut peers = std::collections::HashSet::clone(peers);
                peers.remove(prefix);
                peers
            });
        }
    }

    /// The GROUP-scope dialect spoken with the participant of `prefix`,
    /// decided from what its SPDP announced (`GroupDialect::of`), the spec
    /// dialect only when this participant speaks it too; `Classic` for one
    /// not discovered.
    #[must_use]
    pub fn group_dialect_of(&self, prefix: &[u8; 12]) -> crate::protocol::group::GroupDialect {
        self.group_dialect_known(prefix)
            .unwrap_or(crate::protocol::group::GroupDialect::Classic)
    }

    /// [`group_dialect_of`](Self::group_dialect_of), `None` for a
    /// participant discovery does not know (not yet, or no longer).
    pub fn group_dialect_known(
        &self,
        prefix: &[u8; 12],
    ) -> Option<crate::protocol::group::GroupDialect> {
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::group_dialect_of");
        // Keyed by the participant GUID: one lookup, a scan only for a
        // participant recorded under another entity id.
        let key = GUID::new(
            *prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        db.get(&key)
            .or_else(|| db.values().find(|p| p.guid.prefix == *prefix))
            .map(|p| {
                crate::protocol::group::GroupDialect::of(
                    p.vendor_id,
                    p.hdds_capabilities
                        .map(|theirs| theirs & self.local_capabilities()),
                )
            })
    }

    /// Whether SEDP announcements to the participant of `prefix` carry
    /// PID_TYPE_OBJECT (`ParticipantInfo::type_object_pid`), from what its
    /// SPDP announced and discovery kept (a later SPDP without a vendor id or
    /// capabilities does not erase them); `None` for a participant discovery
    /// does not know, which is sent no announcement. The one reader of the
    /// decision for every SEDP send path.
    #[must_use]
    pub fn type_object_pid_for(
        &self,
        prefix: &[u8; 12],
    ) -> Option<crate::core::discovery::multicast::TypeObjectPid> {
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::type_object_pid_for");
        let key = GUID::new(
            *prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        db.get(&key)
            .or_else(|| db.values().find(|p| p.guid.prefix == *prefix))
            .map(ParticipantInfo::type_object_pid)
    }

    /// Get count of discovered participants.
    ///
    /// More efficient than `get_participants().len()` as it doesn't clone.
    #[must_use]
    pub fn participant_count(&self) -> usize {
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::participant_count");
        db.len()
    }

    /// Get snapshot of all discovered topics with aggregated endpoint information.
    ///
    /// Returns a map of topic names to (writers, readers) endpoint lists.
    /// Used for live topic discovery without compile-time type knowledge.
    ///
    /// # Returns
    /// HashMap mapping topic_name -> `(Vec<EndpointInfo> writers, Vec<EndpointInfo> readers)`
    #[must_use]
    pub fn get_all_topics(
        &self,
    ) -> std::collections::HashMap<String, (Vec<EndpointInfo>, Vec<EndpointInfo>)> {
        crate::trace_fn!("DiscoveryFsm::get_all_topics");
        use std::collections::HashMap;

        let registry = recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::get_all_topics",
        );

        let mut result = HashMap::new();

        // Get all topic names and query each topic for its endpoints
        for topic_name in registry.get_all_topic_names() {
            let writers = registry.find_writers(&topic_name);
            let readers = registry.find_readers(&topic_name);
            result.insert(topic_name, (writers, readers));
        }

        result
    }

    /// The one rule for surfacing a participant's matches once our probation
    /// boundary is past, applied by every path that surfaces them: the live
    /// SEDP path, the boundary's drain, the SPDP replay, the replay a late
    /// liveness mark triggers and the registration catch-up.
    ///
    /// A participant first heard after the boundary is trusted from its first
    /// announcement: the packets of a process that died before we started are
    /// all drained in our first milliseconds, and cannot land that late. One
    /// first heard during the probation is trusted from the first liveness
    /// mark it earns after the boundary instant, on the same premise and with
    /// more evidence (a mark is an emission at a distinct instant, at least
    /// 100 ms after we first heard it), or once it is match eligible
    /// (`ParticipantInfo::is_match_eligible`: two liveness marks or three
    /// counted SPDPs), the zombie guard for what it said before the boundary.
    /// A peer whose second SPDP lands after the boundary is therefore matched
    /// on that SPDP instead of waiting
    /// for a third emission it may never send (a short-lived peer, or one
    /// whose next announcement is 30 s away).
    fn may_surface_matches(&self, participant: &ParticipantInfo) -> bool {
        !self.heard_in_probation(participant)
            || participant.is_match_eligible()
            || participant
                .last_mark
                .is_some_and(|mark| mark >= self.probation_boundary_instant())
    }

    /// The instant of our probation boundary (FSM creation + span).
    fn probation_boundary_instant(&self) -> Instant {
        self.created_at + std::time::Duration::from_millis(PROBATION_SPAN_MS)
    }

    /// `may_surface_matches` for the participant owning `participant_prefix`;
    /// false when it is unknown.
    pub(crate) fn participant_may_surface_matches(&self, participant_prefix: &[u8]) -> bool {
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::participant_may_surface_matches",
        );
        db.values()
            .find(|p| &p.guid.as_bytes()[..12] == participant_prefix)
            .is_some_and(|p| self.may_surface_matches(p))
    }

    /// Whether `participant` was first heard during our probation (its entry
    /// created before the boundary instant): the only participants the
    /// probation heuristics may ever purge. One heard later is trusted from
    /// its first announcement, since the packets of a process that died
    /// before we started are all drained in our first milliseconds.
    fn heard_in_probation(&self, participant: &ParticipantInfo) -> bool {
        participant
            .created_at
            .saturating_duration_since(self.created_at)
            .as_millis()
            < u128::from(PROBATION_SPAN_MS)
    }

    /// The probation verdict: whether the purge removes `participant` now.
    ///
    /// It must have been first heard during our probation, and is judged
    /// once it is `PROBATION_SPAN_MS` old, the span a participant heard at
    /// our start gets before the boundary: a younger one cannot have earned
    /// a mark yet (none counts in an entry's first 100 ms), and a peer first
    /// heard at our uptime 200 ms whose SEDP comes 150 ms later must not be
    /// judged at the boundary, 50 ms after we heard it. It is purged when it
    /// was never heard from after its entry's first 100 ms
    /// (`ParticipantInfo::survives_probation`). The same rule selects the
    /// victims and re-checks each one under the removal's write lock.
    ///
    /// A participant the verdict keeps on one mark, earned before the
    /// boundary, may not surface its matches yet (`may_surface_matches`):
    /// they stay deferred, yet discovery gave its readers a
    /// ReaderProxy in every local reliable writer, which holds the writer's
    /// history back until they acknowledge. If it dies without a dispose,
    /// nothing else would remove it before its lease (30 s for HDDS, longer
    /// for some peers), and a KEEP_ALL writer would time out on every write
    /// meanwhile. So such a participant is also purged once it has been
    /// silent (no SPDP, SEDP or control message under its prefix) for
    /// `PROBATION_SILENCE_MS`. A live one cannot stay in that state: its
    /// next emission at a distinct instant is a mark after the boundary,
    /// and the
    /// quiet peer this probation was reworked for keeps sending HEARTBEATs
    /// (e.g. every 200 ms). If it was alive after all, its retained SEDP
    /// is requeued and its next SPDP rebuilds it.
    ///
    /// RTPS 2.5 8.5.3.2 and 8.5.3.3 keep a participant alive for its whole
    /// leaseDuration; this purge, like the verdict itself, is an HDDS
    /// deviation kept for the packets of a process that died around our
    /// start, and is confined to participants first heard during our
    /// probation whose matches never surfaced. A participant whose matches
    /// may surface lives by its lease.
    ///
    /// So does a participant that completed authentication with us: it signed
    /// our fresh challenge, so it is alive whatever its announcements look
    /// like from here, and removing it drops its session; its next
    /// announcement begins another, which spends the one re-authentication
    /// of the interval (`HandshakeMachine` `handle_auth_request`). A
    /// participant restarted just before had re-authenticated with that one,
    /// so the next waited it out unauthenticated. Asked under the database
    /// lock, in the order every removal takes (`remove_participant_inner`
    /// drops the session under it).
    fn fails_probation(&self, participant: &ParticipantInfo) -> bool {
        if self.may_surface_matches(participant)
            || self.is_authenticated_participant(&participant.guid.prefix)
        {
            return false;
        }
        let never_heard_again = participant.created_at.elapsed().as_millis()
            >= u128::from(PROBATION_SPAN_MS)
            && !participant.survives_probation();
        let last_heard = participant.last_mark.map_or(participant.last_seen, |mark| {
            mark.max(participant.last_seen)
        });
        never_heard_again || last_heard.elapsed().as_millis() >= u128::from(PROBATION_SILENCE_MS)
    }

    /// Whether a participant of the probation is still waiting for its
    /// verdict or for its silence rule: first heard during our probation and
    /// not allowed to surface its matches yet (`fails_probation` may still
    /// remove it).
    fn awaits_probation_verdict(&self, participant: &ParticipantInfo) -> bool {
        !self.may_surface_matches(participant)
    }

    /// Remove the participants the probation verdict does not keep
    /// (`fails_probation`): first heard during our probation, judged once
    /// `PROBATION_SPAN_MS` old, and not heard from since `PROBATION_WINDOW_MS`
    /// after their entry was created, or silent for `PROBATION_SILENCE_MS`
    /// before becoming match eligible. These are likely stale entries from
    /// killed processes whose packets were read from the OS socket buffer
    /// during startup; a live peer that announces slowly has spoken again by
    /// then (its SEDP, its control traffic) and stays, with the reader
    /// proxies discovery gave its writers.
    ///
    /// Run at the boundary and on every later probation tick until the
    /// participants of the probation are settled; a participant younger than
    /// the span at one run is judged at a later one.
    pub fn purge_unconfirmed_participants(&self) {
        let stale_guids: Vec<GUID> = {
            let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::purge_unconfirmed");
            db.values()
                .filter(|p| self.fails_probation(p))
                .map(|p| p.guid)
                .collect()
        };
        if stale_guids.is_empty() {
            return;
        }
        // Requeue BEFORE removing. The peer can be re-inserted by the SPDP
        // handler the instant the removal lands, and that insert is what
        // drives `replay_pending_sedp`; requeueing afterwards means the
        // replay runs against an empty buffer and the entry rots forever.
        let requeued = self.requeue_purged_sedp(&stale_guids);
        for guid in &stale_guids {
            self.remove_participant_inner(*guid, ParticipantRemovalCondition::FailsProbation);
        }
        // A victim the re-check kept (a mark landed between the selection and
        // its removal) is still in the database: its SEDP goes back to the
        // retention, not to `pending_sedp`, where nothing would replay it
        // and it would only take room.
        let kept: Vec<GUID> = {
            let db = recover_read(
                Arc::as_ref(&self.db),
                "DiscoveryFsm::purge_unconfirmed kept",
            );
            stale_guids
                .iter()
                .filter(|guid| db.contains_key(guid))
                .copied()
                .collect()
        };
        if !kept.is_empty() {
            self.restore_retained_sedp(&kept, &requeued);
        }
        log::debug!(
            "[SPDP] Purged {} unconfirmed (stale) participants",
            stale_guids.len() - kept.len()
        );
    }

    /// Move the SEDP `requeue_purged_sedp` moved to `pending_sedp` for
    /// participants that were kept after all back into `probation_sedp`.
    fn restore_retained_sedp(&self, kept: &[GUID], requeued: &[GUID]) {
        let is_kept = |endpoint: &GUID| {
            requeued.contains(endpoint)
                && kept
                    .iter()
                    .any(|participant| participant.prefix == endpoint.prefix)
        };
        let restored: Vec<SedpData> = {
            let mut pending = recover_write(
                Arc::as_ref(&self.pending_sedp),
                "DiscoveryFsm::restore_retained_sedp pending",
            );
            let (restored, remaining) = pending
                .drain(..)
                .partition(|sd: &SedpData| is_kept(&sd.endpoint_guid));
            *pending = remaining;
            restored
        };
        let mut retained = recover_write(
            Arc::as_ref(&self.probation_sedp),
            "DiscoveryFsm::restore_retained_sedp retained",
        );
        for sd in restored {
            if retained.len() < PENDING_SEDP_CAPACITY {
                retained.push(sd);
            }
        }
    }

    /// Move the retained SEDP of just-purged participants back onto
    /// `pending_sedp`, so that the existing replay-on-SPDP path rebuilds their
    /// endpoints if they announce again.
    ///
    /// A participant purged by the probation verdict is either a zombie (never
    /// announces again -> the entries simply age out with the buffer) or a live
    /// peer whose announcements are merely slower than our 250 ms window (comes
    /// back on its next SPDP -> `replay_pending_sedp` re-registers exactly what
    /// we already parsed). Without this, only the second case is silently
    /// broken: peers do not re-send SEDP we already acknowledged, so the topic
    /// registry never learns about their endpoints again.
    ///
    /// Returns the endpoint GUIDs it moved.
    fn requeue_purged_sedp(&self, purged: &[GUID]) -> Vec<GUID> {
        let purged_prefixes: Vec<[u8; 12]> = purged
            .iter()
            .map(|g| {
                let mut p = [0u8; 12];
                p.copy_from_slice(&g.as_bytes()[..12]);
                p
            })
            .collect();

        let to_requeue: Vec<SedpData> = {
            let mut retained = recover_write(
                Arc::as_ref(&self.probation_sedp),
                "DiscoveryFsm::requeue_purged_sedp retained",
            );
            let mut keep = Vec::new();
            let mut take = Vec::new();
            for sd in retained.drain(..) {
                if purged_prefixes
                    .iter()
                    .any(|p| sd.endpoint_guid.as_bytes()[..12] == *p)
                {
                    take.push(sd);
                } else {
                    keep.push(sd);
                }
            }
            *retained = keep;
            take
        };

        let mut moved = Vec::new();
        if to_requeue.is_empty() {
            return moved;
        }

        let mut pending = recover_write(
            Arc::as_ref(&self.pending_sedp),
            "DiscoveryFsm::requeue_purged_sedp pending",
        );
        for sd in to_requeue {
            if pending.len() >= PENDING_SEDP_CAPACITY {
                log::warn!("[SEDP] Requeue buffer full, dropping purged SEDP for replay");
                break;
            }
            // Deduplicate against SEDP already waiting for the same endpoint.
            if pending.iter().any(|e| e.endpoint_guid == sd.endpoint_guid) {
                continue;
            }
            log::debug!(
                "[SEDP] Requeued SEDP of purged participant for replay: topic='{}' endpoint={}",
                sd.topic_name,
                sd.endpoint_guid
            );
            moved.push(sd.endpoint_guid);
            pending.push(sd);
        }
        moved
    }

    /// Refresh a participant's liveness from observed RTPS traffic.
    ///
    /// `last_seen` must not advance ONLY on SPDP announcements: the zombie
    /// purge below assumes the HDDS 3 s announcement period. Other vendors
    /// may announce far slower (tens of seconds), so a live,
    /// actively-ACKing participant would go "stale" 6 s after each
    /// announcement and be purged mid-test -- its readers vanishing from
    /// every send path (second-subscriber starvation). Any authenticated
    /// control-path message (ACKNACK / HEARTBEAT /
    /// GAP / NACK_FRAG) proves the process is alive: touch it. Dead
    /// processes emit nothing, so the zombie purge keeps its fast rig
    /// hygiene.
    ///
    /// The same message is also a liveness mark (`ParticipantInfo::mark_alive`):
    /// a peer that announced once and then only heartbeats is confirmed by
    /// its own traffic, and the mark that makes it eligible after the
    /// probation boundary surfaces the match held back for it.
    ///
    /// The replay runs on the calling thread; the control thread uses
    /// `note_control_traffic` instead and hands the replay to another
    /// thread, because it surfaces matches to user listeners.
    pub fn touch_participant_by_prefix(&self, prefix: &[u8; 12]) {
        if let Some(guid) = self.note_control_traffic(prefix) {
            self.replay_after_late_eligibility(guid);
        }
    }

    /// The liveness part of `touch_participant_by_prefix`: refresh
    /// `last_seen` and count a liveness mark for the participant owning
    /// `prefix`. Returns that participant when this mark made it match
    /// eligible: the caller owes it `replay_after_late_eligibility`, which
    /// runs user callbacks (`on_publication_matched`, ...) and must therefore
    /// not run on a thread whose stall delays the protocol (the control
    /// thread). Takes only the database lock.
    pub(crate) fn note_control_traffic(&self, prefix: &[u8; 12]) -> Option<GUID> {
        let mut guid_bytes = [0u8; 16];
        guid_bytes[..12].copy_from_slice(prefix);
        guid_bytes[12..16].copy_from_slice(&crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT);
        let guid = GUID::from_bytes(guid_bytes);
        let mut db = recover_write(Arc::as_ref(&self.db), "DiscoveryFsm::touch_participant");
        db.get_mut(&guid)
            .is_some_and(|p| {
                p.last_seen = std::time::Instant::now();
                self.mark_and_check_eligibility(p)
            })
            .then_some(guid)
    }

    /// Count a liveness mark for the participant owning `prefix` (an emission
    /// observed now) and, if that mark lets it surface its matches after the
    /// probation boundary (`may_surface_matches`), surface what was held back
    /// for it.
    ///
    /// Returns whether the probation heuristics may still purge that
    /// participant (first heard during our probation, matches not allowed to
    /// surface yet): its SEDP is then retained for a replay (`probation_sedp`).
    fn note_participant_liveness(&self, prefix: &[u8]) -> bool {
        let (became_eligible, may_be_purged) = {
            let mut db = recover_write(
                Arc::as_ref(&self.db),
                "DiscoveryFsm::note_participant_liveness",
            );
            match db.values_mut().find(|p| &p.guid.as_bytes()[..12] == prefix) {
                Some(p) => {
                    let became = self.mark_and_check_eligibility(p).then_some(p.guid);
                    (became, self.awaits_probation_verdict(p))
                }
                None => (None, false),
            }
        };
        if let Some(guid) = became_eligible {
            self.replay_after_late_eligibility(guid);
        }
        may_be_purged
    }

    /// A user DATA or DATA_FRAG from the participant whose GUID prefix the
    /// RTPS header of `datagram` carries (bytes 8..20) was received: the
    /// participant speaking, a liveness mark at the distinct-instant rule
    /// every mark follows (`ParticipantInfo::mark_alive`), counted only for a
    /// participant the probation may still purge.
    ///
    /// A participant first heard during our probation that announced itself
    /// and then sends nothing but samples - best-effort, so no HEARTBEAT, and
    /// its next SPDP seconds away - would earn no mark from them, and be
    /// purged as silent (`fails_probation`) while its writers, paired at
    /// discovery, were delivering: a departure (instances NOT_ALIVE_NO_WRITERS,
    /// then ALIVE again), its proxies gone until its next SPDP. Its first
    /// sample after our boundary instant lets it surface its matches, from
    /// which point the probation no longer judges it.
    ///
    /// Called by the discovery dispatch for every user DATA and DATA_FRAG
    /// it is handed. Once every participant of the probation is settled
    /// (`probation_cohort_settled`: at the earliest `2 * PROBATION_SPAN_MS`
    /// after our start, once each participant of the probation is purged or
    /// may surface its matches; never unset) no participant can earn
    /// anything from a mark of this kind, and the call is one relaxed atomic
    /// load: a stale `false` only takes the slow path, which finds nothing
    /// to judge. Before that, a read lock on the participant database per
    /// sample, and the write lock only when a mark would count - at most
    /// once per `PROBATION_WINDOW_MS` per participant.
    #[inline]
    pub(crate) fn note_user_data(&self, datagram: &[u8]) {
        if self.probation_cohort_settled.load(Ordering::Relaxed) {
            return;
        }
        self.note_user_data_in_probation(datagram);
    }

    /// The slow path of `note_user_data`, while the probation cohort is not
    /// settled. The participant is looked up under the participant entity
    /// id, as for control traffic (`note_control_traffic`).
    #[cold]
    fn note_user_data_in_probation(&self, datagram: &[u8]) {
        let Some(prefix) = datagram
            .get(8..20)
            .and_then(|p| <[u8; 12]>::try_from(p).ok())
        else {
            return;
        };
        let participant = GUID::new(
            prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let counts = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::note_user_data")
            .get(&participant)
            .is_some_and(|p| self.awaits_probation_verdict(p) && p.mark_would_count());
        if counts {
            self.note_participant_liveness(&prefix);
        }
    }

    /// A DATA of sequence `sn` was admitted from `peer`'s
    /// BuiltinParticipantMessageWriter (RTPS v2.5 Sec.8.4.13): record it if
    /// higher than what is already held. KEEP_LAST(1) on this endpoint
    /// means only the highest ever matters, so a duplicate, a reorder, or a
    /// retransmit of an older assertion must never regress it.
    ///
    /// Only for a participant this FSM admitted: an entry is purged by
    /// `remove_participant`, which only an admitted participant reaches, so
    /// recording one for any other prefix would never be forgotten. The
    /// participant table stays read-locked across the insert, so a removal
    /// running concurrently purges after it, never before.
    pub(crate) fn note_participant_message_received(&self, peer: &[u8; 12], sn: u64) {
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::note_participant_message_received",
        );
        let key = GUID::new(
            *peer,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        if !db.contains_key(&key) {
            return;
        }
        let mut map = recover_write(
            &self.participant_message_received,
            "DiscoveryFsm::note_participant_message_received",
        );
        let held = map.entry(*peer).or_insert(0);
        if sn > *held {
            *held = sn;
        }
    }

    /// The highest sequence number received so far from `peer`'s
    /// BuiltinParticipantMessageWriter; 0 before any.
    #[must_use]
    pub(crate) fn participant_message_received(&self, peer: &[u8; 12]) -> u64 {
        recover_read(
            &self.participant_message_received,
            "DiscoveryFsm::participant_message_received",
        )
        .get(peer)
        .copied()
        .unwrap_or(0)
    }

    /// Count one mark; true when THIS mark allowed the participant to
    /// surface its matches (`may_surface_matches`): it made it match
    /// eligible, or it is its first mark after the boundary.
    fn mark_and_check_eligibility(&self, participant: &mut ParticipantInfo) -> bool {
        let could_surface = self.may_surface_matches(participant);
        participant.mark_alive() && !could_surface && self.may_surface_matches(participant)
    }

    /// Surface the matches deferred for a participant that has just become
    /// match-eligible, once the probation boundary is behind us; before it,
    /// the boundary's drain surfaces them.
    ///
    /// The flag is read under the `pending_notifications` lock: the drain
    /// takes its eligibility snapshot and publishes `probation_purge_done`
    /// under that lock, so a mark that lands between the two (put back as not
    /// eligible, flag still false) waits here for the publication and replays
    /// what the drain put back. Read without it, the flag could still be
    /// false and the entry would wait for an SPDP that may be 30 s away.
    pub(crate) fn replay_after_late_eligibility(&self, participant_guid: GUID) {
        // A participant that has said its farewell surfaces nothing more: the
        // replay runs user listeners, and a match notified after the
        // departure went out is a match with nobody. Checked, not held: a
        // listener that drops its own participant would otherwise wait on
        // itself in `depart`; and lock-free, because this runs under an SPDP
        // handler's own `still_here` read (see `departed_flag`).
        if self.has_departed() {
            return;
        }
        let probation_done = {
            let _pending = recover_read(
                Arc::as_ref(&self.pending_notifications),
                "DiscoveryFsm::replay_after_late_eligibility",
            );
            self.probation_purge_done.load(Ordering::Acquire)
        };
        if probation_done {
            self.replay_pending_for_participant(participant_guid);
        }
    }

    /// Purge stale confirmed participants before a catch-up scan.
    ///
    /// Two rules are applied:
    ///
    /// **Tier 1 -- HDDS spdp_count == 2, threshold 300 ms or advertised lease:**
    /// Kept for safety, not from a measured case. It was argued from two
    /// buffered SPDPs of a dead HDDS process arriving at T+5 ms and T+205 ms
    /// (gap > PROBATION_WINDOW_MS=100 ms), which would let the entry survive
    /// `purge_unconfirmed_participants`; that arrival pattern is not one a
    /// socket buffer produces, since two packets drained from one socket buffer are processed
    /// back to back. Whatever reaches spdp_count==2 and then stops refreshing
    /// `last_seen` (SPDP or control traffic) for 300 ms is dropped. A live
    /// HDDS participant at spdp_count==2 normally sends SPDP #3 within 200 ms,
    /// advancing the count before the 300 ms limit. This startup-probation
    /// heuristic intentionally precedes lease enforcement; a peer whose third
    /// burst packet is lost is re-admitted by its next SPDP.
    ///
    /// Never a participant that completed authentication with us: it signed
    /// our fresh challenge, so it is no buffered packet of a dead process,
    /// and it lives by its lease (below). The 300 ms are wall-clock time,
    /// and a thread descheduled for that long between the refresh of an
    /// SPDP and this purge would remove the very participant whose
    /// announcement it was handling. For a secure peer that removal drops the session and
    /// the peer's next announcement begins another, which spends the one
    /// re-authentication of the interval (`HandshakeMachine`
    /// `handle_auth_request`): a participant restarted within it would then
    /// wait it out unauthenticated.
    ///
    /// **Lease -- any participant, threshold = advertised lease:**
    /// A participant not refreshed for its advertised leaseDuration is
    /// removed, whatever its spdp_count and whether or not it completed
    /// authentication with us (DDSI-RTPS 2.5 8.5.3.2 and 8.5.3.3: stale
    /// entries are removed). This is one predicate,
    /// `ParticipantInfo::is_expired`, the one the lease tracker applies; the
    /// authentication exemption above belongs to Tier 1 (and to the probation
    /// verdict) only, never to the lease. An authenticated peer that died
    /// before a second SPDP was counted would otherwise stay forever, with
    /// its session.
    pub fn purge_zombie_confirmed_participants(&self) {
        // Tier 1: burst-phase zombies (spdp_count == 2, stale > 300 ms).
        const ZOMBIE2_LAST_SEEN_MS: u64 = 300;
        // Lease: every participant is entitled to its advertised
        // leaseDuration and to no more (RTPS 2.5 8.5.3.2: alive for
        // leaseDuration after each announcement; 8.5.3.3: stale entries are
        // those not refreshed for longer than it), including HDDS peers using
        // a custom steady-state announcement period. Purging any vendor
        // earlier removes live-but-quiet participants. DURATION_INFINITE
        // intentionally requires explicit dispose or administrative removal.
        // (guid, lease expired): Tier 1 candidates are confirmed against the
        // handshake machine below, with the database lock released.
        let candidates: Vec<(GUID, bool)> = {
            let db = recover_read(
                Arc::as_ref(&self.db),
                "DiscoveryFsm::purge_zombie_confirmed",
            );
            db.values()
                .filter_map(|p| {
                    if p.is_expired() {
                        return Some((p.guid, true));
                    }
                    let elapsed_ms = p.last_seen.elapsed().as_millis() as u64;
                    let is_hdds =
                        p.vendor_id == Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
                    (is_hdds && p.spdp_count == 2 && elapsed_ms > ZOMBIE2_LAST_SEEN_MS)
                        .then_some((p.guid, false))
                })
                .collect()
        };
        let zombie_guids: Vec<(GUID, bool)> = candidates
            .into_iter()
            .filter(|(guid, lease_expired)| {
                *lease_expired || !self.is_authenticated_participant(&guid.prefix)
            })
            .collect();
        for (guid, lease_expired) in &zombie_guids {
            // An expired lease is re-checked under the removal's write lock
            // (an SPDP may have refreshed it since the snapshot), as the
            // lease tracker does.
            if *lease_expired {
                self.remove_expired_participant(*guid);
            } else {
                self.remove_participant(*guid);
            }
        }
        if !zombie_guids.is_empty() {
            log::debug!(
                "[SPDP] Purged {} stale confirmed participants before catch-up scan",
                zombie_guids.len(),
            );
        }
    }

    /// Remove all discovered participants and their endpoints.
    ///
    /// Used at startup to clear stale SPDP/SEDP entries from previous
    /// processes that were using the same domain. Should be called BEFORE
    /// registering discovery listeners to avoid false match notifications.
    pub fn clear_all_participants(&self) {
        let guids: Vec<GUID> = {
            let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::clear_all");
            db.keys().copied().collect()
        };
        for guid in guids {
            self.remove_participant(guid);
        }
    }

    /// One-shot probation-completion trigger. After the 250 ms uptime
    /// mark, atomically claim the right to run the purge + drain via CAS
    /// so concurrent SPDP/SEDP handlers don't double-fire. Triggered from
    /// `handle_spdp` and `handle_sedp`, and from the control thread's
    /// periodic wake (every <= 10 ms), so the boundary fires on our own
    /// clock: a peer that sends no further SPDP or SEDP after its startup
    /// burst (its next SPDP possibly tens of seconds away) otherwise leaves it, and
    /// its deferred match, unresolved for as long as it stays quiet.
    ///
    /// After the boundary, each call also judges the participants of the
    /// probation that have reached their own verdict (`fails_probation`),
    /// until all of them are settled; from then on it is one atomic load.
    /// Before the boundary it is one atomic load and one elapsed check.
    pub(crate) fn maybe_complete_probation(&self) {
        // A participant that has said its farewell runs no boundary and no
        // verdict: the drain surfaces matches to user listeners and the purge
        // tells them of departures, for a participant that is leaving. Checked,
        // not held, as in `replay_after_late_eligibility`.
        if self.has_departed() {
            return;
        }
        if self.probation_purge_done.load(Ordering::Acquire) {
            self.settle_probation_cohort();
            return;
        }
        if (self.created_at.elapsed().as_millis() as u64) < PROBATION_SPAN_MS {
            return;
        }
        // Claim the run. The optimistic `probation_purge_done` check above
        // cannot serialise this on its own: that flag is published at the END
        // of the drain, so two handler threads (SPDP on the multicast listener,
        // SEDP on the unicast one) can both observe `false`, and the loser can
        // still be sitting in front of `purge_unconfirmed_participants` long
        // after the winner published completion. The purge is NOT idempotent
        // with respect to that delay -- it is a snapshot of "everything that
        // does not survive probation RIGHT NOW", so a late second run wipes
        // participants discovered after the boundary: a remote writer whose
        // SEDP is processed with `probation_purge_done` already true would be
        // deleted a few ms later by a stale in-flight purge.
        if self
            .probation_purge_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // Purge first (db write lock), then drain+publish. The drain
        // sets `probation_purge_done = true` under the pending write
        // lock; that interlock is what makes the
        // "deferral path re-checks the flag under pending lock"
        // protocol race-free against a thread that left the optimistic
        // check while the flag was still false (preemption between
        // the early `maybe_complete_probation` and the optimistic
        // check is real and observable).
        self.purge_unconfirmed_participants();
        self.drain_pending_post_probation();
    }

    /// The probation verdicts after the boundary: purge the participants of
    /// the probation that reached theirs and failed it, or fell silent before
    /// becoming match eligible, until none is left to judge. Settled once
    /// every participant first heard during the probation is at least
    /// `PROBATION_SPAN_MS` old (true of all of them from our uptime
    /// `2 * PROBATION_SPAN_MS`, since none is created after the boundary
    /// instant) and every one of them left is match eligible; the retained
    /// SEDP is dead weight then. (Entries belonging to purged participants
    /// were moved to `pending_sedp` by `requeue_purged_sedp`.) Safe to run
    /// concurrently and repeatedly: the verdict only ever selects
    /// participants of the probation, re-checked under the removal lock.
    fn settle_probation_cohort(&self) {
        if self.probation_cohort_settled.load(Ordering::Acquire) {
            return;
        }
        let every_verdict_due =
            self.created_at.elapsed().as_millis() >= u128::from(2 * PROBATION_SPAN_MS);
        self.purge_unconfirmed_participants();
        let unsettled = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::settle_probation")
            .values()
            .any(|p| self.awaits_probation_verdict(p));
        if every_verdict_due && !unsettled {
            self.probation_cohort_settled.store(true, Ordering::Release);
            recover_write(
                Arc::as_ref(&self.probation_sedp),
                "DiscoveryFsm::settle_probation_cohort probation_sedp",
            )
            .clear();
        }
    }

    /// One-shot drain of `pending_notifications` at the probation-window
    /// boundary (FSM uptime >= 250 ms). Endpoints whose participant is
    /// still present in `db` are surfaced to listeners; endpoints whose
    /// participant was purged by `purge_unconfirmed_participants` (zombie
    /// from a prior process) are dropped. This catches entries that
    /// the per-participant `replay_pending_for_participant` could miss
    /// -- notably the race where SPDP confirmation transitions BETWEEN
    /// our optimistic db read and our push to pending.
    fn drain_pending_post_probation(&self) {
        // At the probation boundary we apply the rule `handle_sedp` applies
        // to a new SEDP after it (`may_surface_matches`): surface every
        // deferred endpoint whose participant is present in `db` and may
        // surface (first heard after the boundary, or match eligible); put
        // back the endpoints of a participant still present but not eligible
        // yet, for the replay its eligibility triggers; drop the endpoints
        // of participants purged as zombies. Without this drain, deferred
        // entries of a participant eligible before the boundary would wait
        // for a replay nothing may trigger again (its marks are spent, its
        // next SPDP may be 30 s away).
        //
        // The work happens under the pending write lock so that
        // `replay_pending_for_participant`, triggered by a
        // concurrent SPDP just-confirmed transition, cannot
        // interleave between our drain and our reads.
        let (to_notify, incompat_only_eps, dropped) = {
            let mut pending = recover_write(
                Arc::as_ref(&self.pending_notifications),
                "DiscoveryFsm::drain_pending_post_probation",
            );
            // Idempotent re-entry guard: if some other thread already
            // completed probation while we were waiting for the lock,
            // there is nothing left to do.
            if self.probation_purge_done.load(Ordering::Acquire) {
                return;
            }
            let drained: Vec<EndpointInfo> = pending.drain(..).collect();
            // Map from GUID prefix -> whether it may surface its matches, for
            // every participant still in `db` after the purge
            // (`may_surface_matches`; for a participant first heard during the
            // probation, `ParticipantInfo::is_match_eligible` or a mark earned
            // after the boundary instant):
            //
            //   no liveness mark: purged by purge_unconfirmed_participants above
            //     (single buffered SPDP, or a burst all inside the entry's first
            //     PROBATION_WINDOW_MS), unless two counted SPDPs confirmed it.
            //
            //   spdp_count >= 3, or two liveness marks: eligible, surfaced here.
            //     Three 200 ms-interval SPDPs need the process alive 400 ms after
            //     entry creation; two marks need two emissions of any kind
            //     (SPDP, SEDP, HEARTBEAT, ACKNACK) at instants >= 100 ms apart,
            //     the first >= 100 ms after creation.
            //
            //   anything in between (spdp_count == 2, or one mark, earned before
            //     the boundary): kept but not eligible yet. The entry is put back
            //     below; its next mark (it lands after the boundary), through an
            //     SPDP (`handle_spdp`) or any other emission
            //     (`replay_after_late_eligibility`), surfaces it.
            //
            // What is measured and what is kept for safety: a dead process can
            // emit nothing after it died, so a mark proves the process was alive
            // >= 100 ms after we first heard it. The `spdp_count == 2` tier was
            // argued from two buffered SPDPs of a dead HDDS process arriving at
            // T+5 ms and T+205 ms; that arrival pattern is not one a socket
            // buffer produces (two packets drained from one socket buffer are processed back to back,
            // and a listener stall compresses gaps rather than spreading them).
            // The tier is kept as a safety margin, not as a measured case.
            let prefix_eligibility: std::collections::HashMap<[u8; 12], bool> = {
                let db = recover_read(
                    Arc::as_ref(&self.db),
                    "DiscoveryFsm::drain_pending_post_probation db",
                );
                db.values()
                    .map(|info| {
                        let bytes = info.guid.as_bytes();
                        let mut prefix = [0u8; 12];
                        prefix.copy_from_slice(&bytes[..12]);
                        (prefix, self.may_surface_matches(info))
                    })
                    .collect()
            };
            let is_drain_eligible = |prefix: &[u8; 12]| -> bool {
                matches!(prefix_eligibility.get(prefix), Some(&true))
            };
            let mut to_notify: Vec<EndpointInfo> = Vec::new();
            // Non-eligible endpoints whose participant is still present in `db`.
            // These cannot be MATCH-surfaced yet (see the eligibility map
            // above), but their
            // QoS-incompatibility MUST still be reported: a late-joining local
            // reader that discovered an incompatible remote writer during the
            // probation window had the writer deferred here, and dropping it
            // outright loses the one-shot on_requested_incompatible_qos /
            // on_offered_incompatible_qos fire (the live `is_new` path already
            // ran while the local entry was not yet registered). QoS-incompat is
            // zombie-safe: db-presence is the same bar the deferred type-incompat
            // path uses (see the incompat_present filter below), and a false
            // incompat for a dead participant is harmless. So fire ONLY the
            // incompat path for these -- never the match path.
            let mut incompat_only_eps: Vec<EndpointInfo> = Vec::new();
            let mut dropped = 0u32;
            for endpoint in drained {
                let mut prefix = [0u8; 12];
                prefix.copy_from_slice(&endpoint.endpoint_guid.as_bytes()[..12]);
                if is_drain_eligible(&prefix) {
                    to_notify.push(endpoint);
                } else if prefix_eligibility.contains_key(&prefix) {
                    // Present in db but not yet drain-eligible. Cannot
                    // MATCH-surface yet. QoS-incompat IS surfaced immediately
                    // after the lock is released (see the incompat_only_eps loop
                    // below).
                    //
                    // Critically: we also push a clone BACK into pending so that
                    // replay_pending_for_participant fires the full match path once
                    // the participant becomes eligible (its next SPDP, or the
                    // liveness mark that confirms it). Without this put-back the
                    // endpoint is permanently lost for the match path because
                    // replay_pending_for_participant drains pending_notifications
                    // and would find nothing then.
                    pending.push(endpoint.clone());
                    incompat_only_eps.push(endpoint);
                    dropped += 1;
                } else {
                    // Participant was purged as a zombie (absent from db);
                    // safe to drop entirely.
                    dropped += 1;
                }
            }
            #[cfg(test)]
            if let Some(hook) = self
                .drain_parked_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                hook();
            }
            // Publish completion UNDER the pending write lock. Any
            // deferral path that is currently waiting for this lock
            // (e.g. a thread that observed `flag == false` at its
            // optimistic check and is now blocked on the pending
            // write) will, on acquiring the lock next, re-read the
            // flag and see `true` -- and skip the push, surfacing the
            // endpoint directly. This closes the window where a
            // thread preempted between its early
            // `maybe_complete_probation` (which returned because
            // elapsed < 250 at the time) and its later optimistic
            // check could otherwise push a now-stranded entry into
            // pending.
            self.probation_purge_done.store(true, Ordering::Release);
            (to_notify, incompat_only_eps, dropped)
        };
        // Pending lock released. Notify outside the lock to avoid
        // holding it across listener callbacks (which may take their
        // own locks).
        // Surface QoS-incompat for db-present but not-yet-eligible endpoints
        // (deferred during probation). Incompat only -- these are not match-
        // eligible yet. Fired before the match loop so the
        // "incompat before match" ordering the OMG harness relies on holds.
        for ep in &incompat_only_eps {
            self.notify_endpoint_discovered_incompat_only(ep);
        }
        for ep in &to_notify {
            // Same as replay_pending_for_participant: deferred endpoints missed
            // their one-shot QoS-incompat fire (local entry not yet registered at
            // is_new time), so the match path alone drops QoS mismatches. Re-fire
            // the incompat path first; both paths dedup, so this is idempotent.
            self.notify_endpoint_discovered_incompat_only(ep);
            self.notify_endpoint_discovered(ep);
        }
        if !to_notify.is_empty() || dropped > 0 {
            log::debug!(
                "[SEDP] Probation drain: surfaced {} endpoint(s) from present participants, dropped {} zombie(s)",
                to_notify.len(),
                dropped
            );
        }
    }

    /// Replay deferred endpoint notifications for a participant, after
    /// the probation boundary: on its every SPDP (`handle_spdp`) and on the
    /// liveness mark that makes it match-eligible
    /// (`replay_after_late_eligibility`). Only called after probation ends.
    fn replay_pending_for_participant(&self, participant_guid: GUID) {
        let participant_prefix = &participant_guid.as_bytes()[..12];

        let to_replay: Vec<EndpointInfo> = {
            let mut pending = recover_write(
                Arc::as_ref(&self.pending_notifications),
                "DiscoveryFsm::replay_pending",
            );
            let mut remaining = Vec::new();
            let mut matching = Vec::new();
            for ep in pending.drain(..) {
                if &ep.endpoint_guid.as_bytes()[..12] == participant_prefix {
                    matching.push(ep);
                } else {
                    remaining.push(ep);
                }
            }
            *pending = remaining;
            matching
        };

        #[cfg(test)]
        if !to_replay.is_empty() {
            if let Some(hook) = self
                .replay_parked_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                hook();
            }
        }
        if !to_replay.is_empty() {
            log::debug!(
                "[SEDP] Replaying {} deferred endpoint(s) for confirmed participant {:?}",
                to_replay.len(),
                participant_guid
            );
            for endpoint in &to_replay {
                // Deferred endpoints missed their one-shot QoS-incompat fire: the
                // `is_new` block ran `notify_endpoint_discovered_incompat_only`
                // while the local entry was not yet registered (late-joiner: the
                // remote writer's SEDP is processed before the local reader's
                // match-registry entry exists), so `evaluate_entries` saw zero
                // entries and fired nothing. Replaying only the match path here
                // surfaces compatible pairs but silently drops QoS mismatches
                // (e.g. Presentation access_scope), so on_requested_incompatible_qos
                // / on_offered_incompatible_qos never fire. Re-fire the incompat
                // path first (preserving "incompat before match" ordering); both
                // paths dedup (incompat_remotes / matched_remotes), so this is
                // idempotent against the live SEDP path.
                self.notify_endpoint_discovered_incompat_only(endpoint);
                self.notify_endpoint_discovered(endpoint);
            }
        }
    }

    /// Replay buffered SEDP data that arrived before this participant's SPDP.
    /// Called from handle_spdp after inserting the new participant into the DB.
    fn replay_pending_sedp(&self, participant_guid: &GUID) {
        let participant_prefix = &participant_guid.as_bytes()[..12];
        let to_replay: Vec<SedpData> = {
            let mut pending = recover_write(
                Arc::as_ref(&self.pending_sedp),
                "DiscoveryFsm::replay_pending_sedp",
            );
            let mut remaining = Vec::new();
            let mut matching = Vec::new();
            for sd in pending.drain(..) {
                if &sd.endpoint_guid.as_bytes()[..12] == participant_prefix {
                    matching.push(sd);
                } else {
                    remaining.push(sd);
                }
            }
            *pending = remaining;
            matching
        };

        if !to_replay.is_empty() {
            log::debug!(
                "[SEDP] Replaying {} buffered SEDP(s) for newly registered participant {:?}",
                to_replay.len(),
                participant_guid
            );
            for sd in to_replay {
                self.handle_sedp(sd);
            }
            // The writers announced before their participant was known were
            // decided while it was not (`sedp_handler::record_writer_group_dialect`
            // and `record_writer_vendor` read the participant, and there was
            // none yet), and replayed here they never went back through that
            // handler. Their class and their legacy key-hash decision are
            // taken again now that the participant and its writers are known,
            // whatever the dialect.
            let mut prefix = [0u8; 12];
            prefix.copy_from_slice(participant_prefix);
            self.notify_writers_dialect(&prefix);
        }
    }

    pub fn remove_participant(&self, guid: GUID) {
        self.remove_participant_inner(guid, ParticipantRemovalCondition::Always);
    }

    /// [`remove_participant`](Self::remove_participant), for a participant
    /// that announced its departure (its SPDP dispose): listeners hear it
    /// as announced (`DiscoveryListener::on_participant_left`).
    pub fn remove_departed_participant(&self, guid: GUID) {
        self.remove_participant_inner(guid, ParticipantRemovalCondition::Announced);
    }

    pub(crate) fn remove_expired_participant(&self, guid: GUID) {
        self.remove_participant_inner(guid, ParticipantRemovalCondition::Expired);
    }

    /// Remove a participant only if the selected condition still holds.
    ///
    /// The purge paths select their victims from a read-locked snapshot and
    /// then remove them one by one under a separate write lock. Between those
    /// two steps the SPDP handler runs freely: a participant that was at
    /// `spdp_count == 1` when the snapshot was taken can reach 2 (confirmed
    /// alive) microseconds later and still be deleted, taking its topic-registry
    /// endpoints with it: a victim at `spdp_count=2 last_seen=0ms` --
    /// confirmed, and refreshed in the very instant it was dropped.
    ///
    /// The condition is re-evaluated under the same write lock that performs
    /// the removal, which is the only place it can be evaluated soundly.
    fn remove_participant_inner(&self, guid: GUID, condition: ParticipantRemovalCondition) {
        crate::trace_fn!("DiscoveryFsm::remove_participant");
        // Remove from participant DB.
        let mut db = recover_write(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::remove_participant db.write()",
        );
        let should_remove = db.get(&guid).is_some_and(|participant| match condition {
            ParticipantRemovalCondition::Always
            | ParticipantRemovalCondition::Announced
            | ParticipantRemovalCondition::Farewell => true,
            ParticipantRemovalCondition::FailsProbation => self.fails_probation(participant),
            ParticipantRemovalCondition::Expired => participant.is_expired(),
        });
        if !should_remove {
            return;
        }
        let removed = db.remove(&guid).is_some();
        if removed {
            self.forget_group_dialect(&guid.prefix);
            self.sync_vendor_of(&db, guid.prefix);
        }

        // The participant's handshake session goes with it, in progress or
        // complete, under the same lock that removed it: one that comes back
        // under the same prefix is a new peer and is authenticated again,
        // with fresh keys, instead of being held to a session its new process
        // knows nothing about (as initiator, `start` refuses to begin again
        // over a `Complete` session, so the peer would wait forever). This is the
        // one door every removal takes: a departure, a lease expiry, a
        // probation purge.
        #[cfg(feature = "security")]
        if removed {
            if let Some(ref machine) = self.handshake_machine {
                machine.drop_handshake(&GUID::new(
                    guid.prefix,
                    crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                ));
            }
        }
        drop(db); // Release lock before topic registry operation

        if removed {
            #[cfg(feature = "security")]
            self.release_remote_writer_keys(guid.prefix);
            #[cfg(feature = "security")]
            self.secure_sedp_repairs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&guid.prefix);
            recover_write(
                &self.reannouncements_owed,
                "DiscoveryFsm::remove_participant reannouncement",
            )
            .remove(&guid.prefix);
            recover_write(
                &self.declared_leases,
                "DiscoveryFsm::remove_participant declared lease",
            )
            .remove(&guid.prefix);
            recover_write(
                &self.participant_message_received,
                "DiscoveryFsm::remove_participant participant message received",
            )
            .remove(&guid.prefix);
            #[cfg(feature = "security")]
            self.parked_sedp
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(&guid.prefix);
            #[cfg(feature = "security")]
            self.awaiting_key_sedp
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(&guid.prefix);
            // Its readers' withheld replays: a participant that comes back
            // under the prefix announces its readers again.
            #[cfg(feature = "security")]
            let _ = self
                .withheld_replays
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take_peer(&guid.prefix);
            self.forget_sedp_change_order(&guid.prefix);
            // Every endpoint of the participant leaves the topic registry and
            // the deferred-notification list (the per-endpoint part, shared
            // with `remove_remote_endpoint`).
            let prefix = &guid.as_bytes()[..12];
            let removed_endpoints =
                self.forget_endpoints(|endpoint_guid| &endpoint_guid.as_bytes()[..12] == prefix);

            // Remove from endpoint registry: the participant's own
            // locator and those of all its endpoints.
            self.endpoint_registry.remove(&guid);

            self.metrics
                .participants_expired
                .fetch_add(1, Ordering::Relaxed);

            // Drop the access-control verdict reached for this peer. The cache
            // is keyed on the participant GUID, and a GUID prefix can be
            // recycled by a process that recreates participants; a verdict
            // left behind would be applied to whoever inherits the prefix,
            // which is the same shape of defect as the recycled participant id
            // that silently lost SEDP announcements. Normalised exactly as the
            // gate normalises it -- the DB key carries whatever entity id the
            // peer announced.
            #[cfg(feature = "security")]
            if let Some(ref access) = self.remote_access_control {
                access.forget_peer(&GUID::new(
                    guid.prefix,
                    crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                ));
            }
            // And every admission reached about it (`admission_epoch`): a
            // participant that comes back under the prefix is judged anew.
            #[cfg(feature = "security")]
            self.admission_changes.fetch_add(1, Ordering::Release);

            // Every removal is a departure for the participant's writers,
            // the probation purges included: a participant purged after it
            // fell silent may have delivered samples (a reader takes its
            // WriterProxy at discovery), and its writers are not alive any
            // more (DDS v1.4 Sec.2.2.2.5.1.3). For a writer that delivered
            // nothing the departure changes no instance.
            let listeners = recover_read(
                Arc::as_ref(&self.listeners),
                "DiscoveryFsm::remove_participant departed",
            )
            .clone();
            let announced = matches!(
                condition,
                ParticipantRemovalCondition::Farewell | ParticipantRemovalCondition::Announced
            );
            for listener in &listeners {
                listener.on_participant_left(guid, announced);
            }
            if !matches!(condition, ParticipantRemovalCondition::Farewell) {
                for listener in &listeners {
                    listener.on_participant_forgotten(guid);
                }
            }
            for endpoint in &removed_endpoints {
                self.notify_endpoint_removed(endpoint);
            }
        }
    }

    /// Remove ONE remote endpoint from discovery, leaving its participant in
    /// place.
    ///
    /// A remote DataReader or DataWriter deleted while its participant lives
    /// on is announced by a dispose/unregister of its instance of the SEDP
    /// built-in topic (DCPSSubscription or DCPSPublication; PID_STATUS_INFO,
    /// RTPS v2.5 Sec.9.6.4.9). Without this, an endpoint would leave the topic
    /// registry only together with its whole participant, so a deleted
    /// remote reader would stay matched for the participant's lifetime and the
    /// local writer's `publication_matched.current_count` would never go down,
    /// where DDS v1.4 defines it as the number of readers CURRENTLY matched.
    ///
    /// Runs the per-endpoint part of `remove_participant_inner` through the
    /// same helper, then drops any SEDP of this endpoint still buffered for
    /// replay. A participant purge requeues those on purpose (the peer may be
    /// alive and will announce again); an endpoint that announced its own
    /// deletion must not be rebuilt from its old announcement. A fresh
    /// announcement of the same GUID goes through `handle_sedp` as usual and
    /// matches again.
    ///
    /// Returns whether the endpoint was known to the topic registry. An
    /// unknown GUID is a no-op, and so is a GUID under our own prefix: our
    /// endpoints are not a peer's to retire.
    pub fn remove_remote_endpoint(&self, endpoint_guid: GUID) -> bool {
        crate::trace_fn!("DiscoveryFsm::remove_remote_endpoint");
        if endpoint_guid.as_bytes()[..12] == self.local_guid.as_bytes()[..12] {
            return false;
        }

        #[cfg(feature = "security")]
        self.secure_endpoints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&endpoint_guid);

        // Its sequence tombstones stay, to refuse an older announcement of
        // an endpoint that is gone; they are marked retired so that a prefix
        // at capacity can reclaim them (`evict_retired_sedp_identities`)
        // instead of refusing the next live endpoint forever.
        {
            let mut order = self
                .sedp_change_order
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for channel in [SedpChannel::Plain, SedpChannel::Secure] {
                if let Some(record) = order.get_mut(&(channel, endpoint_guid)) {
                    record.retired = true;
                }
            }
        }

        // Even an endpoint removed before its SEDP was admitted can have
        // tokens waiting for its match at the volatile secure reader.
        #[cfg(feature = "security")]
        if let Some(suite) = self
            .volatile_suite
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            suite.volatile.retire_source(endpoint_guid);
        }
        let removed_endpoints = self.forget_endpoints(|guid| *guid == endpoint_guid);
        self.endpoint_registry
            .remove_endpoint_locators(|guid| *guid == endpoint_guid);
        // Unmatched first: the key material its tokens installed then goes,
        // so that nothing it sent after its deletion opens here, and so
        // that what each deleted endpoint held does not stay for as long as
        // its participant lives.
        #[cfg(feature = "security")]
        if let Some(suite) = self
            .volatile_suite
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            suite
                .volatile
                .forget_source_keys(&suite.data_keys, endpoint_guid);
        }
        #[cfg(feature = "security")]
        let _ = self
            .withheld_replays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(&endpoint_guid);

        for buffer in [&self.pending_sedp, &self.probation_sedp] {
            let mut buffered = recover_write(
                Arc::as_ref(buffer),
                "DiscoveryFsm::remove_remote_endpoint buffered sedp",
            );
            buffered.retain(|sd| sd.endpoint_guid != endpoint_guid);
        }

        for endpoint in &removed_endpoints {
            self.notify_endpoint_removed(endpoint);
        }
        // A writer that said it is gone takes its QoS verdicts with it,
        // whether discovery held it (`on_endpoint_removed` did it above) or
        // held its announcement back, or forgot it with a participant that
        // fell silent (no endpoint to notify).
        if EndpointKind::from_guid(&endpoint_guid) == EndpointKind::Writer {
            if let Some(reg) = self.match_registry.get() {
                reg.forget_remote_writer(&endpoint_guid);
            }
        }
        !removed_endpoints.is_empty()
    }

    /// Forget an endpoint of this participant that was deleted.
    ///
    /// A local endpoint enters the topic registry when it is announced
    /// (`handle_sedp` with our own prefix), and every decision about its
    /// topic reads it there: the refusal of a remote writer incompatible
    /// with every local reader, a writer's negotiated data representation,
    /// a reader's ownership and partition resolution. Kept after its
    /// deletion, it would decide for an endpoint that no longer exists for
    /// the life of the participant. `SedpRetirement` calls this as the endpoint
    /// is deleted.
    ///
    /// Returns whether the endpoint was known. A GUID under another prefix
    /// is a no-op: a remote endpoint leaves by `remove_remote_endpoint`.
    pub(crate) fn remove_local_endpoint(&self, endpoint_guid: GUID) -> bool {
        crate::trace_fn!("DiscoveryFsm::remove_local_endpoint");
        if endpoint_guid.as_bytes()[..12] != self.local_guid.as_bytes()[..12] {
            return false;
        }
        let removed_endpoints = self.forget_endpoints(|guid| *guid == endpoint_guid);
        self.endpoint_registry
            .remove_endpoint_locators(|guid| *guid == endpoint_guid);
        for endpoint in &removed_endpoints {
            self.notify_endpoint_removed(endpoint);
        }
        !removed_endpoints.is_empty()
    }

    /// Per-endpoint teardown shared by participant and endpoint removal.
    ///
    /// Takes every endpoint `is_gone` selects out of the topic registry and
    /// out of `pending_notifications` (a match still deferred for it must
    /// not surface after it is gone), and returns the endpoints that left
    /// the registry. The caller announces them with `notify_endpoint_removed`
    /// once its own bookkeeping is done; no lock is held on return, because
    /// listeners may query discovery state.
    fn forget_endpoints(&self, is_gone: impl Fn(&GUID) -> bool) -> Vec<EndpointInfo> {
        let removed_endpoints = {
            let mut registry = recover_write(
                Arc::as_ref(&self.topic_registry),
                "DiscoveryFsm::forget_endpoints registry.write()",
            );
            registry.remove_endpoints_where(&is_gone)
        };
        if !removed_endpoints.is_empty() {
            // Registry content changed: invalidate writer-side caches
            // keyed on the topic-registry generation (see field doc).
            self.topic_registry_generation
                .fetch_add(1, Ordering::Release);
        }

        // Clean up any pending notifications for these endpoints.
        let mut pending = recover_write(
            Arc::as_ref(&self.pending_notifications),
            "DiscoveryFsm::forget_endpoints pending",
        );
        pending.retain(|ep| !is_gone(&ep.endpoint_guid));
        removed_endpoints
    }
}

#[derive(Clone, Copy)]
enum ParticipantRemovalCondition {
    Always,
    /// Always, for a participant that announced its departure (its SPDP
    /// dispose): its writers are deleted, never taken back for themselves.
    Announced,
    FailsProbation,
    Expired,
    /// Always, for a lease-0 farewell: the discovery records of the peer are
    /// kept (`DiscoveryListener::on_participant_forgotten`).
    Farewell,
}

/// Recover from poisoned read lock by logging and taking ownership.
pub(crate) fn recover_read<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[discovery] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}

/// Recover from poisoned write lock by logging and taking ownership.
pub(crate) fn recover_write<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[discovery] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::{SedpData, SpdpData};
    use std::convert::TryFrom;
    use std::sync::{Mutex, Weak};

    struct RemovalListener {
        removed: Mutex<Vec<GUID>>,
        fsm: Weak<DiscoveryFsm>,
    }

    impl DiscoveryListener for RemovalListener {
        fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
            drop(endpoint);
        }

        fn on_endpoint_removed(&self, endpoint: EndpointInfo) {
            let fsm = self.fsm.upgrade().expect("FSM must outlive callback");
            assert!(fsm.get_participants().is_empty());
            assert!(fsm.find_writers_for_topic(&endpoint.topic_name).is_empty());
            self.removed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(endpoint.endpoint_guid);
        }
    }

    fn sample_remote_guid(byte: u8) -> GUID {
        let mut data = [0u8; 16];
        for (idx, slot) in data.iter_mut().enumerate() {
            let offset = u8::try_from(idx).unwrap_or(0);
            *slot = byte.wrapping_add(offset);
        }
        GUID::from_bytes(data)
    }

    #[test]
    fn test_fsm_new() {
        let local_guid = sample_remote_guid(1);
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        assert_eq!(fsm.local_guid, local_guid);
        assert_eq!(fsm.lease_duration_ms, 100_000);
        assert!(fsm.get_participants().is_empty());
    }

    #[test]
    fn test_handle_spdp_new_participant() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(2);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec!["127.0.0.1:7400"
                .parse()
                .expect("Socket address parsing should succeed")],
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

        fsm.handle_spdp(spdp_data);

        let participants = fsm.get_participants();
        assert_eq!(participants.len(), 1);
        assert_eq!(participants[0].guid, remote_guid);
        assert_eq!(participants[0].endpoints.len(), 1);
    }

    #[test]
    fn test_handle_spdp_duplicate_refresh() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(3);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
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

        fsm.handle_spdp(spdp_data.clone());
        let first_seen = {
            let db = fsm.db.read().expect("RwLock read should succeed");
            db.get(&remote_guid)
                .expect("Participant should exist")
                .last_seen
        };

        std::thread::sleep(std::time::Duration::from_millis(5));

        fsm.handle_spdp(spdp_data);
        let second_seen = {
            let db = fsm.db.read().expect("RwLock read should succeed");
            db.get(&remote_guid)
                .expect("Participant should exist")
                .last_seen
        };

        assert!(second_seen > first_seen);
        assert_eq!(fsm.get_participants().len(), 1);
    }

    #[test]
    fn test_handle_spdp_ignore_self() {
        let local_guid = sample_remote_guid(4);
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let spdp_data = SpdpData {
            participant_guid: local_guid,
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

        fsm.handle_spdp(spdp_data);
        assert!(fsm.get_participants().is_empty());
    }

    #[test]
    fn test_remove_participant() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(5);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
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

        fsm.handle_spdp(spdp_data);
        assert_eq!(fsm.get_participants().len(), 1);

        fsm.remove_participant(remote_guid);
        assert!(fsm.get_participants().is_empty());
    }

    fn reader_on(prefix: [u8; 12], key: u8, topic: &str, partition: Option<&str>) -> EndpointInfo {
        let qos = partition.map(|p| crate::dds::qos::QoS::default().partition_single(p));
        EndpointInfo::from_sedp(
            SedpData {
                topic_name: topic.to_string(),
                type_name: "T".to_string(),
                participant_guid: GUID::new(prefix, [0, 0, 0, 0]),
                endpoint_guid: GUID::new(prefix, [0, 0, key, 0x07]),
                qos_hash: 0,
                qos,
                type_object: None,
                dependents: Vec::new(),
                type_object_legacy_v1: false,
                unicast_locators: vec![],
                user_data: None,
                shm_capability: None,
                has_explicit_reliability: false,
                has_explicit_ownership: false,
                has_ownership_strength: false,
                type_information: None,
                type_consistency: None,
                group_entity_id: None,
                endpoint_security_info: None,
            },
            None,
        )
    }

    /// DDS 1.4 2.2.3.13 (PARTITION): the routing view a writer reads per
    /// packet lists exactly the readers `find_readers_for_topic` lists, in
    /// its order, and marks compatible those whose partition matches the
    /// writer's; with the default partition every reader is.
    #[test]
    fn the_routing_view_lists_the_topics_readers_with_their_partition_verdict() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 30_000);
        {
            let mut registry = recover_write(Arc::as_ref(&fsm.topic_registry), "test");
            registry.insert(reader_on([1; 12], 1, "Routed", Some("a")));
            registry.insert(reader_on([2; 12], 2, "Routed", Some("b")));
            registry.insert(reader_on([3; 12], 3, "Routed", None));
            registry.insert(reader_on([4; 12], 4, "Other", Some("a")));
        }
        let full = fsm.find_readers_for_topic("Routed");
        let identities = |routes: &[ReaderRoute]| {
            routes
                .iter()
                .map(|r| (r.endpoint_guid, r.participant_guid))
                .collect::<Vec<_>>()
        };
        let expected: Vec<_> = full
            .iter()
            .map(|r| (r.endpoint_guid, r.participant_guid))
            .collect();
        assert_eq!(expected.len(), 3, "fixture");

        let open = fsm.reader_routes_for_topic("Routed", None);
        assert_eq!(identities(&open), expected);
        assert!(open.iter().all(|r| r.compatible));

        let writer = crate::dds::qos::QoS::default().partition_single("a");
        let routed = fsm.reader_routes_for_topic("Routed", Some(&writer));
        assert_eq!(identities(&routed), expected);
        for (route, reader) in routed.iter().zip(&full) {
            assert_eq!(
                route.compatible,
                crate::core::discovery::Matcher::is_compatible(&reader.qos, &writer),
                "{:?}",
                reader.endpoint_guid
            );
        }
        let verdicts: Vec<_> = routed
            .iter()
            .map(|r| (r.endpoint_guid.prefix[0], r.compatible))
            .collect();
        assert!(verdicts.contains(&(1, true)), "{verdicts:?}");
        assert!(verdicts.contains(&(2, false)), "{verdicts:?}");
        assert!(fsm.reader_routes_for_topic("Missing", None).is_empty());
    }

    /// An SPDP announcement of `guid` carrying `vendor_id` (no security).
    fn spdp_announcing(guid: GUID, vendor_id: Option<u16>) -> SpdpData {
        SpdpData {
            participant_guid: guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec!["127.0.0.1:7400"
                .parse()
                .expect("Socket address parsing should succeed")],
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

    /// The vendor id of a participant (PID_VENDORID, RTPS 2.5 8.5.3.2) is
    /// found by its GUID prefix, whatever entity id the caller's GUID
    /// carries and under whatever GUID the participant is filed.
    #[test]
    fn a_participants_vendor_is_found_by_its_prefix() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 30_000);
        let filed = GUID::new(
            [7; 12],
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let odd = GUID::new([8; 12], [0, 0, 0, 0]);
        fsm.handle_spdp(spdp_announcing(filed, Some(0x0101)));
        fsm.handle_spdp(spdp_announcing(odd, Some(0x0110)));
        assert_eq!(fsm.vendor_id_for_participant(&filed), Some(0x0101));
        assert_eq!(
            fsm.vendor_id_for_participant(&GUID::new([7; 12], [0, 0, 0, 0])),
            Some(0x0101)
        );
        assert_eq!(
            fsm.vendor_id_for_participant(&GUID::new(
                [8; 12],
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT
            )),
            Some(0x0110)
        );
        assert_eq!(
            fsm.vendor_id_for_participant(&GUID::new([9; 12], [0, 0, 0, 0])),
            None
        );
    }

    /// The per-prefix vendor cache the send paths read follows the database:
    /// a re-announcement with another vendor takes it (while present and
    /// after a return), and a removal drops it, so no vendor outlives the
    /// participant that advertised it.
    #[test]
    fn a_participants_vendor_follows_its_announcements_and_leaves_with_it() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 30_000);
        let guid = GUID::new(
            [7; 12],
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );

        fsm.handle_spdp(spdp_announcing(guid, Some(0x0101)));
        assert_eq!(fsm.vendor_id_for_participant(&guid), Some(0x0101));

        // Re-announced while present: the refresh takes the new vendor.
        fsm.handle_spdp(spdp_announcing(guid, Some(0x0110)));
        assert_eq!(fsm.vendor_id_for_participant(&guid), Some(0x0110));

        fsm.remove_participant(guid);
        assert_eq!(
            fsm.vendor_id_for_participant(&guid),
            None,
            "a removed participant's vendor survived its removal"
        );

        // Back under the same prefix, with another vendor: the new one.
        fsm.handle_spdp(spdp_announcing(guid, Some(0x0101)));
        assert_eq!(fsm.vendor_id_for_participant(&guid), Some(0x0101));
        fsm.remove_participant(guid);
        fsm.handle_spdp(spdp_announcing(guid, Some(0x0110)));
        assert_eq!(fsm.vendor_id_for_participant(&guid), Some(0x0110));
    }

    #[test]
    fn confirmed_hdds_participant_keeps_its_advertised_lease() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 30_000);
        let remote_guid = sample_remote_guid(0x30);
        let mut participant = ParticipantInfo::new(remote_guid, vec![], 20_000);
        participant.vendor_id = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
        participant.spdp_count = 3;
        participant.created_at = Instant::now() - std::time::Duration::from_secs(7);
        participant.last_seen = Instant::now() - std::time::Duration::from_secs(7);
        recover_write(Arc::as_ref(&fsm.db), "test custom lease insert")
            .insert(remote_guid, participant);

        fsm.purge_zombie_confirmed_participants();
        assert!(
            recover_read(Arc::as_ref(&fsm.db), "test custom lease survives")
                .contains_key(&remote_guid),
            "a quiet HDDS peer must not be purged before its advertised lease"
        );
        assert!(
            fsm.is_participant_matchable_and_recent(&remote_guid.as_bytes()[..12]),
            "the matching gate must use the same advertised-lease bound as purge"
        );

        recover_write(Arc::as_ref(&fsm.db), "test custom lease expire")
            .get_mut(&remote_guid)
            .expect("participant remains registered")
            .last_seen = Instant::now() - std::time::Duration::from_secs(21);
        fsm.purge_zombie_confirmed_participants();
        assert!(
            !recover_read(Arc::as_ref(&fsm.db), "test custom lease removed")
                .contains_key(&remote_guid),
            "the participant must still be purged after its advertised lease"
        );
    }

    #[test]
    fn participant_lease_expiration_uses_exact_boundary() {
        for lease_ms in [1_000, 20_000] {
            assert!(!participant_lease_expired(lease_ms - 1, lease_ms));
            assert!(participant_lease_expired(lease_ms, lease_ms));
        }
        assert!(!participant_lease_expired(u64::MAX - 1, u64::MAX));
        assert!(!participant_lease_expired(u64::MAX, u64::MAX));
    }

    #[test]
    fn foreign_participant_does_not_use_hdds_burst_expiration() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 30_000);
        let remote_guid = sample_remote_guid(0x31);
        let mut participant = ParticipantInfo::new(remote_guid, vec![], 30_000);
        participant.vendor_id = Some(0x0101);
        participant.spdp_count = 2;
        // Heard before this FSM existed, hence during its probation: match
        // eligible through two liveness marks (an SPDP count of 2 is not).
        participant.liveness_marks = 2;
        participant.created_at = Instant::now() - std::time::Duration::from_secs(1);
        participant.last_seen = Instant::now() - std::time::Duration::from_millis(500);
        recover_write(Arc::as_ref(&fsm.db), "test foreign lease insert")
            .insert(remote_guid, participant);

        fsm.purge_zombie_confirmed_participants();
        assert!(
            recover_read(Arc::as_ref(&fsm.db), "test foreign lease survives")
                .contains_key(&remote_guid),
            "the HDDS startup-burst heuristic must not evict another vendor"
        );
        assert!(fsm.is_participant_matchable_and_recent(&remote_guid.as_bytes()[..12]));

        recover_write(Arc::as_ref(&fsm.db), "test foreign lease expire")
            .get_mut(&remote_guid)
            .expect("foreign participant remains registered")
            .last_seen = Instant::now() - std::time::Duration::from_secs(31);
        fsm.purge_zombie_confirmed_participants();
        assert!(
            !recover_read(Arc::as_ref(&fsm.db), "test foreign lease removed")
                .contains_key(&remote_guid),
            "a foreign participant must expire at its advertised lease"
        );
    }

    #[test]
    fn spdp_refresh_updates_the_advertised_lease() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 30_000);
        let remote_guid = sample_remote_guid(0x32);
        let mut spdp = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 10_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        assert!(!fsm.handle_spdp(spdp.clone()));

        spdp.lease_duration_ms = 600_000;
        assert!(fsm.handle_spdp(spdp));
        assert_eq!(
            recover_read(Arc::as_ref(&fsm.db), "test refreshed lease")
                .get(&remote_guid)
                .expect("participant remains registered")
                .lease_duration_ms,
            600_000
        );
    }

    /// A participant that announced its departure (its lease-0 farewell, its
    /// SPDP dispose) is heard as announced; one removed without a word is
    /// not: its writers may come back as themselves.
    #[test]
    fn a_departure_is_heard_as_announced_only_when_it_was() {
        struct Left(Mutex<Vec<(GUID, bool)>>);
        impl DiscoveryListener for Left {
            fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
                drop(endpoint);
            }
            fn on_participant_left(&self, participant: GUID, announced: bool) {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((participant, announced));
            }
        }
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let left = Arc::new(Left(Mutex::new(Vec::new())));
        fsm.register_listener(left.clone());
        let spdp = |guid: GUID, lease_duration_ms: u64| SpdpData {
            participant_guid: guid,
            lease_duration_ms,
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
        let (farewell, disposed, purged) = (
            sample_remote_guid(0x41),
            sample_remote_guid(0x51),
            sample_remote_guid(0x61),
        );
        for guid in [farewell, disposed, purged] {
            fsm.handle_spdp(spdp(guid, 100_000));
        }
        fsm.handle_spdp(spdp(farewell, 0));
        fsm.remove_departed_participant(disposed);
        fsm.remove_participant(purged);
        assert_eq!(
            left.0.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            vec![(farewell, true), (disposed, true), (purged, false)]
        );
    }

    #[test]
    fn test_remove_participant_notifies_removed_endpoints() {
        let local_guid = GUID::zero();
        let fsm = Arc::new(DiscoveryFsm::new(local_guid, 100_000));
        let listener = Arc::new(RemovalListener {
            removed: Mutex::new(Vec::new()),
            fsm: Arc::downgrade(&fsm),
        });
        fsm.register_listener(listener.clone());

        let remote_guid = sample_remote_guid(0x31);
        fsm.handle_spdp(SpdpData {
            participant_guid: remote_guid,
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

        let mut endpoint_guid_bytes = remote_guid.as_bytes();
        endpoint_guid_bytes[15] = 0x02;
        let endpoint_guid = GUID::from_bytes(endpoint_guid_bytes);
        fsm.handle_sedp(SedpData {
            topic_name: "removal/topic".to_string(),
            type_name: "RemovalType".to_string(),
            participant_guid: remote_guid,
            endpoint_guid,
            qos_hash: 1,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        assert_eq!(fsm.find_writers_for_topic("removal/topic").len(), 1);

        fsm.remove_participant(remote_guid);

        assert!(fsm.find_writers_for_topic("removal/topic").is_empty());
        assert_eq!(
            listener
                .removed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_slice(),
            &[endpoint_guid]
        );
    }

    fn endpoint_announcement(endpoint_guid: GUID, topic: &str) -> SedpData {
        SedpData {
            topic_name: topic.to_string(),
            type_name: "RemovalType".to_string(),
            participant_guid: GUID::zero(),
            endpoint_guid,
            qos_hash: 1,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// An endpoint whose announcement is still buffered (it raced ahead of
    /// its participant's SPDP) and which then announces its own deletion
    /// must not be rebuilt from that announcement when the participant
    /// shows up.
    #[test]
    fn a_removed_endpoint_is_not_rebuilt_from_its_buffered_announcement() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let participant = sample_remote_guid(0x41);
        let mut reader_bytes = participant.as_bytes();
        reader_bytes[15] = 0x04;
        let reader = GUID::from_bytes(reader_bytes);

        fsm.handle_sedp(endpoint_announcement(reader, "buffered/topic"));
        assert_eq!(
            recover_read(Arc::as_ref(&fsm.pending_sedp), "test pending").len(),
            1,
            "the announcement is buffered until its participant is known"
        );

        assert!(
            !fsm.remove_remote_endpoint(reader),
            "not in the topic registry yet"
        );
        fsm.handle_spdp(SpdpData {
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
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        assert_eq!(fsm.get_participants().len(), 1);
        assert!(
            fsm.find_readers_for_topic("buffered/topic").is_empty(),
            "the deleted reader is not replayed into discovery"
        );
    }

    /// Discovery knows the writers of each remote Publisher (RTPS v2.5
    /// Sec.8.7.5, Table 8.88: the writerSet is the writers "announced in the
    /// DiscoveredWriterData that belonged to the Publisher") and their
    /// GroupDigest; a writer of another group, a reader of the same group,
    /// and a removed writer are not in it.
    #[test]
    fn discovery_knows_the_writers_of_a_remote_publisher() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let participant = sample_remote_guid(0x61);
        fsm.handle_spdp(SpdpData {
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
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let prefix = participant.prefix;
        let endpoint = |entity_id: [u8; 4], group: [u8; 4], topic: &str| {
            let mut data = endpoint_announcement(GUID::new(prefix, entity_id), topic);
            data.group_entity_id = Some(group);
            data
        };
        let (g1, g2) = ([0, 0, 0x21, 0x08], [0, 0, 0x22, 0x08]);
        fsm.handle_sedp(endpoint([0, 0, 1, 0x02], g1, "group/a"));
        fsm.handle_sedp(endpoint([0, 0, 2, 0x02], g1, "group/b"));
        fsm.handle_sedp(endpoint([0, 0, 3, 0x02], g2, "group/a"));
        fsm.handle_sedp(endpoint([0, 0, 4, 0x07], g1, "group/a"));
        assert_eq!(
            fsm.publisher_roster(&prefix, g1),
            vec![[0, 0, 1, 0x02], [0, 0, 2, 0x02]]
        );
        assert_eq!(
            fsm.publisher_digest(&prefix, g1),
            crate::protocol::group::group_digest([[0, 0, 1, 0x02], [0, 0, 2, 0x02]])
        );
        assert_eq!(fsm.publisher_roster(&prefix, g2), vec![[0, 0, 3, 0x02]]);
        assert!(fsm.remove_remote_endpoint(GUID::new(prefix, [0, 0, 2, 0x02])));
        assert_eq!(fsm.publisher_roster(&prefix, g1), vec![[0, 0, 1, 0x02]]);
        assert_eq!(
            fsm.publisher_roster(&[0x77; 12], g1),
            Vec::<[u8; 4]>::new(),
            "another participant's group of the same id"
        );
    }

    /// A peer cannot retire one of OUR endpoints: a removal naming the local
    /// prefix is refused.
    #[test]
    fn a_remote_endpoint_removal_never_touches_a_local_endpoint() {
        let local = sample_remote_guid(0x50);
        let fsm = DiscoveryFsm::new(local, 100_000);
        let mut writer_bytes = local.as_bytes();
        writer_bytes[15] = 0x02;
        let writer = GUID::from_bytes(writer_bytes);
        fsm.handle_sedp(endpoint_announcement(writer, "local/topic"));
        assert_eq!(fsm.find_writers_for_topic("local/topic").len(), 1);

        assert!(!fsm.remove_remote_endpoint(writer));
        assert_eq!(
            fsm.find_writers_for_topic("local/topic").len(),
            1,
            "the local writer stays in discovery"
        );
    }

    #[test]
    fn test_handle_sedp_ignores_unknown_participant() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let sedp_data = SedpData {
            topic_name: "sensor/temp".to_string(),
            type_name: "Temperature".to_string(),
            participant_guid: GUID::zero(), // Test data
            endpoint_guid: sample_remote_guid(6),
            qos_hash: 12345,
            qos: None, // Tests use default QoS values
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };

        fsm.handle_sedp(sedp_data);
        assert!(fsm.find_writers_for_topic("sensor/temp").is_empty());
    }

    #[test]
    fn test_handle_sedp_inserts_endpoint() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(7);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
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
        fsm.handle_spdp(spdp_data);

        let mut endpoint_guid_bytes = remote_guid.as_bytes();
        endpoint_guid_bytes[15] = 0x02; // writer
        let sedp_data = SedpData {
            topic_name: "sensor/temp".to_string(),
            type_name: "Temperature".to_string(),
            participant_guid: GUID::zero(), // Test data
            endpoint_guid: GUID::from_bytes(endpoint_guid_bytes),
            qos_hash: 123,
            qos: None, // Tests use default QoS values
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };

        fsm.handle_sedp(sedp_data);

        let writers = fsm.find_writers_for_topic("sensor/temp");
        assert_eq!(writers.len(), 1);
        assert_eq!(writers[0].type_name, "Temperature");
    }

    /// When a remote endpoint announces a type that is structurally incompatible
    /// with a local endpoint's type, `handle_sedp` must increment the
    /// `inconsistent_type_count` on every matching local MatchEntry.
    ///
    /// Scenario: local writer declares ShapeType (FINAL, 2 fields), remote
    /// reader announces ShapeTypeExtended (APPENDABLE -- different
    /// extensibility). The FINAL vs APPENDABLE mismatch in
    /// `compatible_extensibility` makes `is_assignable_to` return `false`,
    /// so `notify_inconsistent_type_for_topic` must fire.
    #[test]
    fn test_handle_sedp_fires_inconsistent_type_on_mismatch() {
        use crate::dds::match_notification::MatchNotificationRegistry;
        use crate::dds::qos::QoS;
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
            TypeIdentifier,
        };
        use std::sync::atomic::{AtomicU32, Ordering};

        // Local participant GUID prefix: all 0xAA bytes for the prefix, 0x00 suffix bytes.
        let mut local_guid_bytes = [0u8; 16];
        for b in local_guid_bytes.iter_mut().take(12) {
            *b = 0xAA;
        }
        let local_guid = GUID::from_bytes(local_guid_bytes);

        let fsm = Arc::new(DiscoveryFsm::new(local_guid, 100_000));

        // Build the match registry and wire it to the FSM.
        // local_guid_prefix is the first 12 bytes of local_guid.
        let local_prefix: [u8; 12] = {
            let b = local_guid.as_bytes();
            let mut p = [0u8; 12];
            p.copy_from_slice(&b[..12]);
            p
        };
        let match_reg = Arc::new(MatchNotificationRegistry::new(&fsm, local_prefix));
        fsm.set_match_registry(match_reg.clone());

        // Register a local writer in the MatchNotificationRegistry.
        static SIMPLE_DESC: crate::core::types::TypeDescriptor =
            crate::core::types::TypeDescriptor {
                type_id: 0,
                type_name: "ShapeType",
                size_bytes: 8,
                alignment: 4,
                is_variable_size: false,
                fields: &[],
            };

        // Build a FINAL ShapeType CompleteTypeObject (x:int32, y:int32).
        let shape_type_final = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("ShapeType"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("x"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("y"),
                },
            ],
        });

        let incompat_count = Arc::new(AtomicU32::new(0));
        let incompat_count_clone = Arc::clone(&incompat_count);
        let token = match_reg.register_writer_full(
            "Square".into(),
            QoS::best_effort(),
            &SIMPLE_DESC,
            // The type this writer declares, as its SEDP announces it below: the
            // verdict reads a local endpoint's type from its registration.
            Some(shape_type_final.clone()),
            |_, _, _, _, _| {},
            None,
            Some(Box::new(move |_total, _change| {
                incompat_count_clone.fetch_add(1, Ordering::SeqCst);
            })),
            crate::transport::shm::ShmPolicy::default(),
            None,
        );
        let entry_id = token.id();

        // Register the local writer endpoint in the FSM's TopicRegistry via handle_sedp.
        // The endpoint GUID prefix must match local_guid so it is treated as a local endpoint
        // and bypasses the participant DB check.
        let mut local_writer_guid_bytes = local_guid_bytes;
        local_writer_guid_bytes[15] = 0x02; // writer entity kind
        let local_writer_guid = GUID::from_bytes(local_writer_guid_bytes);
        let local_writer_sedp = SedpData {
            topic_name: "Square".into(),
            type_name: "ShapeType".into(),
            participant_guid: local_guid,
            endpoint_guid: local_writer_guid,
            qos_hash: 1,
            qos: None,
            type_object: Some(shape_type_final),
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };
        fsm.handle_sedp(local_writer_sedp);

        // Build an APPENDABLE ShapeTypeExtended (x, y, color) -- different extensibility.
        let shape_type_extended = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("ShapeTypeExtended"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("x"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("y"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 2,
                        member_flags: MemberFlag::IS_OPTIONAL,
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("color"),
                },
            ],
        });

        // Register the remote participant in the FSM's participant DB.
        let mut remote_guid_bytes = [0xBBu8; 16];
        remote_guid_bytes[15] = 0x01; // participant entity kind
        let remote_guid = GUID::from_bytes(remote_guid_bytes);
        let remote_spdp = SpdpData {
            participant_guid: remote_guid,
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
        fsm.handle_spdp(remote_spdp);

        // Feed a remote reader SEDP with the incompatible APPENDABLE type.
        let mut remote_reader_guid_bytes = [0xBBu8; 16];
        remote_reader_guid_bytes[15] = 0x04; // reader entity kind
        let remote_reader_guid = GUID::from_bytes(remote_reader_guid_bytes);
        let remote_reader_sedp = SedpData {
            topic_name: "Square".into(),
            type_name: "ShapeTypeExtended".into(),
            participant_guid: remote_guid,
            endpoint_guid: remote_reader_guid,
            qos_hash: 2,
            qos: None,
            type_object: Some(shape_type_extended),
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };
        fsm.handle_sedp(remote_reader_sedp);

        // The inconsistent-type callback should have fired at least once.
        assert!(
            incompat_count.load(Ordering::SeqCst) >= 1,
            "inconsistent_topic callback must fire when remote type is structurally incompatible"
        );

        // get_inconsistent_topic_status must report a non-zero count.
        let status = match_reg
            .get_inconsistent_topic_status(entry_id)
            .expect("entry must exist");
        assert!(
            status.total_count >= 1,
            "inconsistent_type_count must be >= 1, got {}",
            status.total_count
        );

        // Dedup: feeding the same remote reader again must not increment the counter.
        let same_remote_sedp = SedpData {
            topic_name: "Square".into(),
            type_name: "ShapeTypeExtended".into(),
            participant_guid: remote_guid,
            endpoint_guid: remote_reader_guid,
            qos_hash: 2,
            qos: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            type_object: Some(CompleteTypeObject::Struct(CompleteStructType {
                struct_flags: StructTypeFlag::IS_APPENDABLE,
                header: CompleteStructHeader {
                    base_type: None,
                    detail: CompleteTypeDetail::new("ShapeTypeExtended"),
                },
                member_seq: vec![],
            })),
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };
        let count_before = incompat_count.load(Ordering::SeqCst);
        fsm.handle_sedp(same_remote_sedp);
        assert_eq!(
            incompat_count.load(Ordering::SeqCst),
            count_before,
            "second SEDP from same remote GUID must not re-fire the callback"
        );

        drop(token); // keep token alive until here to prevent unregistration
    }

    #[test]
    fn test_metrics_snapshot() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(8);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
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
        fsm.handle_spdp(spdp_data.clone());
        fsm.handle_spdp(spdp_data);

        let (spdp_rx, sedp_rx, discovered, expired, errors) = fsm.metrics.snapshot();
        let tracking_refused = fsm.metrics.sedp_tracking_refused();
        assert_eq!(spdp_rx, 2);
        assert_eq!(sedp_rx, 0);
        assert_eq!(discovered, 1);
        assert_eq!(expired, 0);
        assert_eq!(errors, 0);
        assert_eq!(tracking_refused, 0);
    }

    /// A refused tracking identity is a fact an operator needs, so it is
    /// published in the metrics snapshot, not only counted in a field no
    /// reader exposes.
    #[test]
    fn a_refused_tracking_identity_is_published_in_the_metrics_snapshot() {
        use super::SedpChannel::Plain;
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let remote = sample_remote_guid(9);
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
        let endpoint = |n: usize| {
            let n = u32::try_from(n)
                .expect("small endpoint index")
                .to_be_bytes();
            GUID::new(remote.prefix, [n[1], n[2], n[3], 2])
        };
        let cap = super::SEDP_CHANGE_ORDER_CAP_PER_PREFIX;
        for n in 0..cap {
            assert!(fsm.admits_sedp_change(Plain, &endpoint(n), 1));
        }
        assert!(!fsm.admits_sedp_change(Plain, &endpoint(cap), 1));
        assert_eq!(
            fsm.metrics.sedp_tracking_refused(),
            1,
            "the refusal is in the published snapshot"
        );
    }

    /// An endpoint whose participant is removed while its announcement is
    /// being handled is not inserted after the removal: the removal takes the
    /// participant's endpoints out of the topic registry, so an endpoint
    /// inserted after it would stay there for good, orphaned (no participant,
    /// no lease to expire it), matched by every local endpoint of its topic,
    /// and its reader locator would stay in the endpoint registry.
    #[test]
    fn an_endpoint_of_a_participant_removed_meanwhile_is_not_inserted_after_it() {
        use crate::dds::match_notification::MatchNotificationRegistry;
        use crate::dds::qos::QoS;
        use std::sync::atomic::{AtomicI64, Ordering};

        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0,
            type_name: "OrphanType",
            size_bytes: 4,
            alignment: 4,
            is_variable_size: false,
            fields: &[],
        };
        let local_prefix = [0xA3; 12];
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new(
                local_prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ),
            100_000,
        ));
        let match_reg = Arc::new(MatchNotificationRegistry::new(&fsm, local_prefix));
        fsm.set_match_registry(match_reg.clone());
        fsm.register_listener(match_reg.clone());
        let matched = Arc::new(AtomicI64::new(0));
        let seen = Arc::clone(&matched);
        let _token = match_reg.register_writer_full(
            "Orphan".into(),
            QoS::best_effort(),
            &DESC,
            None,
            move |_, _, current, _, _| {
                seen.store(i64::from(current), Ordering::SeqCst);
            },
            None,
            None,
            crate::transport::shm::ShmPolicy::default(),
            None,
        );

        let peer_prefix = [0xB4; 12];
        let peer = GUID::new(
            peer_prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let locator: std::net::SocketAddr = "192.0.2.44:7411".parse().expect("addr");
        fsm.handle_spdp(SpdpData {
            participant_guid: peer,
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
        let reader_guid = GUID::new(peer_prefix, [0x00, 0x00, 0x01, 0x07]);
        let remover = Arc::downgrade(&fsm);
        fsm.set_sedp_admitted_hook(Box::new(move || {
            if let Some(fsm) = remover.upgrade() {
                fsm.remove_participant(peer);
            }
        }));
        fsm.handle_sedp(SedpData {
            topic_name: "Orphan".into(),
            type_name: "OrphanType".into(),
            participant_guid: peer,
            endpoint_guid: reader_guid,
            qos_hash: 2,
            qos: Some(QoS::best_effort()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![locator],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        assert!(!fsm.has_participant(&peer), "fixture: removed meanwhile");
        assert!(
            fsm.find_readers_for_topic("Orphan").is_empty(),
            "the endpoint was inserted after its participant was removed"
        );
        assert_eq!(
            fsm.endpoint_registry().get_reader_locator(&reader_guid),
            None,
            "the endpoint's locator outlived its participant"
        );
        assert_eq!(
            matched.load(Ordering::SeqCst),
            0,
            "a local writer matched an endpoint of a removed participant"
        );
    }

    /// A local writer created inside our probation, on a topic where a
    /// remote reader of an incompatible type is already known, hears the
    /// mismatch (DDS-XTypes v1.3 Sec.7.6.3.4.3, INCONSISTENT_TOPIC). Its
    /// catch-up must not hold the notification for the end of the probation
    /// with nothing to replay it: the writer would never be told, while the
    /// same mismatch announced the other way round (the reader's SEDP after the
    /// writer) is reported at once.
    #[test]
    fn a_writer_created_in_probation_hears_a_known_readers_type_mismatch() {
        use crate::dds::match_notification::MatchNotificationRegistry;
        use crate::dds::qos::QoS;
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
            TypeIdentifier,
        };
        use std::sync::atomic::{AtomicU32, Ordering};

        fn shape(flags: StructTypeFlag) -> CompleteTypeObject {
            CompleteTypeObject::Struct(CompleteStructType {
                struct_flags: flags,
                header: CompleteStructHeader {
                    base_type: None,
                    detail: CompleteTypeDetail::new("ShapeType"),
                },
                member_seq: vec![CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("x"),
                }],
            })
        }
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0,
            type_name: "ShapeType",
            size_bytes: 4,
            alignment: 4,
            is_variable_size: false,
            fields: &[],
        };

        let local_prefix = [0xA5; 12];
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new(
                local_prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ),
            100_000,
        ));
        let match_reg = Arc::new(MatchNotificationRegistry::new(&fsm, local_prefix));
        fsm.set_match_registry(match_reg.clone());
        fsm.register_listener(match_reg.clone());

        let peer_prefix = [0xB6; 12];
        let peer = GUID::new(
            peer_prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let spdp = || SpdpData {
            participant_guid: peer,
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
        fsm.handle_sedp(SedpData {
            topic_name: "Square".into(),
            type_name: "ShapeType".into(),
            participant_guid: peer,
            endpoint_guid: GUID::new(peer_prefix, [0x00, 0x00, 0x01, 0x07]),
            qos_hash: 2,
            qos: None,
            type_object: Some(shape(StructTypeFlag::IS_APPENDABLE)),
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        assert!(!fsm.is_probation_done(), "fixture: inside our probation");

        let inconsistent = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&inconsistent);
        let _token = match_reg.register_writer_full(
            "Square".into(),
            QoS::best_effort(),
            &DESC,
            Some(shape(StructTypeFlag::IS_FINAL)),
            |_, _, _, _, _| {},
            None,
            Some(Box::new(move |_total, _change| {
                counter.fetch_add(1, Ordering::SeqCst);
            })),
            crate::transport::shm::ShmPolicy::default(),
            None,
        );
        // The peer goes on announcing itself, so the probation keeps it (a
        // peer purged and announced again would be handled afresh, its SEDP
        // replayed, and the mismatch reported then).
        std::thread::sleep(std::time::Duration::from_millis(150));
        fsm.handle_spdp(spdp());
        assert!(
            !fsm.is_probation_done(),
            "fixture: still inside our probation"
        );
        std::thread::sleep(std::time::Duration::from_millis(150));
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done(), "fixture: the probation is over");
        assert!(fsm.has_participant(&peer), "fixture: the peer survived it");
        fsm.handle_spdp(spdp());
        assert_eq!(
            inconsistent.load(Ordering::SeqCst),
            1,
            "the writer was never told of the known reader's incompatible type"
        );
    }

    /// A type mismatch announced by a participant that is removed while its
    /// announcement is being handled reaches nobody - not at that instant,
    /// and not for a participant that later comes back under its prefix.
    ///
    /// `handle_sedp` buffers the SEDP of a participant it does not know, so
    /// the participant is known when its announcement is admitted; it can
    /// only be unknown again at the type check if it was removed in between
    /// (here: by the test hook, as a departure or a purge on another thread
    /// would). The notification was then deferred for "a participant not
    /// known yet", and replayed for whatever announced under the prefix
    /// next: the successor was reported inconsistent with a type it never
    /// announced, under the GUID of an endpoint it never had.
    #[test]
    fn a_type_mismatch_of_a_participant_removed_meanwhile_is_not_replayed_for_its_successor() {
        use crate::dds::match_notification::MatchNotificationRegistry;
        use crate::dds::qos::QoS;
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
            TypeIdentifier,
        };
        use std::sync::atomic::{AtomicU32, Ordering};

        // FINAL here, APPENDABLE there: never assignable
        // (`compatible_extensibility`).
        fn shape(flags: StructTypeFlag) -> CompleteTypeObject {
            CompleteTypeObject::Struct(CompleteStructType {
                struct_flags: flags,
                header: CompleteStructHeader {
                    base_type: None,
                    detail: CompleteTypeDetail::new("ShapeType"),
                },
                member_seq: vec![CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("x"),
                }],
            })
        }
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0,
            type_name: "ShapeType",
            size_bytes: 4,
            alignment: 4,
            is_variable_size: false,
            fields: &[],
        };

        let local_prefix = [0xA1; 12];
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new(
                local_prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ),
            100_000,
        ));
        let match_reg = Arc::new(MatchNotificationRegistry::new(&fsm, local_prefix));
        fsm.set_match_registry(match_reg.clone());
        let inconsistent = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&inconsistent);
        let _token = match_reg.register_writer_full(
            "Square".into(),
            QoS::best_effort(),
            &DESC,
            Some(shape(StructTypeFlag::IS_FINAL)),
            |_, _, _, _, _| {},
            None,
            Some(Box::new(move |_total, _change| {
                counter.fetch_add(1, Ordering::SeqCst);
            })),
            crate::transport::shm::ShmPolicy::default(),
            None,
        );

        let peer_prefix = [0xB2; 12];
        let peer = GUID::new(
            peer_prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let spdp = || SpdpData {
            participant_guid: peer,
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
        let reader = |entity: u8| SedpData {
            topic_name: "Square".into(),
            type_name: "ShapeType".into(),
            participant_guid: peer,
            endpoint_guid: GUID::new(peer_prefix, [0x00, 0x00, entity, 0x07]),
            qos_hash: 2,
            qos: None,
            type_object: Some(shape(StructTypeFlag::IS_APPENDABLE)),
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };

        // The control: a mismatch announced by a participant that stays is
        // reported, once.
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(reader(0x01));
        assert_eq!(
            inconsistent.load(Ordering::SeqCst),
            1,
            "fixture: the mismatch is reported"
        );
        assert!(
            !fsm.is_probation_done(),
            "fixture: the race is the probation's (a deferral needs it open)"
        );

        // The participant is removed while its next announcement is handled.
        let remover = Arc::downgrade(&fsm);
        fsm.set_sedp_admitted_hook(Box::new(move || {
            if let Some(fsm) = remover.upgrade() {
                fsm.remove_participant(peer);
            }
        }));
        fsm.handle_sedp(reader(0x02));
        assert!(!fsm.has_participant(&peer), "fixture: removed meanwhile");
        assert_eq!(
            inconsistent.load(Ordering::SeqCst),
            1,
            "a mismatch was reported for a participant removed while it was handled"
        );

        // A new process under the same prefix announces itself twice (the
        // second announcement is the refresh that replayed the deferral).
        fsm.handle_spdp(spdp());
        fsm.handle_spdp(spdp());
        assert_eq!(
            inconsistent.load(Ordering::SeqCst),
            1,
            "the successor was reported inconsistent with a type it never announced"
        );
    }

    /// XTypes v1.3 sec. 7.6.3.4: when the local Reader's QoS carries
    /// DISALLOW_TYPE_COERCION (kind=0), even structurally assignable types
    /// (writer has an extra optional field, which ALLOW_TYPE_COERCION permits)
    /// must be treated as incompatible and trigger
    /// `notify_inconsistent_type_for_topic`.
    ///
    /// This test validates the tc_prevent_type_widening_7 requirement: the
    /// handle_sedp Writer branch must pass the local endpoint's effective
    /// TypeConsistencyEnforcement policy to `is_type_compatible_with_policy`,
    /// not use the policy-free `is_type_compatible`.
    #[test]
    fn test_handle_sedp_disallow_policy_triggers_incompat_on_local_reader() {
        use crate::dds::match_notification::MatchNotificationRegistry;
        use crate::dds::qos::QoS;
        use crate::protocol::discovery::types::TypeConsistencyEnforcement;
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
            TypeIdentifier,
        };
        use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        // Local participant: prefix 0xCC.
        let mut local_guid_bytes = [0u8; 16];
        for b in local_guid_bytes.iter_mut().take(12) {
            *b = 0xCC;
        }
        let local_guid = GUID::from_bytes(local_guid_bytes);

        let fsm = Arc::new(DiscoveryFsm::new(local_guid, 100_000));
        let local_prefix: [u8; 12] = {
            let b = local_guid.as_bytes();
            let mut p = [0u8; 12];
            p.copy_from_slice(&b[..12]);
            p
        };
        let match_reg = Arc::new(MatchNotificationRegistry::new(&fsm, local_prefix));
        fsm.set_match_registry(match_reg.clone());

        // Local reader's type: APPENDABLE ShapeType with 2 members.
        let shape_type_2f = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("ShapeType"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("x"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("y"),
                },
            ],
        });

        // QoS with DISALLOW_TYPE_COERCION: requires exact structural equivalence
        // (hash match), no extensibility relaxation allowed.
        let disallow_qos = QoS {
            type_consistency: Some(TypeConsistencyEnforcement {
                kind: 0, // DISALLOW_TYPE_COERCION
                ignore_sequence_bounds: false,
                ignore_string_bounds: false,
                ignore_member_names: false,
                prevent_type_widening: false,
                force_type_validation: false,
            }),
            ..QoS::best_effort()
        };

        static READER_DESC: crate::core::types::TypeDescriptor =
            crate::core::types::TypeDescriptor {
                type_id: 0,
                type_name: "ShapeType",
                size_bytes: 8,
                alignment: 4,
                is_variable_size: false,
                fields: &[],
            };

        let incompat_count = Arc::new(AtomicU32::new(0));
        let incompat_count_clone = Arc::clone(&incompat_count);
        let lifespan = Arc::new(AtomicU64::new(u64::MAX));
        let _reader_token = match_reg.register_reader_with_lifespan(
            "Square".into(),
            disallow_qos.clone(),
            &READER_DESC,
            Some(shape_type_2f.clone()),
            |_, _, _, _, _| {},
            None,
            None,
            Some(Box::new(move |_total, _change| {
                incompat_count_clone.fetch_add(1, Ordering::SeqCst);
            })),
            lifespan,
            crate::transport::shm::ShmPolicy::default(),
        );

        // Register the local reader endpoint in the FSM's TopicRegistry via handle_sedp.
        // GUID prefix must match local_guid so it is treated as a local endpoint.
        let mut local_reader_guid_bytes = local_guid_bytes;
        local_reader_guid_bytes[15] = 0x04; // reader entity kind
        let local_reader_guid = GUID::from_bytes(local_reader_guid_bytes);
        let local_reader_sedp = SedpData {
            topic_name: "Square".into(),
            type_name: "ShapeType".into(),
            participant_guid: local_guid,
            endpoint_guid: local_reader_guid,
            qos_hash: 1,
            qos: Some(disallow_qos),
            type_object: Some(shape_type_2f),
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };
        fsm.handle_sedp(local_reader_sedp);

        // Remote writer's type: APPENDABLE ShapeTypeExtended with an extra optional field.
        // Under ALLOW_TYPE_COERCION, APPENDABLE + extra optional field is assignable.
        // Under DISALLOW_TYPE_COERCION, hashes differ -> incompatible.
        let shape_type_3f = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("ShapeTypeExtended"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("x"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("y"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 2,
                        member_flags: MemberFlag::IS_OPTIONAL,
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("color"),
                },
            ],
        });

        // Register the remote participant.
        let mut remote_guid_bytes = [0xDDu8; 16];
        remote_guid_bytes[15] = 0x01;
        let remote_guid = GUID::from_bytes(remote_guid_bytes);
        let remote_spdp = SpdpData {
            participant_guid: remote_guid,
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
        fsm.handle_spdp(remote_spdp);

        // Feed the remote writer SEDP. The local reader carries DISALLOW_TYPE_COERCION,
        // so even though the remote type is APPENDABLE-compatible under the default policy,
        // it must fail the hash-equality check and trigger the incompat notification.
        let mut remote_writer_guid_bytes = [0xDDu8; 16];
        remote_writer_guid_bytes[15] = 0x02; // writer entity kind
        let remote_writer_guid = GUID::from_bytes(remote_writer_guid_bytes);
        let remote_writer_sedp = SedpData {
            topic_name: "Square".into(),
            type_name: "ShapeTypeExtended".into(),
            participant_guid: remote_guid,
            endpoint_guid: remote_writer_guid,
            qos_hash: 2,
            qos: None,
            type_object: Some(shape_type_3f),
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };
        fsm.handle_sedp(remote_writer_sedp);

        assert!(
            incompat_count.load(Ordering::SeqCst) >= 1,
            "DISALLOW_TYPE_COERCION must fire inconsistent-type notification \
             when writer type hash differs from reader type hash"
        );
    }

    /// `EndpointInfo::from_sedp` builds `participant_guid` with a ZERO
    /// entity id (see that function's doc), but `EndpointRegistry` keys
    /// participant locators by the REAL `RTPS_ENTITYID_PARTICIPANT` GUID
    /// (registered from `handle_spdp`'s `data.participant_guid`). Looking
    /// the raw zero-entity GUID up can never hit, so a SEDP reader that
    /// announces NO unicast locator of its own would silently fall straight
    /// through to `.first()` on an EMPTY list and `replay_for` would never
    /// fire at all, not even with the wrong destination. This pins that
    /// resolution falls back to the participant's SPDP `default_unicast_
    /// locator` in that exact scenario (SEDP has no locator; SPDP does).
    #[test]
    fn replay_dest_falls_back_to_spdp_locator_when_sedp_has_none() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        // Remote participant discovered via SPDP with a real
        // default_unicast_locator -- registered by `handle_spdp` keyed by
        // THIS exact GUID (real RTPS_ENTITYID_PARTICIPANT entity id).
        let remote_prefix = [0x77u8; 12];
        let remote_participant_guid = GUID::new(
            remote_prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let spdp_locator: std::net::SocketAddr =
            "192.168.44.9:7411".parse().expect("valid socket addr");
        fsm.handle_spdp(SpdpData {
            participant_guid: remote_participant_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![spdp_locator],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });

        // A local TransientLocal writer's replay hook, so `replay_for` has
        // somewhere to fire and this test can observe WHERE it fired.
        let topic = "item4/replay_fallback";
        let type_name = "T";
        type CapturedReplays = Arc<Mutex<Vec<(std::net::SocketAddr, Option<[u8; 16]>)>>>;
        let captured: CapturedReplays = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = captured.clone();
        let _token = fsm.replay_registry().register(
            topic,
            type_name,
            Arc::new(move |dest, reader_guid| {
                captured_clone
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((dest, reader_guid));
            }),
        );

        // Remote reader SEDP with NO unicast locator of its own (the
        // scenario under test), TransientLocal so this SEDP takes
        // the history-replay branch at all.
        let mut reader_guid_bytes = [0u8; 16];
        reader_guid_bytes[..12].copy_from_slice(&remote_prefix);
        reader_guid_bytes[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x04]);
        let reader_guid = GUID::from_bytes(reader_guid_bytes);

        fsm.handle_sedp(SedpData {
            topic_name: topic.to_string(),
            type_name: type_name.to_string(),
            participant_guid: remote_participant_guid,
            endpoint_guid: reader_guid,
            qos_hash: 1,
            qos: Some(crate::dds::QoS {
                durability: Durability::TransientLocal,
                ..crate::dds::QoS::default()
            }),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });

        let hits = captured.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            hits.len(),
            1,
            "replay_for must fire exactly once, resolving the SPDP locator \
             (old bug: silently skipped replay entirely, see this test's doc)"
        );
        assert_eq!(
            hits[0].0, spdp_locator,
            "replay destination must fall back to the participant's SPDP \
             default_unicast_locator when SEDP announced no locator of its own"
        );
        assert_eq!(
            hits[0].1,
            Some(reader_guid.as_bytes()),
            "the late-joining reader's GUID must be forwarded to the replay callback"
        );
    }

    /// `handle_sedp` must not call `replay_registry.replay_for` (synchronous
    /// UDP sends for the writer's entire history) while still holding the
    /// `topic_registry` WRITE lock. Proven here by
    /// having the replay callback itself attempt a `try_write` on that
    /// SAME lock: `std::sync::RwLock` excludes a write attempt against an
    /// already-held write lock even from the SAME thread (no re-entrancy),
    /// so `try_write` fails immediately if -- and only if -- `handle_sedp`
    /// is still inside its write-lock block when the callback runs.
    /// `try_write` never blocks, so this test cannot hang even if the lock
    /// were held across the replay.
    #[test]
    fn replay_fires_after_topic_registry_lock_is_released() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_prefix = [0x91u8; 12];
        let remote_participant_guid = GUID::new(
            remote_prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let spdp_locator: std::net::SocketAddr =
            "192.168.55.10:7411".parse().expect("valid socket addr");
        fsm.handle_spdp(SpdpData {
            participant_guid: remote_participant_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![spdp_locator],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });

        let topic = "item6/replay_lock_scope";
        let type_name = "T";
        // Same `Arc<RwLock<TopicRegistry>>` `handle_sedp` locks internally
        // -- accessible here because `mod tests` is a child module of
        // `discovery.rs` and can see the private field.
        let topic_registry_handle = fsm.topic_registry.clone();
        let lock_was_free = Arc::new(AtomicBool::new(false));
        let lock_was_free_clone = lock_was_free.clone();
        let callback_ran = Arc::new(AtomicBool::new(false));
        let callback_ran_clone = callback_ran.clone();
        let _token = fsm.replay_registry().register(
            topic,
            type_name,
            Arc::new(move |_dest, _reader_guid| {
                callback_ran_clone.store(true, Ordering::SeqCst);
                if topic_registry_handle.try_write().is_ok() {
                    lock_was_free_clone.store(true, Ordering::SeqCst);
                }
            }),
        );

        let mut reader_guid_bytes = [0u8; 16];
        reader_guid_bytes[..12].copy_from_slice(&remote_prefix);
        reader_guid_bytes[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x04]);
        let reader_guid = GUID::from_bytes(reader_guid_bytes);

        fsm.handle_sedp(SedpData {
            topic_name: topic.to_string(),
            type_name: type_name.to_string(),
            participant_guid: remote_participant_guid,
            endpoint_guid: reader_guid,
            qos_hash: 1,
            qos: Some(crate::dds::QoS {
                durability: Durability::TransientLocal,
                ..crate::dds::QoS::default()
            }),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });

        assert!(
            callback_ran.load(Ordering::SeqCst),
            "the replay callback must have fired at all"
        );
        assert!(
            lock_was_free.load(Ordering::SeqCst),
            "replay_for must fire AFTER the topic_registry write lock is \
             released (item 6): try_write from inside the replay callback \
             failed, meaning the lock was still held"
        );
    }

    // ---- Locator selection -------------------------------------
    //
    // The receiver picks which announced address it will send to. The LAN
    // cases below characterise the long-standing behaviour, which must not
    // move, since it carries cross-vendor interop.

    fn sa(addr: &str) -> std::net::SocketAddr {
        addr.parse().expect("test locator")
    }

    fn v4(addr: &str) -> std::net::Ipv4Addr {
        addr.parse().expect("test address")
    }

    /// A peer on our own LAN is chosen.
    #[test]
    fn locator_on_our_own_lan_is_chosen() {
        let ours = [(v4("192.168.1.10"), 24)];
        let announced = [sa("192.168.1.50:7410")];
        assert_eq!(
            select_best_locator_among(&announced, &ours),
            Some(&sa("192.168.1.50:7410"))
        );
    }

    /// Characterisation: the Docker default bridge is never preferred.
    ///
    /// Every host runs 172.17.0.0/16 and no two hosts share it, so an
    /// announced 172.17 address names the announcer's own container bridge.
    #[test]
    fn docker_bridge_loses_to_a_real_address() {
        let ours = [(v4("10.0.0.5"), 8)];
        let announced = [sa("172.17.0.2:7410"), sa("10.0.0.9:7410")];
        assert_eq!(
            select_best_locator_among(&announced, &ours),
            Some(&sa("10.0.0.9:7410"))
        );
    }

    /// A foreign private address must lose to a routable one.
    ///
    /// Two participants behind different NATs, meeting through a Discovery
    /// Server reachable over the WAN - a configuration this product documents.
    /// The peer announces its own private address and a routable one. If the
    /// private address won, we would send our data to whatever machine
    /// answers at that address on OUR LAN: a stranger, not the peer.
    ///
    /// Note the addresses: `203.0.113.0/24` and `198.51.100.0/24` are
    /// DOCUMENTATION ranges and are deliberately NOT treated as routable, so
    /// the public address here is an ordinary one.
    #[test]
    fn a_foreign_private_address_never_beats_a_routable_one() {
        let ours = [(v4("192.0.2.3"), 24)];
        let announced = [sa("192.168.1.50:7410"), sa("93.184.216.34:7410")];
        assert_eq!(
            select_best_locator_among(&announced, &ours),
            Some(&sa("93.184.216.34:7410")),
            "a private address outside our subnets names someone else's machine"
        );
    }

    /// The question the relay asks of every peer, and the one the selector
    /// cannot answer: `select_best_locator` ALWAYS returns something, because
    /// its passes 3 and 4 exist so a LAN keeps working. "It returned an
    /// address" therefore says nothing about whether a datagram can arrive.
    #[test]
    fn a_direct_route_is_exactly_our_own_subnet_or_the_open_internet() {
        let ours = [(v4("192.168.1.0"), 24)];

        assert!(
            direct_route_among(&[sa("192.168.1.50:7410")], &ours).is_some(),
            "our own LAN"
        );
        assert!(
            direct_route_among(&[sa("93.184.216.34:7410")], &ours).is_some(),
            "an ordinary public address"
        );
        assert!(
            direct_route_among(&[sa("203.0.113.7:7410")], &ours).is_none(),
            "a documentation range is not routable, and this predicate must agree \
             with `is_globally_routable` rather than keep its own opinion"
        );

        // Someone else's LAN, a carrier-grade NAT address, the Docker bridge
        // every host shares, and the relay's own reserved range. Not one of
        // them can carry a datagram to the peer that announced it, so this is
        // exactly the peer a relay exists for.
        let unreachable = [
            sa("10.4.4.4:7410"),
            sa("100.70.0.1:7410"),
            sa("172.17.0.2:7410"),
            sa("240.0.0.7:7410"),
        ];
        assert!(
            direct_route_among(&unreachable, &ours).is_none(),
            "no announced address is reachable from here"
        );
        assert!(
            select_best_locator_among(&unreachable, &ours).is_some(),
            "the selector still answers for this peer, which is why the relay decision is \
             taken on the predicate and not on the selector's result"
        );
    }

    /// A Docker-bridge address is not treated as being on our subnet.
    ///
    /// Running inside Docker on the default bridge, a peer that announces
    /// 172.17.0.2 is numerically "in our subnet" - but every Docker host has
    /// that range, so the address names a container on the peer's host, or one
    /// of ours. The preferred pass excludes it, or containerised interop
    /// setups would select the wrong address.
    #[test]
    fn the_docker_default_bridge_is_not_our_subnet_even_when_we_are_on_it() {
        let ours = [(v4("172.17.0.5"), 16), (v4("10.7.0.5"), 24)];
        let announced = [sa("172.17.0.2:7410"), sa("10.7.0.9:7410")];
        assert_eq!(
            select_best_locator_among(&announced, &ours),
            Some(&sa("10.7.0.9:7410")),
            "sharing 172.17/16 with a peer proves nothing: every Docker host has it"
        );
    }

    /// A non-default Docker network (a user-defined bridge, e.g. 172.18/16) is
    /// a real shared subnet and stays selectable - only 172.17 is special.
    #[test]
    fn a_user_defined_docker_network_is_still_a_real_subnet() {
        let ours = [(v4("172.18.0.5"), 16)];
        let announced = [sa("172.18.0.9:7410")];
        assert_eq!(
            select_best_locator_among(&announced, &ours),
            Some(&sa("172.18.0.9:7410"))
        );
    }

    /// A relay or NAT mapping is a routable address, and it must win over the
    /// peer's private addresses when we share no subnet with it.
    #[test]
    fn a_relay_address_is_selected_when_no_subnet_is_shared() {
        let ours = [(v4("172.20.5.4"), 24)];
        let announced = [
            sa("192.168.8.2:7410"),
            sa("10.1.2.3:7410"),
            sa("93.184.216.34:7410"),
        ];
        assert_eq!(
            select_best_locator_among(&announced, &ours),
            Some(&sa("93.184.216.34:7410"))
        );
    }

    /// No hairpinning: a peer on our LAN that also announces a public address
    /// is still reached directly.
    #[test]
    fn our_own_subnet_beats_a_routable_address() {
        let ours = [(v4("192.168.1.10"), 24)];
        let announced = [sa("93.184.216.34:7410"), sa("192.168.1.50:7410")];
        assert_eq!(
            select_best_locator_among(&announced, &ours),
            Some(&sa("192.168.1.50:7410")),
            "sending across the Internet to reach the machine next to us would \
             add a round trip, and fails outright on gateways without hairpin NAT"
        );
    }

    /// Characterisation: routed private networks keep working.
    ///
    /// 192.168.1.0/24 reaching 192.168.2.0/24 through a router is a real
    /// deployment. With nothing routable on offer, the foreign private address
    /// is still selected - pass 3 is the fallback.
    #[test]
    fn a_foreign_private_address_is_still_used_when_it_is_the_only_option() {
        let ours = [(v4("192.168.1.10"), 24)];
        let announced = [sa("192.168.2.50:7410")];
        assert_eq!(
            select_best_locator_among(&announced, &ours),
            Some(&sa("192.168.2.50:7410"))
        );
    }

    /// A carrier-grade NAT address is not routable: it answers for one of the
    /// carrier's other subscribers, not for our peer.
    #[test]
    fn carrier_grade_nat_is_not_treated_as_routable() {
        assert!(!is_globally_routable(v4("100.64.0.1")));
        assert!(!is_globally_routable(v4("100.127.255.254")));
        // 100.128.0.0 is outside 100.64/10 and is ordinary public space.
        assert!(is_globally_routable(v4("100.128.0.1")));
    }

    #[test]
    fn routable_classification_covers_the_reserved_ranges() {
        for addr in [
            "10.0.0.1",
            "192.168.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "192.0.2.1",
            "240.0.0.1",
        ] {
            assert!(
                !is_globally_routable(v4(addr)),
                "{addr} must not be routable"
            );
        }
        // Documentation ranges are NOT routable, which is why the selection
        // tests above use an ordinary public address instead.
        for addr in ["203.0.113.7", "198.51.100.9"] {
            assert!(
                !is_globally_routable(v4(addr)),
                "{addr} is a documentation range"
            );
        }
        for addr in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
            assert!(is_globally_routable(v4(addr)), "{addr} must be routable");
        }
    }

    #[test]
    fn subnet_membership_respects_the_prefix() {
        assert!(in_subnet(v4("192.168.1.50"), v4("192.168.1.10"), 24));
        assert!(!in_subnet(v4("192.168.2.50"), v4("192.168.1.10"), 24));
        assert!(in_subnet(v4("10.1.2.3"), v4("10.9.9.9"), 8));
        assert!(!in_subnet(v4("11.1.2.3"), v4("10.9.9.9"), 8));
        // A /32 is just the address itself.
        assert!(in_subnet(v4("10.0.0.1"), v4("10.0.0.1"), 32));
        assert!(!in_subnet(v4("10.0.0.2"), v4("10.0.0.1"), 32));
        // A /0 is a default route, not a membership claim.
        assert!(!in_subnet(v4("8.8.8.8"), v4("10.0.0.1"), 0));
    }

    /// An empty local view must not panic or invent a choice: it degrades to
    /// the ranking of the fallback passes.
    #[test]
    fn an_empty_local_view_degrades_to_the_previous_behaviour() {
        let announced = [sa("172.17.0.2:7410"), sa("192.168.5.5:7410")];
        assert_eq!(
            select_best_locator_among(&announced, &[]),
            Some(&sa("192.168.5.5:7410"))
        );
        assert_eq!(select_best_locator_among(&[], &[]), None);
    }

    /// The two announcements a participant can be created by: one that
    /// carries its address, and one that carries none.
    ///
    /// The address-less shape is not hypothetical. `parse_spdp` accepts any
    /// ParameterList carrying PID_PARTICIPANT_GUID (0x0050), and a SEDP
    /// announcement carries one - our own encoder emits it, as a cross-vendor
    /// interop requirement. A DATA whose writerEntityId no builtin endpoint
    /// claims reaches `handle_data_packet`, which tries the SPDP reader first
    /// and hands the result straight to this FSM, with none of the locator
    /// recovery the SPDP door performs.
    fn spdp_with_and_without_an_address(guid: GUID) -> (SpdpData, SpdpData) {
        let addressed = SpdpData {
            participant_guid: guid,
            lease_duration_ms: 30_000,
            domain_id: 39,
            metatraffic_unicast_locators: vec!["192.0.2.7:7410".parse().expect("addr")],
            default_unicast_locators: vec!["192.0.2.7:7411".parse().expect("addr")],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        let address_less = SpdpData {
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            ..addressed.clone()
        };
        (addressed, address_less)
    }

    /// A participant created without an address takes the one its own
    /// announcement carries.
    ///
    /// Before this rule, the insert branch was the ONLY writer of either
    /// store, so whoever created the entry owned its address for the entry's
    /// lifetime: measured `registry None -> None` and `endpoints 0 -> 0`
    /// across the peer's real announcement. A participant with no metatraffic
    /// locator is one we can see and never answer.
    #[test]
    fn a_participant_without_an_address_accepts_one_from_its_own_announcement() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let peer = sample_remote_guid(210);
        let (addressed, address_less) = spdp_with_and_without_an_address(peer);

        fsm.handle_spdp(address_less);
        assert_eq!(
            fsm.endpoint_registry().get(&peer),
            None,
            "an announcement carrying no locator registers none"
        );

        fsm.handle_spdp(addressed);

        assert_eq!(
            fsm.endpoint_registry().get(&peer),
            Some("192.0.2.7:7411".parse().expect("addr")),
            "the real announcement must be able to give the entry its address"
        );
        let endpoints = fsm
            .get_participants()
            .into_iter()
            .find(|p| p.guid == peer)
            .expect("the peer is known")
            .endpoints;
        assert_eq!(
            endpoints,
            vec!["192.0.2.7:7410"
                .parse::<std::net::SocketAddr>()
                .expect("addr")],
            "SEDP is addressed from this list, so the refresh must fill it too"
        );
    }

    /// A peer that announces no user-data locator is reached on its
    /// metatraffic one.
    ///
    /// RTPS v2.3 Sec.8.5.3.1 says user data goes to the default unicast
    /// locator, and this fallback exists for peers that announce none. It was
    /// carried along unpinned: deleting it turned no test red, and the peers
    /// it serves are exactly the ones a self-only test suite never sees.
    #[test]
    fn a_peer_announcing_only_a_metatraffic_locator_is_reached_on_it() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let peer = sample_remote_guid(213);
        let (addressed, _) = spdp_with_and_without_an_address(peer);
        let metatraffic_only = SpdpData {
            default_unicast_locators: vec![],
            ..addressed
        };

        fsm.handle_spdp(metatraffic_only);

        assert_eq!(
            fsm.endpoint_registry().get(&peer),
            Some("192.0.2.7:7410".parse().expect("addr")),
            "with no user-data locator announced, the metatraffic one is the address"
        );
    }

    /// A peer that announces a new address is followed to it.
    ///
    /// The rule is "take what the announcement carries", not "take it once":
    /// a participant may re-announce with different locators, and the entry
    /// that keeps the first one forever is the same deafness as the entry
    /// that never got one. A narrower rule ("fill only when empty") would
    /// pass both tests above.
    #[test]
    fn a_peer_that_announces_a_new_address_is_followed_to_it() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let peer = sample_remote_guid(212);
        let (addressed, _) = spdp_with_and_without_an_address(peer);
        let moved = SpdpData {
            metatraffic_unicast_locators: vec!["198.51.100.9:7410".parse().expect("addr")],
            default_unicast_locators: vec!["198.51.100.9:7411".parse().expect("addr")],
            ..addressed.clone()
        };

        fsm.handle_spdp(addressed);
        fsm.handle_spdp(moved);

        assert_eq!(
            fsm.endpoint_registry().get(&peer),
            Some("198.51.100.9:7411".parse().expect("addr")),
            "the send-side registry follows the peer"
        );
        let endpoints = fsm
            .get_participants()
            .into_iter()
            .find(|p| p.guid == peer)
            .expect("the peer is known")
            .endpoints;
        assert_eq!(
            endpoints,
            vec!["198.51.100.9:7410"
                .parse::<std::net::SocketAddr>()
                .expect("addr")],
            "and so does the list SEDP is addressed from"
        );
    }

    /// The other side of the same rule: only the EMPTY case is filled.
    ///
    /// A later announcement that carries nothing must not erase what an
    /// earlier one said. Pinned from both sides, because a rule written as
    /// "assign on refresh" passes the test above and silently deletes the
    /// address of every peer whose next announcement is the degenerate one.
    #[test]
    fn an_announcement_carrying_no_address_never_erases_one() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let peer = sample_remote_guid(211);
        let (addressed, address_less) = spdp_with_and_without_an_address(peer);

        fsm.handle_spdp(addressed);
        let registered = fsm.endpoint_registry().get(&peer);
        assert_eq!(
            registered,
            Some("192.0.2.7:7411".parse().expect("addr")),
            "the addressed announcement registers the user-data locator"
        );

        fsm.handle_spdp(address_less);

        assert_eq!(
            fsm.endpoint_registry().get(&peer),
            registered,
            "an announcement with no locator leaves the registered one alone"
        );
        let endpoints = fsm
            .get_participants()
            .into_iter()
            .find(|p| p.guid == peer)
            .expect("the peer is known")
            .endpoints;
        assert_eq!(
            endpoints,
            vec!["192.0.2.7:7410"
                .parse::<std::net::SocketAddr>()
                .expect("addr")],
            "nor the metatraffic list it filled"
        );
    }

    /// `metatraffic_locator_for`'s same-IP preference among a peer's SEVERAL
    /// recorded locators, for a direct origin.
    ///
    /// A peer with only one endpoint cannot tell "pick the one on the reply
    /// IP" from "fall back to the first one" -- both answer the same
    /// address. Two endpoints, on different IPs, with the reply IP matching
    /// the SECOND one, is what actually exercises the preference: the
    /// fallback alone would silently return the FIRST.
    #[test]
    fn metatraffic_locator_for_prefers_the_endpoint_on_the_reply_ip() {
        let fsm = DiscoveryFsm::new(sample_remote_guid(1), 30_000);
        let peer_prefix = [0x22u8; 12];
        let locator_a: std::net::SocketAddr = "192.0.2.10:7410".parse().expect("addr");
        let locator_b: std::net::SocketAddr = "192.0.2.20:7410".parse().expect("addr");
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(peer_prefix, [0x00, 0x00, 0x01, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![locator_a, locator_b],
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

        // The reply address's IP matches locator_b, not locator_a (the
        // first one recorded): only the same-IP preference can find it.
        let reply: std::net::SocketAddr = "192.0.2.20:54321".parse().expect("addr");
        let origin = crate::core::discovery::multicast::Origin::direct(reply);

        assert_eq!(
            fsm.metatraffic_locator_for(&peer_prefix, origin),
            Some(locator_b),
            "the endpoint on the reply IP must win over the first-recorded one"
        );
    }

    /// RTPS 2.5 8.3.4 / 8.3.8.10: relayed has no reply
    /// address to pair with an unusable locator, so `first_metatraffic_locator`
    /// -- used only for relayed origins -- must skip an unspecified-IP or
    /// port-0 locator (both accepted by the SPDP parser,
    /// `spdp/parse/locators.rs`) and fall back to a usable one instead of
    /// handing the caller a destination nothing can be sent to.
    #[test]
    fn first_metatraffic_locator_skips_an_unusable_locator() {
        let fsm = DiscoveryFsm::new(sample_remote_guid(2), 30_000);
        let peer_prefix = [0x23u8; 12];
        let unspecified_ip: std::net::SocketAddr = "0.0.0.0:7410".parse().expect("addr");
        let zero_port: std::net::SocketAddr = "192.0.2.30:0".parse().expect("addr");
        let usable: std::net::SocketAddr = "192.0.2.31:7410".parse().expect("addr");

        for (label, locators) in [
            ("unspecified IP first", vec![unspecified_ip, usable]),
            ("port 0 first", vec![zero_port, usable]),
        ] {
            let fsm = DiscoveryFsm::new(sample_remote_guid(2), 30_000);
            fsm.handle_spdp(SpdpData {
                participant_guid: GUID::new(peer_prefix, [0x00, 0x00, 0x01, 0xC1]),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: locators,
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
            assert_eq!(
                fsm.first_metatraffic_locator(&peer_prefix),
                Some(usable),
                "{label}: the unusable locator must be skipped"
            );
        }

        // A peer with NOTHING usable resolves to None, not to the
        // unusable locator: no caller may send to an address it recorded
        // as invalid.
        let none_usable_prefix = [0x24u8; 12];
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(none_usable_prefix, [0x00, 0x00, 0x01, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![unspecified_ip, zero_port],
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
        assert_eq!(
            fsm.first_metatraffic_locator(&none_usable_prefix),
            None,
            "no usable locator at all resolves to None, never an unusable one"
        );
    }

    /// The direct path is byte-for-byte unchanged: it never filters a
    /// locator for usability, because its own reply address (the
    /// datagram's) is always a real fallback -- unlike relayed, which has
    /// none.
    #[test]
    fn metatraffic_locator_for_direct_keeps_an_unusable_locator_unfiltered() {
        let fsm = DiscoveryFsm::new(sample_remote_guid(3), 30_000);
        let peer_prefix = [0x25u8; 12];
        let zero_port: std::net::SocketAddr = "192.0.2.40:0".parse().expect("addr");
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(peer_prefix, [0x00, 0x00, 0x01, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![zero_port],
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

        // A reply IP that matches nothing: falls back to the first
        // recorded endpoint, exactly as before, unusable or not.
        let reply: std::net::SocketAddr = "203.0.113.1:54321".parse().expect("addr");
        let origin = crate::core::discovery::multicast::Origin::direct(reply);
        assert_eq!(
            fsm.metatraffic_locator_for(&peer_prefix, origin),
            Some(zero_port),
            "direct must not filter locators for usability: that is unchanged behaviour"
        );
    }
}

/// The remote access-control gate in `notify_endpoint_discovered`.
///
/// DDS Security v1.1 9.4.3: once the handshake says WHO the peer is, its own
/// signed permissions document says what it may do, and an endpoint it is not
/// allowed to own must never reach the application.
///
/// These tests drive a REAL 3-message PKI-DH handshake so the state the gate
/// reads is produced the way the wire produces it, not inserted by hand: the
/// key convention under test is exactly the one the protocol writes.
#[cfg(all(test, feature = "security"))]
mod remote_access_gate_tests {
    use super::{DiscoveryFsm, DiscoveryListener, EndpointInfo};
    use crate::core::discovery::GUID;
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::protocol::discovery::SedpData;
    use crate::security::access::{RemoteAccessControl, RemoteAccessInputs};
    use crate::security::cms::PermissionsCa;
    use crate::security::handshake::HandshakeMachine;
    use crate::security::test_pki::{
        AUDIT_PERMISSIONS_SMIME, FIXTURE_NOW_UNIX, PERM_CA_EC_PEM, TEST_IDENTITY_CERT_PEM,
        TEST_IDENTITY_KEY_PEM,
    };
    use std::sync::{Arc, Mutex};

    /// The domain `audit_permissions.smime` writes its grant for.
    const DOMAIN: u32 = 229;
    /// Granted to the fixture subject for publish and subscribe.
    const GRANTED_TOPIC: &str = "sensor/temperature";
    /// Explicitly denied to the fixture subject.
    const DENIED_TOPIC: &str = "admin/shutdown";

    /// Records the topic of every endpoint that reaches the application.
    struct CapturingListener(Mutex<Vec<String>>);

    impl DiscoveryListener for CapturingListener {
        fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(endpoint.topic_name);
        }
    }

    /// The 12-byte prefix the remote peer announces.
    const PEER_PREFIX: [u8; 12] = crate::security::test_pki::bound_test_prefix([0xFF; 6]);
    /// The 12-byte prefix of the local participant running the FSM.
    const LOCAL_PREFIX: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x01; 6]);

    /// Run a full handshake and return the LOCAL machine, holding a `Complete`
    /// session for the peer (`test_pki::local_machine_with_completed_peer`).
    fn local_machine_with_completed_peer(
        peer_permissions: Option<Vec<u8>>,
    ) -> Arc<HandshakeMachine> {
        crate::security::test_pki::local_machine_with_completed_peer(
            LOCAL_PREFIX,
            PEER_PREFIX,
            peer_permissions,
        )
    }

    fn governance(join_access_control: bool) -> String {
        format!(
            r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>{}</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>{}</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#,
            DOMAIN, join_access_control
        )
    }

    /// A governance whose one topic rule, `*`, sets read and write access
    /// control to `topic_access_control`.
    fn governance_with_topic_access(
        join_access_control: bool,
        topic_access_control: bool,
    ) -> String {
        format!(
            r#"<dds><domain_access_rules><domain_rule>
  <domains>{}</domains>
  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
  <enable_join_access_control>{}</enable_join_access_control>
  <discovery_protection_kind>NONE</discovery_protection_kind>
  <liveliness_protection_kind>NONE</liveliness_protection_kind>
  <rtps_protection_kind>NONE</rtps_protection_kind>
  <topic_access_rules><topic_rule>
    <topic_expression>*</topic_expression>
    <enable_discovery_protection>false</enable_discovery_protection>
    <enable_liveliness_protection>false</enable_liveliness_protection>
    <enable_read_access_control>{}</enable_read_access_control>
    <enable_write_access_control>{}</enable_write_access_control>
    <metadata_protection_kind>NONE</metadata_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </topic_rule></topic_access_rules>
</domain_rule></domain_access_rules></dds>"#,
            DOMAIN, join_access_control, topic_access_control, topic_access_control
        )
    }

    fn access_control(join_access_control: bool) -> Arc<RemoteAccessControl> {
        access_control_from(governance(join_access_control))
    }

    fn access_control_from(governance_xml: String) -> Arc<RemoteAccessControl> {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("fixture permissions CA parses");
        Arc::new(
            RemoteAccessControl::new(
                RemoteAccessInputs {
                    governance_xml,
                    permissions_ca: Some(ca),
                    accept_unsigned_for_tests: false,
                    legacy_partition_matching: false,
                },
                DOMAIN,
            )
            .with_fixed_now(FIXTURE_NOW_UNIX),
        )
    }

    /// A writer endpoint on `topic`, owned by the peer, shaped by the same
    /// constructor the SEDP path uses -- which is what puts entity id
    /// `[0,0,0,0]` in `participant_guid`.
    fn peer_writer_endpoint(topic: &str) -> EndpointInfo {
        writer_endpoint_of(PEER_PREFIX, topic)
    }

    /// A writer endpoint on `topic` owned by the participant `prefix`.
    fn writer_endpoint_of(prefix: [u8; 12], topic: &str) -> EndpointInfo {
        let mut endpoint_bytes = [0u8; 16];
        endpoint_bytes[..12].copy_from_slice(&prefix);
        endpoint_bytes[15] = 0x02; // writer
        EndpointInfo::from_sedp(
            SedpData {
                topic_name: topic.to_string(),
                type_name: "Temperature".to_string(),
                participant_guid: GUID::new(prefix, [0, 0, 0, 0]),
                endpoint_guid: GUID::from_bytes(endpoint_bytes),
                qos_hash: 0,
                qos: None,
                type_object: None,
                dependents: Vec::new(),
                type_object_legacy_v1: false,
                unicast_locators: vec![],
                user_data: None,
                shm_capability: None,
                has_explicit_reliability: false,
                has_explicit_ownership: false,
                has_ownership_strength: false,
                type_information: None,
                type_consistency: None,
                group_entity_id: None,
                endpoint_security_info: None,
            },
            None,
        )
    }

    /// Wire an FSM with the handshake machine and (optionally) the evaluator,
    /// surface one endpoint, and return the topics that reached a listener.
    fn surfaced_topics(
        machine: Arc<HandshakeMachine>,
        control: Option<Arc<RemoteAccessControl>>,
        endpoint: &EndpointInfo,
    ) -> Vec<String> {
        let mut fsm =
            DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 100_000);
        fsm.set_handshake_machine(
            machine,
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.set_remote_access_control(control);
        let listener = Arc::new(CapturingListener(Mutex::new(Vec::new())));
        fsm.register_listener(listener.clone());
        fsm.notify_endpoint_discovered(endpoint);
        let seen = listener.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        seen
    }

    /// An endpoint the peer's own document grants must still reach the
    /// application. Without this, a gate that refused everything would pass
    /// every other test here.
    #[test]
    fn a_granted_topic_from_an_authenticated_peer_is_surfaced() {
        let machine = local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec()));
        let endpoint = peer_writer_endpoint(GRANTED_TOPIC);
        let seen = surfaced_topics(machine, Some(access_control(true)), &endpoint);
        assert_eq!(seen, vec![GRANTED_TOPIC.to_string()]);
    }

    /// DDS-Security v1.1 Sec.8.4.2.9 (check_remote_datawriter /
    /// check_remote_datareader "reflects the current permissions") and the
    /// local restriction overlay (`security::permissions::dynamic`): a
    /// reload that revokes a topic this participant may no longer publish
    /// refuses an ALREADY admitted remote reader too, not only a NEW
    /// `check_create_datawriter` at entity creation. No handshake machine,
    /// no signed access control at all is wired on this FSM -- the overlay
    /// alone decides, which is also what proves `admission_gate_active`
    /// turns on for it.
    ///
    /// `DynamicPermissionManager::reload` must bump its `generation`, which
    /// the second assertion pins: otherwise `admission_epoch` never moves, and
    /// the cached `Admitted` verdict from before the reload answers again
    /// instead of being judged anew.
    #[test]
    fn a_revoking_overlay_reload_unadmits_an_already_admitted_remote_reader() {
        use crate::security::permissions::dynamic::ReloadResult;
        use crate::security::test_pki::TEST_CA_CERT_PEM;
        use crate::security::{SecurityConfig, SecurityPluginSuite};
        use std::io::Write as _;

        let write_temp = |contents: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().expect("temp file");
            f.write_all(contents).expect("write");
            f.flush().expect("flush");
            f
        };
        let cert = write_temp(TEST_IDENTITY_CERT_PEM);
        let key = write_temp(TEST_IDENTITY_KEY_PEM);
        let ca = write_temp(TEST_CA_CERT_PEM);
        // Named, but no rule refuses anything (`default: allow`).
        let overlay_file =
            write_temp(b"[subject: CN=DDS Test Identity, O=HDDS Test]\ndefault: allow\n");

        let config = SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .permissions_overlay(overlay_file.path())
            .build()
            .expect("config");
        let suite = Arc::new(SecurityPluginSuite::new(config, DOMAIN).expect("suite"));

        let mut fsm =
            DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 100_000);
        fsm.set_local_restriction(Some(Arc::clone(&suite)));

        assert!(
            fsm.admits_participant_fallback(&PEER_PREFIX, GRANTED_TOPIC),
            "nothing in the overlay refuses publishing this topic before the reload"
        );

        std::fs::write(
            overlay_file.path(),
            format!(
                "[subject: CN=DDS Test Identity, O=HDDS Test]\ndefault: allow\ndeny publish: {}\n",
                GRANTED_TOPIC
            ),
        )
        .expect("write revoked overlay");
        let result = suite
            .reload_permissions_overlay()
            .expect("reload")
            .expect("overlay configured");
        assert_eq!(result, ReloadResult::Reloaded, "the content did change");

        assert!(
            !fsm.admits_participant_fallback(&PEER_PREFIX, GRANTED_TOPIC),
            "a reload that revokes publishing must refuse an already-admitted remote reader, \
             not only a newly created local writer"
        );
    }

    /// `judge_admission` must not probe the overlay against the DEFAULT
    /// partition only (`&[]`): a rule scoped
    /// to a different partition (`deny publish: topic partitions=Classified`)
    /// would never be applied to a remote endpoint that actually announces
    /// `Classified` -- a written security rule silently not enforced. No
    /// handshake machine, no signed access control at all is wired on this
    /// FSM: the overlay alone decides, both at the topic-level pass
    /// (`judge_admission`, which must defer to `Admission::PerEndpoint`
    /// once a partition-scoped rule exists for the topic) and at the
    /// per-endpoint pass (`judge_endpoint`, which has the endpoint's REAL
    /// announced partitions to probe with).
    ///
    /// Also covers a remote endpoint that changes its partitions (SEDP
    /// update): the per-endpoint verdict is cached per (GUID, topic, kind)
    /// under `admission_epoch`, which `topic_registry_generation` moves on
    /// every SEDP mutation, so the changed partition is read fresh and
    /// re-judged, never answered from a stale verdict.
    ///
    /// Both halves of the rule are pinned:
    /// - `judge_admission` must set `needs_per_endpoint = true` (the
    ///   `local_restriction_is_partition_scoped` branch); otherwise the
    ///   topic-level pass decides `Admitted` outright from the
    ///   default-partition probe, and the `Classified` assertion fails.
    /// - `judge_endpoint` must apply the overlay check: with no signed access
    ///   control configured, the per-endpoint pass would otherwise fall
    ///   through to `Ok(())` unconditionally, and the `Classified` assertion
    ///   would fail.
    #[test]
    fn an_overlay_partition_scoped_deny_is_enforced_against_the_endpoints_own_partition() {
        use crate::security::test_pki::TEST_CA_CERT_PEM;
        use crate::security::{SecurityConfig, SecurityPluginSuite};
        use std::io::Write as _;

        let write_temp = |contents: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().expect("temp file");
            f.write_all(contents).expect("write");
            f.flush().expect("flush");
            f
        };
        let cert = write_temp(TEST_IDENTITY_CERT_PEM);
        let key = write_temp(TEST_IDENTITY_KEY_PEM);
        let ca = write_temp(TEST_CA_CERT_PEM);
        let overlay_file = write_temp(
            format!(
                "[subject: CN=DDS Test Identity, O=HDDS Test]\n\
                 default: allow\n\
                 deny publish: {} partitions=Classified\n",
                GRANTED_TOPIC
            )
            .as_bytes(),
        );

        let config = SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .permissions_overlay(overlay_file.path())
            .build()
            .expect("config");
        let suite = Arc::new(SecurityPluginSuite::new(config, DOMAIN).expect("suite"));

        let mut fsm =
            DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 100_000);
        fsm.set_local_restriction(Some(Arc::clone(&suite)));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 30_000,
            domain_id: DOMAIN,
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

        let classified = recheck_announce(
            &fsm,
            GRANTED_TOPIC,
            1,
            &["Classified"],
            super::SedpChannel::Plain,
        );
        assert!(
            !fsm.admits_remote_endpoint(GRANTED_TOPIC, &classified, false),
            "a remote reader in the denied partition must be refused"
        );

        let other = recheck_announce(
            &fsm,
            GRANTED_TOPIC,
            2,
            &["Other"],
            super::SedpChannel::Plain,
        );
        assert!(
            fsm.admits_remote_endpoint(GRANTED_TOPIC, &other, false),
            "a remote reader in a DIFFERENT, unnamed partition must still be admitted \
             (default: allow)"
        );

        // SEDP update: the same endpoint later moves into the denied
        // partition. Re-judged, not answered from a stale cached verdict.
        let _ = recheck_announce(
            &fsm,
            GRANTED_TOPIC,
            2,
            &["Classified"],
            super::SedpChannel::Plain,
        );
        assert!(
            !fsm.admits_remote_endpoint(GRANTED_TOPIC, &other, false),
            "a partition change announced over SEDP must be re-judged"
        );
    }

    /// THE GUID KEY TRAP.
    ///
    /// `EndpointInfo::participant_guid` carries entity id `[0,0,0,0]` while
    /// every write to the handshake map keys on `RTPS_ENTITYID_PARTICIPANT`.
    /// `GUID` hashes over prefix AND entity id, so a gate that looked the raw
    /// field up would get `None` from `peer_credentials` for every peer, skip
    /// the check, and be ALWAYS OPEN -- the mirror image of an always-closed
    /// authentication gate.
    ///
    /// This test fails in exactly that case: the peer authenticated, its
    /// document explicitly denies `admin/*`, and the endpoint must not be
    /// surfaced. The two assertions below pin the two keys as distinct, so the
    /// test cannot pass by accident if the conventions are ever unified.
    #[test]
    fn a_denied_topic_from_an_authenticated_peer_is_refused() {
        let machine = local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec()));
        let endpoint = peer_writer_endpoint(DENIED_TOPIC);

        assert!(
            !machine.has_session(&endpoint.participant_guid),
            "the raw participant_guid must NOT be a key in the handshake map, or this test \
             would pass with the buggy lookup too"
        );
        assert!(
            machine.is_authenticated(&GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT)),
            "the normalised key is the one that carries the session"
        );

        let seen = surfaced_topics(machine, Some(access_control(true)), &endpoint);
        assert!(
            seen.is_empty(),
            "a topic the peer's own permissions document denies reached the application: {:?}",
            seen
        );
    }

    /// A peer that presented no document at all is refused when our governance
    /// asks for join access control, refused on a topic whose access control
    /// our governance enables (no document, no grant: DDS-Security v1.1
    /// Table 63), and admitted only on a topic it leaves open.
    ///
    /// Same peer, same handshake, opposite governance: the verdict comes from
    /// the signed document, not from a constant.
    #[test]
    fn a_peer_with_no_document_is_judged_by_our_governance() {
        let refused = surfaced_topics(
            local_machine_with_completed_peer(None),
            Some(access_control(true)),
            &peer_writer_endpoint(GRANTED_TOPIC),
        );
        assert!(
            refused.is_empty(),
            "enable_join_access_control must refuse a peer that showed nothing: {:?}",
            refused
        );

        let controlled = surfaced_topics(
            local_machine_with_completed_peer(None),
            Some(access_control_from(governance_with_topic_access(
                false, true,
            ))),
            &peer_writer_endpoint(GRANTED_TOPIC),
        );
        assert!(
            controlled.is_empty(),
            "a peer without a document owned an endpoint on an access-controlled topic: {:?}",
            controlled
        );

        let admitted = surfaced_topics(
            local_machine_with_completed_peer(None),
            Some(access_control_from(governance_with_topic_access(
                false, false,
            ))),
            &peer_writer_endpoint(GRANTED_TOPIC),
        );
        assert_eq!(admitted, vec![GRANTED_TOPIC.to_string()]);
    }

    /// A participant with no access control configured is untouched.
    ///
    /// The evaluator is `None` for every participant built without governance
    /// and permissions, and the gate must then not exist at all -- including
    /// for a topic that any configured evaluator would deny.
    #[test]
    fn a_participant_without_access_control_is_unaffected() {
        let machine = local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec()));
        let endpoint = peer_writer_endpoint(DENIED_TOPIC);
        let seen = surfaced_topics(machine, None, &endpoint);
        assert_eq!(seen, vec![DENIED_TOPIC.to_string()]);
    }

    /// A peer that never authenticated at all is untouched by this gate.
    ///
    /// The authentication block above returns early only for a peer with a
    /// session in progress; a plaintext peer has no session and no
    /// credentials, and access control has nothing to read about it. Pinning
    /// this keeps the plaintext-interop bypass from being closed by accident.
    #[test]
    fn a_peer_with_no_handshake_session_is_unaffected() {
        let machine = Arc::new(HandshakeMachine::new());
        let endpoint = peer_writer_endpoint(DENIED_TOPIC);
        let seen = surfaced_topics(machine, Some(access_control(true)), &endpoint);
        assert_eq!(seen, vec![DENIED_TOPIC.to_string()]);
    }

    /// The FSM of `LOCAL_PREFIX` with `machine` and `control` wired, having
    /// admitted the peer's SPDP (with an identity token).
    fn fsm_knowing_the_peer(
        machine: Arc<HandshakeMachine>,
        control: Option<Arc<RemoteAccessControl>>,
    ) -> DiscoveryFsm {
        let mut fsm =
            DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 100_000);
        fsm.set_handshake_machine(
            machine,
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.set_remote_access_control(control);
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: Some(TEST_IDENTITY_CERT_PEM.to_vec()),
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        assert!(fsm.is_participant_known(&PEER_PREFIX), "fixture: known");
        fsm
    }

    /// The peer announces its endpoint `entity` of `topic` (a writer when
    /// `writer`) in `partitions`; returns its GUID.
    fn peer_announces(
        fsm: &DiscoveryFsm,
        topic: &str,
        writer: bool,
        entity: u8,
        partitions: &[&str],
    ) -> GUID {
        peer_announces_on(
            fsm,
            topic,
            writer,
            entity,
            partitions,
            super::SedpChannel::Plain,
        )
    }

    /// `peer_announces`, on the SEDP topics of `channel`.
    fn peer_announces_on(
        fsm: &DiscoveryFsm,
        topic: &str,
        writer: bool,
        entity: u8,
        partitions: &[&str],
        channel: super::SedpChannel,
    ) -> GUID {
        peer_announces_with(fsm, topic, writer, entity, partitions, &[], channel)
    }

    /// `peer_announces_on`, the endpoint's DataTagQosPolicy holding `tags`.
    fn peer_announces_with(
        fsm: &DiscoveryFsm,
        topic: &str,
        writer: bool,
        entity: u8,
        partitions: &[&str],
        tags: &[(&str, &str)],
        channel: super::SedpChannel,
    ) -> GUID {
        let mut bytes = [0u8; 16];
        bytes[..12].copy_from_slice(&PEER_PREFIX);
        bytes[14] = entity;
        bytes[15] = if writer { 0x02 } else { 0x07 };
        let endpoint_guid = GUID::from_bytes(bytes);
        let mut qos = crate::dds::QoS::reliable().partition(crate::qos::partition::Partition::new(
            partitions.iter().map(|name| (*name).to_string()).collect(),
        ));
        qos.data_tags.tags = tags
            .iter()
            .map(|(name, value)| crate::qos::data_tags::DataTag {
                name: (*name).to_string(),
                value: (*value).to_string(),
            })
            .collect();
        fsm.handle_sedp_on(
            SedpData {
                topic_name: topic.to_string(),
                type_name: "Temperature".to_string(),
                participant_guid: GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
                endpoint_guid,
                qos_hash: 0,
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
            },
            channel,
        );
        assert!(
            fsm.current_endpoint(topic, &endpoint_guid).is_some(),
            "fixture: registered"
        );
        endpoint_guid
    }

    /// `peer_announces`, carrying its own `PID_ENDPOINT_SECURITY_INFO`
    /// (`SedpData::endpoint_security_info`) -- `None` for a peer that sends
    /// no such PID.
    fn peer_announces_with_security_info(
        fsm: &DiscoveryFsm,
        topic: &str,
        writer: bool,
        entity: u8,
        info: Option<crate::protocol::discovery::EndpointSecurityInfo>,
    ) -> GUID {
        let mut bytes = [0u8; 16];
        bytes[..12].copy_from_slice(&PEER_PREFIX);
        bytes[14] = entity;
        bytes[15] = if writer { 0x02 } else { 0x07 };
        let endpoint_guid = GUID::from_bytes(bytes);
        fsm.handle_sedp_on(
            SedpData {
                topic_name: topic.to_string(),
                type_name: "Temperature".to_string(),
                participant_guid: GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
                endpoint_guid,
                qos_hash: 0,
                qos: Some(crate::dds::QoS::reliable()),
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
                endpoint_security_info: info,
            },
            super::SedpChannel::Plain,
        );
        assert!(
            fsm.current_endpoint(topic, &endpoint_guid).is_some(),
            "fixture: registered"
        );
        endpoint_guid
    }

    /// DDS-Security v1.1 Sec.7.2.8: unequal valid masks refuse a pair;
    /// absent masks skip comparison for compatibility with older peers.
    #[test]
    fn an_endpoint_security_info_mismatch_refuses_the_pair() {
        use crate::protocol::discovery::EndpointSecurityInfo;
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        const TOPIC: &str = "SecureData";
        let mut fsm =
            DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 100_000);
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: false,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            // Our governance signs the metadata of this topic
            // (`metadata_protection_kind` SIGN): a remote endpoint that
            // does not announce `IS_SUBMESSAGE_PROTECTED` runs a different
            // governance for the SAME topic.
            topic_rules: vec![TopicRule {
                topic_expression: TOPIC.to_string(),
                enable_discovery_protection: false,
                enable_liveliness_protection: false,
                enable_read_access_control: false,
                enable_write_access_control: false,
                metadata_protection_kind: ProtectionKind::Sign,
                data_protection_kind: BasicProtectionKind::None,
            }],
        })));
        // A plain SEDP about an unknown participant is buffered until its
        // SPDP arrives (`handle_sedp_on`'s `pending_sedp`), never
        // registered: admit the peer's participant first, as every real
        // peer's SPDP would, before announcing its endpoints.
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 30_000,
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

        // A peer whose own governance leaves this topic's metadata
        // unprotected: a mismatch against our SIGN requirement.
        let unprotected = peer_announces_with_security_info(
            &fsm,
            TOPIC,
            true,
            1,
            Some(EndpointSecurityInfo {
                endpoint_security_attributes: EndpointSecurityInfo::IS_VALID,
                plugin_endpoint_security_attributes: EndpointSecurityInfo::PLUGIN_IS_VALID,
            }),
        );
        assert!(
            !fsm.admits_remote_endpoint(TOPIC, &unprotected, true),
            "a writer whose governance leaves metadata unprotected must not match ours, which \
             signs it"
        );

        // An absent PID defaults to two invalid masks: skip comparison.
        let absent = peer_announces_with_security_info(&fsm, TOPIC, true, 2, None);
        assert!(
            fsm.admits_remote_endpoint(TOPIC, &absent, true),
            "an absent PID skips both comparisons"
        );

        // A peer that announces the SAME attributes (metadata SIGN,
        // nothing else) matches.
        let matched = peer_announces_with_security_info(
            &fsm,
            TOPIC,
            true,
            3,
            Some(EndpointSecurityInfo {
                endpoint_security_attributes: EndpointSecurityInfo::IS_VALID
                    | EndpointSecurityInfo::IS_SUBMESSAGE_PROTECTED,
                plugin_endpoint_security_attributes: EndpointSecurityInfo::PLUGIN_IS_VALID,
            }),
        );
        assert!(
            fsm.admits_remote_endpoint(TOPIC, &matched, true),
            "identical protections must match"
        );
    }

    /// DDS-Security v1.1 Sec.7.2.7, 9.4.2.4: valid participant masks
    /// must agree, while missing security information skips comparison.
    #[test]
    fn a_participant_security_info_mismatch_is_rejected() {
        use crate::protocol::discovery::ParticipantSecurityInfo;
        use crate::security::access::{DiscoveryGovernance, DomainRule, ProtectionKind};
        const STRANGER: [u8; 12] = [0x44; 12];
        let mut fsm =
            DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 100_000);
        // Our domain rule protects RTPS (SIGN): the participant mask must
        // carry IS_RTPS_PROTECTED to match ours.
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: false,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::Sign,
            topic_rules: vec![],
        })));
        let spdp = |info: Option<[u8; 8]>| crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            // The check is scoped to peers that present an identity token
            // (Sec.9.4.2.4 is reached through the PKI-DH handshake this
            // starts); without one, the comment on the check in
            // `admit_spdp` explains why it is skipped.
            identity_token: Some(vec![0xAA, 0xBB]),
            permissions_token: None,
            participant_security_info: info,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };

        assert_eq!(
            fsm.admit_spdp(spdp(Some([0, 0, 0, 0x80, 0, 0, 0, 0x80]))),
            super::SpdpVerdict::Rejected,
            "valid unprotected masks must not match RTPS SIGN"
        );
        assert_eq!(
            fsm.admit_spdp(spdp(None)),
            super::SpdpVerdict::New,
            "an absent PID skips both comparisons"
        );

        // The matching mask: IS_VALID | IS_RTPS_PROTECTED, little endian.
        let matching = ParticipantSecurityInfo {
            participant_security_attributes: ParticipantSecurityInfo::IS_VALID
                | ParticipantSecurityInfo::IS_RTPS_PROTECTED,
            plugin_participant_security_attributes: ParticipantSecurityInfo::PLUGIN_IS_VALID,
        };
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&matching.participant_security_attributes.to_le_bytes());
        bytes[4..].copy_from_slice(
            &matching
                .plugin_participant_security_attributes
                .to_le_bytes(),
        );
        assert_ne!(
            fsm.admit_spdp(spdp(Some(bytes))),
            super::SpdpVerdict::Rejected,
            "identical protections must admit"
        );
    }

    /// Sec.7.4.1.4: SPDP security masks use the parameter list byte order.
    /// Numeric CDR fixtures exercise parsing through the admission decision.
    #[test]
    fn participant_security_info_byte_order_is_honored_at_admission() {
        use crate::protocol::discovery::parse_spdp;
        use crate::security::access::{DiscoveryGovernance, DomainRule, ProtectionKind};

        for le in [false, true] {
            for (standard, plugin, accepted) in [
                (0x8000_0000u32, 0x8000_0002u32, false),
                (0x8000_0002, 0x8000_0002, true),
                (0x8000_0002, 0x8000_0000, false),
                (0x8000_0002, 0xC000_0002, false),
            ] {
                let mut fsm =
                    DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 100_000);
                fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
                    domains: vec![0],
                    domain_ranges: vec![],
                    allow_unauthenticated: true,
                    enable_join_access_control: false,
                    discovery_protection_kind: ProtectionKind::Encrypt,
                    liveliness_protection_kind: ProtectionKind::None,
                    rtps_protection_kind: ProtectionKind::None,
                    topic_rules: vec![],
                })));
                let u16b = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
                let u32b = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
                // PL_CDR_BE / PL_CDR_LE and zero representation options.
                let mut wire = vec![0, if le { 3 } else { 2 }, 0, 0];
                wire.extend_from_slice(&u16b(0x0050));
                wire.extend_from_slice(&u16b(16));
                wire.extend_from_slice(&[0x44; 12]);
                wire.extend_from_slice(&[0, 0, 1, 0xC1]);
                // An identity token selects the participant comparison path.
                // No validator or handshake is installed in this fixture.
                // A CDR DataHolder: class_id, empty properties and binaries.
                wire.extend_from_slice(&u16b(0x1001));
                wire.extend_from_slice(&u16b(20));
                wire.extend_from_slice(&u32b(8));
                wire.extend_from_slice(b"fixture\0");
                wire.extend_from_slice(&u32b(0));
                wire.extend_from_slice(&u32b(0));
                wire.extend_from_slice(&u16b(0x1005));
                wire.extend_from_slice(&u16b(8));
                wire.extend_from_slice(&u32b(standard));
                wire.extend_from_slice(&u32b(plugin));
                wire.extend_from_slice(&u16b(0x0001));
                wire.extend_from_slice(&u16b(0));
                let data = parse_spdp(&wire).expect("independent CDR fixture");
                assert_eq!(
                    fsm.admit_spdp(data.clone()),
                    if accepted {
                        super::SpdpVerdict::New
                    } else {
                        super::SpdpVerdict::Rejected
                    },
                    "le={le}, standard={standard:#x}, plugin={plugin:#x}"
                );
                let info = data.participant_security_info.expect("security PID");
                assert_eq!(
                    u32::from_le_bytes(info[..4].try_into().expect("word")),
                    standard
                );
                assert_eq!(
                    u32::from_le_bytes(info[4..].try_into().expect("word")),
                    plugin
                );
            }
        }
    }

    /// DDS Security v1.1 Sec.9.4.3: an AUTHENTICATED peer whose permissions
    /// deny a topic is refused at the match, and every data path applies
    /// that verdict: the list our writers send data, heartbeats and repairs
    /// to, the ACKNACK door and the reader's door (`admits_remote_endpoint`),
    /// the participant fallback. Its grant names no partition, so it covers
    /// the default partition only (Sec.9.4.1.3.2.3.1.4): its reader in
    /// partition B is refused too, and so is an endpoint it never announced,
    /// whose partitions are unknown. The data plane must not send or accept
    /// what the match refused.
    #[test]
    fn the_data_plane_applies_the_verdict_of_the_match() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        let granted = peer_announces(&fsm, GRANTED_TOPIC, false, 1, &[]);
        let in_b = peer_announces(&fsm, GRANTED_TOPIC, false, 2, &["B"]);
        let denied = peer_announces(&fsm, DENIED_TOPIC, false, 3, &[]);
        let granted_writer = peer_announces(&fsm, GRANTED_TOPIC, true, 4, &[""]);
        let denied_writer = peer_announces(&fsm, DENIED_TOPIC, true, 5, &[]);

        let sent_to = |topic: &str| -> Vec<GUID> {
            fsm.find_readers_for_topic(topic)
                .iter()
                .map(|reader| reader.endpoint_guid)
                .collect()
        };
        assert_eq!(
            sent_to(GRANTED_TOPIC),
            vec![granted],
            "only the granted reader"
        );
        assert!(
            sent_to(DENIED_TOPIC).is_empty(),
            "nothing to a denied reader"
        );
        assert_eq!(
            fsm.registered_readers_for_topic(GRANTED_TOPIC).len(),
            2,
            "discovery still holds both"
        );

        let admits = |topic: &str, guid: &GUID, writer: bool| {
            fsm.admits_remote_endpoint(topic, guid, writer)
        };
        assert!(admits(GRANTED_TOPIC, &granted, false));
        assert!(!admits(GRANTED_TOPIC, &in_b, false), "partition B");
        assert!(!admits(DENIED_TOPIC, &denied, false));
        assert!(admits(GRANTED_TOPIC, &granted_writer, true));
        assert!(!admits(DENIED_TOPIC, &denied_writer, true));
        let unannounced = GUID::new(PEER_PREFIX, [0, 0, 9, 0x02]);
        assert!(
            !admits(GRANTED_TOPIC, &unannounced, true),
            "an unannounced writer's partitions are unknown"
        );
        assert!(
            !fsm.admits_participant_fallback(&PEER_PREFIX, GRANTED_TOPIC),
            "the fallback does not know the partitions of the readers it sends to"
        );

        // The match reaches the same verdicts.
        for (topic, guid, admitted) in [
            (GRANTED_TOPIC, granted, true),
            (GRANTED_TOPIC, in_b, false),
            (DENIED_TOPIC, denied, false),
            (GRANTED_TOPIC, granted_writer, true),
            (DENIED_TOPIC, denied_writer, false),
        ] {
            let endpoint = fsm.current_endpoint(topic, &guid).expect("registered");
            assert_eq!(fsm.admits_endpoint(&endpoint), admitted, "{:?}", guid);
        }

        // An endpoint announced anew is judged anew (the registry moves the
        // admission epoch): the reader of partition B goes, and comes back
        // under the same GUID in the default partition.
        assert!(fsm.remove_remote_endpoint(in_b), "fixture: removed");
        assert_eq!(peer_announces(&fsm, GRANTED_TOPIC, false, 2, &[]), in_b);
        assert!(
            fsm.admits_remote_endpoint(GRANTED_TOPIC, &in_b, false),
            "re-announced in the default partition"
        );
    }

    /// The partitions an endpoint announced are cached per (topic, GUID):
    /// one GUID announced on two topics, in the default partition on one
    /// and in partition B on the other, is two endpoints: the cache is keyed
    /// by more than the GUID, so the second topic is not judged on the first
    /// topic's partitions.
    #[test]
    fn the_partitions_of_one_guid_on_two_topics_are_judged_apart() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        let other = "sensor/humidity";
        let reader = peer_announces_on(
            &fsm,
            GRANTED_TOPIC,
            false,
            1,
            &[],
            super::SedpChannel::Secure,
        );
        assert_eq!(
            peer_announces_on(&fsm, other, false, 1, &["B"], super::SedpChannel::Secure),
            reader
        );
        // The first answer is cached first, under the current epoch.
        assert!(fsm.admits_remote_endpoint(GRANTED_TOPIC, &reader, false));
        assert!(
            !fsm.admits_remote_endpoint(other, &reader, false),
            "partition B on '{}' admitted from the answer cached for '{}'",
            other,
            GRANTED_TOPIC
        );
        // And in the other order, from a cache that starts over.
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        let reader = peer_announces_on(&fsm, other, false, 1, &["B"], super::SedpChannel::Secure);
        peer_announces_on(
            &fsm,
            GRANTED_TOPIC,
            false,
            1,
            &[],
            super::SedpChannel::Secure,
        );
        assert!(!fsm.admits_remote_endpoint(other, &reader, false));
        assert!(fsm.admits_remote_endpoint(GRANTED_TOPIC, &reader, false));
    }

    /// The participant `prefix` announces a TRANSIENT_LOCAL reader `entity`
    /// of `topic` in `partitions`, with a unicast locator (a late joiner a
    /// writer's history is replayed to): on the secure SEDP topics for the
    /// authenticated peer, on the plain ones for anyone else. Returns its
    /// GUID.
    fn peer_announces_durable_reader(
        fsm: &DiscoveryFsm,
        prefix: [u8; 12],
        topic: &str,
        entity: u8,
        partitions: &[&str],
    ) -> GUID {
        let channel = if prefix == PEER_PREFIX {
            super::SedpChannel::Secure
        } else {
            super::SedpChannel::Plain
        };
        let reader = GUID::new(prefix, [0, 0, entity, 0x07]);
        let qos = crate::dds::QoS::reliable().transient_local().partition(
            crate::qos::partition::Partition::new(
                partitions.iter().map(|name| (*name).to_string()).collect(),
            ),
        );
        fsm.handle_sedp_on(
            SedpData {
                topic_name: topic.to_string(),
                type_name: "Temperature".to_string(),
                participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
                endpoint_guid: reader,
                qos_hash: 1,
                qos: Some(qos),
                type_object: None,
                dependents: Vec::new(),
                type_object_legacy_v1: false,
                unicast_locators: vec!["127.0.0.1:7999".parse().expect("locator")],
                user_data: None,
                shm_capability: None,
                has_explicit_reliability: true,
                has_explicit_ownership: false,
                has_ownership_strength: false,
                type_information: None,
                type_consistency: None,
                group_entity_id: None,
                endpoint_security_info: None,
            },
            channel,
        );
        assert!(
            fsm.current_endpoint(topic, &reader).is_some(),
            "fixture: registered"
        );
        reader
    }

    /// The replays a local writer of each of `topics` is asked for:
    /// (topic, reader GUID).
    type Replays = Arc<Mutex<Vec<(String, GUID)>>>;

    fn replay_probe(
        fsm: &DiscoveryFsm,
        topics: &[&str],
    ) -> (Replays, Vec<crate::core::discovery::replay::ReplayToken>) {
        let replays: Replays = Arc::new(Mutex::new(Vec::new()));
        let tokens = topics
            .iter()
            .map(|topic| {
                let seen = Arc::clone(&replays);
                let name = (*topic).to_string();
                fsm.replay_registry().register(
                    *topic,
                    "Temperature",
                    Arc::new(move |_dest, reader: Option<[u8; 16]>| {
                        seen.lock().unwrap_or_else(|e| e.into_inner()).push((
                            name.clone(),
                            GUID::from_bytes(reader.expect("the replay names its reader")),
                        ));
                    }),
                )
            })
            .collect();
        (replays, tokens)
    }

    fn replayed(replays: &Replays) -> Vec<(String, GUID)> {
        replays.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The late-joiner history replay takes the door (`replay_admitted`):
    /// DDS Security v1.1 Sec.9.4.3, a durable reader whose permissions deny
    /// the topic, or whose partition the grant does not cover, gets none of
    /// a writer's history; the granted one gets it. A later authentication
    /// of the peer judges the withheld replays again, and the denied stays
    /// denied. A late joiner does not get the whole history by default.
    #[test]
    fn the_history_replay_goes_only_to_an_admitted_reader() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        let (replays, _tokens) = replay_probe(&fsm, &[GRANTED_TOPIC, DENIED_TOPIC]);
        let granted = peer_announces_durable_reader(&fsm, PEER_PREFIX, GRANTED_TOPIC, 1, &[]);
        let _denied = peer_announces_durable_reader(&fsm, PEER_PREFIX, DENIED_TOPIC, 2, &[]);
        let _in_b = peer_announces_durable_reader(&fsm, PEER_PREFIX, GRANTED_TOPIC, 3, &["B"]);
        assert_eq!(
            replayed(&replays),
            vec![(GRANTED_TOPIC.to_string(), granted)],
            "only the admitted reader gets the history"
        );
        fsm.peer_authenticated(GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT), false);
        assert_eq!(
            replayed(&replays).len(),
            1,
            "judged again, still refused: {:?}",
            replayed(&replays)
        );
    }

    /// DDS Security v1.1 Sec.9.3.4: a durable reader of a participant whose
    /// handshake is in progress gets no history; it gets it once the
    /// handshake completes (`replay_withheld_for`), once.
    #[test]
    fn a_history_replay_waits_for_the_handshake_to_complete() {
        let (machine, complete) = crate::security::test_pki::local_machine_with_pending_peer(
            LOCAL_PREFIX,
            PEER_PREFIX,
            Some(AUDIT_PERMISSIONS_SMIME.to_vec()),
        );
        let fsm = fsm_knowing_the_peer(machine, Some(access_control(true)));
        let (replays, _tokens) = replay_probe(&fsm, &[GRANTED_TOPIC]);
        let reader = peer_announces_durable_reader(&fsm, PEER_PREFIX, GRANTED_TOPIC, 1, &[]);
        assert!(
            replayed(&replays).is_empty(),
            "replayed before the handshake completed"
        );
        complete();
        let peer = GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT);
        fsm.peer_authenticated(peer, false);
        assert_eq!(
            replayed(&replays),
            vec![(GRANTED_TOPIC.to_string(), reader)]
        );
        fsm.peer_authenticated(peer, false);
        assert_eq!(replayed(&replays).len(), 1, "replayed once");
    }

    /// DDS Security v1.1 Sec.8.8.7.1: a governance that admits
    /// unauthenticated participants still refuses them on a read-protected
    /// topic, and the history replay with it; on an unprotected topic they
    /// get it.
    #[test]
    fn an_unauthenticated_reader_gets_no_history_of_a_protected_topic() {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        const STRANGER: [u8; 12] = [0x33; 12];
        let mut fsm =
            DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 100_000);
        fsm.set_handshake_machine(
            local_machine_with_completed_peer(None),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        let topic = |expression: &str, access: bool| TopicRule {
            topic_expression: expression.to_string(),
            enable_discovery_protection: false,
            enable_liveliness_protection: false,
            enable_read_access_control: access,
            enable_write_access_control: access,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        };
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![topic("Open*", true), topic("Free*", false)],
        })));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 30_000,
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
        assert!(fsm.is_participant_known(&STRANGER), "fixture: admitted");
        let (replays, _tokens) = replay_probe(&fsm, &["OpenData", "FreeData"]);
        let _open = peer_announces_durable_reader(&fsm, STRANGER, "OpenData", 1, &[]);
        let free = peer_announces_durable_reader(&fsm, STRANGER, "FreeData", 2, &[]);
        assert_eq!(
            replayed(&replays),
            vec![("FreeData".to_string(), free)],
            "the history of a read-protected topic went to an unauthenticated reader"
        );
    }

    /// `type_lookup_serves`: a type our endpoints announce on a
    /// discovery-protected topic only is described to an authenticated
    /// participant (it got the announcement on the secure SEDP topics), not
    /// to one that has not authenticated, nor to an unknown requester.
    #[test]
    fn a_discovery_protected_type_is_described_to_authenticated_peers_only() {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        let mut fsm = fsm_knowing_the_peer(local_machine_with_completed_peer(None), None);
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: false,
            discovery_protection_kind: ProtectionKind::Encrypt,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![TopicRule {
                topic_expression: "*".to_string(),
                enable_discovery_protection: true,
                enable_liveliness_protection: false,
                enable_read_access_control: false,
                enable_write_access_control: false,
                metadata_protection_kind: ProtectionKind::None,
                data_protection_kind: BasicProtectionKind::None,
            }],
        })));
        fsm.handle_sedp(SedpData {
            topic_name: "Plans".to_string(),
            type_name: "PlanType".to_string(),
            participant_guid: GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT),
            endpoint_guid: GUID::new(LOCAL_PREFIX, [0, 0, 1, 0x02]),
            qos_hash: 0,
            qos: Some(crate::dds::QoS::reliable()),
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
        assert!(fsm.type_lookup_serves(Some(&PEER_PREFIX), "PlanType"));
        assert!(!fsm.type_lookup_serves(Some(&[0x33; 12]), "PlanType"));
        assert!(!fsm.type_lookup_serves(None, "PlanType"));
        let ungoverned = DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 1);
        assert!(
            ungoverned.type_lookup_serves(None, "PlanType"),
            "no security configured: served as before"
        );
    }

    /// An evaluator that takes a peer's permissions document in plain XML
    /// (`insecure_allow_unsigned_documents`), for documents written here.
    fn access_control_of_plain_documents() -> Arc<RemoteAccessControl> {
        access_control_of_plain_documents_matching(false)
    }

    /// `access_control_of_plain_documents`, partitions read with the
    /// "legacy matching" when `legacy` (`legacy_partition_matching`).
    fn access_control_of_plain_documents_matching(legacy: bool) -> Arc<RemoteAccessControl> {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("fixture permissions CA parses");
        Arc::new(
            RemoteAccessControl::new(
                RemoteAccessInputs {
                    governance_xml: governance(true),
                    permissions_ca: Some(ca),
                    accept_unsigned_for_tests: true,
                    legacy_partition_matching: legacy,
                },
                DOMAIN,
            )
            .with_fixed_now(FIXTURE_NOW_UNIX),
        )
    }

    /// The peer's permissions document: `rules` granted to its subject on
    /// our domain, default DENY.
    fn peer_document(rules: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?><dds><permissions><grant name=\"peer\">\
             <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name><validity>\
             <not_before>2020-01-01T00:00:00</not_before>\
             <not_after>2036-01-01T00:00:00</not_after></validity>{}<default>DENY</default>\
             </grant></permissions></dds>",
            rules.replace("DOMAIN", &DOMAIN.to_string())
        )
        .into_bytes()
    }

    /// DDS Security v1.1 Sec.9.4.1.3.2.3.1.4: a peer whose permissions grant
    /// a topic in partitions `A*` is admitted where its endpoint's partitions
    /// are all in that set, and refused elsewhere, the default partition
    /// included (the document loads: one with
    /// `<partitions>` is accepted). A re-announcement on the secure SEDP
    /// topics that moves the reader moves the verdict (the registry moves the
    /// admission epoch), both ways, at the match and on the data plane.
    #[test]
    fn a_peers_partition_grant_is_enforced_and_followed() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(peer_document(
                "<allow_rule><domains><id>DOMAIN</id></domains><subscribe><topics>\
                 <topic>sensor/*</topic></topics><partitions><partition>A*</partition>\
                 </partitions></subscribe></allow_rule>",
            ))),
            Some(access_control_of_plain_documents()),
        );
        let secure = super::SedpChannel::Secure;
        let in_a = peer_announces_on(&fsm, GRANTED_TOPIC, false, 1, &["A1"], secure);
        let in_b = peer_announces_on(&fsm, GRANTED_TOPIC, false, 2, &["B"], secure);
        let default = peer_announces_on(&fsm, GRANTED_TOPIC, false, 3, &[], secure);
        let both = peer_announces_on(&fsm, GRANTED_TOPIC, false, 4, &["A2", "B"], secure);
        let admitted = |guid: &GUID| fsm.admits_remote_endpoint(GRANTED_TOPIC, guid, false);
        let sent_to = || -> Vec<GUID> {
            fsm.find_readers_for_topic(GRANTED_TOPIC)
                .iter()
                .map(|reader| reader.endpoint_guid)
                .collect()
        };
        assert!(admitted(&in_a));
        assert!(!admitted(&in_b));
        assert!(
            !admitted(&default),
            "A* does not name the default partition"
        );
        assert!(!admitted(&both), "B is not in the granted set");
        assert_eq!(sent_to(), vec![in_a]);
        for (guid, expected) in [(in_a, true), (in_b, false), (default, false)] {
            let endpoint = fsm.current_endpoint(GRANTED_TOPIC, &guid).expect("known");
            assert_eq!(fsm.admits_endpoint(&endpoint), expected, "{:?}", guid);
        }
        // Moved to B, then back to A3, over the secure SEDP topics.
        peer_announces_on(&fsm, GRANTED_TOPIC, false, 1, &["B"], secure);
        assert!(!admitted(&in_a), "moved to B: refused");
        assert!(sent_to().is_empty());
        peer_announces_on(&fsm, GRANTED_TOPIC, false, 1, &["A3"], secure);
        assert!(admitted(&in_a), "back in A3: admitted");
        assert_eq!(sent_to(), vec![in_a]);
    }

    /// Sec.9.4.1.3.2.3.1.4, "legacy matching" selected
    /// (`SecurityConfig::legacy_partition_matching`): a peer's grant for
    /// `A*` admits an endpoint ONE of whose partitions it covers; without
    /// the option, the same endpoint is refused.
    #[test]
    fn a_peers_partition_grant_follows_the_legacy_matching_option() {
        let document = || {
            peer_document(
                "<allow_rule><domains><id>DOMAIN</id></domains><subscribe><topics>\
                 <topic>sensor/*</topic></topics><partitions><partition>A*</partition>\
                 </partitions></subscribe></allow_rule>",
            )
        };
        for legacy in [false, true] {
            let fsm = fsm_knowing_the_peer(
                local_machine_with_completed_peer(Some(document())),
                Some(access_control_of_plain_documents_matching(legacy)),
            );
            let secure = super::SedpChannel::Secure;
            let both = peer_announces_on(&fsm, GRANTED_TOPIC, false, 1, &["A2", "B"], secure);
            let in_b = peer_announces_on(&fsm, GRANTED_TOPIC, false, 2, &["B"], secure);
            assert_eq!(
                fsm.admits_remote_endpoint(GRANTED_TOPIC, &both, false),
                legacy,
                "[A2, B], legacy={legacy}"
            );
            assert!(
                !fsm.admits_remote_endpoint(GRANTED_TOPIC, &in_b, false),
                "[B]"
            );
        }
    }

    /// DDS Security v1.1 Sec.9.4.1.3.2.3.1.5: a peer granted a topic for
    /// the data tag {(level, public)} is admitted for an endpoint announcing
    /// that tag or none, refused for one announcing another; a secure
    /// re-announcement that changes the tags moves the verdict.
    #[test]
    fn a_peers_data_tag_grant_is_enforced_and_followed() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(peer_document(
                "<allow_rule><domains><id>DOMAIN</id></domains><publish><topics>\
                 <topic>sensor/*</topic></topics><data_tags><tag><name>level</name>\
                 <value>public</value></tag></data_tags></publish></allow_rule>",
            ))),
            Some(access_control_of_plain_documents()),
        );
        let secure = super::SedpChannel::Secure;
        let public = [("level", "public")];
        let secret = [("level", "secret")];
        let writer = peer_announces_with(&fsm, GRANTED_TOPIC, true, 1, &[], &public, secure);
        let admitted = || fsm.admits_remote_endpoint(GRANTED_TOPIC, &writer, true);
        assert!(admitted());
        peer_announces_with(&fsm, GRANTED_TOPIC, true, 1, &[], &secret, secure);
        assert!(!admitted(), "re-announced with another tag: refused");
        peer_announces_with(&fsm, GRANTED_TOPIC, true, 1, &[], &[], secure);
        assert!(admitted(), "no tag: within the granted set");
    }

    /// The per-endpoint verdict answers for the kind the endpoint was
    /// announced as: a GUID the peer announced as a reader in a granted
    /// partition is not admitted as a writer of the same topic, before or
    /// after the reader's verdict is cached.
    #[test]
    fn a_readers_verdict_does_not_admit_a_writer_of_the_same_guid() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        let reader = peer_announces_on(
            &fsm,
            GRANTED_TOPIC,
            false,
            1,
            &[],
            super::SedpChannel::Secure,
        );
        assert!(
            !fsm.admits_remote_endpoint(GRANTED_TOPIC, &reader, true),
            "uncached"
        );
        assert!(fsm.admits_remote_endpoint(GRANTED_TOPIC, &reader, false));
        assert!(
            !fsm.admits_remote_endpoint(GRANTED_TOPIC, &reader, true),
            "from the reader's cached verdict"
        );
    }

    /// Past `ADMISSION_CACHE_CAP` entries the admission cache starts over:
    /// a refused verdict is computed again, never flipped open.
    #[test]
    fn the_admission_cache_cap_fails_closed() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        let denied = peer_announces_on(
            &fsm,
            DENIED_TOPIC,
            false,
            3,
            &[],
            super::SedpChannel::Secure,
        );
        assert!(!fsm.admits_remote_endpoint(DENIED_TOPIC, &denied, false));
        for i in 0..10_000u32 {
            let mut prefix = [0u8; 12];
            prefix[..4].copy_from_slice(&i.to_le_bytes());
            prefix[11] = 0x5A;
            let _ =
                fsm.admits_remote_endpoint(DENIED_TOPIC, &GUID::new(prefix, [0, 0, 1, 7]), false);
            if i % 997 == 0 {
                assert!(
                    !fsm.admits_remote_endpoint(DENIED_TOPIC, &denied, false),
                    "i={}",
                    i
                );
            }
        }
        assert!(!fsm.admits_remote_endpoint(DENIED_TOPIC, &denied, false));
    }

    /// The re-announcement case in the configuration a
    /// participant actually runs: remote access control comes with a
    /// governance document (both come from the same plugin suite). An
    /// endpoint first announced on the regular SEDP topics, its topic not
    /// discovery protected, is re-announced there in partition B: the
    /// announcement is taken (`ignores_plain_sedp_about` ignores only what
    /// was announced on the secure topics) and the verdict moves.
    #[test]
    fn a_plain_reannouncement_under_a_governance_moves_the_verdict() {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        let mut fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![DOMAIN],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![TopicRule {
                topic_expression: "*".to_string(),
                enable_discovery_protection: false,
                enable_liveliness_protection: false,
                enable_read_access_control: true,
                enable_write_access_control: true,
                metadata_protection_kind: ProtectionKind::None,
                data_protection_kind: BasicProtectionKind::None,
            }],
        })));
        let plain = super::SedpChannel::Plain;
        let reader = peer_announces_on(&fsm, GRANTED_TOPIC, false, 1, &[], plain);
        assert!(fsm.admits_remote_endpoint(GRANTED_TOPIC, &reader, false));
        peer_announces_on(&fsm, GRANTED_TOPIC, false, 1, &["B"], plain);
        assert!(
            !fsm.admits_remote_endpoint(GRANTED_TOPIC, &reader, false),
            "re-announced in partition B and still admitted"
        );
        assert!(fsm.find_readers_for_topic(GRANTED_TOPIC).is_empty());
    }

    /// DDS Security v1.1 Sec.9.3.4: a participant whose handshake has not
    /// completed is held back at the match, and gets and gives nothing on
    /// the data plane; once its session goes, the verdict is judged again
    /// (the sessions move the admission epoch).
    #[test]
    fn a_peer_whose_handshake_is_not_complete_gets_and_gives_nothing() {
        let machine = Arc::new(HandshakeMachine::new());
        let peer = GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT);
        let fsm = fsm_knowing_the_peer(Arc::clone(&machine), Some(access_control(true)));
        if !machine.has_session(&peer) {
            let _ = machine
                .start(
                    GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT),
                    peer,
                    TEST_IDENTITY_CERT_PEM,
                    TEST_IDENTITY_KEY_PEM,
                )
                .expect("start");
        }
        assert!(machine.has_session(&peer) && !machine.is_authenticated(&peer));
        let reader = peer_announces(&fsm, GRANTED_TOPIC, false, 1, &[]);
        let writer = peer_announces(&fsm, GRANTED_TOPIC, true, 2, &[]);
        assert!(fsm.find_readers_for_topic(GRANTED_TOPIC).is_empty());
        assert!(!fsm.admits_remote_endpoint(GRANTED_TOPIC, &reader, false));
        assert!(!fsm.admits_remote_endpoint(GRANTED_TOPIC, &writer, true));
        assert!(!fsm.admits_participant_fallback(&PEER_PREFIX, GRANTED_TOPIC));

        // The session goes (a peer that stopped answering): no session, no
        // credentials - a participant this machine does not authenticate,
        // judged by the governance alone (none here).
        machine.drop_handshake(&peer);
        assert!(fsm.admits_remote_endpoint(GRANTED_TOPIC, &writer, true));
        assert_eq!(fsm.find_readers_for_topic(GRANTED_TOPIC).len(), 1);
    }

    /// DDS Security v1.1 Sec.9.3.4: a handshake completing between the
    /// refusal of a durable reader's replay (pending) and its withholding
    /// looked for it before it was withheld (`replay_withheld_for`); the
    /// withholding judges it again (`withhold_replay`), and the history
    /// goes, once.
    #[test]
    fn an_authentication_between_the_refusal_and_the_withholding_loses_no_replay() {
        let (machine, complete) = crate::security::test_pki::local_machine_with_pending_peer(
            LOCAL_PREFIX,
            PEER_PREFIX,
            Some(AUDIT_PERMISSIONS_SMIME.to_vec()),
        );
        let fsm = Arc::new(fsm_knowing_the_peer(machine, Some(access_control(true))));
        let (replays, _tokens) = replay_probe(&fsm, &[GRANTED_TOPIC]);
        let authenticating = Arc::clone(&fsm);
        fsm.set_replay_withheld_hook(move || {
            complete();
            authenticating
                .peer_authenticated(GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT), false);
        });
        let reader = peer_announces_durable_reader(&fsm, PEER_PREFIX, GRANTED_TOPIC, 1, &[]);
        assert_eq!(
            replayed(&replays),
            vec![(GRANTED_TOPIC.to_string(), reader)],
            "the history of a reader authenticated during its withholding was lost"
        );
        fsm.peer_authenticated(GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT), false);
        assert_eq!(replayed(&replays).len(), 1, "replayed once");
    }

    /// A departed participant's withheld replays go with it: they are
    /// neither kept nor replayed to a participant that comes back under the
    /// prefix.
    #[test]
    fn a_departed_participants_withheld_replays_go_with_it() {
        let (machine, _complete) = crate::security::test_pki::local_machine_with_pending_peer(
            LOCAL_PREFIX,
            PEER_PREFIX,
            Some(AUDIT_PERMISSIONS_SMIME.to_vec()),
        );
        let fsm = fsm_knowing_the_peer(machine, Some(access_control(true)));
        let (replays, _tokens) = replay_probe(&fsm, &[GRANTED_TOPIC]);
        let _ = peer_announces_durable_reader(&fsm, PEER_PREFIX, GRANTED_TOPIC, 1, &[]);
        assert_eq!(
            fsm.withheld_replays_of(&PEER_PREFIX),
            1,
            "fixture: withheld"
        );
        fsm.remove_participant(GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT));
        assert_eq!(fsm.withheld_replays_of(&PEER_PREFIX), 0, "purged with it");
        fsm.peer_authenticated(GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT), false);
        assert!(replayed(&replays).is_empty());
    }

    /// `judge_endpoint` is reached under `Admission::PerEndpoint` only, a
    /// credentialed admission: with the peer's credentials gone by then, or
    /// no access control to judge them, it refuses (fail closed).
    #[test]
    fn the_per_endpoint_judgement_fails_closed_without_credentials() {
        let judged = |fsm: &DiscoveryFsm| {
            let reader = peer_announces_on(
                fsm,
                GRANTED_TOPIC,
                false,
                1,
                &[],
                super::SedpChannel::Secure,
            );
            let endpoint = fsm
                .current_endpoint(GRANTED_TOPIC, &reader)
                .expect("fixture: registered");
            fsm.judge_endpoint(&endpoint).is_ok()
        };
        let control = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        assert!(
            judged(&control),
            "fixture: credentials and access control admit"
        );
        let no_session = fsm_knowing_the_peer(
            Arc::new(HandshakeMachine::new()),
            Some(access_control(true)),
        );
        assert!(!judged(&no_session), "no credentials: judged open");
        let no_access = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            None,
        );
        assert!(!judged(&no_access), "no access control: judged open");
    }

    /// The epoch a send-list verdict is filed under is loaded before the
    /// registry snapshot it judges (`admission_epoch`): a reader
    /// re-announced in a partition its grant does not cover between the
    /// snapshot and the verdict is judged again at the next walk, not
    /// served from a verdict on its old partitions.
    #[test]
    fn a_reader_moved_during_the_send_list_walk_is_judged_again() {
        let fsm = Arc::new(fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        ));
        let reader = peer_announces_on(
            &fsm,
            GRANTED_TOPIC,
            false,
            1,
            &[],
            super::SedpChannel::Secure,
        );
        assert_eq!(
            fsm.find_readers_for_topic(GRANTED_TOPIC).len(),
            1,
            "fixture"
        );
        let moved = Arc::clone(&fsm);
        fsm.set_endpoint_read_hook(move || {
            peer_announces_on(
                &moved,
                GRANTED_TOPIC,
                false,
                1,
                &["B"],
                super::SedpChannel::Secure,
            );
        });
        // This walk judges the copy it read, in the default partition.
        let _ = fsm.find_readers_for_topic(GRANTED_TOPIC);
        assert!(
            fsm.find_readers_for_topic(GRANTED_TOPIC).is_empty(),
            "the reader moved to partition B is still sent to"
        );
        assert!(!fsm.admits_remote_endpoint(GRANTED_TOPIC, &reader, false));
    }

    /// The same order on the data plane's door (`admits_remote_endpoint`):
    /// the endpoint copy is read after the epoch is loaded.
    #[test]
    fn an_endpoint_moved_during_its_admission_check_is_judged_again() {
        let fsm = Arc::new(fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        ));
        let writer = peer_announces_on(
            &fsm,
            GRANTED_TOPIC,
            true,
            1,
            &[],
            super::SedpChannel::Secure,
        );
        // A fresh epoch, nothing cached about the writer yet.
        let _ = peer_announces_on(
            &fsm,
            GRANTED_TOPIC,
            false,
            2,
            &[],
            super::SedpChannel::Secure,
        );
        let moved = Arc::clone(&fsm);
        fsm.set_endpoint_read_hook(move || {
            peer_announces_on(
                &moved,
                GRANTED_TOPIC,
                true,
                1,
                &["B"],
                super::SedpChannel::Secure,
            );
        });
        // Judged on the copy it read, in the default partition.
        assert!(
            fsm.admits_remote_endpoint(GRANTED_TOPIC, &writer, true),
            "fixture"
        );
        assert!(
            !fsm.admits_remote_endpoint(GRANTED_TOPIC, &writer, true),
            "the writer moved to partition B is still admitted"
        );
    }

    /// The peer (authenticated, grant = default partition only) announces
    /// `entity` on `topic` in `partitions` over `channel`.
    fn recheck_announce(
        fsm: &DiscoveryFsm,
        topic: &str,
        entity: u8,
        partitions: &[&str],
        channel: super::SedpChannel,
    ) -> GUID {
        let mut bytes = [0u8; 16];
        bytes[..12].copy_from_slice(&PEER_PREFIX);
        bytes[14] = entity;
        bytes[15] = 0x07;
        let endpoint_guid = GUID::from_bytes(bytes);
        let qos = crate::dds::QoS::reliable().partition(crate::qos::partition::Partition::new(
            partitions.iter().map(|name| (*name).to_string()).collect(),
        ));
        fsm.handle_sedp_on(
            SedpData {
                topic_name: topic.to_string(),
                type_name: "Temperature".to_string(),
                participant_guid: GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
                endpoint_guid,
                qos_hash: 0,
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
            },
            channel,
        );
        endpoint_guid
    }

    /// The per-endpoint verdict is filed under the admission epoch loaded
    /// AFTER the endpoint copy it was judged on was read
    /// (`find_readers_for_topic` snapshots the registry, then
    /// `endpoint_admitted` loads the epoch; `admits_remote_endpoint` clones
    /// the endpoint, then `endpoint_admitted` loads it). A re-announcement
    /// landing between the two leaves a verdict judged on the OLD partitions
    /// filed under the NEW epoch: stale until the next epoch move.
    /// Race test: many readers widen the window; the flip of one reader to
    /// partition B (not granted) races a writer's send-list walk.
    #[test]
    fn verify3_partition_flip_racing_the_send_list_leaves_a_stale_admission() {
        let fsm = Arc::new(fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        ));
        for entity in 2..=200u8 {
            peer_announces_on(
                &fsm,
                GRANTED_TOPIC,
                false,
                entity,
                &[],
                super::SedpChannel::Secure,
            );
        }
        let mut stale = 0usize;
        let trials = 300usize;
        for trial in 0..trials {
            let r = peer_announces_on(
                &fsm,
                GRANTED_TOPIC,
                false,
                1,
                &[],
                super::SedpChannel::Secure,
            );
            assert!(
                fsm.admits_remote_endpoint(GRANTED_TOPIC, &r, false),
                "fixture: default admitted"
            );
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let walker = {
                let fsm = Arc::clone(&fsm);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Acquire) {
                        let _ = fsm.find_readers_for_topic(GRANTED_TOPIC);
                    }
                    // One more walk racing nothing: models the next write.
                })
            };
            std::thread::sleep(std::time::Duration::from_micros(
                200 + (trial as u64 % 7) * 150,
            ));
            peer_announces_on(
                &fsm,
                GRANTED_TOPIC,
                false,
                1,
                &["B"],
                super::SedpChannel::Secure,
            );
            // Let the in-flight walk finish and file what it judged.
            std::thread::sleep(std::time::Duration::from_millis(3));
            stop.store(true, std::sync::atomic::Ordering::Release);
            walker.join().expect("walker");
            let now = fsm.current_endpoint(GRANTED_TOPIC, &r).expect("registered");
            assert_eq!(
                now.qos.partition.names,
                vec!["B".to_string()],
                "fixture: flipped"
            );
            if fsm.admits_remote_endpoint(GRANTED_TOPIC, &r, false) {
                stale += 1;
            }
        }
        eprintln!(
            "[verify3] stale admissions after a flip to B: {}/{}",
            stale, trials
        );
        assert_eq!(
            stale, 0,
            "a reader re-announced in partition B (not granted) stayed admitted in {}/{} trials",
            stale, trials
        );
    }

    /// Control for the race test: the same flip, no concurrent walk.
    #[test]
    fn verify3_control_flip_without_a_concurrent_walk() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        for entity in 2..=200u8 {
            peer_announces_on(
                &fsm,
                GRANTED_TOPIC,
                false,
                entity,
                &[],
                super::SedpChannel::Secure,
            );
        }
        let r = peer_announces_on(
            &fsm,
            GRANTED_TOPIC,
            false,
            1,
            &[],
            super::SedpChannel::Secure,
        );
        assert!(fsm.admits_remote_endpoint(GRANTED_TOPIC, &r, false));
        let _ = fsm.find_readers_for_topic(GRANTED_TOPIC);
        peer_announces_on(
            &fsm,
            GRANTED_TOPIC,
            false,
            1,
            &["B"],
            super::SedpChannel::Secure,
        );
        let b = fsm.admits_remote_endpoint(GRANTED_TOPIC, &r, false);
        let listed = fsm
            .find_readers_for_topic(GRANTED_TOPIC)
            .iter()
            .any(|e| e.endpoint_guid == r);
        eprintln!(
            "[verify3] control: admitted after flip={} listed={}",
            b, listed
        );
        assert!(!b && !listed);
    }

    /// Withheld replays: the cap clears EVERY entry. Unauthenticated
    /// strangers (allowed by the governance, refused on the protected topic)
    /// announcing 4096 durable readers flush the replay withheld from a
    /// peer whose handshake is pending: once it completes, its admitted
    /// reader never gets the history.
    #[test]
    fn verify3_strangers_flush_a_pending_peers_withheld_replay() {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        let (machine, complete) = crate::security::test_pki::local_machine_with_pending_peer(
            LOCAL_PREFIX,
            PEER_PREFIX,
            Some(AUDIT_PERMISSIONS_SMIME.to_vec()),
        );
        let mut fsm = fsm_knowing_the_peer(machine, Some(access_control(true)));
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![TopicRule {
                topic_expression: "*".to_string(),
                enable_discovery_protection: false,
                enable_liveliness_protection: false,
                enable_read_access_control: true,
                enable_write_access_control: true,
                metadata_protection_kind: ProtectionKind::None,
                data_protection_kind: BasicProtectionKind::None,
            }],
        })));
        // Two SPDPs: confirmed alive, past the startup probation purge.
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: Some(TEST_IDENTITY_CERT_PEM.to_vec()),
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let (replays, _tokens) = replay_probe(&fsm, &[GRANTED_TOPIC]);
        let reader = peer_announces_durable_reader(&fsm, PEER_PREFIX, GRANTED_TOPIC, 1, &[]);
        assert!(
            replayed(&replays).is_empty(),
            "fixture: withheld while pending"
        );
        let mut announced = 0usize;
        'flood: for s in 0..20u8 {
            let stranger = [0x40 + s; 12];
            fsm.handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new(stranger, RTPS_ENTITYID_PARTICIPANT),
                lease_duration_ms: 30_000,
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
            for entity in 1..=250u8 {
                peer_announces_durable_reader(&fsm, stranger, GRANTED_TOPIC, entity, &[]);
                announced += 1;
                if announced.is_multiple_of(50) {
                    // The pending peer and the strangers keep speaking (a live
                    // peer does): no probation silence purge.
                    for prefix in [PEER_PREFIX, stranger] {
                        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
                            participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
                            lease_duration_ms: 30_000,
                            domain_id: 0,
                            metatraffic_unicast_locators: vec![],
                            default_unicast_locators: vec![],
                            default_multicast_locators: vec![],
                            metatraffic_multicast_locators: vec![],
                            identity_token: (prefix == PEER_PREFIX)
                                .then(|| TEST_IDENTITY_CERT_PEM.to_vec()),
                            permissions_token: None,
                            participant_security_info: None,
                            vendor_id: None,
                            hdds_capabilities: None,
                            builtin_endpoint_set: None,
                        });
                    }
                }
                if announced
                    == std::env::var("V3_FLOOD")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(4096usize)
                {
                    break 'flood;
                }
            }
        }
        assert!(
            replayed(&replays).is_empty(),
            "fixture: strangers withheld too"
        );
        complete();
        fsm.peer_authenticated(GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT), false);
        assert_eq!(
            replayed(&replays),
            vec![(GRANTED_TOPIC.to_string(), reader)],
            "the authenticated peer's admitted reader lost its history: {} unauthenticated \
             readers flushed the withheld replays",
            announced
        );
    }

    /// A peer whose handshake is pending announces durable readers of a
    /// granted and a DENIED topic; at authentication only the granted one
    /// is replayed, once.
    #[test]
    fn verify3_pending_peer_denied_topic_not_replayed_at_authentication() {
        let (machine, complete) = crate::security::test_pki::local_machine_with_pending_peer(
            LOCAL_PREFIX,
            PEER_PREFIX,
            Some(AUDIT_PERMISSIONS_SMIME.to_vec()),
        );
        let fsm = fsm_knowing_the_peer(machine, Some(access_control(true)));
        let (replays, _tokens) = replay_probe(&fsm, &[GRANTED_TOPIC, DENIED_TOPIC]);
        let granted = peer_announces_durable_reader(&fsm, PEER_PREFIX, GRANTED_TOPIC, 1, &[]);
        let _denied = peer_announces_durable_reader(&fsm, PEER_PREFIX, DENIED_TOPIC, 2, &[]);
        let _in_b = peer_announces_durable_reader(&fsm, PEER_PREFIX, GRANTED_TOPIC, 3, &["B"]);
        assert!(replayed(&replays).is_empty());
        complete();
        let peer = GUID::new(PEER_PREFIX, RTPS_ENTITYID_PARTICIPANT);
        fsm.peer_authenticated(peer, false);
        fsm.peer_authenticated(peer, false);
        // The same reader re-announced after authentication: not new, no replay.
        peer_announces_durable_reader(&fsm, PEER_PREFIX, GRANTED_TOPIC, 1, &[]);
        assert_eq!(
            replayed(&replays),
            vec![(GRANTED_TOPIC.to_string(), granted)]
        );
    }

    /// No governance (handshake machine + remote access control
    /// only): an authenticated peer re-announces its reader, same GUID, in
    /// partition B over the plain SEDP topic. `ignores_plain_sedp_about`
    /// drops it (authenticated + already known), so the registry keeps the
    /// default partition and the admission stays "admitted".
    ///
    /// The plain change is not taken, by design: DDS Security v1.1
    /// Sec.7.4.1.7, 7.4.1.8 send the information of the topics the
    /// AccessControl plugin considers
    /// sensitive on the secure SEDP topics, and with no governance here
    /// nothing designates a topic non-sensitive; HDDS sends an authenticated
    /// peer its own changes there (`sedp_for_peer`). A plain datagram about
    /// an authenticated participant's endpoint is anybody's, and taking it
    /// would let a forger move the endpoint. Nothing leaks by ignoring it:
    /// the reader stays judged, and served, in the partition its secure
    /// announcement named. The secure re-announcement is taken and judged
    /// again (`recheck_secure_reannounce_in_other_partition_is_rejudged`).
    #[test]
    fn recheck_plain_reannounce_in_other_partition_without_governance() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        let r = recheck_announce(&fsm, GRANTED_TOPIC, 1, &[], super::SedpChannel::Plain);
        assert!(
            fsm.admits_remote_endpoint(GRANTED_TOPIC, &r, false),
            "fixture"
        );
        let _ = recheck_announce(&fsm, GRANTED_TOPIC, 1, &["B"], super::SedpChannel::Plain);
        let now = fsm.current_endpoint(GRANTED_TOPIC, &r).expect("registered");
        assert!(
            now.qos.partition.is_default(),
            "a plain change about an authenticated peer's endpoint was taken: {:?}",
            now.qos.partition.names
        );
        assert!(
            fsm.admits_remote_endpoint(GRANTED_TOPIC, &r, false),
            "judged in the partition its announcement named"
        );
    }

    /// Same over the SECURE SEDP channel: processed, the registry
    /// moves, the epoch moves, and the verdict follows.
    #[test]
    fn recheck_secure_reannounce_in_other_partition_is_rejudged() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        let r = recheck_announce(&fsm, GRANTED_TOPIC, 1, &[], super::SedpChannel::Secure);
        assert!(
            fsm.admits_remote_endpoint(GRANTED_TOPIC, &r, false),
            "fixture"
        );
        assert_eq!(fsm.find_readers_for_topic(GRANTED_TOPIC).len(), 1);
        let _ = recheck_announce(&fsm, GRANTED_TOPIC, 1, &["B"], super::SedpChannel::Secure);
        assert!(
            !fsm.admits_remote_endpoint(GRANTED_TOPIC, &r, false),
            "secure re-announce in B: still admitted (stale)"
        );
        assert!(
            fsm.find_readers_for_topic(GRANTED_TOPIC).is_empty(),
            "still sent to"
        );
    }

    /// The `default_partition` cache is keyed by endpoint GUID only, not by
    /// (topic, GUID): one GUID announced on two topics in two partitions
    /// reuses the first topic's answer for the second.
    #[test]
    fn recheck_default_partition_cache_ignores_the_topic() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        // Find a second topic the fixture grant also covers.
        let other = "sensor/humidity";
        let r = recheck_announce(&fsm, GRANTED_TOPIC, 1, &[], super::SedpChannel::Secure);
        let _ = recheck_announce(&fsm, other, 1, &["B"], super::SedpChannel::Secure);
        // Fresh epoch: ask GRANTED first (caches GUID -> default=true).
        assert!(
            fsm.admits_remote_endpoint(GRANTED_TOPIC, &r, false),
            "fixture"
        );
        let fresh = fsm.admits_remote_endpoint(other, &r, false);
        assert!(
            !fresh,
            "the same GUID in partition B on '{}' admitted from the cached answer of '{}'",
            other, GRANTED_TOPIC
        );
    }

    /// Cap eviction: past ADMISSION_CACHE_CAP entries the cache starts over;
    /// a refused verdict is recomputed, never flipped open.
    #[test]
    fn recheck_cache_cap_eviction_fails_closed() {
        let fsm = fsm_knowing_the_peer(
            local_machine_with_completed_peer(Some(AUDIT_PERMISSIONS_SMIME.to_vec())),
            Some(access_control(true)),
        );
        let denied = recheck_announce(&fsm, DENIED_TOPIC, 3, &[], super::SedpChannel::Secure);
        assert!(
            !fsm.admits_remote_endpoint(DENIED_TOPIC, &denied, false),
            "fixture"
        );
        for i in 0..10_000u32 {
            let mut p = [0u8; 12];
            p[..4].copy_from_slice(&i.to_le_bytes());
            p[11] = 0x5A;
            let _ = fsm.admits_remote_endpoint(DENIED_TOPIC, &GUID::new(p, [0, 0, 1, 7]), false);
            if i % 997 == 0 {
                assert!(
                    !fsm.admits_remote_endpoint(DENIED_TOPIC, &denied, false),
                    "i={i}"
                );
            }
        }
        assert!(!fsm.admits_remote_endpoint(DENIED_TOPIC, &denied, false));
    }

    /// Late-joiner history replay (`handle_sedp` -> `replay_for`) to a
    /// TRANSIENT_LOCAL reader of an "Unauthenticated" participant on a
    /// read-protected topic (allow_unauthenticated TRUE): Sec.8.8.7.1 says
    /// do not match; the replay is the writer's whole history.
    #[test]
    fn recheck_history_replay_to_refused_transient_local_reader() {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        const STRANGER: [u8; 12] = [0x33; 12];
        let mut fsm =
            DiscoveryFsm::new(GUID::new(LOCAL_PREFIX, RTPS_ENTITYID_PARTICIPANT), 100_000);
        fsm.set_handshake_machine(
            local_machine_with_completed_peer(None),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        let topic = |expression: &str, access: bool| TopicRule {
            topic_expression: expression.to_string(),
            enable_discovery_protection: false,
            enable_liveliness_protection: false,
            enable_read_access_control: access,
            enable_write_access_control: access,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        };
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![topic("Open*", true), topic("Free*", false)],
        })));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 30_000,
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
        assert!(fsm.is_participant_known(&STRANGER), "fixture: admitted");
        let replays: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let mut tokens = Vec::new();
        for t in ["OpenData", "FreeData"] {
            let seen = Arc::clone(&replays);
            let name = t.to_string();
            tokens.push(fsm.replay_registry().register(
                t,
                "Probe",
                Arc::new(move |_dest, _guid| {
                    seen.lock().unwrap().push(name.clone());
                }),
            ));
        }
        for (i, t) in ["OpenData", "FreeData"].iter().enumerate() {
            let reader = GUID::new(STRANGER, [0, 0, 0x20 + i as u8, 0x07]);
            fsm.handle_sedp_on(
                SedpData {
                    topic_name: (*t).to_string(),
                    type_name: "Probe".to_string(),
                    participant_guid: GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT),
                    endpoint_guid: reader,
                    qos_hash: 1,
                    qos: Some(crate::dds::QoS::reliable().transient_local()),
                    type_object: None,
                    dependents: Vec::new(),
                    type_object_legacy_v1: false,
                    unicast_locators: vec!["127.0.0.1:7999".parse().unwrap()],
                    user_data: None,
                    shm_capability: None,
                    has_explicit_reliability: true,
                    has_explicit_ownership: false,
                    has_ownership_strength: false,
                    type_information: None,
                    type_consistency: None,
                    group_entity_id: None,
                    endpoint_security_info: None,
                },
                super::SedpChannel::Plain,
            );
            let ep = fsm.current_endpoint(t, &reader).expect("registered");
            eprintln!(
                "[verify2] {} admits_endpoint={}",
                t,
                fsm.admits_endpoint(&ep)
            );
        }
        let seen = replays.lock().unwrap().clone();
        eprintln!("[verify2] replays fired: {:?}", seen);
        assert!(
            seen.contains(&"FreeData".to_string()),
            "fixture: replay hook works"
        );
        assert!(
            !seen.contains(&"OpenData".to_string()),
            "the writer's history of a read-protected topic was replayed to an \
             unauthenticated participant's reader (never matched): {:?}",
            seen
        );
        drop(tokens);
    }

    /// The local participant of the re-authentication tests: the higher
    /// prefix, so the peer initiates, and a restarted peer begins again.
    const RESPONDER_PREFIX: [u8; 12] = crate::security::test_pki::bound_test_prefix([0xEE; 6]);
    /// The peer that authenticates, and authenticates again.
    const INITIATOR_PREFIX: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x02; 6]);

    /// A discovery FSM for `RESPONDER_PREFIX`, its handshake machine wired to
    /// report every completed session to it, as the participant wires it.
    fn reauthentication_fsm(
        control: Arc<RemoteAccessControl>,
    ) -> (Arc<DiscoveryFsm>, Arc<HandshakeMachine>) {
        let machine = Arc::new(HandshakeMachine::new());
        let mut fsm = DiscoveryFsm::new(
            GUID::new(RESPONDER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
            100_000,
        );
        fsm.set_handshake_machine(
            Arc::clone(&machine),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.set_remote_access_control(Some(control));
        let fsm = Arc::new(fsm);
        fsm.arm_surfacing_on_authentication();
        (fsm, machine)
    }

    /// A new process of the peer, presenting `peer_permissions`, completes a
    /// handshake with `local` (the responder), over whatever session `local`
    /// already holds for it. Returns whether the local session completed.
    fn peer_authenticates(local: &HandshakeMachine, peer_permissions: &[u8]) -> bool {
        use crate::security::handshake::tokens::{encode_final, encode_reply, encode_request};
        use crate::security::handshake::HandshakeAction;
        use crate::security::test_pki::TEST_CA_CERT_PEM;

        let (cert, key, ca) = (
            TEST_IDENTITY_CERT_PEM,
            TEST_IDENTITY_KEY_PEM,
            TEST_CA_CERT_PEM,
        );
        let local_guid = GUID::new(RESPONDER_PREFIX, RTPS_ENTITYID_PARTICIPANT);
        let peer_guid = GUID::new(INITIATOR_PREFIX, RTPS_ENTITYID_PARTICIPANT);
        let peer = HandshakeMachine::new().with_local_permissions(Some(peer_permissions.to_vec()));
        let request = match peer
            .start(peer_guid, local_guid, cert, key)
            .expect("start")
            .expect("the lower prefix initiates")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected SendRequest, got {:?}", other),
        };
        let reply = match local
            .on_message(peer_guid, &request, local_guid, cert, key, ca)
            .expect("the request is accepted")
        {
            HandshakeAction::SendReply(_, token) => encode_reply(&token).expect("encode"),
            other => panic!("expected SendReply, got {:?}", other),
        };
        let final_token = match peer
            .on_message(local_guid, &reply, peer_guid, cert, key, ca)
            .expect("the reply is accepted")
        {
            HandshakeAction::SendFinal(_, token) => encode_final(&token).expect("encode"),
            other => panic!("expected SendFinal, got {:?}", other),
        };
        local
            .on_message(peer_guid, &final_token, local_guid, cert, key, ca)
            .expect("the final token is accepted");
        local.is_authenticated(&peer_guid)
    }

    /// A peer refused for an expired grant authenticates again with a
    /// renewed one: its endpoints are admitted. The refusal reached for the
    /// first session does not answer for the second.
    #[test]
    fn a_reauthentication_with_renewed_permissions_is_admitted() {
        use crate::security::test_pki::PERMISSIONS_EXPIRED_GRANT_SMIME;
        let (fsm, machine) = reauthentication_fsm(access_control(true));
        let endpoint = writer_endpoint_of(INITIATOR_PREFIX, GRANTED_TOPIC);

        assert!(peer_authenticates(
            &machine,
            PERMISSIONS_EXPIRED_GRANT_SMIME
        ));
        assert!(
            !fsm.admits_endpoint(&endpoint),
            "an expired grant admits nothing"
        );
        assert!(peer_authenticates(&machine, AUDIT_PERMISSIONS_SMIME));
        assert!(
            fsm.admits_endpoint(&endpoint),
            "the renewed permissions were answered by the refusal reached for the expired ones"
        );
    }

    /// A peer whose certificate expires loses its authenticated session, and
    /// the key of its writers goes with it: discovery's release of the peer's
    /// keys is the wiring that makes a torn-down session unreadable.
    #[test]
    fn an_expired_peer_certificate_takes_the_peers_writer_keys_with_its_session() {
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::peer_keys::SecretKey;
        use crate::security::test_pki::{AUDIT_PERMISSIONS_SMIME, TEST_IDENTITY_KEY_PEM};

        let machine = Arc::new(HandshakeMachine::new());
        let mut fsm = DiscoveryFsm::new(
            GUID::new(RESPONDER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
            100_000,
        );
        fsm.set_handshake_machine(
            Arc::clone(&machine),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.set_remote_access_control(Some(access_control(true)));
        fsm.register_builtin_writer_keys_for_tests();
        let fsm = Arc::new(fsm);
        fsm.arm_surfacing_on_authentication();

        let writer = [0x00, 0x00, 0x03, 0x02];
        fsm.receive_writer_key_for_tests(
            INITIATOR_PREFIX,
            writer,
            1,
            WriterKey::for_tests(SecretKey::from_bytes([0x3C; 32])),
        );
        assert!(peer_authenticates(&machine, AUDIT_PERMISSIONS_SMIME));
        let store = fsm.writer_keys.as_ref().expect("keys registered");
        assert_eq!(
            store.entries_with_prefix(&INITIATOR_PREFIX).len(),
            1,
            "fixture: a key"
        );

        // The peer's certificate has run out: the next pass ends its session.
        let (_, pem) = x509_parser::pem::parse_x509_pem(TEST_IDENTITY_CERT_PEM).expect("pem");
        let not_after = pem
            .parse_x509()
            .expect("x509")
            .validity()
            .not_after
            .timestamp();
        machine.tick_at(std::time::Instant::now(), Some(not_after + 1));

        let peer = GUID::new(INITIATOR_PREFIX, RTPS_ENTITYID_PARTICIPANT);
        assert!(!machine.is_authenticated(&peer));
        assert!(
            store.entries_with_prefix(&INITIATOR_PREFIX).is_empty(),
            "the peer's writer keys must go with its session"
        );
    }

    /// The mirror: a peer admitted authenticates again with permissions
    /// whose grant has expired, and is refused. The admission reached for the
    /// first session does not answer for the second.
    #[test]
    fn a_reauthentication_with_expired_permissions_is_refused() {
        use crate::security::test_pki::PERMISSIONS_EXPIRED_GRANT_SMIME;
        let (fsm, machine) = reauthentication_fsm(access_control(true));
        let endpoint = writer_endpoint_of(INITIATOR_PREFIX, GRANTED_TOPIC);

        assert!(peer_authenticates(&machine, AUDIT_PERMISSIONS_SMIME));
        assert!(fsm.admits_endpoint(&endpoint), "the grant is in force");
        assert!(peer_authenticates(
            &machine,
            PERMISSIONS_EXPIRED_GRANT_SMIME
        ));
        assert!(
            !fsm.admits_endpoint(&endpoint),
            "the expired permissions were answered by the admission reached for the valid ones"
        );
    }

    /// The same document, presented again by a new session after its grant
    /// expired, is judged at that session's instant: the verdict reached for
    /// an earlier session does not answer for a later one, even when the
    /// bytes are the same.
    #[test]
    fn a_reauthentication_is_judged_when_it_completes() {
        let control = access_control(true);
        let (fsm, machine) = reauthentication_fsm(Arc::clone(&control));
        let endpoint = writer_endpoint_of(INITIATOR_PREFIX, GRANTED_TOPIC);

        assert!(peer_authenticates(&machine, AUDIT_PERMISSIONS_SMIME));
        assert!(fsm.admits_endpoint(&endpoint), "the grant is in force");
        // 2037-01-01T00:00:00Z: past the grant's not_after (2036-01-01).
        control.set_fixed_now(2_114_380_800);
        assert!(peer_authenticates(&machine, AUDIT_PERMISSIONS_SMIME));
        assert!(
            !fsm.admits_endpoint(&endpoint),
            "a new session was answered by the verdict reached when the grant was in force"
        );
    }
}

/// The probation boundary and the liveness marks (RTPS 2.5 8.5.3: a
/// participant lives by its lease; the probation is an HDDS heuristic against
/// the packets of a process that died just before we started). Real sleeps:
/// the rules are about instants.
#[cfg(test)]
mod probation_boundary_tests {
    use super::*;
    use crate::protocol::discovery::{SedpData, SpdpData};
    use std::sync::Mutex;
    use std::time::Duration;

    /// Records every endpoint that reaches the application.
    #[derive(Default)]
    struct Surfaced(Mutex<Vec<GUID>>);

    impl DiscoveryListener for Surfaced {
        fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(endpoint.endpoint_guid);
        }
    }

    impl Surfaced {
        fn seen(&self) -> Vec<GUID> {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    const PREFIX: [u8; 12] = [0x6A; 12];

    fn participant() -> GUID {
        GUID::new(
            PREFIX,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        )
    }

    fn writer() -> GUID {
        GUID::new(PREFIX, [0x00, 0x00, 0x01, 0x02])
    }

    fn spdp() -> SpdpData {
        SpdpData {
            participant_guid: participant(),
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

    /// A participant that has said its farewell runs no probation boundary:
    /// no purge, no drain. Dropped inside its probation, it went on purging
    /// and surfacing matches to user listeners on the discovery worker until
    /// its fields dropped.
    #[test]
    fn a_departed_participant_runs_no_probation_boundary() {
        let fsm = DiscoveryFsm::new(GUID::new([0x02; 12], [0x00, 0x00, 0x01, 0xC1]), 30_000);
        // Heard once inside the probation and never again: the boundary
        // purges it as the packet of a process that died before we started.
        fsm.handle_spdp(spdp());
        fsm.depart();
        // Past the boundary (250 ms) and past every probation verdict (500 ms).
        if let Some(rest) = Duration::from_millis(600).checked_sub(fsm.uptime()) {
            std::thread::sleep(rest);
        }
        fsm.maybe_complete_probation();
        assert!(
            !fsm.is_probation_done(),
            "no probation boundary after the farewell"
        );
        assert!(fsm.has_participant(&participant()), "and no purge");
    }

    /// An SPDP handler holds `still_here` while it runs and reaches
    /// `maybe_complete_probation`, which asks `has_departed`. With the
    /// participant being dropped at that moment, `depart` is queued on the
    /// write side; a second read of the same std `RwLock` queued behind it,
    /// and the handler and the drop waited on each other for good (a hang
    /// of `tests/rtps_port_mapping.rs`).
    #[test]
    fn a_handler_checking_departure_under_its_own_still_here_does_not_deadlock_depart() {
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x03; 12], [0x00, 0x00, 0x01, 0xC1]),
            30_000,
        ));
        let held = fsm.still_here().expect("not departed yet");
        let departing = {
            let fsm = Arc::clone(&fsm);
            std::thread::spawn(move || fsm.depart())
        };
        // Let `depart` queue on the write side behind `held`.
        std::thread::sleep(Duration::from_millis(200));
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let fsm = Arc::clone(&fsm);
            std::thread::spawn(move || {
                // What the handler does under `held`: the checks only.
                let _ = tx.send(fsm.has_departed());
            });
        }
        let seen = rx.recv_timeout(Duration::from_secs(5));
        assert_eq!(
            seen,
            Ok(false),
            "the check must not wait for a depart that waits for the handler"
        );
        fsm.maybe_complete_probation();
        drop(held);
        departing
            .join()
            .expect("depart returns once the handler is done");
        assert!(fsm.has_departed());
        assert!(fsm.still_here().is_none());
    }

    fn sedp(endpoint_guid: GUID) -> SedpData {
        SedpData {
            topic_name: "ProbationTopic".to_string(),
            type_name: "ProbationType".to_string(),
            participant_guid: participant(),
            endpoint_guid,
            qos_hash: 1,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    fn fsm_with_listener() -> (DiscoveryFsm, Arc<Surfaced>) {
        let fsm = DiscoveryFsm::new(GUID::new([0x01; 12], [0, 0, 1, 0xC1]), 100_000);
        let surfaced = Arc::new(Surfaced::default());
        fsm.register_listener(surfaced.clone());
        (fsm, surfaced)
    }

    fn sleep_until(fsm: &DiscoveryFsm, uptime: Duration) {
        let now = fsm.uptime();
        if now < uptime {
            std::thread::sleep(uptime - now);
        }
    }

    /// This participant's own endpoint surfaces when it is announced, inside
    /// the probation as after it, and once: it is neither queued for a
    /// participant to be confirmed (our own prefix is never in `db`) nor
    /// dropped as a zombie at the probation drain.
    #[test]
    fn a_local_endpoint_surfaces_at_once_inside_the_probation() {
        let (fsm, surfaced) = fsm_with_listener();
        let local_reader = GUID::new([0x01; 12], [0x00, 0x00, 0x02, 0x07]);
        let mut announced = sedp(local_reader);
        announced.participant_guid = GUID::new(
            [0x01; 12],
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        fsm.handle_sedp(announced);
        assert!(
            fsm.uptime() < Duration::from_millis(PROBATION_SPAN_MS),
            "fixture: announced inside the probation"
        );
        assert_eq!(
            surfaced.seen(),
            vec![local_reader],
            "surfaced when announced, not queued for the drain"
        );

        sleep_until(&fsm, Duration::from_millis(PROBATION_SPAN_MS + 20));
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done(), "fixture: the probation is over");
        assert_eq!(
            surfaced.seen(),
            vec![local_reader],
            "the drain surfaces it no second time"
        );
    }

    /// How long ago the peer's entry was created (`created_at`).
    fn peer_age(fsm: &DiscoveryFsm) -> Duration {
        recover_read(Arc::as_ref(&fsm.db), "test peer age")
            .get(&participant())
            .map(|p| p.created_at.elapsed())
            .expect("the peer is known")
    }

    /// Sleep until the peer's entry is `age` old.
    fn sleep_until_age(fsm: &DiscoveryFsm, age: Duration) {
        let now = peer_age(fsm);
        if now < age {
            std::thread::sleep(age - now);
        }
    }

    fn marks(fsm: &DiscoveryFsm) -> Option<u32> {
        recover_read(Arc::as_ref(&fsm.db), "test marks")
            .get(&participant())
            .map(|p| p.liveness_marks)
    }

    /// A quiet-peer shape: announced once, its SEDP 150 ms later, then
    /// nothing but HEARTBEATs, no further SPDP for 30 s.
    /// The boundary keeps it (one mark: it spoke after its first 100 ms) and
    /// its next HEARTBEAT, at a distinct instant, confirms it and surfaces
    /// the match the boundary put back. Before: purged at the boundary, its
    /// match waiting for an SPDP 30 s away.
    #[test]
    fn a_peer_confirmed_by_its_own_traffic_surfaces_after_the_boundary() {
        let (fsm, surfaced) = fsm_with_listener();
        fsm.handle_spdp(spdp());
        std::thread::sleep(Duration::from_millis(150));
        fsm.handle_sedp(sedp(writer()));
        assert!(
            fsm.uptime() < Duration::from_millis(250),
            "SEDP inside probation"
        );
        assert_eq!(marks(&fsm), Some(1), "the SEDP is the first mark");
        assert!(surfaced.seen().is_empty(), "the match is deferred");

        // The boundary, as the control thread's periodic wake fires it.
        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done());
        assert!(
            fsm.has_participant(&participant()),
            "a participant heard from after its first 100 ms is not purged"
        );
        assert_eq!(fsm.find_writers_for_topic("ProbationTopic").len(), 1);
        assert!(
            surfaced.seen().is_empty(),
            "one mark does not surface the match"
        );

        // Its control traffic, 160 ms after the SEDP: the second mark.
        std::thread::sleep(Duration::from_millis(160));
        fsm.touch_participant_by_prefix(&PREFIX);
        assert_eq!(marks(&fsm), Some(2));
        assert!(fsm.is_participant_confirmed(&PREFIX));
        assert_eq!(
            surfaced.seen(),
            vec![writer()],
            "the mark that confirms the peer surfaces its deferred match"
        );
    }

    /// Two SPDPs more than 100 ms apart inside probation, then silence on
    /// that channel (a case the `spdp_count == 2` tier alone would hold until
    /// the next SPDP): confirmed, kept, not eligible at the boundary. The
    /// second SPDP is a mark; one HEARTBEAT at a distinct instant after it is
    /// the second, and surfaces the match.
    #[test]
    fn an_announcement_is_a_mark_and_one_later_heartbeat_completes_it() {
        let (fsm, surfaced) = fsm_with_listener();
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(sedp(writer()));
        std::thread::sleep(Duration::from_millis(120));
        fsm.handle_spdp(spdp());
        assert_eq!(marks(&fsm), Some(1), "the second SPDP is a mark");
        assert!(fsm.is_participant_confirmed(&PREFIX), "two counted SPDPs");

        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.has_participant(&participant()));
        assert!(surfaced.seen().is_empty(), "not eligible at the boundary");

        std::thread::sleep(Duration::from_millis(110));
        fsm.touch_participant_by_prefix(&PREFIX);
        assert_eq!(surfaced.seen(), vec![writer()]);
    }

    /// Several emissions inside one instant are one mark, whatever their
    /// kind: a burst drained from a socket buffer late (a listener stall)
    /// confirms nothing.
    #[test]
    fn a_burst_after_the_first_100_ms_is_one_mark() {
        let (fsm, surfaced) = fsm_with_listener();
        fsm.handle_spdp(spdp());
        std::thread::sleep(Duration::from_millis(101));
        fsm.touch_participant_by_prefix(&PREFIX);
        fsm.touch_participant_by_prefix(&PREFIX);
        fsm.handle_sedp(sedp(writer()));
        fsm.touch_participant_by_prefix(&PREFIX);
        assert_eq!(marks(&fsm), Some(1), "four emissions, one instant");
        assert!(
            !fsm.is_participant_confirmed(&PREFIX),
            "a burst confirms nothing"
        );

        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.has_participant(&participant()), "it did speak late");
        assert!(surfaced.seen().is_empty(), "but its match stays deferred");
    }

    /// The zombie shape: everything inside the entry's first milliseconds,
    /// then silence. Purged at the boundary, nothing surfaced, its SEDP
    /// requeued for the SPDP that would rebuild it were it alive.
    #[test]
    fn a_burst_inside_the_first_100_ms_is_purged_at_the_boundary() {
        let (fsm, surfaced) = fsm_with_listener();
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(sedp(writer()));
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(sedp(GUID::new(PREFIX, [0x00, 0x00, 0x02, 0x02])));
        fsm.touch_participant_by_prefix(&PREFIX);
        assert_eq!(marks(&fsm), Some(0), "no emission after the first 100 ms");

        sleep_until(&fsm, Duration::from_millis(260));
        sleep_until_age(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done());
        assert!(!fsm.has_participant(&participant()), "purged");
        assert!(fsm.find_writers_for_topic("ProbationTopic").is_empty());
        assert!(
            surfaced.seen().is_empty(),
            "nothing reached the application"
        );
        assert_eq!(
            recover_read(Arc::as_ref(&fsm.pending_sedp), "test requeued").len(),
            2,
            "both SEDP wait for an SPDP that would rebuild them"
        );
        // A zombie sends nothing more; even if a stray packet of its prefix
        // came, a participant that is not in the database gains nothing.
        fsm.touch_participant_by_prefix(&PREFIX);
        assert!(surfaced.seen().is_empty());
    }

    /// A peer confirmed by its own traffic BEFORE the boundary has its
    /// deferred match surfaced BY the boundary's drain: nothing after it is
    /// guaranteed to come (no further SPDP, and its marks are spent).
    #[test]
    fn a_peer_confirmed_before_the_boundary_surfaces_at_the_boundary() {
        let (fsm, surfaced) = fsm_with_listener();
        fsm.handle_spdp(spdp());
        std::thread::sleep(Duration::from_millis(105));
        fsm.handle_sedp(sedp(writer()));
        std::thread::sleep(Duration::from_millis(105));
        fsm.touch_participant_by_prefix(&PREFIX);
        assert!(
            fsm.uptime() < Duration::from_millis(250),
            "fixture: both marks land inside probation"
        );
        assert_eq!(marks(&fsm), Some(2));
        assert!(surfaced.seen().is_empty(), "held until the boundary");

        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert_eq!(surfaced.seen(), vec![writer()], "surfaced by the drain");
    }

    /// The purge picks its victims from a snapshot and removes them one by
    /// one, re-checking the rule under the removal's write lock. A mark that
    /// lands in between keeps the participant: the re-check is the same rule
    /// as the snapshot's (`survives_probation`), not the bare confirmation.
    #[test]
    fn a_mark_between_the_purge_snapshot_and_the_removal_keeps_the_participant() {
        let (fsm, _surfaced) = fsm_with_listener();
        let fsm = Arc::new(fsm);
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(sedp(writer()));
        sleep_until(&fsm, Duration::from_millis(260));
        sleep_until_age(&fsm, Duration::from_millis(260));
        assert_eq!(marks(&fsm), Some(0), "selected by the snapshot");
        assert_eq!(retained_sedp(&fsm), 1, "fixture: its SEDP is retained");

        // `requeue_purged_sedp` takes this lock between the snapshot and the
        // removals: holding it parks the purge right there.
        let retained = recover_write(Arc::as_ref(&fsm.probation_sedp), "test park purge");
        let boundary = {
            let fsm = Arc::clone(&fsm);
            std::thread::spawn(move || fsm.maybe_complete_probation())
        };
        std::thread::sleep(Duration::from_millis(50));
        fsm.touch_participant_by_prefix(&PREFIX);
        assert_eq!(marks(&fsm), Some(1), "it spoke while the purge was parked");
        drop(retained);
        boundary.join().expect("boundary thread");
        assert!(fsm.is_probation_done());
        assert!(
            fsm.has_participant(&participant()),
            "a participant that spoke after its first 100 ms is not removed"
        );
        assert_eq!(
            recover_read(Arc::as_ref(&fsm.pending_sedp), "test pending").len(),
            0,
            "the SEDP of a kept participant is not left waiting for an SPDP"
        );
        assert_eq!(
            retained_sedp(&fsm),
            1,
            "it is retained again, for a later verdict"
        );
    }

    fn retained_sedp(fsm: &DiscoveryFsm) -> usize {
        recover_read(Arc::as_ref(&fsm.probation_sedp), "test retained").len()
    }

    /// A peer first heard late in our probation (uptime 200 ms) cannot
    /// have earned a mark when the boundary fires 50 ms later (none counts in
    /// an entry's first 100 ms). It is judged when it is as old as the
    /// probation span, the span a peer heard at our start gets: its SEDP,
    /// 150 ms after its announcement, is its first mark, which lands after
    /// the boundary and surfaces the match, and the verdict keeps it. Before:
    /// purged at the boundary, its SEDP parked for an SPDP 30 s away.
    #[test]
    fn a_peer_first_heard_late_in_probation_is_judged_at_its_own_age() {
        let (fsm, surfaced) = fsm_with_listener();
        sleep_until(&fsm, Duration::from_millis(200));
        fsm.handle_spdp(spdp());
        assert!(
            fsm.uptime() < Duration::from_millis(240),
            "fixture: first heard late in the probation"
        );

        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done());
        assert!(
            fsm.has_participant(&participant()),
            "too young at the boundary to be judged"
        );

        sleep_until_age(&fsm, Duration::from_millis(150));
        fsm.handle_sedp(sedp(writer()));
        assert_eq!(marks(&fsm), Some(1), "its SEDP is its first mark");
        assert_eq!(
            surfaced.seen(),
            vec![writer()],
            "a mark after the boundary: the match surfaces on it"
        );

        sleep_until_age(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(
            fsm.has_participant(&participant()),
            "judged at its own age: it spoke after its first 100 ms"
        );
        assert_eq!(fsm.find_writers_for_topic("ProbationTopic").len(), 1);
    }

    /// The shape of a short-lived HDDS peer heard late in our probation
    /// (measured in the Discovery Server integration test): its first SPDP
    /// and its SEDP land together at our uptime 200 ms, its second SPDP
    /// 200 ms later, after the boundary, and then it may be gone. That second
    /// SPDP is its first mark, landing after the boundary: it proves the
    /// participant alive after the boundary, which is all a participant first
    /// heard after it has to prove, so its match surfaces on it. A third
    /// emission is not awaited. Its matches surfaced, it then lives by its
    /// lease, not by the silence rule. Before: deferred until a third
    /// emission, and the peer left first.
    #[test]
    fn a_peer_heard_again_after_the_boundary_surfaces_on_that_mark() {
        let (fsm, surfaced) = fsm_with_listener();
        sleep_until(&fsm, Duration::from_millis(200));
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(sedp(writer()));
        assert!(
            fsm.uptime() < Duration::from_millis(240),
            "fixture: first heard late in the probation"
        );
        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(surfaced.seen().is_empty(), "no mark yet: deferred");

        sleep_until_age(&fsm, Duration::from_millis(200));
        fsm.handle_spdp(spdp());
        assert_eq!(marks(&fsm), Some(1), "its second SPDP is its first mark");
        assert!(
            !recover_read(Arc::as_ref(&fsm.db), "test eligibility")
                .get(&participant())
                .expect("known")
                .is_match_eligible(),
            "fixture: two counted SPDPs and one mark, not match eligible"
        );
        assert_eq!(
            surfaced.seen(),
            vec![writer()],
            "surfaced on its first mark after the boundary"
        );

        sleep_until_age(&fsm, Duration::from_millis(1_350));
        fsm.maybe_complete_probation();
        assert!(
            fsm.has_participant(&participant()),
            "a participant whose matches surfaced lives by its lease"
        );
    }

    /// The same first mark after the boundary, through control traffic: it
    /// replays the match the boundary's drain put back.
    #[test]
    fn a_first_mark_after_the_boundary_from_control_traffic_replays_the_deferred_match() {
        let (fsm, surfaced) = fsm_with_listener();
        sleep_until(&fsm, Duration::from_millis(200));
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(sedp(writer()));
        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(
            surfaced.seen().is_empty(),
            "deferred, put back by the drain"
        );

        sleep_until_age(&fsm, Duration::from_millis(150));
        fsm.touch_participant_by_prefix(&PREFIX);
        assert_eq!(marks(&fsm), Some(1));
        assert_eq!(surfaced.seen(), vec![writer()]);
    }

    /// After our own farewell (`depart`), a late mark replays nothing: the
    /// match the boundary's drain put back stays unsurfaced.
    #[test]
    fn a_late_mark_after_our_departure_surfaces_nothing() {
        let (fsm, surfaced) = fsm_with_listener();
        sleep_until(&fsm, Duration::from_millis(200));
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(sedp(writer()));
        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(surfaced.seen().is_empty(), "fixture: deferred");

        fsm.depart();
        sleep_until_age(&fsm, Duration::from_millis(150));
        fsm.touch_participant_by_prefix(&PREFIX);
        assert_eq!(marks(&fsm), Some(1), "fixture: the mark is counted");
        assert!(
            surfaced.seen().is_empty(),
            "nothing surfaces after our farewell"
        );
    }

    /// A participant first heard after the boundary is trusted from its first
    /// announcement: the probation verdict never judges it, however quiet it
    /// stays (the packets of a process that died before we started are all
    /// drained in our first milliseconds).
    #[test]
    fn a_peer_first_heard_after_the_boundary_is_never_judged_by_the_probation() {
        let (fsm, _surfaced) = fsm_with_listener();
        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done());
        fsm.handle_spdp(spdp());
        sleep_until_age(&fsm, Duration::from_millis(300));
        fsm.maybe_complete_probation();
        assert_eq!(marks(&fsm), Some(0), "fixture: never heard again");
        assert!(fsm.has_participant(&participant()));
    }

    /// A participant the verdict keeps on one mark earned before the boundary
    /// may not surface its matches, yet
    /// discovery gave its readers a ReaderProxy in every local reliable
    /// writer. If it dies unconfirmed it is purged one second after it was
    /// last heard (its SEDP here), not at its lease, with its SEDP requeued
    /// in case it was alive after all; not before that second.
    #[test]
    fn a_participant_kept_on_one_mark_is_purged_after_a_second_of_silence() {
        let (fsm, surfaced) = fsm_with_listener();
        fsm.handle_spdp(spdp());
        sleep_until_age(&fsm, Duration::from_millis(150));
        fsm.handle_sedp(sedp(writer()));
        assert_eq!(marks(&fsm), Some(1), "its SEDP is its one mark");
        assert!(
            fsm.uptime() < Duration::from_millis(250),
            "fixture: that mark lands before the boundary"
        );

        sleep_until(&fsm, Duration::from_millis(260));
        sleep_until_age(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.has_participant(&participant()), "kept by its verdict");

        sleep_until_age(&fsm, Duration::from_millis(1_050));
        fsm.maybe_complete_probation();
        assert!(
            fsm.has_participant(&participant()),
            "900 ms after its SEDP: not silent for long enough"
        );

        sleep_until_age(&fsm, Duration::from_millis(1_250));
        fsm.maybe_complete_probation();
        assert!(
            !fsm.has_participant(&participant()),
            "silent for a second without becoming eligible: purged"
        );
        assert!(fsm.find_writers_for_topic("ProbationTopic").is_empty());
        assert!(surfaced.seen().is_empty());
        assert_eq!(
            recover_read(Arc::as_ref(&fsm.pending_sedp), "test requeued").len(),
            1,
            "its SEDP waits for an SPDP that would rebuild it"
        );
    }

    /// The silence rule is confined to participants that never became match
    /// eligible: an eligible one lives by its lease (RTPS 2.5 8.5.3.2),
    /// however quiet.
    #[test]
    fn a_match_eligible_participant_lives_by_its_lease_not_by_its_silence() {
        let (fsm, surfaced) = fsm_with_listener();
        fsm.handle_spdp(spdp());
        sleep_until_age(&fsm, Duration::from_millis(110));
        fsm.handle_sedp(sedp(writer()));
        sleep_until_age(&fsm, Duration::from_millis(220));
        fsm.touch_participant_by_prefix(&PREFIX);
        assert_eq!(marks(&fsm), Some(2), "fixture: eligible");

        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert_eq!(surfaced.seen(), vec![writer()]);
        sleep_until_age(&fsm, Duration::from_millis(1_400));
        fsm.maybe_complete_probation();
        assert!(fsm.has_participant(&participant()));
    }

    /// The catch-up defers a pairing only while the participant is not
    /// matchable, re-checked under the pending lock: a participant that
    /// became matchable meanwhile (its replay may already have drained the
    /// list) gets its match surfaced by the caller, not parked where nothing
    /// will replay it.
    #[test]
    fn the_catch_up_does_not_defer_a_match_its_participant_already_earned() {
        let (fsm, _surfaced) = fsm_with_listener();
        fsm.handle_spdp(spdp());
        sleep_until_age(&fsm, Duration::from_millis(110));
        fsm.handle_sedp(sedp(writer()));
        sleep_until_age(&fsm, Duration::from_millis(220));
        fsm.touch_participant_by_prefix(&PREFIX);
        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.is_participant_confirmed(&PREFIX), "fixture: confirmed");
        let pending_before =
            recover_read(Arc::as_ref(&fsm.pending_notifications), "test pending").len();

        let endpoint = fsm
            .find_writers_for_topic("ProbationTopic")
            .pop()
            .expect("the writer is known");
        assert!(
            !fsm.defer_catch_up_match(&endpoint),
            "surfaced by the caller, not deferred"
        );
        assert_eq!(
            recover_read(Arc::as_ref(&fsm.pending_notifications), "test pending").len(),
            pending_before
        );
    }

    /// One rule surfaces a participant's matches, on every path: one first
    /// heard during our probation surfaces once match eligible or once it
    /// earns a mark after the boundary. A SEDP it sends after the boundary
    /// that is no mark (within 100 ms of its one mark, earned before the
    /// boundary) is deferred like the ones the drain put back, and its next
    /// mark surfaces both. The live path must not surface it at once merely
    /// because the participant is known while the drain holds back the
    /// participant's earlier SEDP.
    #[test]
    fn a_sedp_after_the_boundary_waits_like_the_ones_before_it() {
        let (fsm, surfaced) = fsm_with_listener();
        fsm.handle_spdp(spdp());
        sleep_until_age(&fsm, Duration::from_millis(200));
        fsm.handle_sedp(sedp(writer()));
        let first_mark = std::time::Instant::now();
        assert!(
            fsm.uptime() < Duration::from_millis(250),
            "fixture: its one mark lands before the boundary"
        );
        sleep_until(&fsm, Duration::from_millis(260));
        sleep_until_age(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done());
        let second = GUID::new(PREFIX, [0x00, 0x00, 0x02, 0x02]);
        fsm.handle_sedp(sedp(second));
        assert_eq!(marks(&fsm), Some(1), "fixture: no second mark yet");
        assert!(
            surfaced.seen().is_empty(),
            "not surfaced before the participant is eligible"
        );

        let mark_due = first_mark + Duration::from_millis(110);
        if let Some(left) = mark_due.checked_duration_since(std::time::Instant::now()) {
            std::thread::sleep(left);
        }
        fsm.touch_participant_by_prefix(&PREFIX);
        let mut seen = surfaced.seen();
        seen.sort_by_key(|guid| guid.as_bytes());
        assert_eq!(seen, vec![writer(), second]);
    }

    /// The SPDP path applies the same rule: an announcement of a participant
    /// first heard during the probation that leaves it not match eligible
    /// (here 60 ms after we first heard it: no count, no mark) surfaces
    /// nothing. Before: every SPDP after the boundary replayed whatever was
    /// deferred for its participant.
    #[test]
    fn an_spdp_after_the_boundary_surfaces_nothing_for_a_participant_not_eligible() {
        let (fsm, surfaced) = fsm_with_listener();
        sleep_until(&fsm, Duration::from_millis(200));
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(sedp(writer()));
        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done());
        fsm.handle_spdp(spdp());
        assert!(
            peer_age(&fsm) < Duration::from_millis(100),
            "fixture: the SPDP counts nothing"
        );
        assert!(surfaced.seen().is_empty());
    }

    /// The other side of the same verdict: a peer first heard late in our
    /// probation and never again is still judged, at its own age, and
    /// purged with its SEDP requeued for the SPDP that would rebuild it.
    #[test]
    fn a_peer_first_heard_late_in_probation_and_never_again_is_purged_at_its_own_age() {
        let (fsm, surfaced) = fsm_with_listener();
        sleep_until(&fsm, Duration::from_millis(200));
        fsm.handle_spdp(spdp());
        fsm.handle_sedp(sedp(writer()));
        sleep_until(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(fsm.has_participant(&participant()), "not judged yet");

        sleep_until_age(&fsm, Duration::from_millis(260));
        fsm.maybe_complete_probation();
        assert!(
            !fsm.has_participant(&participant()),
            "purged at its own age"
        );
        assert!(surfaced.seen().is_empty());
        assert_eq!(
            recover_read(Arc::as_ref(&fsm.pending_sedp), "test requeued").len(),
            1,
            "its SEDP waits for an SPDP that would rebuild it"
        );
    }

    /// Park the real drain of the boundary right after its eligibility
    /// snapshot, still holding the pending lock: returns the signal that it
    /// is parked and the release.
    fn park_the_drain(
        fsm: &DiscoveryFsm,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (parked, is_parked) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let parked = Mutex::new(parked);
        let released = Mutex::new(released);
        *fsm.drain_parked_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
            let _ = parked.lock().unwrap_or_else(|e| e.into_inner()).send(());
            let _ = released
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv_timeout(Duration::from_secs(5));
        }));
        (is_parked, release)
    }

    /// The mark that confirms a peer can land while the boundary's drain is
    /// between its eligibility snapshot (not eligible: the entry is put back)
    /// and its publication of `probation_purge_done`. The replay waits for
    /// that publication instead of reading the flag as still false. Runs the
    /// real drain, parked at that point.
    #[test]
    fn a_mark_racing_the_drain_still_surfaces_the_match() {
        let (fsm, surfaced) = fsm_with_listener();
        let fsm = Arc::new(fsm);
        fsm.handle_spdp(spdp());
        std::thread::sleep(Duration::from_millis(110));
        fsm.handle_sedp(sedp(writer()));
        let first_mark = std::time::Instant::now();
        assert_eq!(marks(&fsm), Some(1));
        sleep_until(&fsm, Duration::from_millis(260));
        let mark_due = first_mark + Duration::from_millis(110);
        if let Some(left) = mark_due.checked_duration_since(std::time::Instant::now()) {
            std::thread::sleep(left);
        }

        let (is_parked, release) = park_the_drain(&fsm);
        let boundary = {
            let fsm = Arc::clone(&fsm);
            std::thread::spawn(move || fsm.maybe_complete_probation())
        };
        is_parked
            .recv_timeout(Duration::from_secs(5))
            .expect("the drain parked after its snapshot");
        let marker = {
            let fsm = Arc::clone(&fsm);
            std::thread::spawn(move || fsm.touch_participant_by_prefix(&PREFIX))
        };
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(marks(&fsm), Some(2), "the mark landed during the drain");
        assert!(surfaced.seen().is_empty());
        let _ = release.send(());
        boundary.join().expect("boundary thread");
        marker.join().expect("marker thread");
        assert_eq!(
            surfaced.seen(),
            vec![writer()],
            "replayed once the drain published"
        );
    }

    /// The same race through an SPDP: the announcement whose mark makes the
    /// peer eligible lands while the real drain is parked after its snapshot.
    /// The SPDP path reads the boundary flag under the pending lock, waits
    /// for the publication, and replays what the drain put back. Before: it
    /// read the flag as false, skipped the replay, and the match waited for
    /// the next SPDP (possibly tens of seconds away).
    #[test]
    fn an_spdp_racing_the_drain_still_surfaces_the_match() {
        let (fsm, surfaced) = fsm_with_listener();
        let fsm = Arc::new(fsm);
        fsm.handle_spdp(spdp());
        std::thread::sleep(Duration::from_millis(110));
        fsm.handle_sedp(sedp(writer()));
        let first_mark = std::time::Instant::now();
        assert_eq!(marks(&fsm), Some(1));
        sleep_until(&fsm, Duration::from_millis(260));
        let mark_due = first_mark + Duration::from_millis(110);
        if let Some(left) = mark_due.checked_duration_since(std::time::Instant::now()) {
            std::thread::sleep(left);
        }

        let (is_parked, release) = park_the_drain(&fsm);
        let boundary = {
            let fsm = Arc::clone(&fsm);
            std::thread::spawn(move || fsm.maybe_complete_probation())
        };
        is_parked
            .recv_timeout(Duration::from_secs(5))
            .expect("the drain parked after its snapshot");
        let announcer = {
            let fsm = Arc::clone(&fsm);
            std::thread::spawn(move || fsm.handle_spdp(spdp()))
        };
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            marks(&fsm),
            Some(2),
            "the SPDP's mark landed during the drain"
        );
        assert!(surfaced.seen().is_empty());
        let _ = release.send(());
        boundary.join().expect("boundary thread");
        announcer.join().expect("announcer thread");
        assert_eq!(
            surfaced.seen(),
            vec![writer()],
            "replayed once the drain published"
        );
    }
}

/// A participant's handshake session lives and dies with the participant
/// (DDS Security v1.1 Sec.9.3.4: a participant discovered is authenticated;
/// one removed from discovery is no longer known to be anyone).
#[cfg(all(test, feature = "security"))]
mod session_lifecycle_tests {
    use super::DiscoveryFsm;
    use crate::core::discovery::GUID;
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::protocol::discovery::SpdpData;
    use crate::security::handshake::HandshakeMachine;
    use crate::security::test_pki::{
        local_machine_with_completed_peer, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
    };
    use std::sync::Arc;
    use std::time::Duration;

    /// The local participant: the lower prefix, so the initiator (DDS
    /// Security v1.1 Sec.9.3.4).
    const LOCAL: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x11; 6]);
    /// The peer.
    const PEER: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x21; 6]);

    fn peer() -> GUID {
        GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT)
    }

    /// The peer's announcement: a security participant (identity token).
    fn announcement(lease_duration_ms: u64) -> SpdpData {
        SpdpData {
            participant_guid: peer(),
            lease_duration_ms,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: Some(TEST_IDENTITY_CERT_PEM.to_vec()),
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        }
    }

    /// An FSM whose machine already completed with the peer, and that knows
    /// the peer from `lease_duration_ms`.
    fn authenticated_peer(lease_duration_ms: u64) -> (DiscoveryFsm, Arc<HandshakeMachine>) {
        let machine = local_machine_with_completed_peer(LOCAL, PEER, None);
        let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.set_handshake_machine(
            Arc::clone(&machine),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.register_builtin_writer_keys_for_tests();
        fsm.register_builtin_reader_keys_for_tests();
        fsm.handle_spdp(announcement(lease_duration_ms));
        assert!(fsm.is_participant_known(&PEER));
        assert!(machine.is_authenticated(&peer()), "the fixture completed");
        (fsm, machine)
    }

    /// `register_builtin_reader_keys` mints one key per secure builtin
    /// reader it serves (SEDP pub/sub secure, ParticipantMessage secure),
    /// each ready for `encode_datareader_submessage`; `remote_builtin_
    /// reader_materials` finds the PEER's announced copy of the same key
    /// id by prefix alone, never by mixing up which local reader minted
    /// what (the destination of a `receive_writer_key_for_tests`-style
    /// install below is a GUID, so a wrong one is a wrong lookup, not a
    /// crash); `local_builtin_reader_material_for` maps a peer's secure
    /// writer id to OUR matching reader's key via `builtin_peer_entity_id`.
    ///
    /// `builtin_peer_entity_id` mapping `0xC2` to the WRONG kind
    /// (say `0xC4` instead of `0xC7`) would make `local_builtin_reader_
    /// material_for` look up a reader we never minted a key for, returning
    /// `None` where this test expects `Some` -- caught directly below.
    #[test]
    fn builtin_reader_keys_are_minted_and_found_by_the_matching_writer_id() {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
        };
        let (fsm, _machine) = authenticated_peer(30_000);

        // Our own key, ready for OUR ACKNACK to the peer's secure SEDP
        // publications writer.
        assert!(
            fsm.local_builtin_reader_material_for(
                &PEER,
                &RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER
            )
            .is_some(),
            "a minted reader key must be found through the peer's writer id"
        );

        // An unauthenticated peer gets nothing, even for the same writer id.
        assert!(
            fsm.local_builtin_reader_material_for(
                &[0x44; 12],
                &RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER
            )
            .is_none(),
            "an unauthenticated peer's writer must not resolve to our reader key"
        );

        // A non-builtin entity id has no mirrored reader at all.
        assert!(
            fsm.local_builtin_reader_material_for(&PEER, &[0, 0, 1, 0x02])
                .is_none(),
            "a plain USER writer id names no single local reader"
        );

        // The peer's OWN reader key, once "received" (as the volatile
        // dispatcher installs it): found by prefix and key id, under the
        // reader entity id it actually announced -- never under the
        // writer's.
        let (key_id, material) =
            crate::security::crypto::data_keys::WriterKey::mint().expect("mint");
        let peer_reader = GUID::new(PEER, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER);
        fsm.receive_writer_key_for_tests(
            PEER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            u64::from(key_id),
            material,
        );
        let found = fsm.remote_builtin_reader_materials(&PEER, u64::from(key_id));
        assert_eq!(found.len(), 1, "exactly the one reader key just installed");
        assert_eq!(found[0].0, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER);
        // Never found under the WRITER materials query: the two
        // CryptoTokens classes are disjoint.
        assert!(fsm
            .remote_builtin_writer_materials(&PEER, u64::from(key_id))
            .is_empty());
        let _ = peer_reader;
    }

    /// Under NONE governance no reader material is handed out, so ACKNACK
    /// (normal and repair) are not GCM-protected: the kind is honoured.
    /// `send_sedp_acknack`/`request_secure_sedp_repair` both call this
    /// function unconditionally whenever a key exists, regardless of
    /// governance, so this function's own early refusal is what enforces
    /// it, pinned directly here.
    ///
    /// Without the `discovery_protection_kind() == Some(None)` check, this
    /// test's first assertion would fail (`Some` instead of `None`).
    #[test]
    fn local_builtin_reader_material_is_withheld_under_none_governance() {
        use crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER;
        use crate::security::access::{DiscoveryGovernance, DomainRule, ProtectionKind};

        let (mut fsm, _machine) = authenticated_peer(30_000);
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![],
        })));

        assert!(
            fsm.local_builtin_reader_material_for(
                &PEER,
                &RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER
            )
            .is_none(),
            "governance NONE means no cryptographic transformation on this channel: the \
             minted reader key must not be handed out, even though it exists and the peer \
             is authenticated"
        );

        // Sanity: the SAME fixture, under a DIFFERENT (or no) governance,
        // DOES hand out the material -- this is the NONE case specifically,
        // not a fixture that never had a key to begin with.
        fsm.set_discovery_governance(None);
        assert!(
            fsm.local_builtin_reader_material_for(
                &PEER,
                &RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER
            )
            .is_some(),
            "fixture: without a NONE governance the same key is handed out normally"
        );
    }

    /// Explicit retirement/departure coverage for reader keys (the restart
    /// test filters them out of its own assertion, so it proves nothing about
    /// them). Reader keys live in the SAME `DataKeyStore` as
    /// writer keys (by design), so the EXISTING
    /// prefix-keyed retirement/removal already covers them -- this test
    /// pins that it actually does, for the REMOTE half: a departed
    /// participant's reader key must be gone, not just its writer key.
    #[test]
    fn remote_reader_keys_are_removed_when_the_participant_departs() {
        use crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER;
        let (fsm, _machine) = authenticated_peer(30_000);
        let (key_id, material) = crate::security::crypto::data_keys::WriterKey::mint().unwrap();
        fsm.receive_writer_key_for_tests(
            PEER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            u64::from(key_id),
            material,
        );
        assert_eq!(
            fsm.remote_builtin_reader_materials(&PEER, u64::from(key_id))
                .len(),
            1,
            "fixture: the remote reader key is installed"
        );

        fsm.remove_participant(GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT));

        assert!(
            fsm.remote_builtin_reader_materials(&PEER, u64::from(key_id))
                .is_empty(),
            "a departed participant's reader key must be removed with the rest of it"
        );
    }

    /// The LOCAL half: this participant's own ParticipantMessageSecure/SEDP
    /// reader keys are fresh material after a replaced (re-authenticated)
    /// session, exactly as the writer keys already are
    /// (`prepare_peer_key_replacement`'s loop is generic over any builtin
    /// entity id with the local prefix, reader or writer).
    ///
    /// The filter of `prepare_peer_key_replacement` must stay "any builtin
    /// entity id": narrowing it to "a WRITER entity id specifically" (e.g.
    /// requiring the low nibble to be `0xC2`/`0xC3`) would leave this
    /// reader's key material byte-identical across the replacement,
    /// failing the inequality assertion below.
    #[test]
    fn local_builtin_reader_keys_are_rotated_on_peer_reauthentication() {
        use crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER;
        let (fsm, _machine) = authenticated_peer(30_000);
        let our_reader = GUID::new(LOCAL, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER);
        let (before_id, before) = fsm
            .writer_keys
            .as_ref()
            .expect("registered")
            .material_for_writer(&our_reader)
            .expect("minted");

        fsm.peer_authenticated(peer(), true);

        let (after_id, after) = fsm
            .writer_keys
            .as_ref()
            .expect("registered")
            .material_for_writer(&our_reader)
            .expect("still minted, under a new id");
        assert!(
            before_id != after_id || !before.same_material(&after),
            "a replaced session must mint FRESH reader key material, not keep the old one"
        );
    }

    /// The ParticipantMessageSecure reader's
    /// key must be minted under this participant's LIVELINESS protection
    /// kind (Sec.9.4.1.2.5.5), not its discovery one -- the two SEDP
    /// readers stay keyed under the discovery kind, unaffected.
    ///
    /// Keying all three readers off `discovery_protection_kind()` in
    /// `register_builtin_reader_keys` would make the
    /// ParticipantMessageSecure reader AES256_GCM here (ENCRYPT), not the
    /// AES256_GMAC its OWN SIGN liveliness kind demands.
    #[test]
    fn participant_message_secure_reader_key_follows_liveliness_not_discovery_protection() {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
        };
        use crate::security::access::permissions::DomainRule;
        use crate::security::access::{DiscoveryGovernance, ProtectionKind};
        use crate::security::crypto::secure_submessage::Transformation;

        let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: true,
            // Discovery: ENCRYPT (-> AES256_GCM). Liveliness: SIGN only
            // (-> AES256_GMAC). Deliberately different, so code that
            // reads the wrong field is caught by either assertion below.
            discovery_protection_kind: ProtectionKind::Encrypt,
            liveliness_protection_kind: ProtectionKind::Sign,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![],
        })));
        fsm.register_builtin_reader_keys_for_tests();

        let (sedp_id, sedp_material) = fsm
            .writer_keys
            .as_ref()
            .expect("registered")
            .material_for_writer(&GUID::new(
                LOCAL,
                RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            ))
            .expect("minted");
        assert_eq!(sedp_material.transformation, Transformation::Aes256Gcm);
        let _ = sedp_id;

        let (pm_id, pm_material) = fsm
            .writer_keys
            .as_ref()
            .expect("registered")
            .material_for_writer(&GUID::new(
                LOCAL,
                RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,
            ))
            .expect("minted");
        assert_eq!(
            pm_material.transformation,
            Transformation::Aes256Gmac,
            "ParticipantMessageSecure must follow the LIVELINESS kind (SIGN), not discovery's \
             (ENCRYPT)"
        );
        let _ = pm_id;
    }

    /// The change order of SEDP (`admits_sedp_change`): per endpoint and per
    /// builtin topic, a change older than the last applied is refused, the
    /// same number again passes, another endpoint's later numbers block
    /// nothing, a number below 1 is refused; forgotten with the participant
    /// and when it authenticates again.
    #[test]
    fn an_sedp_change_older_than_the_last_applied_about_its_endpoint_is_refused() {
        use super::SedpChannel::{Plain, Secure};
        let (fsm, _machine) = authenticated_peer(30_000);
        let a = GUID::new(PEER, [0, 0, 0x12, 0x02]);
        let b = GUID::new(PEER, [0, 0, 0x13, 0x02]);
        assert!(fsm.admits_sedp_change(Secure, &a, 7));
        assert!(fsm.admits_sedp_change(Secure, &a, 8), "its dispose");
        assert!(
            !fsm.admits_sedp_change(Secure, &a, 7),
            "the announcement replayed"
        );
        assert!(fsm.admits_sedp_change(Secure, &a, 8), "a retransmission");
        assert!(fsm.admits_sedp_change(Secure, &b, 3), "another endpoint");
        assert!(fsm.admits_sedp_change(Plain, &a, 7), "another topic");
        assert!(!fsm.admits_sedp_change(Plain, &b, 0));
        assert!(!fsm.admits_sedp_change(Plain, &b, -5));

        // Authenticated again: a new process numbers from 1.
        fsm.forget_endpoints_of(PEER);
        assert!(fsm.admits_sedp_change(Secure, &a, 1));

        assert!(fsm.admits_sedp_change(Secure, &a, 9));
        fsm.remove_participant(peer());
        assert!(
            fsm.admits_sedp_change(Secure, &a, 1),
            "forgotten with the participant"
        );
    }

    /// An endpoint GUID of the participant `prefix`, the `n`th one.
    fn tracked_endpoint(prefix: [u8; 12], n: usize) -> GUID {
        let n = u32::try_from(n)
            .expect("small endpoint index")
            .to_be_bytes();
        GUID::new(prefix, [n[1], n[2], n[3], 2])
    }

    #[test]
    fn secure_membership_is_capped_per_participant() {
        let (fsm, _machine) = authenticated_peer(30_000);
        let cap = super::SECURE_ENDPOINTS_CAP_PER_PREFIX;
        let endpoint = |n: usize| tracked_endpoint(PEER, n);
        for n in 0..cap {
            assert!(fsm.track_secure_endpoint(endpoint(n)));
        }
        let next = endpoint(cap);
        assert!(
            !fsm.track_secure_endpoint(next),
            "a prefix announcing past its share is refused"
        );
        assert_eq!(
            fsm.metrics
                .sedp_tracking_refused
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(
            fsm.track_secure_endpoint(tracked_endpoint([0x33; 12], 0)),
            "one prefix's full table refuses nobody else"
        );
        assert!(
            fsm.track_secure_endpoint(endpoint(0)),
            "existing memberships still work"
        );
        fsm.remove_remote_endpoint(endpoint(0));
        assert!(!fsm
            .secure_endpoints
            .lock()
            .expect("lock")
            .contains(&endpoint(0)));
        assert!(
            fsm.track_secure_endpoint(next),
            "retirement reclaimed one slot"
        );
        assert_eq!(
            fsm.secure_endpoints
                .lock()
                .expect("lock")
                .iter()
                .filter(|known| known.prefix == PEER)
                .count(),
            cap
        );
        fsm.forget_sedp_change_order(&PEER);
        assert!(fsm
            .secure_endpoints
            .lock()
            .expect("lock")
            .iter()
            .all(|known| known.prefix != PEER));
    }

    /// A plain announcement must not resurrect an endpoint a protected
    /// dispose removed. Its secure membership is gone with the disposal, so
    /// the sequence tombstone is what still refuses the plain change - with
    /// a governance document on our side and without one.
    #[test]
    fn a_plain_announcement_cannot_resurrect_a_disposed_secure_endpoint() {
        use super::SedpChannel::Secure;
        use crate::security::access::permissions::DomainRule;
        use crate::security::access::{DiscoveryGovernance, ProtectionKind};

        let disposed = tracked_endpoint(PEER, 7);
        let never_secure = tracked_endpoint(PEER, 8);

        for governed in [false, true] {
            let (mut fsm, _machine) = authenticated_peer(30_000);
            if governed {
                fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
                    domains: vec![0],
                    domain_ranges: vec![],
                    allow_unauthenticated: true,
                    enable_join_access_control: true,
                    discovery_protection_kind: ProtectionKind::Encrypt,
                    liveliness_protection_kind: ProtectionKind::None,
                    rtps_protection_kind: ProtectionKind::None,
                    topic_rules: vec![],
                })));
            }
            assert!(
                !fsm.ignores_plain_sedp_about(&disposed),
                "fixture, governed={}: nothing announced yet",
                governed
            );
            assert!(fsm.admits_sedp_change(Secure, &disposed, 3));
            assert!(fsm.track_secure_endpoint(disposed));
            fsm.remove_remote_endpoint(disposed);
            assert!(
                fsm.ignores_plain_sedp_about(&disposed),
                "governed={}: a plain change about a disposed secure endpoint is ignored",
                governed
            );
            assert!(
                !fsm.ignores_plain_sedp_about(&never_secure),
                "governed={}: an endpoint never announced securely is not",
                governed
            );
        }
    }

    /// A single 4096-entry limit for the whole process would refuse part of
    /// this load: three hundred participants with sixteen endpoints each is
    /// 4800 identities. Every one is admitted, and a prefix announcing past
    /// its own share is the only one refused.
    #[test]
    fn sedp_tracking_admits_many_participants_and_caps_each_prefix_alone() {
        use super::SedpChannel::Secure;
        let (fsm, _machine) = authenticated_peer(30_000);
        let prefix = |n: usize| {
            let n = u16::try_from(n).expect("small prefix index").to_be_bytes();
            let mut prefix = [0x40; 12];
            prefix[10] = n[0];
            prefix[11] = n[1];
            prefix
        };
        for p in 0..300 {
            for e in 0..16 {
                assert!(
                    fsm.admits_sedp_change(Secure, &tracked_endpoint(prefix(p), e), 1),
                    "participant {} endpoint {}",
                    p,
                    e
                );
            }
        }
        assert_eq!(fsm.sedp_change_order.lock().expect("lock").len(), 300 * 16);

        let hog = prefix(300);
        let cap = super::SEDP_CHANGE_ORDER_CAP_PER_PREFIX;
        for n in 0..cap {
            assert!(fsm.admits_sedp_change(Secure, &tracked_endpoint(hog, n), 1));
        }
        assert!(
            !fsm.admits_sedp_change(Secure, &tracked_endpoint(hog, cap), 1),
            "the prefix at its share is refused"
        );
        assert!(
            fsm.admits_sedp_change(Secure, &tracked_endpoint(prefix(301), 0), 1),
            "its refusal does not reach another prefix"
        );
    }

    #[test]
    fn sedp_order_is_capped_per_prefix_and_reclaims_retired_endpoints() {
        use super::SedpChannel::Secure;
        let (fsm, _machine) = authenticated_peer(30_000);
        let cap = super::SEDP_CHANGE_ORDER_CAP_PER_PREFIX;
        let endpoint = |n: usize| tracked_endpoint(PEER, n);
        for n in 0..cap {
            assert!(fsm.admits_sedp_change(Secure, &endpoint(n), 1));
        }
        assert!(
            fsm.admits_sedp_change(Secure, &endpoint(0), 3),
            "a known endpoint keeps progressing at capacity"
        );
        assert!(!fsm.admits_sedp_change(Secure, &endpoint(cap), 1));
        assert_eq!(
            fsm.metrics
                .sedp_tracking_refused
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(fsm.sedp_change_order.lock().expect("lock").len(), cap);

        fsm.remove_remote_endpoint(endpoint(0));
        assert!(
            !fsm.admits_sedp_change(Secure, &endpoint(0), 2),
            "a retired endpoint's older announcement is still refused"
        );
        assert!(
            fsm.admits_sedp_change(Secure, &endpoint(cap), 1),
            "its retirement is reclaimed for a new identity"
        );
        assert_eq!(fsm.sedp_change_order.lock().expect("lock").len(), cap);

        fsm.forget_sedp_change_order(&PEER);
        assert!(fsm.sedp_change_order.lock().expect("lock").is_empty());
        assert!(fsm.admits_sedp_change(Secure, &endpoint(cap), 1));
    }

    /// Every participant is asked with the one future_challenge of its
    /// identity (DDS Security v1.1 Sec.9.3.3, Table 52), whatever its
    /// announcement says: an HDDS participant without
    /// `CAP_ONE_FUTURE_CHALLENGE` (1.4.x) cannot authenticate with this
    /// release, and is not challenged otherwise for it. Here we are the
    /// responder (the higher prefix), so its announcement makes us ask.
    #[test]
    fn a_participant_is_asked_with_the_challenge_of_its_identity() {
        use crate::core::rtps_constants::HDDS_VENDOR_ID_U16;
        use crate::protocol::group::{CAP_ONE_FUTURE_CHALLENGE, CAP_SPEC_GROUP_COHERENT};
        for caps in [
            Some(CAP_SPEC_GROUP_COHERENT),
            Some(CAP_SPEC_GROUP_COHERENT | CAP_ONE_FUTURE_CHALLENGE),
        ] {
            let machine = Arc::new(HandshakeMachine::new());
            let mut fsm = DiscoveryFsm::new(
                GUID::new(
                    crate::security::test_pki::bound_test_prefix([0xF1; 6]),
                    RTPS_ENTITYID_PARTICIPANT,
                ),
                30_000,
            );
            fsm.set_handshake_machine(
                Arc::clone(&machine),
                TEST_IDENTITY_CERT_PEM.to_vec(),
                TEST_IDENTITY_KEY_PEM.to_vec(),
            );
            let mut data = announcement(30_000);
            data.vendor_id = Some(HDDS_VENDOR_ID_U16);
            data.hdds_capabilities = caps;
            fsm.handle_spdp(data.clone());
            let first = machine.awaited_challenge(&peer()).expect("we asked");
            let _ = machine.tick(std::time::Instant::now() + Duration::from_secs(31));
            fsm.handle_spdp(data);
            let second = machine.awaited_challenge(&peer()).expect("we asked again");
            assert_eq!(first, second, "capabilities {:?}", caps);
        }
    }

    /// The burst-phase zombie purge (Tier 1 of
    /// `purge_zombie_confirmed_participants`: an HDDS participant at two
    /// counted SPDPs, silent for 300 ms) never removes a participant that
    /// completed authentication: it is alive, and its removal would drop the
    /// session and spend its re-authentication. Its lease still applies.
    #[test]
    fn an_authenticated_participant_is_no_burst_phase_zombie() {
        let age = |fsm: &DiscoveryFsm, silent: Duration| {
            let mut db = super::recover_write(Arc::as_ref(&fsm.db), "test age");
            let p = db.get_mut(&peer()).expect("fixture: known");
            p.vendor_id = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
            p.spdp_count = 2;
            p.last_seen = std::time::Instant::now() - silent;
        };

        let (fsm, machine) = authenticated_peer(30_000);
        age(&fsm, Duration::from_millis(500));
        fsm.purge_zombie_confirmed_participants();
        assert!(
            fsm.is_participant_known(&PEER) && machine.is_authenticated(&peer()),
            "an authenticated participant was purged as a burst-phase zombie"
        );

        // The other side of the rule: the same participant past its lease is
        // purged, session and all.
        let (fsm, machine) = authenticated_peer(1_000);
        age(&fsm, Duration::from_millis(1_500));
        fsm.purge_zombie_confirmed_participants();
        assert!(
            !fsm.is_participant_known(&PEER) && !machine.has_session(&peer()),
            "an authenticated participant past its lease must still be purged"
        );

        // And one not authenticated is still judged by the 300 ms.
        let fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.handle_spdp(announcement(30_000));
        age(&fsm, Duration::from_millis(500));
        fsm.purge_zombie_confirmed_participants();
        assert!(
            !fsm.is_participant_known(&PEER),
            "a participant with no session must still be purged as a burst-phase zombie"
        );
    }

    /// An authenticated participant first heard during our probation that
    /// died with fewer than two counted SPDPs is removed by its lease
    /// (DDSI-RTPS 2.5 8.5.3.2 leaseDuration, 8.5.3.3): the authentication
    /// exemption spares it the probation heuristics, never its lease.
    #[test]
    fn a_dead_authenticated_participant_is_purged_by_its_lease_whatever_its_spdp_count() {
        let (fsm, machine) = authenticated_peer(1_000);
        {
            let mut db = super::recover_write(Arc::as_ref(&fsm.db), "test age");
            let p = db.get_mut(&peer()).expect("fixture: known");
            p.vendor_id = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
            p.spdp_count = 1;
            p.last_seen = std::time::Instant::now() - Duration::from_secs(10);
            p.created_at = p.last_seen;
        }
        fsm.purge_unconfirmed_participants();
        fsm.purge_zombie_confirmed_participants();
        assert!(
            !fsm.is_participant_known(&PEER),
            "a dead authenticated participant 10x past its lease is immortal (session kept: {})",
            machine.is_authenticated(&peer())
        );
        assert!(
            !machine.is_authenticated(&peer()),
            "its session goes with it"
        );
    }

    /// The same shape with no session, first heard after our probation (so
    /// no probation heuristic applies): one counted SPDP, lease expired, it
    /// is removed by the same lease rule.
    #[test]
    fn a_dead_participant_heard_after_the_probation_is_purged_by_its_lease() {
        let fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
        std::thread::sleep(Duration::from_millis(300));
        fsm.maybe_complete_probation();
        fsm.handle_spdp(announcement(1_000));
        {
            let mut db = super::recover_write(Arc::as_ref(&fsm.db), "test age");
            let p = db.get_mut(&peer()).expect("fixture: known");
            p.vendor_id = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
            p.spdp_count = 1;
            p.last_seen = std::time::Instant::now() - Duration::from_secs(10);
        }
        fsm.purge_unconfirmed_participants();
        fsm.purge_zombie_confirmed_participants();
        assert!(
            !fsm.is_participant_known(&PEER),
            "a dead participant (spdp_count 1) 10x past its lease is never purged"
        );
    }

    /// The probation purge (`fails_probation`) never removes a participant
    /// that completed authentication, silent or not: it is alive, and its
    /// removal would drop the session and spend its re-authentication.
    #[test]
    fn an_authenticated_participant_never_fails_the_probation() {
        let silence = |fsm: &DiscoveryFsm| {
            let mut db = super::recover_write(Arc::as_ref(&fsm.db), "test silence");
            let p = db.get_mut(&peer()).expect("fixture: known");
            p.last_seen = std::time::Instant::now() - Duration::from_secs(2);
            p.created_at = p.last_seen;
        };

        let (fsm, machine) = authenticated_peer(30_000);
        silence(&fsm);
        fsm.purge_unconfirmed_participants();
        assert!(
            fsm.is_participant_known(&PEER) && machine.is_authenticated(&peer()),
            "an authenticated participant was purged by the probation"
        );

        // The other side: the same participant with no session is purged.
        let fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.handle_spdp(announcement(30_000));
        silence(&fsm);
        fsm.purge_unconfirmed_participants();
        assert!(
            !fsm.is_participant_known(&PEER),
            "fixture: a silent participant of the probation with no session is purged"
        );
    }

    /// A participant removed from discovery takes its session with it, and
    /// when it announces itself again we, the initiator, authenticate it
    /// again. `start` must not refuse to begin over the `Complete` session the
    /// removal would otherwise leave behind: a peer that came back with a new
    /// process - and no keys - would wait for an AuthRequest that never came.
    #[test]
    fn a_participant_back_after_its_removal_is_authenticated_again() {
        let (fsm, machine) = authenticated_peer(30_000);

        fsm.remove_participant(peer());
        assert!(
            !machine.has_session(&peer()),
            "the session outlived its participant"
        );

        fsm.handle_spdp(announcement(30_000));
        assert!(
            machine.has_session(&peer()) && !machine.is_authenticated(&peer()),
            "a returning participant must be handshaken again, not held to the old keys"
        );
    }

    /// DDS Security v1.1 Sec.7.4.1.6: a plain announcement of an
    /// authenticated participant maintains its liveliness - the participant
    /// outlives a lease it would otherwise have run out - and nothing else.
    #[test]
    fn a_plain_announcement_of_an_authenticated_participant_only_keeps_it_alive() {
        use super::SpdpVerdict;
        let (fsm, _machine) = authenticated_peer(200);
        let admitted = fsm.admitted_locators_and_lease(&PEER);
        assert_eq!(admitted, Some((vec![], 200)), "fixture");

        std::thread::sleep(Duration::from_millis(120));
        let mut moved = announcement(1);
        moved.metatraffic_unicast_locators = vec!["198.51.100.9:7410".parse().expect("addr")];
        moved.default_unicast_locators = vec!["198.51.100.9:7411".parse().expect("addr")];
        moved.vendor_id = Some(0x0101);
        assert_eq!(fsm.admit_spdp(moved), SpdpVerdict::LivelinessOnly);
        std::thread::sleep(Duration::from_millis(120));

        // 240 ms after the first announcement, 120 ms after the second: the
        // lease of 200 ms ran from the second.
        fsm.remove_expired_participant(peer());
        assert!(
            fsm.is_participant_known(&PEER),
            "its liveliness was not taken"
        );
        assert_eq!(
            fsm.admitted_locators_and_lease(&PEER),
            admitted,
            "a plain announcement changed an authenticated participant"
        );
        assert_eq!(fsm.endpoint_registry().get(&peer()), None);
        assert_eq!(fsm.vendor_id_for_participant(&peer()), None);
    }

    /// While the peer's handshake is in progress, a plain announcement under
    /// its prefix (anyone's) does not move its locators: received just before
    /// the handshake completes, it would be the record frozen then (DDS
    /// Security v1.1 Sec.7.4.1.6). Once the session failed, the next
    /// announcement is taken whole and begins the next session.
    #[test]
    fn a_plain_announcement_moves_no_locator_while_the_handshake_is_in_progress() {
        use super::SpdpVerdict;
        let machine = Arc::new(HandshakeMachine::new());
        let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.set_handshake_machine(
            Arc::clone(&machine),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        let at = |host: &str| {
            let mut spdp = announcement(30_000);
            spdp.metatraffic_unicast_locators = vec![format!("{host}:7410").parse().expect("addr")];
            spdp.default_unicast_locators = vec![format!("{host}:7411").parse().expect("addr")];
            spdp
        };
        let real: std::net::SocketAddr = "192.0.2.21:7410".parse().expect("addr");
        let forged: std::net::SocketAddr = "198.51.100.9:7410".parse().expect("addr");

        assert_eq!(fsm.admit_spdp(at("192.0.2.21")), SpdpVerdict::New);
        assert!(
            machine.has_session(&peer()) && !machine.is_authenticated(&peer()),
            "fixture: its handshake is in progress"
        );
        let registered = fsm.endpoint_registry().get(&peer());
        assert!(registered.is_some(), "fixture: an address is registered");

        assert_eq!(fsm.admit_spdp(at("198.51.100.9")), SpdpVerdict::Refreshed);
        assert_eq!(
            fsm.admitted_locators_and_lease(&PEER).map(|(l, _)| l),
            Some(vec![real]),
            "a plain announcement moved the locators of a handshake in progress"
        );
        assert_eq!(fsm.endpoint_registry().get(&peer()), registered);

        // The session fails at its deadline: the next announcement is taken.
        let _ = machine.tick(std::time::Instant::now() + Duration::from_secs(31));
        assert_eq!(fsm.admit_spdp(at("198.51.100.9")), SpdpVerdict::Refreshed);
        assert_eq!(
            fsm.admitted_locators_and_lease(&PEER).map(|(l, _)| l),
            Some(vec![forged])
        );
        assert_ne!(fsm.endpoint_registry().get(&peer()), registered);
        assert!(
            machine.has_session(&peer()) && !machine.is_authenticated(&peer()),
            "the announcement after a failed session begins the next one"
        );
    }

    /// An authentication request from the peer, as its machine sends it.
    fn auth_request_from_peer() -> Vec<u8> {
        crate::security::handshake::tokens::encode_auth_req(
            &crate::security::handshake::tokens::AuthReqToken {
                future_challenge: [0x5E; 32],
            },
        )
        .expect("encode")
    }

    /// During a re-authentication (a parallel session in flight) the keys of
    /// the peer are changing too: what it sends is held, the sealed and then
    /// the plain behind it, and handed back in the order it came when the
    /// keys settle - here, the parallel session abandoned at its deadline.
    #[test]
    fn sedp_during_a_reauthentication_is_held_in_order_until_the_keys_settle() {
        use crate::core::discovery::multicast::{Origin, PacketKind};
        use crate::security::test_pki::TEST_CA_CERT_PEM;
        let (fsm, machine) = authenticated_peer(30_000);
        let replayed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&replayed);
        fsm.set_secure_sedp_replay(Box::new(move |kind, datagram, _, _| {
            seen.lock().expect("lock").push((kind, datagram.to_vec()));
        }));
        let origin = Origin::direct("192.0.2.7:7410".parse().expect("addr"));
        assert!(
            !fsm.park_sedp(PEER, PacketKind::SecureSEDP, b"settled", 0, origin),
            "nothing is held while the keys are settled"
        );

        // The peer asks us, its initiator, to authenticate again.
        match machine
            .on_message(
                peer(),
                &auth_request_from_peer(),
                GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT),
                TEST_IDENTITY_CERT_PEM,
                TEST_IDENTITY_KEY_PEM,
                TEST_CA_CERT_PEM,
            )
            .expect("ordinary traffic")
        {
            crate::security::handshake::HandshakeAction::SendRequest(..) => {}
            other => panic!("fixture: a parallel session begins, got {:?}", other),
        }
        assert!(fsm.park_sedp(PEER, PacketKind::SecureSEDP, b"sealed", 0, origin));
        assert!(
            fsm.park_sedp(PEER, PacketKind::SEDP, b"plain", 0, origin),
            "what follows something held is held behind it"
        );

        let _ = machine.tick(std::time::Instant::now() + Duration::from_secs(31));
        fsm.settle_parked_sedp(PEER);
        assert_eq!(
            *replayed.lock().expect("lock"),
            vec![
                (PacketKind::SecureSEDP, b"sealed".to_vec()),
                (PacketKind::SEDP, b"plain".to_vec())
            ]
        );
        assert!(!fsm.has_parked_sedp(&PEER));
    }

    /// What is held for a participant goes with it when it is removed.
    #[test]
    fn what_is_held_for_a_participant_goes_with_it() {
        use crate::core::discovery::multicast::{Origin, PacketKind};
        use crate::security::test_pki::TEST_CA_CERT_PEM;
        let (fsm, machine) = authenticated_peer(30_000);
        machine
            .on_message(
                peer(),
                &auth_request_from_peer(),
                GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT),
                TEST_IDENTITY_CERT_PEM,
                TEST_IDENTITY_KEY_PEM,
                TEST_CA_CERT_PEM,
            )
            .expect("a parallel session begins");
        let origin = Origin::direct("192.0.2.7:7410".parse().expect("addr"));
        assert!(fsm.park_sedp(PEER, PacketKind::SecureSEDP, b"held", 0, origin));
        fsm.remove_participant(peer());
        assert!(
            !fsm.has_parked_sedp(&PEER),
            "held datagrams outlived their participant"
        );
    }

    /// `authenticated_peer`, the peer announcing `vendor_id` and
    /// `hdds_capabilities`.
    fn authenticated_peer_announcing(
        vendor_id: Option<u16>,
        hdds_capabilities: Option<u32>,
    ) -> (DiscoveryFsm, Arc<HandshakeMachine>) {
        let machine = crate::security::test_pki::local_machine_with_completed_peer_capabilities(
            LOCAL,
            PEER,
            None,
            hdds_capabilities.unwrap_or(crate::protocol::group::LOCAL_CAPABILITIES),
        );
        let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.set_handshake_machine(
            Arc::clone(&machine),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.register_builtin_writer_keys_for_tests();
        let mut data = announcement(30_000);
        data.vendor_id = vendor_id;
        data.hdds_capabilities = hdds_capabilities;
        fsm.handle_spdp(data);
        assert!(machine.is_authenticated(&peer()), "the fixture completed");
        (fsm, machine)
    }

    /// Our SEDP announcement of a writer, and its dispose (Q set: its key
    /// hash and status in the inline QoS), as built for the peer.
    fn local_sedp_announcement_and_dispose() -> [(&'static str, Vec<u8>); 2] {
        use crate::core::discovery::multicast::{
            build_sedp_dispose_packet, build_sedp_rtps_packet, SedpEndpointKind,
        };
        use crate::protocol::dialect::Dialect;
        let mut writer = peer_writer(LOCAL);
        writer.participant_guid = GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT);
        let announcement = build_sedp_rtps_packet(
            &writer,
            SedpEndpointKind::Writer,
            &LOCAL,
            Some(&PEER),
            1,
            Dialect::Hdds,
        )
        .expect("build");
        let dispose = build_sedp_dispose_packet(
            &writer.endpoint_guid,
            SedpEndpointKind::Writer,
            &LOCAL,
            Some(&PEER),
            2,
            Dialect::Hdds,
        );
        [("announcement", announcement), ("dispose", dispose)]
    }

    /// The submessages of an RTPS message: (offset, id, E flag, body).
    fn submessages(datagram: &[u8]) -> Vec<(usize, u8, bool, std::ops::Range<usize>)> {
        let mut out = Vec::new();
        let mut at = 20;
        while at + 4 <= datagram.len() {
            let e = datagram[at + 1] & 0x01 != 0;
            let n = if e {
                u16::from_le_bytes([datagram[at + 2], datagram[at + 3]])
            } else {
                u16::from_be_bytes([datagram[at + 2], datagram[at + 3]])
            };
            let end = if n == 0 {
                datagram.len()
            } else {
                at + 4 + usize::from(n)
            };
            assert!(
                end <= datagram.len(),
                "submessage at {} runs past the end",
                at
            );
            out.push((at, datagram[at], e, at + 4..end));
            at = end;
        }
        out
    }

    /// HMAC-SHA256 of the concatenation of `parts` under `key`.
    fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        let mut ctx = ring::hmac::Context::with_key(&key);
        for part in parts {
            ctx.update(part);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(ctx.sign().as_ref());
        out
    }

    /// A sealed SEDP datagram read as DDS-Security 1.1 lays it out,
    /// independently of our codec: SEC_PREFIX / SEC_BODY / SEC_POSTFIX
    /// (Sec.7.3.7.5-7.3.7.7), CryptoHeader, CryptoContent and CryptoFooter
    /// big endian (Sec.9.5.2.3-9.5.2.5), the session key of Sec.9.5.3.3.3,
    /// the IV of Sec.9.5.3.3.4, AES-256-GCM with empty AAD and the common
    /// MAC as its tag (Sec.9.5.3.3.4.5). The master key and salt are what the
    /// sending writer's DatawriterCryptoTokens carry. Returns the offset of the
    /// SEC_PREFIX, the submessage it protects, and the offset past the
    /// SEC_POSTFIX.
    fn read_as_the_spec_lays_it_out(
        datagram: &[u8],
        master_key: &[u8; 32],
        master_salt: &[u8; 32],
        key_id: [u8; 4],
    ) -> (usize, Vec<u8>, usize) {
        let subs = submessages(datagram);
        let i = subs
            .iter()
            .position(|s| s.1 == 0x31)
            .expect("a SEC_PREFIX (0x31)");
        let (prefix_at, _, _, header) = subs[i].clone();
        let (_, body_id, _, body) = subs.get(i + 1).cloned().expect("a submessage after it");
        let (_, postfix_id, _, footer) = subs.get(i + 2).cloned().expect("and one more");
        assert_eq!(body_id, 0x30, "SEC_BODY follows the SEC_PREFIX");
        assert_eq!(postfix_id, 0x32, "SEC_POSTFIX follows the SEC_BODY");

        assert_eq!(header.len(), 20, "CryptoHeader: 4 + 4 + 4 + 8 octets");
        let h = &datagram[header];
        assert_eq!(
            h[0..4],
            [0, 0, 0, 4],
            "CRYPTO_TRANSFORMATION_KIND_AES256_GCM"
        );

        assert_eq!(h[4..8], key_id, "transformation_key_id of that writer");
        // Sec.9.5.3.3.3: SessionKey := HMAC256(MasterKey, "SessionKey" |
        // MasterSalt | SessionId), from the material the writer's
        // DatawriterCryptoTokens carry.
        let session_key = hmac256(master_key, &[b"SessionKey", master_salt, &h[8..12]]);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&h[8..20]);

        let content = &datagram[body];
        let n = u32::from_be_bytes([content[0], content[1], content[2], content[3]]) as usize;
        assert!(4 + n <= content.len(), "CryptoContent fits its SEC_BODY");
        let f = &datagram[footer.clone()];
        assert_eq!(
            f.len(),
            20,
            "common_mac 16, an empty receiver_specific_macs"
        );
        assert_eq!(f[16..20], [0, 0, 0, 0], "no receiver specific MAC");

        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &session_key).expect("key"),
        );
        let mut in_out = content[4..4 + n].to_vec();
        in_out.extend_from_slice(&f[..16]);
        let plain = key
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(iv),
                ring::aead::Aad::empty(),
                &mut in_out,
            )
            .expect("the common MAC verifies")
            .to_vec();
        (prefix_at, plain, footer.end)
    }

    /// Every authenticated participant receives DDS-Security v1.1
    /// submessage protection (Sec.9.4.1.2.5.4, 9.5.3.3.4.5), even without
    /// CAP_SPEC_SECURE_SEDP in its SPDP or signed c.pdata. The complete DATA,
    /// inline QoS included, is protected with the sending writer's material.
    #[test]
    fn sedp_to_an_authenticated_participant_is_one_protected_submessage() {
        for (vendor_id, caps) in [
            (
                Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
                Some(crate::protocol::group::LOCAL_CAPABILITIES),
            ),
            (Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16), None),
            (
                Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
                Some(
                    crate::protocol::group::LOCAL_CAPABILITIES
                        & !crate::protocol::group::CAP_SPEC_SECURE_SEDP,
                ),
            ),
            (Some(0x0101), None),
            (None, None),
        ] {
            let (fsm, _machine) = authenticated_peer_announcing(vendor_id, caps);
            // What our publications writer's DatawriterCryptoTokens carry to
            // the peer: the only material the peer decodes it with.
            let (key_id, ours) = fsm.local_builtin_writer_key_for_tests(
                crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            );
            let key_id = u32::try_from(key_id).expect("32-bit").to_be_bytes();
            for (what, packet) in local_sedp_announcement_and_dispose() {
                let sealed = fsm
                    .sedp_for_peer(&PEER, packet.clone(), None)
                    .expect("sealed");
                let plain_subs = submessages(&packet);
                let data = plain_subs
                    .iter()
                    .find(|s| s.1 == 0x15)
                    .expect("fixture: a DATA")
                    .clone();
                assert!(
                    submessages(&sealed).iter().all(|s| s.1 != 0x15),
                    "{}: no DATA in clear",
                    what
                );
                assert_eq!(
                    sealed[..data.0],
                    packet[..data.0],
                    "{}: what precedes the DATA is untouched",
                    what
                );

                let (prefix_at, inner, end) = read_as_the_spec_lays_it_out(
                    &sealed,
                    ours.key.as_bytes(),
                    ours.salt.as_bytes(),
                    key_id,
                );
                assert_eq!(prefix_at, data.0, "{}: in the DATA's place", what);
                assert_eq!(end, sealed.len(), "{}: nothing after it", what);

                let mut expected = packet[data.0..data.3.end].to_vec();
                expected[8] = 0xff; // readerId 000003c7 -> ff0003c7
                expected[12] = 0xff; // writerId 000003c2 -> ff0003c2
                assert_eq!(
                    expected[8..16],
                    [0xff, 0, 3, 0xc7, 0xff, 0, 3, 0xc2],
                    "fixture"
                );
                assert_eq!(inner, expected, "{}: the DATA we built, renamed", what);

                let mut alone = packet[..20].to_vec();
                alone.extend_from_slice(&inner);
                let layout = crate::protocol::builder::data_submessage_layout(&alone, 20)
                    .unwrap_or_else(|| panic!("{}: a valid RTPS DATA inside", what));
                if inner[1] & 0x02 != 0 {
                    let (from, to) = layout.inline_qos.expect("Q set: an inline QoS");
                    assert!(
                        alone[from..to]
                            .chunks(4)
                            .any(|c| c[0] == 0x71 && c[1] == 0x00),
                        "{}: PID_STATUS_INFO readable in clear inside the protection",
                        what
                    );
                }

                let opened = crate::security::crypto::secure_sedp::open_secure_sedp_as(
                    &sealed,
                    prefix_at,
                    &ours.submessage_material(u32::from_be_bytes(key_id)),
                    &crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
                    crate::security::access::ProtectionKind::Encrypt,
                )
                .expect("the peer opens it");
                assert_eq!(
                    opened.datagram, packet,
                    "{}: the peer reads back what we built",
                    what
                );
                let plain_layout =
                    crate::protocol::builder::data_submessage_layout(&packet, data.0).expect("ok");
                assert_eq!(
                    opened.payload_at, plain_layout.payload,
                    "{}: at its payload",
                    what
                );
            }
        }
    }

    /// Unchanged for a participant that has not authenticated, and for a
    /// datagram with no DATA.
    #[test]
    fn sedp_to_an_unauthenticated_participant_or_without_data_is_not_sealed() {
        let (fsm, _machine) = authenticated_peer(30_000);
        for (_, packet) in local_sedp_announcement_and_dispose() {
            assert_eq!(
                fsm.sedp_for_peer(&[0x33; 12], packet.clone(), None),
                Some(packet),
                "a participant that has not authenticated gets it as it is"
            );
        }
        let no_data = packet_without_data();
        assert_eq!(
            fsm.sedp_for_peer(&PEER, no_data.clone(), None),
            Some(no_data)
        );
    }

    /// The departure we seal opens, at its SEC_PREFIX, under the key
    /// material our secure participant writer's DatawriterCryptoTokens carry
    /// (what the peer received), with what follows it left out of the seal;
    /// nothing else opens as a departure: not under another material (the
    /// peer's own, or our secure SEDP writer's), not a protected DATA of
    /// another writer under that material, not another payload, not a
    /// departure that names another participant than the one whose prefix
    /// the header carries, and none is sealed for a participant that has not
    /// authenticated.
    ///
    /// The writer check in `open_sealed_departure` is pinned by "another
    /// writer", its GUID check by "another participant's".
    #[test]
    fn a_sealed_departure_opens_under_our_participant_writers_material_and_nothing_else_does() {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER, RTPS_ENTITYID_SPDP_SECURE_WRITER,
        };
        use crate::security::crypto::secure_submessage::{
            encode_datawriter_submessage, Transformation,
        };
        let (fsm, _machine) = authenticated_peer(30_000);
        let ours = GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT);
        let material = |writer: [u8; 4]| {
            let (key_id, key) = fsm.local_builtin_writer_key_for_tests(writer);
            key.submessage_material(u32::try_from(key_id).expect("32-bit"))
        };
        let announced = material(RTPS_ENTITYID_SPDP_SECURE_WRITER);
        let open =
            |datagram: &[u8],
             with: &crate::security::crypto::secure_submessage::WriterKeyMaterial| {
                DiscoveryFsm::open_sealed_departure(
                    datagram,
                    20,
                    with,
                    crate::security::access::ProtectionKind::Encrypt,
                )
            };

        let mut departure = fsm
            .sealed_departure_for(&PEER, ours)
            .expect("authenticated");
        assert_eq!(departure[20], 0x31, "a SEC_PREFIX after the header");
        assert_eq!(
            &departure[8..20],
            &LOCAL,
            "sent by the departing participant"
        );
        assert_eq!(open(&departure, &announced), Some(ours));
        // An INFO_TS after it, as a sender may append.
        departure.extend_from_slice(&[0x09, 0x01, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            open(&departure, &announced),
            Some(ours),
            "what follows the protected DATA is not part of the seal"
        );

        assert_eq!(
            open(
                &departure,
                &material(RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER)
            ),
            None,
            "under our secure SEDP writer's material"
        );
        let (theirs, _) = super::mint_sedp_writer_keys_for_tests(Transformation::Aes256Gcm);
        assert_eq!(
            open(&departure, &theirs.publications),
            None,
            "under another's"
        );

        // A protected DATA of another writer, under the participant writer's
        // material.
        let decoded = crate::security::crypto::secure_submessage::decode_datawriter_submessage(
            &announced, &departure, 20,
        )
        .expect("fixture: it decodes");
        let mut relabelled = decoded.submessage.clone();
        relabelled[12..16].copy_from_slice(&RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER);
        let mut other_writer = departure[..20].to_vec();
        other_writer.extend_from_slice(
            &encode_datawriter_submessage(&announced, &relabelled).expect("protect"),
        );
        assert_eq!(open(&other_writer, &announced), None, "another writer");

        // An invalid inline parameter list of the same length, ending
        // with that GUID, does not describe a participant status change.
        let mut other_payload = decoded.submessage.clone();
        let payload_at = other_payload.len() - 24;
        other_payload[payload_at..payload_at + 8]
            .copy_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x50, 0x00, 0x10, 0x00]);
        let mut cdr = departure[..20].to_vec();
        cdr.extend_from_slice(
            &encode_datawriter_submessage(&announced, &other_payload).expect("protect"),
        );
        assert_eq!(
            open(&cdr, &announced),
            None,
            "an invalid parameter list is not a departure"
        );

        let other = GUID::new([0x44; 12], RTPS_ENTITYID_PARTICIPANT);
        let mut naming_another = super::sealed_departure_datagram(
            &announced,
            other,
            crate::security::access::ProtectionKind::Encrypt,
        )
        .expect("protected");
        naming_another[8..20].copy_from_slice(&LOCAL);
        assert_eq!(
            open(&naming_another, &announced),
            None,
            "another participant's departure: a participant announces its own"
        );

        assert_eq!(
            fsm.sealed_departure_for(&[0x33; 12], ours),
            None,
            "nothing for a participant that has not authenticated"
        );
    }

    /// The secure departures a participant owes as it leaves: one for each
    /// authenticated participant with somewhere to send it.
    #[test]
    fn a_sealed_departure_goes_to_each_authenticated_participant() {
        let departures = |vendor_id: Option<u16>| {
            let machine = local_machine_with_completed_peer(LOCAL, PEER, None);
            let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
            fsm.set_handshake_machine(
                Arc::clone(&machine),
                TEST_IDENTITY_CERT_PEM.to_vec(),
                TEST_IDENTITY_KEY_PEM.to_vec(),
            );
            fsm.register_builtin_writer_keys_for_tests();
            let mut data = announcement(30_000);
            data.metatraffic_unicast_locators = vec!["192.0.2.7:7410".parse().expect("addr")];
            data.vendor_id = vendor_id;
            fsm.handle_spdp(data);
            fsm.sealed_departures(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT))
        };
        let hdds = departures(Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16));
        assert_eq!(hdds.len(), 1);
        assert_eq!(hdds[0].1, vec!["192.0.2.7:7410".parse().expect("addr")]);
        assert_eq!(
            departures(Some(0x0101)).len(),
            1,
            "another authenticated vendor"
        );
    }

    /// An RTPS datagram with no DATA (a header and an INFO_TS).
    fn packet_without_data() -> Vec<u8> {
        let mut packet = b"RTPS".to_vec();
        packet.extend_from_slice(&[0x02, 0x05, 0x01, 0x1a]);
        packet.extend_from_slice(&LOCAL);
        packet.extend_from_slice(&[0x09, 0x01, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);
        packet
    }

    /// A secure SEDP datagram from a participant whose handshake is still in
    /// progress here (we are the responder: our session completes only at
    /// the AuthFinal, after the initiator already sealed with the new key) is
    /// held and handed back when the handshake completes. Nothing is held
    /// for a participant with no session, nor beyond the bound.
    #[test]
    fn a_secure_sedp_datagram_from_a_peer_still_handshaking_is_held_until_it_completes() {
        use crate::core::discovery::multicast::{Origin, PacketKind};
        use crate::security::handshake::tokens::{encode_final, encode_reply, encode_request};
        use crate::security::handshake::HandshakeAction;
        use crate::security::test_pki::TEST_CA_CERT_PEM;

        let high = crate::security::test_pki::bound_test_prefix([0xF1; 6]);
        let local = GUID::new(high, RTPS_ENTITYID_PARTICIPANT);
        let (cert, key, ca) = (
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
            TEST_CA_CERT_PEM.to_vec(),
        );
        let machine = Arc::new(HandshakeMachine::new());
        let mut fsm = DiscoveryFsm::new(local, 30_000);
        fsm.set_handshake_machine(Arc::clone(&machine), cert.clone(), key.clone());
        let fsm = Arc::new(fsm);
        fsm.arm_surfacing_on_authentication();
        let replayed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&replayed);
        fsm.set_secure_sedp_replay(Box::new(move |_, datagram, _, _| {
            seen.lock().expect("lock").push(datagram.to_vec());
        }));
        let origin = Origin::direct("192.0.2.7:7410".parse().expect("addr"));

        assert!(
            !fsm.park_sedp(PEER, PacketKind::SecureSEDP, b"no session", 0, origin),
            "a participant with no session"
        );
        let peer_machine = HandshakeMachine::new();
        let request = match peer_machine
            .start(peer(), local, &cert, &key)
            .expect("start")
            .expect("the peer initiates")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected SendRequest, got {:?}", other),
        };
        let reply = match machine
            .on_message(peer(), &request, local, &cert, &key, &ca)
            .expect("accepted")
        {
            HandshakeAction::SendReply(_, token) => encode_reply(&token).expect("encode"),
            other => panic!("expected SendReply, got {:?}", other),
        };
        let final_bytes = match peer_machine
            .on_message(local, &reply, peer(), &cert, &key, &ca)
            .expect("the peer completes first")
        {
            HandshakeAction::SendFinal(_, token) => encode_final(&token).expect("encode"),
            other => panic!("expected SendFinal, got {:?}", other),
        };

        for n in 0..super::PARKED_SECURE_SEDP_PER_PEER {
            assert!(
                fsm.park_sedp(PEER, PacketKind::SecureSEDP, &[n as u8], 0, origin),
                "held {}",
                n
            );
        }
        assert!(!fsm.park_sedp(PEER, PacketKind::SecureSEDP, b"one too many", 0, origin));
        assert!(replayed.lock().expect("lock").is_empty());

        machine
            .on_message(peer(), &final_bytes, local, &cert, &key, &ca)
            .expect("we complete");
        let back = replayed.lock().expect("lock").clone();
        assert_eq!(back.len(), super::PARKED_SECURE_SEDP_PER_PEER);
        assert_eq!(back[0], vec![0u8], "handed back in order");
        assert!(
            !fsm.park_sedp(PEER, PacketKind::SecureSEDP, b"authenticated", 0, origin),
            "nothing is held for an authenticated participant"
        );
    }

    /// Datagrams handed back by discovery, with the prefix they came from.
    type HandedBack = Arc<std::sync::Mutex<Vec<([u8; 12], Vec<u8>)>>>;

    /// A discovery participant with a handshake machine, and a session in
    /// progress (begun, not answered) toward each prefix in `prefixes`.
    fn sessions_in_progress(
        prefixes: &[[u8; 12]],
    ) -> (Arc<DiscoveryFsm>, Arc<HandshakeMachine>, HandedBack) {
        let local = GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT);
        let machine = Arc::new(HandshakeMachine::new());
        let mut fsm = DiscoveryFsm::new(local, 30_000);
        fsm.set_handshake_machine(
            Arc::clone(&machine),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        let fsm = Arc::new(fsm);
        let replayed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&replayed);
        fsm.set_secure_sedp_replay(Box::new(move |_, datagram, _, _| {
            let mut prefix = [0u8; 12];
            prefix.copy_from_slice(&datagram[..12]);
            seen.lock().expect("lock").push((prefix, datagram.to_vec()));
        }));
        for prefix in prefixes {
            machine
                .start(
                    local,
                    GUID::new(*prefix, RTPS_ENTITYID_PARTICIPANT),
                    TEST_IDENTITY_CERT_PEM,
                    TEST_IDENTITY_KEY_PEM,
                )
                .expect("a session begins");
            assert!(machine.has_session(&GUID::new(*prefix, RTPS_ENTITYID_PARTICIPANT)));
        }
        (fsm, machine, replayed)
    }

    /// The `n`th of a series of distinct participant prefixes.
    fn nth_prefix(n: usize) -> [u8; 12] {
        let mut prefix = [0x5Au8; 12];
        prefix[8..].copy_from_slice(&(n as u32).to_be_bytes());
        prefix
    }

    /// A participant whose handshake is in progress has proven nothing, and
    /// one plain announcement per prefix opens that window: what all of them
    /// park together is bounded, in participants and in bytes, however many
    /// prefixes send.
    #[test]
    fn parked_sedp_is_bounded_over_every_participant() {
        use crate::core::discovery::multicast::{Origin, PacketKind};
        let flood = super::PARKED_SECURE_SEDP_PREFIXES + 64;
        let prefixes: Vec<[u8; 12]> = (0..flood).map(nth_prefix).collect();
        let (fsm, machine, replayed) = sessions_in_progress(&prefixes);
        let origin = Origin::direct("192.0.2.7:7410".parse().expect("addr"));

        // Small datagrams from more prefixes than may hold any.
        let mut held = 0;
        for prefix in &prefixes {
            if fsm.park_sedp(*prefix, PacketKind::SecureSEDP, prefix, 0, origin) {
                held += 1;
            }
        }
        assert_eq!(held, super::PARKED_SECURE_SEDP_PREFIXES);
        assert_eq!(
            fsm.parked_sedp.lock().expect("lock").participants(),
            super::PARKED_SECURE_SEDP_PREFIXES
        );

        // The largest datagrams from the prefixes already holding one.
        let mut large = vec![0u8; 64 * 1024];
        for prefix in &prefixes {
            large[..12].copy_from_slice(prefix);
            for _ in 0..super::PARKED_SECURE_SEDP_PER_PEER {
                let _ = fsm.park_sedp(*prefix, PacketKind::SecureSEDP, &large, 0, origin);
            }
        }
        let bytes = fsm.parked_sedp.lock().expect("lock").bytes();
        assert!(
            bytes <= super::PARKED_SECURE_SEDP_BYTES,
            "{} bytes held, bound {}",
            bytes,
            super::PARKED_SECURE_SEDP_BYTES
        );
        assert!(
            bytes > super::PARKED_SECURE_SEDP_BYTES - super::ParkedSedpQueue::cost(64 * 1024),
            "the bound refused before it was reached: {} bytes",
            bytes
        );
        assert!(
            fsm.metrics
                .secure_sedp_queue_overflow
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0,
            "the refusals are counted"
        );
        assert!(
            replayed.lock().expect("lock").is_empty(),
            "no session settled, nothing is handed back"
        );

        // Handed back, what was held frees its bytes: every session fails,
        // and a newcomer's datagram takes the room.
        let _ = machine.tick(std::time::Instant::now() + Duration::from_secs(31));
        let newcomer = nth_prefix(flood);
        machine
            .start(
                GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT),
                GUID::new(newcomer, RTPS_ENTITYID_PARTICIPANT),
                TEST_IDENTITY_CERT_PEM,
                TEST_IDENTITY_KEY_PEM,
            )
            .expect("a session begins");
        assert!(fsm.park_sedp(newcomer, PacketKind::SecureSEDP, &large, 0, origin));
        let parked = fsm.parked_sedp.lock().expect("lock");
        assert_eq!(
            (parked.participants(), parked.bytes()),
            (1, super::ParkedSedpQueue::cost(large.len()))
        );
    }

    /// A session that failed changes no key: nothing its participant sends
    /// is held, and what was held for it before it failed is handed back
    /// (where the sealed part is dropped as unreadable) as soon as the room
    /// it takes is needed by a participant whose handshake is in progress.
    #[test]
    fn nothing_is_parked_for_a_failed_session_and_what_was_held_is_released() {
        use crate::core::discovery::multicast::{Origin, PacketKind};
        let prefixes: Vec<[u8; 12]> = (0..super::PARKED_SECURE_SEDP_PREFIXES)
            .map(nth_prefix)
            .collect();
        let (fsm, machine, replayed) = sessions_in_progress(&prefixes);
        let origin = Origin::direct("192.0.2.7:7410".parse().expect("addr"));
        for prefix in &prefixes {
            assert!(fsm.park_sedp(*prefix, PacketKind::SecureSEDP, prefix, 0, origin));
        }

        // Every session reaches its deadline and fails.
        let _ = machine.tick(std::time::Instant::now() + Duration::from_secs(31));
        for prefix in &prefixes {
            assert!(
                !fsm.park_sedp(*prefix, PacketKind::SecureSEDP, prefix, 0, origin),
                "held for a failed session"
            );
        }
        assert!(replayed.lock().expect("lock").is_empty());

        // A participant whose handshake has just begun still gets its SEDP
        // held, though every slot was taken by failed sessions.
        let newcomer = nth_prefix(super::PARKED_SECURE_SEDP_PREFIXES);
        machine
            .start(
                GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT),
                GUID::new(newcomer, RTPS_ENTITYID_PARTICIPANT),
                TEST_IDENTITY_CERT_PEM,
                TEST_IDENTITY_KEY_PEM,
            )
            .expect("a session begins");
        assert!(fsm.park_sedp(newcomer, PacketKind::SecureSEDP, &newcomer, 0, origin));
        assert!(fsm.has_parked_sedp(&newcomer));
        let mut back: Vec<[u8; 12]> = replayed
            .lock()
            .expect("lock")
            .iter()
            .map(|(prefix, _)| *prefix)
            .collect();
        back.sort_unstable();
        assert_eq!(back, prefixes, "what failed sessions held was handed back");
        let parked = fsm.parked_sedp.lock().expect("lock");
        assert_eq!(parked.participants(), 1);
    }

    /// The window in which the AuthFinal is verified (a signature and a key
    /// agreement, long on a loaded host) is part of the handshake in
    /// progress: a secure SEDP datagram of the peer received then is held
    /// like one received before it, and handed back when the session
    /// completes, instead of being dropped as the datagram of a participant
    /// that has no session and has not authenticated.
    #[test]
    fn a_secure_sedp_datagram_received_while_the_final_is_verified_is_held() {
        use crate::core::discovery::multicast::{Origin, PacketKind};
        use crate::security::handshake::tokens::{encode_final, encode_reply, encode_request};
        use crate::security::handshake::HandshakeAction;
        use crate::security::test_pki::TEST_CA_CERT_PEM;

        let high = crate::security::test_pki::bound_test_prefix([0xF1; 6]);
        let local = GUID::new(high, RTPS_ENTITYID_PARTICIPANT);
        let (cert, key, ca) = (
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
            TEST_CA_CERT_PEM.to_vec(),
        );
        let machine = Arc::new(HandshakeMachine::new());
        let mut fsm = DiscoveryFsm::new(local, 30_000);
        fsm.set_handshake_machine(Arc::clone(&machine), cert.clone(), key.clone());
        let fsm = Arc::new(fsm);
        fsm.arm_surfacing_on_authentication();
        let replayed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&replayed);
        fsm.set_secure_sedp_replay(Box::new(move |_, datagram, _, _| {
            seen.lock().expect("lock").push(datagram.to_vec());
        }));
        let origin = Origin::direct("192.0.2.7:7410".parse().expect("addr"));

        let peer_machine = HandshakeMachine::new();
        let request = match peer_machine
            .start(peer(), local, &cert, &key)
            .expect("start")
            .expect("the peer initiates")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected SendRequest, got {:?}", other),
        };
        let reply = match machine
            .on_message(peer(), &request, local, &cert, &key, &ca)
            .expect("accepted")
        {
            HandshakeAction::SendReply(_, token) => encode_reply(&token).expect("encode"),
            other => panic!("expected SendReply, got {:?}", other),
        };
        let final_bytes = match peer_machine
            .on_message(local, &reply, peer(), &cert, &key, &ca)
            .expect("the peer completes first")
        {
            HandshakeAction::SendFinal(_, token) => encode_final(&token).expect("encode"),
            other => panic!("expected SendFinal, got {:?}", other),
        };

        let held = Arc::new(std::sync::Mutex::new(None));
        let held_in_hook = Arc::clone(&held);
        let fsm_in_hook = Arc::clone(&fsm);
        machine.set_parked_hook(Box::new(move |_| {
            *held_in_hook.lock().expect("lock") = Some(fsm_in_hook.park_sedp(
                PEER,
                PacketKind::SecureSEDP,
                b"during the verification",
                0,
                origin,
            ));
        }));
        machine
            .on_message(peer(), &final_bytes, local, &cert, &key, &ca)
            .expect("we complete");

        assert_eq!(
            *held.lock().expect("lock"),
            Some(true),
            "a datagram received while the AuthFinal is verified was not held"
        );
        assert_eq!(
            *replayed.lock().expect("lock"),
            vec![b"during the verification".to_vec()],
            "and it is handed back when the session completes"
        );
    }

    /// A participant whose session replaced a completed one may be a new
    /// process under the same prefix, reusing its entity ids: its old
    /// endpoint records go, so that a new endpoint announced under a reused
    /// GUID - in the clear, before it authenticated - is not ignored as a
    /// known one. A first completion keeps them. Either way its next
    /// announcement gets our endpoints again, sealed.
    #[test]
    fn a_participant_that_authenticates_again_loses_its_old_endpoints() {
        use super::{SedpChannel, SpdpVerdict};
        let (fsm, _machine) = authenticated_peer(30_000);
        let writer = peer_writer(PEER);
        let guid = writer.endpoint_guid;
        fsm.handle_sedp_on(writer.clone(), SedpChannel::Secure);

        fsm.peer_authenticated(peer(), false);
        assert!(
            fsm.current_endpoint("sensor", &guid).is_some(),
            "a first completion forgets nothing"
        );
        assert_eq!(
            fsm.admit_spdp(announcement(30_000)),
            SpdpVerdict::Reauthenticated
        );
        assert_eq!(
            fsm.admit_spdp(announcement(30_000)),
            SpdpVerdict::LivelinessOnly
        );

        fsm.peer_authenticated(peer(), true);
        assert!(
            fsm.current_endpoint("sensor", &guid).is_none(),
            "the old endpoint outlived the session that replaced its participant's"
        );
        let mut reused = writer;
        reused.topic_name = "elsewhere".to_string();
        fsm.handle_sedp(reused);
        assert!(
            fsm.current_endpoint("elsewhere", &guid).is_some(),
            "the new endpoint under the reused GUID was ignored"
        );
        assert_eq!(
            fsm.admit_spdp(announcement(30_000)),
            SpdpVerdict::Reauthenticated
        );
    }

    /// The lease a participant declared is the lease it is held to, once it
    /// has authenticated: no text lets a receiver shorten it. An infinite
    /// one included.
    #[test]
    fn an_authenticated_participant_keeps_the_lease_it_declared() {
        let (fsm, _machine) = authenticated_peer(u64::MAX);
        assert_eq!(
            fsm.admitted_locators_and_lease(&PEER)
                .map(|(_, lease)| lease),
            Some(u64::MAX)
        );
    }

    /// While its handshake is pending, a participant's declared lease came in
    /// a plain announcement nothing vouches for: it is held to the bound.
    /// When the handshake completes it gets the shortest lease it declared
    /// meanwhile - not a forged infinite one sent during the handshake - and
    /// plain announcements after that do not change it.
    #[test]
    fn a_pending_participant_is_bounded_and_gets_its_declared_lease_when_it_authenticates() {
        use super::{SpdpVerdict, PENDING_AUTHENTICATION_LEASE_BOUND_MS};
        use crate::security::handshake::tokens::{encode_reply, encode_request};
        use crate::security::handshake::HandshakeAction;
        use crate::security::test_pki::TEST_CA_CERT_PEM;

        let local = GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT);
        let (cert, key, ca) = (
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
            TEST_CA_CERT_PEM.to_vec(),
        );
        let machine = Arc::new(HandshakeMachine::new());
        let mut fsm = DiscoveryFsm::new(local, 30_000);
        fsm.set_handshake_machine(Arc::clone(&machine), cert.clone(), key.clone());
        let fsm = Arc::new(fsm);
        fsm.arm_surfacing_on_authentication();
        let lease = || {
            fsm.admitted_locators_and_lease(&PEER)
                .map(|(_, lease)| lease)
        };

        // Announced with 300 s: the announcement starts the handshake (we
        // initiate), which is then pending.
        assert_eq!(fsm.admit_spdp(announcement(300_000)), SpdpVerdict::New);
        assert_eq!(lease(), Some(PENDING_AUTHENTICATION_LEASE_BOUND_MS));
        // A forger's announcement under its prefix, still pending, declares
        // an infinite lease; held to the bound meanwhile.
        fsm.admit_spdp(announcement(u64::MAX));
        assert_eq!(lease(), Some(PENDING_AUTHENTICATION_LEASE_BOUND_MS));

        // The handshake completes.
        let request = match machine.start(local, peer(), &cert, &key) {
            Ok(None) => {
                // The announcement already began it: take its request from
                // the retry ladder.
                match machine
                    .tick(std::time::Instant::now() + Duration::from_millis(1100))
                    .pop()
                {
                    Some(HandshakeAction::SendRequest(_, token)) => {
                        encode_request(&token).expect("encode")
                    }
                    other => panic!("expected the pending request, got {:?}", other),
                }
            }
            other => panic!("the announcement began the handshake, got {:?}", other),
        };
        let reply = match HandshakeMachine::new()
            .on_message(local, &request, peer(), &cert, &key, &ca)
            .expect("the peer accepts")
        {
            HandshakeAction::SendReply(_, token) => encode_reply(&token).expect("encode"),
            other => panic!("expected SendReply, got {:?}", other),
        };
        machine
            .on_message(peer(), &reply, local, &cert, &key, &ca)
            .expect("completes");
        assert_eq!(
            lease(),
            Some(300_000),
            "the shortest lease declared while pending, not the forged infinite one"
        );

        // The first announcement after completion is answered with our
        // endpoints (`Reauthenticated`); either way, liveliness only.
        assert_eq!(
            fsm.admit_spdp(announcement(1_000)),
            SpdpVerdict::Reauthenticated
        );
        assert_eq!(
            fsm.admit_spdp(announcement(1_000)),
            SpdpVerdict::LivelinessOnly
        );
        assert_eq!(lease(), Some(300_000), "a plain announcement changed it");
    }

    /// A reader of the peer, `entity` its last entity-id byte, announced at
    /// `locator` on `topic`.
    fn peer_reader(entity: u8, topic: &str, locator: &str) -> crate::protocol::discovery::SedpData {
        let mut reader = [0u8; 16];
        reader[..12].copy_from_slice(&PEER);
        reader[14] = entity;
        reader[15] = 0x04;
        crate::protocol::discovery::SedpData {
            topic_name: topic.to_string(),
            type_name: "Temperature".to_string(),
            participant_guid: peer(),
            endpoint_guid: GUID::from_bytes(reader),
            qos_hash: 0,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![locator.parse().expect("addr")],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// The locator samples are sent to for a reader, and its topic.
    fn reader_as_known(
        fsm: &DiscoveryFsm,
        reader: &GUID,
    ) -> (Option<std::net::SocketAddr>, Vec<String>) {
        let topics = ["sensor", "elsewhere"]
            .into_iter()
            .filter(|topic| fsm.current_endpoint(topic, reader).is_some())
            .map(str::to_string)
            .collect();
        (fsm.endpoint_registry().get_reader_locator(reader), topics)
    }

    /// A plain re-announcement of an authenticated participant's reader that
    /// moves it (another locator: the samples our writers send it would go
    /// there) or changes what it is (another topic) is refused; one that
    /// changes neither, and a reader announced for the first time, are taken.
    /// The same change on the secure SEDP topic is taken.
    #[test]
    fn a_plain_announcement_does_not_move_an_authenticated_participants_reader() {
        use super::SedpChannel;
        let (fsm, _machine) = authenticated_peer(30_000);
        let admitted = peer_reader(1, "sensor", "192.0.2.7:7411");
        let reader = admitted.endpoint_guid;
        fsm.handle_sedp(admitted.clone());
        let as_admitted = (
            Some("192.0.2.7:7411".parse().expect("addr")),
            vec!["sensor".to_string()],
        );
        assert_eq!(reader_as_known(&fsm, &reader), as_admitted, "fixture");

        fsm.handle_sedp(peer_reader(1, "sensor", "198.51.100.9:7411"));
        assert_eq!(
            reader_as_known(&fsm, &reader),
            as_admitted,
            "moved by a plain datagram"
        );
        fsm.handle_sedp(peer_reader(1, "elsewhere", "192.0.2.7:7411"));
        assert_eq!(
            reader_as_known(&fsm, &reader),
            as_admitted,
            "re-topicked by a plain datagram"
        );

        // A plain retransmission changes nothing and is taken; a new reader
        // on the plain topic is taken.
        fsm.handle_sedp(admitted);
        assert_eq!(reader_as_known(&fsm, &reader), as_admitted);
        let new_reader = peer_reader(2, "sensor", "192.0.2.7:7412");
        let new_guid = new_reader.endpoint_guid;
        fsm.handle_sedp(new_reader);
        assert!(fsm.current_endpoint("sensor", &new_guid).is_some());

        // The secure topic is where a change is taken from.
        fsm.handle_sedp_on(
            peer_reader(1, "sensor", "198.51.100.9:7411"),
            SedpChannel::Secure,
        );
        assert_eq!(
            fsm.endpoint_registry().get_reader_locator(&reader),
            Some("198.51.100.9:7411".parse().expect("addr"))
        );
    }

    /// Records the endpoints that reach the application.
    #[derive(Default)]
    struct Surfaced(std::sync::Mutex<Vec<GUID>>);

    impl super::DiscoveryListener for Surfaced {
        fn on_endpoint_discovered(&self, endpoint: super::EndpointInfo) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(endpoint.endpoint_guid);
        }
    }

    /// A writer of the peer, as its SEDP announces it.
    fn peer_writer(prefix: [u8; 12]) -> crate::protocol::discovery::SedpData {
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&prefix);
        writer[15] = 0x02;
        crate::protocol::discovery::SedpData {
            topic_name: "sensor".to_string(),
            type_name: "Temperature".to_string(),
            participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
            endpoint_guid: GUID::from_bytes(writer),
            qos_hash: 0,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// An FSM past its startup probation (nothing defers a peer's endpoints
    /// any more), armed as a participant arms it, with a listener.
    fn armed_fsm(
        local: GUID,
        machine: &Arc<HandshakeMachine>,
    ) -> (Arc<DiscoveryFsm>, Arc<Surfaced>) {
        let mut fsm = DiscoveryFsm::new(local, 30_000);
        fsm.set_handshake_machine(
            Arc::clone(machine),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        let fsm = Arc::new(fsm);
        fsm.arm_surfacing_on_authentication();
        let surfaced = Arc::new(Surfaced::default());
        fsm.register_listener(surfaced.clone());
        std::thread::sleep(Duration::from_millis(300));
        (fsm, surfaced)
    }

    fn seen(surfaced: &Surfaced) -> Vec<GUID> {
        surfaced.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// An endpoint the peer announced while its handshake was in progress is
    /// refused then, and surfaced when the handshake completes: nothing else
    /// offers a known endpoint again. We initiate: our side completes at the
    /// AuthReply.
    #[test]
    fn an_endpoint_announced_before_the_handshake_completes_surfaces_when_it_does() {
        use crate::security::handshake::tokens::{encode_reply, encode_request};
        use crate::security::handshake::HandshakeAction;
        use crate::security::test_pki::TEST_CA_CERT_PEM;

        let local = GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT);
        let (cert, key, ca) = (
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
            TEST_CA_CERT_PEM.to_vec(),
        );
        let machine = Arc::new(HandshakeMachine::new());
        let request = match machine
            .start(local, peer(), &cert, &key)
            .expect("start")
            .expect("we initiate")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected SendRequest, got {:?}", other),
        };
        let (fsm, surfaced) = armed_fsm(local, &machine);
        fsm.handle_spdp(announcement(30_000));
        let writer = peer_writer(PEER);
        let writer_guid = writer.endpoint_guid;
        fsm.handle_sedp(writer);
        assert!(
            seen(&surfaced).is_empty(),
            "an endpoint of a peer still handshaking surfaced"
        );

        let peer_machine = HandshakeMachine::new();
        let reply = match peer_machine
            .on_message(local, &request, peer(), &cert, &key, &ca)
            .expect("the peer accepts the request")
        {
            HandshakeAction::SendReply(_, token) => encode_reply(&token).expect("encode"),
            other => panic!("expected SendReply, got {:?}", other),
        };
        machine
            .on_message(peer(), &reply, local, &cert, &key, &ca)
            .expect("the reply completes our side");
        assert!(machine.is_authenticated(&peer()));

        assert_eq!(
            seen(&surfaced),
            vec![writer_guid],
            "the endpoint refused during the handshake must surface when it completes"
        );
    }

    /// The responder's side: our session completes at the peer's AuthFinal.
    #[test]
    fn an_endpoint_announced_before_the_final_surfaces_at_the_final() {
        use crate::security::handshake::tokens::{encode_final, encode_reply, encode_request};
        use crate::security::handshake::HandshakeAction;
        use crate::security::test_pki::TEST_CA_CERT_PEM;

        // We are the higher prefix: the peer initiates.
        let high = crate::security::test_pki::bound_test_prefix([0xF1; 6]);
        let local = GUID::new(high, RTPS_ENTITYID_PARTICIPANT);
        let (cert, key, ca) = (
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
            TEST_CA_CERT_PEM.to_vec(),
        );
        let machine = Arc::new(HandshakeMachine::new());
        let (fsm, surfaced) = armed_fsm(local, &machine);
        fsm.handle_spdp(announcement(30_000));

        let peer_machine = HandshakeMachine::new();
        let request = match peer_machine
            .start(peer(), local, &cert, &key)
            .expect("start")
            .expect("the peer initiates")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected SendRequest, got {:?}", other),
        };
        let reply = match machine
            .on_message(peer(), &request, local, &cert, &key, &ca)
            .expect("we accept the request")
        {
            HandshakeAction::SendReply(_, token) => encode_reply(&token).expect("encode"),
            other => panic!("expected SendReply, got {:?}", other),
        };
        let writer = peer_writer(PEER);
        let writer_guid = writer.endpoint_guid;
        fsm.handle_sedp(writer);
        assert!(
            seen(&surfaced).is_empty(),
            "an endpoint of a peer still handshaking surfaced"
        );

        let final_bytes = match peer_machine
            .on_message(local, &reply, peer(), &cert, &key, &ca)
            .expect("the peer accepts the reply")
        {
            HandshakeAction::SendFinal(_, token) => encode_final(&token).expect("encode"),
            other => panic!("expected SendFinal, got {:?}", other),
        };
        machine
            .on_message(peer(), &final_bytes, local, &cert, &key, &ca)
            .expect("the final completes our side");

        assert_eq!(seen(&surfaced), vec![writer_guid]);
    }

    /// Same rule through the lease expiry, the removal an authenticated peer
    /// actually gets (its departures on the plain topic are ignored).
    #[test]
    fn a_participant_whose_lease_expired_is_authenticated_again() {
        let (fsm, machine) = authenticated_peer(30);
        std::thread::sleep(Duration::from_millis(60));

        fsm.remove_expired_participant(peer());
        assert!(!fsm.is_participant_known(&PEER));
        assert!(!machine.has_session(&peer()));

        fsm.handle_spdp(announcement(30_000));
        assert!(machine.has_session(&peer()) && !machine.is_authenticated(&peer()));
    }

    // ---- Routing per entity under a governance document (DDS-Security v1.1
    // Table 29, Sec.9.4.1.2.5.4, Sec.8.8.2.1) ----

    /// A governance domain rule for LOCAL's domain: topics `Open*` announced
    /// on the regular SEDP topics, every other on the secure ones, the
    /// secure discovery writers protected by `kind`.
    fn governed(kind: crate::security::access::ProtectionKind) -> DiscoveryFsm {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        let topic = |expression: &str, discovery: bool| TopicRule {
            topic_expression: expression.to_string(),
            enable_discovery_protection: discovery,
            enable_liveliness_protection: false,
            enable_read_access_control: true,
            enable_write_access_control: true,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        };
        let rule = DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: kind,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![topic("Open*", false), topic("*", true)],
        };
        let (mut fsm, _) = authenticated_peer_announcing(
            Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            Some(crate::protocol::group::LOCAL_CAPABILITIES),
        );
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(rule)));
        // Our writers' key material, of the transformation the governance
        // names (`register_builtin_writer_keys`).
        fsm.register_builtin_writer_keys_for_tests();
        fsm
    }

    /// Where the writer id of the first DATA in clear sits, if there is one.
    fn clear_data_writer(datagram: &[u8]) -> Option<[u8; 4]> {
        submessages(datagram).iter().find(|s| s.1 == 0x15).map(|s| {
            datagram[s.3.start + 8..s.3.start + 12]
                .try_into()
                .expect("4")
        })
    }

    /// Table 29: an endpoint not discovery protected goes on the regular
    /// SEDP writer, in clear, to an authenticated participant too; one that
    /// is goes on the secure writer, transformed as the discovery protection
    /// kind says - NONE untransformed, SIGN in clear between a SEC_PREFIX
    /// and a SEC_POSTFIX (AES256_GMAC), ENCRYPT with no DATA in clear
    /// (AES256_GCM).
    #[test]
    fn each_endpoint_goes_on_the_sedp_topic_its_governance_names() {
        use crate::security::access::ProtectionKind;
        for kind in [
            ProtectionKind::None,
            ProtectionKind::Sign,
            ProtectionKind::Encrypt,
        ] {
            let fsm = governed(kind);
            for (what, packet) in local_sedp_announcement_and_dispose() {
                let open = fsm
                    .sedp_for_peer(&PEER, packet.clone(), Some(false))
                    .expect("sent");
                assert_eq!(
                    open, packet,
                    "{:?} {}: regular writer, untouched",
                    kind, what
                );
                assert_eq!(clear_data_writer(&open), Some([0x00, 0x00, 0x03, 0xc2]));

                let secure = fsm
                    .sedp_for_peer(&PEER, packet.clone(), Some(true))
                    .expect("sent");
                let subs = submessages(&secure);
                match kind {
                    ProtectionKind::None => {
                        assert!(subs.iter().all(|s| s.1 != 0x31), "{}: no SEC_PREFIX", what);
                        assert_eq!(
                            clear_data_writer(&secure),
                            Some([0xff, 0x00, 0x03, 0xc2]),
                            "{}: the secure writer's DATA, untransformed",
                            what
                        );
                    }
                    ProtectionKind::Sign => {
                        let prefix = subs.iter().find(|s| s.1 == 0x31).expect("SEC_PREFIX");
                        assert_eq!(&secure[prefix.3.start..prefix.3.start + 4], &[0, 0, 0, 3]);
                        assert_eq!(clear_data_writer(&secure), Some([0xff, 0x00, 0x03, 0xc2]));
                        assert!(subs.iter().any(|s| s.1 == 0x32), "SEC_POSTFIX");
                    }
                    _ => {
                        let prefix = subs.iter().find(|s| s.1 == 0x31).expect("SEC_PREFIX");
                        assert_eq!(&secure[prefix.3.start..prefix.3.start + 4], &[0, 0, 0, 4]);
                        assert_eq!(
                            clear_data_writer(&secure),
                            None,
                            "{}: no DATA in clear",
                            what
                        );
                    }
                }
            }
        }
    }

    /// Sec.8.8.2.1: a participant that has not authenticated is matched with
    /// the regular builtin endpoints only. A protected endpoint is not
    /// announced to it at all (its number becomes a GAP, `None` here); an
    /// unprotected one is, in clear.
    #[test]
    fn a_protected_endpoint_is_not_announced_to_a_participant_that_has_not_authenticated() {
        let fsm = governed(crate::security::access::ProtectionKind::Encrypt);
        let stranger = [0x33; 12];
        for (what, packet) in local_sedp_announcement_and_dispose() {
            assert_eq!(
                fsm.sedp_for_peer(&stranger, packet.clone(), Some(true)),
                None,
                "{}",
                what
            );
            assert_eq!(
                fsm.sedp_for_peer(&stranger, packet.clone(), Some(false)),
                Some(packet.clone()),
                "{}",
                what
            );
        }
    }

    /// Table 29 and Sec.9.4.1.2.5.4 decide routing even if an authenticated
    /// peer omits CAP_SPEC_SECURE_SEDP. NONE sends a clear secure DATA for
    /// protected endpoints and a regular DATA for unprotected endpoints.
    #[test]
    fn an_absent_capability_cannot_override_discovery_governance() {
        use crate::security::access::{DiscoveryGovernance, DomainRule, ProtectionKind};
        let (mut fsm, _) = authenticated_peer_announcing(
            Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            Some(
                crate::protocol::group::LOCAL_CAPABILITIES
                    & !crate::protocol::group::CAP_SPEC_SECURE_SEDP,
            ),
        );
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![],
        })));
        for (what, packet) in local_sedp_announcement_and_dispose() {
            assert_eq!(
                fsm.sedp_for_peer(&PEER, packet.clone(), Some(false)),
                Some(packet.clone()),
                "{}: regular writer",
                what
            );
            let secure = fsm
                .sedp_for_peer(&PEER, packet, Some(true))
                .expect("secure writer");
            assert_eq!(
                clear_data_writer(&secure),
                Some([0xff, 0, 3, 0xc2]),
                "{}",
                what
            );
            assert!(
                submessages(&secure).iter().all(|s| s.1 != 0x31),
                "NONE: no transformation"
            );
        }
    }

    /// Our governance puts a topic on the secure SEDP topics: a plain
    /// announcement of an endpoint of it is not taken, from anybody. One of
    /// an unprotected topic is. Without a governance document nothing
    /// changes.
    #[test]
    fn a_plain_announcement_of_a_protected_topic_is_refused() {
        let fsm = governed(crate::security::access::ProtectionKind::Encrypt);
        let remote = peer_writer(PEER).endpoint_guid;
        assert!(fsm.refuses_plain_announcement_of(&remote, "Secret"));
        assert!(!fsm.refuses_plain_announcement_of(&remote, "OpenData"));
        let ours = GUID::new(LOCAL, [0, 0, 1, 2]);
        assert!(
            !fsm.refuses_plain_announcement_of(&ours, "Secret"),
            "our own"
        );
        let (ungoverned, _) = authenticated_peer(30_000);
        assert!(!ungoverned.refuses_plain_announcement_of(&remote, "Secret"));
    }

    /// Under a governance document an authenticated participant changes on
    /// the regular SEDP topics what it announced there: only what it
    /// announced on a secure topic ignores plain changes. Without one, every
    /// known endpoint of an authenticated participant does, as before.
    #[test]
    fn only_an_endpoint_announced_securely_ignores_plain_changes_under_governance() {
        let fsm = governed(crate::security::access::ProtectionKind::Encrypt);
        let mut open = peer_writer(PEER);
        open.topic_name = "OpenData".to_string();
        fsm.handle_sedp_on(open.clone(), super::SedpChannel::Plain);
        assert!(
            !fsm.ignores_plain_sedp_about(&open.endpoint_guid),
            "announced in clear, changed in clear"
        );
        let mut secret = peer_writer(PEER);
        secret.endpoint_guid = GUID::new(PEER, [0, 0, 2, 2]);
        fsm.handle_sedp_on(secret.clone(), super::SedpChannel::Secure);
        assert!(fsm.ignores_plain_sedp_about(&secret.endpoint_guid));

        let (ungoverned, _) = authenticated_peer(30_000);
        let known = peer_writer(PEER);
        ungoverned.handle_sedp_on(known.clone(), super::SedpChannel::Plain);
        assert!(ungoverned.ignores_plain_sedp_about(&known.endpoint_guid));
    }

    /// An FSM authenticated with PEER, whose governance allows (or not)
    /// unauthenticated participants, with three topic rules: `Open*`
    /// announced in clear with read and write access control, `Free*`
    /// announced in clear with no access control, `*` on the secure topics.
    fn governed_allowing(allow_unauthenticated: bool) -> DiscoveryFsm {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        let topic = |expression: &str, discovery: bool, access: bool| TopicRule {
            topic_expression: expression.to_string(),
            enable_discovery_protection: discovery,
            enable_liveliness_protection: false,
            enable_read_access_control: access,
            enable_write_access_control: access,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        };
        let rule = DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::Encrypt,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![
                topic("Open*", false, true),
                topic("Free*", false, false),
                topic("*", true, true),
            ],
        };
        let (mut fsm, _) = authenticated_peer_announcing(
            Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            Some(crate::protocol::group::LOCAL_CAPABILITIES),
        );
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(rule)));
        fsm
    }

    /// A participant that does not implement DDS-Security: no identity
    /// token, so no handshake session.
    const STRANGER: [u8; 12] = [0x33; 12];

    fn stranger_announces(fsm: &DiscoveryFsm) {
        let mut spdp = announcement(30_000);
        spdp.participant_guid = GUID::new(STRANGER, RTPS_ENTITYID_PARTICIPANT);
        spdp.identity_token = None;
        fsm.handle_spdp(spdp);
    }

    /// The stranger's reader of `topic`, as discovery registered it.
    fn stranger_reader_of(fsm: &DiscoveryFsm, topic: &str) -> super::EndpointInfo {
        let mut reader = peer_writer(STRANGER);
        reader.topic_name = topic.to_string();
        reader.endpoint_guid = GUID::new(STRANGER, [0, 0, 0x12, 0x07]);
        assert!(
            !fsm.refuses_plain_announcement_of(&reader.endpoint_guid, topic),
            "fixture: discovery of {} is not protected",
            topic
        );
        fsm.handle_sedp_on(reader.clone(), super::SedpChannel::Plain);
        fsm.current_endpoint(topic, &reader.endpoint_guid)
            .expect("fixture: registered")
    }

    /// DDS Security v1.1 Sec.8.8.7.1: of the endpoints of an
    /// "Unauthenticated" participant, admitted because the governance allows
    /// unauthenticated participants, those of a topic that is read or write
    /// protected are not matched; those of a topic with no access control
    /// are, without asking access control.
    #[test]
    fn an_unauthenticated_participants_endpoint_of_a_protected_topic_is_not_matched() {
        let fsm = governed_allowing(true);
        stranger_announces(&fsm);
        assert!(fsm.is_participant_known(&STRANGER), "allowed: admitted");

        let protected = stranger_reader_of(&fsm, "OpenData");
        assert!(
            !fsm.admits_endpoint(&protected),
            "an unauthenticated participant's reader of a read-protected topic is surfaced \
             for matching (Sec.8.8.7.1 says reject)"
        );
        assert!(
            !fsm.find_readers_for_topic("OpenData")
                .iter()
                .any(|reader| reader.endpoint_guid == protected.endpoint_guid),
            "nor is it a reader the writers of the topic send to"
        );

        let free = stranger_reader_of(&fsm, "FreeData");
        assert!(fsm.admits_endpoint(&free), "no access control: matched");
        assert_eq!(fsm.find_readers_for_topic("FreeData").len(), 1);

        // The authenticated peer's reader of the protected topic is matched:
        // the rule is about the participant, not the topic alone.
        let mut ours = peer_writer(PEER);
        ours.topic_name = "OpenData".to_string();
        ours.endpoint_guid = GUID::new(PEER, [0, 0, 0x13, 0x07]);
        fsm.handle_sedp_on(ours.clone(), super::SedpChannel::Plain);
        let ours = fsm
            .current_endpoint("OpenData", &ours.endpoint_guid)
            .expect("registered");
        assert!(fsm.admits_endpoint(&ours), "authenticated: matched");

        // The data plane asks the same question of a writer, and of one
        // whose participant it does not know: no session, so unauthenticated.
        let writer = |prefix: [u8; 12]| GUID::new(prefix, [0, 0, 0x14, 0x02]);
        assert!(!fsm.admits_remote_endpoint("OpenData", &writer(STRANGER), true));
        assert!(fsm.admits_remote_endpoint("OpenData", &writer(PEER), true));
        assert!(fsm.admits_remote_endpoint("FreeData", &writer(STRANGER), true));
        assert!(!fsm.admits_remote_endpoint("OpenData", &writer([0x44; 12]), true));
        assert!(fsm.admits_remote_endpoint("FreeData", &writer([0x44; 12]), true));
    }

    /// DDS Security v1.1 Sec.8.8.2.2: with allow_unauthenticated_participants
    /// FALSE, a participant that does not implement DDS-Security "shall be
    /// rejected", whatever SecurityConfig::require_authentication says.
    #[test]
    fn an_unauthenticated_participant_is_rejected_unless_the_governance_allows_it() {
        let fsm = governed_allowing(false);
        stranger_announces(&fsm);
        assert!(
            !fsm.is_participant_known(&STRANGER),
            "the governance does not allow unauthenticated participants: rejected"
        );
        // And nothing of it is matched should it be known by another way.
        for topic in ["OpenData", "FreeData"] {
            assert!(fsm.refuses_unauthenticated(&STRANGER, topic), "{}", topic);
        }
        assert!(
            !fsm.refuses_unauthenticated(&PEER, "OpenData"),
            "authenticated"
        );
    }
}

/// Legacy TypeObject v1 arrival-order and same-name substitution tests.
///
/// Every type verdict goes through `MatchNotificationRegistry`
/// (`effective_type_object`, `pairing_type_verdict`): the remote endpoint's
/// legacy v1 object is replaced there, at judgement time, by a same-named
/// v1-projection-equivalent local type. The observables are the reader's
/// data-plane refusal (`is_writer_refused_by_any`) and the
/// `on_inconsistent_topic` callback count.
#[cfg(all(test, feature = "xtypes-structural-assignability"))]
mod legacy_v1_arrival_tests {
    use super::*;
    use crate::dds::match_notification::{MatchNotificationRegistry, MatchToken};
    use crate::dds::qos::QoS;
    use crate::protocol::discovery::types::TypeConsistencyEnforcement;
    use crate::transport::shm::ShmPolicy;
    use crate::xtypes::{
        decode_type_object_v1, legacy_v1_test_vectors, CommonStructMember, CommonUnionMember,
        CompleteMemberDetail, CompleteStructHeader, CompleteStructMember, CompleteStructType,
        CompleteTypeDetail, CompleteTypeObject, CompleteUnionHeader, CompleteUnionMember,
        CompleteUnionType, MemberFlag, StructTypeFlag, TypeIdentifier, TypeKind, UnionTypeFlag,
    };
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    // -----------------------------------------------------------------------
    // Legacy TypeObject v1 pipeline: live arrival-order tests.
    //
    // The first two tests replay the arrival order observed live against RTI
    // Connext 7.7.0 in --type-object-version 1 mode: the remote writer's SEDP
    // (carrying only a legacy v1 TypeObject, decoded by decode_type_object_v1,
    // no PID_TYPE_INFORMATION) is processed during participant bootstrap,
    // BEFORE the local reader exists; the remote participant has sent a single
    // SPDP (unconfirmed, probation active); the local reader is then announced
    // (handle_sedp) and only afterwards registers its match-registry entry
    // (the ReaderBuilder ordering). The writer TypeObject is the REAL captured
    // CoreDX wire vector for the OMG suite type Test::struct_x1, decoded
    // through the production v1 decoder, exactly as parse.rs produces it for
    // 0x0072/0x8021 payloads.
    // -----------------------------------------------------------------------

    /// A local participant (prefix 0xAA) with its match registry installed.
    fn local_fixture() -> (Arc<DiscoveryFsm>, Arc<MatchNotificationRegistry>, GUID) {
        let mut local_guid_bytes = [0u8; 16];
        for b in local_guid_bytes.iter_mut().take(12) {
            *b = 0xAA;
        }
        let local_guid = GUID::from_bytes(local_guid_bytes);
        let fsm = Arc::new(DiscoveryFsm::new(local_guid, 100_000));
        let local_prefix: [u8; 12] = {
            let b = local_guid.as_bytes();
            let mut p = [0u8; 12];
            p.copy_from_slice(&b[..12]);
            p
        };
        let match_reg = Arc::new(MatchNotificationRegistry::new(&fsm, local_prefix));
        fsm.set_match_registry(match_reg.clone());
        (fsm, match_reg, local_guid)
    }

    /// `guid` with its entity kind byte set (0x02 writer, 0x04 reader).
    fn with_entity_kind(guid: GUID, kind: u8) -> GUID {
        let mut bytes = guid.as_bytes();
        bytes[15] = kind;
        GUID::from_bytes(bytes)
    }

    /// One SPDP from a remote participant with prefix byte `fill` (known but
    /// unconfirmed: the probation purge task is not running in unit tests, so
    /// probation stays active). Returns its participant GUID.
    fn remote_participant_announces(fsm: &DiscoveryFsm, fill: u8) -> GUID {
        let mut bytes = [0u8; 16];
        for b in bytes.iter_mut().take(12) {
            *b = fill;
        }
        bytes[15] = 0xC1;
        let participant = GUID::from_bytes(bytes);
        fsm.handle_spdp(SpdpData {
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
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        participant
    }

    /// A SEDP announcement on topic "test" with nothing optional announced.
    fn sedp_base(
        type_name: &str,
        participant_guid: GUID,
        endpoint_guid: GUID,
        qos_hash: u64,
    ) -> SedpData {
        SedpData {
            topic_name: "test".into(),
            type_name: type_name.into(),
            participant_guid,
            endpoint_guid,
            qos_hash,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// Shared scaffolding for the two v1-arrival-order tests. Returns the
    /// match registry, the remote writer GUID, the observed
    /// inconsistent-topic counter and the reader's registration token, after
    /// driving: remote SPDP -> remote v1 writer SEDP -> local reader announce
    /// (with `reader_policy`) -> local reader entry registration.
    #[allow(clippy::type_complexity)]
    fn drive_v1_writer_first_scenario(
        reader_policy: Option<TypeConsistencyEnforcement>,
    ) -> (
        Arc<MatchNotificationRegistry>,
        GUID,
        Arc<AtomicU32>,
        MatchToken,
    ) {
        let (fsm, match_reg, local_guid) = local_fixture();

        // 1. Remote participant: ONE SPDP observed.
        let remote_participant = remote_participant_announces(&fsm, 0xBB);

        // 2. Remote writer SEDP arrives FIRST (no local reader yet), carrying
        //    the v1-decoded Test::struct_x1 exactly as parse.rs produces it.
        let decoded = decode_type_object_v1(&legacy_v1_test_vectors::COREDX_STRUCT_X1_V1)
            .expect("captured CoreDX struct_x1 v1 vector must decode");
        let writer_guid = with_entity_kind(remote_participant, 0x02);
        fsm.handle_sedp(SedpData {
            qos_hash: 1,
            type_object: Some(decoded.root),
            dependents: decoded.dependents,
            // Wire-faithful: parse.rs marks every v1-decoded object lossy.
            // The local type store holds no same-named type in this
            // scenario, so the substitution recourse misses and the decoded
            // object must remain authoritative (rejection preserved).
            type_object_legacy_v1: true,
            // connext to1 sends NO PID_TYPE_INFORMATION
            type_information: None,
            ..sedp_base("Test::struct_x1", remote_participant, writer_guid, 1)
        });

        // No local reader exists yet: nothing may be gated at this point.
        assert!(
            !match_reg.is_writer_refused_by_any(&writer_guid.as_bytes()),
            "gate must not be armed before any local reader exists"
        );

        // Local reader type: the suite's Test::struct_x2 (same shape as
        // struct_x1, member NAME x2 instead of x1 -- the discriminating
        // difference for the ignore_member_names cases).
        let struct_x2 = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Test::struct_x2"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::TRY_CONSTRUCT1,
                    member_type_id: TypeIdentifier::TK_INT32,
                },
                detail: CompleteMemberDetail::new("x2"),
            }],
        });

        // 3. Local reader ANNOUNCE (handle_sedp) -- runs BEFORE the reader's
        //    match-registry entry registration, per the ReaderBuilder order
        //    observed live.
        let mut reader_qos = QoS::best_effort();
        reader_qos.type_consistency = reader_policy;
        let local_reader_guid = with_entity_kind(local_guid, 0x04);
        fsm.handle_sedp(SedpData {
            qos: Some(reader_qos.clone()),
            type_object: Some(struct_x2.clone()),
            type_consistency: reader_qos.type_consistency.clone(),
            ..sedp_base("Test::struct_x2", local_guid, local_reader_guid, 2)
        });

        // 4. Reader match-registry entry registration (the ReaderBuilder
        //    step). catch_up runs synchronously inside.
        static STRUCT_X2_DESC: crate::core::types::TypeDescriptor =
            crate::core::types::TypeDescriptor {
                type_id: 0,
                type_name: "Test::struct_x2",
                size_bytes: 4,
                alignment: 4,
                is_variable_size: false,
                fields: &[],
            };
        let inconsistent_count = Arc::new(AtomicU32::new(0));
        let inconsistent_count_cb = Arc::clone(&inconsistent_count);
        let token = match_reg.register_reader_with_lifespan(
            "test".into(),
            reader_qos,
            &STRUCT_X2_DESC,
            Some(struct_x2),
            |_, _, _, _, _| {},
            None,
            None,
            Some(Box::new(move |_total, _change| {
                inconsistent_count_cb.fetch_add(1, Ordering::SeqCst);
            })),
            Arc::new(AtomicU64::new(u64::MAX)),
            ShmPolicy::default(),
        );
        // The token's Drop deregisters the entry: return it so the caller
        // keeps the registration alive for the duration of the test.
        (match_reg, writer_guid, inconsistent_count, token)
    }

    /// OMG suite negative scenario (`--ignore-member-names f`/`d` on the
    /// sub): the local reader carries the spec-default policy
    /// (ignore_member_names=false). The v1-decoded writer type
    /// (Test::struct_x1) pairs member id 0 but the member NAME differs
    /// (x1 vs x2), so structural assignability must REJECT, the late-reader
    /// scan must arm the writer data-plane gate at announce time, and
    /// catch_up must fire on_inconsistent_topic at entry registration
    /// DESPITE probation being active (the armed gate bypasses it).
    #[test]
    fn v1_writer_first_late_reader_strict_names_fires_inconsistent_topic() {
        // Spec default per XTypes v1.3 Sec 7.6.3.4.1: ignore_member_names =
        // false. This is exactly what the interop driver emits for
        // `--ignore-member-names f` and `d`.
        let (match_reg, writer_guid, inconsistent_count, _reader_token) =
            drive_v1_writer_first_scenario(Some(TypeConsistencyEnforcement::default()));

        assert!(
            match_reg.is_writer_refused_by_any(&writer_guid.as_bytes()),
            "late-reader scan must arm the data-plane gate against the \
             v1-decoded incompatible writer"
        );
        assert!(
            inconsistent_count.load(Ordering::SeqCst) >= 1,
            "on_inconsistent_topic must fire at reader entry registration \
             (catch_up, armed-gate path) despite active probation"
        );
    }

    /// Companion: with NO reader policy at all (the sub app run without any
    /// --ignore-member-names flag, as in the live mechanism test), the
    /// matcher's permissive local fallback (ignore_member_names=true)
    /// ACCEPTS struct_x1 -> struct_x2 (same member id and type, only the
    /// name differs). No gate, no notification -- this is by design and is
    /// what the suite's `--ignore-member-names t` OK-expectation relies on.
    #[test]
    fn v1_writer_first_late_reader_no_policy_stays_compatible() {
        let (match_reg, writer_guid, inconsistent_count, _reader_token) =
            drive_v1_writer_first_scenario(None);

        assert!(
            !match_reg.is_writer_refused_by_any(&writer_guid.as_bytes()),
            "permissive no-policy reader must NOT gate the v1-decoded writer \
             (struct_x1 vs struct_x2 differ only by member name)"
        );
        assert_eq!(
            inconsistent_count.load(Ordering::SeqCst),
            0,
            "no on_inconsistent_topic may fire for the permissive no-policy reader"
        );
    }

    // -----------------------------------------------------------------------
    // Lossy legacy-v1 same-name substitution (RTI 8-bit collapse).
    //
    // RTI Connext 7.7.0 TypeObject v1 emits the single wire kind BYTE for
    // IDL byte, uint8 AND int8 (measured: the OMG struct_byte_int8 /
    // struct_byte_uint8 negatives fail as false-accepts even in the
    // connext-vs-connext control cell). A v1-decoded object for an
    // IDENTICAL type can therefore differ from the local registration
    // (TK_BYTE vs TK_UINT8/TK_INT8), which would falsely reject the OMG
    // positives struct_uint8_uint8, struct_int8_int8 and
    // union_primitives_{final,appendable,mutable}. The judge substitutes a
    // same-named locally-registered CompleteTypeObject for the lossy v1
    // reconstruction (name miss = decoded object stays authoritative; the
    // negative-path coverage for that is the strict-names test above).
    // -----------------------------------------------------------------------

    /// Local struct type used by the substitution tests: the OMG suite's
    /// `Test::struct_primitive_uint8` as our own registration produces it
    /// (member kind TK_UINT8, which the v1 wire cannot represent).
    fn local_struct_primitive_uint8() -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Test::struct_primitive_uint8"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::TRY_CONSTRUCT1,
                    member_type_id: TypeIdentifier::Primitive(TypeKind::TK_UINT8),
                },
                detail: CompleteMemberDetail::new("x1"),
            }],
        })
    }

    /// The same type as a lossy v1 reconstruction: identical shape but the
    /// uint8 member arrives as v1 kind BYTE -> TK_BYTE (the collapse).
    fn v1_lossy_struct_primitive_uint8() -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Test::struct_primitive_uint8"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::TRY_CONSTRUCT1,
                    member_type_id: TypeIdentifier::Primitive(TypeKind::TK_BYTE),
                },
                detail: CompleteMemberDetail::new("x1"),
            }],
        })
    }

    /// Register `obj` in the participant type store keyed by its Minimal
    /// EquivalenceHash, exactly as ReaderBuilder/WriterBuilder do for local
    /// endpoint types (register_type_objects path).
    fn register_local_type(reg: &MatchNotificationRegistry, obj: &CompleteTypeObject) {
        let minimal = crate::dynamic::complete_to_minimal_type_object(obj)
            .expect("local type must convert to Minimal");
        let hash = minimal
            .compute_equivalence_hash()
            .expect("minimal hash must compute");
        let mut map = std::collections::HashMap::new();
        map.insert(hash, obj.clone());
        reg.register_type_objects(map);
    }

    /// OMG positive struct_uint8_uint8, hdds-PUB direction (the measured
    /// xcdr2-to1 hdds-connext dimension): our writer exists first, the
    /// remote connext READER then announces the SAME type whose v1
    /// TypeObject collapsed uint8 to BYTE. The same-name substitution must
    /// replace the lossy object with the local registration when the pair is
    /// judged: no false on_inconsistent_topic, and the type the endpoint is
    /// judged by is the faithful (TK_UINT8) object.
    #[test]
    fn v1_lossy_same_name_remote_reader_substitutes_local_type() {
        let (fsm, match_reg, local_guid) = local_fixture();
        let local_type = local_struct_primitive_uint8();

        // Local WRITER: match-registry entry + type store + topic registry
        // (announce), all before the remote reader appears -- the common
        // ordering in the hdds-pub cell.
        static UINT8_DESC: crate::core::types::TypeDescriptor =
            crate::core::types::TypeDescriptor {
                type_id: 0,
                type_name: "Test::struct_primitive_uint8",
                size_bytes: 1,
                alignment: 1,
                is_variable_size: false,
                fields: &[],
            };
        let inconsistent_count = Arc::new(AtomicU32::new(0));
        let cb_count = Arc::clone(&inconsistent_count);
        let token = match_reg.register_writer_full(
            "test".into(),
            QoS::best_effort(),
            &UINT8_DESC,
            Some(local_type.clone()),
            |_, _, _, _, _| {},
            None,
            Some(Box::new(move |_t, _c| {
                cb_count.fetch_add(1, Ordering::SeqCst);
            })),
            ShmPolicy::default(),
            None,
        );
        // Bind the registration for the test's lifetime (Drop deregisters).
        let _writer_token = token;
        register_local_type(&match_reg, &local_type);

        fsm.handle_sedp(SedpData {
            type_object: Some(local_type.clone()),
            ..sedp_base(
                "Test::struct_primitive_uint8",
                local_guid,
                with_entity_kind(local_guid, 0x02),
                1,
            )
        });

        // Remote participant (one SPDP: known).
        let remote_participant = remote_participant_announces(&fsm, 0xCC);

        // Remote READER announces the SAME type; its v1 TypeObject arrives
        // with the uint8 member collapsed to BYTE.
        let reader_guid = with_entity_kind(remote_participant, 0x04);
        fsm.handle_sedp(SedpData {
            type_object: Some(v1_lossy_struct_primitive_uint8()),
            type_object_legacy_v1: true,
            ..sedp_base(
                "Test::struct_primitive_uint8",
                remote_participant,
                reader_guid,
                2,
            )
        });

        assert_eq!(
            inconsistent_count.load(Ordering::SeqCst),
            0,
            "identical-type v1 reader must not raise on_inconsistent_topic \
             (uint8-vs-BYTE is v1 wire lossiness, not a type mismatch)"
        );

        // The endpoint's record keeps the raw lossy announcement and its
        // marker; the substitution happens where the type is judged
        // (`effective_type_object`), and that is the faithful object.
        let readers = fsm.find_readers_for_topic("test");
        assert_eq!(readers.len(), 1);
        assert!(
            readers[0].type_object_legacy_v1,
            "the record keeps the lossy marker: the judge re-attempts the substitution"
        );
        let judged = match_reg
            .effective_type_object(&readers[0])
            .expect("the judged reader must have a TypeObject");
        match judged {
            CompleteTypeObject::Struct(s) => {
                assert_eq!(
                    s.member_seq[0].common.member_type_id,
                    TypeIdentifier::Primitive(TypeKind::TK_UINT8),
                    "judged object must be the substituted local one (TK_UINT8)"
                );
            }
            other => panic!("expected Struct, got {other:?}"),
        }
    }

    /// OMG positive union_primitives_final, hdds-SUB ordering (remote v1
    /// WRITER first, store empty at arrival; local reader late): the lazy
    /// same-name substitution at the late-reader scan and at catch_up must
    /// rescue the pair. The remote object is the REAL hand-built v1 wire
    /// payload decoded by the production decoder (uint8 discriminator and
    /// uint8/int8/byte cases all collapsed to BYTE).
    #[test]
    fn v1_lossy_union_same_name_sub_ordering_no_false_inconsistent() {
        let (fsm, match_reg, local_guid) = local_fixture();

        // Remote participant + remote v1 WRITER arrive FIRST (store empty:
        // the substitution must miss and keep the lossy object).
        let remote_participant = remote_participant_announces(&fsm, 0xBB);
        let decoded = decode_type_object_v1(&legacy_v1_test_vectors::UNION_PRIMITIVES_FINAL_V1)
            .expect("union_primitives_final v1 payload must decode");
        let writer_guid = with_entity_kind(remote_participant, 0x02);
        fsm.handle_sedp(SedpData {
            type_object: Some(decoded.root),
            dependents: decoded.dependents,
            type_object_legacy_v1: true,
            ..sedp_base(
                "Test::union_primitives_final",
                remote_participant,
                writer_guid,
                1,
            )
        });

        // Local union registration: what our own XML loading produces for
        // union_primitives_final (uint8 discriminator kept distinct,
        // 1-based case member ids per DDS-XTypes 7.3.1.2.1.1).
        let case = |id: u32, label: i32, kind: TypeKind, name: &str| CompleteUnionMember {
            common: CommonUnionMember {
                member_id: id,
                member_flags: MemberFlag::TRY_CONSTRUCT1,
                member_type_id: TypeIdentifier::Primitive(kind),
                label_seq: vec![label],
            },
            detail: CompleteMemberDetail::new(name),
        };
        let local_union = CompleteTypeObject::Union(CompleteUnionType {
            union_flags: UnionTypeFlag::IS_FINAL,
            header: CompleteUnionHeader {
                discriminator: TypeIdentifier::Primitive(TypeKind::TK_UINT8),
                discriminator_flags: MemberFlag::empty(),
                detail: CompleteTypeDetail::new("Test::union_primitives_final"),
            },
            member_seq: vec![
                case(1, 1, TypeKind::TK_UINT8, "x1"),
                case(2, 2, TypeKind::TK_UINT16, "x2"),
                case(3, 3, TypeKind::TK_UINT32, "x3"),
                case(4, 4, TypeKind::TK_UINT64, "x4"),
                case(5, 5, TypeKind::TK_INT8, "x5"),
                case(6, 6, TypeKind::TK_INT16, "x6"),
                case(7, 7, TypeKind::TK_INT32, "x7"),
                case(8, 8, TypeKind::TK_INT64, "x8"),
                case(9, 9, TypeKind::TK_BOOLEAN, "x9"),
                case(10, 10, TypeKind::TK_FLOAT32, "x10"),
                case(11, 11, TypeKind::TK_FLOAT64, "x11"),
                case(12, 12, TypeKind::TK_FLOAT128, "x12"),
                case(13, 13, TypeKind::TK_BYTE, "x13"),
                case(14, 14, TypeKind::TK_CHAR8, "x14"),
            ],
        });
        register_local_type(&match_reg, &local_union);

        // Local reader announce (same type name, spec-default policy: the
        // strictest profile the suite applies to these positives).
        let mut reader_qos = QoS::best_effort();
        reader_qos.type_consistency = Some(TypeConsistencyEnforcement::default());
        fsm.handle_sedp(SedpData {
            qos: Some(reader_qos.clone()),
            type_object: Some(local_union.clone()),
            type_consistency: reader_qos.type_consistency.clone(),
            ..sedp_base(
                "Test::union_primitives_final",
                local_guid,
                with_entity_kind(local_guid, 0x04),
                2,
            )
        });

        // The late-reader scan must have substituted (name hit) and found
        // the pair compatible: no data-plane gate.
        assert!(
            !match_reg.is_writer_refused_by_any(&writer_guid.as_bytes()),
            "identical union (v1-lossy vs local) must not arm the gate"
        );

        // Reader entry registration: catch_up must also substitute and stay
        // quiet.
        static UNION_DESC: crate::core::types::TypeDescriptor =
            crate::core::types::TypeDescriptor {
                type_id: 0,
                type_name: "Test::union_primitives_final",
                size_bytes: 24,
                alignment: 8,
                is_variable_size: false,
                fields: &[],
            };
        let inconsistent_count = Arc::new(AtomicU32::new(0));
        let cb_count = Arc::clone(&inconsistent_count);
        let token = match_reg.register_reader_with_lifespan(
            "test".into(),
            reader_qos,
            &UNION_DESC,
            Some(local_union),
            |_, _, _, _, _| {},
            None,
            None,
            Some(Box::new(move |_t, _c| {
                cb_count.fetch_add(1, Ordering::SeqCst);
            })),
            Arc::new(AtomicU64::new(u64::MAX)),
            ShmPolicy::default(),
        );
        // Bind the registration for the test's lifetime (Drop deregisters).
        let _reader_token = token;

        assert_eq!(
            inconsistent_count.load(Ordering::SeqCst),
            0,
            "identical union must not raise on_inconsistent_topic in the \
             writer-first ordering (lazy same-name substitution)"
        );
        assert!(
            !match_reg.is_writer_refused_by_any(&writer_guid.as_bytes()),
            "identical union must not arm the gate once the reader's entry judges it"
        );
    }

    /// THE ADVERSARIAL CASE: a remote v1 publisher announces `Test::adv_foo`
    /// as `{ float64 a }` while the local reader registered `Test::adv_foo`
    /// as `{ int32 a }`. Same fully-qualified name, structurally different
    /// types. Name-triggered substitution would replace the decoded
    /// object with the local one, the pair would match, and remote float64
    /// data would be silently decoded as int32. With the projection-equivalence
    /// gate the same-named local is NOT equivalent (float64 vs int32 is a
    /// v1-representable difference), the decoded object stays
    /// authoritative, and the pair is REJECTED: gate armed +
    /// on_inconsistent_topic fired.
    #[test]
    fn v1_adversarial_same_name_different_shape_rejects() {
        fn adv_struct(kind: TypeKind) -> CompleteTypeObject {
            CompleteTypeObject::Struct(CompleteStructType {
                struct_flags: StructTypeFlag::IS_APPENDABLE,
                header: CompleteStructHeader {
                    base_type: None,
                    detail: CompleteTypeDetail::new("Test::adv_foo"),
                },
                member_seq: vec![CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::TRY_CONSTRUCT1,
                        member_type_id: TypeIdentifier::Primitive(kind),
                    },
                    detail: CompleteMemberDetail::new("a"),
                }],
            })
        }

        let (fsm, match_reg, local_guid) = local_fixture();

        // Remote participant known (one SPDP).
        let remote_participant = remote_participant_announces(&fsm, 0xEE);

        // Remote v1 WRITER arrives first: same name, float64 member.
        let writer_guid = with_entity_kind(remote_participant, 0x02);
        fsm.handle_sedp(SedpData {
            type_object: Some(adv_struct(TypeKind::TK_FLOAT64)),
            type_object_legacy_v1: true,
            ..sedp_base("Test::adv_foo", remote_participant, writer_guid, 1)
        });

        // Local reader: SAME NAME, int32 member -- registered in the type
        // store so the name RESOLVES (the substitution trigger fires) and
        // only the equivalence gate stands between us and corruption.
        let local_type = adv_struct(TypeKind::TK_INT32);
        register_local_type(&match_reg, &local_type);

        let mut reader_qos = QoS::best_effort();
        reader_qos.type_consistency = Some(TypeConsistencyEnforcement::default());
        fsm.handle_sedp(SedpData {
            qos: Some(reader_qos.clone()),
            type_object: Some(local_type.clone()),
            type_consistency: reader_qos.type_consistency.clone(),
            ..sedp_base(
                "Test::adv_foo",
                local_guid,
                with_entity_kind(local_guid, 0x04),
                2,
            )
        });

        // Entry registration: catch_up judges the pair (the local reader's
        // announce above judges nothing: only registered entries judge a
        // remote endpoint).
        static ADV_DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0,
            type_name: "Test::adv_foo",
            size_bytes: 4,
            alignment: 4,
            is_variable_size: false,
            fields: &[],
        };
        let inconsistent_count = Arc::new(AtomicU32::new(0));
        let cb_count = Arc::clone(&inconsistent_count);
        let token = match_reg.register_reader_with_lifespan(
            "test".into(),
            reader_qos,
            &ADV_DESC,
            Some(local_type),
            |_, _, _, _, _| {},
            None,
            None,
            Some(Box::new(move |_t, _c| {
                cb_count.fetch_add(1, Ordering::SeqCst);
            })),
            Arc::new(AtomicU64::new(u64::MAX)),
            ShmPolicy::default(),
        );
        // Bind the registration for the test's lifetime (Drop deregisters).
        let _reader_token = token;

        // The equivalence gate must have refused the substitution and the
        // judgement must have armed the data-plane gate.
        assert!(
            match_reg.is_writer_refused_by_any(&writer_guid.as_bytes()),
            "same-named but structurally different v1 writer must be gated"
        );
        assert!(
            inconsistent_count.load(Ordering::SeqCst) >= 1,
            "adversarial same-name pair must raise on_inconsistent_topic \
             (float64-vs-int32 is a real type mismatch, not v1 lossiness)"
        );
    }

    /// The named types a legacy v1 TypeObject references (`dependents`, keyed
    /// by the Minimal hash the member references carry) reach the
    /// participant's type store when the SEDP is handled, so the hash a
    /// decoded member refers to resolves afterwards. The vector is the
    /// hand-built `Test::StructWithEnum`, whose `color` member references the
    /// named enum `Test::Color`.
    #[test]
    fn v1_dependents_are_registered_in_the_type_store_by_handle_sedp() {
        let (fsm, match_reg, _local_guid) = local_fixture();
        let remote_participant = remote_participant_announces(&fsm, 0xDD);

        let decoded = decode_type_object_v1(&legacy_v1_test_vectors::STRUCT_WITH_ENUM_V1)
            .expect("hand-built struct_with_enum v1 payload must decode");
        assert_eq!(decoded.dependents.len(), 1, "fixture: one named dependent");
        let (dep_hash, dep_obj) = decoded.dependents[0].clone();
        assert!(
            match_reg.resolve_type_by_minimal_hash(&dep_hash).is_none(),
            "fixture: the type store does not know the enum yet"
        );

        fsm.handle_sedp(SedpData {
            type_object: Some(decoded.root),
            dependents: decoded.dependents,
            type_object_legacy_v1: true,
            ..sedp_base(
                "Test::StructWithEnum",
                remote_participant,
                with_entity_kind(remote_participant, 0x02),
                1,
            )
        });

        assert_eq!(
            match_reg.resolve_type_by_minimal_hash(&dep_hash),
            Some(dep_obj),
            "the v1 dependent must be resolvable by its hash once its SEDP is handled"
        );
    }

    /// The ShapeType TypeObject `shape_main` announces, from the one file
    /// that defines it for the application too.
    mod shape_main {
        use crate::xtypes::*;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/shape_common/shape_type_object.rs"
        ));
    }

    static SHAPE_DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
        type_id: 0,
        type_name: "ShapeType",
        size_bytes: 0,
        alignment: 4,
        is_variable_size: true,
        fields: &[],
    };

    /// A Connext 7.7 publisher of the interop suite's ShapeType announces
    /// only a legacy v1 TypeObject (PID 0x8021, no PID_TYPE_INFORMATION):
    /// the real captured bytes, decoded by the production decoder. Its
    /// unbounded `sequence<uint8>` arrives with bound 0x7FFFFFFF and element
    /// kind BYTE. A shape_main reader (type consistency left unset) must
    /// judge it by its own same-named ShapeType: no gate, no
    /// on_inconsistent_topic. The reader's type is only the one its entry
    /// registers with, as for an application reader: a root type is not in
    /// the participant type store.
    #[test]
    fn connext_v1_shapetype_writer_matches_a_shape_main_reader() {
        let (fsm, match_reg, local_guid) = local_fixture();
        let local_type = shape_main::shape_type_object();

        let reader_qos = QoS::best_effort();
        fsm.handle_sedp(SedpData {
            qos: Some(reader_qos.clone()),
            type_object: Some(local_type.clone()),
            ..sedp_base(
                "ShapeType",
                local_guid,
                with_entity_kind(local_guid, 0x04),
                2,
            )
        });
        let inconsistent_count = Arc::new(AtomicU32::new(0));
        let cb_count = Arc::clone(&inconsistent_count);
        let _reader_token = match_reg.register_reader_with_lifespan(
            "test".into(),
            reader_qos,
            &SHAPE_DESC,
            Some(local_type.clone()),
            |_, _, _, _, _| {},
            None,
            None,
            Some(Box::new(move |_t, _c| {
                cb_count.fetch_add(1, Ordering::SeqCst);
            })),
            Arc::new(AtomicU64::new(u64::MAX)),
            ShmPolicy::default(),
        );

        let remote_participant = remote_participant_announces(&fsm, 0xBB);
        let decoded = decode_type_object_v1(&legacy_v1_test_vectors::CONNEXT_SHAPETYPE_V1)
            .expect("captured Connext ShapeType v1 vector must decode");
        let writer_guid = with_entity_kind(remote_participant, 0x02);
        fsm.handle_sedp(SedpData {
            type_object: Some(decoded.root),
            dependents: decoded.dependents,
            type_object_legacy_v1: true,
            ..sedp_base("ShapeType", remote_participant, writer_guid, 1)
        });

        assert!(
            !match_reg.is_writer_refused_by_any(&writer_guid.as_bytes()),
            "the Connext ShapeType writer must not be refused"
        );
        assert_eq!(inconsistent_count.load(Ordering::SeqCst), 0);
        let writers = fsm.find_writers_for_topic("test");
        assert_eq!(writers.len(), 1);
        assert_eq!(
            match_reg.effective_type_object(&writers[0]),
            Some(local_type),
            "the Connext writer is judged by shape_main's own ShapeType"
        );
    }

    /// The other direction: a shape_main writer, then a Connext 7.7 reader
    /// announcing the same captured v1 ShapeType. The reader is judged by
    /// shape_main's ShapeType and no on_inconsistent_topic fires.
    #[test]
    fn connext_v1_shapetype_reader_matches_a_shape_main_writer() {
        let (fsm, match_reg, local_guid) = local_fixture();
        let local_type = shape_main::shape_type_object();
        let inconsistent_count = Arc::new(AtomicU32::new(0));
        let cb_count = Arc::clone(&inconsistent_count);
        let _writer_token = match_reg.register_writer_full(
            "test".into(),
            QoS::best_effort(),
            &SHAPE_DESC,
            Some(local_type.clone()),
            |_, _, _, _, _| {},
            None,
            Some(Box::new(move |_t, _c| {
                cb_count.fetch_add(1, Ordering::SeqCst);
            })),
            ShmPolicy::default(),
            None,
        );
        fsm.handle_sedp(SedpData {
            type_object: Some(local_type.clone()),
            ..sedp_base(
                "ShapeType",
                local_guid,
                with_entity_kind(local_guid, 0x02),
                1,
            )
        });

        let remote_participant = remote_participant_announces(&fsm, 0xCC);
        let decoded = decode_type_object_v1(&legacy_v1_test_vectors::CONNEXT_SHAPETYPE_V1)
            .expect("captured Connext ShapeType v1 vector must decode");
        fsm.handle_sedp(SedpData {
            type_object: Some(decoded.root),
            dependents: decoded.dependents,
            type_object_legacy_v1: true,
            ..sedp_base(
                "ShapeType",
                remote_participant,
                with_entity_kind(remote_participant, 0x04),
                2,
            )
        });

        assert_eq!(inconsistent_count.load(Ordering::SeqCst), 0);
        let readers = fsm.find_readers_for_topic("test");
        assert_eq!(readers.len(), 1);
        assert_eq!(
            match_reg.effective_type_object(&readers[0]),
            Some(local_type),
            "the Connext reader is judged by shape_main's own ShapeType"
        );
    }
}
