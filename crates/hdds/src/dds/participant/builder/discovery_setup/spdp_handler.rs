// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP packet handler.
//!
//! Handles SPDP (Simple Participant Discovery Protocol) packets including:
//! - SPDP parsing (full and partial)
//! - Metatraffic locator inference
//! - Dialect-specific discovery handshake (via DialectEncoder trait)
//! - SEDP re-announcements to unicast locators
//!
//! # Architecture
//!
//! This handler is vendor-neutral. Vendor-specific discovery handshake
//! behavior (e.g., the `Rti` dialect's discovery HEARTBEATs) is encapsulated in
//! the `DialectEncoder::build_discovery_handshake()` trait method.

use crate::core::discovery::multicast::Origin;
use crate::core::discovery::{
    multicast::{
        build_heartbeat_submessage, build_heartbeat_submessage_final, build_spdp_rtps_packet,
        rtps_packet::next_sedp_heartbeat_count, DiscoveryFsm, SedpEndpointKind, SedpSend,
        SpdpVerdict,
    },
    spdp_announcer::{spdp_announcement, AnnouncedLocators, SPDP_SENT_COUNT},
};
use crate::core::discovery::{SpdpPeerSet, GUID};
use crate::protocol::dialect::{get_encoder, Dialect};
use crate::protocol::discovery::constants::{CDR_LE, PID_METATRAFFIC_UNICAST_LOCATOR, PL_CDR2_LE};
use crate::protocol::discovery::{parse_spdp, parse_spdp_partial, ParseError, SpdpData};
use crate::transport::UdpTransport;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::sedp_handler::{data_submessage_at, data_writer_and_seq};
use super::{super::entity_registry::SedpAnnouncementsCache, SpdpSecurityTokens};

// =============================================================================
// SEDP Retry Flood Prevention
// =============================================================================
// Without deduplication, each SPDP received would spawn a NEW retry thread
// and a burst of SPDPs would flood the peer with SEDP sends, which it may
// drop as lost samples.
//
// A RetryGuard (RAII) ensures only ONE retry thread per peer.
//
// After a retry cycle completes, the peer is moved to COMPLETED_PEERS.
// Subsequent SPDPs from the same peer will NOT trigger re-announce.
// This prevents continuous SEDP DATA + non-Final HEARTBEAT floods, which can
// keep a peer from starting its own SEDP writer.

/// Identifies one discovery path inside a process.
///
/// GUID prefixes alone are not enough: participant IDs are reused across DDS
/// domains, so two participants in the same process can have identical local
/// and remote prefixes. The local metatraffic port carries the domain/participant
/// scope from the RTPS port mapping and keeps their retry state independent.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DiscoveryPeerKey {
    local_prefix: [u8; 12],
    local_metatraffic_port: u16,
    peer_prefix: [u8; 12],
}

impl DiscoveryPeerKey {
    fn new(local_prefix: [u8; 12], local_metatraffic_port: u16, peer_prefix: [u8; 12]) -> Self {
        Self {
            local_prefix,
            local_metatraffic_port,
            peer_prefix,
        }
    }
}

/// Tracks active retry threads by local discovery path and peer GUID prefix.
/// Prevents multiple threads from retrying SEDP to the same peer.
fn active_retries() -> &'static Mutex<HashSet<DiscoveryPeerKey>> {
    static ACTIVE_RETRIES: OnceLock<Mutex<HashSet<DiscoveryPeerKey>>> = OnceLock::new();
    ACTIVE_RETRIES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Tracks peers that completed at least one SEDP reannounce cycle.
/// Peers in this set will NOT be re-announced on subsequent SPDPs.
fn completed_peers() -> &'static Mutex<HashSet<DiscoveryPeerKey>> {
    static COMPLETED_PEERS: OnceLock<Mutex<HashSet<DiscoveryPeerKey>>> = OnceLock::new();
    COMPLETED_PEERS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// TTL for RESPONDED_SPDP_PEERS entries.
///
/// An entry not refreshed (no SPDP seen from this peer) for longer than this
/// gets lazily evicted on the next `mark_peer_responded` call. Chosen to
/// comfortably cover active peers (SPDP announce every 3 s) while bounding
/// memory in long-running processes that see steady peer churn. The value is
/// large relative to the 3 s announce interval so benign scheduling jitter
/// cannot evict a live peer; and small enough to reclaim memory for departed
/// peers within a minute.
const PEER_SEEN_TTL: Duration = Duration::from_secs(60);

/// Tracks peers we have already sent an immediate SPDP unicast
/// response to on each local discovery path, along with the instant of the
/// most recent SPDP we observed from them.
///
/// Without this dedup, every SPDP received (including our own unicast
/// responses bouncing back as incoming packets) triggers a fresh immediate
/// response, creating a reactive bounce loop with N*(N-1) edges between the
/// N participants in a domain: SPDP traffic grows without bound for as long
/// as the participants run.
///
/// The immediate SPDP response exists to accelerate first contact with
/// a peer (otherwise first contact waits for the peer's next periodic SPDP
/// before our discovery HEARTBEATs are processed). That goal is satisfied by responding **once**
/// per peer; subsequent SPDPs from the same peer are already covered by our
/// own periodic SPDP announcer, so suppressing them is safe.
///
/// **Lease tracking:** each entry stores the timestamp of the last SPDP
/// observed for that peer. `mark_peer_responded` lazily evicts entries older
/// than [`PEER_SEEN_TTL`] on every call. This bounds memory in processes
/// that see steady peer churn (without eviction every peer ever seen would
/// stay in the map for the process lifetime) and lets a peer that disappeared for more than the TTL get the
/// 200 ms immediate-SPDP boost again on rejoin.
///
/// **Scope note:** this dedup set gates only the immediate SPDP *unicast
/// response*. The SEDP re-announce path has its own independent dedup via
/// `COMPLETED_PEERS` / `ACTIVE_RETRIES` (above); do not assume
/// membership here implies anything about the SEDP side, and vice versa.
///
/// **Why no dispose hook on a lease of 0:** an
/// `if lease_duration_ms == 0 { forget_peer; return }` short-circuit driven
/// by remote SPDP announcements with a lease of 0 is deliberately absent:
/// its `return` would skip a `RetryGuard`/`COMPLETED_PEERS`
/// state update the rest
/// of a full announcement's handling makes. The RTPS signal of a departure
/// is the dispose/unregister of the DCPSParticipant instance, a DATA with no
/// payload, which never reaches that handling (it parses as no
/// announcement): `handle_spdp_packet` takes it first, apart
/// (`detect_spdp_participant_dispose`). Do not add lease-based logic here.
///
/// Known limitation, kept on purpose: a 1.4.x peer's lease-0 farewell
/// retires the participant but leaves its per-peer records (this map and
/// `COMPLETED_PEERS`), so that peer re-created in its process with the same
/// prefix is not re-announced to until `completed_peers` forgets it (on a
/// departure in the dispose form or any other removal, `forget_remote_peer`, or
/// on our own participant's drop, `forget_local_participant`).
fn responded_spdp_peers() -> &'static Mutex<HashMap<DiscoveryPeerKey, Instant>> {
    static RESPONDED_SPDP_PEERS: OnceLock<Mutex<HashMap<DiscoveryPeerKey, Instant>>> =
        OnceLock::new();
    RESPONDED_SPDP_PEERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Drop every discovery-dedup entry that belongs to one local participant.
///
/// The three maps above are process-global. A GUID prefix made of
/// `vendor id + host id + PID + participant id` would repeat: the participant
/// id is handed out by scanning for the lowest one whose RTPS ports are free,
/// so the NEXT participant built in the same process after one terminated
/// would get the same id, the same prefix and the same port, a
/// `DiscoveryPeerKey` identical, byte for byte, to the dead one's. The prefix
/// is unique per participant (`entity_registry::generate_guid`), so a
/// successor does not share the key; the eviction stays, as it is also what
/// bounds the maps.
///
/// Without eviction `COMPLETED_PEERS` would let the new participant inherit
/// "already announced" from its predecessor, and `RetryGuard::try_acquire`
/// would refuse to retry SEDP towards a peer it had never spoken to.
/// Discovery would then stop with no error reported anywhere: the peer would
/// simply never surface. Any process that destroys and recreates
/// participants is exposed, not only a test binary.
///
/// Called from `Participant::drop`, which is also what bounds the growth of
/// these maps in a long-lived process.
pub(crate) fn forget_local_participant(local_prefix: [u8; 12]) {
    if let Ok(mut set) = active_retries().lock() {
        set.retain(|key| key.local_prefix != local_prefix);
    }
    if let Ok(mut set) = completed_peers().lock() {
        set.retain(|key| key.local_prefix != local_prefix);
    }
    if let Ok(mut map) = responded_spdp_peers().lock() {
        map.retain(|key, _| key.local_prefix != local_prefix);
    }
}

/// Pure, testable core of the mark-responded-with-TTL logic.
///
/// Evicts entries whose `last_seen` is older than `ttl` (lazy GC on every
/// call, amortized O(1) per call in steady state), then inserts / refreshes
/// the entry for `peer` at `now`. Returns `true` iff the discovery path was
/// absent or just evicted -- i.e. the caller should send the immediate
/// unicast response. Returns `false` on refresh of an already-tracked peer.
fn mark_peer_responded_at(
    map: &mut HashMap<DiscoveryPeerKey, Instant>,
    peer: DiscoveryPeerKey,
    now: Instant,
    ttl: Duration,
) -> bool {
    map.retain(|_, last_seen| now.duration_since(*last_seen) < ttl);
    map.insert(peer, now).is_none()
}

/// Record that we observed an SPDP from this peer. Returns `true`
/// if the caller should send the immediate unicast response (new peer, or
/// peer that had expired from the set), `false` if we have already responded
/// within [`PEER_SEEN_TTL`].
///
/// Handles a poisoned mutex by recovering the inner map so discovery stays
/// best-effort functional even after a panic elsewhere.
fn mark_peer_responded(peer: DiscoveryPeerKey) -> bool {
    let mut map = responded_spdp_peers()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    mark_peer_responded_at(&mut map, peer, Instant::now(), PEER_SEEN_TTL)
}

/// RAII guard for SEDP retry thread deduplication.
///
/// Ensures only one retry thread runs per local discovery path and peer. When
/// dropped, moves that key from ACTIVE_RETRIES to COMPLETED_PEERS.
struct RetryGuard {
    peer: DiscoveryPeerKey,
}

impl RetryGuard {
    /// Try to acquire exclusive retry rights for a peer.
    ///
    /// Returns `Some(RetryGuard)` if no other thread is retrying to this peer,
    /// `None` if a retry is already in progress OR already completed.
    fn try_acquire(peer: DiscoveryPeerKey) -> Option<Self> {
        // Check completed peers first -- skip if already announced
        if let Ok(completed) = completed_peers().lock() {
            if completed.contains(&peer) {
                return None;
            }
        }
        let mut set = active_retries().lock().ok()?;
        if set.contains(&peer) {
            return None;
        }
        set.insert(peer);
        Some(Self { peer })
    }
}

impl Drop for RetryGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = active_retries().lock() {
            set.remove(&self.peer);
        }
        // Mark peer as completed to suppress future re-announce
        if let Ok(mut completed) = completed_peers().lock() {
            completed.insert(self.peer);
        }
    }
}

/// Detect a remote participant's departure: the dispose/unregister of its
/// instance of the SPDP built-in topic (DCPSParticipant): PID_STATUS_INFO,
/// RTPS v2.5 Sec.9.6.4.9.
///
/// The DATA `cdr_offset` names (`data_submessage_at`) comes from the SPDP
/// writer (`ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER`), carries inline QoS
/// and no data payload (Q=1, D=0), and a PID_STATUS_INFO with the DISPOSED
/// or UNREGISTERED bit. The participant is its instance key, read from
/// PID_KEY_HASH (Sec.9.6.4.8) or, when that is absent, from
/// PID_PARTICIPANT_GUID in the key-only payload (K=1, Sec.9.6.3.2), the
/// only place a departure in that form names its participant.
///
/// A participant announces only its own departure: the SPDP writer that
/// sent the DATA is that participant's (Sec.8.5.3.2), so the key must name
/// the participant whose prefix the message carries (the RTPS header, or
/// the INFO_SRC the walk split it on). A departure naming another is
/// refused. Returns the participant, under its participant entity id;
/// `None` for anything else, an announcement included.
fn detect_spdp_participant_dispose(payload: &[u8], cdr_offset: usize) -> Option<GUID> {
    use crate::protocol::builder::{
        extract_inline_qos_at, extract_key_hash, extract_participant_guid_from_serialized_key,
        extract_serialized_key_at, extract_status_info,
    };

    let data_off = data_submessage_at(payload, cdr_offset)?;
    let (writer_entity_id, _) = data_writer_and_seq(payload, data_off)?;
    if writer_entity_id != crate::core::rtps_constants::RTPS_ENTITYID_SPDP_WRITER {
        return None;
    }
    let flags = payload[data_off + 1];
    if flags & 0x02 == 0 || flags & 0x04 != 0 {
        return None;
    }
    let (inline_qos, is_le) = extract_inline_qos_at(payload, data_off)?;
    if extract_status_info(inline_qos, is_le)? & 0x03 == 0 {
        return None;
    }
    let key = extract_key_hash(inline_qos, is_le).or_else(|| {
        extract_serialized_key_at(payload, data_off)
            .and_then(extract_participant_guid_from_serialized_key)
    })?;
    let sender_prefix = payload.get(8..20)?;
    if key[..12] != *sender_prefix {
        log::debug!(
            "[SPDP] departure of {:02x?} sent under {:02x?}: not that participant's, ignored",
            &key[..12],
            sender_prefix
        );
        return None;
    }
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&key[..12]);
    Some(GUID::new(
        prefix,
        crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
    ))
}

/// Retire a participant that announced its departure
/// (`detect_spdp_participant_dispose`): out of discovery, with its
/// endpoints, out of the unicast SPDP destinations, and out of the
/// per-peer discovery records (`forget_remote_peer`). Our own departure,
/// heard back over multicast, is not ours to apply, nor is the departure of
/// a participant that authenticated with us: this one came on the plain
/// DCPSParticipants topic (`DiscoveryFsm::ignores_plain_departure_of`,
/// DDS Security v1.1 Sec.7.4.1.6).
fn apply_participant_departure(
    departed: GUID,
    our_guid_prefix: [u8; 12],
    fsm: &DiscoveryFsm,
    discovered_peers: Option<&SpdpPeerSet>,
) {
    if departed.prefix == our_guid_prefix {
        return;
    }
    if fsm.ignores_plain_departure_of(&departed.prefix) {
        return;
    }
    log::debug!("[SPDP] participant {:?} announced its departure", departed);
    fsm.remove_departed_participant(departed);
    if let Some(peers) = discovered_peers {
        peers.remove_discovered(&departed.prefix);
    }
    forget_remote_peer(our_guid_prefix, departed.prefix);
}

/// Retire a participant that announced its departure SEALED, on the secure
/// participant endpoints (`DiscoveryFsm::sealed_departure_for`): the one
/// departure of an authenticated participant that is applied (DDS Security
/// v1.1 Sec.7.4.1.6). `departed` is what `DiscoveryFsm::open_sealed_departure`
/// decoded after the dispatch checked authentication and the configured
/// discovery protection kind (including NONE).
#[cfg(feature = "security")]
pub(super) fn apply_sealed_participant_departure(
    departed: GUID,
    our_guid_prefix: [u8; 12],
    fsm: &DiscoveryFsm,
    discovered_peers: Option<&SpdpPeerSet>,
) {
    // Our own prefix: a datagram naming us can only be one of our own, heard
    // back (a peer that lists our metatraffic locator among its own has it
    // sent to us). It is not ours to apply, exactly as on the clear path.
    if departed.prefix == our_guid_prefix {
        return;
    }
    log::debug!(
        "[SPDP] authenticated participant {:?} announced its departure on DCPSParticipantsSecure",
        departed
    );
    fsm.remove_departed_participant(departed);
    if let Some(peers) = discovered_peers {
        peers.remove_discovered(&departed.prefix);
    }
    forget_remote_peer(our_guid_prefix, departed.prefix);
}

/// Drop what this local participant recorded about one remote peer: that it
/// was answered (`responded_spdp_peers`) and that its SEDP re-announcement
/// is done (`completed_peers`). A participant re-created in the departed
/// process gets the same GUID prefix (`forget_local_participant` explains
/// why); left in place, "already announced" would keep us from announcing
/// our endpoints to it, with no error anywhere. A retry still running
/// (`active_retries`) owns its entry and records completion when it ends.
fn forget_remote_peer(local_prefix: [u8; 12], peer_prefix: [u8; 12]) {
    let other =
        |key: &DiscoveryPeerKey| key.local_prefix != local_prefix || key.peer_prefix != peer_prefix;
    if let Ok(mut set) = completed_peers().lock() {
        set.retain(|key| other(key));
    }
    if let Ok(mut map) = responded_spdp_peers().lock() {
        map.retain(|key, _| other(key));
    }
}

/// What an SPDP handler may do with an announcement.
enum Answer {
    /// Nothing more.
    No,
    /// Answer it as usual: SPDP destination, discovery handshake, immediate
    /// SPDP reply, SEDP re-announcement.
    Yes,
    /// Re-announce our endpoints to the participant, at these locators (the
    /// ones it was admitted with) and nothing else.
    Reannounce(Vec<SocketAddr>),
}

/// What an SPDP handler may do with an announcement, given the verdict the
/// FSM reached on it ([`SpdpVerdict`]).
///
/// A participant the security policy refused gets nothing: before, the
/// verdict was not read at all, and a participant refused under
/// `require_authentication` was still made an SPDP destination and sent the
/// discovery handshake and our SEDP, in the clear.
///
/// An authenticated peer's plain announcement carries nothing we may act on
/// (DDS Security v1.1 Sec.7.4.1.6): it only keeps the peer alive. Its SPDP
/// destination, which the multicast-less modes send our announcements to,
/// is kept alive with it, at the locators and for the lease the peer was
/// admitted with - never those of the datagram, which anyone can send under
/// its prefix. When it has just authenticated again
/// (`SpdpVerdict::Reauthenticated`), what we recorded about it is forgotten
/// and our endpoints are re-announced to it, at those same locators.
fn may_answer(
    verdict: SpdpVerdict,
    our_prefix: [u8; 12],
    peer_prefix: [u8; 12],
    fsm: &DiscoveryFsm,
    discovered_peers: Option<&SpdpPeerSet>,
) -> Answer {
    match verdict {
        SpdpVerdict::Own | SpdpVerdict::New | SpdpVerdict::Refreshed | SpdpVerdict::Departed => {
            Answer::Yes
        }
        SpdpVerdict::Rejected => {
            log::debug!(
                "[SPDP] {:02x?} refused by the security policy: not answered",
                peer_prefix
            );
            Answer::No
        }
        SpdpVerdict::DepartureIgnored => Answer::No,
        SpdpVerdict::LivelinessOnly | SpdpVerdict::Reauthenticated => {
            let admitted = fsm.admitted_locators_and_lease(&peer_prefix);
            if let (Some(peers), Some((locators, lease_ms))) = (discovered_peers, &admitted) {
                peers.refresh_discovered(
                    peer_prefix,
                    locators.iter().copied(),
                    Duration::from_millis(*lease_ms),
                );
            }
            match (verdict, admitted) {
                (SpdpVerdict::Reauthenticated, Some((locators, _))) => {
                    forget_remote_peer(our_prefix, peer_prefix);
                    release_retry(our_prefix, peer_prefix);
                    Answer::Reannounce(locators)
                }
                _ => Answer::No,
            }
        }
    }
}

/// Forgets what a local participant recorded about a peer removed from
/// discovery (`forget_remote_peer`): its lease expired, a probation or
/// zombie purge removed it, it departed.
///
/// A peer that comes back under the same prefix (a participant re-created in
/// the same process, a host back from a network partition, a live peer the
/// probation purged too early) is a new peer to us: without this, "already
/// announced" kept our SEDP re-announcement from it and "already answered"
/// our immediate SPDP reply, with no error anywhere, for as long as the
/// records lived.
pub(super) struct ForgottenPeerRecords {
    local_prefix: [u8; 12],
}

impl ForgottenPeerRecords {
    pub(super) fn new(local_prefix: [u8; 12]) -> Self {
        Self { local_prefix }
    }
}

impl crate::core::discovery::multicast::DiscoveryListener for ForgottenPeerRecords {
    fn on_endpoint_discovered(&self, endpoint: crate::core::discovery::multicast::EndpointInfo) {
        drop(endpoint);
    }

    fn on_participant_forgotten(&self, participant: GUID) {
        log::debug!(
            "[SPDP] {:?} left discovery: its discovery records are forgotten",
            participant
        );
        forget_remote_peer(self.local_prefix, participant.prefix);
    }
}

/// Let a re-announcement to `peer_prefix` begin even though one is still
/// running: the one running began before the peer authenticated and goes
/// out in the clear, which an authenticated peer ignores for an endpoint it
/// knows; the one that follows a completed handshake goes sealed, and must
/// not be skipped as "already active" (`RetryGuard::try_acquire`). The
/// running one keeps running; whichever ends last records the completion.
fn release_retry(local_prefix: [u8; 12], peer_prefix: [u8; 12]) {
    if let Ok(mut set) = active_retries().lock() {
        set.retain(|key| key.local_prefix != local_prefix || key.peer_prefix != peer_prefix);
    }
}

/// Handle SPDP packet.
///
/// # Arguments
/// - `payload`: Full RTPS packet (including headers)
/// - `cdr_offset`: CDR payload offset within the packet (computed by classifier)
/// - `origin`: where the datagram came from, and where a reply may go
///   (RTPS 2.5 8.3.4, 8.3.8.10: `None` behind an INFO_SRC; no metatraffic
///   locator is inferred, and no ACKNACK reply is sent, when it is)
/// - `our_guid_prefix`: Our participant GUID prefix (for loopback filtering)
/// - `transport`: UDP transport for sending ACKNACKs and SEDP re-announcements
/// - `fsm`: Discovery FSM for state updates
/// - `sedp_cache`: SEDP announcements cache for re-announcements
/// - `dialect_detector`: Dialect detector for SPDP packet monitoring (Phase 1.6)
/// - `port_mapping`: Port mapping for metatraffic locator inference
/// - `spdp_security_tokens`: Security payloads owned by the local participant
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_spdp_packet(
    payload: &[u8],
    cdr_offset: usize,
    origin: Origin,
    our_guid_prefix: [u8; 12],
    transport: Arc<UdpTransport>,
    fsm: Arc<DiscoveryFsm>,
    sedp_cache: SedpAnnouncementsCache,
    dialect_detector: Arc<
        std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>,
    >,
    port_mapping: crate::transport::PortMapping,
    spdp_security_tokens: &SpdpSecurityTokens,
    discovered_peers: Option<&SpdpPeerSet>,
) {
    log::debug!(
        "[callback-builder] Received SPDP packet, len={}, cdr_offset={}",
        payload.len(),
        cdr_offset
    );

    // Held to the end: our farewell (`DiscoveryFsm::depart`) waits for it,
    // and once it has gone this participant answers nobody.
    let Some(_still_here) = fsm.still_here() else {
        log::debug!("[SPDP] we have said our farewell: announcement not answered");
        return;
    };

    // A departure is no announcement: none of what follows applies to it.
    if let Some(departed) = detect_spdp_participant_dispose(payload, cdr_offset) {
        apply_participant_departure(departed, our_guid_prefix, &fsm, discovered_peers);
        return;
    }

    // Extract GUID prefix from RTPS header to detect self-loopback BEFORE dialect detection.
    // RTPS header: bytes 8-19 contain the GUID prefix (after magic + version + vendor).
    // Without this check, the dialect detector locks to Hdds on our own SPDP before it sees
    // the remote peer's.
    let packet_guid_prefix: Option<[u8; 12]> = if payload.len() >= 20 {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&payload[8..20]);
        Some(prefix)
    } else {
        None
    };

    let is_self_packet = packet_guid_prefix == Some(our_guid_prefix);

    // Phase 1.6: Feed full RTPS packet to dialect detector (monitoring passif)
    // and remember detected dialect for SEDP encoding.
    //
    // HDDS-first strategy:
    // - Default = Dialect::Hdds (native mode, fast discovery)
    // - If interop_mode enabled (non-HDDS vendor detected) -> use detected dialect
    let mut encoding_dialect = Dialect::Hdds; // Default: HDDS native mode
    let mut is_interop_mode = false;

    if let Ok(mut detector) = dialect_detector.lock() {
        // Skip dialect detection for self-loopback packets.
        // This prevents locking to Hdds before receiving packets from remote peers.
        if !is_self_packet {
            if let Some(detected_dialect) = detector.process_packet(payload, origin) {
                let confidence = detector.confidence();
                log::debug!(
                    "[DIALECT-DETECTOR] [OK] Dialect detected: {:?} (confidence: {}%)",
                    detected_dialect,
                    confidence
                );
            }
        } else {
            log::trace!("[DIALECT-DETECTOR] Skipping self-loopback packet");
        }

        is_interop_mode = detector.is_interop_mode();
        if is_interop_mode {
            // In interop mode with mixed vendors (HDDS + foreign), use Hybrid
            // as conservative fallback. However, a peer locked to the `Rti` dialect
            // keeps that dialect's encoder, which emits PID_KEY_HASH, its PID
            // ordering, and PID_TYPE_CONSISTENCY that Hybrid does not provide.
            if let Some(Dialect::Rti) = detector.locked_dialect() {
                encoding_dialect = Dialect::Rti;
            } else {
                encoding_dialect = Dialect::Hybrid;
            }
        } else if let Some(locked) = detector.locked_dialect() {
            // Native mode: should be Dialect::Hdds
            encoding_dialect = locked;
        }
    }

    log::trace!(
        "[SPDP] encoding_dialect={:?}, interop_mode={}",
        encoding_dialect,
        is_interop_mode
    );

    // Extract CDR payload using offset from classifier
    let cdr_payload = if cdr_offset < payload.len() {
        log::debug!("[spdp] Extracting CDR payload at offset {}", cdr_offset);
        &payload[cdr_offset..]
    } else {
        log::debug!("[spdp] Invalid offset {}, using full payload", cdr_offset);
        payload
    };

    // Prefer full SPDP parse to extract unicast locators; fallback to partial on fragments
    let spdp_parse = match parse_spdp(cdr_payload) {
        Ok(full) => Ok(full),
        Err(ParseError::TruncatedData) => parse_spdp_partial(cdr_payload),
        Err(e) => Err(e),
    };

    match spdp_parse {
        Ok(mut spdp_data) => {
            log::debug!(
                "[callback] [OK] SPDP parsed (via classifier): GUID={:?}",
                spdp_data.participant_guid
            );

            // First, try to recover metatraffic_unicast locator directly from the
            // SPDP CDR payload. The announcement may carry a proper
            // PID_METATRAFFIC_UNICAST_LOCATOR that our generic SPDP parser
            // misses in corner cases. As a safety net, scan the raw payload.
            if spdp_data.metatraffic_unicast_locators.is_empty() {
                if let Some(loc) = extract_metatraffic_unicast_from_cdr(cdr_payload) {
                    log::debug!(
                        "[SPDP-RECOVER] [OK] Recovered metatraffic_unicast locator from CDR: {}",
                        loc
                    );
                    spdp_data.metatraffic_unicast_locators.push(loc);
                }
            }

            // Fallback: infer metatraffic_unicast locator from source IP if still empty.
            //
            // RTPS 2.5 8.3.8.10: behind an INFO_SRC `origin` names no reply
            // locator -- the datagram's real sender only forwarded this
            // announcement, and inferring a metatraffic locator from its
            // address would aim every reply at the forwarder instead of the
            // participant the announcement names. Leave the list as the
            // announcement made it; a relayed peer with no locator in its
            // own SPDP stays without a metatraffic locator, honestly.
            if spdp_data.metatraffic_unicast_locators.is_empty() {
                if let Some(reply) = origin.reply() {
                    let inferred_port = port_mapping.metatraffic_unicast;
                    let inferred_locator = SocketAddr::new(reply.ip(), inferred_port);
                    spdp_data
                        .metatraffic_unicast_locators
                        .push(inferred_locator);
                    log::debug!(
                        "[SPDP-INFER] [OK] Inferred metatraffic_unicast locator from source: {} (port from config)",
                        inferred_locator
                    );
                } else {
                    log::debug!(
                        "[SPDP-INFER] relayed origin (behind an INFO_SRC): no metatraffic \
                         locator inferred from {}",
                        origin.from()
                    );
                }
            }

            let verdict = fsm.admit_spdp(spdp_data.clone());

            // The dialect's discovery handshake (DialectEncoder::
            // build_discovery_handshake) goes to the peer before SEDP
            // publications are exchanged.
            let peer_guid_prefix = {
                let bytes = spdp_data.participant_guid.as_bytes();
                let mut prefix = [0u8; 12];
                prefix.copy_from_slice(&bytes[..12]);
                prefix
            };

            // Skip our own SPDP multicast loopback!
            // Without this, HDDS sends ACKNACKs to itself instead of the peer
            if peer_guid_prefix == our_guid_prefix {
                log::debug!("[SPDP-FILTER] [!]  Ignoring our own SPDP (multicast loopback)");
                return; // Exit handler early
            }
            match may_answer(
                verdict,
                our_guid_prefix,
                peer_guid_prefix,
                &fsm,
                discovered_peers,
            ) {
                Answer::Yes => {}
                Answer::No => return,
                Answer::Reannounce(locators) => {
                    let mut admitted = spdp_data.clone();
                    admitted.metatraffic_unicast_locators = locators;
                    send_sedp_reannouncements_with_prealloc(
                        &admitted,
                        &our_guid_prefix,
                        &peer_guid_prefix,
                        port_mapping.metatraffic_unicast,
                        transport,
                        &sedp_cache,
                        preallocate_sedp_sequence_numbers(&sedp_cache),
                        "[SEDP-REANNOUNCE-REAUTH]",
                        encoding_dialect,
                        &fsm,
                        #[cfg(feature = "security")]
                        fsm.sedp_keys_for(&peer_guid_prefix),
                    );
                    return;
                }
            }

            // MulticastMode v2 (ReceiveOnly / Disabled): multicast cannot carry
            // our announcements to this peer, so every participant we learn
            // about, by any means, becomes a unicast SPDP destination for the
            // duration of its lease. Without this a peer heard over multicast
            // would never receive our DATA(p): one-way discovery, SEDP sent to
            // a participant that does not know us, its lease on us thrashing.
            // A dispose (lease 0) removes it. Same locators = no wake-up.
            if let Some(peers) = discovered_peers {
                if spdp_data.lease_duration_ms == 0 {
                    // Not an authenticated peer's: `may_answer` stopped that
                    // one (DDS Security v1.1 Sec.7.4.1.6).
                    peers.remove_discovered(&peer_guid_prefix);
                } else {
                    peers.refresh_discovered(
                        peer_guid_prefix,
                        spdp_data.metatraffic_unicast_locators.iter().copied(),
                        Duration::from_millis(spdp_data.lease_duration_ms),
                    );
                }
            }

            // Get dialect encoder for this peer
            let encoder = get_encoder(encoding_dialect);

            // Send immediate SPDP unicast response BEFORE handshake HEARTBEATs.
            //
            // On the peer's SPDP: our SPDP by unicast to its metatraffic unicast
            // locator first, then our discovery HEARTBEATs, so that the peer
            // already knows us when they arrive and answers them at once.
            //
            // Without immediate SPDP, first contact waits for the peer's periodic
            // SPDP before our HEARTBEATs are processed, delaying discovery.
            // Only respond once per peer. Without this dedup, every SPDP
            // received from a peer triggers another unicast response, which the
            // peer parses as an incoming SPDP and again triggers a response,
            // creating a reactive bounce loop that saturates discovery traffic
            // (see the RESPONDED_SPDP_PEERS doc-comment for the full analysis).
            if encoder.requires_immediate_spdp_response()
                && !spdp_data.metatraffic_unicast_locators.is_empty()
                && mark_peer_responded(DiscoveryPeerKey::new(
                    our_guid_prefix,
                    port_mapping.metatraffic_unicast,
                    peer_guid_prefix,
                ))
            {
                send_immediate_spdp_unicast(
                    &our_guid_prefix,
                    &peer_guid_prefix,
                    &spdp_data.metatraffic_unicast_locators,
                    &transport,
                    port_mapping,
                    fsm.local_lease_duration_ms(),
                    fsm.local_capabilities(),
                    encoder.name(),
                    spdp_security_tokens,
                );
            }

            // Pre-allocate SEDP sequence numbers BEFORE building the handshake.
            //
            // The handshake sends HEARTBEATs with lastSeq from the atomic counter.
            // Building it BEFORE spawning the retry thread would read lastSeq=0,
            // then the retry thread would allocate seq 1,2,3... for DATA(r):
            // the peer would receive HEARTBEAT(lastSeq=0), then DATA(r)(seq=1), a
            // change the HEARTBEAT said did not exist.
            //
            // So sequence numbers are pre-allocated synchronously, THEN the
            // handshake is built and reads the correct lastSeq values from the
            // atomic counters.
            let pre_allocated_endpoints = preallocate_sedp_sequence_numbers(&sedp_cache);

            // Send dialect-specific discovery handshake packets (if required)
            // The encoder knows what handshake its dialect needs (e.g., HEARTBEATs)
            // NOTE: Handshake HEARTBEATs read lastSeq from the pre-allocated counters
            if let Some(handshake_packets) =
                encoder.build_discovery_handshake(&our_guid_prefix, &peer_guid_prefix)
            {
                for (idx, packet) in handshake_packets.iter().enumerate() {
                    // Prefer UNICAST to peer metatraffic_unicast locators; fallback to multicast
                    if !spdp_data.metatraffic_unicast_locators.is_empty() {
                        for ep in &spdp_data.metatraffic_unicast_locators {
                            match transport.send_to_endpoint(packet, ep) {
                                Ok(_) => log::debug!(
                                    "[DISCOVERY-HANDSHAKE] [OK] Sent packet {} (unicast) to {} [{} dialect]",
                                    idx + 1, ep, encoder.name()
                                ),
                                Err(e) => log::debug!(
                                    "[DISCOVERY-HANDSHAKE] Failed to send packet {}: {} to {}",
                                    idx + 1, e, ep
                                ),
                            }
                        }
                    } else if let Err(e) = transport.send(packet) {
                        log::debug!(
                            "[DISCOVERY-HANDSHAKE] Failed to send packet {} (multicast): {}",
                            idx + 1,
                            e
                        );
                    } else {
                        log::debug!(
                            "[DISCOVERY-HANDSHAKE] [OK] Sent packet {} (multicast) [{} dialect]",
                            idx + 1,
                            encoder.name()
                        );
                    }
                }
            }

            // Unicast SEDP re-announce to this peer's metatraffic_unicast locators (if available)
            // Pass pre-allocated endpoints to avoid double-allocation
            send_sedp_reannouncements_with_prealloc(
                &spdp_data,
                &our_guid_prefix,
                &peer_guid_prefix,
                port_mapping.metatraffic_unicast,
                transport,
                &sedp_cache,
                pre_allocated_endpoints,
                "[SEDP-REANNOUNCE]",
                encoding_dialect,
                &fsm,
                #[cfg(feature = "security")]
                fsm.sedp_keys_for(&peer_guid_prefix),
            );
        }
        Err(e) => {
            log::debug!("[callback] SPDP parse failed (via classifier): {:?}", e);
        }
    }
}

/// Handle an SPDP announcement that arrived in fragments.
///
/// # Arguments
/// - `sample`: the reassembled sample, i.e. the CDR ParameterList itself. Not
///   a datagram: every fragment of the announcement has been concatenated and
///   the RTPS framing is gone.
/// - `datagram`: the packet that carried the LAST fragment. Read only for what
///   belongs to the packet and not to the announcement - the source GUID
///   prefix in the RTPS header, and the bytes the dialect detector scores.
/// - `origin`: where the datagram came from, and where a reply may go
///   (RTPS 2.5 8.3.4, 8.3.8.10: `None` behind an INFO_SRC; no metatraffic
///   locator is inferred, and no ACKNACK reply is sent, when it is)
/// - `our_guid_prefix`: Our participant GUID prefix (for loopback filtering)
/// - `transport`: UDP transport for sending ACKNACKs and SEDP re-announcements
/// - `fsm`: Discovery FSM for state updates
/// - `sedp_cache`: SEDP announcements cache for re-announcements
/// - `dialect_detector`: Dialect detector for SPDP packet monitoring (Phase 1.6)
/// - `port_mapping`: Port mapping for metatraffic locator inference
/// - `spdp_security_tokens`: Security payloads owned by the local participant
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_spdp_from_fragments(
    sample: &[u8],
    datagram: &[u8],
    origin: Origin,
    our_guid_prefix: [u8; 12],
    transport: Arc<UdpTransport>,
    fsm: Arc<DiscoveryFsm>,
    sedp_cache: SedpAnnouncementsCache,
    dialect_detector: Arc<
        std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>,
    >,
    port_mapping: crate::transport::PortMapping,
    spdp_security_tokens: &SpdpSecurityTokens,
    discovered_peers: Option<&SpdpPeerSet>,
) {
    // Held to the end, as in `handle_spdp_packet`: once our farewell has
    // gone, this participant answers nobody.
    let Some(_still_here) = fsm.still_here() else {
        log::debug!("[SPDP-FRAG] we have said our farewell: announcement not answered");
        return;
    };

    // Extract GUID prefix from RTPS header to detect self-loopback BEFORE dialect detection.
    // RTPS header: bytes 8-19 contain the GUID prefix (after magic + version + vendor).
    let packet_guid_prefix: Option<[u8; 12]> = if datagram.len() >= 20 {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&datagram[8..20]);
        Some(prefix)
    } else {
        None
    };

    let is_self_packet = packet_guid_prefix == Some(our_guid_prefix);

    // Phase 1.6: Feed reassembled SPDP packet to dialect detector
    // and remember detected dialect for SEDP encoding.
    //
    // HDDS-first strategy (same as non-fragment path):
    // - Default = Dialect::Hdds (native mode, fast discovery)
    // - If interop_mode enabled (non-HDDS vendor detected) -> use detected dialect
    let mut encoding_dialect = Dialect::Hdds; // Default: HDDS native mode
    let mut is_interop_mode = false;

    if let Ok(mut detector) = dialect_detector.lock() {
        // Skip dialect detection for self-loopback packets.
        if !is_self_packet {
            if let Some(detected_dialect) = detector.process_packet(datagram, origin) {
                let confidence = detector.confidence();
                log::debug!(
                    "[DIALECT-DETECTOR] [OK] Dialect detected (from fragments): {:?} (confidence: {}%)",
                    detected_dialect,
                    confidence
                );
            }
        } else {
            log::trace!("[DIALECT-DETECTOR] Skipping self-loopback fragment packet");
        }

        is_interop_mode = detector.is_interop_mode();
        if is_interop_mode {
            // In interop mode, use Hybrid as conservative fallback.
            // Exception: a peer locked to the `Rti` dialect keeps that dialect's
            // encoder (PID_KEY_HASH, PID ordering).
            if let Some(Dialect::Rti) = detector.locked_dialect() {
                encoding_dialect = Dialect::Rti;
            } else {
                encoding_dialect = Dialect::Hybrid;
            }
        } else if let Some(locked) = detector.locked_dialect() {
            // Native mode: should be Dialect::Hdds
            encoding_dialect = locked;
        }
    }

    log::trace!(
        "[SPDP-FRAG] encoding_dialect={:?}, interop_mode={}",
        encoding_dialect,
        is_interop_mode
    );

    // The reassembled sample IS the CDR. What stood here was a walk over the
    // buffer looking for a DATA or DATA_FRAG submessage, because the buffer
    // held whole datagrams - a workaround inside the callee for a mistake in
    // the caller. Its DATA_FRAG branch also started the payload at
    // `offset + 24`, twelve octets before the serialized data (the fixed
    // DATA_FRAG fields run to +36, RTPS v2.5 Sec.8.3.8.3), and it could never
    // run: the gate in its only caller refused a buffer beginning with "RTPS"
    // before this function was ever entered.
    let cdr_payload = sample;

    match parse_spdp(cdr_payload) {
        Ok(mut spdp_data) => {
            log::debug!(
                "[callback] [OK] SPDP parsed from reassembled fragments: GUID={:?}",
                spdp_data.participant_guid
            );

            // Infer the metatraffic_unicast locator from the source IP if not in SPDP
            //
            // RTPS 2.5 8.3.8.10: same rule as the non-fragment path above --
            // no inference behind an INFO_SRC.
            if spdp_data.metatraffic_unicast_locators.is_empty() {
                if let Some(reply) = origin.reply() {
                    let inferred_port = port_mapping.metatraffic_unicast;
                    let inferred_locator = SocketAddr::new(reply.ip(), inferred_port);
                    spdp_data
                        .metatraffic_unicast_locators
                        .push(inferred_locator);
                    log::debug!(
                        "[SPDP-INFER] [OK] Inferred metatraffic_unicast locator from source: {} (port from config)",
                        inferred_locator
                    );
                } else {
                    log::debug!(
                        "[SPDP-INFER] relayed origin (behind an INFO_SRC): no metatraffic \
                         locator inferred from {}",
                        origin.from()
                    );
                }
            }

            let verdict = fsm.admit_spdp(spdp_data.clone());

            // Dialect discovery handshake (same as non-fragment path)
            let peer_guid_prefix = {
                let bytes = spdp_data.participant_guid.as_bytes();
                let mut prefix = [0u8; 12];
                prefix.copy_from_slice(&bytes[..12]);
                prefix
            };

            // Skip our own SPDP multicast loopback!
            if peer_guid_prefix == our_guid_prefix {
                log::debug!(
                    "[SPDP-FILTER] [!]  Ignoring our own SPDP fragment (multicast loopback)"
                );
                return; // Exit handler early
            }
            match may_answer(
                verdict,
                our_guid_prefix,
                peer_guid_prefix,
                &fsm,
                discovered_peers,
            ) {
                Answer::Yes => {}
                Answer::No => return,
                Answer::Reannounce(locators) => {
                    let mut admitted = spdp_data.clone();
                    admitted.metatraffic_unicast_locators = locators;
                    send_sedp_reannouncements(
                        &admitted,
                        &our_guid_prefix,
                        &peer_guid_prefix,
                        port_mapping.metatraffic_unicast,
                        transport,
                        sedp_cache,
                        "[SEDP-REANNOUNCE-REAUTH-FRAG]",
                        encoding_dialect,
                        &fsm,
                        #[cfg(feature = "security")]
                        fsm.sedp_keys_for(&peer_guid_prefix),
                    );
                    return;
                }
            }

            // MulticastMode v2 (ReceiveOnly / Disabled): multicast cannot carry
            // our announcements to this peer, so every participant we learn
            // about, by any means, becomes a unicast SPDP destination for the
            // duration of its lease. Without this a peer heard over multicast
            // would never receive our DATA(p): one-way discovery, SEDP sent to
            // a participant that does not know us, its lease on us thrashing.
            // A dispose (lease 0) removes it. Same locators = no wake-up.
            if let Some(peers) = discovered_peers {
                if spdp_data.lease_duration_ms == 0 {
                    // Not an authenticated peer's: `may_answer` stopped that
                    // one (DDS Security v1.1 Sec.7.4.1.6).
                    peers.remove_discovered(&peer_guid_prefix);
                } else {
                    peers.refresh_discovered(
                        peer_guid_prefix,
                        spdp_data.metatraffic_unicast_locators.iter().copied(),
                        Duration::from_millis(spdp_data.lease_duration_ms),
                    );
                }
            }

            // Get dialect encoder for this peer
            let encoder = get_encoder(encoding_dialect);

            // Send immediate SPDP unicast response BEFORE handshake HEARTBEATs.
            // (Same logic as non-fragment path)
            // Only respond once per peer. Without this dedup, every SPDP
            // received from a peer triggers another unicast response, which the
            // peer parses as an incoming SPDP and again triggers a response,
            // creating a reactive bounce loop that saturates discovery traffic
            // (see the RESPONDED_SPDP_PEERS doc-comment for the full analysis).
            if encoder.requires_immediate_spdp_response()
                && !spdp_data.metatraffic_unicast_locators.is_empty()
                && mark_peer_responded(DiscoveryPeerKey::new(
                    our_guid_prefix,
                    port_mapping.metatraffic_unicast,
                    peer_guid_prefix,
                ))
            {
                send_immediate_spdp_unicast(
                    &our_guid_prefix,
                    &peer_guid_prefix,
                    &spdp_data.metatraffic_unicast_locators,
                    &transport,
                    port_mapping,
                    fsm.local_lease_duration_ms(),
                    fsm.local_capabilities(),
                    encoder.name(),
                    spdp_security_tokens,
                );
            }

            // Send dialect-specific discovery handshake packets (if required)
            // The encoder knows what handshake its dialect needs (e.g., HEARTBEATs)
            if let Some(handshake_packets) =
                encoder.build_discovery_handshake(&our_guid_prefix, &peer_guid_prefix)
            {
                for (idx, packet) in handshake_packets.iter().enumerate() {
                    if !spdp_data.metatraffic_unicast_locators.is_empty() {
                        for ep in &spdp_data.metatraffic_unicast_locators {
                            match transport.send_to_endpoint(packet, ep) {
                                Ok(_) => log::debug!(
                                    "[DISCOVERY-HANDSHAKE-FRAG] [OK] Sent packet {} (unicast) to {} [{} dialect]",
                                    idx + 1, ep, encoder.name()
                                ),
                                Err(e) => log::debug!(
                                    "[DISCOVERY-HANDSHAKE-FRAG] Failed to send packet {}: {} to {}",
                                    idx + 1, e, ep
                                ),
                            }
                        }
                    } else if let Err(e) = transport.send(packet) {
                        log::debug!(
                            "[DISCOVERY-HANDSHAKE-FRAG] Failed to send packet {} (multicast): {}",
                            idx + 1,
                            e
                        );
                    } else {
                        log::debug!(
                            "[DISCOVERY-HANDSHAKE-FRAG] [OK] Sent packet {} (multicast) [{} dialect]",
                            idx + 1,
                            encoder.name()
                        );
                    }
                }
            }

            // Unicast SEDP re-announce (if we have peer locators)
            send_sedp_reannouncements(
                &spdp_data,
                &our_guid_prefix,
                &peer_guid_prefix,
                port_mapping.metatraffic_unicast,
                transport,
                sedp_cache,
                "[SEDP-REANNOUNCE-FRAG]",
                encoding_dialect,
                &fsm,
                #[cfg(feature = "security")]
                fsm.sedp_keys_for(&peer_guid_prefix),
            );
        }
        Err(e) => {
            log::debug!(
                "[callback] SPDP parse failed on reassembled payload: {:?}",
                e
            );
        }
    }
}

/// Pre-allocated SEDP messages, each under its positional sequence number
/// (`SedpHistory::sends`).
type PreallocatedEndpoints = Vec<SedpSend>;

/// Pre-allocate SEDP sequence numbers synchronously.
///
/// This function reads the SEDP history and raises the per-writer atomic
/// counters to its numbers. By calling this BEFORE building handshake
/// HEARTBEATs, the heartbeats will read the correct lastSeq values from the
/// counters.
///
/// # Arguments
/// - `sedp_cache`: SEDP history
///
/// # Returns
/// Every message of the history, in sequence-number order: the announcement
/// of each endpoint that exists, a GAP for the announcement of each one since
/// deleted, the dispose of each deleted one (RTPS v2.5 Sec.8.5.4.4). Empty
/// if the history is.
fn preallocate_sedp_sequence_numbers(sedp_cache: &SedpAnnouncementsCache) -> PreallocatedEndpoints {
    // Use FIXED positional sequence numbers (1-based index per kind).
    // Must match the scheme used by ControlHandler::retransmit_sedp_data().
    // `sends` also keeps the atomic high-water >= the history's last
    // number, which the dialect handshake HEARTBEATs read as their lastSN.
    sedp_cache
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .sends(None)
}

/// An SEDP change a participant is not to receive is not sent, and the
/// sequence number it was allotted is retired with a GAP: a protected
/// endpoint to a participant that has not authenticated (DDS Security v1.1
/// Sec.8.8.2.1, `secure_sedp::sedp_datagram_for`), or a secure announcement
/// that could not be encrypted (counted and logged there).
///
/// `preallocate_sedp_sequence_numbers` has already taken the number and
/// raised the writer's high water, so the HEARTBEATs this participant emits
/// advertise a range that covers it. Dropping the DATA alone leaves the peer's
/// reliable builtin reader NACKing that sequence forever, and because reliable
/// delivery is in order, withholding every later SEDP sample too: the peer
/// stops discovering anything from us, not just the one endpoint. The
/// refusal is deterministic (the encrypted body no longer fits
/// `octetsToNextHeader`), so it recurs on every retry and re-announcement,
/// and nothing "clears on the next round".
///
/// A GAP (RTPS v2.5 Sec.8.3.8.4) tells the reader the sequence is irrelevant
/// to it, so it advances past it. It is sent in the clear and names the
/// plaintext SEDP writer, exactly as the HEARTBEAT appended after a wrapped
/// DATA does: the receiving side unwraps the secure DATA back into the
/// plaintext namespace before attributing it, so both control submessages
/// meet the same writer proxy.
///
#[cfg(feature = "security")]
fn retire_sedp_sequence_with_gap(
    kind: SedpEndpointKind,
    seq_num: u64,
    our_prefix: &[u8; 12],
    peer_prefix: &[u8; 12],
    transport: &UdpTransport,
    locators: &[SocketAddr],
    log_prefix: &str,
) {
    log::debug!(
        "{} [secure-sedp] SEDP {:?} seq={} not sent to {:02x?}: retired with a GAP",
        log_prefix,
        kind,
        seq_num,
        peer_prefix
    );

    let (reader_id, writer_id) = match kind {
        SedpEndpointKind::Writer => ([0x00, 0x00, 0x03, 0xC7], [0x00, 0x00, 0x03, 0xC2]),
        SedpEndpointKind::Reader => ([0x00, 0x00, 0x04, 0xC7], [0x00, 0x00, 0x04, 0xC2]),
    };
    // gapStart = seq, gapList based at seq + 1 with no bits: exactly one
    // sequence retired, the single-SN form the ECS close path uses too.
    let gap = crate::protocol::builder::build_gap_packet_from_parts(
        &reader_id,
        &writer_id,
        seq_num,
        seq_num.saturating_add(1),
        &[],
        *our_prefix,
    );
    if gap.is_empty() {
        log::error!(
            "{} [secure-sedp] GAP for seq={} could not be built; the peer's SEDP reader \
             will stall on this sequence",
            log_prefix,
            seq_num
        );
        return;
    }
    for ep in locators {
        if let Err(e) = transport.send_to_endpoint(&gap, ep) {
            log::debug!(
                "{} [secure-sedp] GAP for seq={} not delivered to {}: {}",
                log_prefix,
                seq_num,
                ep,
                e
            );
        }
    }
}

/// Send SEDP re-announcements with pre-allocated sequence numbers.
///
/// This variant uses sequence numbers that were pre-allocated synchronously
/// before building handshake HEARTBEATs, ensuring consistency between the
/// HEARTBEAT lastSeq and the DATA(r) sequence numbers.
///
/// # Arguments
/// - `spdp_data`: SPDP data with peer locators
/// - `our_guid_prefix`: Our participant GUID prefix
/// - `peer_guid_prefix`: Peer participant GUID prefix
/// - `local_metatraffic_port`: local port that scopes process-wide retry dedup
/// - `transport`: UDP transport for sending
/// - `sedp_cache`: the SEDP history, read again before each retry after the
///   first
/// - `pre_allocated`: Pre-allocated endpoints with sequence numbers
/// - `log_prefix`: Log prefix for log::debug! messages
/// - `encoding_dialect`: Dialect for encoding
/// - `peer_sedp_keys`: what SEDP to the peer is sealed with, when it has
///   completed authentication (`DiscoveryFsm::sedp_keys_for`: our secure SEDP
///   writers' own key material, or the 1.4.x metatraffic key for a 1.4.x
///   peer). Each change goes as `secure_sedp::sedp_datagram_for` decides from
///   it and the endpoint's `is_discovery_protected`: sealed on the secure
///   SEDP topic, in clear on the regular one, or, to a peer that is not to
///   receive it, as a GAP.
#[allow(clippy::too_many_arguments)]
fn send_sedp_reannouncements_with_prealloc(
    spdp_data: &SpdpData,
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
    local_metatraffic_port: u16,
    transport: Arc<UdpTransport>,
    sedp_cache: &SedpAnnouncementsCache,
    pre_allocated: PreallocatedEndpoints,
    log_prefix: &str,
    encoding_dialect: Dialect,
    fsm: &DiscoveryFsm,
    #[cfg(feature = "security")] peer_sedp_keys: Option<
        crate::security::crypto::secure_sedp::SedpWriterKeys,
    >,
) {
    // Skip if no pre-allocated endpoints
    if pre_allocated.is_empty() {
        log::debug!(
            "{} No pre-allocated endpoints, skipping SEDP retries",
            log_prefix
        );
        return;
    }

    // SPDP->SEDP barrier: only send SEDP after a few local SPDP
    // announcements, to give the remote PDP
    // time to create ParticipantProxyData for our GUID.
    let spdp_sent = SPDP_SENT_COUNT.load(Ordering::Relaxed);
    // Skip SPDP barrier when dialect encoder indicates it's safe.
    // Each dialect encoder defines its own requirement via skip_spdp_barrier().
    let encoder = crate::protocol::dialect::get_encoder(encoding_dialect);
    let skip_spdp_barrier = encoder.skip_spdp_barrier();

    if spdp_sent < 3 && !skip_spdp_barrier {
        log::debug!(
            "{} Skipping SEDP re-announce: only {} SPDP sent so far (<3)",
            log_prefix,
            spdp_sent
        );
        return;
    }

    if spdp_sent < 3 && skip_spdp_barrier {
        log::debug!(
            "{} [INTEROP] Skipping SPDP barrier (spdp_sent={})",
            log_prefix,
            spdp_sent
        );
    }

    // Clone data needed by the retry loop.
    let spdp_data_clone = spdp_data.clone();
    let transport_clone = Arc::clone(&transport);
    let our_prefix = *our_guid_prefix;
    let peer_prefix = *peer_guid_prefix;
    let peer_key = DiscoveryPeerKey::new(our_prefix, local_metatraffic_port, peer_prefix);
    let prefix = log_prefix.to_string();
    // Read from discovery, the one reader of the decision, which keeps what
    // the peer's SPDP announced; never from this SPDP's datagram, which may
    // carry less (a partial parse, a re-announcement's copy). The SPDP is
    // admitted by now; a peer discovery does not know is withheld it.
    let type_object = fsm
        .type_object_pid_for(peer_guid_prefix)
        .unwrap_or(crate::core::discovery::multicast::TypeObjectPid::Withhold);
    // The protection of our secure discovery writers, ENCRYPT when this
    // participant runs no governance (what it has always sealed with).
    #[cfg(feature = "security")]
    let discovery_kind = fsm
        .discovery_protection_kind()
        .unwrap_or(crate::security::access::ProtectionKind::Encrypt);
    // Governance alone decides where a change goes: without a document the
    // endpoint's announced attribute describes the payload plane
    // (`secure_sedp::governed_discovery_protected`). Read here, the thread
    // outlives the FSM handle.
    #[cfg(feature = "security")]
    let discovery_governed = fsm.discovery_governed();

    // Move pre-allocated endpoints into the thread
    let mut endpoints = pre_allocated;
    let sedp_cache = Arc::clone(sedp_cache);

    // SEDP retry flood prevention
    // - RetryGuard prevents multiple threads per peer
    // - Pre-allocate seq numbers BEFORE loop (RTPS Sec.8.4.7.5: retransmit = same seq)
    // - Bounded retries: 5 x 500ms = 2.5s
    let rounds = sedp_cache
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .retry_rounds();
    let rounds_in_thread = Arc::clone(&rounds);
    let handle = std::thread::spawn(crate::core::rt::shutdown::owned(move || {
        use std::time::Duration;
        let rounds = rounds_in_thread;

        // Acquire RetryGuard - skip if already retrying to this peer
        let _guard = match RetryGuard::try_acquire(peer_key) {
            Some(g) => g,
            None => {
                log::debug!(
                    "{} [SEDP-RETRY] peer={:02x}{:02x}...{:02x}{:02x} already active, skipping",
                    prefix,
                    peer_prefix[0],
                    peer_prefix[1],
                    peer_prefix[10],
                    peer_prefix[11]
                );
                return;
            }
        };

        // endpoints already have pre-allocated sequence numbers

        if spdp_data_clone.metatraffic_unicast_locators.is_empty() {
            log::debug!(
                "{} No metatraffic_unicast_locators, skipping SEDP retries",
                prefix
            );
            return;
        }

        log::debug!(
            "{} [SEDP-RETRY] Starting {} endpoints, {} retries to peer {:02x}{:02x}...{:02x}{:02x}",
            prefix,
            endpoints.len(),
            5, // max retries
            peer_prefix[0],
            peer_prefix[1],
            peer_prefix[10],
            peer_prefix[11]
        );

        // Send SEDP immediately first, then retry with delays
        // so SEDP DATA promptly follows the peer's ACKNACK request
        // (sleeping BEFORE the first send would delay it by 500ms)
        for retry in 0..5 {
            // Send immediately on first iteration, then delay for retries
            if retry > 0 {
                // A participant that says its farewell meanwhile ends the
                // retries: none comes due after it.
                if !rounds.wait_while_running(Duration::from_millis(500)) {
                    return;
                }
                // The history as it is now: same numbers, but an endpoint
                // deleted since the last round is a GAP and its dispose,
                // never its announcement again after the dispose went out
                // (RTPS v2.5 Sec.8.5.4.4).
                endpoints = preallocate_sedp_sequence_numbers(&sedp_cache);
            }

            for send in &endpoints {
                // Built and sent under the history's read lock, the history
                // open: the participant closes it under the write lock
                // before its farewell (`Drop for Participant`), so nothing
                // of a round, a GAP included, goes out after the farewell.
                // The first round's numbers were read before this thread
                // started, so the check is made here, not only when the
                // history is read again.
                let history = sedp_cache.read().unwrap_or_else(|e| e.into_inner());
                if history.is_closed() {
                    return;
                }
                let kind = &send.kind;
                let seq_num = &send.last_seq();
                match send.build_for(
                    &our_prefix,
                    Some(&peer_prefix),
                    encoding_dialect,
                    type_object,
                ) {
                    Ok(pkt) => {
                        // Authenticated peers receive protected secure SEDP. A
                        // transformation failure must never emit plaintext.
                        // AEAD overhead can exceed octetsToNextHeader: that
                        // change remains owed and is retried from history.
                        //
                        // Where the change goes is decided per endpoint since the
                        // governance says so (`secure_sedp::sedp_datagram_for`): a
                        // protected endpoint only to an authenticated participant,
                        // on the secure SEDP topic; any other on the regular one.
                        #[cfg(feature = "security")]
                        let mut pkt = {
                            // A GAP carries no endpoint data and is read against
                            // the plaintext writer: sent as is (see
                            // `retire_sedp_sequence_with_gap`).
                            if send.is_gap() {
                                pkt
                            } else {
                                let Some(routed) =
                                    crate::security::crypto::secure_sedp::sedp_datagram_for(
                                        pkt,
                                        send.discovery_protected(),
                                        discovery_governed,
                                        peer_sedp_keys.as_ref(),
                                        discovery_kind,
                                        &peer_prefix,
                                    )
                                else {
                                    retire_sedp_sequence_with_gap(
                                        *kind,
                                        *seq_num,
                                        &our_prefix,
                                        &peer_prefix,
                                        &transport_clone,
                                        &spdp_data_clone.metatraffic_unicast_locators,
                                        &prefix,
                                    );
                                    continue;
                                };
                                routed
                            }
                        };
                        #[cfg(not(feature = "security"))]
                        let mut pkt = pkt;

                        // Append the SEDP HEARTBEAT only on the first retry. A late joiner
                        // that associates our SEDP writer AFTER this first HB is handled
                        // REACTIVELY in control.rs: when such a peer ACKs with a bitmapBase at or
                        // below our last published SEDP seq (e.g. base=1 with an empty bitmap),
                        // control.rs retransmits the SEDP DATA and re-sends a HEARTBEAT. Emitting
                        // the HB on every retry caused a HEARTBEAT storm with a peer that answers
                        // each one, hence first-retry-only here.
                        let has_heartbeat = if retry == 0 {
                            let (reader_id, writer_id) = match kind {
                                SedpEndpointKind::Writer => {
                                    ([0x00, 0x00, 0x03, 0xC7], [0x00, 0x00, 0x03, 0xC2])
                                }
                                SedpEndpointKind::Reader => {
                                    ([0x00, 0x00, 0x04, 0xC7], [0x00, 0x00, 0x04, 0xC2])
                                }
                            };

                            // Use dialect encoder for Final flag decision (same as Path B).
                            // The `Hybrid` and `FastDds` dialects use non-Final to force an
                            // ACKNACK response.
                            // The `Rti` dialect uses Final=true to prevent an HB/ACKNACK storm.
                            let count = next_sedp_heartbeat_count();
                            let use_final = encoder.sedp_heartbeat_final(&writer_id);
                            // firstSN = the first change not superseded when the
                            // history was read (RTPS v2.5 Sec.8.3.8.6), lastSN =
                            // seq_num. A GAP retiring the superseded prefix gets
                            // (first, first - 1), valid (Example 4 there).
                            let first_seq = send.first_available;
                            let hb = if use_final {
                                build_heartbeat_submessage_final(
                                    &reader_id, &writer_id, first_seq, *seq_num, count,
                                )
                            } else {
                                build_heartbeat_submessage(
                                    &reader_id, &writer_id, first_seq, *seq_num, count,
                                )
                            };
                            pkt.extend_from_slice(&hb);
                            true
                        } else {
                            false
                        };

                        for ep in &spdp_data_clone.metatraffic_unicast_locators {
                            match transport_clone.send_to_endpoint(&pkt, ep) {
                                Ok(_) => log::debug!(
                                    "{} [OK] SEDP retry #{} sent ({:?}) seq={} to {}{}",
                                    prefix,
                                    retry + 1,
                                    kind,
                                    seq_num,
                                    ep,
                                    if has_heartbeat { " (+HB)" } else { "" }
                                ),
                                Err(e) => log::debug!(
                                    "{} Failed to send SEDP retry #{} to {}: {}",
                                    prefix,
                                    retry + 1,
                                    ep,
                                    e
                                ),
                            }
                        }
                    }
                    Err(e) => {
                        log::debug!("{} Failed to build SEDP packet: {:?}", prefix, e);
                    }
                }
                drop(history);
            }
        }

        log::debug!(
            "{} [SEDP-RETRY] Completed all retries to peer {:02x}{:02x}...{:02x}{:02x}",
            prefix,
            peer_prefix[0],
            peer_prefix[1],
            peer_prefix[10],
            peer_prefix[11]
        );
    }));
    // Joined by the participant when it goes (`RetryRounds`).
    rounds.track(handle);
}

/// Send SEDP re-announcements to peer's unicast locators: the history as it
/// is now (`preallocate_sedp_sequence_numbers`), through the one retry loop
/// (`send_sedp_reannouncements_with_prealloc`).
///
/// # Arguments
/// - `spdp_data`: SPDP data with peer locators
/// - `our_guid_prefix`: Our participant GUID prefix
/// - `peer_guid_prefix`: Peer participant GUID prefix
/// - `local_metatraffic_port`: local port that scopes process-wide retry dedup
/// - `transport`: UDP transport for sending
/// - `sedp_cache`: SEDP announcements cache
/// - `log_prefix`: Log prefix for log::debug! messages
// justification: protocol handler needs SPDP data, both GUID prefixes,
// transport, SEDP cache, log prefix, dialect, and the security-gated shared
// secret; grouping into a struct would change call sites across the module.
#[allow(clippy::too_many_arguments)]
fn send_sedp_reannouncements(
    spdp_data: &SpdpData,
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
    local_metatraffic_port: u16,
    transport: Arc<UdpTransport>,
    sedp_cache: SedpAnnouncementsCache,
    log_prefix: &str,
    encoding_dialect: Dialect,
    fsm: &DiscoveryFsm,
    #[cfg(feature = "security")] peer_sedp_keys: Option<
        crate::security::crypto::secure_sedp::SedpWriterKeys,
    >,
) {
    let pre_allocated = preallocate_sedp_sequence_numbers(&sedp_cache);
    send_sedp_reannouncements_with_prealloc(
        spdp_data,
        our_guid_prefix,
        peer_guid_prefix,
        local_metatraffic_port,
        transport,
        &sedp_cache,
        pre_allocated,
        log_prefix,
        encoding_dialect,
        fsm,
        #[cfg(feature = "security")]
        peer_sedp_keys,
    );
}

/// Best-effort extractor for PID_METATRAFFIC_UNICAST_LOCATOR (0x0032) from a
/// raw SPDP CDR payload. This is a lightweight, vendor-tolerant parser used
/// when the main SPDP parser did not populate `metatraffic_unicast_locators`.
fn extract_metatraffic_unicast_from_cdr(buf: &[u8]) -> Option<SocketAddr> {
    // Need at least encapsulation (2 bytes) + PID header (4 bytes)
    if buf.len() < 6 {
        return None;
    }

    // Encapsulation is big-endian per CDR spec
    let encapsulation = u16::from_be_bytes([buf[0], buf[1]]);

    // An SPDP payload is usually PL_CDR_LE (0x0003) here.
    // We treat this as little-endian ParameterList for this recovery path.
    let is_le = matches!(encapsulation, CDR_LE | PL_CDR2_LE);

    // Detect padding: standard CDR uses 2-byte padding after encapsulation.
    let mut offset = if buf.len() > 3 && buf[2] == 0x00 && buf[3] == 0x00 {
        4
    } else {
        2
    };

    while offset + 4 <= buf.len() {
        let pid = if is_le {
            u16::from_le_bytes([buf[offset], buf[offset + 1]])
        } else {
            u16::from_be_bytes([buf[offset], buf[offset + 1]])
        };
        let length = if is_le {
            u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize
        };

        offset += 4;

        // PID_SENTINEL (0x0001) terminates the list
        if pid == 0x0001 {
            break;
        }

        if offset + length > buf.len() {
            break;
        }

        if pid == PID_METATRAFFIC_UNICAST_LOCATOR && length >= 24 {
            // locator: kind (4) + port (4) + address (16)
            let port_bytes = [
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ];

            // Under a little-endian encapsulation the locator port is little-endian.
            let port_u32 = if is_le {
                u32::from_le_bytes(port_bytes)
            } else {
                u32::from_be_bytes(port_bytes)
            };

            if let Ok(port_u16) = u16::try_from(port_u32) {
                let addr = Ipv4Addr::new(
                    buf[offset + 20],
                    buf[offset + 21],
                    buf[offset + 22],
                    buf[offset + 23],
                );
                return Some(SocketAddr::new(addr.into(), port_u16));
            }
        }

        // Advance to next PID (4-byte alignment is already handled by vendors).
        offset += length;
    }

    None
}

/// Send immediate SPDP unicast response to peer.
///
/// A peer may process our discovery HEARTBEATs only after it has our SPDP; an
/// immediate SPDP unicast response, sent as soon as the peer's SPDP is
/// received, provides it.
///
/// # Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: Remote participant GUID prefix (for INFO_DST)
/// - `peer_locators`: Peer's metatraffic_unicast locators
/// - `transport`: UDP transport for sending
/// - `port_mapping`: Port mapping for calculating locator ports
/// - `hdds_capabilities`: The local participant's `PID_HDDS_CAPABILITIES`
/// - `dialect_name`: Dialect name for logging
/// - `spdp_security_tokens`: Security payloads owned by the local participant
// 8 parameters: two independent lineages each added one (the SPDP timing work
// added `lease_duration_ms`, the per-participant token scoping added
// `spdp_security_tokens`) and the integration keeps both. Folding them into
// a context struct is the right follow-up; it is not done here because an
// integration branch replays proven commits, it does not redesign them.
#[allow(clippy::too_many_arguments)]
fn send_immediate_spdp_unicast(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
    peer_locators: &[SocketAddr],
    transport: &Arc<UdpTransport>,
    port_mapping: crate::transport::PortMapping,
    lease_duration_ms: u64,
    hdds_capabilities: u32,
    dialect_name: &str,
    spdp_security_tokens: &SpdpSecurityTokens,
) {
    // What the periodic announcement announces, read the same way.
    let locators = AnnouncedLocators::of(transport, port_mapping.user_unicast);
    let our_spdp_data = build_immediate_spdp_data(
        our_guid_prefix,
        &locators,
        lease_duration_ms,
        hdds_capabilities,
        spdp_security_tokens,
    );

    // The participant's next SPDP SN, from the counter its announcer
    // numbers with too: never one its announcements already passed.
    let seq_num = spdp_security_tokens
        .sequence
        .fetch_add(1, Ordering::Relaxed);

    // Build SPDP RTPS packet targeting peer (unicast mode)
    match build_spdp_rtps_packet(&our_spdp_data, seq_num, Some(peer_guid_prefix)) {
        Ok(packet) => {
            for ep in peer_locators {
                match transport.send_to_endpoint(&packet, ep) {
                    Ok(_) => log::debug!(
                        "[SPDP-UNICAST] [OK] Sent immediate SPDP unicast to {} (seq={}) [{} dialect]",
                        ep, seq_num, dialect_name
                    ),
                    Err(e) => log::debug!(
                        "[SPDP-UNICAST] Failed to send immediate SPDP unicast to {}: {}",
                        ep, e
                    ),
                }
            }
        }
        Err(e) => {
            log::debug!(
                "[SPDP-UNICAST] Failed to build immediate SPDP packet: {:?}",
                e
            );
        }
    }
}

/// Build the SPDP sample sent immediately to one freshly seen peer: the
/// participant's one SPDP sample (`spdp_announcement`), the one its periodic
/// announcement carries, from what its transport announces (`locators`).
///
/// It carries the participant's capabilities (`hdds_capabilities`), as its
/// periodic announcement does: it is often the first SPDP a peer gets, and
/// the peer decides the participant's GROUP dialect from it, and of its
/// writers as it discovers them. Without them, the peer took a participant
/// of the spec class for one of the 1.4.x class until its next periodic
/// announcement.
fn build_immediate_spdp_data(
    our_guid_prefix: &[u8; 12],
    locators: &AnnouncedLocators,
    lease_duration_ms: u64,
    hdds_capabilities: u32,
    spdp_security_tokens: &SpdpSecurityTokens,
) -> SpdpData {
    use crate::core::discovery::GUID;
    let participant_guid = GUID::new(
        *our_guid_prefix,
        crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
    );
    spdp_announcement(
        participant_guid,
        locators,
        lease_duration_ms,
        spdp_security_tokens.identity_token.clone(),
        spdp_security_tokens.permissions_token.clone(),
        spdp_security_tokens.participant_security_info,
        hdds_capabilities,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a participant on domain 0 announces with these unicast locators
    /// and no multicast.
    fn announced(metatraffic: &[SocketAddr], user: &[SocketAddr]) -> AnnouncedLocators {
        AnnouncedLocators {
            domain_id: 0,
            metatraffic_unicast: metatraffic.to_vec(),
            default_unicast: user.to_vec(),
            default_multicast: Vec::new(),
        }
    }

    /// The participant whose departure `synthetic_departure` announces.
    const DEPARTING_PREFIX: [u8; 12] = [
        0x01, 0x1a, 0x7e, 0x40, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
    ];
    /// The writerSN of that departure.
    const DEPARTURE_SN: u32 = 6;

    /// A participant's departure, the key-hash form, built for the test from
    /// RTPS v2.5 under the participant's own prefix. To exercise the
    /// detection it must carry, after a submessage the receiver skips, the
    /// DATA of the SPDP writer with E|Q (no payload), its instance named by
    /// PID_KEY_HASH and a PID_STATUS_INFO with DISPOSED|UNREGISTERED. The
    /// vendorId is HDDS's: the detection does not branch on it.
    fn synthetic_departure() -> Vec<u8> {
        let mut p = Vec::new();
        // RTPS header (Sec.8.3.3.1): protocol, version 2.5, vendorId, prefix.
        p.extend_from_slice(b"RTPS");
        p.extend_from_slice(&[0x02, 0x05]);
        p.extend_from_slice(&crate::core::rtps_constants::HDDS_VENDOR_ID);
        p.extend_from_slice(&DEPARTING_PREFIX);
        // A submessage with the unassigned id 0x00 (Table 8.13), E set, 8
        // octets: the receiver skips it by its length (Sec.8.3.4.1).
        p.extend_from_slice(&[0x00, 0x05, 0x08, 0x00]);
        p.extend_from_slice(&[0x3c, 0x5a, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44]);
        // INFO_TS (Sec.8.3.8.11), E: Time_t seconds, fraction.
        p.extend_from_slice(&[0x09, 0x01, 0x08, 0x00]);
        p.extend_from_slice(&1_790_000_123u32.to_le_bytes());
        p.extend_from_slice(&0x2000_0000u32.to_le_bytes());
        // DATA (Sec.8.3.8.2), E|Q, D and K clear, 52 octets: extraFlags,
        // octetsToInlineQos 16, readerId ENTITYID_UNKNOWN, writerId
        // ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER, writerSN.
        p.extend_from_slice(&[0x15, 0x03, 0x34, 0x00]);
        p.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]);
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0xc2]);
        p.extend_from_slice(&0i32.to_le_bytes());
        p.extend_from_slice(&DEPARTURE_SN.to_le_bytes());
        // Inline QoS: PID_STATUS_INFO (Sec.9.6.4.9), flags DISPOSED|UNREGISTERED
        // in the last octet; PID_KEY_HASH (Sec.9.6.4.8), the participant GUID;
        // PID_SENTINEL.
        p.extend_from_slice(&[0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03]);
        p.extend_from_slice(&[0x70, 0x00, 0x10, 0x00]);
        p.extend_from_slice(&departing_participant().as_bytes());
        p.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        p
    }

    /// Where the classifier says the DATA's serialized payload starts: the
    /// offset `handle_spdp_packet` is handed.
    fn data_payload_offsets(packet: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        crate::core::discovery::multicast::classifier::for_each_data_submessage(packet, |data| {
            offsets.push(data.payload_offset)
        });
        offsets
    }

    fn departing_participant() -> GUID {
        GUID::new(
            DEPARTING_PREFIX,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        )
    }

    /// RTPS v2.5 Sec.9.6.4.9: a departure behind a skipped submessage and an
    /// INFO_TS is read as one, with the participant it names.
    #[test]
    fn a_participant_departure_is_read_as_one() {
        let packet = synthetic_departure();
        // Header 20, unknown submessage 12, INFO_TS 12, DATA 4 + 52.
        assert_eq!(packet.len(), 100, "fixture: the datagram as laid out");
        let offsets = data_payload_offsets(&packet);
        assert_eq!(offsets.len(), 1, "fixture: one DATA");
        assert_eq!(
            detect_spdp_participant_dispose(&packet, offsets[0]),
            Some(departing_participant())
        );
    }

    /// A DATA that disposes nothing (StatusInfo without the DISPOSED or the
    /// UNREGISTERED bit) is not a departure.
    #[test]
    fn a_status_without_dispose_nor_unregister_is_no_departure() {
        let mut packet = synthetic_departure();
        let status = packet
            .windows(8)
            .position(|w| w == [0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03])
            .expect("fixture: the StatusInfo parameter");
        packet[status + 7] = 0x00;
        let offsets = data_payload_offsets(&packet);
        assert_eq!(detect_spdp_participant_dispose(&packet, offsets[0]), None);
    }

    /// The same parameters on another writer's DATA (here the SEDP
    /// publications writer: an endpoint's dispose) or on a DATA that carries
    /// a payload are not a participant's departure.
    #[test]
    fn only_a_payload_less_data_of_the_spdp_writer_is_a_departure() {
        let reference = synthetic_departure();
        let at = data_submessage_at(&reference, data_payload_offsets(&reference)[0]).expect("DATA");

        let mut sedp = reference.clone();
        sedp[at + 12..at + 16].copy_from_slice(&[0x00, 0x00, 0x03, 0xc2]);
        assert_eq!(
            detect_spdp_participant_dispose(&sedp, data_payload_offsets(&sedp)[0]),
            None,
            "an endpoint dispose"
        );

        let mut with_payload = reference.clone();
        with_payload[at + 1] |= 0x04;
        assert_eq!(
            detect_spdp_participant_dispose(&with_payload, data_payload_offsets(&with_payload)[0]),
            None,
            "a DATA with a payload"
        );
    }

    /// The key-only form of a departure (K=1, no PID_KEY_HASH, Sec.9.6.3.2):
    /// inline QoS with only PID_STATUS_INFO, then a PL_CDR serialized key
    /// holding PID_PARTICIPANT_GUID. Built for the test, sent under
    /// `sender`, with HDDS's vendorId: the detection does not branch on it.
    fn key_only_departure(participant: GUID, sender: [u8; 12]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[0x02, 0x04]);
        packet.extend_from_slice(&crate::core::rtps_constants::HDDS_VENDOR_ID);
        packet.extend_from_slice(&sender);
        let inline_qos: [u8; 12] = [
            0x71, 0x00, 0x04, 0x00, 0, 0, 0, 0x03, 0x01, 0x00, 0x00, 0x00,
        ];
        let mut key = vec![0x00, 0x03, 0x00, 0x00, 0x50, 0x00, 0x10, 0x00];
        key.extend_from_slice(&participant.as_bytes());
        key.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let body = 20 + inline_qos.len() + key.len();
        packet.extend_from_slice(&[0x15, 0x0b]);
        packet.extend_from_slice(&u16::try_from(body).expect("small").to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0xc7, 0x00, 0x01, 0x00, 0xc2]);
        packet.extend_from_slice(&[0, 0, 0, 0, 9, 0, 0, 0]);
        packet.extend_from_slice(&inline_qos);
        packet.extend_from_slice(&key);
        packet
    }

    /// A departure carrying its participant in the serialized key, not in a
    /// key hash, is read as one. It must not fall through to the
    /// announcement parser, which accepts a lone PID_PARTICIPANT_GUID and
    /// would refresh the departed participant for a default 100 s lease.
    #[test]
    fn a_key_only_departure_is_read_as_one() {
        let participant = departing_participant();
        let packet = key_only_departure(participant, participant.prefix);
        let offsets = data_payload_offsets(&packet);
        assert_eq!(offsets.len(), 1, "fixture: one DATA");
        assert_eq!(
            detect_spdp_participant_dispose(&packet, offsets[0]),
            Some(participant)
        );
    }

    /// A participant announces only its own departure: one naming another
    /// participant than the one whose prefix the message carries is refused.
    #[test]
    fn a_departure_naming_another_participant_is_refused() {
        let named = departing_participant();
        let spoofed = key_only_departure(named, [0xEE; 12]);
        assert_eq!(
            detect_spdp_participant_dispose(&spoofed, data_payload_offsets(&spoofed)[0]),
            None
        );
        let mut hashed = synthetic_departure();
        hashed[8..20].copy_from_slice(&[0xEE; 12]);
        assert_eq!(
            detect_spdp_participant_dispose(&hashed, data_payload_offsets(&hashed)[0]),
            None
        );
    }

    /// The whole prefix is compared, not a part of it: a sender whose prefix
    /// differs from the named participant's in its first octet only, or in
    /// its last octet only, is refused too, in both forms.
    #[test]
    fn a_departure_naming_a_prefix_one_octet_away_is_refused() {
        let named = departing_participant();
        for octet in [0, 11] {
            let mut sender = named.prefix;
            sender[octet] ^= 0x01;

            let spoofed = key_only_departure(named, sender);
            assert_eq!(
                detect_spdp_participant_dispose(&spoofed, data_payload_offsets(&spoofed)[0]),
                None,
                "key only, octet {octet}"
            );

            let mut hashed = synthetic_departure();
            hashed[8..20].copy_from_slice(&sender);
            assert_eq!(
                detect_spdp_participant_dispose(&hashed, data_payload_offsets(&hashed)[0]),
                None,
                "key hash, octet {octet}"
            );
        }
    }

    /// The departed participant is named by its prefix, under the
    /// participant entity id, whatever entity id the key carries.
    #[test]
    fn a_departure_names_the_participant_by_its_prefix() {
        let mut packet = synthetic_departure();
        let key = packet
            .windows(4)
            .position(|w| w == [0x70, 0x00, 0x10, 0x00])
            .expect("fixture: PID_KEY_HASH")
            + 4;
        packet[key + 15] = 0xc0;
        assert_eq!(
            detect_spdp_participant_dispose(&packet, data_payload_offsets(&packet)[0]),
            Some(departing_participant())
        );
    }

    /// A departure drops what this participant recorded about that peer,
    /// and only that: another peer, and another local participant's record
    /// of the same peer, stay.
    #[test]
    fn a_departure_forgets_that_peer_only() {
        let ours = [0x31; 12];
        let other_local = [0x32; 12];
        let departed = [0x33; 12];
        let staying = [0x34; 12];
        let keys = [
            DiscoveryPeerKey::new(ours, 7410, departed),
            DiscoveryPeerKey::new(ours, 7410, staying),
            DiscoveryPeerKey::new(other_local, 7412, departed),
        ];
        for key in keys {
            completed_peers().lock().expect("lock").insert(key);
            responded_spdp_peers()
                .lock()
                .expect("lock")
                .insert(key, Instant::now());
        }
        forget_remote_peer(ours, departed);
        let completed = completed_peers().lock().expect("lock").clone();
        let responded: HashSet<DiscoveryPeerKey> = responded_spdp_peers()
            .lock()
            .expect("lock")
            .keys()
            .copied()
            .collect();
        for (key, kept) in keys.iter().zip([false, true, true]) {
            assert_eq!(completed.contains(key), kept, "completed {key:?}");
            assert_eq!(responded.contains(key), kept, "responded {key:?}");
        }
        forget_local_participant(ours);
        forget_local_participant(other_local);
    }

    /// A peer whose lease expired is forgotten like one that announced its
    /// departure: answered and announced to again if it comes back under the
    /// same prefix. Another peer's records, and a peer removed for another
    /// reason, are not touched by the expiry hook.
    #[test]
    fn a_peer_whose_lease_expired_is_forgotten() {
        use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
        let ours = [0x41; 12];
        let expired = [0x42; 12];
        let staying = [0x43; 12];
        let fsm = DiscoveryFsm::new(GUID::new(ours, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.register_listener(Arc::new(ForgottenPeerRecords::new(ours)));
        let announcement = |prefix: [u8; 12], lease_duration_ms: u64| SpdpData {
            participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
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
        fsm.handle_spdp(announcement(expired, 20));
        fsm.handle_spdp(announcement(staying, 30_000));
        let keys = [
            DiscoveryPeerKey::new(ours, 7410, expired),
            DiscoveryPeerKey::new(ours, 7410, staying),
        ];
        for key in keys {
            completed_peers().lock().expect("lock").insert(key);
            responded_spdp_peers()
                .lock()
                .expect("lock")
                .insert(key, Instant::now());
        }

        std::thread::sleep(Duration::from_millis(60));
        fsm.remove_expired_participant(GUID::new(expired, RTPS_ENTITYID_PARTICIPANT));
        fsm.remove_expired_participant(GUID::new(staying, RTPS_ENTITYID_PARTICIPANT));

        let completed = completed_peers().lock().expect("lock").clone();
        let responded = responded_spdp_peers().lock().expect("lock").clone();
        assert!(!fsm.is_participant_known(&expired));
        assert!(
            !completed.contains(&keys[0]),
            "an expired peer stays announced-to"
        );
        assert!(
            !responded.contains_key(&keys[0]),
            "an expired peer stays answered"
        );
        assert!(completed.contains(&keys[1]), "a live peer lost its record");
        assert!(responded.contains_key(&keys[1]));
        forget_local_participant(ours);
    }

    /// The same rule on a participant as it is built: the hook is wired, and
    /// an expired peer's records go.
    #[test]
    fn a_built_participant_forgets_a_peer_whose_lease_expired() {
        use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
        let domain = crate::test_support::domains::unique_domain();
        let p = crate::dds::Participant::builder("expired-peer-records")
            .domain_id(domain.id())
            .with_transport(crate::dds::TransportMode::UdpMulticast)
            .build()
            .expect("participant");
        let fsm = p
            .discovery_fsm
            .clone()
            .expect("a UDP participant runs discovery");
        let ours = p.guid().prefix;
        let peer = [0x44; 12];
        // A participant first heard during the startup probation and never
        // again is purged, not expired: announce it after.
        std::thread::sleep(Duration::from_millis(300).saturating_sub(fsm.uptime()));
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(peer, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 20,
            domain_id: domain.id(),
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
        let key = DiscoveryPeerKey::new(ours, 7410, peer);
        completed_peers().lock().expect("lock").insert(key);

        std::thread::sleep(Duration::from_millis(60));
        fsm.remove_expired_participant(GUID::new(peer, RTPS_ENTITYID_PARTICIPANT));

        assert!(!fsm.is_participant_known(&peer));
        assert!(
            !completed_peers().lock().expect("lock").contains(&key),
            "the participant kept its record of a peer whose lease expired"
        );
    }

    /// A participant that authenticated again over its completed session (a
    /// participant re-created under the same prefix, `SpdpVerdict::
    /// Reauthenticated`) is forgotten as a departed one is: "already
    /// announced" would keep our endpoints from the new process, which has
    /// none of them. The verdict is taken once, on its next announcement.
    #[cfg(feature = "security")]
    #[test]
    fn a_participant_that_authenticated_again_is_announced_to_again() {
        use super::super::wire_fixtures::{
            announcement_from, data_datagram, Harness, OUR_PREFIX, SAMPLE_AT, SENDER_PREFIX, SPDP,
        };
        use crate::core::discovery::multicast::PacketKind;
        let mut h = Harness::new();
        let machine = crate::security::test_pki::local_machine_with_completed_peer(
            OUR_PREFIX,
            SENDER_PREFIX,
            None,
        );
        Arc::get_mut(&mut h.dispatch.fsm)
            .expect("the harness is the FSM's only owner")
            .set_handshake_machine(
                machine,
                crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
                crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
            );
        std::sync::Arc::get_mut(&mut h.dispatch.fsm)
            .expect("the harness is the FSM's only owner")
            .register_builtin_writer_keys_for_tests();
        let (_, cdr) = announcement_from(SENDER_PREFIX);
        let announcement = data_datagram(SENDER_PREFIX, &SPDP, &cdr);
        h.feed(PacketKind::SPDP, &announcement, SAMPLE_AT, None);
        let key = DiscoveryPeerKey::new(
            OUR_PREFIX,
            h.dispatch.port_mapping.metatraffic_unicast,
            SENDER_PREFIX,
        );
        completed_peers().lock().expect("lock").insert(key);

        // A plain announcement of an authenticated peer changes nothing...
        h.feed(PacketKind::SPDP, &announcement, SAMPLE_AT, None);
        assert!(completed_peers().lock().expect("lock").contains(&key));

        // ...unless it has just authenticated (again): the records go, and a
        // re-announcement still running from before is no reason to skip
        // the sealed one.
        active_retries().lock().expect("lock").insert(key);
        h.dispatch.fsm.owe_reannouncement(SENDER_PREFIX);
        h.feed(PacketKind::SPDP, &announcement, SAMPLE_AT, None);
        assert!(
            !completed_peers().lock().expect("lock").contains(&key),
            "a re-authenticated participant is still recorded as announced to"
        );
        assert!(
            !active_retries().lock().expect("lock").contains(&key),
            "a re-announcement still running from before would skip the sealed one"
        );
        forget_local_participant(OUR_PREFIX);
    }

    /// A participant the startup probation purges (first heard in our first
    /// 100 ms, never again) is forgotten too: if it was alive after all and
    /// announces itself again, it is announced to and answered again. The
    /// lease-0 farewell of a 1.4.x peer keeps them: its announcement is
    /// still answered after it, and forgetting first would re-announce to a
    /// participant that is leaving.
    #[test]
    fn a_participant_the_probation_purges_is_forgotten_and_a_farewell_is_not() {
        use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
        let ours = [0x51; 12];
        let purged = [0x52; 12];
        let farewell = [0x53; 12];
        let fsm = DiscoveryFsm::new(GUID::new(ours, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.register_listener(Arc::new(ForgottenPeerRecords::new(ours)));
        let announcement = |prefix: [u8; 12], lease_duration_ms: u64| SpdpData {
            participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
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
        fsm.handle_spdp(announcement(purged, 30_000));
        fsm.handle_spdp(announcement(farewell, 30_000));
        let keys = [
            DiscoveryPeerKey::new(ours, 7410, purged),
            DiscoveryPeerKey::new(ours, 7410, farewell),
        ];
        for key in keys {
            completed_peers().lock().expect("lock").insert(key);
        }

        fsm.handle_spdp(announcement(farewell, 0));
        std::thread::sleep(Duration::from_millis(300));
        fsm.maybe_complete_probation();

        assert!(!fsm.is_participant_known(&purged), "fixture: purged");
        assert!(!fsm.is_participant_known(&farewell), "fixture: departed");
        let completed = completed_peers().lock().expect("lock").clone();
        assert!(
            !completed.contains(&keys[0]),
            "a purged peer stays announced-to"
        );
        assert!(
            completed.contains(&keys[1]),
            "a lease-0 farewell forgot its peer"
        );
        forget_local_participant(ours);
    }

    /// An announcement is no departure, whatever its lease.
    #[test]
    fn an_announcement_is_no_departure() {
        let packet = crate::core::discovery::multicast::build_spdp_rtps_packet(
            &SpdpData {
                participant_guid: departing_participant(),
                lease_duration_ms: 0,
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
            },
            3,
            None,
        )
        .expect("announcement");
        let offsets = data_payload_offsets(&packet);
        assert_eq!(detect_spdp_participant_dispose(&packet, offsets[0]), None);
    }

    /// Our own departure has the shape of the departure built from the spec
    /// above, octet for octet but for the participant it names and its
    /// readerId (ours addresses the SPDP reader, as our announcements do),
    /// and reads back as the departure of that participant.
    #[test]
    fn our_departure_has_the_reference_shape_and_reads_back() {
        let ours = GUID::from_bytes([
            0x01, 0x1a, 0x3d, 0x52, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00,
            0x01, 0xc1,
        ]);
        let packet = crate::core::discovery::multicast::build_spdp_dispose_packet(
            &ours,
            u64::from(DEPARTURE_SN),
        );
        let offsets = data_payload_offsets(&packet);
        assert_eq!(offsets.len(), 1);
        assert_eq!(
            detect_spdp_participant_dispose(&packet, offsets[0]),
            Some(ours)
        );

        let data_of = |packet: &[u8]| -> Vec<u8> {
            let at = data_submessage_at(packet, data_payload_offsets(packet)[0]).expect("DATA");
            packet[at..].to_vec()
        };
        let mut reference = data_of(&synthetic_departure());
        // readerId: ENTITYID_UNKNOWN in the reference, the SPDP reader here.
        reference[8..12].copy_from_slice(&[0x00, 0x01, 0x00, 0xc7]);
        // The key hash names our participant.
        let key = reference
            .windows(4)
            .position(|w| w == [0x70, 0x00, 0x10, 0x00])
            .expect("reference: PID_KEY_HASH")
            + 4;
        reference[key..key + 16].copy_from_slice(&ours.as_bytes());
        assert_eq!(data_of(&packet), reference);
    }

    /// A departure retires the participant, heard as announced; our own,
    /// heard back over multicast, does not retire us.
    #[test]
    fn a_departure_retires_the_participant_it_names_but_never_us() {
        struct Left(std::sync::Mutex<Vec<bool>>);
        impl crate::core::discovery::multicast::DiscoveryListener for Left {
            fn on_endpoint_discovered(
                &self,
                endpoint: crate::core::discovery::multicast::EndpointInfo,
            ) {
                drop(endpoint);
            }
            fn on_participant_left(&self, _participant: GUID, announced: bool) {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(announced);
            }
        }
        let local = GUID::new(
            [0x01, 0x1a, 0x3d, 0x52, 0, 7, 0, 0, 0, 0, 0, 0x41],
            [0, 0, 1, 0xc1],
        );
        let fsm = DiscoveryFsm::new(local, 30_000);
        let left = std::sync::Arc::new(Left(std::sync::Mutex::new(Vec::new())));
        fsm.register_listener(left.clone());
        let announce = |guid: GUID| SpdpData {
            participant_guid: guid,
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
        let remote = departing_participant();
        fsm.handle_spdp(announce(remote));
        assert!(fsm.is_participant_known(&remote.prefix), "fixture: known");

        apply_participant_departure(local, local.prefix, &fsm, None);
        assert!(
            fsm.is_participant_known(&remote.prefix),
            "ours retires nobody"
        );

        let peers = SpdpPeerSet::new();
        peers.refresh_discovered(
            remote.prefix,
            ["192.0.2.7:7410".parse::<SocketAddr>().expect("addr")],
            Duration::from_secs(100),
        );
        assert_eq!(peers.snapshot().len(), 1, "fixture: a unicast destination");
        let record = DiscoveryPeerKey::new(local.prefix, 7410, remote.prefix);
        completed_peers().lock().expect("lock").insert(record);
        apply_participant_departure(remote, local.prefix, &fsm, Some(&peers));
        assert!(!fsm.is_participant_known(&remote.prefix), "retired");
        assert_eq!(
            left.0.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            vec![true],
            "heard as announced"
        );
        assert!(peers.snapshot().is_empty(), "no longer a SPDP destination");
        assert!(
            !completed_peers().lock().expect("lock").contains(&record),
            "no longer recorded as announced to"
        );
        forget_local_participant(local.prefix);
    }

    /// A sealed departure naming our own prefix - one of our datagrams heard
    /// back, or a peer that lists our metatraffic locator among its own and
    /// has it sent to us - is not ours to apply. The guard is the clear
    /// path's (`apply_participant_departure`); the same call about a peer
    /// still retires it, so this is not a departure dropped everywhere.
    #[cfg(feature = "security")]
    #[test]
    fn a_sealed_departure_naming_us_is_not_ours_to_apply() {
        let local = GUID::new(
            [0x01, 0x1a, 0x3d, 0x52, 0, 7, 0, 0, 0, 0, 0, 0x41],
            [0, 0, 1, 0xc1],
        );
        let remote = departing_participant();
        let fsm = DiscoveryFsm::new(local, 30_000);
        let store = fsm.db();
        {
            let mut db = store.write().expect("lock");
            for guid in [local, remote] {
                db.insert(
                    guid,
                    crate::core::discovery::multicast::ParticipantInfo::new(
                        guid,
                        Vec::new(),
                        100_000,
                    ),
                );
            }
        }

        apply_sealed_participant_departure(local, local.prefix, &fsm, None);
        assert!(
            fsm.is_participant_known(&local.prefix),
            "a sealed departure naming us is not ours to apply"
        );

        apply_sealed_participant_departure(remote, local.prefix, &fsm, None);
        assert!(
            !fsm.is_participant_known(&remote.prefix),
            "the same call retires a peer"
        );
    }

    /// The one accessor hands out strictly increasing counts, so two SEDP
    /// HEARTBEATs built back to back can never carry the same Count_t.
    #[test]
    fn sedp_heartbeat_counts_strictly_increase() {
        let a = next_sedp_heartbeat_count();
        let b = next_sedp_heartbeat_count();
        let c = next_sedp_heartbeat_count();
        assert!(a < b && b < c, "{} {} {}", a, b, c);
    }

    /// An SEDP change not sent to a participant retires its sequence with a
    /// GAP on the peer's metatraffic locators: single-SN form, plaintext SEDP
    /// writer id, our prefix in the header.
    #[test]
    #[cfg(feature = "security")]
    fn a_sedp_sequence_not_sent_is_retired_with_a_gap() {
        use crate::test_support::domains::unique_domain;
        let domain = unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport = UdpTransport::new(domain.id(), 0, mapping).expect("test transport");

        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set timeout");
        let peer_locator = listener.local_addr().expect("listener addr");

        retire_sedp_sequence_with_gap(
            SedpEndpointKind::Writer,
            7,
            &[0x11; 12],
            &[0x22; 12],
            &transport,
            &[peer_locator],
            "[test]",
        );

        let mut buf = [0u8; 256];
        let n = listener
            .recv(&mut buf)
            .expect("the GAP reaches the peer locator");
        let pkt = &buf[..n];
        assert_eq!(&pkt[0..4], b"RTPS");
        assert_eq!(&pkt[8..20], &[0x11; 12], "the header carries OUR prefix");
        assert_eq!(pkt[20], 0x08, "one GAP submessage, nothing else");
        assert_eq!(
            &pkt[24..28],
            &[0x00, 0x00, 0x03, 0xC7],
            "readerId = SEDP publications reader"
        );
        assert_eq!(
            &pkt[28..32],
            &[0x00, 0x00, 0x03, 0xC2],
            "writerId = plaintext SEDP writer"
        );
        // gapStart = 7 (high i32 0, low u32 7), gapList base = 8, numBits = 0
        assert_eq!(&pkt[32..40], &[0, 0, 0, 0, 7, 0, 0, 0], "gapStart = 7");
        assert_eq!(&pkt[40..48], &[0, 0, 0, 0, 8, 0, 0, 0], "gapList.base = 8");
        assert_eq!(
            &pkt[48..52],
            &[0, 0, 0, 0],
            "numBits = 0: exactly one sequence retired"
        );
        assert_eq!(n, 52, "no bitmap words follow an empty set");
    }

    #[test]
    fn immediate_spdp_security_tokens_stay_with_their_participant() {
        let locators = vec!["127.0.0.1:9160".parse().expect("valid locator")];

        let participant_a = SpdpSecurityTokens::new(
            Some(vec![0xA1, 0xA2, 0xA3]),
            Some(vec![0xA4, 0xA5]),
            Some([0xA6; 8]),
        );
        let participant_b = SpdpSecurityTokens::new(
            Some(vec![0xB1, 0xB2, 0xB3]),
            Some(vec![0xB4, 0xB5]),
            Some([0xB6; 8]),
        );

        let user_locators = vec!["127.0.0.1:7411".parse::<SocketAddr>().expect("valid")];
        let response_b = build_immediate_spdp_data(
            &[0xB0; 12],
            &announced(&locators, &user_locators),
            600_000,
            crate::protocol::group::LOCAL_CAPABILITIES,
            &participant_b,
        );
        let response_a = build_immediate_spdp_data(
            &[0xA0; 12],
            &announced(&locators, &user_locators),
            600_000,
            crate::protocol::group::LOCAL_CAPABILITIES,
            &participant_a,
        );

        assert_eq!(response_a.identity_token, Some(vec![0xA1, 0xA2, 0xA3]));
        assert_eq!(response_a.permissions_token, Some(vec![0xA4, 0xA5]));
        assert_eq!(response_a.participant_security_info, Some([0xA6; 8]));
        assert_eq!(response_b.identity_token, Some(vec![0xB1, 0xB2, 0xB3]));
        assert_eq!(response_b.permissions_token, Some(vec![0xB4, 0xB5]));
        assert_eq!(response_b.participant_security_info, Some([0xB6; 8]));
        assert_ne!(response_a.identity_token, response_b.identity_token);
    }

    fn discovery_peer_key(tag: u8, local_metatraffic_port: u16) -> DiscoveryPeerKey {
        let mut local_prefix = [0x7F; 12];
        local_prefix[11] = tag;
        let mut peer_prefix = [0xED; 12];
        peer_prefix[11] = tag;
        DiscoveryPeerKey::new(local_prefix, local_metatraffic_port, peer_prefix)
    }

    /// A fresh discovery path should be marked as newly responded on the first
    /// call and as already responded on any subsequent call.
    #[test]
    fn mark_peer_responded_is_idempotent_per_peer() {
        // Use a distinctive prefix that no other test is likely to reuse,
        // since the underlying HashSet is a process-wide static.
        let peer = discovery_peer_key(1, 41_010);

        assert!(
            mark_peer_responded(peer),
            "first call must return true (peer was not in the set)"
        );
        assert!(
            !mark_peer_responded(peer),
            "second call must return false (peer is already in the set)"
        );
        assert!(
            !mark_peer_responded(peer),
            "third call must also return false (no bounce)"
        );
    }

    /// What this guards: a participant that terminates frees its
    /// participant id and its RTPS ports, so the next participant in the same
    /// process may be handed the same id, the same GUID prefix and the same
    /// metatraffic port. Its key is then byte-identical to the dead one's, and
    /// `COMPLETED_PEERS` must not keep that key forever, or `try_acquire`
    /// would refuse to retry SEDP towards a peer the new participant had never
    /// spoken to, with discovery stopping with no error anywhere.
    #[test]
    fn a_recycled_discovery_path_may_retry_sedp_again() {
        let peer = discovery_peer_key(90, 41_900);

        let guard = RetryGuard::try_acquire(peer).expect("a fresh path must be allowed to retry");
        drop(guard);
        assert!(
            RetryGuard::try_acquire(peer).is_none(),
            "while the participant lives, a completed cycle must not retry again"
        );

        // The participant terminates and its slot is recycled.
        forget_local_participant(peer.local_prefix);

        let reborn = RetryGuard::try_acquire(peer);
        assert!(
            reborn.is_some(),
            "a participant reusing a freed id must announce itself, not inherit \
             the dead one's completed state"
        );
        drop(reborn);
        forget_local_participant(peer.local_prefix);
    }

    /// The purge is scoped to one local participant: a sibling still alive in
    /// the same process keeps its dedup state.
    #[test]
    fn forgetting_one_participant_leaves_its_siblings_alone() {
        let mine = discovery_peer_key(91, 41_910);
        let sibling = discovery_peer_key(92, 41_920);

        assert!(mark_peer_responded(mine));
        assert!(mark_peer_responded(sibling));
        drop(RetryGuard::try_acquire(mine).expect("mine acquires"));
        drop(RetryGuard::try_acquire(sibling).expect("sibling acquires"));

        forget_local_participant(mine.local_prefix);

        assert!(
            mark_peer_responded(mine),
            "my responded-SPDP entry must be gone"
        );
        assert!(
            !mark_peer_responded(sibling),
            "the sibling's responded-SPDP entry must survive"
        );
        assert!(
            RetryGuard::try_acquire(sibling).is_none(),
            "the sibling's completed state must survive"
        );

        forget_local_participant(mine.local_prefix);
        forget_local_participant(sibling.local_prefix);
    }

    /// Different peer prefixes must be tracked independently of one another.
    #[test]
    fn mark_peer_responded_distinguishes_peers() {
        let peer_a = discovery_peer_key(2, 41_020);
        let peer_b = discovery_peer_key(3, 41_020);

        assert!(mark_peer_responded(peer_a));
        assert!(mark_peer_responded(peer_b));
        assert!(!mark_peer_responded(peer_a));
        assert!(!mark_peer_responded(peer_b));
    }

    #[test]
    fn immediate_spdp_response_is_scoped_by_local_discovery_path() {
        let first_domain = discovery_peer_key(4, 41_270);
        let second_domain =
            DiscoveryPeerKey::new(first_domain.local_prefix, 41_520, first_domain.peer_prefix);

        assert!(mark_peer_responded(first_domain));
        assert!(!mark_peer_responded(first_domain));
        assert!(
            mark_peer_responded(second_domain),
            "another DDS domain must receive its own immediate SPDP response"
        );
    }

    /// An entry not refreshed for longer than the TTL must be evicted
    /// on the next call, and the peer should re-signal "respond" as if new.
    #[test]
    fn mark_peer_responded_at_expires_after_ttl() {
        let mut map: HashMap<DiscoveryPeerKey, Instant> = HashMap::new();
        let peer = discovery_peer_key(0x10, 41_030);
        let ttl = Duration::from_secs(1);
        let t0 = Instant::now();

        assert!(
            mark_peer_responded_at(&mut map, peer, t0, ttl),
            "fresh peer must return true"
        );
        assert!(
            !mark_peer_responded_at(&mut map, peer, t0 + Duration::from_millis(500), ttl),
            "peer seen 500 ms ago (within 1 s TTL) must return false"
        );
        assert!(
            mark_peer_responded_at(&mut map, peer, t0 + Duration::from_secs(2), ttl),
            "peer last seen 2 s ago (past 1 s TTL) must be evicted and return true"
        );
    }

    /// A peer that keeps announcing within the TTL window stays tracked
    /// indefinitely -- the "last seen" timestamp is refreshed on every call.
    #[test]
    fn mark_peer_responded_at_refreshes_last_seen_on_active_peer() {
        let mut map: HashMap<DiscoveryPeerKey, Instant> = HashMap::new();
        let peer = discovery_peer_key(0x11, 41_040);
        let ttl = Duration::from_secs(1);
        let t0 = Instant::now();

        assert!(mark_peer_responded_at(&mut map, peer, t0, ttl));
        // Three refreshes spaced 500 ms apart, all within TTL -- map never evicts.
        for i in 1..=3u32 {
            let t = t0 + Duration::from_millis(500 * u64::from(i));
            assert!(
                !mark_peer_responded_at(&mut map, peer, t, ttl),
                "refresh #{i} within TTL must return false"
            );
        }
        // Confirm the refresh genuinely moved last_seen forward: almost-TTL
        // from the most recent refresh still counts as tracked.
        let last_refresh = t0 + Duration::from_millis(500 * 3);
        assert!(
            !mark_peer_responded_at(
                &mut map,
                peer,
                last_refresh + ttl - Duration::from_millis(1),
                ttl
            ),
            "almost-TTL from last refresh must still return false (refresh worked)"
        );
    }

    #[test]
    fn immediate_spdp_carries_both_public_ports_of_an_external_locator_on_the_wire() {
        // A participant behind a NAT announces one address with TWO public
        // ports. Deriving the user-data locator by rewriting the metatraffic
        // locator's port -- what this function did before -- would put
        // 93.184.216.34:7411 on the wire, a pair the NAT maps to nothing.
        let local_meta: SocketAddr = "192.168.1.50:7410".parse().expect("valid");
        let local_user: SocketAddr = "192.168.1.50:7411".parse().expect("valid");
        let public_meta: SocketAddr = "93.184.216.34:40001".parse().expect("valid");
        let public_user: SocketAddr = "93.184.216.34:40002".parse().expect("valid");

        let data = build_immediate_spdp_data(
            &[0x42; 12],
            &announced(&[local_meta, public_meta], &[local_user, public_user]),
            600_000,
            crate::protocol::group::LOCAL_CAPABILITIES,
            &SpdpSecurityTokens::default(),
        );
        let mut wire = vec![0u8; 2048];
        let len = crate::protocol::discovery::build_spdp(&data, &mut wire).expect("build");
        let parsed = parse_spdp(&wire[..len]).expect("parse");

        assert!(
            parsed.metatraffic_unicast_locators.contains(&public_meta),
            "metatraffic locators on the wire: {:?}",
            parsed.metatraffic_unicast_locators
        );
        assert!(
            parsed.default_unicast_locators.contains(&public_user),
            "user-data locators on the wire: {:?}",
            parsed.default_unicast_locators
        );
        // The rewritten pair must be absent: that is the defect this guards.
        assert!(
            !parsed
                .default_unicast_locators
                .contains(&"93.184.216.34:7411".parse().expect("valid")),
            "the public address was advertised with the LOCAL user port: {:?}",
            parsed.default_unicast_locators
        );
        // And the LAN pair survives, so a peer on our subnet keeps a direct
        // route.
        assert!(parsed.metatraffic_unicast_locators.contains(&local_meta));
        assert!(parsed.default_unicast_locators.contains(&local_user));
    }

    /// The immediate reply and the periodic announcement of one participant,
    /// on the wire: the same parameters, the domain the transport's (custom
    /// ports do not encode it), no multicast locator for a participant that
    /// sends no multicast. The reply re-derived the domain from the
    /// multicast port and always advertised the multicast group.
    #[test]
    fn the_immediate_spdp_is_the_periodic_one() {
        use crate::core::discovery::GUID;
        let (domain, ports) = (
            crate::test_support::domains::unique_domain(),
            crate::test_support::domains::unique_domain(),
        );
        // Custom ports: another domain's.
        let mapping = crate::transport::PortMapping::calculate(ports.id(), 0).expect("mapping");
        for (unicast_only, multicast) in [(false, true), (true, false)] {
            let mut options = crate::transport::TransportOptions::default();
            if unicast_only {
                options = options.unicast_only();
            }
            let transport =
                UdpTransport::new_with_options(domain.id(), 0, mapping, &options.resolve())
                    .expect("transport");
            let tokens = SpdpSecurityTokens::default();
            let caps = crate::protocol::group::LOCAL_CAPABILITIES;
            let locators = AnnouncedLocators::of(&transport, mapping.user_unicast);
            let immediate =
                build_immediate_spdp_data(&[0x42; 12], &locators, 600_000, caps, &tokens);
            // As `announcer_loop` builds it.
            let periodic = spdp_announcement(
                GUID::new(
                    [0x42; 12],
                    crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                ),
                &AnnouncedLocators::of(&transport, mapping.user_unicast),
                600_000,
                None,
                None,
                None,
                caps,
            );
            let wire = |data: &SpdpData| {
                let mut buf = vec![0u8; 2048];
                let len = crate::protocol::discovery::build_spdp(data, &mut buf).expect("build");
                buf.truncate(len);
                buf
            };
            assert_eq!(wire(&immediate), wire(&periodic), "one sample");
            let parsed = parse_spdp(&wire(&immediate)).expect("parse");
            assert_eq!(parsed.domain_id, domain.id(), "the transport's domain");
            assert_eq!(
                !parsed.default_multicast_locators.is_empty(),
                multicast,
                "unicast only: {unicast_only}"
            );
        }
    }

    /// The immediate reply is numbered from the participant's SPDP writer
    /// counter, the one its announcer numbers with: a reply numbered from a
    /// process-wide count went back below the participant's announcements.
    #[test]
    fn the_immediate_spdp_takes_the_participants_next_sn() {
        let domain = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(domain.id(), 0).expect("mapping");
        let transport = Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("transport"));
        let capture = crate::test_support::ports::bind_capture_socket();
        capture
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        let tokens = SpdpSecurityTokens::default();
        tokens.sequence().store(42, Ordering::Relaxed);
        send_immediate_spdp_unicast(
            &[0x42; 12],
            &[0x43; 12],
            &[capture.local_addr().expect("addr")],
            &transport,
            mapping,
            600_000,
            crate::protocol::group::LOCAL_CAPABILITIES,
            "test",
            &tokens,
        );
        let mut buf = [0u8; 2048];
        let n = capture.recv(&mut buf).expect("the reply");
        // The DATA submessage after the 20-octet header, INFO_DST (16) and
        // INFO_TS (12): writerSN at octets 16..24 of the submessage.
        let data = 20 + 16 + 12;
        assert_eq!(buf[data], 0x15, "a DATA: {:02x?}", &buf[..n.min(64)]);
        let le = buf[data + 1] & 1 == 1;
        let word = |at: usize| {
            let b: [u8; 4] = buf[at..at + 4].try_into().expect("4");
            u64::from(if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            })
        };
        let sn = (word(data + 16) << 32) | word(data + 20);
        assert_eq!(sn, 42, "the participant's next SPDP SN");
        assert_eq!(tokens.sequence().load(Ordering::Relaxed), 43, "taken");
    }

    /// The immediate SPDP carries the participant's capabilities, as its
    /// periodic announcement does: the peer decides the participant's GROUP
    /// dialect from the first SPDP it gets, often this one.
    #[test]
    fn the_immediate_spdp_carries_the_participants_capabilities() {
        for caps in [0, crate::protocol::group::CAP_SPEC_GROUP_COHERENT] {
            let data = build_immediate_spdp_data(
                &[0x42; 12],
                &announced(
                    &["127.0.0.1:7410".parse().expect("valid")],
                    &["127.0.0.1:7411".parse().expect("valid")],
                ),
                600_000,
                caps,
                &SpdpSecurityTokens::default(),
            );
            let mut wire = vec![0u8; 2048];
            let len = crate::protocol::discovery::build_spdp(&data, &mut wire).expect("build");
            let parsed = parse_spdp(&wire[..len]).expect("parse");
            assert_eq!(parsed.hdds_capabilities, Some(caps));
        }
    }

    #[test]
    fn immediate_spdp_uses_configured_lease_on_wire() {
        let prefix = [0x42; 12];
        let data = build_immediate_spdp_data(
            &prefix,
            &announced(
                &["127.0.0.1:7410".parse().unwrap()],
                &["127.0.0.1:7411".parse().unwrap()],
            ),
            600_000,
            crate::protocol::group::LOCAL_CAPABILITIES,
            &SpdpSecurityTokens::default(),
        );
        let mut wire = vec![0u8; 2048];
        let len = crate::protocol::discovery::build_spdp(&data, &mut wire).unwrap();
        let parsed = parse_spdp(&wire[..len]).unwrap();

        assert_eq!(parsed.lease_duration_ms, 600_000);
    }

    #[test]
    fn completed_sedp_retry_on_one_domain_does_not_block_another_domain() {
        let first_domain = discovery_peer_key(0x12, 41_050);
        let second_domain =
            DiscoveryPeerKey::new(first_domain.local_prefix, 41_300, first_domain.peer_prefix);

        drop(RetryGuard::try_acquire(first_domain).expect("first domain must acquire retry"));
        assert!(
            RetryGuard::try_acquire(first_domain).is_none(),
            "completed retries must remain deduplicated inside one discovery path"
        );
        assert!(
            RetryGuard::try_acquire(second_domain).is_some(),
            "the same participant prefixes on another DDS domain need their own retry cycle"
        );
    }

    /// Return once the re-announcement thread of a replay test has ended.
    ///
    /// That thread holds the other clone of `transport`, bound to its
    /// domain's participant-0 ports, for its five rounds (about 2.5 s): a test
    /// that returned before it would release its domain lease while those
    /// ports are still bound, and the next test to lease the same domain
    /// would find them taken.
    fn wait_for_the_rounds_to_end(transport: Arc<UdpTransport>) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while Arc::strong_count(&transport) > 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            Arc::strong_count(&transport),
            1,
            "the re-announcement thread still holds the transport"
        );
    }

    /// A participant discovered after one of our endpoints was deleted is
    /// replayed the history as it is now (RTPS v2.5 Sec.8.5.4.4): a GAP for
    /// the deleted endpoint's announcement, its dispose at N+1, the
    /// announcement of the endpoint that exists. Never the announcement of
    /// the deleted one.
    #[test]
    fn a_replay_after_a_deletion_sends_a_gap_and_the_dispose() {
        use crate::protocol::discovery::SedpData;
        use crate::test_support::domains::unique_domain;

        const OURS: [u8; 12] = [0x01, 0x1a, 0x7a, 0x7a, 0x7a, 0x7a, 0, 0, 0x22, 0x01, 0, 1];
        const PEER: [u8; 12] = [0x01, 0x1a, 0x7b, 0x7b, 0x7b, 0x7b, 0, 0, 0x22, 0x02, 0, 2];
        let deleted = GUID::new(OURS, [0x00, 0x00, 0x01, 0x03]);
        let alive = GUID::new(OURS, [0x00, 0x00, 0x02, 0x03]);
        let announcement = |endpoint: GUID| SedpData {
            topic_name: "Y22Replay".to_string(),
            type_name: "Y22Type".to_string(),
            participant_guid: GUID::new(OURS, [0, 0, 1, 0xC1]),
            endpoint_guid: endpoint,
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
        };
        let history: SedpAnnouncementsCache = Arc::new(std::sync::RwLock::new(
            crate::core::discovery::multicast::SedpHistory::new(),
        ));
        {
            let mut h = history.write().expect("history");
            h.announce(announcement(deleted), SedpEndpointKind::Writer);
            h.announce(announcement(alive), SedpEndpointKind::Writer);
            assert_eq!(h.retire(&deleted, SedpEndpointKind::Writer), Some(3));
        }

        let domain = unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("set timeout");
        let peer = SpdpData {
            participant_guid: GUID::new(PEER, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![listener.local_addr().expect("addr")],
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
        send_sedp_reannouncements_with_prealloc(
            &peer,
            &OURS,
            &PEER,
            mapping.metatraffic_unicast,
            Arc::clone(&transport),
            &history,
            preallocate_sedp_sequence_numbers(&history),
            "[test]",
            Dialect::Hdds,
            &DiscoveryFsm::new(GUID::zero(), 100_000),
            #[cfg(feature = "security")]
            None,
        );

        // The first round goes out at once; the next one 500 ms later, after
        // this read has timed out. A HEARTBEAT is recorded as (0x07, firstSN,
        // lastSN).
        let mut seen: Vec<(u8, u64, u64)> = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(len) = listener.recv(&mut buf) {
            let dgram = &buf[..len];
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                dgram,
                |sub| {
                    let body = sub.offset + 4;
                    let sn = |at: usize| {
                        u64::from(u32::from_le_bytes(
                            dgram[at + 4..at + 8].try_into().expect("four octets"),
                        ))
                    };
                    match sub.id {
                        0x15 => seen.push((sub.id, u64::from(sub.flags & 0x0c), sn(body + 12))),
                        0x08 => seen.push((sub.id, 0, sn(body + 8))),
                        0x07 => seen.push((sub.id, sn(body + 8), sn(body + 16))),
                        _ => {}
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
        }
        forget_local_participant(OURS);
        wait_for_the_rounds_to_end(transport);
        assert_eq!(
            seen,
            vec![
                (0x08, 0, 1),
                (0x07, 2, 1),
                (0x15, 0x04, 2),
                (0x07, 2, 2),
                (0x15, 0x08, 3),
                (0x07, 2, 3)
            ],
            "GAP 1, the announcement (D) at 2, the dispose (K) at 3, each with a HEARTBEAT \
             from 2, the first change not superseded (after the GAP: 2..1, RTPS v2.5 \
             Sec.8.3.8.6 Example 4)"
        );
    }

    /// The SEDP an HDDS 1.4.x participant (HDDS vendor, no
    /// PID_HDDS_CAPABILITIES in its SPDP) is sent leaves PID_TYPE_OBJECT
    /// (0x0072) out and keeps PID_TYPE_INFORMATION (0x0075): its matcher
    /// would read our string TypeIdentifiers as incompatible with its own
    /// and drop every sample. A participant announcing the PID is sent both.
    /// Read from the datagrams on the wire.
    #[cfg(feature = "xtypes")]
    #[test]
    fn a_1_4_peer_is_not_sent_the_type_object() {
        use crate::protocol::discovery::SedpData;
        use crate::test_support::domains::unique_domain;
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
            TypeIdentifier,
        };

        const OURS: [u8; 12] = [0x01, 0x1a, 0x7c, 0x7c, 0x7c, 0x7c, 0, 0, 0x22, 0x01, 0, 1];
        /// The PIDs of every SEDP DATA in `dgram` (PL_CDR_LE payloads).
        fn pids(dgram: &[u8]) -> Vec<u16> {
            let mut out = Vec::new();
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                dgram,
                |sub| {
                    if sub.id == 0x15 {
                        let body = sub.offset + 4;
                        let to_inline =
                            usize::from(u16::from_le_bytes([dgram[body + 2], dgram[body + 3]]));
                        let mut p = body + 4 + to_inline + 4;
                        while p + 4 <= sub.body_end {
                            let pid = u16::from_le_bytes([dgram[p], dgram[p + 1]]);
                            let len = usize::from(u16::from_le_bytes([dgram[p + 2], dgram[p + 3]]));
                            if pid == 0x0001 {
                                break;
                            }
                            out.push(pid);
                            p += 4 + len;
                        }
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
            out
        }
        let type_object = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("ZoneT"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag(
                        MemberFlag::IS_KEY.0
                            | MemberFlag::IS_MUST_UNDERSTAND.0
                            | MemberFlag::TRY_CONSTRUCT1.0,
                    ),
                    member_type_id: TypeIdentifier::string(128),
                },
                detail: CompleteMemberDetail::new("color"),
            }],
        });
        let sent_to = |peer: [u8; 12], announced: &[Option<u32>]| -> Vec<u16> {
            let history: SedpAnnouncementsCache = Arc::new(std::sync::RwLock::new(
                crate::core::discovery::multicast::SedpHistory::new(),
            ));
            history.write().expect("history").announce(
                SedpData {
                    topic_name: "ZoneTopic".to_string(),
                    type_name: "ZoneT".to_string(),
                    participant_guid: GUID::new(OURS, [0, 0, 1, 0xC1]),
                    endpoint_guid: GUID::new(OURS, [0x00, 0x00, 0x01, 0x02]),
                    qos_hash: 0,
                    qos: None,
                    type_object: Some(type_object.clone()),
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
                SedpEndpointKind::Writer,
            );
            let domain = unique_domain();
            let mapping =
                crate::transport::PortMapping::calculate(domain.id(), 0).expect("port mapping");
            let transport =
                Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
            let listener = crate::test_support::ports::bind_capture_socket();
            listener
                .set_read_timeout(Some(Duration::from_millis(300)))
                .expect("set timeout");
            let spdp = |caps: Option<u32>| SpdpData {
                participant_guid: GUID::new(peer, [0, 0, 1, 0xC1]),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![listener.local_addr().expect("addr")],
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None,
                permissions_token: None,
                participant_security_info: None,
                vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
                hdds_capabilities: caps,
                builtin_endpoint_set: None,
            };
            // Discovery admits each SPDP in turn; the re-announcement answers
            // the last one, as the SPDP handler does after `admit_spdp`.
            let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
            for caps in announced {
                fsm.handle_spdp(spdp(*caps));
            }
            let last = spdp(*announced.last().expect("one SPDP"));
            send_sedp_reannouncements_with_prealloc(
                &last,
                &OURS,
                &peer,
                mapping.metatraffic_unicast,
                Arc::clone(&transport),
                &history,
                preallocate_sedp_sequence_numbers(&history),
                "[test]",
                Dialect::Hybrid,
                &fsm,
                #[cfg(feature = "security")]
                None,
            );
            let mut seen = Vec::new();
            let mut buf = [0u8; 8192];
            if let Ok(len) = listener.recv(&mut buf) {
                seen = pids(&buf[..len]);
            }
            forget_local_participant(OURS);
            wait_for_the_rounds_to_end(transport);
            seen
        };

        use crate::protocol::group::{CAP_SPEC_GROUP_COHERENT, LOCAL_CAPABILITIES};
        let peer = |n: u8| [0x01, 0x1a, n, n, n, n, 0, 0, 0x22, n, 0, n];
        let old = sent_to(peer(0x7d), &[None]);
        assert!(old.contains(&0x0075), "{old:04x?}");
        assert!(
            !old.contains(&0x0072),
            "1.4.x is sent PID_TYPE_OBJECT: {old:04x?}"
        );
        let no_bit = sent_to(peer(0x7f), &[Some(CAP_SPEC_GROUP_COHERENT)]);
        assert!(no_bit.contains(&0x0075), "{no_bit:04x?}");
        assert!(
            !no_bit.contains(&0x0072),
            "capabilities without the bit: {no_bit:04x?}"
        );
        let new = sent_to(peer(0x7e), &[Some(LOCAL_CAPABILITIES)]);
        assert!(new.contains(&0x0075), "{new:04x?}");
        assert!(new.contains(&0x0072), "{new:04x?}");
        // An SPDP of the same peer without the capabilities (a partial parse,
        // a re-announcement's copy) answered after one with them: discovery
        // kept them, and the re-announcement is read from discovery, so it
        // still carries the PID, as a repair to the same peer does.
        let later = sent_to(peer(0x7c), &[Some(LOCAL_CAPABILITIES), None]);
        assert!(
            later.contains(&0x0072),
            "read from the datagram: {later:04x?}"
        );
    }

    /// A participant's SEDP history holding one writer's announcement, a
    /// transport, and a capture socket standing for a peer known by `peer`,
    /// for the retry rounds' tests. The domain lease is returned to be held.
    fn retry_fixture(
        ours: [u8; 12],
        peer: [u8; 12],
    ) -> (
        SedpAnnouncementsCache,
        Arc<UdpTransport>,
        crate::transport::PortMapping,
        std::net::UdpSocket,
        SpdpData,
        crate::test_support::domains::DomainLease,
    ) {
        let history: SedpAnnouncementsCache = Arc::new(std::sync::RwLock::new(
            crate::core::discovery::multicast::SedpHistory::new(),
        ));
        history.write().expect("history").announce(
            crate::protocol::discovery::SedpData {
                topic_name: "RetryAfterFarewell".to_string(),
                type_name: "RetryType".to_string(),
                participant_guid: GUID::new(ours, [0, 0, 1, 0xC1]),
                endpoint_guid: GUID::new(ours, [0x00, 0x00, 0x01, 0x03]),
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
            SedpEndpointKind::Writer,
        );
        let domain = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set timeout");
        let announcement = SpdpData {
            participant_guid: GUID::new(peer, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![listener.local_addr().expect("addr")],
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
        (history, transport, mapping, listener, announcement, domain)
    }

    /// The datagrams `listener` receives until `window` has passed.
    fn datagrams_within(listener: &std::net::UdpSocket, window: Duration) -> usize {
        let deadline = std::time::Instant::now() + window;
        let mut buf = [0u8; 4096];
        let mut count = 0;
        while std::time::Instant::now() < deadline {
            if listener.recv(&mut buf).is_ok() {
                count += 1;
            }
        }
        count
    }

    /// A retry round that comes due after the participant's farewell sends
    /// nothing. The participant closes its SEDP history before its SPDP
    /// dispose (`Drop for Participant`); the retry thread, joined by nobody,
    /// read the history again only for its numbers and sent its next rounds
    /// anyway, so a peer that had just removed the participant on its
    /// farewell was announced its endpoints again.
    #[test]
    fn a_retry_that_comes_due_after_the_farewell_sends_nothing() {
        const OURS: [u8; 12] = [0x01, 0x1a, 0x7e, 0x7e, 0x7e, 0x7e, 0, 0, 0x22, 0x05, 0, 5];
        const PEER: [u8; 12] = [0x01, 0x1a, 0x7f, 0x7f, 0x7f, 0x7f, 0, 0, 0x22, 0x06, 0, 6];
        let (history, transport, mapping, listener, peer, _domain) = retry_fixture(OURS, PEER);
        send_sedp_reannouncements_with_prealloc(
            &peer,
            &OURS,
            &PEER,
            mapping.metatraffic_unicast,
            Arc::clone(&transport),
            &history,
            preallocate_sedp_sequence_numbers(&history),
            "[test]",
            Dialect::Hdds,
            &DiscoveryFsm::new(GUID::zero(), 100_000),
            #[cfg(feature = "security")]
            None,
        );
        let first_round = datagrams_within(&listener, Duration::from_millis(200));
        history.write().expect("history").close();
        // The next two rounds would come 500 ms and 1 s after the first.
        let after_the_farewell = datagrams_within(&listener, Duration::from_millis(1_300));
        // Its last round would be due 2 s after the first: a thread still
        // waiting for it holds the transport.
        let thread_ended = Arc::strong_count(&transport) == 1;
        forget_local_participant(OURS);
        wait_for_the_rounds_to_end(transport);
        assert_eq!(first_round, 1, "fixture: the first round went out at once");
        assert_eq!(after_the_farewell, 0, "no retry round after the farewell");
        assert!(thread_ended, "the retry thread ended at the farewell");
    }

    /// A retry thread waiting for its next round ends on the close of the
    /// history at once, and is joined (`RetryRounds::join_all`): nothing of
    /// it holds the transport, nor re-enters the dedup maps, once the join
    /// returns. Detached, it slept on for up to its 50 ms slice, holding the
    /// transport, and its guard inserted its key into `COMPLETED_PEERS`
    /// after the participant had forgotten its entries.
    #[test]
    fn a_retry_thread_is_woken_and_joined_at_the_close() {
        const OURS: [u8; 12] = [0x01, 0x1a, 0x82, 0x82, 0x82, 0x82, 0, 0, 0x22, 0x09, 0, 9];
        const PEER: [u8; 12] = [0x01, 0x1a, 0x83, 0x83, 0x83, 0x83, 0, 0, 0x22, 0x0a, 0, 10];
        let (history, transport, mapping, listener, peer, _domain) = retry_fixture(OURS, PEER);
        send_sedp_reannouncements_with_prealloc(
            &peer,
            &OURS,
            &PEER,
            mapping.metatraffic_unicast,
            Arc::clone(&transport),
            &history,
            preallocate_sedp_sequence_numbers(&history),
            "[test]",
            Dialect::Hdds,
            &DiscoveryFsm::new(GUID::zero(), 100_000),
            #[cfg(feature = "security")]
            None,
        );
        let first_round = datagrams_within(&listener, Duration::from_millis(150));
        let rounds = history.read().expect("history").retry_rounds();
        assert_eq!(rounds.tracked(), 1, "fixture: the retry thread is tracked");
        let rounds = {
            let mut h = history.write().expect("history");
            h.close();
            h.retry_rounds()
        };
        let started = std::time::Instant::now();
        rounds.join_all();
        let joined_in = started.elapsed();
        let transport_held = Arc::strong_count(&transport) > 1;
        forget_local_participant(OURS);
        let key = DiscoveryPeerKey::new(OURS, mapping.metatraffic_unicast, PEER);
        std::thread::sleep(Duration::from_millis(80));
        let reentered = completed_peers().lock().expect("map").contains(&key);
        assert_eq!(first_round, 1, "fixture: the first round went out at once");
        assert!(
            !transport_held,
            "the joined retry thread still holds the transport"
        );
        assert!(
            !reentered,
            "the retry thread re-entered the dedup maps after its participant forgot them"
        );
        assert!(
            joined_in < Duration::from_millis(200),
            "the close did not wake the retry thread (joined in {joined_in:?})"
        );
    }

    /// The first round's numbers are read before the retry thread starts: a
    /// farewell between that read and the thread's first send stops that
    /// round too.
    #[test]
    fn a_retry_started_after_the_farewell_sends_nothing() {
        const OURS: [u8; 12] = [0x01, 0x1a, 0x80, 0x80, 0x80, 0x80, 0, 0, 0x22, 0x07, 0, 7];
        const PEER: [u8; 12] = [0x01, 0x1a, 0x81, 0x81, 0x81, 0x81, 0, 0, 0x22, 0x08, 0, 8];
        let (history, transport, mapping, listener, peer, _domain) = retry_fixture(OURS, PEER);
        let first_round = preallocate_sedp_sequence_numbers(&history);
        assert_eq!(first_round.len(), 1, "fixture: one announcement to send");
        history.write().expect("history").close();
        send_sedp_reannouncements_with_prealloc(
            &peer,
            &OURS,
            &PEER,
            mapping.metatraffic_unicast,
            Arc::clone(&transport),
            &history,
            first_round,
            "[test]",
            Dialect::Hdds,
            &DiscoveryFsm::new(GUID::zero(), 100_000),
            #[cfg(feature = "security")]
            None,
        );
        let sent = datagrams_within(&listener, Duration::from_millis(800));
        forget_local_participant(OURS);
        wait_for_the_rounds_to_end(transport);
        assert_eq!(sent, 0, "nothing goes out after the farewell");
    }

    /// Under a peer's metatraffic key the announcements and the disposes of
    /// a replay are protected; the GAP that retires deleted announcements is
    /// sent as is, in the plaintext writer's namespace, covering its whole
    /// range (a GAP carries no endpoint data, and protecting it is not
    /// possible: there is no serialized payload to encrypt).
    #[test]
    #[cfg(feature = "security")]
    fn a_protected_replay_sends_its_gap_in_the_clear() {
        use crate::protocol::discovery::SedpData;
        use crate::test_support::domains::unique_domain;

        const OURS: [u8; 12] = [0x01, 0x1a, 0x7c, 0x7c, 0x7c, 0x7c, 0, 0, 0x22, 0x03, 0, 3];
        const PEER: [u8; 12] = [0x01, 0x1a, 0x7d, 0x7d, 0x7d, 0x7d, 0, 0, 0x22, 0x04, 0, 4];
        let endpoint = |n: u8| GUID::new(OURS, [0x00, 0x00, n, 0x03]);
        let history: SedpAnnouncementsCache = Arc::new(std::sync::RwLock::new(
            crate::core::discovery::multicast::SedpHistory::new(),
        ));
        {
            let mut h = history.write().expect("history");
            for n in 1..=3 {
                h.announce(
                    SedpData {
                        topic_name: "Y22SecureReplay".to_string(),
                        type_name: "Y22Type".to_string(),
                        participant_guid: GUID::new(OURS, [0, 0, 1, 0xC1]),
                        endpoint_guid: endpoint(n),
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
                    SedpEndpointKind::Writer,
                );
            }
            h.retire(&endpoint(1), SedpEndpointKind::Writer);
            h.retire(&endpoint(2), SedpEndpointKind::Writer);
        }

        let domain = unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("set timeout");
        let peer = SpdpData {
            participant_guid: GUID::new(PEER, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![listener.local_addr().expect("addr")],
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
        send_sedp_reannouncements_with_prealloc(
            &peer,
            &OURS,
            &PEER,
            mapping.metatraffic_unicast,
            Arc::clone(&transport),
            &history,
            preallocate_sedp_sequence_numbers(&history),
            "[test]",
            Dialect::Hdds,
            &DiscoveryFsm::new(GUID::zero(), 100_000),
            Some(crate::security::crypto::secure_sedp::test_writer_keys(
                0x5c,
                crate::security::crypto::secure_submessage::Transformation::Aes256Gcm,
            )),
        );
        let our_writers = crate::security::crypto::secure_sedp::test_writer_keys(
            0x5c,
            crate::security::crypto::secure_submessage::Transformation::Aes256Gcm,
        );

        // (id, writerId, gapStart or writerSN, gapList.base)
        let mut seen: Vec<(u8, [u8; 4], u64, u64)> = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(len) = listener.recv(&mut buf) {
            let dgram = &buf[..len];
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                dgram,
                |sub| {
                    let body = sub.offset + 4;
                    let sn = |at: usize| {
                        u64::from(u32::from_le_bytes(
                            dgram[at + 4..at + 8].try_into().expect("four octets"),
                        ))
                    };
                    let id = |at: usize| -> [u8; 4] {
                        dgram[at..at + 4].try_into().expect("four octets")
                    };
                    match sub.id {
                        0x15 => seen.push((sub.id, id(body + 8), sn(body + 12), 0)),
                        0x08 => seen.push((sub.id, id(body + 4), sn(body + 8), sn(body + 16))),
                        // A protected submessage: the DATA it protects, read
                        // with the key material of our secure SEDP writer.
                        0x31 => {
                            let inner =
                                crate::security::crypto::secure_submessage::decode_datawriter_submessage(
                                    &our_writers.publications,
                                    dgram,
                                    sub.offset,
                                )
                                .expect("it decodes")
                                .submessage;
                            let low = u32::from_le_bytes(inner[20..24].try_into().expect("four"));
                            seen.push((
                                inner[0],
                                inner[12..16].try_into().expect("four octets"),
                                u64::from(low),
                                0,
                            ));
                        }
                        _ => {}
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
        }
        forget_local_participant(OURS);
        wait_for_the_rounds_to_end(transport);
        const PLAIN: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];
        const SECURE: [u8; 4] = [0xff, 0x00, 0x03, 0xC2];
        assert_eq!(
            seen,
            vec![
                (0x08, PLAIN, 1, 3),
                (0x15, SECURE, 3, 0),
                (0x15, SECURE, 4, 0),
                (0x15, SECURE, 5, 0),
            ],
            "one clear GAP over 1..2, then the announcement and both disposes, protected"
        );
    }

    /// An endpoint deleted while a peer's re-announcement rounds are still
    /// running is not announced again in the later rounds: they read the
    /// history again and send the GAP and the dispose (RTPS v2.5
    /// Sec.8.5.4.4). A round sending the old announcement after the dispose
    /// went out would bring the endpoint back at a receiver that applies SEDP
    /// in arrival order.
    #[test]
    fn a_later_round_sends_what_the_history_says_now() {
        use crate::protocol::discovery::SedpData;
        use crate::test_support::domains::unique_domain;

        const OURS: [u8; 12] = [0x01, 0x1a, 0x7e, 0x7e, 0x7e, 0x7e, 0, 0, 0x22, 0x05, 0, 5];
        const PEER: [u8; 12] = [0x01, 0x1a, 0x7f, 0x7f, 0x7f, 0x7f, 0, 0, 0x22, 0x06, 0, 6];
        let endpoint = GUID::new(OURS, [0x00, 0x00, 0x01, 0x07]);
        let history: SedpAnnouncementsCache = Arc::new(std::sync::RwLock::new(
            crate::core::discovery::multicast::SedpHistory::new(),
        ));
        history.write().expect("history").announce(
            SedpData {
                topic_name: "Y22Rounds".to_string(),
                type_name: "Y22Type".to_string(),
                participant_guid: GUID::new(OURS, [0, 0, 1, 0xC1]),
                endpoint_guid: endpoint,
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
            SedpEndpointKind::Reader,
        );

        let domain = unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("set timeout");
        let peer = SpdpData {
            participant_guid: GUID::new(PEER, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![listener.local_addr().expect("addr")],
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
        send_sedp_reannouncements_with_prealloc(
            &peer,
            &OURS,
            &PEER,
            mapping.metatraffic_unicast,
            Arc::clone(&transport),
            &history,
            preallocate_sedp_sequence_numbers(&history),
            "[test]",
            Dialect::Hdds,
            &DiscoveryFsm::new(GUID::zero(), 100_000),
            #[cfg(feature = "security")]
            None,
        );

        // (id, D/K flags, writerSN or gapStart) of what a round carried.
        let read_round = || {
            let mut seen: Vec<(u8, u8, u64)> = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(len) = listener.recv(&mut buf) {
                let dgram = &buf[..len];
                crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                    dgram,
                    |sub| {
                        let body = sub.offset + 4;
                        let sn = |at: usize| {
                            u64::from(u32::from_le_bytes(
                                dgram[at + 4..at + 8].try_into().expect("four octets"),
                            ))
                        };
                        match sub.id {
                            0x15 => seen.push((sub.id, sub.flags & 0x0c, sn(body + 12))),
                            0x08 => seen.push((sub.id, 0, sn(body + 8))),
                            _ => {}
                        }
                        crate::core::discovery::multicast::classifier::walk::Step::Continue
                    },
                );
            }
            seen
        };
        assert_eq!(
            read_round(),
            vec![(0x15, 0x04, 1)],
            "round one: the announcement"
        );
        assert_eq!(
            history
                .write()
                .expect("history")
                .retire(&endpoint, SedpEndpointKind::Reader),
            Some(2)
        );
        // Every later round, until the rounds stop.
        let mut later = Vec::new();
        for _ in 0..12 {
            later.extend(read_round());
        }
        forget_local_participant(OURS);
        wait_for_the_rounds_to_end(transport);
        assert!(!later.is_empty(), "the later rounds went out");
        assert!(
            later
                .chunks(2)
                .all(|round| round == [(0x08, 0, 1), (0x15, 0x08, 2)]),
            "each later round: GAP 1, the dispose (K) at 2; never the announcement: {later:?}"
        );
    }
}
