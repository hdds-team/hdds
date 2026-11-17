// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TypeLookup handler -- two independent code paths:
//!
//! 1. HTLK (HDDS-only proprietary, `type-lookup` feature) -- only active when NOT
//!    in interop mode. Uses PL_CDR2_LE (0x000B) encapsulation + `HTLK` magic.
//!
//! 2. OMG getTypes (`xtypes-structural-assignability` feature) -- always active
//!    even in interop mode, both directions:
//!    - SERVE: parse an OMG-standard PLAIN_CDR2_LE (0x0007) getTypes request
//!      and send the matching TypeObject pairs back to the requester.
//!    - REQUEST: when a peer's SEDP carries `PID_TYPE_INFORMATION` but no
//!      inline TypeObject, ask that peer for the COMPLETE TypeObject and feed
//!      the answer to `DiscoveryFsm::update_type_object_for_hash`, which is
//!      what lets the structural-assignability matcher work on a type whose
//!      definition never travelled in SEDP.
//!
//! The two directions are told apart by the RTPS writer entity id of the
//! carrying DATA submessage, not by the CDR: a request and a reply share the
//! same PLAIN_CDR2_LE encapsulation and the same 24-byte requestId prefix.
//!
//! Scope note: only EK_COMPLETE is requested. `update_type_object_for_hash`
//! takes a `CompleteTypeObject`, so a MinimalTypeObject would have nowhere to
//! go; a peer that publishes only a minimal TypeIdentifier is logged and
//! skipped rather than asked for something we could not store.

#[cfg(feature = "xtypes-structural-assignability")]
mod resolution;

use crate::core::discovery::multicast::{DiscoveryFsm, Origin};
use crate::transport::UdpTransport;
#[cfg(feature = "xtypes-structural-assignability")]
use std::net::SocketAddr;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Imports shared by any active path
// ---------------------------------------------------------------------------
use crate::core::discovery::multicast::directed_writer::TypeLookupWriters;
#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
use crate::core::types::TypeObjectHandle;
#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
use crate::xtypes::CompleteTypeObject;
#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
use crate::Cdr2Decode;
#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
use crate::Cdr2Encode;
#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
use parking_lot::{Mutex, RwLock};
#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// HTLK-only imports
// ---------------------------------------------------------------------------
#[cfg(feature = "type-lookup")]
use crate::protocol::discovery::constants::PL_CDR2_LE;
// The crate's ONE sequence-number split and ONE octetsToNextHeader rule, shared
// rather than copied into this file.
#[cfg(feature = "xtypes-structural-assignability")]
use crate::protocol::rtps::{octets_to_next_header_for_last_submessage, split_sequence_number};
#[cfg(feature = "type-lookup")]
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// OMG serve path imports
// ---------------------------------------------------------------------------
#[cfg(feature = "xtypes-structural-assignability")]
use crate::core::discovery::multicast::rtps_packet::rtps_time_from_unix;
#[cfg(feature = "xtypes-structural-assignability")]
use crate::core::rtps_constants::{
    HDDS_VENDOR_ID, RTPS_ENTITYID_TYPELOOKUP_REPLY_READER, RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
    RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER, RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
    RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR,
};
#[cfg(feature = "xtypes-structural-assignability")]
use crate::protocol::discovery::types::TypeInformation;
#[cfg(feature = "xtypes-structural-assignability")]
use crate::xtypes::EquivalenceHash;
#[cfg(feature = "xtypes-structural-assignability")]
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// HTLK constants (type-lookup only)
// ---------------------------------------------------------------------------
#[cfg(feature = "type-lookup")]
const TYPE_LOOKUP_MAGIC: [u8; 4] = *b"HTLK";
#[cfg(feature = "type-lookup")]
const TYPE_LOOKUP_VERSION: u8 = 1;
#[cfg(feature = "type-lookup")]
const TYPE_LOOKUP_KIND_REQUEST: u8 = 1;
#[cfg(feature = "type-lookup")]
const TYPE_LOOKUP_KIND_RESPONSE: u8 = 2;

// ---------------------------------------------------------------------------
// OMG getTypes wire constants (xtypes-structural-assignability only)
// ---------------------------------------------------------------------------

/// OMG TypeLookup_getTypes operation discriminant.
#[cfg(feature = "xtypes-structural-assignability")]
const GETTYPES_OP_DISC: u32 = 0x0182_52d3;

/// `GETTYPES_OP_DISC` as the in-memory LE bytes the encoders splice in.
#[cfg(feature = "xtypes-structural-assignability")]
const GETTYPES_OP_DISC_LE: [u8; 4] = GETTYPES_OP_DISC.to_le_bytes();

/// EMHEADER for MUTABLE 'types' member (LC=5, id = MD5("types")[0:4] & 0x0FFFFFFF).
/// In-memory LE bytes for u32 0x52804ad1.
#[cfg(feature = "xtypes-structural-assignability")]
const EMHDR_TYPES_LE: [u8; 4] = [0xd1, 0x4a, 0x80, 0x52];

/// EMHEADER for MUTABLE 'complete_to_minimal' member (LC=5).
/// In-memory LE bytes for u32 0x5b8e6577.
#[cfg(feature = "xtypes-structural-assignability")]
const EMHDR_C2M_LE: [u8; 4] = [0x77, 0x65, 0x8e, 0x5b];

/// Member id of 'types' in getTypes_Out -- `EMHDR_TYPES_LE` without the LC
/// nibble. Used on RX to pick the right MUTABLE member out of a reply.
#[cfg(feature = "xtypes-structural-assignability")]
const MEMBER_ID_TYPES: u32 = 0x0280_4AD1;

/// EMHEADER for the MUTABLE 'type_ids' member of getTypes_In (LC=5).
///
/// Member ids are `u32::from_le_bytes(MD5(member_name)[0..4]) & 0x0FFFFFFF`
/// per DDS-XTypes v1.3 sec. 7.3.1.2.1 -- note the LITTLE-endian read of the MD5
/// prefix, which is what reproduces the two ids already on the reply path
/// ('types' -> 0x02804AD1, 'complete_to_minimal' -> 0x0B8E6577). Here
/// MD5("type_ids")[0..4] = 65 60 53 6c -> id 0x0C536065 -> EMHEADER
/// 0x5C536065. In-memory LE bytes below.
#[cfg(feature = "xtypes-structural-assignability")]
const EMHDR_TYPE_IDS_LE: [u8; 4] = [0x65, 0x60, 0x53, 0x5c];

/// A getTypes request whose reply has not arrived within this window is
/// forgotten, so the next SEDP announcement for the same still-unresolved
/// type re-asks instead of waiting forever on a lost datagram.
#[cfg(feature = "xtypes-structural-assignability")]
const GETTYPES_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a root type waits for its member types before it is judged on
/// what is known (`release_or_wait_at`): three request timeouts, so a lost
/// dependency request is retried before the wait ends.
#[cfg(feature = "xtypes-structural-assignability")]
const AWAIT_DEPENDENCIES_BOUND: Duration = Duration::from_secs(15);

/// Roots held at once; a root arriving when full is released at once.
#[cfg(feature = "xtypes-structural-assignability")]
const MAX_AWAITING_ROOTS: usize = 128;

/// Sends of one endpoint's getTypes request before it is given up on.
#[cfg(feature = "xtypes-structural-assignability")]
const MAX_REQUEST_ATTEMPTS: u8 = 5;

/// Period of the TypeLookup tick (`TypeLookupService::tick_at`).
#[cfg(feature = "xtypes-structural-assignability")]
const TYPE_LOOKUP_TICK: Duration = Duration::from_millis(100);

/// Period of the TypeLookup writers' HEARTBEATs (RTPS 2.5 8.4.2.2.3).
#[cfg(feature = "xtypes-structural-assignability")]
const HEARTBEAT_PERIOD: Duration = Duration::from_secs(1);

/// EK_MINIMAL discriminant byte in TypeIdentifier / TypeObject union.
#[cfg(feature = "xtypes-structural-assignability")]
const EK_MINIMAL: u8 = 0xf1;

/// EK_COMPLETE discriminant byte in TypeIdentifier / TypeObject union.
#[cfg(feature = "xtypes-structural-assignability")]
const EK_COMPLETE: u8 = 0xf2;

// ---------------------------------------------------------------------------
// HTLK error / message types
// ---------------------------------------------------------------------------

#[cfg(feature = "type-lookup")]
#[derive(Debug)]
#[allow(dead_code)]
enum TypeLookupError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidKind(u8),
    InvalidUtf8,
}

#[cfg(feature = "type-lookup")]
#[derive(Debug)]
struct TypeLookupMessage {
    kind: u8,
    type_name: String,
    type_object: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// TypeLookupConfig
// ---------------------------------------------------------------------------

#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
pub(in crate::dds::participant::builder) struct TypeLookupConfig {
    pub registered_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    /// Types the participant can SERVE but never announces (see
    /// `Participant::register_served_type`); consulted by both responders
    /// alongside `registered_types`, never by SEDP announcement.
    pub served_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    #[cfg(feature = "type-lookup")]
    pub dialect_detector:
        Arc<std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>>,
}

#[cfg(not(any(feature = "type-lookup", feature = "xtypes-structural-assignability")))]
pub(in crate::dds::participant::builder) struct TypeLookupConfig;

// ---------------------------------------------------------------------------
// TypeLookupService
// ---------------------------------------------------------------------------

#[cfg(feature = "xtypes-structural-assignability")]
type TypeRequestKey = ([u8; 12], [u8; 14]);

#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
pub(in crate::dds::participant) struct TypeLookupService {
    fsm: Arc<DiscoveryFsm>,
    transport: Arc<UdpTransport>,
    our_guid_prefix: [u8; 12],
    registered_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    served_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    /// The request writer and the reply writer, one sequence-number space
    /// each (RTPS 2.5 8.3.5.4, 8.3.8.2 writerSN). Shared with the
    /// ControlHandler, which answers the ACKNACKs addressed to them.
    writers: Arc<TypeLookupWriters>,
    /// In-flight OMG getTypes requests, keyed by the requested
    /// peer GUID prefix and `EquivalenceHash`. Doubles as the de-duplication set: SEDP repeats an
    /// announcement on every cadence tick, and one unresolved type must not
    /// produce one request per tick.
    #[cfg(feature = "xtypes-structural-assignability")]
    pending_requests: Mutex<HashMap<TypeRequestKey, PendingTypeRequest>>,
    /// Every verified reply, bounded with least-recently-used eviction and
    /// cleaned of what a departed participant alone served
    /// (`TypeCache`). Never a gate: the root a reply resolves is carried
    /// by `awaiting_dependencies` itself, so an evicted entry costs a
    /// re-request, never a root.
    #[cfg(feature = "xtypes-structural-assignability")]
    resolved_types: RwLock<crate::core::discovery::matcher::type_cache::TypeCache>,
    /// Types answered for an endpoint (a root) whose member types are still
    /// being looked up. A root is given to its endpoints, and so judged,
    /// only once its type graph is known, or once `AWAIT_DEPENDENCIES_BOUND`
    /// has passed (`release_or_wait_at`, driven by the periodic tick).
    #[cfg(feature = "xtypes-structural-assignability")]
    awaiting_dependencies: Mutex<HashMap<EquivalenceHash, AwaitingRoot>>,
    /// When the TypeLookup writers last sent their periodic HEARTBEATs.
    #[cfg(feature = "xtypes-structural-assignability")]
    last_heartbeat: Mutex<Option<Instant>>,
    #[cfg(feature = "type-lookup")]
    requested_types: Mutex<HashSet<String>>,
    #[cfg(feature = "type-lookup")]
    dialect_detector:
        Arc<std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>>,
    /// The periodic tick thread (`start_tick`): its stop flag and handle.
    #[cfg(feature = "xtypes-structural-assignability")]
    tick: Mutex<Option<TickThread>>,
}

/// The tick thread of a [`TypeLookupService`]: stopped and joined by
/// `stop_tick`, which the participant's drop calls, so the thread (and the
/// transport its ticks send on) does not outlive the participant.
#[cfg(feature = "xtypes-structural-assignability")]
struct TickThread {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: std::thread::JoinHandle<()>,
}

#[cfg(feature = "xtypes-structural-assignability")]
impl Drop for TypeLookupService {
    fn drop(&mut self) {
        self.stop_tick();
    }
}

/// One outstanding OMG getTypes request.
///
/// `type_name` is the name observed in SEDP for a request made on behalf of
/// an endpoint; `None` for a request no endpoint named. Only the former
/// resolves endpoints when answered (`DiscoveryFsm::update_type_object_for_hash`).
#[cfg(feature = "xtypes-structural-assignability")]
struct PendingTypeRequest {
    type_name: Option<String>,
    sequence: u64,
    sent_at: Instant,
    /// Requests sent for this key so far, the first included.
    attempts: u8,
}

/// A root type held until its member types are known.
#[cfg(feature = "xtypes-structural-assignability")]
struct AwaitingRoot {
    object: CompleteTypeObject,
    peer: [u8; 12],
    since: Instant,
}

#[cfg(not(any(feature = "type-lookup", feature = "xtypes-structural-assignability")))]
pub(in crate::dds::participant) struct TypeLookupService;

pub(in crate::dds::participant) type TypeLookupHandle = Option<Arc<TypeLookupService>>;

// ---------------------------------------------------------------------------
// TypeLookupService -- active path implementation
// ---------------------------------------------------------------------------

#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
impl TypeLookupService {
    pub(super) fn new(
        fsm: Arc<DiscoveryFsm>,
        transport: Arc<UdpTransport>,
        our_guid_prefix: [u8; 12],
        config: TypeLookupConfig,
    ) -> Self {
        Self {
            fsm,
            transport,
            our_guid_prefix,
            registered_types: config.registered_types,
            served_types: config.served_types,
            writers: Arc::new(TypeLookupWriters::new()),
            #[cfg(feature = "xtypes-structural-assignability")]
            pending_requests: Mutex::new(HashMap::new()),
            #[cfg(feature = "xtypes-structural-assignability")]
            resolved_types: RwLock::new(Default::default()),
            #[cfg(feature = "xtypes-structural-assignability")]
            awaiting_dependencies: Mutex::new(HashMap::new()),
            #[cfg(feature = "xtypes-structural-assignability")]
            last_heartbeat: Mutex::new(None),
            #[cfg(feature = "type-lookup")]
            requested_types: Mutex::new(HashSet::new()),
            #[cfg(feature = "type-lookup")]
            dialect_detector: config.dialect_detector,
            #[cfg(feature = "xtypes-structural-assignability")]
            tick: Mutex::new(None),
        }
    }

    /// The two TypeLookup writers, for the ControlHandler.
    pub(in crate::dds::participant) fn writers(&self) -> Arc<TypeLookupWriters> {
        Arc::clone(&self.writers)
    }

    #[cfg(feature = "type-lookup")]
    fn is_interop_mode(&self) -> bool {
        self.dialect_detector
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_interop_mode()
    }

    /// Dispatch an incoming TypeLookup DATA payload.
    ///
    /// Detection is based on the CDR encapsulation identifier:
    /// - 0x0007 (PLAIN_CDR2_LE) -> OMG getTypes [always served]
    /// - 0x000B (PL_CDR2_LE) + "HTLK" magic -> proprietary HTLK [type-lookup only, not interop]
    ///
    /// Within the OMG path a REQUEST and a REPLY are indistinguishable from
    /// the encapsulation alone, so the two are separated by the writer entity
    /// id of the carrying DATA submessage: 0x000300C3 is the request writer,
    /// 0x000301C3 the reply writer (DDS-XTypes v1.3 sec. 7.6.3.3.3 Table 61).
    pub(super) fn handle_packet(&self, payload: &[u8], cdr_offset: usize, origin: Origin) {
        let cdr_payload = match payload.get(cdr_offset..) {
            Some(slice) => slice,
            None => {
                log::debug!(
                    "[TL] Invalid CDR offset {} (len={})",
                    cdr_offset,
                    payload.len()
                );
                return;
            }
        };

        let writer_entity_id = crate::protocol::builder::extract_writer_guid(payload)
            .map(|guid| [guid[12], guid[13], guid[14], guid[15]]);
        self.handle_sample(
            cdr_payload,
            writer_entity_id,
            extract_peer_guid_prefix(payload),
            type_lookup_writer_sn(payload),
            origin,
        );
    }

    /// Dispatch a TypeLookup sample that is already whole.
    ///
    /// The two values this takes beyond the CDR are the only things the
    /// datagram was ever read for, and both are properties of the WRITER
    /// rather than of the carrier. Naming them here is what lets a
    /// REASSEMBLED sample take this door: a sample rebuilt from DATA_FRAGs
    /// has no RTPS header of its own to read them out of, and a TypeObject
    /// is the largest sample discovery ever carries - the fragmented form is
    /// the ordinary one here.
    ///
    /// # Arguments
    /// - `writer_entity_id`: entity id of the writer that emitted the sample.
    ///   `None` when the carrier could not be read; the OMG path then treats
    ///   the sample as a REQUEST, which is what it always did.
    /// - `peer_guid_prefix`: the sending participant, i.e. where an answer
    ///   goes. `None` disables the OMG reply path, which has nobody to
    ///   correlate against.
    pub(super) fn handle_sample(
        &self,
        cdr_payload: &[u8],
        writer_entity_id: Option<[u8; 4]>,
        peer_guid_prefix: Option<[u8; 12]>,
        writer_sn: Option<u64>,
        origin: Origin,
    ) {
        // A sample our reader already received (a peer repairing what a
        // HEARTBEAT of ours or its own NACKed) is not processed twice: a
        // request answered twice would take a second reply number.
        if let (Some(eid), Some(peer), Some(sn)) = (writer_entity_id, peer_guid_prefix, writer_sn) {
            if TypeLookupWriters::reader_for(&eid).is_some()
                && !self.writers.received.on_data(peer, eid, sn)
            {
                return;
            }
        }
        // Read only by the OMG path, to tell a request from a reply.
        #[cfg(not(feature = "xtypes-structural-assignability"))]
        let _ = writer_entity_id;

        if cdr_payload.len() < 2 {
            return;
        }

        // OMG PLAIN_CDR2_LE path -- served even in interop mode.
        // The early return below is the last statement of the function when
        // the `type-lookup` feature is off, which trips needless_return on
        // that feature combination only.
        #[allow(clippy::needless_return)]
        #[cfg(feature = "xtypes-structural-assignability")]
        if cdr_payload[0] == 0x00 && cdr_payload[1] == 0x07 {
            match writer_entity_id {
                Some(eid) if eid == RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER => {
                    self.handle_omg_get_types_reply(cdr_payload, peer_guid_prefix);
                }
                // Absent or unexpected entity id: treat as a request, which is
                // what every getTypes packet reaching this build was until the
                // requesting side existed. A reply misrouted here cannot be
                // mistaken for a request -- `parse_omg_get_types_request`
                // rejects the reply layout at the MUTABLE member walk.
                _ => self.handle_omg_get_types(cdr_payload, peer_guid_prefix, origin),
            }
            return;
        }

        // HTLK proprietary path -- only when not in interop mode.
        #[cfg(feature = "type-lookup")]
        {
            if self.is_interop_mode() {
                return;
            }
            let message = match decode_htlk_message(cdr_payload) {
                Ok(msg) => msg,
                Err(err) => {
                    log::debug!("[TL] HTLK decode failed: {:?}", err);
                    return;
                }
            };
            match message.kind {
                TYPE_LOOKUP_KIND_REQUEST => {
                    self.handle_htlk_request(&message, peer_guid_prefix, origin);
                }
                TYPE_LOOKUP_KIND_RESPONSE => {
                    self.handle_htlk_response(&message);
                }
                _ => {
                    log::debug!("[TL] Unknown HTLK kind={}", message.kind);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // OMG getTypes serve path (xtypes-structural-assignability)
    // -----------------------------------------------------------------------

    #[cfg(feature = "xtypes-structural-assignability")]
    fn handle_omg_get_types(
        &self,
        cdr_payload: &[u8],
        peer_guid_prefix: Option<[u8; 12]>,
        origin: Origin,
    ) {
        let req = match parse_omg_get_types_request(cdr_payload) {
            Some(r) => r,
            None => {
                log::debug!(
                    "[TL-OMG] Failed to parse getTypes request from {}",
                    origin.from()
                );
                return;
            }
        };

        log::debug!(
            "[TL-OMG] getTypes from {}: {} type_id(s) requested",
            origin.from(),
            req.type_ids.len()
        );

        // Look up each requested TypeObject from the local registry, then
        // from the SERVE-ONLY map (types created by an ordinary typed
        // endpoint -- see `Participant::register_served_type`).
        // Only what the requester may be told (`DiscoveryFsm::
        // type_lookup_serves`: under the security plugins, a type announced
        // on discovery-protected topics only is not handed to a participant
        // that has not authenticated).
        let pairs: Vec<(u8, [u8; 14], Arc<TypeObjectHandle>)> = {
            let registered = self.registered_types.read();
            let served = self.served_types.read();
            req.type_ids
                .iter()
                .filter_map(|&(ek, hash)| {
                    lookup_named_type_object(&registered, ek, hash)
                        .or_else(|| lookup_named_type_object(&served, ek, hash))
                        .filter(|(name, _)| {
                            self.fsm.type_lookup_serves(peer_guid_prefix.as_ref(), name)
                        })
                        .map(|(_, h)| (ek, hash, h))
                })
                .collect()
        };

        if pairs.is_empty() {
            if log::log_enabled!(log::Level::Debug) {
                let registered = self.registered_types.read();
                let served = self.served_types.read();
                for &(ek, hash) in &req.type_ids {
                    let found = lookup_named_type_object(&registered, ek, hash)
                        .or_else(|| lookup_named_type_object(&served, ek, hash));
                    log::debug!(
                        "[TL-OMG] getTypes miss: ek=0x{:02x} hash={:02x?} known={} \
                         (registered={}, served={})",
                        ek,
                        hash,
                        found
                            .as_ref()
                            .map_or("no", |_| "yes, refused by the serving policy"),
                        registered.len(),
                        served.len()
                    );
                }
            }
            log::debug!("[TL-OMG] No matching TypeObjects found; not replying");
            return;
        }

        let peer_guid_prefix = match peer_guid_prefix {
            Some(p) => p,
            None => {
                log::debug!("[TL-OMG] No peer GUID prefix for this sample; cannot address a reply");
                return;
            }
        };

        let cdr_reply = match encode_omg_get_types_reply(
            &req.request_writer_guid,
            req.request_seq_high,
            req.request_seq_low,
            &pairs,
        ) {
            Some(r) => r,
            None => {
                log::debug!("[TL-OMG] Failed to encode getTypes reply");
                return;
            }
        };

        // Resolved before a number is taken: a reply that cannot be sent
        // must not leave a hole in the reply writer's sequence.
        let Some(dest) = self.resolve_send_addr(&peer_guid_prefix, origin) else {
            log::debug!(
                "[TL-OMG] relayed origin (behind an INFO_SRC) and peer {:02x?} unknown to \
                 the FSM: no reply address, dropping",
                peer_guid_prefix
            );
            return;
        };

        // The reply writer's own number space; a number is taken only once
        // the packet exists (a refused build leaves no hole).
        let Some((_, packet)) = self
            .writers
            .reply
            .write_to(peer_guid_prefix, |our_seq, gap| {
                Some(build_omg_reply_rtps_packet(
                    &self.our_guid_prefix,
                    &peer_guid_prefix,
                    our_seq,
                    gap,
                    &req.request_writer_guid,
                    req.request_seq_high,
                    req.request_seq_low,
                    &cdr_reply,
                ))
            })
        else {
            return;
        };

        match self.transport.send_to_endpoint(&packet, &dest) {
            Ok(_) => log::debug!(
                "[TL-OMG] Sent reply ({} pairs, {} bytes) to {}",
                pairs.len(),
                packet.len(),
                dest
            ),
            Err(e) => log::debug!("[TL-OMG] Send error to {}: {}", dest, e),
        }
    }

    /// Resolve a destination for `peer_guid_prefix`: prefer the FSM's own
    /// endpoint on the same IP as `origin`'s reply address, else the FSM's
    /// first known endpoint for that prefix, else the reply address itself.
    ///
    /// RTPS 2.5 8.3.4 / 8.3.8.10: `origin.reply()` is `None` behind an
    /// INFO_SRC. The same-IP preference and the final fallback both need a
    /// real reply address, so they apply only when one exists; the FSM
    /// lookup does not (it never reads `origin`), so a peer the FSM already
    /// knows is still reachable even when relayed. A peer this participant
    /// has never seen in SPDP/SEDP, reached only through a relay, has no
    /// resolvable destination: `None`, and the caller must not send.
    ///
    /// Used only by the OMG getTypes SERVE path above, which is the one
    /// consumer of this same-IP-preference rule; the HTLK paths do not use
    /// it, and must not gain it (see
    /// `maybe_request_type_object`, `handle_htlk_request`).
    #[cfg(feature = "xtypes-structural-assignability")]
    fn resolve_send_addr(&self, peer_guid_prefix: &[u8; 12], origin: Origin) -> Option<SocketAddr> {
        self.fsm
            .metatraffic_locator_for(peer_guid_prefix, origin)
            .or_else(|| origin.reply())
    }

    // -----------------------------------------------------------------------
    // OMG getTypes request path (xtypes-structural-assignability)
    // -----------------------------------------------------------------------

    /// Ask the resolved destination for the COMPLETE TypeObject behind a type it announced
    /// in SEDP without an inline TypeObject.
    ///
    /// No-op when the peer published no COMPLETE TypeIdentifier (nothing we
    /// could store), or when a request for the same hash is already in flight.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(super) fn maybe_request_omg_type_object(
        &self,
        type_name: &str,
        type_information: &TypeInformation,
        origin: Origin,
        peer_guid_prefix: Option<[u8; 12]>,
    ) {
        let Some(complete) = type_information.complete.as_ref() else {
            log::debug!(
                "[TL-OMG] '{}' announced no COMPLETE TypeIdentifier; not requesting \
                 (a MinimalTypeObject has no sink in update_type_object_for_hash)",
                type_name
            );
            return;
        };
        if let Some(peer) = peer_guid_prefix {
            self.request_complete_type(Some(type_name), complete.hash, origin, peer);
        }
    }

    /// Queue a bounded, correlated lookup. Polling callers retry after timeout.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn request_complete_type(
        &self,
        type_name: Option<&str>,
        hash: EquivalenceHash,
        origin: Origin,
        peer: [u8; 12],
    ) {
        let cached = self.resolved_types.read().get(&hash).cloned();
        if let Some(object) = cached {
            self.resolved_types.write().touch(&hash);
            if type_name.is_some() {
                self.await_root(hash, object, peer, Instant::now());
                self.release_or_wait_at(Instant::now());
            }
            return;
        }
        let key = (peer, *hash.as_bytes());
        // RTPS 2.5 8.3.4 / 8.3.8.10: direct is exactly what this always was
        // -- straight to the reply address, no FSM preference (this path
        // never had one; `resolve_send_addr` is the OMG SERVE path's own
        // rule, not this REQUEST path's). Relayed falls back to the FSM's own
        // record of the peer. Resolved before a number is taken: a request
        // that cannot be sent must not leave a hole in the request writer's
        // sequence.
        let dest = origin
            .reply()
            .or_else(|| self.fsm.first_metatraffic_locator(&peer));
        let Some(dest) = dest else {
            log::debug!(
                "[TL-OMG] relayed origin and peer {:02x?} unknown to the FSM: no reply \
                 address, not requesting COMPLETE {:?}",
                peer,
                hash
            );
            return;
        };
        let packet = {
            let mut pending = self.pending_requests.lock();
            let now = Instant::now();
            pending.retain(|_, req| now.duration_since(req.sent_at) < GETTYPES_REQUEST_TIMEOUT);
            if let Some(request) = pending.get_mut(&key) {
                if request.type_name.is_none() {
                    request.type_name = type_name.map(str::to_owned);
                }
                return;
            }
            if pending.len() >= 128 {
                return;
            }
            let mut writer = [0u8; 16];
            writer[..12].copy_from_slice(&self.our_guid_prefix);
            writer[12..].copy_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
            // A number is taken only for a request that is about to leave:
            // a de-duplicated or refused request takes none (the request
            // writer's numbers are its own, RTPS 2.5 8.3.8.2 writerSN).
            let Some((seq, packet)) = self.writers.request.write_to(peer, |seq, gap| {
                let [a, b, c, d, e, f, g, h] = seq.to_le_bytes();
                let cdr = encode_omg_get_types_request(
                    &writer,
                    i32::from_le_bytes([e, f, g, h]),
                    u32::from_le_bytes([a, b, c, d]),
                    &[(EK_COMPLETE, key.1)],
                )?;
                Some(build_omg_request_rtps_packet(
                    &self.our_guid_prefix,
                    Some(&peer),
                    seq,
                    gap,
                    &cdr,
                ))
            }) else {
                return;
            };
            pending.insert(
                key,
                PendingTypeRequest {
                    type_name: type_name.map(str::to_owned),
                    sequence: seq,
                    sent_at: now,
                    attempts: 1,
                },
            );
            packet
        };
        // A failed send keeps the request in flight: the request writer holds
        // the datagram and announces it by HEARTBEAT, the peer NACKs it and
        // it is repaired (`DirectedWriter::answer_acknack`), as for a datagram
        // lost on the wire.
        if let Err(e) = self.transport.send_to_endpoint(&packet, &dest) {
            log::debug!("[TL-OMG] Send error to {}: {}", dest, e);
        } else {
            log::debug!("[TL-OMG] Requested COMPLETE {:?} from {}", hash, dest);
        }
    }

    /// Consume only matching, unexpired replies with the requested content hash.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn handle_omg_get_types_reply(&self, cdr_payload: &[u8], peer: Option<[u8; 12]>) {
        let (Some(reply), Some(peer)) = (parse_omg_get_types_reply(cdr_payload), peer) else {
            return;
        };
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&self.our_guid_prefix);
        writer[12..].copy_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
        if reply.request_writer_guid != writer {
            return;
        }
        for (hash, type_object) in reply.pairs {
            let key = (peer, hash);
            let hash = EquivalenceHash::from_bytes(hash);
            if type_object.compute_equivalence_hash().ok() != Some(hash) {
                log::debug!("[TL-OMG] Reply object does not match its requested hash");
                continue;
            }
            let pending = {
                let mut requests = self.pending_requests.lock();
                let Some(request) = requests.get(&key) else {
                    continue;
                };
                if request.sequence != reply.sequence
                    || request.sent_at.elapsed() >= GETTYPES_REQUEST_TIMEOUT
                {
                    continue;
                }
                requests.remove(&key)
            };
            if let Some(pending) = pending {
                // Keep the content-addressed cache separate from name-based
                // discovery. Bounded by eviction: it always accepts.
                self.resolved_types
                    .write()
                    .insert(hash, type_object.clone(), peer);
                // The type verdict resolves the hash references of a peer's
                // TypeObject through the types learned here.
                self.fsm
                    .register_remote_type_object(hash, type_object.clone(), peer);
                // The reply answers a hash: it resolves the endpoints that
                // announced that hash (`update_type_object_for_hash`), once
                // the types it references are known too. A request made for
                // a dependency, named by no endpoint, fills the cache, and
                // may complete a root that waits for it.
                if pending.type_name.is_some() {
                    self.await_root(hash, type_object, peer, Instant::now());
                }
            }
        }
        self.release_or_wait_at(Instant::now());
    }

    /// Hold `object`, the root type an endpoint announced as `hash`, until
    /// its member types are known. A full holding area releases the root at
    /// once rather than hold or drop it: judged early beats never judged.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn await_root(
        &self,
        hash: EquivalenceHash,
        object: CompleteTypeObject,
        peer: [u8; 12],
        now: Instant,
    ) {
        let mut awaiting = self.awaiting_dependencies.lock();
        if awaiting.contains_key(&hash) {
            return;
        }
        if awaiting.len() >= MAX_AWAITING_ROOTS {
            drop(awaiting);
            self.fsm.update_type_object_for_hash(&hash, object);
            return;
        }
        awaiting.insert(
            hash,
            AwaitingRoot {
                object,
                peer,
                since: now,
            },
        );
    }

    /// Give each awaiting root to its endpoints once nothing it references
    /// that can be looked up is unknown, or once it has waited
    /// `AWAIT_DEPENDENCIES_BOUND`; ask the serving peer for what is still
    /// missing otherwise.
    ///
    /// DDS-XTypes v1.3 7.6.3.4.2 Step 1 compares TYPES. A peer's COMPLETE
    /// TypeObject names its member types by hash; judged before those arrive,
    /// a refusal rested on types this participant had not seen, and was
    /// final. Waiting keeps the verdict pending (the endpoint's type is still
    /// unknown, Step 2). The wait is bounded, and the bound is enforced by
    /// the periodic tick (`tick_at`), not by the next event: a root still
    /// incomplete is then judged on what is known, an unresolved reference
    /// being, as before, not assignable.
    ///
    /// Each missing type is requested by its own kind. Only EK_COMPLETE can
    /// be: getTypes answers EK_MINIMAL with a MinimalTypeObject, which the
    /// type verdict has no use for, so a root missing only MINIMAL references
    /// is released at once.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn release_or_wait_at(&self, now: Instant) {
        let roots: Vec<(EquivalenceHash, [u8; 12], Instant, CompleteTypeObject)> = self
            .awaiting_dependencies
            .lock()
            .iter()
            .map(|(hash, root)| (*hash, root.peer, root.since, root.object.clone()))
            .collect();
        for (root, peer, since, object) in roots {
            let missing: Vec<EquivalenceHash> = self
                .fsm
                .unresolved_type_refs(&object)
                .into_iter()
                .filter(|r| r.complete)
                .map(|r| r.hash)
                .collect();
            if missing.is_empty()
                || now.saturating_duration_since(since) >= AWAIT_DEPENDENCIES_BOUND
            {
                self.awaiting_dependencies.lock().remove(&root);
                self.fsm.update_type_object_for_hash(&root, object);
                continue;
            }
            let Some(address) = self.fsm.first_metatraffic_locator(&peer) else {
                continue;
            };
            for dependency in missing {
                self.request_complete_type(None, dependency, Origin::direct(address), peer);
            }
        }
    }

    /// Start the periodic tick (`tick_at`) on its own thread. It ends at
    /// `stop_tick`, or when the service is dropped.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(in crate::dds::participant) fn start_tick(self: &Arc<Self>) {
        use std::sync::atomic::{AtomicBool, Ordering};
        let weak = Arc::downgrade(self);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let spawned = std::thread::Builder::new()
            .name("hdds-typelookup".to_string())
            .spawn(crate::core::rt::shutdown::owned(move || loop {
                // Parked rather than asleep: `stop_tick` unparks us.
                let due = Instant::now() + TYPE_LOOKUP_TICK;
                loop {
                    if stopped.load(Ordering::Acquire) {
                        return;
                    }
                    let now = Instant::now();
                    if now >= due {
                        break;
                    }
                    std::thread::park_timeout(due - now);
                }
                match weak.upgrade() {
                    Some(service) => service.tick_at(Instant::now()),
                    None => break,
                }
            }));
        match spawned {
            Ok(handle) => *self.tick.lock() = Some(TickThread { stop, handle }),
            Err(e) => log::warn!("[TL] TypeLookup tick thread not started: {}", e),
        }
    }

    /// Stop the tick thread and wait for it (never from the tick thread
    /// itself: see `join_bounded`).
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(in crate::dds::participant) fn stop_tick(&self) {
        let tick = self.tick.lock().take();
        if let Some(TickThread { stop, handle }) = tick {
            stop.store(true, std::sync::atomic::Ordering::Release);
            handle.thread().unpark();
            crate::core::rt::shutdown::join_bounded(handle, "TypeLookup tick");
        }
    }

    /// The periodic work no event can be relied on to trigger:
    /// - retry an endpoint's request whose reply has not come, up to
    ///   `MAX_REQUEST_ATTEMPTS` sends;
    /// - release or re-request every held root (`release_or_wait_at`);
    /// - every `HEARTBEAT_PERIOD`, a HEARTBEAT from each TypeLookup writer to
    ///   each peer holding unacknowledged samples (RTPS 2.5 8.4.2.2.3), and
    ///   forget the participants discovery no longer knows.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(super) fn tick_at(&self, now: Instant) {
        let expired: Vec<(TypeRequestKey, String, u8)> = {
            let mut pending = self.pending_requests.lock();
            let keys: Vec<TypeRequestKey> = pending
                .iter()
                .filter(|(_, req)| {
                    now.saturating_duration_since(req.sent_at) >= GETTYPES_REQUEST_TIMEOUT
                })
                .map(|(key, _)| *key)
                .collect();
            keys.into_iter()
                .filter_map(|key| {
                    let req = pending.remove(&key)?;
                    let name = req.type_name?;
                    (req.attempts < MAX_REQUEST_ATTEMPTS).then_some((key, name, req.attempts))
                })
                .collect()
        };
        for ((peer, hash), name, attempts) in expired {
            let Some(address) = self.fsm.first_metatraffic_locator(&peer) else {
                continue;
            };
            let hash = EquivalenceHash::from_bytes(hash);
            self.request_complete_type(Some(&name), hash, Origin::direct(address), peer);
            if let Some(req) = self
                .pending_requests
                .lock()
                .get_mut(&(peer, *hash.as_bytes()))
            {
                req.attempts = attempts.saturating_add(1);
            }
        }
        self.release_or_wait_at(now);

        let due = {
            let mut last = self.last_heartbeat.lock();
            let due = last.is_none_or(|at| now.saturating_duration_since(at) >= HEARTBEAT_PERIOD);
            if due {
                *last = Some(now);
            }
            due
        };
        if !due {
            return;
        }
        for writer in [&self.writers.request, &self.writers.reply] {
            for (peer, datagram) in writer.heartbeats(&self.our_guid_prefix) {
                if let Some(address) = self.fsm.first_metatraffic_locator(&peer) {
                    let _ = self.transport.send_to_endpoint(&datagram, &address);
                }
            }
        }
        self.forget_departed_peers();
    }

    /// Drop every trace of the participants discovery no longer knows: the
    /// writers' records, the types only they served (here and in the type
    /// verdict's store), their held roots and their requests in flight.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn forget_departed_peers(&self) {
        let mut peers = self.writers.request.peers();
        peers.extend(self.writers.reply.peers());
        peers.extend(self.resolved_types.read().peers());
        peers.extend(self.awaiting_dependencies.lock().values().map(|r| r.peer));
        peers.extend(self.pending_requests.lock().keys().map(|(p, _)| *p));
        peers.sort_unstable();
        peers.dedup();
        for peer in peers {
            if self.fsm.is_participant_known(&peer) {
                continue;
            }
            self.writers.forget_peer(&peer);
            self.resolved_types.write().forget_peer(&peer);
            self.fsm.forget_remote_types_of(&peer);
            self.awaiting_dependencies
                .lock()
                .retain(|_, r| r.peer != peer);
            self.pending_requests.lock().retain(|(p, _), _| *p != peer);
        }
    }

    // -----------------------------------------------------------------------
    // HTLK path (type-lookup only)
    // -----------------------------------------------------------------------

    #[cfg(feature = "type-lookup")]
    pub(super) fn maybe_request_type_object(
        &self,
        type_name: &str,
        origin: Origin,
        peer_guid_prefix: Option<[u8; 12]>,
    ) {
        if self.is_interop_mode() {
            return;
        }

        // RTPS 2.5 8.3.4 / 8.3.8.10: direct is exactly what this always was
        // -- straight to the reply address, no FSM preference (unlike the
        // OMG getTypes serve path, HTLK never had one). Relayed falls back
        // to the FSM's own record of the peer; give up if neither exists.
        //
        // Resolved BEFORE the dedup insert below, on purpose: this type is
        // marked "already requested" for good the moment it goes in, and a
        // destination that can never resolve (relayed, peer unknown) would
        // otherwise starve a LATER, resolvable announcement of the very same
        // type -- e.g. a direct one following a relayed-and-unknown attempt
        // -- of ever being requested at all.
        let dest = origin.reply().or_else(|| {
            peer_guid_prefix.and_then(|peer| self.fsm.first_metatraffic_locator(&peer))
        });
        let Some(dest) = dest else {
            log::debug!(
                "[TL] relayed origin and peer unknown to the FSM: no reply address, not \
                 requesting TypeObject for '{}'",
                type_name
            );
            return;
        };

        let mut requested = self.requested_types.lock();
        if !requested.insert(type_name.to_string()) {
            return;
        }
        drop(requested);

        let payload = match encode_htlk_message(type_name, None) {
            Ok(buf) => buf,
            Err(err) => {
                log::debug!("[TL] Failed to encode HTLK request: {:?}", err);
                return;
            }
        };

        // HTLK rides the request writer entity (0x000300C3), so it draws
        // from that writer's number space; a refused build takes no number.
        let Some((_, packet)) = self
            .writers
            .request
            .write_undirected(peer_guid_prefix, |seq| {
                build_htlk_packet(
                    &payload,
                    &self.our_guid_prefix,
                    peer_guid_prefix.as_ref(),
                    seq,
                )
                .map_err(|err| log::debug!("[TL] Failed to build HTLK packet: {}", err))
                .ok()
            })
        else {
            return;
        };

        if let Err(err) = self.transport.send_to_endpoint(&packet, &dest) {
            log::debug!("[TL] Failed to send HTLK request: {}", err);
        } else {
            log::debug!(
                "[TL] Requested TypeObject for '{}' from {}",
                type_name,
                dest
            );
        }
    }

    #[cfg(feature = "type-lookup")]
    fn handle_htlk_request(
        &self,
        message: &TypeLookupMessage,
        peer_prefix: Option<[u8; 12]>,
        origin: Origin,
    ) {
        // Check the ROS/live-capture registry first, then the SERVE-ONLY map
        // populated by an ordinary typed endpoint (see
        // `Participant::register_served_type`).
        let handle = self
            .registered_types
            .read()
            .get(&message.type_name)
            .cloned()
            .or_else(|| self.served_types.read().get(&message.type_name).cloned());

        let Some(handle) = handle else {
            log::debug!("[TL] No local TypeObject for '{}'", message.type_name);
            return;
        };
        // As on the OMG path (`DiscoveryFsm::type_lookup_serves`).
        if !self
            .fsm
            .type_lookup_serves(peer_prefix.as_ref(), &message.type_name)
        {
            return;
        }

        let type_object_bytes = match encode_htlk_type_object(&handle.complete) {
            Ok(bytes) => bytes,
            Err(err) => {
                log::debug!("[TL] Encode TypeObject failed: {}", err);
                return;
            }
        };

        let payload = match encode_htlk_message(&message.type_name, Some(&type_object_bytes)) {
            Ok(buf) => buf,
            Err(err) => {
                log::debug!("[TL] Encode HTLK response failed: {:?}", err);
                return;
            }
        };

        // Same writer entity as the HTLK request: same number space.
        let Some((_, pkt)) = self.writers.request.write_undirected(peer_prefix, |seq| {
            build_htlk_packet(&payload, &self.our_guid_prefix, peer_prefix.as_ref(), seq)
                .map_err(|err| log::debug!("[TL] Build HTLK response packet failed: {}", err))
                .ok()
        }) else {
            return;
        };

        // RTPS 2.5 8.3.4 / 8.3.8.10: same rule as the request path above --
        // direct is exactly what this always was (straight to the reply
        // address, no FSM preference), relayed falls back to the FSM.
        let dest = origin
            .reply()
            .or_else(|| peer_prefix.and_then(|peer| self.fsm.first_metatraffic_locator(&peer)));
        let Some(dest) = dest else {
            log::debug!(
                "[TL] relayed origin and peer unknown to the FSM: no reply address, not \
                 sending TypeObject for '{}'",
                message.type_name
            );
            return;
        };

        if let Err(err) = self.transport.send_to_endpoint(&pkt, &dest) {
            log::debug!("[TL] Failed to send HTLK response: {}", err);
        } else {
            log::debug!(
                "[TL] Sent TypeObject for '{}' to {}",
                message.type_name,
                dest
            );
        }
    }

    #[cfg(feature = "type-lookup")]
    fn handle_htlk_response(&self, message: &TypeLookupMessage) {
        let Some(bytes) = message.type_object.as_ref() else {
            log::debug!(
                "[TL] HTLK response missing TypeObject for '{}'",
                message.type_name
            );
            return;
        };

        let type_object = match CompleteTypeObject::decode_cdr2_le(bytes) {
            Ok((obj, _)) => obj,
            Err(err) => {
                log::debug!("[TL] Decode HTLK TypeObject failed: {}", err);
                return;
            }
        };

        let updated = self
            .fsm
            .update_type_object_for_type(&message.type_name, type_object);

        if updated > 0 {
            log::debug!(
                "[TL] Updated {} endpoint(s) with TypeObject for '{}'",
                updated,
                message.type_name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Stub impl when no active feature
// ---------------------------------------------------------------------------

#[cfg(not(any(feature = "type-lookup", feature = "xtypes-structural-assignability")))]
impl TypeLookupService {
    #[allow(dead_code)]
    pub(super) fn new(
        _fsm: Arc<DiscoveryFsm>,
        _transport: Arc<UdpTransport>,
        _our_guid_prefix: [u8; 12],
        _config: TypeLookupConfig,
    ) -> Self {
        Self
    }
}

// ---------------------------------------------------------------------------
// Top-level dispatch functions
// ---------------------------------------------------------------------------

#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
pub(super) fn handle_type_lookup_packet(
    handle: &TypeLookupHandle,
    payload: &[u8],
    cdr_offset: usize,
    origin: Origin,
) {
    if let Some(service) = handle {
        service.handle_packet(payload, cdr_offset, origin);
    }
}

#[cfg(not(any(feature = "type-lookup", feature = "xtypes-structural-assignability")))]
pub(super) fn handle_type_lookup_packet(
    _handle: &TypeLookupHandle,
    _payload: &[u8],
    _cdr_offset: usize,
    _origin: Origin,
) {
}

/// Hand a REASSEMBLED TypeLookup sample to the service.
///
/// The fragment path knows the writer GUID exactly -- reassembly is keyed on
/// it -- so both values the datagram path has to dig out of an RTPS header
/// arrive here already known, and better known: a datagram may bundle
/// fragments of more than one writer, and its header names the sending
/// participant, not the writer of this particular sample.
/// writerSN of the first DATA or DATA_FRAG of `datagram` sent by a
/// TypeLookup writer, the number our TypeLookup reader records it under.
pub(super) fn type_lookup_writer_sn(datagram: &[u8]) -> Option<u64> {
    use crate::core::discovery::multicast::classifier::walk;
    let mut sn = None;
    walk::for_each_submessage(datagram, |sub| {
        if sub.id != 0x15 && sub.id != 0x16 {
            return walk::Step::Continue;
        }
        let body = sub.offset + 4;
        let (Some(writer), Some(high), Some(low)) = (
            datagram.get(body + 8..body + 12),
            datagram.get(body + 12..body + 16),
            datagram.get(body + 16..body + 20),
        ) else {
            return walk::Step::Stop;
        };
        if TypeLookupWriters::reader_for(&[writer[0], writer[1], writer[2], writer[3]]).is_none() {
            return walk::Step::Continue;
        }
        let le = sub.flags & 0x01 != 0;
        let word = |b: &[u8]| {
            let b = [b[0], b[1], b[2], b[3]];
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        sn = Some((u64::from(word(high)) << 32) | u64::from(word(low)));
        walk::Step::Stop
    });
    sn
}

#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
pub(super) fn handle_type_lookup_sample(
    handle: &TypeLookupHandle,
    sample: &[u8],
    writer_entity_id: [u8; 4],
    peer_guid_prefix: [u8; 12],
    writer_sn: Option<u64>,
    origin: Origin,
) {
    if let Some(service) = handle {
        service.handle_sample(
            sample,
            Some(writer_entity_id),
            Some(peer_guid_prefix),
            writer_sn,
            origin,
        );
    }
}

#[cfg(not(any(feature = "type-lookup", feature = "xtypes-structural-assignability")))]
pub(super) fn handle_type_lookup_sample(
    _handle: &TypeLookupHandle,
    _sample: &[u8],
    _writer_entity_id: [u8; 4],
    _peer_guid_prefix: [u8; 12],
    _writer_sn: Option<u64>,
    _origin: Origin,
) {
}

#[cfg(feature = "type-lookup")]
pub(super) fn maybe_request_type_object(
    handle: &TypeLookupHandle,
    type_name: &str,
    origin: Origin,
    peer_guid_prefix: Option<[u8; 12]>,
) {
    if let Some(service) = handle {
        service.maybe_request_type_object(type_name, origin, peer_guid_prefix);
    }
}

#[cfg(not(feature = "type-lookup"))]
pub(super) fn maybe_request_type_object(
    _handle: &TypeLookupHandle,
    _type_name: &str,
    _origin: Origin,
    _peer_guid_prefix: Option<[u8; 12]>,
) {
}

#[cfg(feature = "xtypes-structural-assignability")]
pub(super) fn maybe_request_omg_type_object(
    handle: &TypeLookupHandle,
    type_name: &str,
    type_information: Option<&TypeInformation>,
    origin: Origin,
    peer_guid_prefix: Option<[u8; 12]>,
) {
    if let (Some(service), Some(info)) = (handle, type_information) {
        service.maybe_request_omg_type_object(type_name, info, origin, peer_guid_prefix);
    }
}

#[cfg(not(feature = "xtypes-structural-assignability"))]
pub(super) fn maybe_request_omg_type_object(
    _handle: &TypeLookupHandle,
    _type_name: &str,
    _type_information: Option<&crate::protocol::discovery::types::TypeInformation>,
    _origin: Origin,
    _peer_guid_prefix: Option<[u8; 12]>,
) {
}

// ---------------------------------------------------------------------------
// OMG getTypes request parser
// ---------------------------------------------------------------------------

/// Parsed OMG DDS-RPC getTypes request.
#[cfg(feature = "xtypes-structural-assignability")]
struct OmgGetTypesRequest {
    request_writer_guid: [u8; 16],
    request_seq_high: i32,
    request_seq_low: u32,
    /// (EK discriminant, 14-byte EquivalenceHash) pairs.
    type_ids: Vec<(u8, [u8; 14])>,
}

/// Member id of 'type_ids' in getTypes_In -- `EMHDR_TYPE_IDS_LE` without the
/// flags and LC nibble.
#[cfg(feature = "xtypes-structural-assignability")]
const MEMBER_ID_TYPE_IDS: u32 = 0x0C53_6065;

/// One MUTABLE member of a getTypes_In / getTypes_Out body.
#[cfg(feature = "xtypes-structural-assignability")]
struct MutableMember {
    id: u32,
    lc: u32,
    /// Start of the member extent (for LC 5..=7 this is the NEXTINT word).
    start: usize,
    /// End of the member extent, never past the enclosing struct.
    end: usize,
}

/// Read the next MUTABLE member header in `[*off, parent_end)`.
///
/// `*off` is first aligned to 4 (an EMHEADER is a u32; offsets are relative
/// to the CDR body origin), then the member extent comes from the one LC
/// table of the crate (`emheader_member_extent`, DDS-XTypes v1.3 sec.
/// 7.4.3.5.3), so every LC 0..=7 is skipped correctly. A member whose extent
/// leaves the enclosing struct is refused (None), never clipped. On success
/// `*off` is the end of the member.
#[cfg(feature = "xtypes-structural-assignability")]
fn next_mutable_member(data: &[u8], off: &mut usize, parent_end: usize) -> Option<MutableMember> {
    let parent_end = parent_end.min(data.len());
    let at = off.checked_add(3)? & !3;
    let header_end = at.checked_add(4)?;
    if header_end > parent_end {
        return None;
    }
    let emheader = u32::from_le_bytes(data[at..header_end].try_into().ok()?);
    let lc = (emheader >> 28) & 0x07;
    let nextint = if lc >= 4 {
        let nextint_end = header_end.checked_add(4)?;
        if nextint_end > parent_end {
            return None;
        }
        u32::from_le_bytes(data[header_end..nextint_end].try_into().ok()?)
    } else {
        0
    };
    let (start, len) =
        crate::core::ser::pl_cdr2::emheader_member_extent(lc, header_end, |_| nextint);
    let end = start.checked_add(len)?;
    if end > parent_end {
        return None;
    }
    *off = end;
    Some(MutableMember {
        id: emheader & 0x0FFF_FFFF,
        lc,
        start,
        end,
    })
}

/// Start of the sequence DHEADER inside `m`, for a member whose value is a
/// sequence of non-primitive elements.
///
/// Both legal encodings land on the same DHEADER: LC=5 shares NEXTINT with
/// it (what HDDS emits), LC=4 carries a byte-count NEXTINT followed by the
/// whole sequence (what OpenDDS emits); for LC=4 the DHEADER must then equal
/// the byte count minus its own 4 bytes. Accepting only LC=5 silently dropped
/// OpenDDS getTypes requests. Any other LC cannot carry this value: None.
#[cfg(feature = "xtypes-structural-assignability")]
fn sequence_dheader_at(data: &[u8], m: &MutableMember) -> Option<usize> {
    if m.start.checked_add(8)? > m.end {
        return None; // DHEADER + count must fit
    }
    match m.lc {
        5 => Some(m.start),
        4 => {
            let dheader = u32::from_le_bytes(data[m.start..m.start + 4].try_into().ok()?) as usize;
            (dheader.checked_add(4)? == m.end - m.start).then_some(m.start)
        }
        _ => None,
    }
}

/// Parse an OMG PLAIN_CDR2_LE getTypes REQUEST CDR payload.
///
/// `cdr_payload` starts with the 4-byte encapsulation header (`00 07 xx xx`).
/// Offsets documented relative to the CDR body (after the encap header).
#[cfg(feature = "xtypes-structural-assignability")]
fn parse_omg_get_types_request(cdr_payload: &[u8]) -> Option<OmgGetTypesRequest> {
    if cdr_payload.len() < 4 {
        return None;
    }
    // Must be PLAIN_CDR2_LE (0x0007).
    if cdr_payload[0] != 0x00 || cdr_payload[1] != 0x07 {
        return None;
    }

    let data = &cdr_payload[4..]; // CDR body, offsets 0x00..
    let mut off = 0usize;

    // RequestHeader.requestId.writer_guid (16 bytes).
    if data.len() < off + 16 {
        return None;
    }
    let mut request_writer_guid = [0u8; 16];
    request_writer_guid.copy_from_slice(&data[off..off + 16]);
    off += 16;

    // RequestHeader.requestId.sequence_number: {i32 high LE, u32 low LE} = 8 bytes.
    if data.len() < off + 8 {
        return None;
    }
    let request_seq_high = i32::from_le_bytes(data[off..off + 4].try_into().ok()?);
    off += 4;
    let request_seq_low = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
    off += 4;

    // instance_name: u32 length + null-terminated bytes.
    if data.len() < off + 4 {
        return None;
    }
    let name_len = u32::from_le_bytes(data[off..off + 4].try_into().ok()?) as usize;
    off += 4;
    if data.len() < off + name_len {
        return None;
    }
    off += name_len;

    // Pad to 4B for TypeLookup_Call DHEADER.
    let pad = (4 - (off % 4)) % 4;
    off += pad;

    // TypeLookup_Call (APPENDABLE union): DHEADER (4B) + discriminant (u32).
    if data.len() < off + 8 {
        return None;
    }
    let _call_dheader = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
    off += 4;
    let disc = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
    off += 4;
    if disc != GETTYPES_OP_DISC {
        // Not getTypes (could be getTypeDependencies etc.) -- ignore.
        return None;
    }

    // getTypes_In (MUTABLE struct): DHEADER (4B) + EMHEADER members.
    if data.len() < off + 4 {
        return None;
    }
    let in_dheader = u32::from_le_bytes(data[off..off + 4].try_into().ok()?) as usize;
    off += 4;
    let in_end = off.saturating_add(in_dheader).min(data.len());

    let mut type_ids: Vec<(u8, [u8; 14])> = Vec::new();

    // Walk MUTABLE members; only 'type_ids' is consumed, any other member is
    // skipped by its extent.
    while let Some(m) = next_mutable_member(data, &mut off, in_end) {
        if m.id != MEMBER_ID_TYPE_IDS {
            continue;
        }
        let member_end = m.end;
        // Parse sequence<TypeIdentifier>: DHEADER, u32 count, N * 15 bytes.
        if let Some(seq_start) = sequence_dheader_at(data, &m) {
            let count =
                u32::from_le_bytes(data[seq_start + 4..seq_start + 8].try_into().ok()?) as usize;
            let mut id_off = seq_start + 8;
            for _ in 0..count {
                if id_off + 15 > member_end {
                    break;
                }
                let ek = data[id_off];
                if ek == EK_MINIMAL || ek == EK_COMPLETE {
                    let mut hash = [0u8; 14];
                    hash.copy_from_slice(&data[id_off + 1..id_off + 15]);
                    type_ids.push((ek, hash));
                }
                id_off += 15;
            }
        }
    }

    if type_ids.is_empty() {
        return None;
    }

    Some(OmgGetTypesRequest {
        request_writer_guid,
        request_seq_high,
        request_seq_low,
        type_ids,
    })
}

// ---------------------------------------------------------------------------
// OMG getTypes request CDR encoder
// ---------------------------------------------------------------------------

/// Encode an OMG DDS-RPC `getTypes` REQUEST as PLAIN_CDR2_LE.
///
/// Byte-for-byte the layout `parse_omg_get_types_request` reads back, which is
/// also what the round-trip test asserts:
///
/// ```text
/// 0x00  RequestHeader.requestId.writer_guid [16 B]
/// 0x10  requestId.sequence_number.high i32 LE [4 B]
/// 0x14  requestId.sequence_number.low  u32 LE [4 B]
/// 0x18  instance_name length u32 LE = 1 [4 B]
/// 0x1c  instance_name bytes: the NUL terminator [1 B]
///       [pad to 4B -> 0x20]
/// 0x20  TypeLookup_Call DHEADER [4 B]
/// 0x24  TypeLookup_Call discriminant (getTypes) [4 B]
/// 0x28  getTypes_In DHEADER [4 B]
/// 0x2c  'type_ids' EMHEADER LC=5 [4 B]
/// 0x30  'type_ids' NEXTINT [4 B]
/// 0x34  type_ids.length u32 LE [4 B]
/// 0x38  TypeIdentifier[] -- EK discriminant (1 B) + EquivalenceHash (14 B)
/// ```
///
/// `instance_name` is the empty CDR string: length 1 covering the NUL, per
/// CDR string encoding. It is not a service instance selector here -- the
/// TypeLookup service is participant-scoped.
#[cfg(feature = "xtypes-structural-assignability")]
fn encode_omg_get_types_request(
    request_writer_guid: &[u8; 16],
    request_seq_high: i32,
    request_seq_low: u32,
    type_ids: &[(u8, [u8; 14])],
) -> Option<Vec<u8>> {
    if type_ids.is_empty() {
        return None;
    }

    let mut buf = vec![0u8; 0x38 + type_ids.len() * 15];
    let mut off = 0usize;

    // -- RequestHeader --
    buf[off..off + 16].copy_from_slice(request_writer_guid);
    off += 16;
    buf[off..off + 4].copy_from_slice(&request_seq_high.to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&request_seq_low.to_le_bytes());
    off += 4;

    // -- instance_name: empty CDR string (length includes the terminator) --
    buf[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
    off += 4;
    off += 1; // the NUL, already zero
    let pad = (4 - (off % 4)) % 4;
    off += pad; // off == 0x20

    // -- TypeLookup_Call APPENDABLE union --
    let call_dh = off;
    off += 4;
    let call_body = off;
    buf[off..off + 4].copy_from_slice(&GETTYPES_OP_DISC_LE);
    off += 4;

    // -- getTypes_In MUTABLE struct --
    let in_dh = off;
    off += 4;
    let in_body = off;

    // 'type_ids' EMHEADER (LC=5) + NEXTINT placeholder.
    buf[off..off + 4].copy_from_slice(&EMHDR_TYPE_IDS_LE);
    off += 4;
    let ids_ni = off;
    off += 4;
    let ids_seq = off;

    // sequence<TypeIdentifier>: count then 15-byte entries, 1-byte aligned.
    let count = u32::try_from(type_ids.len()).ok()?;
    buf[off..off + 4].copy_from_slice(&count.to_le_bytes());
    off += 4;
    for (ek, hash) in type_ids {
        buf[off] = *ek;
        off += 1;
        buf[off..off + 14].copy_from_slice(hash);
        off += 14;
    }

    // -- Back-fill NEXTINT and the two DHEADERs --
    let ids_size = u32::try_from(off - ids_seq).ok()?;
    buf[ids_ni..ids_ni + 4].copy_from_slice(&ids_size.to_le_bytes());
    let in_size = u32::try_from(off - in_body).ok()?;
    buf[in_dh..in_dh + 4].copy_from_slice(&in_size.to_le_bytes());
    let call_size = u32::try_from(off - call_body).ok()?;
    buf[call_dh..call_dh + 4].copy_from_slice(&call_size.to_le_bytes());

    let mut out = Vec::with_capacity(4 + off);
    out.extend_from_slice(&[0x00, 0x07, 0x00, 0x00]);
    out.extend_from_slice(&buf[..off]);
    Some(out)
}

// ---------------------------------------------------------------------------
// OMG getTypes REQUEST RTPS packet builder
// ---------------------------------------------------------------------------

/// Build an RTPS packet carrying an OMG getTypes REQUEST.
///
/// Addressed from our TypeLookup request writer (0x000300C3) to the peer's
/// TypeLookup request reader (0x000300C4). DATA flags = 0x05 (E=LE,
/// D=data-present): a request carries no inline QoS, since there is no prior
/// sample identity to relate it to.
///
/// The DATA is the LAST submessage of this message, so a body that does not
/// fit `octetsToNextHeader` (u16, RTPS v2.5 Sec.9.4.5.1.3) is framed with the
/// sentinel 0, "extends to the end of the message" (Sec.8.3.3.3.3), through
/// `protocol::rtps::octets_to_next_header_for_last_submessage`. Whether the
/// datagram then fits the transport is the transport's verdict, given by name
/// at send time.
#[cfg(feature = "xtypes-structural-assignability")]
fn build_omg_request_rtps_packet(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: Option<&[u8; 12]>,
    our_seq: u64,
    gap: &[u8],
    cdr_payload: &[u8],
) -> Vec<u8> {
    // DATA body = ExtraFlags(2) + OctetsToInlineQos(2) + EIDs(8) + SN(8) + payload
    let body_len = 2 + 2 + 4 + 4 + 8 + cdr_payload.len();
    let octets_to_next_header = octets_to_next_header_for_last_submessage(body_len);

    let (sn_high, sn_low) = split_sequence_number(our_seq);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let (ts_sec, ts_frac) = rtps_time_from_unix(now);

    let mut pkt = Vec::with_capacity(20 + 16 + 12 + 4 + body_len);

    // RTPS header (20 bytes).
    pkt.extend_from_slice(b"RTPS");
    pkt.push(RTPS_VERSION_MAJOR);
    pkt.push(RTPS_VERSION_MINOR);
    pkt.extend_from_slice(&HDDS_VENDOR_ID);
    pkt.extend_from_slice(our_guid_prefix);

    // INFO_DST (16 bytes) -- only when the peer prefix is known.
    if let Some(prefix) = peer_guid_prefix {
        pkt.push(0x0e);
        pkt.push(0x01); // flags: LE
        pkt.extend_from_slice(&12u16.to_le_bytes());
        pkt.extend_from_slice(prefix);
    }

    // GAP for the numbers this writer used for other participants
    // (`DirectedWriter::write_to`); empty when there are none.
    pkt.extend_from_slice(gap);

    // INFO_TS (12 bytes).
    pkt.push(0x09);
    pkt.push(0x01); // flags: LE
    pkt.extend_from_slice(&8u16.to_le_bytes());
    pkt.extend_from_slice(&ts_sec.to_le_bytes());
    pkt.extend_from_slice(&ts_frac.to_le_bytes());

    // DATA submsg header (4 bytes).
    pkt.push(0x15); // DATA
    pkt.push(0x05); // E=LE | D=data
    pkt.extend_from_slice(&octets_to_next_header.to_le_bytes());

    // DATA body.
    pkt.extend_from_slice(&[0x00, 0x00]); // ExtraFlags
    pkt.extend_from_slice(&16u16.to_le_bytes()); // OctetsToInlineQos = 16
    pkt.extend_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER);
    pkt.extend_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
    pkt.extend_from_slice(&sn_high.to_le_bytes());
    pkt.extend_from_slice(&sn_low.to_le_bytes());

    // Serialized data.
    pkt.extend_from_slice(cdr_payload);

    pkt
}

// ---------------------------------------------------------------------------
// OMG getTypes reply CDR encoder
// ---------------------------------------------------------------------------

/// Find a TypeObject handle by EK discriminant and 14-byte hash, with the
/// name it is registered under.
#[cfg(feature = "xtypes-structural-assignability")]
fn lookup_named_type_object(
    map: &HashMap<String, Arc<TypeObjectHandle>>,
    ek: u8,
    hash: [u8; 14],
) -> Option<(String, Arc<TypeObjectHandle>)> {
    use crate::xtypes::TypeIdentifier;
    let target = EquivalenceHash::from_bytes(hash);
    map.iter()
        .find(|(_, h)| {
            if ek == EK_MINIMAL {
                h.type_id_minimal == TypeIdentifier::Minimal(target)
            } else {
                // Spec-correct wire id first (Complete member refs per
                // DDS-XTypes v1.3 7.3.4.5 -- the id announced in
                // PID_TYPE_INFORMATION); the legacy hybrid id stays matched
                // so a peer that cached the old identity keeps resolving.
                h.type_id_complete_wire
                    .as_ref()
                    .is_some_and(|id| *id == TypeIdentifier::Complete(target))
                    || h.type_id_complete == TypeIdentifier::Complete(target)
            }
        })
        .map(|(name, h)| (name.clone(), Arc::clone(h)))
}

/// Encode a complete OMG getTypes REPLY CDR payload (encap header included).
///
/// The returned bytes start with the 4-byte `PLAIN_CDR2_LE` encapsulation header
/// (`00 07 00 00`), followed by the CDR body.
///
/// CDR body layout (offsets within body, i.e. after encap header):
/// ```text
/// 0x00  ReplyHeader.relatedRequestId.writer_guid [16 B]
/// 0x10  .sequence_number {high i32 LE, low u32 LE} [8 B]
/// 0x18  remoteEx u32 LE = 0 [4 B]
/// 0x1c  TypeLookup_Return DHEADER [4 B] (APPENDABLE)
/// 0x20  TypeLookup_Return discriminant u32 LE = 0x018252d3 [4 B]
/// 0x24  getTypes_Result DHEADER [4 B] (APPENDABLE)
/// 0x28  getTypes_Result discriminant u32 LE = 0 (DDS_RETCODE_OK) [4 B]
/// 0x2c  getTypes_Out DHEADER [4 B] (MUTABLE)
/// 0x30  types EMHEADER LC=5 [4 B]
/// 0x34  types NEXTINT [4 B]
/// 0x38  types.length u32 LE [4 B]
/// 0x3c  TypeIdentifierTypeObjectPair[] (variable)
///       [pad to 4B]
///       complete_to_minimal EMHEADER LC=5 [4 B]
///       complete_to_minimal NEXTINT = 4 [4 B]
///       complete_to_minimal.length = 0 [4 B]
/// ```
#[cfg(feature = "xtypes-structural-assignability")]
fn encode_omg_get_types_reply(
    request_writer_guid: &[u8; 16],
    request_seq_high: i32,
    request_seq_low: u32,
    pairs: &[(u8, [u8; 14], Arc<TypeObjectHandle>)],
) -> Option<Vec<u8>> {
    // Pre-allocate: fixed header (~ 60 B) + generous space per TypeObject.
    let cap = 512 + pairs.len() * 4096;
    let mut buf = vec![0u8; cap];
    let mut off = 0usize; // cursor within the CDR body (not counting the 4-byte encap)

    // -- ReplyHeader (28 bytes) --
    buf[off..off + 16].copy_from_slice(request_writer_guid);
    off += 16;
    buf[off..off + 4].copy_from_slice(&request_seq_high.to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&request_seq_low.to_le_bytes());
    off += 4;
    // remoteEx = 0 already zero-filled; advance 4.
    off += 4;
    // off == 28 == 0x1c  (4B aligned)

    // -- TypeLookup_Return APPENDABLE union: reserve DHEADER slot --
    let ret_dh = off;
    off += 4;
    let ret_body = off; // == 0x20

    // TypeLookup_Return discriminant (getTypes op).
    buf[off..off + 4].copy_from_slice(&GETTYPES_OP_DISC_LE);
    off += 4; // off == 0x24

    // -- getTypes_Result APPENDABLE union: reserve DHEADER slot --
    let res_dh = off;
    off += 4;
    let res_body = off; // == 0x28

    // getTypes_Result discriminant = 0 (DDS_RETCODE_OK), already zero.
    off += 4; // off == 0x2c

    // -- getTypes_Out MUTABLE struct: reserve DHEADER slot --
    let out_dh = off;
    off += 4;
    let out_body = off; // == 0x30

    // 'types' EMHEADER (LC=5) + NEXTINT placeholder.
    buf[off..off + 4].copy_from_slice(&EMHDR_TYPES_LE);
    off += 4;
    let types_ni = off;
    off += 4; // reserve NEXTINT
    let types_seq = off; // == 0x38

    // types.length (u32 LE).
    let n = u32::try_from(pairs.len()).ok()?;
    buf[off..off + 4].copy_from_slice(&n.to_le_bytes());
    off += 4; // off == 0x3c

    // -- Encode TypeIdentifierTypeObjectPair[] --
    for (ek, hash, handle) in pairs {
        // TypeIdentifier: EK discriminant (1 B) + 14-byte EquivalenceHash.
        // No alignment requirement for TypeIdentifier itself.
        if off + 15 > buf.len() {
            return None;
        }
        buf[off] = *ek;
        off += 1;
        buf[off..off + 14].copy_from_slice(hash);
        off += 14;

        // Pad to 4B alignment for the TypeObject DHEADER.
        let pad = (4 - (off % 4)) % 4;
        off += pad; // bytes already zero

        // TypeObject (APPENDABLE union): DHEADER + EK disc + inner TypeObject.
        if off + 5 > buf.len() {
            return None;
        }
        let to_dh = off;
        off += 4; // reserve DHEADER
        let to_body = off;

        buf[off] = *ek; // EK discriminant of outer TypeObject union
        off += 1;

        // Inner TypeObject (MinimalTypeObject or CompleteTypeObject) via Cdr2Encode.
        // Does NOT include its own outer APPENDABLE DHEADER -- that is the `to_dh` slot.
        // `off` is the global cursor so XCDR2 alignment inside encode_cdr2_le_at is correct.
        let encode_result = if *ek == EK_MINIMAL {
            handle.minimal.encode_cdr2_le_at(&mut buf, &mut off)
        } else {
            // Serve the Complete object whose equivalence hash matches the
            // REQUESTED TypeIdentifier: the spec-correct wire form
            // (Complete member refs, DDS-XTypes v1.3 7.3.4.5) under the
            // wire hash, the legacy hybrid under the old hash. A receiver
            // may verify that the served object hashes to the requested
            // id, so the pair must stay consistent.
            use crate::xtypes::TypeIdentifier;
            let requested = TypeIdentifier::Complete(EquivalenceHash::from_bytes(*hash));
            handle
                .complete_for_id(&requested)
                .encode_cdr2_le_at(&mut buf, &mut off)
        };
        if encode_result.is_err() {
            log::debug!("[TL-OMG] TypeObject encode error (possible buffer overflow)");
            return None;
        }

        // Fill TypeObject DHEADER.
        let to_size = u32::try_from(off - to_body).ok()?;
        buf[to_dh..to_dh + 4].copy_from_slice(&to_size.to_le_bytes());
    }

    // Fill 'types' NEXTINT = bytes from start of sequence (count field) to now.
    let types_seq_size = u32::try_from(off - types_seq).ok()?;
    buf[types_ni..types_ni + 4].copy_from_slice(&types_seq_size.to_le_bytes());

    // -- 'complete_to_minimal' member --
    // Pad to 4B alignment for EMHEADER.
    let pad = (4 - (off % 4)) % 4;
    off += pad;

    if off + 12 > buf.len() {
        return None;
    }
    buf[off..off + 4].copy_from_slice(&EMHDR_C2M_LE);
    off += 4;
    // NEXTINT = 4 (just the count u32).
    buf[off..off + 4].copy_from_slice(&4u32.to_le_bytes());
    off += 4;
    // count = 0, already zero.
    off += 4;

    // -- Back-fill DHEADERs --
    let out_size = u32::try_from(off - out_body).ok()?;
    buf[out_dh..out_dh + 4].copy_from_slice(&out_size.to_le_bytes());

    let res_size = u32::try_from(off - res_body).ok()?;
    buf[res_dh..res_dh + 4].copy_from_slice(&res_size.to_le_bytes());

    let ret_size = u32::try_from(off - ret_body).ok()?;
    buf[ret_dh..ret_dh + 4].copy_from_slice(&ret_size.to_le_bytes());

    // Prepend 4-byte PLAIN_CDR2_LE encap header.
    let mut out = Vec::with_capacity(4 + off);
    out.extend_from_slice(&[0x00, 0x07, 0x00, 0x00]);
    out.extend_from_slice(&buf[..off]);
    Some(out)
}

// ---------------------------------------------------------------------------
// OMG getTypes REPLY RTPS packet builder
// ---------------------------------------------------------------------------

/// Build an RTPS packet carrying the OMG getTypes REPLY.
///
/// DATA flags = 0x07 (E=LE, D=data-present, Q=inline-QoS).
/// Inline QoS carries PID_RELATED_SAMPLE_IDENTITY (0x0083) referencing the
/// request sequence number, followed by PID_SENTINEL.
///
/// The DATA is the LAST submessage of this message; see
/// `build_omg_request_rtps_packet` for how an oversized body is framed.
#[cfg(feature = "xtypes-structural-assignability")]
// justification: each argument is one field of the datagram (prefixes, SN,
// GAP, related sample identity split as on the wire, payload).
#[allow(clippy::too_many_arguments)]
fn build_omg_reply_rtps_packet(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
    our_seq: u64,
    gap: &[u8],
    request_writer_guid: &[u8; 16],
    request_seq_high: i32,
    request_seq_low: u32,
    cdr_payload: &[u8],
) -> Vec<u8> {
    // Inline QoS block (32 bytes):
    //   PID 0x0083 len=24: request_writer_guid(16) + request_seq(8)
    //   PID_SENTINEL 0x0001 len=0
    let mut iqos = [0u8; 32];
    iqos[0] = 0x83;
    iqos[1] = 0x00;
    iqos[2] = 0x18; // length 24 LE
    iqos[3] = 0x00;
    iqos[4..20].copy_from_slice(request_writer_guid);
    iqos[20..24].copy_from_slice(&request_seq_high.to_le_bytes());
    iqos[24..28].copy_from_slice(&request_seq_low.to_le_bytes());
    iqos[28] = 0x01; // PID_SENTINEL low byte
                     // iqos[29..32] = 0x00 0x00 0x00 (already zero)

    // DATA body = ExtraFlags(2) + OctetsToInlineQos(2) + EIDs(8) + SN(8) + InlineQoS(32) + payload
    let body_len = 2 + 2 + 4 + 4 + 8 + iqos.len() + cdr_payload.len();
    // A reply carrying TypeObjects can exceed the u16; as the last submessage
    // it is then framed with the sentinel 0 rather than refused.
    let octets_to_next_header = octets_to_next_header_for_last_submessage(body_len);

    let (sn_high, sn_low) = split_sequence_number(our_seq);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let (ts_sec, ts_frac) = rtps_time_from_unix(now);

    let mut pkt = Vec::with_capacity(20 + 16 + 12 + 4 + body_len);

    // RTPS header (20 bytes).
    pkt.extend_from_slice(b"RTPS");
    pkt.push(RTPS_VERSION_MAJOR);
    pkt.push(RTPS_VERSION_MINOR);
    pkt.extend_from_slice(&HDDS_VENDOR_ID);
    pkt.extend_from_slice(our_guid_prefix);

    // INFO_DST (16 bytes).
    pkt.push(0x0e);
    pkt.push(0x01); // flags: LE
    pkt.extend_from_slice(&12u16.to_le_bytes());
    pkt.extend_from_slice(peer_guid_prefix);

    // GAP for the numbers this writer used for other participants
    // (`DirectedWriter::write_to`); empty when there are none.
    pkt.extend_from_slice(gap);

    // INFO_TS (12 bytes).
    pkt.push(0x09);
    pkt.push(0x01); // flags: LE
    pkt.extend_from_slice(&8u16.to_le_bytes());
    pkt.extend_from_slice(&ts_sec.to_le_bytes());
    pkt.extend_from_slice(&ts_frac.to_le_bytes());

    // DATA submsg header (4 bytes).
    pkt.push(0x15); // DATA
    pkt.push(0x07); // E=LE | D=data | Q=inline-QoS
    pkt.extend_from_slice(&octets_to_next_header.to_le_bytes());

    // DATA body.
    pkt.extend_from_slice(&[0x00, 0x00]); // ExtraFlags
    pkt.extend_from_slice(&16u16.to_le_bytes()); // OctetsToInlineQos = 16
    pkt.extend_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REPLY_READER);
    pkt.extend_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER);
    pkt.extend_from_slice(&sn_high.to_le_bytes());
    pkt.extend_from_slice(&sn_low.to_le_bytes());

    // Inline QoS.
    pkt.extend_from_slice(&iqos);

    // Serialized data.
    pkt.extend_from_slice(cdr_payload);

    pkt
}

// ---------------------------------------------------------------------------
// OMG getTypes reply CDR parser
// ---------------------------------------------------------------------------

/// Parsed OMG DDS-RPC getTypes reply.
#[cfg(feature = "xtypes-structural-assignability")]
struct OmgGetTypesReply {
    request_writer_guid: [u8; 16],
    sequence: u64,
    /// (14-byte EquivalenceHash, decoded COMPLETE TypeObject) pairs.
    ///
    /// EK_MINIMAL pairs are skipped: `maybe_request_omg_type_object` never
    /// asks for one, and a MinimalTypeObject has no sink in the FSM.
    pairs: Vec<([u8; 14], CompleteTypeObject)>,
}

/// Parse an OMG PLAIN_CDR2_LE getTypes REPLY CDR payload.
///
/// Mirror of `encode_omg_get_types_reply`; offsets are documented there.
/// Returns `None` when the payload is not a well-formed getTypes reply or
/// carries a non-OK return code. A reply with an OK code but zero usable
/// pairs still parses -- an empty `pairs` is the peer saying "I do not have
/// that type", which is not a decode failure.
#[cfg(feature = "xtypes-structural-assignability")]
fn parse_omg_get_types_reply(cdr_payload: &[u8]) -> Option<OmgGetTypesReply> {
    if cdr_payload.len() < 4 {
        return None;
    }
    if cdr_payload[0] != 0x00 || cdr_payload[1] != 0x07 {
        return None;
    }
    let data = &cdr_payload[4..];

    // -- ReplyHeader (28 bytes: requestId 24 + remoteEx 4) --
    if data.len() < 28 {
        return None;
    }
    let mut request_writer_guid = [0u8; 16];
    request_writer_guid.copy_from_slice(&data[0..16]);
    let sequence = ((u32::from_le_bytes(data[16..20].try_into().ok()?) as u64) << 32)
        | u32::from_le_bytes(data[20..24].try_into().ok()?) as u64;
    let mut off = 28usize;

    // -- TypeLookup_Return APPENDABLE union: DHEADER + discriminant --
    if data.len() < off + 8 {
        return None;
    }
    off += 4; // return DHEADER
    let disc = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
    off += 4;
    if disc != GETTYPES_OP_DISC {
        return None;
    }

    // -- getTypes_Result APPENDABLE union: DHEADER + return code --
    if data.len() < off + 8 {
        return None;
    }
    off += 4; // result DHEADER
    let retcode = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
    off += 4;
    if retcode != 0 {
        log::debug!("[TL-OMG] getTypes reply carries retcode {}", retcode);
        return None;
    }

    // -- getTypes_Out MUTABLE struct --
    if data.len() < off + 4 {
        return None;
    }
    let out_dheader = u32::from_le_bytes(data[off..off + 4].try_into().ok()?) as usize;
    off += 4;
    let out_end = off.saturating_add(out_dheader).min(data.len());

    let mut pairs: Vec<([u8; 14], CompleteTypeObject)> = Vec::new();

    // Walk MUTABLE members; only 'types' is consumed, 'complete_to_minimal'
    // and any other member are skipped by their extent, in any order.
    while let Some(m) = next_mutable_member(data, &mut off, out_end) {
        if m.id != MEMBER_ID_TYPES {
            continue;
        }
        if let Some(seq_start) = sequence_dheader_at(data, &m) {
            // parse_type_object_pairs starts at the sequence length, past the
            // sequence DHEADER.
            parse_type_object_pairs(data, seq_start + 4, m.end, &mut pairs);
        }
    }

    Some(OmgGetTypesReply {
        request_writer_guid,
        sequence,
        pairs,
    })
}

/// Parse the `sequence<TypeIdentifierTypeObjectPair>` body of a getTypes reply.
///
/// `start` points at the sequence length; `end` bounds the member. Malformed
/// or undecodable entries are logged and skipped rather than aborting the
/// whole reply: one unusable pair must not discard the usable ones.
#[cfg(feature = "xtypes-structural-assignability")]
fn parse_type_object_pairs(
    data: &[u8],
    start: usize,
    end: usize,
    out: &mut Vec<([u8; 14], CompleteTypeObject)>,
) {
    if start + 4 > end {
        return;
    }
    let Ok(len_bytes) = <[u8; 4]>::try_from(&data[start..start + 4]) else {
        return;
    };
    let count = u32::from_le_bytes(len_bytes) as usize;
    let mut off = start + 4;

    for _ in 0..count {
        // TypeIdentifier: EK discriminant (1 B) + EquivalenceHash (14 B).
        if off + 15 > end {
            return;
        }
        let ek = data[off];
        let mut hash = [0u8; 14];
        hash.copy_from_slice(&data[off + 1..off + 15]);
        off += 15;

        // TypeObject APPENDABLE union: 4B-aligned DHEADER, then EK + body.
        off += (4 - (off % 4)) % 4;
        if off + 4 > end {
            return;
        }
        let Ok(dh_bytes) = <[u8; 4]>::try_from(&data[off..off + 4]) else {
            return;
        };
        let to_size = u32::from_le_bytes(dh_bytes) as usize;
        off += 4;
        let to_body = off;
        let to_end = to_body.saturating_add(to_size);
        if to_size == 0 || to_end > end {
            return;
        }

        // The inner object decodes against the global CDR-body cursor, which
        // is how `encode_omg_get_types_reply` wrote it: XCDR2 alignment is
        // relative to the start of the body, not to the member.
        if data[to_body] == EK_COMPLETE && ek == EK_COMPLETE {
            let mut cursor = to_body + 1;
            match CompleteTypeObject::decode_cdr2_le_at(&data[..to_end], &mut cursor) {
                Ok(obj) if cursor == to_end => out.push((hash, obj)),
                Ok(_) => log::debug!("[TL-OMG] TypeObject size does not match its delimiter"),
                Err(e) => log::debug!("[TL-OMG] CompleteTypeObject decode failed: {}", e),
            }
        } else {
            log::debug!(
                "[TL-OMG] Skipping non-COMPLETE TypeObject in reply (EK 0x{:02x})",
                ek
            );
        }

        // Advance by the DHEADER, never by what the decoder consumed: a short
        // or long decode must not desynchronise the following pairs.
        off = to_end;
    }
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

/// Extract the GUID prefix (bytes 8..20) from a raw RTPS packet header.
fn extract_peer_guid_prefix(packet: &[u8]) -> Option<[u8; 12]> {
    if packet.len() < 20 || &packet[0..4] != b"RTPS" {
        return None;
    }
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&packet[8..20]);
    Some(prefix)
}

// ---------------------------------------------------------------------------
// HTLK helpers (type-lookup only)
// ---------------------------------------------------------------------------

#[cfg(feature = "type-lookup")]
fn encode_htlk_type_object(type_object: &CompleteTypeObject) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; type_object.max_cdr2_size()];
    let len = type_object
        .encode_cdr2_le(&mut buf)
        .map_err(|_| "cdr2 encode failed".to_string())?;
    buf.truncate(len);
    Ok(buf)
}

#[cfg(feature = "type-lookup")]
fn decode_htlk_message(payload: &[u8]) -> Result<TypeLookupMessage, TypeLookupError> {
    if payload.len() < 8 {
        return Err(TypeLookupError::Truncated);
    }

    let encapsulation = u16::from_be_bytes([payload[0], payload[1]]);
    if encapsulation != PL_CDR2_LE {
        return Err(TypeLookupError::InvalidMagic);
    }

    let mut offset = 4; // skip encap + options
    if payload.len() < offset + 8 {
        return Err(TypeLookupError::Truncated);
    }

    if payload[offset..offset + 4] != TYPE_LOOKUP_MAGIC {
        return Err(TypeLookupError::InvalidMagic);
    }
    offset += 4;

    let version = payload[offset];
    offset += 1;
    if version != TYPE_LOOKUP_VERSION {
        return Err(TypeLookupError::UnsupportedVersion(version));
    }

    let kind = payload[offset];
    offset += 1;
    if kind != TYPE_LOOKUP_KIND_REQUEST && kind != TYPE_LOOKUP_KIND_RESPONSE {
        return Err(TypeLookupError::InvalidKind(kind));
    }

    if payload.len() < offset + 2 + 4 {
        return Err(TypeLookupError::Truncated);
    }

    offset += 2; // flags/reserved

    let name_len = u32::from_le_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ]) as usize;
    offset += 4;

    if payload.len() < offset + name_len + 4 {
        return Err(TypeLookupError::Truncated);
    }

    let name_bytes = &payload[offset..offset + name_len];
    let type_name = std::str::from_utf8(name_bytes)
        .map_err(|_| TypeLookupError::InvalidUtf8)?
        .to_string();
    offset += name_len;

    let obj_len = u32::from_le_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ]) as usize;
    offset += 4;

    if obj_len == 0 {
        return Ok(TypeLookupMessage {
            kind,
            type_name,
            type_object: None,
        });
    }

    if payload.len() < offset + obj_len {
        return Err(TypeLookupError::Truncated);
    }

    let type_object = payload[offset..offset + obj_len].to_vec();

    Ok(TypeLookupMessage {
        kind,
        type_name,
        type_object: Some(type_object),
    })
}

#[cfg(feature = "type-lookup")]
fn encode_htlk_message(
    type_name: &str,
    type_object: Option<&[u8]>,
) -> Result<Vec<u8>, TypeLookupError> {
    let name_bytes = type_name.as_bytes();
    let name_len = name_bytes.len();
    let object_len = type_object.map(|obj| obj.len()).unwrap_or(0);

    let name_len_u32 = u32::try_from(name_len).map_err(|_| TypeLookupError::Truncated)?;
    let object_len_u32 = u32::try_from(object_len).map_err(|_| TypeLookupError::Truncated)?;

    let mut buf = Vec::with_capacity(4 + 4 + name_len + object_len + 16);
    buf.extend_from_slice(&PL_CDR2_LE.to_be_bytes());
    buf.extend_from_slice(&[0u8; 2]); // options
    buf.extend_from_slice(&TYPE_LOOKUP_MAGIC);
    buf.push(TYPE_LOOKUP_VERSION);
    buf.push(if type_object.is_some() {
        TYPE_LOOKUP_KIND_RESPONSE
    } else {
        TYPE_LOOKUP_KIND_REQUEST
    });
    buf.extend_from_slice(&[0u8; 2]); // flags/reserved
    buf.extend_from_slice(&name_len_u32.to_le_bytes());
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(&object_len_u32.to_le_bytes());
    if let Some(bytes) = type_object {
        buf.extend_from_slice(bytes);
    }

    Ok(buf)
}

#[cfg(feature = "type-lookup")]
fn build_htlk_packet(
    payload: &[u8],
    participant_guid_prefix: &[u8; 12],
    destination_prefix: Option<&[u8; 12]>,
    seq_num: u64,
) -> Result<Vec<u8>, String> {
    use crate::core::discovery::multicast::rtps_packet::build_type_lookup_rtps_packet;
    build_type_lookup_rtps_packet(
        payload,
        participant_guid_prefix,
        destination_prefix,
        seq_num,
    )
    .map_err(|_| "build_type_lookup_rtps_packet failed".to_string())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // The getTypes request these parser tests read is built, from the
    // DDS-XTypes text, with the other wire fixtures of this directory:
    // `dispatch` feeds the same bytes, fragmented, to prove they reach this
    // parser at all.
    #[cfg(feature = "xtypes-structural-assignability")]
    use super::super::wire_fixtures::{
        get_types_request, GET_TYPES_FIRST_MINIMAL_HASH, GET_TYPES_REQUESTER_GUID,
        GET_TYPES_REQUEST_SN, GET_TYPES_SECOND_MINIMAL_HASH,
    };

    /// A fragmented getTypes REPLY resolves the type it was asked for.
    ///
    /// The other half of the rule that gives the two TypeLookup writers an arm
    /// in `dispatch_reassembled`. The REQUEST direction is proved by the
    /// answer, a datagram anyone can watch for on a socket. The REPLY direction leaves no packet behind: what it
    /// does is resolve a type, in memory, several correlation checks deep. So
    /// it is easy to leave unpinned, and half a rule is worth little.
    ///
    /// A TypeObject is the largest sample discovery carries, so a reply is
    /// the delivery MOST likely to arrive in fragments - which makes this the
    /// half that matters more of the two.
    ///
    /// The observable is the topic-registry generation counter, which
    /// `update_type_object_for_hash` bumps. That is the exact end of the reply
    /// path, and reaching it means every correlation check passed: the reply
    /// was named after the REPLY writer and not served as a request, its
    /// related request GUID was ours, its sequence matched the one in flight,
    /// and the TypeObject it carried hashed to the identifier it was requested
    /// under.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_fragmented_get_types_reply_resolves_the_type_it_was_asked_for() {
        use super::super::wire_fixtures::{
            a_complete_type_object, a_type_known_as, two_fragments, Harness, FRAGMENT_AT,
            OUR_PREFIX, SENDER_PREFIX, TYPELOOKUP_REPLY,
        };
        use crate::core::discovery::multicast::PacketKind;
        use crate::protocol::discovery::types::TypeIdentifierWithDependencies;
        use crate::xtypes::TypeIdentifier;

        // A real hash, computed from the object that will actually ship: the
        // reply path refuses a TypeObject that does not hash to the id it was
        // requested under, so this is not a number a fixture may invent.
        let obj = a_complete_type_object("wire_fixtures::ResolvedType");
        let hash = obj.compute_equivalence_hash().expect("a hashable type");

        // Somewhere for the outgoing request to go. Its send must SUCCEED:
        // on error `request_complete_type` drops the pending entry it just
        // made, and the reply would then have nothing to correlate against.
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
        let peer_addr = peer.local_addr().expect("the peer address");

        let h = Harness::serving_the_get_types_request();
        let service = h
            .dispatch
            .type_lookup
            .clone()
            .expect("the harness attaches a TypeLookup service");

        // Put one request in flight, for a type named in SEDP.
        service.maybe_request_omg_type_object(
            "ResolvedType",
            &TypeInformation {
                minimal: None,
                complete: Some(TypeIdentifierWithDependencies {
                    hash,
                    typeobject_serialized_size: 0,
                    dependent_typeids: Vec::new(),
                }),
            },
            Origin::direct(peer_addr),
            Some(SENDER_PREFIX),
        );
        let before = h.dispatch.fsm.topic_registry_generation();

        // The answer, from the peer's point of view: our request writer GUID,
        // and the sequence the service allocated for that first request.
        let mut related_writer = [0u8; 16];
        related_writer[..12].copy_from_slice(&OUR_PREFIX);
        related_writer[12..].copy_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
        let served = Arc::new(a_type_known_as(TypeIdentifier::Complete(hash), obj.clone()));
        let cdr = encode_omg_get_types_reply(
            &related_writer,
            0,
            1,
            &[(EK_COMPLETE, *hash.as_bytes(), served)],
        )
        .expect("encode the reply");

        let (one, two, meta_one, meta_two) = two_fragments(SENDER_PREFIX, &TYPELOOKUP_REPLY, &cdr);

        h.feed_from(
            PacketKind::TypeLookup,
            &one,
            FRAGMENT_AT,
            Some(meta_one),
            peer_addr,
        );
        assert_eq!(
            h.dispatch.fsm.topic_registry_generation(),
            before,
            "half a reply resolves nothing: a TypeObject read from one fragment \
             would not hash to the identifier it was requested under, and would \
             be refused - but it must not even be offered"
        );

        h.feed_from(
            PacketKind::TypeLookup,
            &two,
            FRAGMENT_AT,
            Some(meta_two),
            peer_addr,
        );
        assert!(
            h.dispatch.fsm.topic_registry_generation() > before,
            "the reassembled reply must reach update_type_object_for_hash"
        );
    }

    /// A SEDP whose type the TypeLookup cache already holds is resolved by
    /// it: the cached answer is applied once the endpoint is registered.
    ///
    /// A cache hit answers at once, without a request. It must be applied
    /// after the SEDP handler has registered the endpoint: applied before, it
    /// would resolve nothing, and the endpoint would stay typeless for good
    /// (no request is sent either): a second writer of an already-resolved
    /// foreign type would be judged as of unknown type, accepted where its
    /// twin had been refused.
    /// The announcement fed here is peer A's, built field by field in
    /// `type_verdict_tests`, through the dispatch every SEDP datagram takes.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_sedp_whose_type_is_cached_is_resolved_by_the_cache() {
        use super::super::wire_fixtures::{Harness, SAMPLE_AT};
        use crate::core::discovery::multicast::PacketKind;
        use crate::dds::participant::type_verdict_tests::{peer_a, peer_sedp_datagram};

        let shape = peer_a();
        let hash = shape
            .type_object
            .compute_equivalence_hash()
            .expect("a hashable type");
        let h = Harness::serving_the_get_types_request();
        let service = h
            .dispatch
            .type_lookup
            .clone()
            .expect("the harness attaches a TypeLookup service");
        // An earlier reply for this hash, as `handle_omg_get_types_reply`
        // caches it.
        service
            .resolved_types
            .write()
            .insert(hash, shape.type_object.clone(), [0x5E; 12]);
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
        let peer_addr = peer.local_addr().expect("the peer address");
        h.dispatch
            .fsm
            .handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: crate::core::discovery::GUID::new(
                    shape.sedp.participant_guid.prefix,
                    [0x00, 0x00, 0x01, 0xC1],
                ),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![peer_addr],
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

        h.feed_from(
            PacketKind::SEDP,
            &peer_sedp_datagram(),
            SAMPLE_AT,
            None,
            peer_addr,
        );

        let writer = h
            .dispatch
            .fsm
            .find_writers_for_topic("Square")
            .into_iter()
            .find(|w| w.endpoint_guid == shape.sedp.endpoint_guid)
            .expect("the SEDP registered peer A's writer");
        assert_eq!(
            writer.type_object,
            Some(shape.type_object),
            "the cached answer resolved the endpoint its hash names"
        );
    }

    /// A getTypes request captured on the wire from OpenDDS 3.34.0-dev
    /// (OpenDDS -> HDDS). OpenDDS encodes the MUTABLE
    /// member `type_ids` with LC=4 (byte-count NEXTINT, then the sequence with
    /// its own DHEADER); HDDS emits LC=5. Both are legal (DDS-XTypes v1.3
    /// sec. 7.4.3.5.3); the parser must accept both, or OpenDDS never
    /// gets a reply and never matches an HDDS reader.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn opendds_lc4_get_types_request_parses() {
        let cdr: [u8; 127] = [
            0x00, 0x07, 0x00, 0x00, 0x01, 0x03, 0xac, 0x1f, 0x6b, 0x40, 0x1c, 0x2c, 0xb9, 0x53,
            0x0f, 0xba, 0x00, 0x03, 0x00, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x31, 0x00, 0x00, 0x00, 0x64, 0x64, 0x73, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x74, 0x69,
            0x6e, 0x2e, 0x54, 0x4f, 0x53, 0x2e, 0x30, 0x31, 0x31, 0x61, 0x30, 0x61, 0x32, 0x61,
            0x30, 0x30, 0x31, 0x36, 0x39, 0x65, 0x33, 0x31, 0x34, 0x33, 0x39, 0x61, 0x36, 0x66,
            0x38, 0x62, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x63, 0x31, 0x00, 0x00, 0x00, 0x00,
            0x27, 0x00, 0x00, 0x00, 0xd3, 0x52, 0x82, 0x01, 0x1f, 0x00, 0x00, 0x00, 0x65, 0x60,
            0x53, 0x4c, 0x17, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xf1, 0x00, 0x71, 0x8e, 0x78, 0x7a, 0xc6, 0x01, 0x8e, 0x3e, 0x07, 0x0b, 0xac, 0x08,
            0xde,
        ];
        let req = parse_omg_get_types_request(&cdr).expect("OpenDDS LC=4 request must parse");
        assert_eq!(
            req.request_writer_guid,
            [
                0x01, 0x03, 0xac, 0x1f, 0x6b, 0x40, 0x1c, 0x2c, 0xb9, 0x53, 0x0f, 0xba, 0x00, 0x03,
                0x00, 0xc3
            ]
        );
        assert_eq!((req.request_seq_high, req.request_seq_low), (0, 1));
        assert_eq!(
            req.type_ids,
            vec![(
                EK_MINIMAL,
                [
                    0x00, 0x71, 0x8e, 0x78, 0x7a, 0xc6, 0x01, 0x8e, 0x3e, 0x07, 0x0b, 0xac, 0x08,
                    0xde
                ]
            )]
        );
    }

    /// LC=4 and LC=5 encodings of the same sequence member land on the same
    /// sequence DHEADER and the same member end; an LC=4 byte count that
    /// disagrees with the sequence DHEADER, or an extent past the parent, is
    /// refused.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn mutable_member_lc4_and_lc5_agree_and_refuse_bad_extents() {
        // Sequence value: DHEADER 19, count 1, one 15-byte TypeIdentifier.
        let mut seq = vec![19u8, 0, 0, 0, 1, 0, 0, 0, 0xf1];
        seq.extend_from_slice(&[0xAB; 14]);
        let id = MEMBER_ID_TYPE_IDS;
        // LC=5: NEXTINT is the sequence DHEADER itself.
        let mut lc5 = (0x5000_0000u32 | id).to_le_bytes().to_vec();
        lc5.extend_from_slice(&seq);
        // LC=4: NEXTINT = byte count of the whole value, then the value.
        let mut lc4 = (0x4000_0000u32 | id).to_le_bytes().to_vec();
        lc4.extend_from_slice(&(seq.len() as u32).to_le_bytes());
        lc4.extend_from_slice(&seq);
        for buf in [&lc5, &lc4] {
            let mut off = 0usize;
            let m = next_mutable_member(buf, &mut off, buf.len()).expect("member");
            assert_eq!(m.id, id);
            assert_eq!(off, buf.len(), "cursor ends at the member end");
            let at = sequence_dheader_at(buf, &m).expect("sequence");
            assert_eq!(&buf[at..m.end], &seq[..]);
        }
        // LC=4 whose byte count disagrees with the sequence DHEADER.
        let mut bad = lc4.clone();
        bad[8] = 18;
        let m = next_mutable_member(&bad, &mut 0, bad.len()).expect("header still reads");
        assert!(sequence_dheader_at(&bad, &m).is_none());
        // Extent past the enclosing struct: refused, not clipped.
        assert!(next_mutable_member(&lc5, &mut 0, lc5.len() - 1).is_none());
        // LC 0..=3 members are skippable but are not sequences.
        let mut lc0 = (0x0000_0123u32).to_le_bytes().to_vec();
        lc0.push(0xEE);
        let mut off = 0usize;
        let m = next_mutable_member(&lc0, &mut off, lc0.len()).expect("lc0 member");
        assert_eq!((m.id, off), (0x123, 5));
        assert!(sequence_dheader_at(&lc0, &m).is_none());
    }

    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_parse_omg_get_types_request() {
        let req = parse_omg_get_types_request(&get_types_request())
            .expect("should parse a getTypes request built from the spec");

        assert_eq!(req.request_writer_guid, GET_TYPES_REQUESTER_GUID);
        assert_eq!(req.request_seq_high, GET_TYPES_REQUEST_SN.0);
        assert_eq!(req.request_seq_low, GET_TYPES_REQUEST_SN.1);
        assert_eq!(req.type_ids.len(), 2);
        assert_eq!(req.type_ids[0].0, EK_MINIMAL);
        assert_eq!(req.type_ids[1].0, EK_MINIMAL);
        assert_eq!(req.type_ids[0].1, GET_TYPES_FIRST_MINIMAL_HASH);
        assert_eq!(req.type_ids[1].1, GET_TYPES_SECOND_MINIMAL_HASH);
    }

    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_parse_rejects_pl_cdr2_htlk() {
        // PL_CDR2_LE encap (HTLK format) must not be parsed as OMG getTypes.
        let htlk_bytes = &[0x00, 0x0b, 0x00, 0x00, b'H', b'T', b'L', b'K'];
        assert!(parse_omg_get_types_request(htlk_bytes).is_none());
    }

    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_parse_rejects_wrong_discriminant() {
        let mut payload = get_types_request();
        // Patch discriminant to 0x07a425d3 (getTypeDependencies-like value).
        // Discriminant position: encap(4) + guid(16) + sn(8) + name_len(4) + name(49) + pad(3) + DHEADER(4) = 88
        let disc_pos = 4 + 16 + 8 + 4 + 49 + 3 + 4;
        payload[disc_pos] = 0x23;
        payload[disc_pos + 1] = 0xa4;
        payload[disc_pos + 2] = 0x25;
        payload[disc_pos + 3] = 0x07;
        assert!(parse_omg_get_types_request(&payload).is_none());
    }

    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_reply_cdr_structural_headers() {
        // Encode a reply with zero pairs and check fixed-offset header fields.
        let request_guid = [0u8; 16];
        let reply = encode_omg_get_types_reply(&request_guid, 0, 42, &[])
            .expect("zero-pair reply should succeed");

        // Encapsulation header: PLAIN_CDR2_LE + options 0x0000
        assert_eq!(&reply[0..4], &[0x00, 0x07, 0x00, 0x00], "encap header");

        // ReplyHeader: relatedRequestId.writer_guid (echoed) at [4..20]
        assert_eq!(&reply[4..20], &[0u8; 16], "echoed GUID");

        // sequence_number at [20..28]: high=0, low=42
        assert_eq!(&reply[20..24], &[0u8; 4], "seq high = 0");
        assert_eq!(&reply[24..28], &[42u8, 0, 0, 0], "seq low = 42");

        // remoteEx = 0 at [28..32]
        assert_eq!(&reply[28..32], &[0u8; 4], "remoteEx = 0");

        // TypeLookup_Return discriminant at [36..40] (after DHEADER at [32..36])
        assert_eq!(
            &reply[36..40],
            &GETTYPES_OP_DISC_LE,
            "TypeLookup_Return disc"
        );

        // getTypes_Result discriminant = 0 at [44..48]
        assert_eq!(
            &reply[44..48],
            &[0u8; 4],
            "getTypes_Result disc = DDS_RETCODE_OK"
        );

        // types.length = 0 at [52..56] (after getTypes_Out DHEADER[48..52])
        // types EMHEADER[52..56] ... actually: getTypes_Out DHEADER at [48..52],
        // types EMHEADER at [52..56], types NEXTINT at [56..60], types.length at [60..64]
        assert_eq!(&reply[60..64], &[0u8; 4], "types.length = 0");
    }

    // -----------------------------------------------------------------------
    // Requesting side
    // -----------------------------------------------------------------------

    /// The `type_ids` member id is derived, not guessed: the request built
    /// from the spec computes its EMHEADER from MD5("type_ids") (DDS-XTypes
    /// 1.3 7.3.1.2.1.1) and LC=5, independently of the constant we emit.
    /// Offset in that request: encap(4) + guid(16) + sn(8) + name_len(4) +
    /// name(49) + pad(3) + Call DHEADER(4) + disc(4) + In DHEADER(4) = 96.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_type_ids_emheader_matches_the_spec_built_request() {
        assert_eq!(
            &get_types_request()[96..100],
            &EMHDR_TYPE_IDS_LE,
            "our type_ids EMHEADER must equal the one the spec gives"
        );
    }

    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_get_types_request_round_trip() {
        let guid: [u8; 16] = [
            0x01, 0x1a, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x00, 0x01, 0x00, 0x03,
            0x00, 0xc3,
        ];
        let hash_a = [0xAAu8; 14];
        let hash_b = [0xBBu8; 14];
        let cdr = encode_omg_get_types_request(
            &guid,
            7,
            9,
            &[(EK_COMPLETE, hash_a), (EK_MINIMAL, hash_b)],
        )
        .expect("encode should succeed");

        let req = parse_omg_get_types_request(&cdr).expect("our own request must parse back");
        assert_eq!(req.request_writer_guid, guid);
        assert_eq!(req.request_seq_high, 7);
        assert_eq!(req.request_seq_low, 9);
        assert_eq!(
            req.type_ids,
            vec![(EK_COMPLETE, hash_a), (EK_MINIMAL, hash_b)]
        );
    }

    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_request_encoder_rejects_empty_type_ids() {
        assert!(encode_omg_get_types_request(&[0u8; 16], 0, 1, &[]).is_none());
    }

    /// The handler tells a request from a reply by the DATA writer entity id,
    /// so both builders must stamp the entity id that dispatch expects.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_builders_stamp_the_dispatching_entity_ids() {
        use crate::protocol::builder::extract_writer_guid;

        let prefix = [0x11u8; 12];
        let peer = [0x22u8; 12];

        let request =
            build_omg_request_rtps_packet(&prefix, Some(&peer), 1, &[], &[0x00, 0x07, 0, 0]);
        let guid = extract_writer_guid(&request).expect("request must expose a writer GUID");
        assert_eq!(guid[..12], prefix, "request carries our prefix");
        assert_eq!(
            guid[12..],
            RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
            "request must come from the TypeLookup request writer"
        );

        let reply = build_omg_reply_rtps_packet(
            &prefix,
            &peer,
            1,
            &[],
            &[0u8; 16],
            0,
            1,
            &[0x00, 0x07, 0, 0],
        );
        let guid = extract_writer_guid(&reply).expect("reply must expose a writer GUID");
        assert_eq!(
            guid[12..],
            RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
            "reply must come from the TypeLookup reply writer"
        );
    }

    /// An INFO_DST-less request is still walkable: the peer prefix is optional
    /// because SEDP does not always hand one over.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_request_packet_without_info_dst() {
        use crate::protocol::builder::extract_writer_guid;

        let prefix = [0x33u8; 12];
        let request = build_omg_request_rtps_packet(&prefix, None, 5, &[], &[0x00, 0x07, 0, 0]);
        let guid = extract_writer_guid(&request).expect("writer GUID must still be found");
        assert_eq!(guid[12..], RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
    }

    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_reply_parser_rejects_a_request() {
        assert!(
            parse_omg_get_types_reply(&get_types_request()).is_none(),
            "a getTypes REQUEST must not parse as a reply"
        );
    }

    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn test_get_types_reply_round_trip() {
        use crate::core::types::{Distro, ROS_HASH_SIZE};
        use crate::xtypes::{
            CompleteEnumeratedHeader, CompleteEnumeratedType, CompleteTypeDetail,
            MinimalEnumeratedHeader, MinimalEnumeratedType, MinimalTypeDetail, MinimalTypeObject,
            TypeIdentifier,
        };

        let complete = CompleteTypeObject::Enumerated(CompleteEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: CompleteEnumeratedHeader {
                bit_bound: 32,
                detail: CompleteTypeDetail::new("RoundTrip"),
            },
            literal_seq: vec![],
        });
        let minimal = MinimalTypeObject::Enumerated(MinimalEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: MinimalEnumeratedHeader {
                bit_bound: 32,
                detail: MinimalTypeDetail::new(),
            },
            literal_seq: vec![],
        });
        let hash = [0x5Au8; 14];
        let handle = Arc::new(TypeObjectHandle::new(
            Distro::Humble,
            Arc::from("RoundTrip"),
            0,
            Arc::new([0u8; ROS_HASH_SIZE]),
            complete.clone(),
            minimal,
            TypeIdentifier::Complete(EquivalenceHash::from_bytes(hash)),
            TypeIdentifier::Minimal(EquivalenceHash::from_bytes([2u8; 14])),
        ));

        let guid = [0x7Fu8; 16];
        let cdr = encode_omg_get_types_reply(&guid, 0, 3, &[(EK_COMPLETE, hash, handle)])
            .expect("reply encode should succeed");

        let reply = parse_omg_get_types_reply(&cdr).expect("our own reply must parse back");
        assert_eq!(reply.request_writer_guid, guid);
        assert_eq!(reply.pairs.len(), 1, "one TypeObject pair expected");
        assert_eq!(reply.pairs[0].0, hash, "hash survives the round trip");
        assert_eq!(
            reply.pairs[0].1, complete,
            "the decoded TypeObject must equal the one served"
        );

        // The same reply re-encoded the ways another vendor may legally write
        // it. `types` is the LC=5 EMHEADER d1 4a 80 52; before it sit the
        // getTypes_Out DHEADER (-4), the result DHEADER (-12, discriminant at
        // -8) and the TypeLookup_Return DHEADER (-20, getTypes hash at -16).
        let e = cdr
            .windows(4)
            .position(|w| w == [0xd1, 0x4a, 0x80, 0x52])
            .expect("types EMHEADER (LC=5)");
        let word = |v: &[u8], at: usize| u32::from_le_bytes(v[at..at + 4].try_into().expect("4"));
        assert_eq!(word(&cdr, e - 16), GETTYPES_OP_DISC, "layout guard");
        let widen = |v: &mut Vec<u8>, by: u32| {
            for at in [e - 4, e - 12, e - 20] {
                let x = word(v, at) + by;
                v[at..at + 4].copy_from_slice(&x.to_le_bytes());
            }
        };

        // (a) `types` as LC=4: byte-count NEXTINT, then the sequence with its
        // own DHEADER (the former shared NEXTINT).
        let mut lc4 = cdr.clone();
        let shared = word(&lc4, e + 4);
        lc4[e + 3] = 0x42;
        lc4.splice(e + 4..e + 4, (shared + 4).to_le_bytes());
        widen(&mut lc4, 4);
        let r = parse_omg_get_types_reply(&lc4).expect("LC=4 reply parses");
        assert_eq!(r.pairs.len(), 1, "LC=4 types member is read");
        assert_eq!(r.pairs[0].1, complete);

        // (b) an unknown LC=0 member (1-byte value, 3 pad) before `types`:
        // skipped by its extent, then realigned to 4 for the next EMHEADER.
        let mut unknown = cdr.clone();
        unknown.splice(e..e, [0x23, 0x01, 0x00, 0x00, 0xEE, 0x00, 0x00, 0x00]);
        widen(&mut unknown, 8);
        let r = parse_omg_get_types_reply(&unknown).expect("reply with an unknown member");
        assert_eq!(r.pairs.len(), 1, "types found after an unknown member");
        assert_eq!(r.pairs[0].1, complete);

        // (c) LC=4 with a byte count that disagrees with the sequence DHEADER.
        let mut bad = lc4.clone();
        let x = word(&bad, e + 8) + 1;
        bad[e + 8..e + 12].copy_from_slice(&x.to_le_bytes());
        let r = parse_omg_get_types_reply(&bad).expect("header still parses");
        assert!(r.pairs.is_empty(), "inconsistent LC=4 member is refused");

        // (d) truncated inside `types`: refused, not clipped and half-read.
        let r = parse_omg_get_types_reply(&cdr[..e + 4 + 12]);
        assert!(
            r.is_none_or(|r| r.pairs.is_empty()),
            "truncated member is refused"
        );
    }

    // ------------------------------------------------------------------
    // RTPS 2.5 8.3.4 / 8.3.8.10: a relayed origin has no reply locator, and
    // the fallback for a peer this participant cannot resolve any other way
    // must never become the forwarder's own address.
    // ------------------------------------------------------------------

    /// T1: `resolve_send_addr`'s final fallback. A peer entirely unknown to
    /// the FSM, reached only through a relay, has no destination at all --
    /// not the forwarder's address.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn resolve_send_addr_gives_up_on_a_relayed_unknown_peer() {
        use super::super::wire_fixtures::Harness;

        let h = Harness::serving_the_get_types_request();
        let service = h
            .dispatch
            .type_lookup
            .clone()
            .expect("the harness attaches a TypeLookup service");
        let forwarder: SocketAddr = "203.0.113.50:9999".parse().expect("valid address");
        let unknown_peer = [0x99u8; 12];

        assert_eq!(
            service.resolve_send_addr(&unknown_peer, Origin::relayed(forwarder)),
            None,
            "a relayed forwarder must never stand in for a peer the FSM has never seen"
        );

        // RTPS 2.5 8.3.8.9 / 8.4.8.2.6: an INFO_REPLY naming another address
        // gives an unknown peer no destination, and a known one its
        // recorded locator.
        let named: std::net::SocketAddrV4 = "198.51.100.4:7999".parse().expect("addr");
        assert_eq!(
            service.resolve_send_addr(
                &unknown_peer,
                Origin::relayed(forwarder).replying_to(Some(named))
            ),
            None
        );
        let known_peer = [0x98u8; 12];
        service
            .fsm
            .handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: crate::core::discovery::GUID::new(
                    known_peer,
                    [0x00, 0x00, 0x01, 0xC1],
                ),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec!["192.0.2.98:7410".parse().expect("addr")],
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
            service.resolve_send_addr(
                &known_peer,
                Origin::direct(forwarder).replying_to(Some(named))
            ),
            Some("192.0.2.98:7410".parse().expect("addr"))
        );
    }

    /// A standalone `TypeLookupService`, for the HTLK tests below -- no
    /// `Harness`/`DiscoveryDispatch` needed, since these two paths (T2, T3)
    /// only exist under `type-lookup`, and the harness's TypeLookup wiring
    /// is behind `xtypes-structural-assignability`.
    ///
    /// The domain lease comes back with the service and must outlive it:
    /// dropped here, the domain went back to the pool while the transport
    /// still held its unicast ports, and the next test given that domain
    /// failed to bind them.
    #[cfg(feature = "type-lookup")]
    fn standalone_type_lookup_service(
    ) -> (crate::test_support::domains::DomainLease, TypeLookupService) {
        standalone_type_lookup_service_on(|_| {})
    }

    /// `standalone_type_lookup_service`, its FSM configured by `configure`.
    #[cfg(feature = "type-lookup")]
    fn standalone_type_lookup_service_on(
        configure: impl FnOnce(&mut DiscoveryFsm),
    ) -> (crate::test_support::domains::DomainLease, TypeLookupService) {
        use crate::core::discovery::GUID;
        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 0, mapping).expect("a test transport"));
        let mut fsm = DiscoveryFsm::new(GUID::new([0x11; 12], [0x00, 0x00, 0x01, 0xC1]), 30_000);
        configure(&mut fsm);
        let fsm = Arc::new(fsm);
        let service = TypeLookupService::new(
            fsm,
            transport,
            [0x11; 12],
            TypeLookupConfig {
                registered_types: Arc::new(RwLock::new(HashMap::new())),
                served_types: Arc::new(RwLock::new(HashMap::new())),
                dialect_detector: Arc::new(std::sync::Mutex::new(
                    crate::core::discovery::multicast::dialect_detector::DialectDetector::new(),
                )),
            },
        );
        (lease, service)
    }

    /// T2: the HTLK request path with NO peer prefix at all (the request's
    /// own carrier told nothing about who sent it). Relayed: no reply
    /// address to fall back to, so nothing may be sent -- and nothing
    /// invents the forwarder as a destination.
    #[cfg(feature = "type-lookup")]
    #[test]
    fn maybe_request_type_object_relayed_with_no_peer_prefix_sends_nothing() {
        let (_domain, service) = standalone_type_lookup_service();
        let forwarder = std::net::UdpSocket::bind("127.0.0.1:0").expect("forwarder socket");
        forwarder
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .expect("set timeout");
        let forwarder_addr = forwarder.local_addr().expect("forwarder address");

        service.maybe_request_type_object("Y11bT2Type", Origin::relayed(forwarder_addr), None);

        let mut buf = [0u8; 256];
        assert!(
            forwarder.recv_from(&mut buf).is_err(),
            "no peer prefix and a relayed origin: nothing must reach the forwarder"
        );
    }

    /// The direct twin of the relayed-origin test: the silence above must come from
    /// the relayed origin having no reply address, never from an unrelated
    /// early return (interop-mode gate, dedup, encode/build failure) that
    /// the relayed test alone could not tell apart from the real cause.
    /// Same fixture, only the origin changes -- and a direct one with no
    /// peer prefix at all must still be sent, to the reply address.
    #[cfg(feature = "type-lookup")]
    #[test]
    fn maybe_request_type_object_direct_with_no_peer_prefix_still_sends() {
        let (_domain, service) = standalone_type_lookup_service();
        let a = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket A");
        a.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("set timeout");
        let a_addr = a.local_addr().expect("addr A");

        service.maybe_request_type_object("Y11bT2Type", Origin::direct(a_addr), None);

        let mut buf = [0u8; 256];
        assert!(
            a.recv_from(&mut buf).is_ok(),
            "a direct request with no peer prefix must still reach the reply address"
        );
    }

    /// Regression check: a direct HTLK request must go
    /// straight to the reply address -- never through the FSM's own preference, which is the OMG
    /// getTypes SERVE path's rule (`resolve_send_addr`), not this path's.
    ///
    /// Both sockets bind on 127.0.0.1, so they share an IP: exactly the
    /// condition that would hide a wrong choice for a peer on a
    /// DIFFERENT port than its own FSM-recorded locator -- the same-IP
    /// preference would match anyway and silently redirect the request.
    #[cfg(feature = "type-lookup")]
    #[test]
    fn maybe_request_type_object_direct_ignores_the_fsm_and_uses_the_reply_address() {
        use crate::core::discovery::GUID;

        let (_domain, service) = standalone_type_lookup_service();

        let a = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket A");
        a.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("set timeout");
        let a_addr = a.local_addr().expect("addr A");

        let b = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket B");
        b.set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .expect("set timeout");
        let b_addr = b.local_addr().expect("addr B");

        const PEER: [u8; 12] = [0x22; 12];
        service
            .fsm
            .handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new(PEER, [0x00, 0x00, 0x01, 0xC1]),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![b_addr],
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

        service.maybe_request_type_object("Y11bR2Type", Origin::direct(a_addr), Some(PEER));

        let mut buf = [0u8; 256];
        assert!(
            a.recv_from(&mut buf).is_ok(),
            "the request must reach A, the reply address -- what this did before"
        );
        assert!(
            b.recv_from(&mut buf).is_err(),
            "and never B, the FSM's own record for this peer"
        );
    }

    /// Regression check: `maybe_request_type_object` must not
    /// mark a type "already requested" BEFORE resolving a destination, or a
    /// relayed attempt for a peer the FSM does not know -- which resolves to
    /// no destination and sends nothing -- would permanently poison the dedup
    /// set, and a later, perfectly resolvable DIRECT announcement of the exact
    /// same type would silently never be requested at all.
    #[cfg(feature = "type-lookup")]
    #[test]
    fn a_relayed_unknown_peer_does_not_poison_a_later_direct_request_of_the_same_type() {
        let (_domain, service) = standalone_type_lookup_service();

        let forwarder: std::net::SocketAddr = "203.0.113.90:9999".parse().expect("valid address");
        service.maybe_request_type_object("Y11bR3Type", Origin::relayed(forwarder), None);

        let a = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket A");
        a.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("set timeout");
        let a_addr = a.local_addr().expect("addr A");

        service.maybe_request_type_object("Y11bR3Type", Origin::direct(a_addr), None);

        let mut buf = [0u8; 256];
        assert!(
            a.recv_from(&mut buf).is_ok(),
            "the later direct announcement of the same type must still be requested"
        );
    }

    /// A minimal, locally-built `TypeObjectHandle` for "Y11bT3Type" -- built
    /// from plain `xtypes` types (not the `xtypes-structural-assignability`-
    /// gated wire_fixtures helpers), so this stays reachable under
    /// `type-lookup` alone.
    #[cfg(feature = "type-lookup")]
    fn served_type_handle(name: &str) -> Arc<TypeObjectHandle> {
        use crate::xtypes::{
            CompleteStructHeader, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
            MinimalStructHeader, MinimalStructType, MinimalTypeDetail, MinimalTypeObject,
            StructTypeFlag, TypeIdentifier, TypeKind,
        };
        let complete = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(name),
            },
            member_seq: Vec::new(),
        });
        let minimal = MinimalTypeObject::Struct(MinimalStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: MinimalStructHeader {
                base_type: None,
                detail: MinimalTypeDetail::new(),
            },
            member_seq: Vec::new(),
        });
        let placeholder = TypeIdentifier::primitive(TypeKind::TK_INT32);
        Arc::new(TypeObjectHandle::new(
            crate::core::types::Distro::Humble,
            Arc::<str>::from(name),
            1,
            Arc::new([0u8; crate::core::types::ROS_HASH_SIZE]),
            complete,
            minimal,
            placeholder.clone(),
            placeholder,
        ))
    }

    /// T3: the HTLK response path with NO peer prefix. Same rule as T2, on
    /// the reply side: relayed and no prefix to resolve by means no send,
    /// never one to the forwarder.
    #[cfg(feature = "type-lookup")]
    #[test]
    fn handle_htlk_request_relayed_with_no_peer_prefix_sends_nothing() {
        let (_domain, service) = standalone_type_lookup_service();
        service
            .served_types
            .write()
            .insert("Y11bT3Type".to_string(), served_type_handle("Y11bT3Type"));

        let forwarder = std::net::UdpSocket::bind("127.0.0.1:0").expect("forwarder socket");
        forwarder
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .expect("set timeout");
        let forwarder_addr = forwarder.local_addr().expect("forwarder address");

        let message = TypeLookupMessage {
            kind: TYPE_LOOKUP_KIND_REQUEST,
            type_name: "Y11bT3Type".to_string(),
            type_object: None,
        };
        service.handle_htlk_request(&message, None, Origin::relayed(forwarder_addr));

        let mut buf = [0u8; 256];
        assert!(
            forwarder.recv_from(&mut buf).is_err(),
            "no peer prefix and a relayed origin: nothing must reach the forwarder"
        );
    }

    /// The direct twin of the relayed-response test: same fixture (the registered type,
    /// the message), only the origin changes -- a direct response with no
    /// peer prefix at all must still be sent, to the reply address. Without
    /// this, the relayed test's silence could just as well come from "no
    /// local TypeObject" or an encode failure as from the relayed origin.
    #[cfg(feature = "type-lookup")]
    #[test]
    fn handle_htlk_request_direct_with_no_peer_prefix_still_sends() {
        let (_domain, service) = standalone_type_lookup_service();
        service
            .served_types
            .write()
            .insert("Y11bT3Type".to_string(), served_type_handle("Y11bT3Type"));

        let a = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket A");
        a.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("set timeout");
        let a_addr = a.local_addr().expect("addr A");

        let message = TypeLookupMessage {
            kind: TYPE_LOOKUP_KIND_REQUEST,
            type_name: "Y11bT3Type".to_string(),
            type_object: None,
        };
        service.handle_htlk_request(&message, None, Origin::direct(a_addr));

        let mut buf = [0u8; 256];
        assert!(
            a.recv_from(&mut buf).is_ok(),
            "a direct response with no peer prefix must still reach the reply address"
        );
    }

    /// (submessage ids in order, writerId and writerSN of the DATA) of one
    /// little-endian datagram.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn walk(datagram: &[u8]) -> (Vec<u8>, [u8; 4], u64) {
        let mut ids = Vec::new();
        let mut data = ([0u8; 4], 0u64);
        let mut off = 20;
        while off + 4 <= datagram.len() {
            let id = datagram[off];
            let len = usize::from(u16::from_le_bytes([datagram[off + 2], datagram[off + 3]]));
            ids.push(id);
            if id == 0x15 {
                let b = off + 4;
                let writer: [u8; 4] = datagram[b + 8..b + 12].try_into().expect("writerId");
                let high = u32::from_le_bytes(datagram[b + 12..b + 16].try_into().expect("SN"));
                let low = u32::from_le_bytes(datagram[b + 16..b + 20].try_into().expect("SN"));
                data = (writer, (u64::from(high) << 32) | u64::from(low));
            }
            if len == 0 {
                break;
            }
            off += 4 + len;
        }
        (ids, data.0, data.1)
    }

    /// Each TypeLookup writer numbers its own samples from 1 (RTPS 2.5
    /// 8.3.5.4, 8.3.8.2 writerSN). The request writer and the reply writer
    /// once drew from ONE counter: the first reply after one request went
    /// out as SN 2, with no HEARTBEAT or GAP for 1, and a reliable reply
    /// reader waited for 1 for good. Three requests, then a reply: the
    /// requests are 1, 2, 3, the reply is 1 and carries no GAP. A request
    /// de-duplicated against one in flight takes no number.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn the_first_reply_is_sequence_one_whatever_was_requested_before() {
        use super::super::wire_fixtures::{
            data_datagram, Harness, SAMPLE_AT, SENDER_PREFIX, TYPELOOKUP_REQUEST,
        };
        use crate::core::discovery::multicast::PacketKind;

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("a read timeout");
        let peer_addr = peer.local_addr().expect("the peer address");

        let h = Harness::serving_the_get_types_request();
        let service = h
            .dispatch
            .type_lookup
            .clone()
            .expect("the harness attaches a TypeLookup service");
        for i in 1..=3u8 {
            let hash = EquivalenceHash::from_bytes([i; 14]);
            service.request_complete_type(None, hash, Origin::direct(peer_addr), SENDER_PREFIX);
            // The same hash again: in flight already, no number taken.
            service.request_complete_type(None, hash, Origin::direct(peer_addr), SENDER_PREFIX);
        }
        let mut buf = [0u8; 4096];
        for expected in 1..=3u64 {
            let (n, _) = peer.recv_from(&mut buf).expect("a request");
            let (ids, writer, sn) = walk(&buf[..n]);
            assert_eq!(writer, RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
            assert_eq!(sn, expected, "requests are numbered 1, 2, 3 with no hole");
            assert!(!ids.contains(&0x08), "no GAP: nothing went to another peer");
        }

        let request = data_datagram(SENDER_PREFIX, &TYPELOOKUP_REQUEST, &get_types_request());
        h.feed_from(PacketKind::TypeLookup, &request, SAMPLE_AT, None, peer_addr);
        let (n, _) = peer.recv_from(&mut buf).expect("the reply");
        let (ids, writer, sn) = walk(&buf[..n]);
        assert_eq!(writer, RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER);
        assert_eq!(sn, 1, "the reply writer's first sample is 1");
        assert_eq!(
            ids,
            vec![0x0e, 0x09, 0x15],
            "INFO_DST, INFO_TS, DATA: no GAP"
        );
    }

    /// A governance (no handshake machine needed: the security plugins
    /// judge as soon as one is configured) that admits unauthenticated
    /// participants, protects the discovery of `Secret*` and not of the
    /// other topics.
    #[cfg(feature = "security")]
    fn governed(fsm: &mut DiscoveryFsm) {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        let rule = |expression: &str, discovery: bool| TopicRule {
            topic_expression: expression.to_string(),
            enable_discovery_protection: discovery,
            enable_liveliness_protection: false,
            enable_read_access_control: false,
            enable_write_access_control: false,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        };
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: false,
            discovery_protection_kind: ProtectionKind::Encrypt,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![rule("Secret*", true), rule("*", false)],
        })));
    }

    /// Our own endpoint of `topic`, type `type_name`, as our announcement
    /// enters our discovery.
    #[cfg(feature = "security")]
    fn our_writer(
        fsm: &DiscoveryFsm,
        our_prefix: [u8; 12],
        topic: &str,
        type_name: &str,
        entity: u8,
    ) {
        use crate::core::discovery::GUID;
        fsm.handle_sedp(crate::protocol::discovery::SedpData {
            topic_name: topic.to_string(),
            type_name: type_name.to_string(),
            participant_guid: GUID::new(our_prefix, [0, 0, 1, 0xC1]),
            endpoint_guid: GUID::new(our_prefix, [0, 0, entity, 0x02]),
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
    }

    /// DDS Security v1.1 Sec.7.4.1.7, 7.4.1.8, 9.4.1.2.6.2: the type
    /// information of an endpoint of a discovery-protected topic travels on
    /// the secure SEDP topics only, to authenticated participants. Our
    /// getTypes service does not hand the same TypeObject to a participant
    /// that has not authenticated (`DiscoveryFsm::type_lookup_serves`); it
    /// does once one of our endpoints announces the type on the regular
    /// topics, and refuses everybody before that.
    #[cfg(all(feature = "security", feature = "xtypes-structural-assignability"))]
    #[test]
    fn get_types_does_not_reveal_a_discovery_protected_type_to_an_unauthenticated_peer() {
        use super::super::wire_fixtures::{
            assert_is_a_get_types_reply_for, data_datagram, get_types_request, Harness, OUR_PREFIX,
            SAMPLE_AT, SENDER_PREFIX, TYPELOOKUP_REQUEST,
        };
        use crate::core::discovery::multicast::PacketKind;
        const SERVED: &str = "wire_fixtures::ServedType";
        let reply_to = |public_too: bool| -> Option<Vec<u8>> {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
            peer.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .expect("a read timeout");
            let h = Harness::serving_the_get_types_request_on(governed);
            our_writer(&h.dispatch.fsm, OUR_PREFIX, "SecretPlans", SERVED, 1);
            if public_too {
                our_writer(&h.dispatch.fsm, OUR_PREFIX, "PublicNews", SERVED, 2);
            }
            let request = data_datagram(SENDER_PREFIX, &TYPELOOKUP_REQUEST, &get_types_request());
            h.feed_from(
                PacketKind::TypeLookup,
                &request,
                SAMPLE_AT,
                None,
                peer.local_addr().expect("addr"),
            );
            let mut buf = [0u8; 4096];
            peer.recv_from(&mut buf)
                .ok()
                .map(|(n, _)| buf[..n].to_vec())
        };
        assert!(
            reply_to(false).is_none(),
            "a type announced on a discovery-protected topic only was handed to an \
             unauthenticated participant"
        );
        let reply = reply_to(true).expect("announced in the clear too: answered");
        assert_is_a_get_types_reply_for(&reply, SENDER_PREFIX);
    }

    /// The same rule on HDDS's own TypeLookup service (HTLK), which asks by
    /// type name.
    #[cfg(all(feature = "security", feature = "type-lookup"))]
    #[test]
    fn htlk_does_not_reveal_a_discovery_protected_type_to_an_unauthenticated_peer() {
        let answered = |public_too: bool| -> bool {
            let (_domain, service) = standalone_type_lookup_service_on(governed);
            service
                .served_types
                .write()
                .insert("SecretType".to_string(), served_type_handle("SecretType"));
            our_writer(&service.fsm, [0x11; 12], "SecretPlans", "SecretType", 1);
            if public_too {
                our_writer(&service.fsm, [0x11; 12], "PublicNews", "SecretType", 2);
            }
            let a = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket A");
            a.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .expect("set timeout");
            let message = TypeLookupMessage {
                kind: TYPE_LOOKUP_KIND_REQUEST,
                type_name: "SecretType".to_string(),
                type_object: None,
            };
            service.handle_htlk_request(
                &message,
                Some([0x33; 12]),
                Origin::direct(a.local_addr().expect("addr A")),
            );
            let mut buf = [0u8; 4096];
            a.recv_from(&mut buf).is_ok()
        };
        assert!(
            !answered(false),
            "a type announced on a discovery-protected topic only was handed to an \
             unauthenticated participant"
        );
        assert!(answered(true), "announced in the clear too: answered");
    }

    /// A reply to a second participant is preceded by a GAP for the number
    /// the first one was sent: the reply reader of the second never saw 1,
    /// and is told it never will.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_reply_to_a_second_peer_gaps_the_number_the_first_was_sent() {
        use super::super::wire_fixtures::{
            data_datagram, Harness, SAMPLE_AT, SENDER_PREFIX, TYPELOOKUP_REQUEST,
        };
        use crate::core::discovery::multicast::PacketKind;

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("a read timeout");
        let peer_addr = peer.local_addr().expect("the peer address");
        let h = Harness::serving_the_get_types_request();
        let other = [0x5A; 12];
        let mut buf = [0u8; 4096];

        for sender in [SENDER_PREFIX, other] {
            let request = data_datagram(sender, &TYPELOOKUP_REQUEST, &get_types_request());
            h.feed_from(PacketKind::TypeLookup, &request, SAMPLE_AT, None, peer_addr);
        }
        let (n, _) = peer.recv_from(&mut buf).expect("the first reply");
        assert_eq!(walk(&buf[..n]).2, 1);
        let (n, _) = peer.recv_from(&mut buf).expect("the second reply");
        let (ids, _, sn) = walk(&buf[..n]);
        assert_eq!(sn, 2);
        assert_eq!(
            ids,
            vec![0x0e, 0x08, 0x09, 0x15],
            "INFO_DST, GAP, INFO_TS, DATA"
        );
        assert_eq!(&buf[24..36], &other, "addressed to the second participant");
        // GAP [1, 1]: gapStart 1, gapList.base 2, no bitmap.
        assert_eq!(&buf[48..56], &[0, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&buf[56..64], &[0, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&buf[64..68], &[0, 0, 0, 0], "numBits 0");
    }

    /// A participant whose TypeLookup service asked a known peer for a root
    /// type `Root { Member m; }`, `Member` named by COMPLETE hash, and the
    /// replies that peer would send.
    #[cfg(feature = "xtypes-structural-assignability")]
    struct HeldRoot {
        h: super::super::wire_fixtures::Harness,
        service: Arc<TypeLookupService>,
        peer: std::net::UdpSocket,
        peer_addr: SocketAddr,
        root: CompleteTypeObject,
        root_hash: EquivalenceHash,
        member: CompleteTypeObject,
        member_hash: EquivalenceHash,
    }

    #[cfg(feature = "xtypes-structural-assignability")]
    impl HeldRoot {
        fn new() -> Self {
            use super::super::wire_fixtures::{
                a_complete_type_object, Harness, OUR_PREFIX, SENDER_PREFIX,
            };
            use crate::dds::match_notification::MatchNotificationRegistry;
            use crate::protocol::discovery::types::TypeIdentifierWithDependencies;
            use crate::xtypes::{
                CommonStructMember, CompleteMemberDetail, CompleteStructHeader,
                CompleteStructMember, CompleteStructType, CompleteTypeDetail, MemberFlag,
                StructTypeFlag, TypeIdentifier,
            };
            let member = a_complete_type_object("wire_fixtures::Member");
            let member_hash = member.compute_equivalence_hash().expect("hashable");
            let root = CompleteTypeObject::Struct(CompleteStructType {
                struct_flags: StructTypeFlag::IS_FINAL,
                header: CompleteStructHeader {
                    base_type: None,
                    detail: CompleteTypeDetail::new("wire_fixtures::Root"),
                },
                member_seq: vec![CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::Complete(member_hash),
                    },
                    detail: CompleteMemberDetail::new("m"),
                }],
            });
            let root_hash = root.compute_equivalence_hash().expect("hashable");
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
            peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("a read timeout");
            let peer_addr = peer.local_addr().expect("the peer address");
            let h = Harness::serving_the_get_types_request();
            let fsm = h.dispatch.fsm.clone();
            fsm.set_match_registry(Arc::new(MatchNotificationRegistry::new(&fsm, OUR_PREFIX)));
            fsm.handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: crate::core::discovery::GUID::new(
                    SENDER_PREFIX,
                    [0x00, 0x00, 0x01, 0xC1],
                ),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![peer_addr],
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
            let service = h
                .dispatch
                .type_lookup
                .clone()
                .expect("the harness attaches a TypeLookup service");
            service.maybe_request_omg_type_object(
                "Root",
                &TypeInformation {
                    minimal: None,
                    complete: Some(TypeIdentifierWithDependencies {
                        hash: root_hash,
                        typeobject_serialized_size: 0,
                        dependent_typeids: Vec::new(),
                    }),
                },
                Origin::direct(peer_addr),
                Some(SENDER_PREFIX),
            );
            let fixture = Self {
                h,
                service,
                peer,
                peer_addr,
                root,
                root_hash,
                member,
                member_hash,
            };
            assert_eq!(
                fixture.next_request(),
                (1, root_hash),
                "the root is asked for"
            );
            fixture
        }

        /// The next getTypes request the peer receives: (writerSN, hash).
        fn next_request(&self) -> (u64, EquivalenceHash) {
            let mut buf = [0u8; 4096];
            // HEARTBEATs may come first; the request is the datagram with a DATA.
            let (n, sn) = loop {
                let (n, _) = self.peer.recv_from(&mut buf).expect("a request");
                let (ids, writer, sn) = walk(&buf[..n]);
                if ids.contains(&0x15) {
                    assert_eq!(writer, RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
                    break (n, sn);
                }
            };
            let data_at = (20..n)
                .find(|&i| {
                    buf[i] == 0x15 && buf[i + 12..i + 16] == RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER
                })
                .expect("a DATA");
            let req =
                parse_omg_get_types_request(&buf[data_at + 24..n]).expect("a getTypes request");
            assert_eq!(req.type_ids.len(), 1);
            (sn, EquivalenceHash::from_bytes(req.type_ids[0].1))
        }

        /// The peer's reply to our request `seq`, as its reply writer's `seq`th sample.
        fn reply(&self, seq: u32, hash: EquivalenceHash, obj: &CompleteTypeObject) {
            use super::super::wire_fixtures::{
                a_type_known_as, data_datagram, OUR_PREFIX, SAMPLE_AT, SENDER_PREFIX,
                TYPELOOKUP_REPLY,
            };
            use crate::core::discovery::multicast::PacketKind;
            let mut related_writer = [0u8; 16];
            related_writer[..12].copy_from_slice(&OUR_PREFIX);
            related_writer[12..].copy_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
            let served = Arc::new(a_type_known_as(
                crate::xtypes::TypeIdentifier::Complete(hash),
                obj.clone(),
            ));
            let cdr = encode_omg_get_types_reply(
                &related_writer,
                0,
                seq,
                &[(EK_COMPLETE, *hash.as_bytes(), served)],
            )
            .expect("encode the reply");
            let mut datagram = data_datagram(SENDER_PREFIX, &TYPELOOKUP_REPLY, &cdr);
            // The reply writer's own number for it.
            datagram[40..44].copy_from_slice(&seq.to_le_bytes());
            self.h.feed_from(
                PacketKind::TypeLookup,
                &datagram,
                SAMPLE_AT,
                None,
                self.peer_addr,
            );
        }

        fn generation(&self) -> u64 {
            self.h.dispatch.fsm.topic_registry_generation()
        }
    }

    /// A reply whose type names a member type by a hash this participant
    /// has not seen is HELD, the member type is requested from the peer by
    /// the service itself, and the root is given to its endpoints only once
    /// the member's reply is in. Given at once, the pairing was judged on a
    /// type graph with a hole in it, and a refusal so made was final.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_reply_waits_for_the_member_types_it_references() {
        let f = HeldRoot::new();
        let before = f.generation();
        f.reply(1, f.root_hash, &f.root);
        assert_eq!(f.generation(), before, "held: nothing is judged yet");
        assert_eq!(
            f.next_request(),
            (2, f.member_hash),
            "the service asks the peer for the member type"
        );
        // Evicting the cached root must not lose it: the held root carries
        // its own object.
        f.service
            .resolved_types
            .write()
            .forget_peer(&super::super::wire_fixtures::SENDER_PREFIX);
        f.reply(2, f.member_hash, &f.member);
        assert!(
            f.generation() > before,
            "the member arrived: the root is released"
        );
        assert!(f.service.awaiting_dependencies.lock().is_empty());
    }

    /// The wait is bounded by the tick, not by a later event: a member type
    /// that never comes releases the root once the bound has passed, and
    /// not before.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_held_root_is_released_by_the_tick_once_the_bound_has_passed() {
        let f = HeldRoot::new();
        let before = f.generation();
        f.reply(1, f.root_hash, &f.root);
        let _ = f.next_request();
        let now = Instant::now();
        f.service.tick_at(now + AWAIT_DEPENDENCIES_BOUND / 2);
        assert_eq!(f.generation(), before, "inside the bound: still held");
        f.service
            .tick_at(now + AWAIT_DEPENDENCIES_BOUND + Duration::from_secs(1));
        assert!(f.generation() > before, "past the bound: released");
    }

    /// An endpoint's request whose reply never comes is sent again by the
    /// tick, with a new number, until `MAX_REQUEST_ATTEMPTS` sends.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn an_unanswered_request_is_retried_by_the_tick_then_given_up() {
        let f = HeldRoot::new();
        let mut now = Instant::now();
        for attempt in 2..=u64::from(MAX_REQUEST_ATTEMPTS) {
            now += GETTYPES_REQUEST_TIMEOUT + Duration::from_secs(1);
            f.service.tick_at(now);
            let (sn, hash) = f.next_request();
            assert_eq!(hash, f.root_hash);
            assert!(sn >= attempt, "a new number for each send");
        }
        now += GETTYPES_REQUEST_TIMEOUT + Duration::from_secs(1);
        f.service.tick_at(now);
        assert!(
            f.service.pending_requests.lock().is_empty(),
            "given up after the last attempt"
        );
    }

    /// A participant discovery no longer knows takes its traces with it:
    /// the cached types only it served, the writers' records of it.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_departed_peer_is_forgotten_by_the_tick() {
        use super::super::wire_fixtures::SENDER_PREFIX;
        let f = HeldRoot::new();
        f.reply(1, f.root_hash, &f.root);
        let _ = f.next_request();
        assert!(f.service.resolved_types.read().contains_key(&f.root_hash));
        assert_eq!(f.service.writers.request.tracked_peers(), 1);
        f.h.dispatch
            .fsm
            .remove_participant(crate::core::discovery::GUID::new(
                SENDER_PREFIX,
                [0x00, 0x00, 0x01, 0xC1],
            ));
        f.service.tick_at(Instant::now() + HEARTBEAT_PERIOD);
        assert!(!f.service.resolved_types.read().contains_key(&f.root_hash));
        assert_eq!(f.service.writers.request.tracked_peers(), 0);
        assert!(f.service.awaiting_dependencies.lock().is_empty());
        assert!(f.service.pending_requests.lock().is_empty());
    }

    /// The request writer HEARTBEATs a peer holding an unacknowledged
    /// request, at the locator it announced.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn the_request_writer_heartbeats_an_unacknowledged_request() {
        let f = HeldRoot::new();
        f.service.tick_at(Instant::now() + HEARTBEAT_PERIOD);
        let mut buf = [0u8; 512];
        let (n, _) = f.peer.recv_from(&mut buf).expect("a HEARTBEAT");
        assert_eq!(walk(&buf[..n]).0, vec![0x0e, 0x07], "INFO_DST, HEARTBEAT");
        let hb = 36; // after the header and the INFO_DST
        assert_eq!(
            &buf[hb + 8..hb + 12],
            &RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER
        );
        assert_eq!(
            &buf[hb + 12..hb + 20],
            &[0, 0, 0, 0, 1, 0, 0, 0],
            "firstSN 1"
        );
        assert_eq!(
            &buf[hb + 20..hb + 28],
            &[0, 0, 0, 0, 1, 0, 0, 0],
            "lastSN 1"
        );
    }

    /// A sample our reader already received is not processed twice.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_resent_request_is_not_answered_twice() {
        use super::super::wire_fixtures::{
            data_datagram, Harness, SAMPLE_AT, SENDER_PREFIX, TYPELOOKUP_REQUEST,
        };
        use crate::core::discovery::multicast::PacketKind;
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
        peer.set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .expect("a read timeout");
        let peer_addr = peer.local_addr().expect("the peer address");
        let h = Harness::serving_the_get_types_request();
        let request = data_datagram(SENDER_PREFIX, &TYPELOOKUP_REQUEST, &get_types_request());
        h.feed_from(PacketKind::TypeLookup, &request, SAMPLE_AT, None, peer_addr);
        h.feed_from(PacketKind::TypeLookup, &request, SAMPLE_AT, None, peer_addr);
        let mut buf = [0u8; 4096];
        assert!(peer.recv_from(&mut buf).is_ok(), "answered once");
        assert!(peer.recv_from(&mut buf).is_err(), "and only once");
    }
}

#[cfg(all(test, feature = "xtypes-structural-assignability"))]
#[path = "type_lookup_handler/conformance_tests.rs"]
mod conformance_tests;

#[cfg(all(test, feature = "xtypes-structural-assignability"))]
#[path = "type_lookup_handler/nested_name_collision_tests.rs"]
mod nested_name_collision_tests;
