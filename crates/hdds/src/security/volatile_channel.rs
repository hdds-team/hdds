// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The `ParticipantVolatileMessageSecure` channel (DDS Security v1.1
//! Sec.7.4.4) as the reliable pair the specification makes it: the
//! `BuiltinParticipantVolatileMessageSecureWriter` is an RTPS reliable
//! StatefulWriter and its reader a reliable StatefulReader (Sec.7.4.4.2,
//! RTPS v2.5 Sec.8.4.9.2 and Sec.8.4.12.2), with RELIABLE, KEEP_ALL and
//! VOLATILE QoS (Tables 18 and 19).
//!
//! Every submessage of the pair -- the writer's DATA, HEARTBEAT and GAP,
//! the reader's ACKNACK and NACK_FRAG -- travels protected under the
//! peer's Table 67 KxKeys (Sec.7.4.4.1, Table 17: `is_submessage_
//! protected`; Sec.8.5.1.9.2: the receiving material of this one writer is
//! the KxKey). What arrives otherwise is refused and counted.
//!
//! # The writer
//!
//! One history, one sequence-number space (Sec.7.4.4.3: `message_identity.
//! sequence_number` "incremented for each different message sent by the
//! BuiltinParticipantVolatileMessageSecureWriter"), and one [`ReaderProxy`]
//! per authenticated peer. A message is addressed to one peer
//! (`destination_participant_guid`, Sec.7.4.4.4) and kept, protected, in
//! that peer's proxy until the peer acknowledges it; every other change of
//! the history is irrelevant to that reader and is announced to it with a
//! GAP (Sec.8.4.9.2.4: "the writer sends a GAP to indicate an irrelevant
//! change"). A proxy with unacknowledged changes is sent a HEARTBEAT every
//! [`HEARTBEAT_PERIOD`]; an ACKNACK purges what it acknowledges and is
//! answered with the changes it requests, or a GAP for those not the
//! reader's. Nothing is ever resent on a timer of its own: what repairs a
//! loss is the reader's request, as RTPS has it.
//!
//! # The reader
//!
//! One [`WriterProxy`] per peer: what was delivered in order, what arrived
//! ahead of it (bounded by [`READER_WINDOW`]), what the writer declared
//! irrelevant. New changes are inspected in sequence-number order, while
//! deferred ones remain missing until installation or a bounded refusal.
//! Later builtin keys can therefore unblock discovery. A
//! HEARTBEAT is answered with an ACKNACK naming what is missing (none, and
//! the Final flag set, when nothing is).
//!
//! # Sessions
//!
//! Both proxies of a peer are bound to the KxKeys they were built under (a
//! digest of them, never the keys). A peer that authenticates again holds
//! other KxKeys: what was protected under the old ones can no longer be
//! read by anyone, so both proxies start over, and the writer's owner
//! re-announces what the peer must hold ([`WriterState::take_resets`]).

use crate::core::discovery::GUID;
use crate::core::rtps_constants::{
    HDDS_VENDOR_ID, RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
    RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER, RTPS_MAGIC,
    RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR,
};
use crate::security::crypto::data_keys::{DataKeyStore, WriterKey};
use crate::security::crypto::secure_submessage::{
    encode_datareader_submessage, encode_datawriter_submessage, WriterKeyMaterial,
};
use crate::security::crypto::volatile::{is_reader_entity_id, is_writer_entity_id, GUID_UNKNOWN};
use crate::security::SecurityError;
use parking_lot::Mutex;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Changes one reader proxy holds unacknowledged at most. Table 18 asks
/// for KEEP_ALL, and KEEP_ALL is bounded by RESOURCE_LIMITS (DDS v1.4
/// Sec.2.2.3.19): past this a new change is refused -- the writer's owner
/// offers it again later, once acknowledgements have freed room -- and an
/// unacknowledged one is never dropped.
pub(crate) const MAX_UNACKED_PER_READER: usize = 256;

/// Period of the HEARTBEAT a reader proxy with unacknowledged changes is
/// sent (RTPS v2.5 Sec.8.4.7.2 `heartbeatPeriod`).
pub(crate) const HEARTBEAT_PERIOD: Duration = Duration::from_secs(1);

/// How far past its last in-order change a writer proxy buffers what
/// arrives out of order, and the most sequence numbers one ACKNACK asks
/// for (a SequenceNumberSet holds 256 at most, RTPS v2.5 Sec.9.4.2.6).
pub(crate) const READER_WINDOW: i64 = 256;

/// Largest RTPS message the channel builds; a reply that would exceed it
/// goes out as several.
const MAX_MESSAGE_LEN: usize = 8 * 1024;

const ACKNACK_ID: u8 = 0x06;
const HEARTBEAT_ID: u8 = 0x07;
const GAP_ID: u8 = 0x08;
const NACK_FRAG_ID: u8 = 0x12;
const FLAG_E: u8 = 0x01;
const FLAG_F: u8 = 0x02;
const ENTITYID_UNKNOWN: [u8; 4] = [0; 4];
const VOLATILE_WRITER: [u8; 4] = RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER;
const VOLATILE_READER: [u8; 4] = RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER;

/// A digest of the KxKeys a proxy was built under
/// (`WriterKeyMaterial::fingerprint`).
pub(crate) type Session = [u8; 32];

// ---------------------------------------------------------------------------
//  Statistics
// ---------------------------------------------------------------------------

/// Counters of the volatile channel, monotonic, across every peer.
#[derive(Debug, Default)]
pub(crate) struct VolatileStats {
    /// A clear (unprotected) DATA of the volatile endpoints: the topic is
    /// submessage-protected, so nothing of it is read in clear.
    clear_refused: AtomicU64,
    /// A submessage that opened under a peer's KxKeys and is not one of
    /// the volatile endpoints' own: the Kx material protects nothing else.
    foreign_submessage_refused: AtomicU64,
    /// A submessage under the KxKeys' key id that did not open under them.
    undecodable: AtomicU64,
    /// A message whose `destination_participant_guid` is neither
    /// GUID_UNKNOWN nor this participant (Sec.7.4.4.4).
    misaddressed_participant_refused: AtomicU64,
    /// A DATA the reader already had, or already knew irrelevant.
    duplicates_dropped: AtomicU64,
    /// A DATA the writer sent again, at a reader's request.
    data_retransmitted: AtomicU64,
    /// A write or deferred-token admission refused by resource limits.
    refused_full: AtomicU64,
    /// CryptoTokens refused for their `destination_endpoint_guid`
    /// (Sec.7.4.4.6.2-3): GUID_UNKNOWN, another participant, an endpoint
    /// of the wrong kind or of no existence here, or a builtin endpoint
    /// other than the mirror of the source.
    misaddressed_endpoint_refused: AtomicU64,
    /// Deferred DATA consumed after its installation deadline expired.
    pending_expired: AtomicU64,
    /// Deferred tokens consumed because their source endpoint was removed.
    pending_source_removed: AtomicU64,
    /// A submessage this participant sealed, received back under a peer's
    /// prefix: the KxKeys are one material for both directions, so it
    /// opens, and only its SessionId says whose it is.
    reflection_refused: AtomicU64,
}

macro_rules! counters {
    ($($field:ident => $note:ident),* $(,)?) => {
        impl VolatileStats {
            $(
                pub(crate) fn $note(&self) {
                    self.$field.fetch_add(1, Ordering::Relaxed);
                }

                // Read by operators and tests, not by the protocol.
                #[allow(dead_code)]
                pub(crate) fn $field(&self) -> u64 {
                    self.$field.load(Ordering::Relaxed)
                }
            )*
        }
    };
}

counters! {
    clear_refused => note_clear_refused,
    foreign_submessage_refused => note_foreign_submessage_refused,
    undecodable => note_undecodable,
    misaddressed_participant_refused => note_misaddressed_participant,
    duplicates_dropped => note_duplicate,
    data_retransmitted => note_retransmitted,
    refused_full => note_refused_full,
    misaddressed_endpoint_refused => note_misaddressed_endpoint,
    pending_expired => note_pending_expired,
    pending_source_removed => note_pending_source_removed,
    reflection_refused => note_reflection_refused,
}

// ---------------------------------------------------------------------------
//  The channel
// ---------------------------------------------------------------------------

/// The local endpoints of this participant and what each is matched with:
/// what the CryptoTokens of a USER endpoint are addressed by and checked
/// against (DDS Security v1.1 Sec.7.4.4.6.2-3).
pub(crate) trait LocalEndpoints: Send + Sync {
    /// The remote endpoints the local endpoint `local` is matched with, or
    /// `None` when `local` is no endpoint of this participant.
    fn matched_with(&self, local: &GUID) -> Option<Vec<GUID>>;

    /// A new value on each match event, including an unmatch followed by a
    /// match between distribution sweeps. Repeated announcements keep it.
    fn match_generation(&self, local: &GUID, remote: &GUID) -> Option<u64> {
        self.matched_with(local)?.contains(remote).then_some(0)
    }
}

/// The participant's match registry, through its discovery FSM, held
/// weakly: the FSM holds the security suite this hangs off.
impl LocalEndpoints for std::sync::Weak<crate::core::discovery::multicast::DiscoveryFsm> {
    fn matched_with(&self, local: &GUID) -> Option<Vec<GUID>> {
        self.upgrade()?.local_endpoint_matches(local)
    }

    fn match_generation(&self, local: &GUID, remote: &GUID) -> Option<u64> {
        self.upgrade()?
            .local_endpoint_match_generation(local, remote)
    }
}

/// How long the CryptoTokens of a remote USER endpoint, addressed to a real
/// local endpoint of the right kind that is not (yet) matched with it, are
/// held for that match. The tokens are written once the sender has matched
/// the destination; the destination's participant matches the sender's
/// endpoint on its own discovery, which can come second.
pub(crate) const PENDING_MATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// CryptoTokens held for a match at most, across every peer.
pub(crate) const MAX_PENDING_TOKENS: usize = 256;

/// One peer cannot consume the entire shared hold capacity.
pub(crate) const MAX_PENDING_PER_PEER: usize = 64;

/// The verdict on a CryptoTokens message's `destination_endpoint_guid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Addressing {
    /// An endpoint of this participant matched with the source.
    Matched,
    /// An endpoint of this participant, of the kind the source addresses,
    /// not matched with it yet.
    NotYetMatched,
    /// Anything else: refused.
    Refused,
}

/// The CryptoTokens of the remote endpoint `source`, addressed to the
/// local endpoint `destination`, held until the two match.
pub(crate) struct PendingTokens {
    pub(crate) peer: [u8; 12],
    pub(crate) session: Session,
    pub(crate) order: i64,
    pub(crate) writer_sn: i64,
    pub(crate) source: GUID,
    pub(crate) destination: GUID,
    pub(crate) key_id: u64,
    pub(crate) key: WriterKey,
    pub(crate) deadline: Instant,
}

/// The channel's state, one per participant (`SecurityPluginSuite::volatile`).
#[derive(Default)]
pub(crate) struct VolatileChannel {
    pub(crate) stats: VolatileStats,
    pub(crate) writer: Mutex<WriterState>,
    pub(crate) reader: Mutex<ReaderState>,
    endpoints: OnceLock<Box<dyn LocalEndpoints>>,
    pending: Mutex<Vec<PendingTokens>>,
    installed: Mutex<HashMap<GUID, (Session, i64)>>,
    token_refresh_epoch: OnceLock<Instant>,
}

impl std::fmt::Debug for VolatileChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolatileChannel")
            .field("stats", &self.stats)
            .field("writer", &self.writer)
            .field("reader", &self.reader)
            .field("pending", &self.pending.lock().len())
            .finish_non_exhaustive()
    }
}

impl VolatileChannel {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Where the local endpoints and their matches are read from. Set
    /// once; a second call is ignored.
    pub(crate) fn set_local_endpoints(&self, endpoints: Box<dyn LocalEndpoints>) {
        let _ = self.endpoints.set(endpoints);
    }

    /// Forget both proxies of every peer not in `authenticated`, and the
    /// tokens held from it: its KxKeys are gone, so nothing protected under
    /// them can be read or repaired any more.
    pub(crate) fn retain_peers(&self, authenticated: &HashSet<[u8; 12]>) {
        self.writer.lock().retain_peers(authenticated);
        self.reader.lock().retain_peers(authenticated);
        self.pending
            .lock()
            .retain(|held| authenticated.contains(&held.peer));
        self.installed
            .lock()
            .retain(|source, _| authenticated.contains(&source.prefix));
    }

    /// The endpoints of `peer` the CryptoTokens of the local USER endpoint
    /// `source` are addressed to: each one it is matched with, of the
    /// opposite kind (Sec.7.4.4.6.2: a DataWriter's to the matched
    /// DataReader; Sec.7.4.4.6.3: a DataReader's to the matched
    /// DataWriter), one message each.
    pub(crate) fn user_destinations(&self, source: &GUID, peer: &[u8; 12]) -> Vec<GUID> {
        let Some(endpoints) = self.endpoints.get() else {
            return Vec::new();
        };
        let source_is_reader = is_reader_entity_id(source.entity_id);
        let mut destinations: Vec<GUID> = endpoints
            .matched_with(source)
            .unwrap_or_default()
            .into_iter()
            .filter(|remote| {
                remote.prefix == *peer
                    && if source_is_reader {
                        is_writer_entity_id(remote.entity_id)
                    } else {
                        is_reader_entity_id(remote.entity_id)
                    }
            })
            .collect();
        destinations.sort_unstable_by_key(GUID::as_bytes);
        destinations
    }

    /// USER tokens have an application-level lifetime at the receiver. A
    /// receiver-only late match does not notify the sender: while a pair
    /// stays matched, fresh messages periodically offer its material again.
    /// Lost DATA is still repaired by RTPS with its original identity.
    pub(crate) fn token_refresh_generation(&self, now: Instant) -> u64 {
        let epoch = self.token_refresh_epoch.get_or_init(|| now);
        now.saturating_duration_since(*epoch).as_secs() / PENDING_MATCH_TIMEOUT.as_secs()
    }

    /// The match event that owes a fresh token even when its key is unchanged.
    pub(crate) fn match_generation(&self, source: &GUID, destination: &GUID) -> Option<u64> {
        self.endpoints.get()?.match_generation(source, destination)
    }

    /// A SEDP dispose/unregister makes held tokens from this source obsolete.
    /// Consume their DATA under the same reader/pending lock order as receipt.
    pub(crate) fn retire_source(&self, source: GUID) {
        let mut reader = self.reader.lock();
        let mut pending = self.pending.lock();
        pending.retain(|tokens| {
            if tokens.source != source {
                return true;
            }
            reader.accept_deferred(tokens.peer, tokens.session, tokens.writer_sn);
            self.stats.note_pending_source_removed();
            false
        });
    }

    /// A remote endpoint that announced its deletion: the key material its
    /// CryptoTokens installed goes, as the CryptoKeyFactory unregister
    /// operations release it (DDS Security v1.1 Sec.8.5.1.7), and its
    /// installation record with it. Under the lock `install_tokens` takes,
    /// so that no token installed in between survives the removal.
    pub(crate) fn forget_source_keys(&self, data_keys: &DataKeyStore, source: GUID) {
        let mut installed = self.installed.lock();
        installed.remove(&source);
        data_keys.remove_writer(&source);
    }

    /// Sec.7.4.4.6.2-3 on receipt, for the CryptoTokens of the remote USER
    /// endpoint `source` addressed to `destination`: it must name an
    /// endpoint of this participant (`our_prefix`), of the kind `source`
    /// addresses (a writer's tokens a reader, a reader's a writer), matched
    /// with `source`.
    pub(crate) fn user_addressing(
        &self,
        our_prefix: &[u8; 12],
        source: &GUID,
        destination: &[u8; 16],
    ) -> Addressing {
        if *destination == GUID_UNKNOWN {
            return Addressing::Refused;
        }
        let destination = GUID::from_bytes(*destination);
        let right_kind = if is_writer_entity_id(source.entity_id) {
            is_reader_entity_id(destination.entity_id)
        } else if is_reader_entity_id(source.entity_id) {
            is_writer_entity_id(destination.entity_id)
        } else {
            false
        };
        if destination.prefix != *our_prefix || !right_kind {
            return Addressing::Refused;
        }
        match self
            .endpoints
            .get()
            .and_then(|endpoints| endpoints.matched_with(&destination))
        {
            None => Addressing::Refused,
            Some(matched) if matched.contains(source) => Addressing::Matched,
            Some(_) => Addressing::NotYetMatched,
        }
    }

    /// A session transition invalidates every deferred token of that peer.
    pub(crate) fn reset_pending(&self, peer: [u8; 12]) {
        self.pending.lock().retain(|tokens| tokens.peer != peer);
        self.installed
            .lock()
            .retain(|source, _| source.prefix != peer);
    }

    /// Hold without acknowledging. Retransmissions neither duplicate an
    /// entry nor extend its deadline; resource limits apply per peer too.
    pub(crate) fn hold(&self, tokens: PendingTokens) -> bool {
        let mut pending = self.pending.lock();
        if pending.iter().any(|held| {
            held.peer == tokens.peer && held.session == tokens.session && held.order == tokens.order
        }) {
            return true;
        }
        if pending.len() >= MAX_PENDING_TOKENS
            || pending
                .iter()
                .filter(|held| held.peer == tokens.peer)
                .count()
                >= MAX_PENDING_PER_PEER
        {
            self.stats.note_refused_full();
            return false;
        }
        pending.push(tokens);
        true
    }

    /// Only a newer identity in the active generation may replace material
    /// of this endpoint. Other endpoints have independent installation order.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn install_tokens(
        &self,
        data_keys: &DataKeyStore,
        source: GUID,
        session: Session,
        order: i64,
        key_id: u64,
        key: WriterKey,
    ) -> Option<bool> {
        let mut installed = self.installed.lock();
        if installed
            .get(&source)
            .is_some_and(|(seen_session, seen_order)| {
                *seen_session == session && *seen_order >= order
            })
        {
            return Some(false);
        }
        match data_keys.insert(source, key_id, key) {
            Ok(()) => {
                installed.insert(source, (session, order));
                Some(true)
            }
            Err(e) => {
                log::warn!(
                    "[security::volatile] endpoint tokens refused by key store: {}",
                    e
                );
                None
            }
        }
    }

    /// Retry under the authentication lease, then the reader and pending
    /// locks, just like receive. Processing in place counts every entry
    /// against capacity, including the one whose match is being checked.
    /// A received DATA can be consumed with a counted application refusal:
    /// RTPS reception is independent of token installation (Sec.7.4.4.2).
    /// Expiry bounds the acknowledgement hole, including resource refusals
    /// with no held copy. A new match event owes a fresh message.
    pub(crate) fn retry_pending(
        &self,
        data_keys: &DataKeyStore,
        handshakes: &crate::security::handshake::HandshakeMachine,
        now: Instant,
    ) -> usize {
        let peers = handshakes.authenticated_peer_prefixes();
        let mut installed = 0;
        for peer in peers {
            let _ = handshakes.with_volatile_key_material(&peer, |material| {
                let session = material.fingerprint();
                let mut reader = self.reader.lock();
                let mut pending = self.pending.lock();
                let mut i = 0;
                while i < pending.len() {
                    let tokens = &pending[i];
                    if tokens.peer != peer {
                        i += 1;
                        continue;
                    }
                    if tokens.session != session {
                        pending.remove(i);
                        continue;
                    }
                    let superseded = self.installed.lock().get(&tokens.source).is_some_and(
                        |(seen_session, seen_order)| {
                            *seen_session == session && *seen_order >= tokens.order
                        },
                    );
                    if superseded {
                        let tokens = pending.remove(i);
                        reader.accept_deferred(peer, session, tokens.writer_sn);
                        continue;
                    }
                    let deadline = reader
                        .writers
                        .get(&peer)
                        .filter(|proxy| proxy.session == session)
                        .and_then(|proxy| proxy.deferred.get(&tokens.writer_sn))
                        .map_or(tokens.deadline, |(_, deadline)| {
                            tokens.deadline.min(*deadline)
                        });
                    if now >= deadline {
                        self.stats.note_pending_expired();
                        let tokens = pending.remove(i);
                        reader.accept_deferred(peer, session, tokens.writer_sn);
                        continue;
                    }
                    let matched = self
                        .endpoints
                        .get()
                        .and_then(|endpoints| endpoints.matched_with(&tokens.destination))
                        .is_some_and(|matched| matched.contains(&tokens.source));
                    if !matched {
                        i += 1;
                        continue;
                    }
                    let tokens = pending.remove(i);
                    if let Some(did_install) = self.install_tokens(
                        data_keys,
                        tokens.source,
                        session,
                        tokens.order,
                        tokens.key_id,
                        tokens.key,
                    ) {
                        installed += usize::from(did_install);
                        reader.accept_deferred(peer, session, tokens.writer_sn);
                    }
                }
                reader.expire_deferred(peer, session, now, &self.stats);
            });
        }
        installed
    }

    /// Tokens held for a match.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn pending(&self) -> usize {
        self.pending.lock().len()
    }
}

// ---------------------------------------------------------------------------
//  Wire: control submessages
// ---------------------------------------------------------------------------

/// A control submessage of the volatile pair, as one opened under the
/// KxKeys reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Control {
    /// HEARTBEAT (RTPS v2.5 Sec.8.3.7.5) of the volatile writer.
    Heartbeat {
        first: i64,
        last: i64,
        count: u32,
        final_flag: bool,
    },
    /// GAP (Sec.8.3.7.4) of the volatile writer: every sequence number in
    /// `[start, list_base)` and every member of `list` is irrelevant.
    Gap {
        start: i64,
        list_base: i64,
        list: Vec<i64>,
    },
    /// ACKNACK (Sec.8.3.7.1) of the volatile reader: everything below
    /// `base` received, every member of `requested` missing.
    AckNack {
        base: i64,
        requested: Vec<i64>,
        count: u32,
    },
    /// NACK_FRAG (Sec.8.3.7.6) of the volatile reader for change `sn`.
    NackFrag { sn: i64, count: u32 },
}

/// A little cursor over one submessage, in the endianness its E flag
/// names.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    le: bool,
}

impl<'a> Cursor<'a> {
    fn u32(&mut self) -> Option<u32> {
        let b: [u8; 4] = self.bytes.get(self.at..self.at + 4)?.try_into().ok()?;
        self.at += 4;
        Some(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    fn entity(&mut self) -> Option<[u8; 4]> {
        let b: [u8; 4] = self.bytes.get(self.at..self.at + 4)?.try_into().ok()?;
        self.at += 4;
        Some(b)
    }

    /// SequenceNumber_t (RTPS v2.5 Sec.9.4.2.5): high (signed), low.
    fn sn(&mut self) -> Option<i64> {
        let high = i32::from_le_bytes(self.u32()?.to_le_bytes());
        let low = self.u32()?;
        Some((i64::from(high) << 32) | i64::from(low))
    }

    /// The members of a bitmap of `num_bits` bits over `base` (Sec.9.4.2.6:
    /// bit `i` is `bitmap[i / 32] & (1 << (31 - i % 32))`).
    fn bitmap(&mut self, base: i64) -> Option<Vec<i64>> {
        let num_bits = self.u32()?;
        if num_bits > 256 {
            return None;
        }
        let words = num_bits.div_ceil(32);
        let mut members = Vec::new();
        for w in 0..words {
            let word = self.u32()?;
            for bit in 0..32 {
                let i = w * 32 + bit;
                if i < num_bits && word & (1u32 << (31 - bit)) != 0 {
                    members.push(base.checked_add(i64::from(i))?);
                }
            }
        }
        Some(members)
    }
}

/// Read `submessage` (one complete RTPS submessage, header included, as it
/// opened under the KxKeys) as a control submessage of the volatile pair:
/// HEARTBEAT and GAP from the volatile writer (readerId the volatile
/// reader or `ENTITYID_UNKNOWN`), ACKNACK and NACK_FRAG from the volatile
/// reader to the volatile writer. `None` for anything else.
#[must_use]
pub(crate) fn parse_control(submessage: &[u8]) -> Option<Control> {
    let head = submessage.get(..4)?;
    let le = head[1] & FLAG_E != 0;
    let final_flag = head[1] & FLAG_F != 0;
    let declared = usize::from(if le {
        u16::from_le_bytes([head[2], head[3]])
    } else {
        u16::from_be_bytes([head[2], head[3]])
    });
    let end = if declared == 0 {
        submessage.len()
    } else {
        4usize.checked_add(declared)?
    };
    let body = submessage.get(..end)?;
    let mut c = Cursor {
        bytes: body,
        at: 4,
        le,
    };
    let reader = c.entity()?;
    let writer = c.entity()?;
    if writer != VOLATILE_WRITER {
        return None;
    }
    let from_writer = reader == VOLATILE_READER || reader == ENTITYID_UNKNOWN;
    match head[0] {
        HEARTBEAT_ID if from_writer => {
            let first = c.sn()?;
            let last = c.sn()?;
            let count = c.u32()?;
            Some(Control::Heartbeat {
                first,
                last,
                count,
                final_flag,
            })
        }
        GAP_ID if from_writer => {
            let start = c.sn()?;
            let list_base = c.sn()?;
            let list = c.bitmap(list_base)?;
            Some(Control::Gap {
                start,
                list_base,
                list,
            })
        }
        ACKNACK_ID if reader == VOLATILE_READER => {
            let base = c.sn()?;
            let requested = c.bitmap(base)?;
            let count = c.u32()?;
            Some(Control::AckNack {
                base,
                requested,
                count,
            })
        }
        NACK_FRAG_ID if reader == VOLATILE_READER => {
            let sn = c.sn()?;
            // FragmentNumberSet: base, numBits, bitmap; only its length
            // matters here (a fragment of a change is answered with the
            // whole change, below).
            let _base = c.u32()?;
            let num_bits = c.u32()?;
            if num_bits > 256 {
                return None;
            }
            for _ in 0..num_bits.div_ceil(32) {
                c.u32()?;
            }
            let count = c.u32()?;
            Some(Control::NackFrag { sn, count })
        }
        _ => None,
    }
}

/// The members of `members` as a bitmap over `base`: `(num_bits, words)`,
/// the members past `base + 255` left out (the caller sends them in a
/// further set).
fn bitmap_of(base: i64, members: &[i64]) -> (u32, Vec<u32>) {
    let offsets: Vec<u32> = members
        .iter()
        .filter_map(|sn| u32::try_from(sn.checked_sub(base)?).ok())
        .filter(|o| *o < 256)
        .collect();
    let num_bits = offsets.iter().max().map_or(0, |o| o + 1);
    let mut words = vec![0u32; num_bits.div_ceil(32) as usize];
    for o in offsets {
        words[(o / 32) as usize] |= 1u32 << (31 - o % 32);
    }
    (num_bits, words)
}

fn as_wire_sn(sn: i64) -> u64 {
    u64::try_from(sn).unwrap_or(0)
}

/// GAP submessages declaring every member of `irrelevant` (sorted,
/// deduplicated) irrelevant: a run starting at the first member, then
/// whatever of the rest fits a 256-bit list, as many GAPs as it takes.
fn gaps(irrelevant: &[i64]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = irrelevant;
    while let Some(&start) = rest.first() {
        let mut run_end = start;
        let mut used = 1;
        while rest.get(used) == Some(&(run_end + 1)) {
            run_end += 1;
            used += 1;
        }
        let list_base = run_end + 1;
        let tail: Vec<i64> = rest[used..]
            .iter()
            .copied()
            .take_while(|sn| *sn < list_base + 256)
            .collect();
        used += tail.len();
        let (num_bits, words) = bitmap_of(list_base, &tail);
        if let Ok(gap) = crate::protocol::rtps::encode_gap(
            &VOLATILE_READER,
            &VOLATILE_WRITER,
            as_wire_sn(start),
            as_wire_sn(list_base),
            num_bits,
            &words,
        ) {
            out.push(gap);
        }
        rest = &rest[used..];
    }
    out
}

/// One GAP declaring the contiguous range `[from, to]` irrelevant.
fn gap_range(from: i64, to: i64) -> Option<Vec<u8>> {
    crate::protocol::rtps::encode_gap(
        &VOLATILE_READER,
        &VOLATILE_WRITER,
        as_wire_sn(from),
        as_wire_sn(to + 1),
        0,
        &[],
    )
    .ok()
}

fn heartbeat(first: i64, last: i64, count: u32) -> Option<Vec<u8>> {
    crate::protocol::rtps::encode_heartbeat(
        &VOLATILE_READER,
        &VOLATILE_WRITER,
        as_wire_sn(first),
        as_wire_sn(last),
        count,
    )
    .ok()
}

/// RTPS messages from `local` to `peer` carrying `protected` (each already
/// a SEC_PREFIX/SEC_BODY/SEC_POSTFIX triple), in order, split so none
/// exceeds [`MAX_MESSAGE_LEN`]: the header, INFO_DST naming the peer, an
/// INFO_TS when `timestamped`, then the submessages.
fn messages(
    local: &[u8; 12],
    peer: &[u8; 12],
    timestamped: bool,
    protected: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let head = || {
        let mut m = Vec::with_capacity(MAX_MESSAGE_LEN);
        m.extend_from_slice(RTPS_MAGIC);
        m.push(RTPS_VERSION_MAJOR);
        m.push(RTPS_VERSION_MINOR);
        m.extend_from_slice(&HDDS_VENDOR_ID);
        m.extend_from_slice(local);
        m.extend_from_slice(&crate::protocol::rtps::encode_info_dst(peer));
        if timestamped {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let sec = u32::try_from(now.as_secs()).unwrap_or(u32::MAX);
            let frac = u32::try_from(u64::from(now.subsec_nanos()) * 0x1_0000_0000 / 1_000_000_000)
                .unwrap_or(u32::MAX);
            m.extend_from_slice(&crate::protocol::rtps::encode_info_ts(sec, frac));
        }
        m
    };
    let mut out = Vec::new();
    let mut current = head();
    let empty_len = current.len();
    for sub in protected {
        if current.len() > empty_len && current.len() + sub.len() > MAX_MESSAGE_LEN {
            out.push(std::mem::replace(&mut current, head()));
        }
        current.extend_from_slice(&sub);
    }
    if current.len() > empty_len {
        out.push(current);
    }
    out
}

// ---------------------------------------------------------------------------
//  The writer
// ---------------------------------------------------------------------------

/// Why [`WriterState::write`] did not take a change.
#[derive(Debug)]
pub(crate) enum WriteRefusal {
    /// The reader's proxy holds [`MAX_UNACKED_PER_READER`] unacknowledged
    /// changes.
    Full,
    /// The change could not be built.
    Seal(SecurityError),
}

/// What the writer keeps about one matched (authenticated) reader.
#[derive(Debug)]
struct ReaderProxy {
    session: Session,
    /// Changes for this reader it has not acknowledged, each the protected
    /// DATA it was sent as.
    unacked: BTreeMap<i64, Vec<u8>>,
    /// Every sequence number up to here was sent to this reader, as a
    /// DATA or inside a GAP.
    announced_through: i64,
    last_acknack: Option<u32>,
    last_nack_frag: Option<u32>,
    next_heartbeat: Instant,
}

impl ReaderProxy {
    fn new(session: Session, now: Instant) -> Self {
        Self {
            session,
            unacked: BTreeMap::new(),
            announced_through: 0,
            last_acknack: None,
            last_nack_frag: None,
            next_heartbeat: now + HEARTBEAT_PERIOD,
        }
    }
}

/// The `BuiltinParticipantVolatileMessageSecureWriter` (module docs).
#[derive(Debug)]
pub(crate) struct WriterState {
    next_sn: i64,
    heartbeat_count: u32,
    readers: HashMap<[u8; 12], ReaderProxy>,
    /// Peers whose proxy started over since the owner last asked.
    resets: HashSet<[u8; 12]>,
}

impl Default for WriterState {
    fn default() -> Self {
        Self {
            next_sn: 1,
            heartbeat_count: 0,
            readers: HashMap::new(),
            resets: HashSet::new(),
        }
    }
}

impl WriterState {
    /// The proxy of `peer`, built (or rebuilt, when the peer's KxKeys
    /// changed) for `session`.
    fn proxy(&mut self, peer: [u8; 12], session: Session, now: Instant) -> &mut ReaderProxy {
        match self.readers.entry(peer) {
            Entry::Occupied(occupied) => {
                let proxy = occupied.into_mut();
                if proxy.session != session {
                    self.resets.insert(peer);
                    *proxy = ReaderProxy::new(session, now);
                }
                proxy
            }
            Entry::Vacant(vacant) => vacant.insert(ReaderProxy::new(session, now)),
        }
    }

    /// Bind `peer`'s proxy to `session`; a proxy built under other KxKeys
    /// starts over, and the peer is reported by [`Self::take_resets`].
    pub(crate) fn sync_session(&mut self, peer: [u8; 12], session: Session, now: Instant) {
        let _ = self.proxy(peer, session, now);
    }

    /// The peers whose proxy started over since the last call: what was
    /// announced to them must be announced again.
    pub(crate) fn take_resets(&mut self) -> HashSet<[u8; 12]> {
        std::mem::take(&mut self.resets)
    }

    pub(crate) fn retain_peers(&mut self, authenticated: &HashSet<[u8; 12]>) {
        self.readers.retain(|peer, _| authenticated.contains(peer));
    }

    /// The last sequence number written, whoever it was for.
    fn last_sn(&self) -> i64 {
        self.next_sn - 1
    }

    fn next_heartbeat_count(&mut self) -> u32 {
        self.heartbeat_count = self.heartbeat_count.wrapping_add(1);
        self.heartbeat_count
    }

    /// Write one change for `peer`: `seal` builds its protected DATA for
    /// the sequence number it is given. Returns the RTPS messages to send
    /// it in: a GAP for whatever this reader has not been told about
    /// before it, the DATA, and a HEARTBEAT asking for its
    /// acknowledgement.
    pub(crate) fn write(
        &mut self,
        local: &[u8; 12],
        peer: [u8; 12],
        kx: &WriterKeyMaterial,
        now: Instant,
        seal: impl FnOnce(i64) -> Result<Vec<u8>, SecurityError>,
    ) -> Result<Vec<Vec<u8>>, WriteRefusal> {
        let session = kx.fingerprint();
        if self.proxy(peer, session, now).unacked.len() >= MAX_UNACKED_PER_READER {
            return Err(WriteRefusal::Full);
        }
        let sn = self.next_sn;
        let data = seal(sn).map_err(WriteRefusal::Seal)?;
        self.next_sn += 1;
        let count = self.next_heartbeat_count();
        // `self.proxy` built it above; the entry is only a lookup here.
        debug_assert!(self.readers.contains_key(&peer), "write follows proxy()");
        let proxy = self.readers.entry(peer).or_insert_with(|| {
            log::error!("volatile proxy rebuilt on write: it was missing after proxy()");
            ReaderProxy::new(session, now)
        });
        let mut protected = Vec::new();
        if proxy.announced_through + 1 < sn {
            if let Some(gap) = gap_range(proxy.announced_through + 1, sn - 1) {
                protected.push(protect_writer(kx, &gap));
            }
        }
        protected.push(Ok(data.clone()));
        proxy.unacked.insert(sn, data);
        proxy.announced_through = sn;
        let first = proxy.unacked.keys().next().copied().unwrap_or(sn);
        if let Some(hb) = heartbeat(first, sn, count) {
            protected.push(protect_writer(kx, &hb));
        }
        proxy.next_heartbeat = now + HEARTBEAT_PERIOD;
        let protected: Result<Vec<_>, _> = protected.into_iter().collect();
        Ok(messages(
            local,
            &peer,
            true,
            protected.map_err(WriteRefusal::Seal)?,
        ))
    }

    /// The periodic HEARTBEAT of `peer`'s proxy, when it holds
    /// unacknowledged changes and its period has elapsed, preceded by a
    /// GAP for what the history wrote for others since this reader was
    /// last told.
    pub(crate) fn tick(
        &mut self,
        local: &[u8; 12],
        peer: [u8; 12],
        kx: &WriterKeyMaterial,
        now: Instant,
    ) -> Vec<Vec<u8>> {
        let session = kx.fingerprint();
        let last = self.last_sn();
        let due = {
            let proxy = self.proxy(peer, session, now);
            !proxy.unacked.is_empty() && now >= proxy.next_heartbeat
        };
        if !due {
            return Vec::new();
        }
        let count = self.next_heartbeat_count();
        // `self.proxy` built it above; the entry is only a lookup here.
        debug_assert!(self.readers.contains_key(&peer), "tick follows proxy()");
        let proxy = self.readers.entry(peer).or_insert_with(|| {
            log::error!("volatile proxy rebuilt on tick: it was missing after proxy()");
            ReaderProxy::new(session, now)
        });
        let mut protected = Vec::new();
        if proxy.announced_through < last {
            if let Some(gap) = gap_range(proxy.announced_through + 1, last) {
                protected.push(protect_writer(kx, &gap));
            }
            proxy.announced_through = last;
        }
        let first = proxy.unacked.keys().next().copied().unwrap_or(last + 1);
        if let Some(hb) = heartbeat(first, last, count) {
            protected.push(protect_writer(kx, &hb));
        }
        proxy.next_heartbeat = now + HEARTBEAT_PERIOD;
        match protected.into_iter().collect::<Result<Vec<_>, _>>() {
            Ok(protected) => messages(local, &peer, false, protected),
            Err(_) => Vec::new(),
        }
    }

    /// `peer`'s ACKNACK: purge what it acknowledges, answer what it
    /// requests -- the change again when it is this reader's, a GAP when
    /// it is not -- followed by a HEARTBEAT when changes remain
    /// unacknowledged. A count at or below the last one processed is a
    /// duplicate or stale ACKNACK and is ignored (RTPS v2.5 Sec.8.4.15.7).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_acknack(
        &mut self,
        local: &[u8; 12],
        peer: [u8; 12],
        kx: &WriterKeyMaterial,
        now: Instant,
        base: i64,
        requested: &[i64],
        count: u32,
        stats: &VolatileStats,
    ) -> Vec<Vec<u8>> {
        let session = kx.fingerprint();
        let last = self.last_sn();
        let proxy = self.proxy(peer, session, now);
        if proxy.last_acknack.is_some_and(|seen| count <= seen) {
            return Vec::new();
        }
        proxy.last_acknack = Some(count);
        proxy.unacked = proxy.unacked.split_off(&base);
        self.answer(local, peer, kx, now, requested, last, stats)
    }

    /// `peer`'s NACK_FRAG for change `sn`: the writer never fragments a
    /// change of this channel (each fits one message), so a fragment
    /// request is answered with the whole change, or a GAP when it is not
    /// this reader's.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_nack_frag(
        &mut self,
        local: &[u8; 12],
        peer: [u8; 12],
        kx: &WriterKeyMaterial,
        now: Instant,
        sn: i64,
        count: u32,
        stats: &VolatileStats,
    ) -> Vec<Vec<u8>> {
        let session = kx.fingerprint();
        let last = self.last_sn();
        let proxy = self.proxy(peer, session, now);
        if proxy.last_nack_frag.is_some_and(|seen| count <= seen) {
            return Vec::new();
        }
        proxy.last_nack_frag = Some(count);
        self.answer(local, peer, kx, now, &[sn], last, stats)
    }

    #[allow(clippy::too_many_arguments)]
    fn answer(
        &mut self,
        local: &[u8; 12],
        peer: [u8; 12],
        kx: &WriterKeyMaterial,
        now: Instant,
        requested: &[i64],
        last: i64,
        stats: &VolatileStats,
    ) -> Vec<Vec<u8>> {
        let mut resend = Vec::new();
        let mut irrelevant = BTreeSet::new();
        debug_assert!(
            self.readers.contains_key(&peer),
            "the caller built the peer's proxy"
        );
        if let Some(proxy) = self.readers.get(&peer) {
            for &sn in requested {
                if sn < 1 || sn > last {
                    continue;
                }
                match proxy.unacked.get(&sn) {
                    Some(data) => resend.push(data.clone()),
                    None => {
                        irrelevant.insert(sn);
                    }
                }
            }
        } else {
            log::error!("ACKNACK answered with nothing: the peer's proxy is missing");
        }
        if resend.is_empty() && irrelevant.is_empty() {
            return Vec::new();
        }
        let mut protected = Vec::new();
        let irrelevant: Vec<i64> = irrelevant.into_iter().collect();
        for gap in gaps(&irrelevant) {
            protected.push(protect_writer(kx, &gap));
        }
        for data in &resend {
            stats.note_retransmitted();
            protected.push(Ok(data.clone()));
        }
        let still_unacked = self
            .readers
            .get(&peer)
            .is_some_and(|proxy| !proxy.unacked.is_empty());
        if !resend.is_empty() && still_unacked {
            let count = self.next_heartbeat_count();
            debug_assert!(
                self.readers.contains_key(&peer),
                "unacked changes imply a proxy"
            );
            if let Some(proxy) = self.readers.get_mut(&peer) {
                let first = proxy.unacked.keys().next().copied().unwrap_or(last + 1);
                if let Some(hb) = heartbeat(first, last, count) {
                    protected.push(protect_writer(kx, &hb));
                }
                proxy.next_heartbeat = now + HEARTBEAT_PERIOD;
            } else {
                log::error!("ACKNACK heartbeat dropped: the peer's proxy is missing");
            }
        }
        match protected.into_iter().collect::<Result<Vec<_>, _>>() {
            Ok(protected) => messages(local, &peer, !resend.is_empty(), protected),
            Err(_) => Vec::new(),
        }
    }

    /// Changes `peer`'s proxy holds unacknowledged.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn unacked(&self, peer: &[u8; 12]) -> usize {
        self.readers
            .get(peer)
            .map_or(0, |proxy| proxy.unacked.len())
    }
}

fn protect_writer(kx: &WriterKeyMaterial, submessage: &[u8]) -> Result<Vec<u8>, SecurityError> {
    encode_datawriter_submessage(kx, submessage)
}

// ---------------------------------------------------------------------------
//  The reader
// ---------------------------------------------------------------------------

/// What the reader keeps about one matched (authenticated) writer.
#[derive(Debug)]
struct WriterProxy {
    session: Session,
    /// Every change up to here was delivered, or known irrelevant.
    delivered_through: i64,
    /// New DATA inspected through here, including deferred changes.
    processed_through: i64,
    /// Fingerprints authorize only byte-identical repairs of deferred DATA.
    /// The deadline also covers DATA refused by the hold queue or key store.
    deferred: BTreeMap<i64, ([u8; 32], Instant)>,
    /// Raw changes waiting for their first inspection in transport order.
    buffered: BTreeMap<i64, Vec<u8>>,
    /// Changes admitted ahead of the acknowledgement floor, or declared
    /// irrelevant by the writer.
    completed: BTreeSet<i64>,
    last_heartbeat: Option<u32>,
    acknack_count: u32,
}

fn payload_fingerprint(payload: &[u8]) -> [u8; 32] {
    // SHA256 yields exactly 32 octets, so the zip copies every one of them.
    let digest = ring::digest::digest(&ring::digest::SHA256, payload);
    let mut out = [0u8; 32];
    for (dst, src) in out.iter_mut().zip(digest.as_ref()) {
        *dst = *src;
    }
    out
}

impl WriterProxy {
    fn new(session: Session) -> Self {
        Self {
            session,
            delivered_through: 0,
            processed_through: 0,
            deferred: BTreeMap::new(),
            buffered: BTreeMap::new(),
            completed: BTreeSet::new(),
            last_heartbeat: None,
            acknack_count: 0,
        }
    }

    /// Whether `sn` is inside the window this proxy keeps state for.
    fn in_window(&self, sn: i64) -> bool {
        sn > self.delivered_through && sn <= self.delivered_through + READER_WINDOW
    }

    /// Move `delivered_through` to at least `through` (everything at or
    /// below it irrelevant or lost), dropping what was kept below it.
    fn skip_through(&mut self, through: i64) {
        if through > self.delivered_through {
            self.delivered_through = through;
            self.processed_through = self.processed_through.max(through);
            self.deferred = self.deferred.split_off(&(through + 1));
            self.buffered = self.buffered.split_off(&(through + 1));
            self.completed = self.completed.split_off(&(through + 1));
        }
    }

    fn advance_acknowledgement(&mut self) {
        while self.completed.remove(&(self.delivered_through + 1)) {
            self.delivered_through += 1;
        }
    }

    /// Inspect new changes in transport order, without letting a deferred
    /// user match prevent later builtin keys from reaching discovery.
    fn advance(
        &mut self,
        out: &mut Vec<Vec<u8>>,
        admit: &mut impl FnMut(i64, &[u8], bool) -> bool,
    ) {
        loop {
            let next = self.processed_through + 1;
            if let Some(payload) = self.buffered.remove(&next) {
                if admit(next, &payload, false) {
                    self.completed.insert(next);
                    out.push(payload);
                } else {
                    self.deferred.insert(
                        next,
                        (
                            payload_fingerprint(&payload),
                            Instant::now() + PENDING_MATCH_TIMEOUT,
                        ),
                    );
                }
            } else if !self.completed.contains(&next) {
                return;
            }
            self.processed_through = next;
            self.advance_acknowledgement();
        }
    }

    fn missing(&self, last: i64) -> Vec<i64> {
        let from = self.delivered_through + 1;
        let to = last.min(self.delivered_through + READER_WINDOW);
        (from..=to)
            .filter(|sn| !self.buffered.contains_key(sn) && !self.completed.contains(sn))
            .collect()
    }
}

/// What one submessage made the reader deliver.
#[derive(Debug, Default)]
pub(crate) struct Delivery {
    /// The payloads of the changes now delivered, in order.
    pub(crate) payloads: Vec<Vec<u8>>,
    /// The peer's proxy is new: a first contact, or a peer that
    /// authenticated again (what was accepted from it before belongs to
    /// KxKeys nobody holds any more), or one whose proxy was forgotten
    /// with its authentication. Whatever was remembered of an earlier
    /// session of the peer is to be forgotten.
    pub(crate) session_reset: bool,
    /// The RTPS messages to send the peer in answer (an ACKNACK).
    pub(crate) replies: Vec<Vec<u8>>,
}

/// The `BuiltinParticipantVolatileMessageSecureReader` (module docs).
#[derive(Debug, Default)]
pub(crate) struct ReaderState {
    writers: HashMap<[u8; 12], WriterProxy>,
}

impl ReaderState {
    fn proxy(
        &mut self,
        peer: [u8; 12],
        session: Session,
        delivery: &mut Delivery,
    ) -> &mut WriterProxy {
        match self.writers.entry(peer) {
            Entry::Occupied(occupied) => {
                let proxy = occupied.into_mut();
                if proxy.session != session {
                    delivery.session_reset = true;
                    *proxy = WriterProxy::new(session);
                }
                proxy
            }
            Entry::Vacant(vacant) => {
                delivery.session_reset = true;
                vacant.insert(WriterProxy::new(session))
            }
        }
    }

    /// A held copy was installed, superseded, or terminally refused. The
    /// DATA is received without waiting for another repair cycle.
    fn accept_deferred(&mut self, peer: [u8; 12], session: Session, sn: i64) {
        if let Some(proxy) = self.writers.get_mut(&peer) {
            if proxy.session == session && proxy.deferred.remove(&sn).is_some() {
                proxy.completed.insert(sn);
                proxy.advance_acknowledgement();
            }
        }
    }

    /// Every application deferral has a terminal exit, even without a held
    /// copy. Completing reception allows RTPS to advance its bounded window.
    fn expire_deferred(
        &mut self,
        peer: [u8; 12],
        session: Session,
        now: Instant,
        stats: &VolatileStats,
    ) {
        let Some(proxy) = self.writers.get_mut(&peer) else {
            return;
        };
        if proxy.session != session {
            return;
        }
        proxy.deferred.retain(|sn, (_, deadline)| {
            if now < *deadline {
                return true;
            }
            proxy.completed.insert(*sn);
            stats.note_pending_expired();
            false
        });
        proxy.advance_acknowledgement();
    }

    pub(crate) fn start_session(&mut self, peer: [u8; 12], session: Session) -> bool {
        let mut delivery = Delivery::default();
        self.proxy(peer, session, &mut delivery);
        delivery.session_reset
    }

    pub(crate) fn retain_peers(&mut self, authenticated: &HashSet<[u8; 12]>) {
        self.writers.retain(|peer, _| authenticated.contains(peer));
    }

    /// Change `sn` of `peer`'s volatile writer: delivered when it is the
    /// next one, kept when it is ahead within the window, dropped (and
    /// counted) when it was already received or declared irrelevant.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_data(
        &mut self,
        peer: [u8; 12],
        session: Session,
        sn: i64,
        payload: &[u8],
        stats: &VolatileStats,
        admit: &mut impl FnMut(i64, &[u8], bool) -> bool,
    ) -> Delivery {
        let mut delivery = Delivery::default();
        let proxy = self.proxy(peer, session, &mut delivery);
        if let Some(expected) = proxy.deferred.get(&sn) {
            if expected.0 != payload_fingerprint(payload) {
                stats.note_duplicate();
                return delivery;
            }
            if admit(sn, payload, true) {
                proxy.deferred.remove(&sn);
                proxy.completed.insert(sn);
                proxy.advance_acknowledgement();
                delivery.payloads.push(payload.to_vec());
            }
            return delivery;
        }
        if sn <= proxy.processed_through
            || proxy.buffered.contains_key(&sn)
            || proxy.completed.contains(&sn)
        {
            stats.note_duplicate();
            return delivery;
        }
        if !proxy.in_window(sn) {
            // Past the window: asked for again once the window reaches it.
            return delivery;
        }
        proxy.buffered.insert(sn, payload.to_vec());
        proxy.advance(&mut delivery.payloads, admit);
        delivery
    }

    /// `peer`'s GAP: the sequence numbers it names are irrelevant.
    pub(crate) fn on_gap(
        &mut self,
        peer: [u8; 12],
        session: Session,
        start: i64,
        list_base: i64,
        list: &[i64],
        admit: &mut impl FnMut(i64, &[u8], bool) -> bool,
    ) -> Delivery {
        let mut delivery = Delivery::default();
        let proxy = self.proxy(peer, session, &mut delivery);
        if start <= proxy.delivered_through + 1 && list_base > start {
            proxy.skip_through(list_base - 1);
        } else {
            let to = (list_base - 1).min(proxy.delivered_through + READER_WINDOW);
            for sn in start.max(proxy.delivered_through + 1)..=to {
                proxy.buffered.remove(&sn);
                proxy.deferred.remove(&sn);
                proxy.completed.insert(sn);
            }
        }
        for &sn in list {
            if proxy.in_window(sn) && !proxy.buffered.contains_key(&sn) {
                proxy.deferred.remove(&sn);
                proxy.completed.insert(sn);
            }
        }
        proxy.advance(&mut delivery.payloads, admit);
        delivery
    }

    /// `peer`'s HEARTBEAT: what is below `first` is no longer available
    /// (acknowledged or irrelevant, the writer never drops a change this
    /// reader has not acknowledged), so the proxy moves past it; then an
    /// ACKNACK names what is missing up to `last`, unless the writer set
    /// the Final flag and nothing is missing. A count at or below the last
    /// one processed is ignored (RTPS v2.5 Sec.8.4.15.5).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_heartbeat(
        &mut self,
        local: &[u8; 12],
        peer: [u8; 12],
        kx: &WriterKeyMaterial,
        first: i64,
        last: i64,
        count: u32,
        final_flag: bool,
        admit: &mut impl FnMut(i64, &[u8], bool) -> bool,
    ) -> Delivery {
        let mut delivery = Delivery::default();
        let proxy = self.proxy(peer, kx.fingerprint(), &mut delivery);
        if proxy.last_heartbeat.is_some_and(|seen| count <= seen) {
            return delivery;
        }
        proxy.last_heartbeat = Some(count);
        proxy.skip_through(first - 1);
        proxy.advance(&mut delivery.payloads, admit);
        let missing = proxy.missing(last);
        if final_flag && missing.is_empty() {
            return delivery;
        }
        proxy.acknack_count = proxy.acknack_count.wrapping_add(1);
        let base = proxy.delivered_through + 1;
        let (num_bits, words) = bitmap_of(base, &missing);
        if let Ok(acknack) = crate::protocol::rtps::encode_acknack_with_final(
            &VOLATILE_READER,
            &VOLATILE_WRITER,
            as_wire_sn(base),
            num_bits,
            &words,
            proxy.acknack_count,
            missing.is_empty(),
        ) {
            if let Ok(protected) = encode_datareader_submessage(kx, &acknack) {
                delivery.replies = messages(local, &peer, false, vec![protected]);
            }
        }
        delivery
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::crypto::secure_submessage::{
        decode_datawriter_submessage, first_secure_prefix, first_secure_prefix_from,
    };
    use crate::security::crypto::volatile::{parse_data, protect_message};

    /// The writer's participant, the reader's, and a third one.
    const W: [u8; 12] = [0x0A; 12];
    const R: [u8; 12] = [0x0B; 12];
    const OTHER: [u8; 12] = [0x0C; 12];

    fn kx(seed: u8) -> WriterKeyMaterial {
        WriterKeyMaterial::new([seed; 32], [seed ^ 0x55; 32], [0, 0, 0, 0])
    }

    /// Every protected submessage of `message`, opened under `kx`.
    fn opened(message: &[u8], kx: &WriterKeyMaterial) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut at = first_secure_prefix(message);
        while let Some(prefix) = at {
            let decoded = decode_datawriter_submessage(kx, message, prefix).expect("opens");
            out.push(decoded.submessage);
            at = first_secure_prefix_from(message, decoded.end);
        }
        out
    }

    /// A writer at `W` and a reader at `R` sharing one KxKeys, wired by
    /// hand: what one sends is handed to the other only when a test says
    /// so, which is the whole loss injection.
    struct Pair {
        writer: WriterState,
        reader: ReaderState,
        writer_stats: VolatileStats,
        reader_stats: VolatileStats,
        kx: WriterKeyMaterial,
        now: Instant,
        delivered: Vec<Vec<u8>>,
    }

    impl Pair {
        fn new() -> Self {
            Self {
                writer: WriterState::default(),
                reader: ReaderState::default(),
                writer_stats: VolatileStats::default(),
                reader_stats: VolatileStats::default(),
                kx: kx(0x21),
                now: Instant::now(),
                delivered: Vec::new(),
            }
        }

        /// The writer writes `payload` for `R`: the messages it sends.
        fn write(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
            let kx = &self.kx;
            self.writer
                .write(&W, R, kx, self.now, |sn| protect_message(kx, sn, payload))
                .expect("written")
        }

        /// `message` reaches the reader: what it answers.
        fn deliver_to_reader(&mut self, message: &[u8]) -> Vec<Vec<u8>> {
            let mut replies = Vec::new();
            for sub in opened(message, &self.kx) {
                let delivery = if let Some(data) = parse_data(&sub) {
                    self.reader.on_data(
                        W,
                        self.kx.fingerprint(),
                        data.sequence_number,
                        data.payload,
                        &self.reader_stats,
                        &mut |_, _, _| true,
                    )
                } else {
                    match parse_control(&sub).expect("a control submessage") {
                        Control::Heartbeat {
                            first,
                            last,
                            count,
                            final_flag,
                        } => self.reader.on_heartbeat(
                            &R,
                            W,
                            &self.kx,
                            first,
                            last,
                            count,
                            final_flag,
                            &mut |_, _, _| true,
                        ),
                        Control::Gap {
                            start,
                            list_base,
                            list,
                        } => self.reader.on_gap(
                            W,
                            self.kx.fingerprint(),
                            start,
                            list_base,
                            &list,
                            &mut |_, _, _| true,
                        ),
                        other => panic!("the writer sent {:?}", other),
                    }
                };
                self.delivered.extend(delivery.payloads);
                replies.extend(delivery.replies);
            }
            replies
        }

        /// `message` reaches the writer: what it answers.
        fn deliver_to_writer(&mut self, message: &[u8]) -> Vec<Vec<u8>> {
            let mut replies = Vec::new();
            for sub in opened(message, &self.kx) {
                match parse_control(&sub).expect("a control submessage") {
                    Control::AckNack {
                        base,
                        requested,
                        count,
                    } => replies.extend(self.writer.on_acknack(
                        &W,
                        R,
                        &self.kx,
                        self.now,
                        base,
                        &requested,
                        count,
                        &self.writer_stats,
                    )),
                    Control::NackFrag { sn, count } => replies.extend(self.writer.on_nack_frag(
                        &W,
                        R,
                        &self.kx,
                        self.now,
                        sn,
                        count,
                        &self.writer_stats,
                    )),
                    other => panic!("the reader sent {:?}", other),
                }
            }
            replies
        }

        /// Deliver `messages` to the reader, its answers to the writer, and
        /// so on, until both are silent.
        fn exchange(&mut self, messages: Vec<Vec<u8>>) {
            let mut to_reader = messages;
            for _ in 0..16 {
                let to_writer: Vec<Vec<u8>> = to_reader
                    .iter()
                    .flat_map(|m| self.deliver_to_reader(m))
                    .collect();
                to_reader = to_writer
                    .iter()
                    .flat_map(|m| self.deliver_to_writer(m))
                    .collect();
                if to_reader.is_empty() {
                    return;
                }
            }
            panic!("the pair never went quiet");
        }
    }

    /// DDS Security v1.1 Sec.7.4.4.2 (Tables 18/19): the volatile pair is
    /// RELIABLE. A change whose message is lost is repaired on the
    /// reader's request (RTPS v2.5 Sec.8.4.9.2: the HEARTBEAT announces it,
    /// the ACKNACK asks for it, the writer sends it again) and every change
    /// is delivered once, in order.
    ///
    /// Mutant: `WriterState::answer` treating every requested change as
    /// irrelevant (a GAP instead of the DATA) loses "two".
    #[test]
    fn a_lost_change_is_repaired_on_the_readers_request_and_delivered_in_order() {
        let mut p = Pair::new();
        let one = p.write(b"one");
        p.exchange(one);
        let _lost = p.write(b"two");
        let three = p.write(b"three");
        p.exchange(three);
        assert_eq!(
            p.delivered,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
        assert_eq!(p.writer_stats.data_retransmitted(), 1);
        assert_eq!(
            p.writer.unacked(&R),
            0,
            "everything acknowledged is purged from the history"
        );
    }

    /// The periodic HEARTBEAT (RTPS v2.5 Sec.8.4.7.2) is what recovers a
    /// change whose whole message was lost: nothing before its period,
    /// then a HEARTBEAT the reader answers with a request.
    ///
    /// Mutant: `tick` never finding a HEARTBEAT due leaves "lost"
    /// undelivered.
    #[test]
    fn the_periodic_heartbeat_recovers_a_change_whose_message_was_lost_whole() {
        let mut p = Pair::new();
        let _lost = p.write(b"lost");
        assert!(
            p.writer.tick(&W, R, &p.kx, p.now).is_empty(),
            "nothing is due before the period"
        );
        p.now += HEARTBEAT_PERIOD;
        let heartbeat = p.writer.tick(&W, R, &p.kx, p.now);
        assert_eq!(heartbeat.len(), 1);
        p.exchange(heartbeat);
        assert_eq!(p.delivered, vec![b"lost".to_vec()]);
        assert_eq!(p.writer.unacked(&R), 0);
        p.now += HEARTBEAT_PERIOD;
        assert!(
            p.writer.tick(&W, R, &p.kx, p.now).is_empty(),
            "a proxy with nothing unacknowledged is sent no HEARTBEAT"
        );
    }

    /// The wire of the control submessages, octet by octet (RTPS v2.5
    /// Sec.9.4.5.5 GAP, 9.4.5.7 HEARTBEAT, 9.4.5.2 ACKNACK), each opened
    /// from its SEC_PREFIX/SEC_BODY/SEC_POSTFIX by the decoder alone. The
    /// history wrote change 1 for another peer, then change 2 for R: R is
    /// told change 1 is irrelevant (GAP 1..2), sent change 2, and asked to
    /// acknowledge [2, 2]; with change 2 lost, it asks for it.
    ///
    /// Mutant: `bitmap_of` setting bit `1 << (o % 32)` instead of
    /// `1 << (31 - o % 32)` fails the ACKNACK bitmap.
    #[test]
    fn the_control_submessages_are_the_rtps_ones_octet_by_octet() {
        let mut p = Pair::new();
        let kx = kx(0x21);
        let _other = p
            .writer
            .write(&W, OTHER, &kx, p.now, |sn| protect_message(&kx, sn, b"x"))
            .expect("written");
        let to_r = p.write(b"y");
        assert_eq!(to_r.len(), 1);
        let subs = opened(&to_r[0], &kx);
        assert_eq!(subs.len(), 3, "GAP, DATA, HEARTBEAT");

        let c4 = [0xff, 0x02, 0x02, 0xc4];
        let c3 = [0xff, 0x02, 0x02, 0xc3];
        let sn = |high: i32, low: u32| {
            let mut b = high.to_le_bytes().to_vec();
            b.extend_from_slice(&low.to_le_bytes());
            b
        };
        let mut gap = vec![0x08, 0x01, 28, 0];
        gap.extend_from_slice(&c4);
        gap.extend_from_slice(&c3);
        gap.extend_from_slice(&sn(0, 1)); // gapStart
        gap.extend_from_slice(&sn(0, 2)); // gapList.bitmapBase
        gap.extend_from_slice(&0u32.to_le_bytes()); // gapList.numBits
        assert_eq!(subs[0], gap, "GAP [1, 2): change 1 is not R's");

        assert_eq!(&subs[1][..2], &[0x15, 0x05], "then the DATA");
        assert_eq!(&subs[1][16..24], &sn(0, 2)[..], "change 2");

        let mut heartbeat = vec![0x07, 0x01, 28, 0];
        heartbeat.extend_from_slice(&c4);
        heartbeat.extend_from_slice(&c3);
        heartbeat.extend_from_slice(&sn(0, 2)); // firstSN
        heartbeat.extend_from_slice(&sn(0, 2)); // lastSN
        heartbeat.extend_from_slice(&2u32.to_le_bytes()); // count
        assert_eq!(subs[2], heartbeat, "HEARTBEAT [2, 2], Final clear");

        // The reader got the GAP and the HEARTBEAT, not the DATA.
        let mut lossy = header_for_tests();
        for (i, sub) in subs.iter().enumerate() {
            if i != 1 {
                lossy.extend_from_slice(&encode_datawriter_submessage(&kx, sub).expect("protect"));
            }
        }
        let replies = p.deliver_to_reader(&lossy);
        assert_eq!(replies.len(), 1);
        let acknack = opened(&replies[0], &kx);
        let mut expected = vec![0x06, 0x01, 28, 0];
        expected.extend_from_slice(&c4);
        expected.extend_from_slice(&c3);
        expected.extend_from_slice(&sn(0, 2)); // readerSNState.bitmapBase
        expected.extend_from_slice(&1u32.to_le_bytes()); // numBits
        expected.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // 2 missing
        expected.extend_from_slice(&1u32.to_le_bytes()); // count
        assert_eq!(acknack, vec![expected], "ACKNACK: 2 missing, Final clear");

        // Repaired, it acknowledges everything with the Final flag set.
        let repair = p.deliver_to_writer(&replies[0]);
        let replies: Vec<Vec<u8>> = repair.iter().flat_map(|m| p.deliver_to_reader(m)).collect();
        let acknack = opened(&replies[0], &kx);
        let mut expected = vec![0x06, 0x03, 24, 0];
        expected.extend_from_slice(&c4);
        expected.extend_from_slice(&c3);
        expected.extend_from_slice(&sn(0, 3)); // everything below 3 received
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            acknack,
            vec![expected],
            "ACKNACK: nothing missing, Final set"
        );
        assert_eq!(p.delivered, vec![b"y".to_vec()]);
    }

    /// An RTPS header and INFO_DST, for a message assembled by a test.
    fn header_for_tests() -> Vec<u8> {
        let mut m = RTPS_MAGIC.to_vec();
        m.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
        m.extend_from_slice(&HDDS_VENDOR_ID);
        m.extend_from_slice(&W);
        m.extend_from_slice(&crate::protocol::rtps::encode_info_dst(&R));
        m
    }

    /// A message is addressed to one participant (Sec.7.4.4.4): a reader
    /// asking for a change written for another peer is told it is
    /// irrelevant, and never sent it.
    ///
    /// Mutant: `answer` resending whatever the history holds under that
    /// number (any peer's) sends R the other peer's DATA.
    #[test]
    fn another_peers_change_is_answered_with_a_gap_never_its_data() {
        let mut p = Pair::new();
        let kx = kx(0x21);
        let _other = p
            .writer
            .write(&W, OTHER, &kx, p.now, |sn| {
                protect_message(&kx, sn, b"secret")
            })
            .expect("written");
        let mine = p.write(b"mine");
        p.exchange(mine);
        assert_eq!(p.delivered, vec![b"mine".to_vec()]);
        let ask = crate::protocol::rtps::encode_acknack_with_final(
            &VOLATILE_READER,
            &VOLATILE_WRITER,
            1,
            1,
            &[0x8000_0000],
            99,
            false,
        )
        .expect("ACKNACK");
        let mut asking = header_for_tests();
        asking.extend_from_slice(&encode_datareader_submessage(&kx, &ask).expect("protect"));
        let answer = p.deliver_to_writer(&asking);
        let subs: Vec<Vec<u8>> = answer.iter().flat_map(|m| opened(m, &kx)).collect();
        assert!(!subs.is_empty(), "the request is answered");
        assert!(
            subs.iter().all(|s| s[0] == GAP_ID),
            "with a GAP only: {:02x?}",
            subs
        );
    }

    /// KEEP_ALL under a resource limit (Table 18, DDS v1.4 Sec.2.2.3.19):
    /// a full proxy refuses a new change, never drops an unacknowledged
    /// one, and takes changes again once acknowledgements purged it.
    ///
    /// Mutant: dropping the purge (`split_off`) from `on_acknack` keeps
    /// the proxy full.
    #[test]
    fn a_full_proxy_refuses_new_changes_until_acknowledgements_purge_it() {
        let mut p = Pair::new();
        let kx = kx(0x21);
        for _ in 0..MAX_UNACKED_PER_READER {
            let _ = p.write(b"m");
        }
        assert!(matches!(
            p.writer
                .write(&W, R, &kx, p.now, |sn| protect_message(&kx, sn, b"m")),
            Err(WriteRefusal::Full)
        ));
        assert_eq!(p.writer.unacked(&R), MAX_UNACKED_PER_READER);
        let last = i64::try_from(MAX_UNACKED_PER_READER).expect("i64");
        let ack = crate::protocol::rtps::encode_acknack_with_final(
            &VOLATILE_READER,
            &VOLATILE_WRITER,
            as_wire_sn(last + 1),
            0,
            &[],
            1,
            true,
        )
        .expect("ACKNACK");
        let mut acking = header_for_tests();
        acking.extend_from_slice(&encode_datareader_submessage(&kx, &ack).expect("protect"));
        let _ = p.deliver_to_writer(&acking);
        assert_eq!(p.writer.unacked(&R), 0);
        assert!(p
            .writer
            .write(&W, R, &kx, p.now, |sn| protect_message(&kx, sn, b"m"))
            .is_ok());
    }

    /// A change received twice is delivered once (RTPS v2.5 Sec.8.4.12:
    /// the reader keeps what it received per writer), the second counted.
    ///
    /// Mutant: deleting the already-received check delivers it twice.
    #[test]
    fn a_change_received_twice_is_delivered_once() {
        let mut p = Pair::new();
        let one = p.write(b"one");
        let _ = p.deliver_to_reader(&one[0]);
        let _ = p.deliver_to_reader(&one[0]);
        assert_eq!(p.delivered, vec![b"one".to_vec()]);
        assert_eq!(p.reader_stats.duplicates_dropped(), 1);
    }

    /// A peer that authenticated again holds other KxKeys: both proxies
    /// start over (what was protected under the old ones cannot be read by
    /// anyone), the writer reports the reset so its owner writes again
    /// what the peer must hold, and the reader reports it so the caller
    /// forgets what it accepted under the old session.
    ///
    /// Mutant: `proxy` keeping an existing proxy whatever its session
    /// fails every assertion.
    #[test]
    fn new_kx_keys_start_both_proxies_over() {
        let mut p = Pair::new();
        let one = p.write(b"one");
        p.exchange(one);
        assert!(p.writer.take_resets().is_empty());
        let other = kx(0x99);
        let _ = p
            .writer
            .write(&W, R, &other, p.now, |sn| {
                protect_message(&other, sn, b"two")
            })
            .expect("written");
        assert_eq!(p.writer.take_resets(), HashSet::from([R]));
        assert_eq!(p.writer.unacked(&R), 1, "only the new change");
        let delivery = p.reader.on_data(
            W,
            other.fingerprint(),
            2,
            b"two",
            &p.reader_stats,
            &mut |_, _, _| true,
        );
        assert!(delivery.session_reset);
    }

    /// A HEARTBEAT or ACKNACK whose count is not above the last processed
    /// one is a duplicate or arrived late, and is ignored (RTPS v2.5
    /// Sec.8.4.15.5, Sec.8.4.15.7).
    ///
    /// Mutant: deleting the count check from `on_acknack` answers the
    /// replayed request again.
    #[test]
    fn a_stale_acknack_is_ignored() {
        let mut p = Pair::new();
        let kx = kx(0x21);
        let _lost = p.write(b"one");
        let ask = crate::protocol::rtps::encode_acknack_with_final(
            &VOLATILE_READER,
            &VOLATILE_WRITER,
            1,
            1,
            &[0x8000_0000],
            5,
            false,
        )
        .expect("ACKNACK");
        let mut asking = header_for_tests();
        asking.extend_from_slice(&encode_datareader_submessage(&kx, &ask).expect("protect"));
        assert!(!p.deliver_to_writer(&asking).is_empty());
        assert!(
            p.deliver_to_writer(&asking).is_empty(),
            "the same count again is not answered"
        );
        assert_eq!(p.writer_stats.data_retransmitted(), 1);
    }

    /// The writer never fragments a change of this channel; a NACK_FRAG
    /// (RTPS v2.5 Sec.8.3.7.6) for one is answered with the whole change.
    ///
    /// Mutant: `on_nack_frag` returning nothing leaves it undelivered.
    #[test]
    fn a_nack_frag_is_answered_with_the_whole_change() {
        let mut p = Pair::new();
        let kx = kx(0x21);
        let _lost = p.write(b"whole");
        let nack_frag = crate::protocol::builder::build_nack_frag_submessage(
            VOLATILE_READER,
            VOLATILE_WRITER,
            1,
            &[1],
            1,
        );
        let mut asking = header_for_tests();
        asking.extend_from_slice(&encode_datareader_submessage(&kx, &nack_frag).expect("protect"));
        let answer = p.deliver_to_writer(&asking);
        p.exchange(answer);
        assert_eq!(p.delivered, vec![b"whole".to_vec()]);
    }
    /// A deferred transport identity authorizes only the original payload,
    /// not another token carried under a reused writerSN.
    #[test]
    fn deferred_repairs_must_match_the_original_payload() {
        let mut reader = ReaderState::default();
        let stats = VolatileStats::default();
        reader.on_data(W, [1; 32], 1, b"original", &stats, &mut |_, _, _| false);
        reader.on_data(W, [1; 32], 2, b"later", &stats, &mut |_, _, _| true);
        assert!(reader
            .on_data(
                W,
                [1; 32],
                1,
                b"replacement",
                &stats,
                &mut |_, _, _| panic!("changed repair must not reach admission")
            )
            .payloads
            .is_empty());
        let repaired = reader.on_data(
            W,
            [1; 32],
            1,
            b"original",
            &stats,
            &mut |sn, payload, repair| {
                assert_eq!(sn, 1);
                assert_eq!(payload, b"original");
                assert!(repair);
                true
            },
        );
        assert_eq!(repaired.payloads, vec![b"original".to_vec()]);
        assert_eq!(reader.writers[&W].delivered_through, 2);
        assert_eq!(reader.writers[&W].deferred.len(), 0);
    }

    fn held(peer: [u8; 12], session: Session, order: i64, destination: GUID) -> PendingTokens {
        let (id, key) = WriterKey::mint().unwrap();
        PendingTokens {
            peer,
            session,
            order,
            writer_sn: order,
            source: GUID::new(peer, [0, 1, 2, 0x02]),
            destination,
            key_id: id.into(),
            key,
            deadline: Instant::now() + PENDING_MATCH_TIMEOUT,
        }
    }

    /// One peer's deferred tokens must leave room for another peer.
    #[test]
    fn pending_capacity_reserves_a_share_for_other_peers() {
        let channel = VolatileChannel::new();
        let destination = GUID::new(R, [0, 1, 3, 0x07]);
        for order in 1..=MAX_PENDING_PER_PEER as i64 {
            assert!(channel.hold(held(W, [1; 32], order, destination)));
        }
        assert!(!channel.hold(held(W, [1; 32], 1000, destination)));
        assert!(channel.hold(held(OTHER, [1; 32], 1, destination)));
        assert_eq!(channel.pending(), MAX_PENDING_PER_PEER + 1);
    }

    /// The participant's aggregate resource limit still bounds many peers.
    #[test]
    fn pending_capacity_is_bounded_globally() {
        let channel = VolatileChannel::new();
        let destination = GUID::new(R, [0, 1, 3, 0x07]);
        for peer in [W, OTHER, [0x0D; 12], [0x0E; 12]] {
            for order in 1..=MAX_PENDING_PER_PEER as i64 {
                assert!(channel.hold(held(peer, [1; 32], order, destination)));
            }
        }
        assert_eq!(channel.pending(), MAX_PENDING_TOKENS);
        assert!(!channel.hold(held([0x0F; 12], [1; 32], 1, destination)));
        assert_eq!(channel.pending(), MAX_PENDING_TOKENS);
    }

    /// A repair carries the same identity. Holding it twice must neither
    /// consume more capacity nor extend the lifetime of the deferred copy.
    #[test]
    fn pending_retransmission_preserves_capacity_and_deadline() {
        let channel = VolatileChannel::new();
        let destination = GUID::new(R, [0, 1, 3, 0x07]);
        let tokens = held(W, [1; 32], 1, destination);
        let deadline = tokens.deadline;
        assert!(channel.hold(tokens));
        let mut repair = held(W, [1; 32], 1, destination);
        repair.deadline += Duration::from_secs(5);
        assert!(channel.hold(repair));
        assert_eq!(channel.pending(), 1);
        assert_eq!(channel.pending.lock()[0].deadline, deadline);
    }

    /// Pause the retry at the registry lookup: its entries must still
    /// occupy capacity while another thread is ready to admit more tokens.
    /// The two channels are deterministic synchronization, with no sleeps.
    #[test]
    fn pending_retry_keeps_in_flight_entries_in_capacity() {
        use crate::security::test_pki::{bound_test_prefix, local_machine_with_completed_peer};
        use std::sync::{mpsc, Arc};
        struct PausedMatch {
            entered: mpsc::SyncSender<()>,
            resume: Mutex<mpsc::Receiver<()>>,
        }
        impl LocalEndpoints for PausedMatch {
            fn matched_with(&self, _: &GUID) -> Option<Vec<GUID>> {
                self.entered.send(()).unwrap();
                self.resume.lock().recv().unwrap();
                Some(vec![])
            }
        }
        let peer = bound_test_prefix([0xA1; 6]);
        let local = bound_test_prefix([0xA2; 6]);
        let machine = local_machine_with_completed_peer(local, peer, None);
        let session = machine.volatile_key_material(&peer).unwrap().fingerprint();
        let channel = Arc::new(VolatileChannel::new());
        let destination = GUID::new(local, [0, 1, 3, 0x07]);
        assert!(channel.hold(held(peer, session, 1, destination)));
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = mpsc::sync_channel(0);
        channel.set_local_endpoints(Box::new(PausedMatch {
            entered: entered_tx,
            resume: Mutex::new(resume_rx),
        }));
        std::thread::scope(|scope| {
            let retry = scope
                .spawn(|| channel.retry_pending(&DataKeyStore::new(), &machine, Instant::now()));
            entered_rx.recv().unwrap();
            // This is the admission lock itself: hold cannot observe an
            // empty queue or add entries while retry owns the old ones.
            let counted = channel.pending.try_lock().is_none();
            let adding = Arc::clone(&channel);
            let (ready_tx, ready_rx) = mpsc::sync_channel(0);
            let admission = scope.spawn(move || {
                ready_tx.send(()).unwrap();
                for order in 2..=MAX_PENDING_PER_PEER as i64 {
                    assert!(adding.hold(held(peer, session, order, destination)));
                }
                adding.hold(held(peer, session, 1000, destination))
            });
            ready_rx.recv().unwrap();
            resume_tx.send(()).unwrap();
            assert_eq!(retry.join().unwrap(), 0);
            let overflow_accepted = admission.join().unwrap();
            assert!(counted, "retry must keep every in-flight entry counted");
            assert!(
                !overflow_accepted,
                "the original entry still consumes a slot"
            );
        });
        assert_eq!(channel.pending(), MAX_PENDING_PER_PEER);
    }
}
