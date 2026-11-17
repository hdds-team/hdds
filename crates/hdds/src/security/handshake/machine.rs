// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PKI-DH handshake state machine driver.
//!
//! `HandshakeMachine` manages one `HandshakeState` per remote participant
//! GUID. It is the only consumer of the low-level crypto primitives from
//! `security::authentication::x509` and `security::crypto::key_exchange`.
//!
//! # Thread-Safety
//!
//! All per-peer state is protected behind ONE `Arc<RwLock<Sessions>>`.
//! The `RwLock` is held for the minimum duration required: reads (is_authenticated)
//! take a shared lock; mutations take an exclusive lock. `HandshakeMachine`
//! is `Send + Sync` and can be held inside a `SecurityPluginSuite`.
//!
//! # Replay Protection
//!
//! A FIFO ring of the last 1024 challenge nonces (from AuthRequest tokens
//! received) is maintained in `recent_nonces`. Any request whose `challenge1`
//! matches a nonce in this window is silently dropped (sec. 9.3.4.1 replay rule).
//!
//! # Retry Policy
//!
//! Exponential backoff: initial 1 s, 4 s, 16 s (3 attempts total).
//! After 3 failures the entry is moved to `Failed`. The 30 s absolute deadline
//! is enforced separately; any state older than 30 s in a non-terminal variant
//! is also failed.

use crate::core::discovery::GUID;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::security::audit::{self, AuthenticationOutcome, SecurityEvent, SharedAuditLogger};
use crate::security::crypto::key_exchange::{EcdhKeyExchange, KeyAgreementSuite};
use crate::security::crypto::peer_keys::PeerKeys;
use crate::security::crypto::session_keys::SessionKeyManager;
use crate::security::handshake::pdata;
use crate::security::handshake::state::{am_i_initiator, HandshakeState, SharedSecret};
use crate::security::handshake::tokens::{
    algo_name, final_sign_input, parse_token, reply_sign_input, AuthFinalToken, AuthReplyToken,
    AuthReqToken, AuthRequestToken, TokenKind, PRE_1_5_HANDSHAKE,
};
use crate::security::SecurityError;
use ring::agreement::EphemeralPrivateKey;

use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================
//  Timing constants
// ============================================================

/// First retransmit delay.
const RETRY_DELAY_1: Duration = Duration::from_secs(1);
/// Second retransmit delay.
const RETRY_DELAY_2: Duration = Duration::from_secs(4);
/// Third retransmit delay.
const RETRY_DELAY_3: Duration = Duration::from_secs(16);
/// Total session deadline before hard fail (sec. 9.3.4.1 recommendation).
const SESSION_DEADLINE: Duration = Duration::from_secs(30);
/// Maximum number of transmit attempts (request or reply).
const MAX_RETRIES: u8 = 3;

/// Replay protection window depth (nonces from incoming AuthRequest tokens).
const REPLAY_WINDOW: usize = 1024;

/// The window over which the sessions begun for one completed peer on its
/// authentication requests are counted (`handle_auth_request`).
///
/// An authentication request is signed by nobody, and each one honoured costs
/// us an ephemeral key pair, and the peer an AuthReply signature, an ECDH and
/// a key derivation. `REAUTHENTICATIONS_PER_INTERVAL` per peer per
/// `SESSION_DEADLINE`, and never while one is in flight, bounds what a sender
/// of forged requests gets to: a forced re-keying of an authenticated pair at
/// most three times every 30 s, each replacing the session only once the
/// real peer has signed the new one.
const REAUTHENTICATION_INTERVAL: Duration = SESSION_DEADLINE;

/// How many sessions a completed peer's authentication requests may begin
/// within any `REAUTHENTICATION_INTERVAL` (a sliding window: a slot comes back
/// `REAUTHENTICATION_INTERVAL` after the session that took it began).
///
/// It was one. A single spurious re-authentication (a late request of an
/// earlier incarnation of the peer, a request whose session was lost) then
/// spent the interval, and a participant that really restarted in the next
/// 30 s waited them out unauthenticated, its request refused at every
/// retransmission. Three leave room for that one loss and the restart that
/// follows it, and keep a flood of unsigned requests to three key pairs per
/// peer per 30 s.
const REAUTHENTICATIONS_PER_INTERVAL: usize = 3;

/// How long after a session completes an authentication request carrying the
/// challenge that session answered is taken for one that crossed it
/// (`handle_auth_request`).
///
/// A responder announces ONE future_challenge per remote identity (DDS
/// Security v1.1 Sec.9.3.3, Table 52, `validate_remote_identity`), so every
/// request it sends us carries the challenge our completed session already
/// answered: the challenge alone no longer tells a request that crossed our
/// AuthRequest from one sent after the responder gave up on a session we
/// completed (its AuthFinal lost, `tick`). Time does. The responder sends
/// requests while it waits for our AuthRequest and stops when it receives
/// it, which is before we complete: a crossing request was SENT before our
/// completion and is late by its transit only. A request after an abandoned
/// session is sent at that session's deadline, `SESSION_DEADLINE` after its
/// reply, and that reply reached us `RETRY_DELAY_3` after it at the latest:
/// at least 14 s after we completed. 4 s separates the two.
const CROSSING_WINDOW: Duration = RETRY_DELAY_2;

/// The most remote identities whose one future_challenge is kept
/// (`Sessions::future_challenge`).
///
/// A challenge is filed for a remote identity at its first request to us or
/// ours to it, and both need a certificate of our CA bound to the prefix,
/// but bits 48 to 95 of a bound prefix are the holder's to choose: one
/// certificate can name any number of identities. Past the bound an
/// identity is challenged with a new nonce each time (the specification's
/// one challenge per identity is kept for the identities filed first, and
/// none is evicted, which would change the challenge of one already
/// announced).
const MAX_FUTURE_CHALLENGES: usize = 4096;

/// The most participants a machine holds a session of record for
/// (`Sessions::states`), in any state: past it, no session is begun for a
/// participant that holds none (`Sessions::has_room_for`).
///
/// Every session costs its key material and its tables' entries, and a
/// participant prefix is chosen by its holder: one certificate can name any
/// number of them (bits 48 to 95). Discovery frees the session of every
/// participant it drops (`drop_handshake`), and a failed session of a
/// participant discovery no longer knows is freed by `tick`; this is the
/// bound that holds whatever comes in between.
const MAX_SESSIONS: usize = 4096;

/// How many sessions this machine begins as responder, over all peers, per
/// `RESPONDER_BUDGET_INTERVAL` (`HandshakeMachine::take_responder_budget`).
///
/// An AuthRequest is signed by nobody, and each one honoured costs a
/// certificate chain verification, an ephemeral key pair and a signature.
/// 64 per second answers a whole system starting at once (a request
/// refused is retransmitted by its initiator 1, 4 and 16 s later), and
/// bounds what a sender of forged requests makes us spend.
const RESPONDER_SESSIONS_PER_INTERVAL: usize = 64;

/// The window `RESPONDER_SESSIONS_PER_INTERVAL` is counted over.
const RESPONDER_BUDGET_INTERVAL: Duration = Duration::from_secs(1);

/// How often `tick` looks for the failed sessions of participants discovery
/// no longer knows (`HandshakeMachine::free_failed_of_unknown`).
const FAILED_SESSION_SWEEP: Duration = Duration::from_secs(1);

/// The most announcements (AuthRequestMessageTokens) kept per remote
/// identity while they await their attempt (`Sessions::remote_future_challenges`).
///
/// An announcement is signed by nobody. Kept one per identity, the last one
/// received, a forged announcement under a peer's prefix replaced the peer's
/// own, and the peer's Request, whose challenge1 is its own announcement's
/// future_challenge (Table 52), was refused at every retransmission: one
/// datagram per deadline locked the peer out. Kept several, a Request (or a
/// Reply's challenge2) answers any one of them; the peer sends its
/// announcement and its Request back to back, and a forger has to fit more
/// than this many announcements between the two to evict the real one.
const ANNOUNCEMENTS_KEPT_PER_IDENTITY: usize = 4;

/// Whether the next retransmission is due.
///
/// `retries` counts transmissions already made *beyond the first*, and
/// `elapsed` is measured from the first transmission, so the rungs are
/// cumulative: 1 s, then 4 s, then 16 s after the original send. Returns
/// `false` once the ladder is exhausted; from there only `SESSION_DEADLINE`
/// can move the session.
fn retry_due(retries: u8, elapsed: Duration) -> bool {
    if retries >= MAX_RETRIES {
        return false;
    }
    match retries {
        0 => elapsed > RETRY_DELAY_1,
        1 => elapsed > RETRY_DELAY_2,
        _ => elapsed > RETRY_DELAY_3,
    }
}

// ============================================================
//  HandshakeAction
// ============================================================

/// Actions the caller (stateless-channel dispatcher) must take after
/// each `HandshakeMachine` call.
#[derive(Debug)]
pub enum HandshakeAction {
    /// Encode and enqueue this token for transmission to `remote`.
    SendRequest(GUID, AuthRequestToken),
    /// Encode and enqueue this token for transmission to `remote`.
    SendReply(GUID, AuthReplyToken),
    /// Encode and enqueue this token for transmission to `remote`.
    ///
    /// NOTE: by the time `SendFinal` is returned the initiator state entry
    /// is already `Complete`. The consolidation dispatcher should enqueue
    /// the final token AND immediately report the peer as authenticated.
    SendFinal(GUID, AuthFinalToken),
    /// Handshake succeeded (responder path); caller may now authorize the peer.
    /// The `Vec<u8>` is the 32-byte HKDF-derived MasterSharedSecret.
    Completed(GUID, SharedSecret),
    /// Handshake failed; caller should log and quarantine the peer.
    Failed(GUID, String),
    /// Peer departed before completion; entry has been cleaned up.
    Drop(GUID),
    /// Encode and enqueue this authentication request for transmission to
    /// `remote` (DDS Security v1.1 Sec.7.4.3.6.2, Table 52): announce our
    /// local future_challenge when no remote token was received.
    SendAuthRequest(GUID, AuthReqToken),
    /// A message that changes nothing and needs no answer (an authentication
    /// request the machine does not honour now, with the reason). Logged at
    /// debug: anyone can send one, and a warning per datagram is a log flood.
    Ignored(GUID, String),
}

/// What `HandshakeMachine::new_request` builds: the AuthRequest and the
/// secrets of the session it opens.
struct NewRequest {
    token: AuthRequestToken,
    our_nonce: [u8; 32],
    our_dh_priv: EphemeralPrivateKey,
    our_dh_pub: Vec<u8>,
    suite: KeyAgreementSuite,
}

impl NewRequest {
    /// The `ReqSent` session this request opens.
    fn into_state(self, expected_challenge2: Vec<[u8; 32]>) -> HandshakeState {
        HandshakeState::ReqSent {
            our_nonce: self.our_nonce,
            our_dh_priv: self.our_dh_priv,
            our_dh_pub: self.our_dh_pub,
            suite: self.suite,
            last_request: self.token,
            started_at: Instant::now(),
            retries: 0,
            expected_challenge2,
        }
    }
}

/// A fresh 32-byte nonce.
fn new_nonce() -> Result<[u8; 32], SecurityError> {
    generate_challenge_nonce()?
        .as_slice()
        .try_into()
        .map_err(|_| SecurityError::CryptoError("challenge nonce wrong length".into()))
}

/// The wall clock in Unix seconds, or `None` when it cannot be read.
#[cfg(feature = "security")]
fn wall_clock_unix() -> Option<i64> {
    crate::security::revocation::unix_now_seconds().ok()
}

#[cfg(not(feature = "security"))]
fn wall_clock_unix() -> Option<i64> {
    None
}

/// Whether a peer certificate whose `notAfter` is `not_after` has expired at
/// `unix_now`. The validity period runs "from notBefore through notAfter,
/// inclusive" (RFC 5280 4.1.2.5): expired only strictly after it. A clock that
/// cannot be read counts as expired, because no certificate can then be shown
/// to be current, and a broken clock must not keep sessions alive.
fn certificate_has_expired(not_after: i64, unix_now: Option<i64>) -> bool {
    unix_now.is_none_or(|now| now > not_after)
}

/// `notAfter` of the PEM certificate `cert_pem`, in Unix seconds.
#[cfg(feature = "security")]
fn not_after_unix(cert_pem: &[u8]) -> Result<i64, SecurityError> {
    use x509_parser::pem::parse_x509_pem;
    let (_, pem) = parse_x509_pem(cert_pem).map_err(|e| {
        SecurityError::CertificateInvalid(format!("failed to parse cert PEM: {:?}", e))
    })?;
    let cert = pem.parse_x509().map_err(|e| {
        SecurityError::CertificateInvalid(format!("failed to parse X.509 cert: {:?}", e))
    })?;
    Ok(cert.validity().not_after.timestamp())
}

#[cfg(not(feature = "security"))]
fn not_after_unix(_cert_pem: &[u8]) -> Result<i64, SecurityError> {
    Err(SecurityError::CertificateInvalid(
        "certificate validity needs the `security` feature".to_string(),
    ))
}

/// The authentication protocol's `SharedSecret` (DDS Security v1.1 Sec.9.3.2,
/// Table 53): "the SHA256 hash of the derived shared secret computed by the
/// key agreement algorithm". `dh_shared_secret` is the raw output of
/// `EcdhKeyExchange::derive_shared_secret`, BEFORE the extra HKDF step this
/// module applies to get its own `MasterSharedSecret` -- the two must not be
/// confused, see `crypto::kx_keys`.
fn sha256_32(dh_shared_secret: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
    let digest = ring::digest::digest(&ring::digest::SHA256, dh_shared_secret);
    // The SharedSecret of Table 53 is key material: wiped by its holder.
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    out.copy_from_slice(digest.as_ref());
    out
}

// ============================================================
//  Per-peer tables
// ============================================================

/// The revocation list in force, and the file it is re-read from when there is one.
#[derive(Default)]
struct RevocationState {
    list: crate::security::revocation::ListInForce,
    #[cfg(feature = "security")]
    source: Option<RevocationSource>,
}

/// Why a revocation file was refused: a stable token, which the audit record
/// carries, and the detail, which the log carries.
#[cfg(feature = "security")]
struct Refusal {
    token: &'static str,
    detail: String,
}

/// Where the revocation list is re-read from, and what it is judged against.
#[cfg(feature = "security")]
struct RevocationSource {
    file: Box<dyn crate::security::revocation::RevocationFile>,
    /// The CA certificates a list must be signed by: the trust store.
    issuers_pem: Vec<u8>,
    /// The modification time of the content last judged, accepted or refused.
    seen: Option<std::time::SystemTime>,
    /// The reason the last judgement refused the file, so that a refusal is
    /// reported once and not on every pass.
    refusal: Option<String>,
}

#[cfg(feature = "security")]
impl RevocationSource {
    /// Judge the file if it changed since it was last judged. `Ok(None)`: it did
    /// not change. `Ok(Some(list))`: a new list, which may replace the one in
    /// force. `Err`: refused, with the reason. Content that is refused is not read
    /// again until its modification time changes.
    fn judge(&mut self) -> Result<Option<Vec<u8>>, Refusal> {
        let refuse = |token: &'static str| {
            move |e: &dyn std::fmt::Display| Refusal {
                token,
                detail: e.to_string(),
            }
        };
        let modified = self.file.modified().map_err(|e| {
            refuse("stat_failed")(&format!("cannot stat the revocation list: {}", e))
        })?;
        if self.seen == Some(modified) {
            return Ok(None);
        }
        self.seen = Some(modified);
        let bytes = self.file.read().map_err(|e| {
            refuse("read_failed")(&format!("cannot read the revocation list: {}", e))
        })?;
        crate::security::revocation::accept_list(&bytes, &self.issuers_pem)
            .map_err(|e| refuse("verify_failed")(&e))?;
        Ok(Some(bytes))
    }
}

/// Every per-peer table of the machine, under ONE lock, so that what a
/// handler reads and what it then writes cannot be separated by another
/// handler's write to a sibling table.
#[derive(Default)]
struct Sessions {
    /// The session of record for each peer: what `is_authenticated`, the keys
    /// and the credentials are read from.
    states: HashMap<GUID, HandshakeState>,
    /// A session begun next to the session of record, which it replaces only
    /// when it completes:
    /// - a responder session for a peer whose session of record is
    ///   `Complete` (a participant re-created under the same prefix starts
    ///   over with an AuthRequest) or still `ReplySent`. An AuthRequest is
    ///   signed by nobody, so it must cost the session of record nothing:
    ///   the new one replaces it only when its own AuthFinal, signed by the
    ///   peer's key, verifies. Until then the session of record keeps
    ///   carrying the peer's traffic, and an in-progress one can still
    ///   complete;
    /// - an initiator session begun on the peer's authentication request
    ///   while our session of record is `Complete` (`handle_auth_request`).
    superseding: HashMap<GUID, HandshakeState>,
    /// The generation of the latest session of record begun or dropped for
    /// each peer.
    ///
    /// `handle_reply` and `handle_final` take their session out of the table,
    /// verify and derive with no lock held, and put the result back. A
    /// session dropped (its participant left discovery) or begun anew in that
    /// window is not theirs any more: they install their result only if the
    /// generation they took the session at is still the peer's. Without this
    /// a late message of an old session would install keys for a
    /// participant that was removed, or overwrite the session that replaced
    /// it with keys the peer no longer holds.
    generations: HashMap<GUID, u64>,
    /// The same, for the session in `superseding`. Separate on purpose: a
    /// parallel session that begins must not invalidate the work in flight
    /// for the session of record, or one unsigned AuthRequest would make the
    /// legitimate AuthFinal of an in-progress handshake install nothing.
    superseding_generations: HashMap<GUID, u64>,
    /// The session of record `handle_reply` or `handle_final` took out of
    /// `states` to verify with no lock held, by the generation it was taken
    /// at (`Verifying`). It is absent from `states` meanwhile, yet still in
    /// progress: whatever decides to begin a session of record reads this
    /// too, or the peer's announcement handled in that window begins a new
    /// one and the message being verified installs nothing.
    verifying: HashMap<GUID, u64>,
    /// The same for the parallel session (`superseding`) taken out of its
    /// table to be verified: a re-authentication still in flight, though
    /// `superseding` does not hold it meanwhile.
    verifying_parallel: HashMap<GUID, u64>,
    /// When we began the sessions on a peer's authentication requests within
    /// the last `REAUTHENTICATION_INTERVAL` (`handle_auth_request`), oldest
    /// first, at most `REAUTHENTICATIONS_PER_INTERVAL` of them: to bound how
    /// often anyone can make us.
    reauthentications: HashMap<GUID, VecDeque<Instant>>,
    /// The responder's local AuthRequestMessageToken challenge toward each
    /// remote identity (DDS Security v1.1 Sec.9.3.3 Table 52). Initiator
    /// challenges belong to their ReqSent attempt instead, so a restart
    /// never reuses a challenge1 already in the peer's replay window.
    future_challenges: HashMap<GUID, [u8; 32]>,
    /// Remote announcements awaiting their authentication attempt. Accepted
    /// Requests consume them; announcements without a Request expire at the
    /// session deadline. They never bind a later attempt to an old nonce.
    remote_future_challenges: HashMap<GUID, VecDeque<PendingAuthRequest>>,
    /// The HDDS participants before 1.5 already reported as unable to
    /// authenticate (`note_peer_capabilities`), so that each is reported
    /// once.
    pre_1_5_peers: HashSet<GUID>,
    /// Source of both generation maps; never reused within a machine.
    last_generation: u64,
    /// When the responder sessions of the last `RESPONDER_BUDGET_INTERVAL`
    /// were begun, oldest first (`HandshakeMachine::take_responder_budget`).
    responder_sessions: VecDeque<Instant>,
    /// When `tick` last looked for failed sessions to free.
    last_failed_sweep: Option<Instant>,
}

/// An announcement received before the corresponding handshake begins.
struct PendingAuthRequest {
    future_challenge: [u8; 32],
    received_at: Instant,
}

/// Which table a session taken out for verification belongs to, and the
/// generation it was taken at.
#[derive(Clone, Copy, Debug)]
enum Slot {
    /// The session of record (`Sessions::states`).
    Record(Option<u64>),
    /// The parallel session (`Sessions::superseding`).
    Superseding(Option<u64>),
}

impl Sessions {
    /// A session of record begins for `guid`: any work in flight for an
    /// earlier one will install nothing, and a parallel one is forgotten.
    fn begin(&mut self, guid: GUID) -> u64 {
        self.last_generation += 1;
        self.generations.insert(guid, self.last_generation);
        self.superseding.remove(&guid);
        self.superseding_generations.remove(&guid);
        self.last_generation
    }

    /// A parallel session begins for `guid`: work in flight for an earlier
    /// parallel session will install nothing; the session of record is
    /// untouched.
    fn begin_superseding(&mut self, guid: GUID) -> u64 {
        self.last_generation += 1;
        self.superseding_generations
            .insert(guid, self.last_generation);
        self.last_generation
    }

    /// The generation of `guid`'s latest session of record, `None` once
    /// dropped.
    fn generation(&self, guid: &GUID) -> Option<u64> {
        self.generations.get(guid).copied()
    }

    /// The generation of `guid`'s latest parallel session.
    fn superseding_generation(&self, guid: &GUID) -> Option<u64> {
        self.superseding_generations.get(guid).copied()
    }

    /// The session of record of `guid` at `slot` was just taken out of
    /// `states` to be verified: note it (`verifying`) until its `Verifying`
    /// guard is dropped. A parallel session is noted apart
    /// (`verifying_parallel`): nothing begins a session on its absence, but
    /// whoever asks whether keys are changing must still see it.
    fn taken_for_verification(&mut self, guid: GUID, slot: Slot) {
        match slot {
            Slot::Record(Some(generation)) => {
                self.verifying.insert(guid, generation);
            }
            Slot::Superseding(Some(generation)) => {
                self.verifying_parallel.insert(guid, generation);
            }
            Slot::Record(None) | Slot::Superseding(None) => {}
        }
    }

    /// Whether a session of record may be filed for `guid`: it holds one
    /// already, or there is room for one more (`max_sessions`).
    fn has_room_for(&self, guid: &GUID, max_sessions: usize) -> bool {
        self.states.contains_key(guid)
            || self.verifying.contains_key(guid)
            || self.states.len() < max_sessions
    }

    /// Forget every table entry of `guid`.
    fn forget(&mut self, guid: &GUID) {
        self.states.remove(guid);
        self.superseding.remove(guid);
        self.generations.remove(guid);
        self.superseding_generations.remove(guid);
        self.verifying.remove(guid);
        self.verifying_parallel.remove(guid);
        self.reauthentications.remove(guid);
        self.future_challenges.remove(guid);
        self.remote_future_challenges.remove(guid);
        self.pre_1_5_peers.remove(guid);
    }

    /// `guid`'s one future_challenge, generated at the first need; a new
    /// one each time, kept nowhere, past `MAX_FUTURE_CHALLENGES`.
    fn future_challenge(&mut self, guid: GUID) -> Result<[u8; 32], SecurityError> {
        if let Some(challenge) = self.future_challenges.get(&guid) {
            return Ok(*challenge);
        }
        let challenge = new_nonce()?;
        if self.future_challenges.len() < MAX_FUTURE_CHALLENGES {
            self.future_challenges.insert(guid, challenge);
        }
        Ok(challenge)
    }

    /// Remember an announcement before its Request is accepted, next to
    /// the ones already pending for that identity (at most
    /// `ANNOUNCEMENTS_KEPT_PER_IDENTITY`, the oldest dropped first). Late
    /// datagrams cannot change the attempt already waiting for Final.
    fn remember_remote_future_challenge(&mut self, guid: GUID, future_challenge: [u8; 32]) {
        if !self.remote_future_challenges.contains_key(&guid)
            && self.remote_future_challenges.len() >= MAX_FUTURE_CHALLENGES
        {
            return;
        }
        let pending = self.remote_future_challenges.entry(guid).or_default();
        pending.retain(|announced| {
            announced.received_at.elapsed() < SESSION_DEADLINE
                && announced.future_challenge != future_challenge
        });
        pending.push_back(PendingAuthRequest {
            future_challenge,
            received_at: Instant::now(),
        });
        while pending.len() > ANNOUNCEMENTS_KEPT_PER_IDENTITY {
            pending.pop_front();
        }
    }

    /// The latest announcement of `guid` still within its deadline.
    fn pending_auth_request(&self, guid: &GUID) -> Option<&PendingAuthRequest> {
        self.remote_future_challenges.get(guid).and_then(|pending| {
            pending
                .iter()
                .rev()
                .find(|announced| announced.received_at.elapsed() < SESSION_DEADLINE)
        })
    }

    /// The future_challenges of `guid`'s announcements still within their
    /// deadline; empty when it announced none.
    fn remote_future_challenges_of(&self, guid: &GUID) -> Vec<[u8; 32]> {
        self.remote_future_challenges
            .get(guid)
            .map(|pending| {
                pending
                    .iter()
                    .filter(|announced| announced.received_at.elapsed() < SESSION_DEADLINE)
                    .map(|announced| announced.future_challenge)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Table 52, begin_handshake_reply: a non-NIL remote token binds
    /// challenge1, to one of the announcements pending for the identity. A
    /// mismatch leaves them intact.
    fn validate_remote_challenge(
        &self,
        guid: &GUID,
        challenge1: &[u8; 32],
    ) -> Result<(), SecurityError> {
        if !matches!(self.states.get(guid), Some(HandshakeState::Complete { .. })) {
            let announced = self.remote_future_challenges_of(guid);
            if !announced.is_empty() && !announced.contains(challenge1) {
                return Err(SecurityError::AuthenticationFailed(
                    "AuthRequest challenge1 does not match the future_challenge this peer \
                     announced earlier over the stateless channel: refused"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// Holds `Sessions::verifying` (or `verifying_parallel`) for a session taken
/// out of its table, until the handler that took it returns, by whatever path
/// (a verdict installed, a refusal, an early `?`, a panic). Removes only the
/// note of its own generation: a session dropped and begun again meanwhile
/// may be out for verification in its turn.
struct Verifying<'a> {
    sessions: &'a RwLock<Sessions>,
    guid: GUID,
    slot: Slot,
}

impl<'a> Verifying<'a> {
    fn new(sessions: &'a RwLock<Sessions>, guid: GUID, slot: Slot) -> Self {
        Self {
            sessions,
            guid,
            slot,
        }
    }
}

impl Drop for Verifying<'_> {
    fn drop(&mut self) {
        let mut sessions = self.sessions.write();
        match self.slot {
            Slot::Record(Some(generation)) => {
                if sessions.verifying.get(&self.guid) == Some(&generation) {
                    sessions.verifying.remove(&self.guid);
                }
            }
            Slot::Superseding(Some(generation)) => {
                if sessions.verifying_parallel.get(&self.guid) == Some(&generation) {
                    sessions.verifying_parallel.remove(&self.guid);
                }
            }
            Slot::Record(None) | Slot::Superseding(None) => {}
        }
    }
}

/// What a completed handshake is reported to (`set_on_authenticated`).
///
/// The flag says whether the session that completed replaced a completed one
/// (the peer authenticated again: re-created under the same prefix, or made
/// to re-key): whatever the peer had learned under the old session it may
/// not hold any more.
pub(crate) type AuthenticatedHook = Box<dyn Fn(GUID, bool) + Send + Sync>;

/// Told of a completed session that `tick` tore down because its peer's
/// certificate expired. Runs with no lock of the machine held.
pub(crate) type TornDownHook = Box<dyn Fn(&GUID) + Send + Sync>;

type BeforeReauthentication = Box<dyn Fn(GUID) -> Result<(), SecurityError> + Send + Sync>;

/// Whether discovery knows the participant of a GUID prefix
/// (`HandshakeMachine::set_participant_known`).
pub(crate) type ParticipantKnown = Box<dyn Fn(&[u8; 12]) -> bool + Send + Sync>;

/// A test hook handed the machine it runs in.
#[cfg(test)]
type ParkedHook = Box<dyn Fn(&HandshakeMachine) + Send + Sync>;

/// The write side of the session tables (`HandshakeMachine::sessions_mut`):
/// moves the machine's `state_epoch` when it is dropped, BEFORE the lock it
/// holds is released (a struct's `Drop` runs before its fields are dropped).
struct SessionsWrite<'a> {
    guard: parking_lot::RwLockWriteGuard<'a, Sessions>,
    epoch: &'a std::sync::atomic::AtomicU64,
    /// Set by `unchanged`: a pass that changed nothing leaves the epoch.
    unchanged: bool,
}

impl SessionsWrite<'_> {
    /// Declare that this write changed nothing (`HandshakeMachine::tick`
    /// with no session due): the epoch stays, and what discovery cached
    /// under it stays valid.
    fn unchanged(&mut self) {
        self.unchanged = true;
    }
}

impl std::ops::Deref for SessionsWrite<'_> {
    type Target = Sessions;
    fn deref(&self) -> &Sessions {
        &self.guard
    }
}

impl std::ops::DerefMut for SessionsWrite<'_> {
    fn deref_mut(&mut self) -> &mut Sessions {
        &mut self.guard
    }
}

impl Drop for SessionsWrite<'_> {
    fn drop(&mut self) {
        if !self.unchanged {
            self.epoch
                .fetch_add(1, std::sync::atomic::Ordering::Release);
        }
    }
}

// ============================================================
//  HandshakeMachine
// ============================================================

/// Drives the 3-message PKI-DH authentication protocol for all known peers.
pub struct HandshakeMachine {
    /// Per-GUID session tables.
    handshakes: Arc<RwLock<Sessions>>,
    /// Moved by every write to `handshakes` (`sessions_mut`), while it is
    /// held: a reader that loads it and then reads the sessions reads them
    /// at least as new as the value it loaded (`state_epoch`).
    state_epoch: std::sync::atomic::AtomicU64,
    /// Replay-protection ring buffer of seen challenge1 nonces.
    recent_nonces: Arc<Mutex<VecDeque<[u8; 32]>>>,
    /// Key-agreement algorithm string placed in AuthRequest.kagree_algo
    /// (DDS Security v1.1 sec. 9.3.1.1.1). Defaults to "ECDH+prime256v1-CEUM".
    kagree_algo: String,
    /// Shared suite audit chain. Terminal transitions only: never retries.
    audit: Option<SharedAuditLogger>,
    /// DER-encoded certificate revocation list, when the deployment supplies
    /// one.
    ///
    /// `None` means revocation is not checked, and that has to be a decision
    /// the operator made rather than a state we drifted into: the suite
    /// refuses to build when `check_certificate_revocation` is on and no list
    /// was given, so a machine reaching this point with `None` is one whose
    /// operator turned revocation OFF.
    revocation: Mutex<RevocationState>,
    /// This participant's SIGNED permissions document, sent as `c.perm`.
    ///
    /// `None` when the participant runs without access control, which is a
    /// legitimate configuration: there is then nothing to prove, and `c.perm`
    /// goes empty (`c_perm`). It is NOT a way to opt out of being checked by
    /// the peer - the peer decides what a missing document means to it.
    local_permissions: Option<Vec<u8>>,
    /// Capabilities bound into this participant's c.pdata.
    local_capabilities: u32,
    /// The SessionIds this participant seals its volatile channel under,
    /// its own rather than the process's (`SealingSession`): the KxKeys are
    /// one material for both ends of a pair, and what this end sealed must
    /// be told from what the peer did when it comes back. `None` only when
    /// randomness failed at construction; the channel then seals under the
    /// process's SessionIds and reflections are not recognised.
    volatile_sealing: Option<Arc<crate::security::crypto::secure_submessage::SealingSession>>,
    /// Told the participant GUID of every session that completes, once its
    /// keys are filed, with no lock of the machine held. Discovery sets it to
    /// surface the endpoints the peer announced while it was not yet
    /// authenticated: they were refused then, and nothing else would offer
    /// them again.
    on_authenticated: std::sync::OnceLock<AuthenticatedHook>,
    /// Teardown of an expired session (`tick_at`), for discovery to purge keys.
    on_torn_down: std::sync::OnceLock<TornDownHook>,
    /// The local identity's GUID and the `notAfter` of its certificate (Unix
    /// seconds). Set once; see `set_local_identity`.
    local_identity: std::sync::OnceLock<(GUID, i64)>,
    /// Whether the local identity's expiry has been reported (once per machine).
    local_expiry_reported: std::sync::atomic::AtomicBool,
    /// Refresh writer generations before replacement KxKeys become visible.
    /// Runs under the session write lock; it must not call this machine.
    before_reauthentication: std::sync::OnceLock<BeforeReauthentication>,
    /// Whether discovery knows the participant of a prefix: an AuthRequest
    /// from one it does not is not answered, and a failed session of one it
    /// no longer knows is freed. Unset (no discovery), every prefix is known.
    participant_known: std::sync::OnceLock<ParticipantKnown>,
    /// `MAX_SESSIONS`, lowered by tests.
    max_sessions: usize,
    /// `RESPONDER_SESSIONS_PER_INTERVAL` per `RESPONDER_BUDGET_INTERVAL`,
    /// changed by tests.
    responder_budget: (usize, Duration),
    /// Test hook run, once, at the first of these windows reached: in
    /// `handle_reply` and `handle_final` right after they took their session
    /// out of the table and before they verify it, in `start` between its
    /// unlocked check and the write lock that decides, and in `handle_request`
    /// between the signature of its reply and the write lock that files it.
    /// Lets a test drop, restart or race a session in that window.
    #[cfg(test)]
    parked_hook: Mutex<Option<ParkedHook>>,
}

impl HandshakeMachine {
    /// Create a new empty machine with the default ECDH+prime256v1-CEUM algorithm.
    pub fn new() -> Self {
        Self::with_kagree_algo("ECDH+prime256v1-CEUM")
    }

    /// Create a new empty machine with an explicit key-agreement algorithm.
    ///
    /// The `kagree_algo` string is placed in `AuthRequest.kagree_algo` during
    /// the PKI-DH initiator path. Supported suites are the spec's
    /// `"ECDH+prime256v1-CEUM"` and the HDDS extension
    /// `"ECDH+secp384r1-CEUM"`. Unknown strings (including the spec's
    /// unimplemented `"DH+MODP-2048-256"`) are accepted at construction time;
    /// `start()` then refuses them locally, before any packet leaves.
    pub fn with_kagree_algo<S: Into<String>>(kagree_algo: S) -> Self {
        Self {
            handshakes: Arc::new(RwLock::new(Sessions::default())),
            state_epoch: std::sync::atomic::AtomicU64::new(0),
            recent_nonces: Arc::new(Mutex::new(VecDeque::with_capacity(REPLAY_WINDOW))),
            kagree_algo: kagree_algo.into(),
            audit: None,
            revocation: Mutex::new(RevocationState::default()),
            local_permissions: None,
            local_capabilities: crate::protocol::group::LOCAL_CAPABILITIES,
            volatile_sealing: crate::security::crypto::secure_submessage::SealingSession::new()
                .ok()
                .map(Arc::new),
            #[cfg(test)]
            parked_hook: Mutex::new(None),
            on_authenticated: std::sync::OnceLock::new(),
            on_torn_down: std::sync::OnceLock::new(),
            local_identity: std::sync::OnceLock::new(),
            local_expiry_reported: std::sync::atomic::AtomicBool::new(false),
            before_reauthentication: std::sync::OnceLock::new(),
            participant_known: std::sync::OnceLock::new(),
            max_sessions: MAX_SESSIONS,
            responder_budget: (RESPONDER_SESSIONS_PER_INTERVAL, RESPONDER_BUDGET_INTERVAL),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_local_capabilities_for_tests(mut self, caps: u32) -> Self {
        self.local_capabilities = caps;
        self
    }

    /// The session tables, for writing. Every write goes through here, so
    /// that `state_epoch` moves with each.
    fn sessions_mut(&self) -> SessionsWrite<'_> {
        SessionsWrite {
            guard: self.handshakes.write(),
            epoch: &self.state_epoch,
            unchanged: false,
        }
    }

    /// A number that changes whenever any session changes - begun, advanced,
    /// completed, failed, superseded, dropped - and never goes back.
    ///
    /// Discovery caches what it concluded from the sessions (whether a peer
    /// holds one, has completed it, which credentials it presented: the
    /// admission of its endpoints) and keys the cache on this value. It is
    /// moved while the write lock is held, before it is released: a reader
    /// that loads it and then reads the sessions reads them at least as new
    /// as the value it loaded, so a verdict filed under a value is never
    /// older than the sessions that value describes.
    pub(crate) fn state_epoch(&self) -> u64 {
        self.state_epoch.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn set_before_reauthentication(&self, hook: BeforeReauthentication) {
        let _ = self.before_reauthentication.set(hook);
    }

    /// Tell the machine which participants discovery knows. Set once. Runs
    /// with no lock of the machine held: it may take discovery's.
    pub(crate) fn set_participant_known(&self, hook: ParticipantKnown) {
        let _ = self.participant_known.set(hook);
    }

    /// Whether discovery knows the participant of `prefix` (every one, when
    /// no discovery told the machine).
    fn participant_known(&self, prefix: &[u8; 12]) -> bool {
        self.participant_known
            .get()
            .is_none_or(|known| known(prefix))
    }

    /// Lower `MAX_SESSIONS`, for the tests that fill it.
    #[cfg(test)]
    pub(crate) fn with_max_sessions_for_tests(mut self, max_sessions: usize) -> Self {
        self.max_sessions = max_sessions;
        self
    }

    /// Change the responder budget, for the tests that spend it.
    #[cfg(test)]
    pub(crate) fn with_responder_budget_for_tests(
        mut self,
        per_interval: usize,
        interval: Duration,
    ) -> Self {
        self.responder_budget = (per_interval, interval);
        self
    }

    /// Age the responder budget without sleeping.
    #[cfg(test)]
    pub(crate) fn age_responder_budget(&self, age: Duration) {
        for began in self.sessions_mut().responder_sessions.iter_mut() {
            if let Some(earlier) = began.checked_sub(age) {
                *began = earlier;
            }
        }
    }

    /// How many sessions of record the machine holds, in any state.
    #[cfg(test)]
    pub(crate) fn sessions_held(&self) -> usize {
        self.handshakes.read().states.len()
    }

    /// Take one responder session of the budget
    /// (`RESPONDER_SESSIONS_PER_INTERVAL` per `RESPONDER_BUDGET_INTERVAL`,
    /// over all peers), or `false` when the window has none left.
    fn take_responder_budget(&self, now: Instant) -> bool {
        let (per_interval, interval) = self.responder_budget;
        let mut sessions = self.sessions_mut();
        while sessions
            .responder_sessions
            .front()
            .is_some_and(|began| now.saturating_duration_since(*began) >= interval)
        {
            sessions.responder_sessions.pop_front();
        }
        if sessions.responder_sessions.len() >= per_interval {
            sessions.unchanged();
            return false;
        }
        sessions.responder_sessions.push_back(now);
        sessions.unchanged();
        true
    }

    /// Free the failed sessions of the participants discovery no longer
    /// knows, at most once per `FAILED_SESSION_SWEEP`.
    ///
    /// A failed session is kept for a participant discovery knows: it says
    /// the participant takes part in authentication (`has_session`), and
    /// discovery frees it when it drops the participant (`drop_handshake`).
    /// One discovery never knew, or dropped while the session was being
    /// filed, has nobody to free it. The hook is called with no lock of the
    /// machine held, and a session that changed meanwhile is kept.
    fn free_failed_of_unknown(&self, now: Instant) {
        if self.participant_known.get().is_none() {
            return;
        }
        let candidates: Vec<(GUID, Instant)> = {
            let mut sessions = self.sessions_mut();
            sessions.unchanged();
            if sessions
                .last_failed_sweep
                .is_some_and(|last| now.saturating_duration_since(last) < FAILED_SESSION_SWEEP)
            {
                return;
            }
            sessions.last_failed_sweep = Some(now);
            sessions
                .states
                .iter()
                .filter_map(|(guid, state)| match state {
                    HandshakeState::Failed { failed_at, .. } => Some((*guid, *failed_at)),
                    _ => None,
                })
                .collect()
        };
        let unknown: Vec<(GUID, Instant)> = candidates
            .into_iter()
            .filter(|(guid, _)| !self.participant_known(&guid.prefix))
            .collect();
        if unknown.is_empty() {
            return;
        }
        let mut sessions = self.sessions_mut();
        for (guid, failed_at) in unknown {
            let unchanged = matches!(
                sessions.states.get(&guid),
                Some(HandshakeState::Failed { failed_at: at, .. }) if *at == failed_at
            ) && !sessions.verifying.contains_key(&guid)
                && !sessions.superseding.contains_key(&guid);
            if unchanged {
                log::debug!(
                    "[security::handshake] failed session of {}, a participant discovery does \
                     not know, freed",
                    guid
                );
                sessions.forget(&guid);
            }
        }
    }

    /// Keep the session stable while a writer-key snapshot is sealed or a
    /// received token is installed. A replacement cannot pair old writer
    /// material with new KxKeys, or retire resources before an old token
    /// operation holding the lease finishes.
    pub(crate) fn with_volatile_key_material<R>(
        &self,
        prefix: &[u8; 12],
        use_material: impl FnOnce(crate::security::crypto::secure_submessage::WriterKeyMaterial) -> R,
    ) -> Option<R> {
        let sessions = self.handshakes.read();
        let peer = GUID::new(*prefix, RTPS_ENTITYID_PARTICIPANT);
        match sessions.states.get(&peer) {
            Some(HandshakeState::Complete { keys, .. }) => {
                let material = keys.volatile_key_material();
                Some(use_material(match &self.volatile_sealing {
                    Some(sealing) => material.with_sealing_session(Arc::clone(sealing)),
                    None => material,
                }))
            }
            _ => None,
        }
    }

    /// Set the hook told of every session that completes
    /// (`on_authenticated`). Set once; a second call is ignored.
    /// Record the local identity: its GUID and the certificate PEM it is
    /// presented with. Set once, at participant construction.
    ///
    /// Once the certificate's `notAfter` has passed, the machine refuses to begin
    /// or advance any handshake and ends every authenticated session on its next
    /// pass (`tick_at`). DDS-Security v1.1 8.3.2.12.2 (`revoke_identity`) says the
    /// middleware "shall terminate any communications with the DomainParticipant
    /// associated with that handle".
    pub(crate) fn set_local_identity(
        &self,
        guid: GUID,
        certificate_pem: &[u8],
    ) -> Result<(), SecurityError> {
        let not_after = not_after_unix(certificate_pem)?;
        let _ = self.local_identity.set((guid, not_after));
        Ok(())
    }

    /// Tell the machine what to do with a session it tears down (`tick_at`).
    /// Set once; the first hook is kept.
    pub(crate) fn set_on_torn_down(&self, hook: TornDownHook) {
        let _ = self.on_torn_down.set(hook);
    }

    pub(crate) fn set_on_authenticated(&self, hook: AuthenticatedHook) {
        if self.on_authenticated.set(hook).is_err() {
            log::debug!("[security::handshake] completion hook already set; kept the first");
        }
    }

    /// Note what the remote participant `remote_guid` announced in its SPDP
    /// (`PID_VENDORID`, `PID_HDDS_CAPABILITIES`).
    ///
    /// Every HDDS release that does not announce `CAP_ONE_FUTURE_CHALLENGE`
    /// is a 1.4.x one, and signs its handshake otherwise than DDS Security v1.1
    /// Sec.9.3.2.5.2 and Sec.9.3.2.5.3 define (dh2 and both hashes
    /// unsigned): it cannot authenticate with this release, which accepts
    /// the specification's signatures only. Said once per peer, at its first
    /// note, in the log and in the audit chain, so the failure that follows
    /// is not a silent timeout.
    pub(crate) fn note_peer_capabilities(
        &self,
        remote_guid: GUID,
        vendor_id: Option<u16>,
        hdds_capabilities: Option<u32>,
    ) {
        let remote_guid = GUID::new(remote_guid.prefix, RTPS_ENTITYID_PARTICIPANT);
        let pre_1_5 = vendor_id == Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16)
            && hdds_capabilities
                .is_none_or(|caps| caps & crate::protocol::group::CAP_ONE_FUTURE_CHALLENGE == 0);
        if !pre_1_5 {
            return;
        }
        let first_note = self.sessions_mut().pre_1_5_peers.insert(remote_guid);
        if first_note {
            log::warn!(
                "[security::handshake] {} is an HDDS participant without \
                 CAP_ONE_FUTURE_CHALLENGE, a release before 1.5: {}",
                remote_guid,
                PRE_1_5_HANDSHAKE
            );
            self.audit_authentication(&remote_guid, AuthenticationOutcome::Failed);
        }
    }

    /// The future_challenge announced to `remote_guid` by the request we
    /// wait an answer to, if we wait for one.
    #[cfg(test)]
    pub(crate) fn awaited_challenge(&self, remote_guid: &GUID) -> Option<[u8; 32]> {
        match self.handshakes.read().states.get(remote_guid) {
            Some(HandshakeState::AwaitingRequest {
                future_challenge, ..
            }) => *future_challenge,
            _ => None,
        }
    }

    /// How many future_challenges are kept, and the bound.
    #[cfg(test)]
    pub(crate) fn future_challenges_kept(&self) -> (usize, usize) {
        (
            self.handshakes.read().future_challenges.len(),
            MAX_FUTURE_CHALLENGES,
        )
    }

    /// Age an announcement without sleeping, for delayed-SPDP tests.
    #[cfg(test)]
    pub(crate) fn age_pending_announcement(&self, remote_guid: &GUID, age: Duration) {
        if let Some(pending) = self
            .sessions_mut()
            .remote_future_challenges
            .get_mut(remote_guid)
        {
            for announced in pending.iter_mut() {
                if let Some(earlier) = announced.received_at.checked_sub(age) {
                    announced.received_at = earlier;
                }
            }
        }
    }

    /// Age an unanswered Reply without sleeping.
    #[cfg(test)]
    pub(crate) fn age_pending_reply(&self, remote_guid: &GUID, age: Duration) {
        if let Some(HandshakeState::ReplySent { started_at, .. }) =
            self.sessions_mut().states.get_mut(remote_guid)
        {
            if let Some(earlier) = started_at.checked_sub(age) {
                *started_at = earlier;
            }
        }
    }

    /// Pretend the session of record with `remote_guid` completed longer
    /// ago than `CROSSING_WINDOW`.
    #[cfg(test)]
    pub(crate) fn age_completion(&self, remote_guid: &GUID) {
        if let Some(HandshakeState::Complete { completed_at, .. }) =
            self.sessions_mut().states.get_mut(remote_guid)
        {
            if let Some(earlier) = completed_at.checked_sub(CROSSING_WINDOW + CROSSING_WINDOW) {
                *completed_at = earlier;
            }
        }
    }

    /// A session with `remote_guid` completed: tell the hook.
    fn authenticated(&self, remote_guid: GUID, replaced_complete: bool) {
        if let Some(hook) = self.on_authenticated.get() {
            hook(remote_guid, replaced_complete);
        }
    }

    /// Pretend every session begun on `remote_guid`'s authentication requests
    /// began `REAUTHENTICATION_INTERVAL` earlier than it did.
    #[cfg(test)]
    pub(crate) fn age_reauthentication(&self, remote_guid: &GUID) {
        if let Some(began) = self.sessions_mut().reauthentications.get_mut(remote_guid) {
            for at in began.iter_mut() {
                if let Some(earlier) = at.checked_sub(REAUTHENTICATION_INTERVAL) {
                    *at = earlier;
                }
            }
        }
    }

    /// Install the test hook (`parked_hook`).
    #[cfg(test)]
    pub(crate) fn set_parked_hook(&self, hook: ParkedHook) {
        *self.parked_hook.lock() = Some(hook);
    }

    #[cfg(test)]
    fn parked(&self) {
        let hook = self.parked_hook.lock().take();
        if let Some(hook) = hook {
            hook(self);
        }
    }

    /// Attach the suite's single audit chain to this state machine.
    pub(crate) fn with_audit_logger(mut self, audit: Option<SharedAuditLogger>) -> Self {
        self.audit = audit;
        self
    }

    /// Hold the revocation list in `list`, the cell the authentication plugin
    /// also reads: a reload put in force here is the list both judge against.
    pub(crate) fn with_shared_revocation(
        mut self,
        list: crate::security::revocation::ListInForce,
    ) -> Self {
        self.revocation.get_mut().list = list;
        self
    }

    /// Where the revocation list is re-read from, and the CA certificates it is
    /// judged against. The machine checks the file on each periodic pass and
    /// reads it only when its modification time changed.
    #[cfg(feature = "security")]
    pub(crate) fn with_revocation_file(
        mut self,
        source: Option<(
            Box<dyn crate::security::revocation::RevocationFile>,
            Vec<u8>,
        )>,
    ) -> Self {
        self.revocation.get_mut().source = source.map(|(file, issuers_pem)| RevocationSource {
            file,
            issuers_pem,
            seen: None,
            refusal: None,
        });
        self
    }

    /// The revocation list in force, if any.
    fn revocation_list(&self) -> Option<Vec<u8>> {
        self.revocation.lock().list.lock().clone()
    }

    /// Judge the revocation file if it changed. Returns the list that now
    /// stands when it was replaced. A refused file leaves the list in force as it
    /// was; the refusal is logged and audited once for each distinct reason.
    #[cfg(feature = "security")]
    fn reload_revocation(&self) -> Option<Vec<u8>> {
        let mut state = self.revocation.lock();
        let judged = state.source.as_mut()?.judge();
        match judged {
            Ok(None) => None,
            Ok(Some(list)) => {
                *state.list.lock() = Some(list.clone());
                if let Some(source) = state.source.as_mut() {
                    source.refusal = None;
                }
                log::info!("[security::handshake] revocation list reloaded from its file");
                Some(list)
            }
            Err(refusal) => {
                let source = state.source.as_mut()?;
                if source.refusal.as_deref() != Some(refusal.detail.as_str()) {
                    log::error!(
                        "[security::handshake] revocation list refused, the last good list \
                         stays in force: {}",
                        refusal.detail
                    );
                    // A Crypto record: its operation text is the one free-text field
                    // the public event model has, and it carries the stable token.
                    audit::record_committed(
                        &self.audit,
                        &SecurityEvent::Crypto {
                            key_id: 0,
                            operation: format!("revocation_list_refused:{}", refusal.token),
                            outcome: audit::CryptoOutcome::Failed,
                            timestamp: audit::timestamp_ns(),
                        },
                    );
                    source.refusal = Some(refusal.detail);
                }
                None
            }
        }
    }

    /// The authenticated sessions whose peer certificate chain `list` revokes,
    /// each with the peer certificate it was judged on: a session replaced in the
    /// meantime is not ended by a verdict on the one it replaced.
    #[cfg(feature = "security")]
    fn sessions_listed_by(&self, list: &[u8]) -> Vec<(GUID, Vec<u8>)> {
        let ca = match self.revocation.lock().source.as_ref() {
            Some(source) => source.issuers_pem.clone(),
            None => return Vec::new(),
        };
        let peers: Vec<(GUID, Vec<u8>)> = self
            .handshakes
            .read()
            .states
            .iter()
            .filter_map(|(guid, state)| match state {
                HandshakeState::Complete { peer_cert, .. } => Some((*guid, peer_cert.clone())),
                _ => None,
            })
            .collect();
        peers
            .into_iter()
            .filter(|(_, cert)| {
                matches!(
                    crate::security::authentication::x509::cert::path_is_listed(cert, &ca, list),
                    Ok(true)
                )
            })
            .collect()
    }

    /// Attach this participant's signed permissions document.
    ///
    /// It travels as the `c.perm` binary property of AuthRequest and AuthReply
    /// (DDS-Security v1.1 section 9.3.2), so the peer can verify our grants
    /// against the permissions CA it already trusts. Without it the peer knows
    /// who we are and nothing about what we may do.
    pub(crate) fn with_local_permissions(mut self, permissions: Option<Vec<u8>>) -> Self {
        self.local_permissions = permissions;
        self
    }

    /// The `c.perm` this participant sends (DDS Security v1.1 Tables 49 and
    /// 50, listed unconditionally): its signed permissions document, or
    /// nothing, as an empty value, when it runs without access control.
    fn c_perm(&self) -> Vec<u8> {
        self.local_permissions.clone().unwrap_or_default()
    }

    /// The key-agreement suite string this machine was configured with.
    ///
    /// Introspection for in-crate tests: lets an e2e assert that the suite a
    /// `SecurityConfig` names is the one the live machine actually carries,
    /// instead of inferring it from handshake completion alone.
    #[cfg(test)]
    pub(crate) fn kagree_algo(&self) -> &str {
        &self.kagree_algo
    }

    // --------------------------------------------------------
    //  Public API
    // --------------------------------------------------------

    /// Initiate a handshake toward `remote_guid`.
    ///
    /// Called by the SPDP handler immediately after a remote secure
    /// participant is admitted. `local_cert_der` is the DER-encoded local
    /// identity certificate; `local_key_pem` is the PEM-encoded private key.
    /// The AuthRequest carries the participant data of `local_guid` as
    /// `c.pdata` (`handshake::pdata`).
    ///
    /// Returns `Some(SendRequest(...))` when local is the Initiator and no
    /// active session exists for this peer, and `Some(SendAuthRequest(...))`
    /// when local is the Responder and holds no session: the peer may hold
    /// one from before, and then nothing else would make it begin again
    /// (DDS Security v1.1 Sec.7.4.3.6.2, 9.3.2.4). Returns `Ok(None)` when a
    /// session is already in progress or complete.
    ///
    /// A new initiator attempt uses a fresh challenge1. If no remote
    /// AuthRequestMessageToken was received, that challenge also supplies
    /// the local token returned by `start_and_announce` (DDS Security v1.1
    /// Sec.9.3.3 Table 52). A received remote token instead binds challenge2
    /// of the Reply, and no local announcement is created.
    pub fn start(
        &self,
        local_guid: GUID,
        remote_guid: GUID,
        local_cert_der: &[u8],
        _local_key_pem: &[u8],
    ) -> Result<Option<HandshakeAction>, SecurityError> {
        self.start_attempt(local_guid, remote_guid, local_cert_der)
            .map(|(action, _)| action)
    }

    /// Return the action and whether this attempt created a local token.
    /// Both decisions are committed under the same session lock.
    fn start_attempt(
        &self,
        local_guid: GUID,
        remote_guid: GUID,
        local_cert_der: &[u8],
    ) -> Result<(Option<HandshakeAction>, bool), SecurityError> {
        // ONE key convention in this map (C9). The caller hands us the raw
        // PID_PARTICIPANT_GUID off the wire, whose entity-id half is whatever
        // the peer chose to put there; every other write and every read in this
        // file keys on prefix + ENTITYID_PARTICIPANT. Filing the ReqSent entry
        // under an unnormalized key hides it from the lookup that matches the
        // peer's AuthReply, and the handshake then dies at "received AuthReply
        // without a matching ReqSent state" with nothing pointing at the key.
        //
        // HDDS always writes ENTITYID_PARTICIPANT there, so the divergence is
        // invisible in self-pairing and only bites cross-vendor.
        //
        // Normalizing here is safe: `am_i_initiator` compares prefixes only, and
        // the stateless writer rebuilds the destination address from the prefix,
        // so neither the initiator election nor the addressing reads this half.
        let remote_guid = GUID::new(remote_guid.prefix, RTPS_ENTITYID_PARTICIPANT);

        if !am_i_initiator(&local_guid, &remote_guid) {
            return self
                .await_request(remote_guid)
                .map(|action| (action, false));
        }

        self.refuse_if_audit_degraded()?;
        self.refuse_if_local_identity_expired()?;

        // Guard: don't restart an active or completed session. Checked here
        // before any key is generated, and again under the write lock below,
        // where the decision is taken.
        {
            let sessions = self.handshakes.read();
            if !Self::may_start(&sessions, &remote_guid)
                || !sessions.has_room_for(&remote_guid, self.max_sessions)
            {
                return Ok((None, false));
            }
        }
        #[cfg(test)]
        self.parked();

        // A new attempt needs a fresh challenge1 (Sec.9.3.2.5.1, Table 49).
        // Retransmissions retain this request verbatim; start_and_announce
        // binds the local AuthRequestMessageToken to this attempt's nonce.
        let challenge1 = new_nonce()?;
        let request = self.new_request(local_cert_der, &local_guid, challenge1)?;
        let token = request.token.clone();

        let announce;
        {
            let mut sessions = self.sessions_mut();
            // Two announcements of the same peer can both pass the read
            // check above; only one session may begin, or the peer answers
            // the request whose state the other one overwrote.
            if !Self::may_start(&sessions, &remote_guid) {
                return Ok((None, false));
            }
            if !sessions.has_room_for(&remote_guid, self.max_sessions) {
                log::debug!(
                    "[security::handshake] {} not authenticated: this participant holds the \
                     most sessions it keeps",
                    remote_guid
                );
                return Ok((None, false));
            }
            // Table 52, validate_remote_identity: receipt of a remote
            // token makes our local token NIL. Its future_challenge binds
            // the Reply's challenge2, independent of SPDP arrival order.
            let expected_challenge2 = sessions.remote_future_challenges_of(&remote_guid);
            announce = expected_challenge2.is_empty();
            sessions.remote_future_challenges.remove(&remote_guid);
            sessions.begin(remote_guid);
            sessions
                .states
                .insert(remote_guid, request.into_state(expected_challenge2));
        }

        Ok((
            Some(HandshakeAction::SendRequest(remote_guid, token)),
            announce,
        ))
    }

    /// Begin a session and return the local AuthRequestMessageToken only
    /// when no remote token was received for this attempt (Table 52).
    /// An emitted announcement uses the committed Request's challenge1.
    pub fn start_and_announce(
        &self,
        local_guid: GUID,
        remote_guid: GUID,
        local_cert_der: &[u8],
        _local_key_pem: &[u8],
    ) -> Result<Vec<HandshakeAction>, SecurityError> {
        match self.start_attempt(local_guid, remote_guid, local_cert_der)? {
            (Some(HandshakeAction::SendRequest(remote, token)), true) => {
                let future_challenge = token.challenge1;
                Ok(vec![
                    HandshakeAction::SendAuthRequest(remote, AuthReqToken { future_challenge }),
                    HandshakeAction::SendRequest(remote, token),
                ])
            }
            (Some(other), _) => Ok(vec![other]),
            (None, _) => Ok(vec![]),
        }
    }

    /// The responder's side of `start`: with no session for the peer (or a
    /// failed one), ask it to begin one, and wait for its AuthRequest.
    fn await_request(&self, remote_guid: GUID) -> Result<Option<HandshakeAction>, SecurityError> {
        self.refuse_if_audit_degraded()?;
        self.refuse_if_local_identity_expired()?;
        if !Self::may_start(&self.handshakes.read(), &remote_guid) {
            return Ok(None);
        }
        let token;
        {
            let mut sessions = self.sessions_mut();
            if !Self::may_start(&sessions, &remote_guid) {
                return Ok(None);
            }
            if !sessions.has_room_for(&remote_guid, self.max_sessions) {
                log::debug!(
                    "[security::handshake] {} not authenticated: this participant holds the \
                     most sessions it keeps",
                    remote_guid
                );
                return Ok(None);
            }
            // A NIL local token still opens an unauthenticated waiting
            // session, so discovery keeps the peer's endpoints gated.
            let received_at = sessions
                .pending_auth_request(&remote_guid)
                .map(|pending| pending.received_at);
            // Receipt began this attempt, even when SPDP was delayed. The
            // pending token and its NIL-token wait must expire together.
            let started_at = received_at.unwrap_or_else(Instant::now);
            token = if received_at.is_some() {
                None
            } else {
                Some(AuthReqToken {
                    future_challenge: sessions.future_challenge(remote_guid)?,
                })
            };
            sessions.begin(remote_guid);
            sessions.states.insert(
                remote_guid,
                HandshakeState::AwaitingRequest {
                    future_challenge: token.as_ref().map(|token| token.future_challenge),
                    last_auth_request: token.clone(),
                    started_at,
                    retries: 0,
                },
            );
        }
        Ok(token.map(|token| HandshakeAction::SendAuthRequest(remote_guid, token)))
    }

    /// A fresh AuthRequest from the participant `local`, with the given
    /// `challenge1`: a new ephemeral key pair, and the challenge the caller
    /// chose.
    ///
    /// With a non-NIL local AuthRequestMessageToken, the caller supplies
    /// its future_challenge here (Table 52, begin_handshake_request).
    fn new_request(
        &self,
        local_cert_der: &[u8],
        local: &GUID,
        challenge1: [u8; 32],
    ) -> Result<NewRequest, SecurityError> {
        // A config typo here must be a loud local error before any packet
        // leaves, not a silent downgrade to P-256.
        let suite = KeyAgreementSuite::from_kagree_algo(&self.kagree_algo).ok_or_else(|| {
            SecurityError::CryptoError(format!(
                "unknown key_establishment_algorithm '{}' in local config -- refusing to \
                 start a handshake with a suite this build cannot perform",
                self.kagree_algo
            ))
        })?;
        let (our_dh_pub, our_dh_priv) = EcdhKeyExchange::generate_keypair(suite)?;
        let our_nonce = challenge1;
        let token = AuthRequestToken {
            identity_cert_der: local_cert_der.to_vec(),
            challenge1: our_nonce,
            dh1: our_dh_pub.clone(),
            pdata: pdata::serialize_with_capabilities(local, self.local_capabilities),
            dsign_algo: Dsign::of_cert(local_cert_der)?.name().to_string(),
            kagree_algo: self.kagree_algo.clone(),
            permissions_doc: Some(self.c_perm()),
        };
        Ok(NewRequest {
            token,
            our_nonce,
            our_dh_priv,
            our_dh_pub,
            suite,
        })
    }

    /// Whether `start` may begin a session toward `remote_guid`: none exists,
    /// or the last one failed, and none is out of the table being verified.
    fn may_start(sessions: &Sessions, remote_guid: &GUID) -> bool {
        if sessions.verifying.contains_key(remote_guid) {
            return false;
        }
        match sessions.states.get(remote_guid) {
            None | Some(HandshakeState::Failed { .. }) => true,
            Some(
                HandshakeState::Complete { .. }
                | HandshakeState::ReqSent { .. }
                | HandshakeState::AwaitingRequest { .. }
                | HandshakeState::ReplySent { .. },
            ) => false,
        }
    }

    /// Process an incoming raw token from the stateless channel.
    ///
    /// Decodes the bytes, dispatches to the correct handler based on token
    /// class_id and current peer state, and returns the action the caller
    /// must take.
    pub fn on_message(
        &self,
        remote_guid: GUID,
        bytes: &[u8],
        local_guid: GUID,
        local_cert_der: &[u8],
        local_key_pem: &[u8],
        ca_cert_pem: &[u8],
    ) -> Result<HandshakeAction, SecurityError> {
        self.refuse_if_audit_degraded()?;
        self.refuse_if_local_identity_expired()?;
        let token = parse_token(bytes)?;

        match token {
            TokenKind::AuthReq(auth_req) => {
                self.handle_auth_request(remote_guid, auth_req, local_guid, local_cert_der)
            }
            TokenKind::Request(req) => self.handle_request(
                remote_guid,
                req,
                local_guid,
                local_cert_der,
                local_key_pem,
                ca_cert_pem,
            ),
            TokenKind::Reply(rep) => {
                self.handle_reply(remote_guid, rep, local_cert_der, local_key_pem, ca_cert_pem)
            }
            TokenKind::Final(fin) => self.handle_final(remote_guid, fin, ca_cert_pem),
        }
    }

    /// Remove every session held for a participant that left discovery, in
    /// progress or complete, with the keys it carries.
    ///
    /// Called by discovery for every removal of a participant (its departure,
    /// its lease expiring, a probation purge). A participant that comes back
    /// under the same prefix is then a new peer: it is authenticated again,
    /// with fresh keys, instead of being held to a session its new process
    /// knows nothing about. Work in flight for the dropped session installs
    /// nothing (`Sessions::generations`).
    ///
    /// The key is the participant GUID (prefix + ENTITYID_PARTICIPANT), the
    /// one every write to the table uses.
    pub fn drop_handshake(&self, remote_guid: &GUID) -> HandshakeAction {
        self.sessions_mut().forget(remote_guid);
        HandshakeAction::Drop(*remote_guid)
    }

    /// Drain all per-peer handshake state.
    ///
    /// Called from `Participant::drop` to release all in-progress or
    /// completed handshake entries and their associated ECDH key material.
    /// After this call `is_authenticated` returns `false` for every GUID.
    pub fn drain(&self) {
        {
            let mut sessions = self.sessions_mut();
            *sessions = Sessions::default();
        }
        self.recent_nonces.lock().clear();
        log::debug!("[security::handshake] all per-peer handshake state cleared");
    }

    /// Check whether a peer has completed authentication.
    pub fn is_authenticated(&self, remote_guid: &GUID) -> bool {
        matches!(
            self.handshakes.read().states.get(remote_guid),
            Some(HandshakeState::Complete { .. })
        )
    }

    /// Whether this peer is taking part in the authentication protocol at all,
    /// in any state (in progress, complete, or failed).
    ///
    /// Distinguishes "not authenticated YET" from "not a security peer". A
    /// participant that never advertised an identity token never gets an entry
    /// here, so callers that gate on authentication can tell a peer they should
    /// wait for from a plaintext peer they should let through.
    pub fn has_session(&self, remote_guid: &GUID) -> bool {
        let sessions = self.handshakes.read();
        sessions.states.contains_key(remote_guid) || sessions.verifying.contains_key(remote_guid)
    }

    /// Whether a session runs next to this peer's session of record
    /// (`Sessions::superseding`): a re-authentication in flight.
    pub fn has_parallel_session(&self, remote_guid: &GUID) -> bool {
        let sessions = self.handshakes.read();
        sessions.superseding.contains_key(remote_guid)
            || sessions.verifying_parallel.contains_key(remote_guid)
    }

    /// Whether this peer's session of record failed, with none out of the
    /// table being verified: no key is changing for it until a new session
    /// begins (`start`).
    pub(crate) fn has_failed_session(&self, remote_guid: &GUID) -> bool {
        let sessions = self.handshakes.read();
        !sessions.verifying.contains_key(remote_guid)
            && matches!(
                sessions.states.get(remote_guid),
                Some(HandshakeState::Failed { .. })
            )
    }

    /// Retrieve the MasterSharedSecret for a completed peer, if any.
    ///
    /// Root key material. Returned in a `Zeroizing` buffer: the copy the caller
    /// holds is wiped when it drops, like the one the session keeps. It remains
    /// as the oracle the end-to-end test uses to assert that both sides of a
    /// pair agreed on the identical secret, which no derived key can substitute
    /// for.
    pub fn shared_secret_for(&self, remote_guid: &GUID) -> Option<SharedSecret> {
        match self.handshakes.read().states.get(remote_guid) {
            Some(HandshakeState::Complete { shared_secret, .. }) => Some(shared_secret.clone()),
            _ => None,
        }
    }

    /// The credentials a completed peer presented: its identity certificate
    /// and, if it sent one, its signed permissions document.
    ///
    /// Returns `None` for any state other than `Complete`; a peer still
    /// handshaking has presented nothing that has been checked yet.
    ///
    /// The two travel together, in ONE lock acquisition, on purpose: the
    /// certificate says WHO the peer is and the permissions document says what
    /// it may do, and evaluating a grant needs both at once. DDS-Security v1.1
    /// 9.4.3 selects the grants by matching the subject name in the identity
    /// certificate against the `<subject_name>` of the document, so a caller
    /// that fetched them in two calls could pair a certificate with the
    /// document of whichever session replaced it in between.
    ///
    /// The `Option` on the second half is load-bearing and is NOT flattened
    /// into the outer one: "completed, and sent no document" is a different
    /// fact from "never completed", and only the access-control layer may
    /// decide what the first one means.
    pub(crate) fn peer_credentials(
        &self,
        remote_guid: &GUID,
    ) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        match self.handshakes.read().states.get(remote_guid) {
            Some(HandshakeState::Complete {
                peer_cert,
                peer_permissions,
                ..
            }) => Some((peer_cert.clone(), peer_permissions.clone())),
            _ => None,
        }
    }

    /// The Table 67 KxKeys for `remote_prefix`'s volatile channel (both
    /// directions use the same material -- see `crypto::kx_keys`), or
    /// `None` when that peer has not completed the PKI-DH handshake.
    ///
    /// Takes the prefix so callers cannot use a different participant entity id.
    pub fn volatile_key_material(
        &self,
        remote_prefix: &[u8; 12],
    ) -> Option<crate::security::crypto::secure_submessage::WriterKeyMaterial> {
        let guid = GUID::new(*remote_prefix, RTPS_ENTITYID_PARTICIPANT);
        match self.handshakes.read().states.get(&guid) {
            Some(HandshakeState::Complete { keys, .. }) => Some(keys.volatile_key_material()),
            _ => None,
        }
    }

    /// GUID prefixes of every peer whose handshake is `Complete`.
    ///
    /// The key distributor's walk list: it crosses these with the local
    /// encrypting writers to decide which announcements to enqueue.
    pub fn authenticated_peer_prefixes(&self) -> Vec<[u8; 12]> {
        self.handshakes
            .read()
            .states
            .iter()
            .filter(|(_, state)| matches!(state, HandshakeState::Complete { .. }))
            .map(|(guid, _)| guid.prefix)
            .collect()
    }

    /// Number of peers that have completed the handshake.
    ///
    /// Read only by the writer's fail-closed refusal, so the error can say
    /// whether nobody authenticated or whether peers authenticated and the
    /// missing piece is data-key distribution. Never on a success path.
    pub fn authenticated_peer_count(&self) -> usize {
        self.handshakes
            .read()
            .states
            .values()
            .filter(|state| matches!(state, HandshakeState::Complete { .. }))
            .count()
    }

    /// Advance timeouts: retransmit the pending handshakes whose retry rung is
    /// due, and fail the sessions that have passed the absolute deadline.
    ///
    /// Returns the actions the caller must execute by handing each one to
    /// `pump::enqueue_action`. Unlike every other entry point here, `tick`
    /// needs no certificate material: `ReqSent` and `ReplySent` retain the
    /// token they transmitted, so a retransmission is a clone rather than a
    /// rebuild, and the returned `SendRequest` / `SendReply` are the ordinary
    /// variants that the pump already knows how to put on the wire.
    ///
    /// The ladder is measured from the FIRST transmission, so the three
    /// retransmissions land at `RETRY_DELAY_1`, `RETRY_DELAY_2` and
    /// `RETRY_DELAY_3` after it (1 s / 4 s / 16 s), matching the module-level
    /// backoff contract. `retries` is advanced *here*: a rung that fired
    /// without advancing it would re-fire on every subsequent call for the
    /// remainder of the session.
    ///
    /// Without an engine caller this method is inert and no session ever
    /// leaves `ReqSent` / `ReplySent`, which also blocks the `Failed` ->
    /// `start()` restart path in `handle_spdp`. The `hdds-stateless-writer`
    /// thread owns the call; see `pump::drive_timers`.
    ///
    /// # Locking
    ///
    /// Takes the write lock once for the whole pass. This method performs no
    /// crypto and no I/O -- it compares instants and clones a token -- so the
    /// exclusive section is bounded by the number of in-flight handshakes.
    /// Splitting it into a read pass and a write pass would reopen a window in
    /// which `on_message` completes a session that this method then re-arms.
    pub fn tick(&self, now: Instant) -> Vec<HandshakeAction> {
        self.tick_at(now, wall_clock_unix())
    }

    /// `tick` with the wall clock given: `unix_now` is Unix seconds, or `None`
    /// when the clock cannot be read. Tests pass the time they need, so an
    /// expiry is reached without sleeping.
    pub(crate) fn tick_at(&self, now: Instant, unix_now: Option<i64>) -> Vec<HandshakeAction> {
        let mut actions = Vec::new();
        let mut expired: Vec<(GUID, String)> = Vec::new();

        // The revocation list is re-read before the session lock is taken: the file
        // is I/O, and the sessions it revokes are found without holding the lock.
        #[cfg(feature = "security")]
        let listed: Vec<(GUID, Vec<u8>)> = match self.reload_revocation() {
            Some(list) => self.sessions_listed_by(&list),
            None => Vec::new(),
        };
        #[cfg(not(feature = "security"))]
        let listed: Vec<(GUID, Vec<u8>)> = Vec::new();

        let mut sessions = self.sessions_mut();

        // A request to begin that the peer never answered is no failed
        // authentication: it becomes `Failed` (so the next announcement asks
        // again, `start`) without a failure reported or audited.
        let mut unanswered: Vec<GUID> = Vec::new();
        // Whether this pass changed a session beyond its retry counters: the
        // machine's timer thread runs it periodically, and a pass with
        // nothing due must not move `state_epoch` (it would throw away every
        // admission verdict discovery cached, at every period).
        // A pending token may prepare the next attempt while an older one
        // still waits for Final. Expire it on its own receipt deadline.
        let pending_before: usize = sessions
            .remote_future_challenges
            .values()
            .map(VecDeque::len)
            .sum();
        sessions.remote_future_challenges.retain(|_, pending| {
            pending.retain(|announced| {
                now.saturating_duration_since(announced.received_at) < SESSION_DEADLINE
            });
            !pending.is_empty()
        });
        let pending_after: usize = sessions
            .remote_future_challenges
            .values()
            .map(VecDeque::len)
            .sum();
        let mut changed = pending_after != pending_before;
        for (guid, state) in sessions.states.iter_mut() {
            if let Some(reason) = Self::advance_ladder(guid, state, now, &mut actions) {
                if matches!(state, HandshakeState::AwaitingRequest { .. }) {
                    unanswered.push(*guid);
                } else {
                    actions.push(HandshakeAction::Failed(*guid, reason.clone()));
                    expired.push((*guid, reason));
                }
            }
        }
        for guid in unanswered {
            changed = true;
            log::debug!(
                "[security::handshake] {} did not begin a handshake within {:?}; asked again \
                 on its next announcement",
                guid,
                SESSION_DEADLINE
            );
            sessions.states.insert(
                guid,
                HandshakeState::Failed {
                    reason: "authentication request unanswered".into(),
                    failed_at: now,
                },
            );
        }

        // A re-authentication that never completes costs the completed
        // session nothing: it is forgotten, and no failure is reported for a
        // peer that is still authenticated.
        //
        // Except that the peer may have completed it. As responder we answer
        // an AuthRequest with our AuthReply, and the initiator completes on
        // that reply: if its AuthFinal (and our retransmissions) were lost,
        // it now holds a new secret and we the old one, and neither side's
        // `start` would ever begin again over a completed session. So when a
        // parallel session in which we already replied - or in which we
        // already asked the peer to begin - is abandoned while our session
        // of record is complete, we ask the peer to begin again (an
        // authentication request, Sec.7.4.3.6.2 of DDS Security v1.1), and
        // keep asking every deadline until a session completes. The peer
        // honours at most one such request per 30 s. A parallel session we
        // initiated cannot have completed on the peer's side without our
        // AuthFinal, which follows our own completion: it is just forgotten.
        //
        // The request carries the peer's one future_challenge (Sec.9.3.3,
        // Table 52), the one the session the peer may have completed
        // answered: a new challenge is not what makes the peer begin again,
        // the time is (`CROSSING_WINDOW`).
        // A completed session whose peer certificate has run out is torn down,
        // and it is done before the superseding pass below, so that a session
        // torn down here is not asked to begin again. The check is one
        // comparison per completed session on this periodic pass; the data
        // path does nothing new. DDS-Security v1.1 8.3.2.12 (AuthenticationListener)
        // says an identity that expires is revoked for its participant.
        let local = self.local_identity.get().copied();
        let local_expired =
            local.is_some_and(|(_, not_after)| certificate_has_expired(not_after, unix_now));
        let mut torn_down: Vec<(GUID, String, AuthenticationOutcome)> = Vec::new();
        for (guid, state) in sessions.states.iter() {
            if let HandshakeState::Complete {
                peer_cert,
                peer_cert_not_after,
                ..
            } = state
            {
                if listed
                    .iter()
                    .any(|(listed_guid, cert)| listed_guid == guid && cert == peer_cert)
                {
                    torn_down.push((
                        *guid,
                        "peer certificate is revoked: listed in the revocation list".to_string(),
                        AuthenticationOutcome::Revoked,
                    ));
                } else if local_expired {
                    torn_down.push((
                        *guid,
                        "local identity certificate expired: its notAfter has passed".to_string(),
                        AuthenticationOutcome::Failed,
                    ));
                } else if certificate_has_expired(*peer_cert_not_after, unix_now) {
                    torn_down.push((
                        *guid,
                        "peer certificate expired: its notAfter has passed".to_string(),
                        AuthenticationOutcome::Failed,
                    ));
                }
            }
        }
        for (guid, reason, _) in &torn_down {
            log::warn!(
                "[security::handshake] {} tore its authenticated session down: {}",
                guid,
                reason
            );
            sessions.states.insert(
                *guid,
                HandshakeState::Failed {
                    reason: reason.clone(),
                    failed_at: now,
                },
            );
            actions.push(HandshakeAction::Failed(*guid, reason.clone()));
            changed = true;
        }

        let mut abandoned: Vec<(GUID, bool)> = Vec::new();
        for (guid, state) in sessions.superseding.iter_mut() {
            if Self::advance_ladder(guid, state, now, &mut actions).is_some() {
                let peer_may_have_completed = matches!(
                    state,
                    HandshakeState::ReplySent { .. } | HandshakeState::AwaitingRequest { .. }
                );
                abandoned.push((*guid, peer_may_have_completed));
            }
        }
        for (guid, peer_may_have_completed) in abandoned {
            changed = true;
            sessions.superseding.remove(&guid);
            // Its generation goes with it: a late verdict on it installs
            // nothing, and the entry is not left behind for good.
            sessions.superseding_generations.remove(&guid);
            let record_complete = matches!(
                sessions.states.get(&guid),
                Some(HandshakeState::Complete { .. })
            );
            if peer_may_have_completed && record_complete {
                if let Ok(future_challenge) = sessions.future_challenge(guid) {
                    let token = AuthReqToken { future_challenge };
                    log::warn!(
                        "[security::handshake] re-authentication of {} abandoned after {:?}, \
                         where the peer may have completed it: asking it to begin again",
                        guid,
                        SESSION_DEADLINE
                    );
                    sessions.begin_superseding(guid);
                    sessions.superseding.insert(
                        guid,
                        HandshakeState::AwaitingRequest {
                            future_challenge: Some(future_challenge),
                            last_auth_request: Some(token.clone()),
                            started_at: now,
                            retries: 0,
                        },
                    );
                    actions.push(HandshakeAction::SendAuthRequest(guid, token));
                    continue;
                }
            }
            log::warn!(
                "[security::handshake] re-authentication of {} abandoned after {:?}; the \
                 completed session stays",
                guid,
                SESSION_DEADLINE
            );
        }

        let mut audit_failures = Vec::with_capacity(expired.len());
        if !changed && actions.is_empty() && expired.is_empty() {
            sessions.unchanged();
        }
        for (guid, reason) in expired {
            log::warn!(
                "[security::handshake] session with {} expired after {:?}: {}",
                guid,
                SESSION_DEADLINE,
                reason
            );
            sessions.states.insert(
                guid,
                HandshakeState::Failed {
                    reason,
                    failed_at: now,
                },
            );
            audit_failures.push(guid);
        }
        drop(sessions);

        if let Some((local_guid, _)) = local.filter(|_| local_expired) {
            if !self
                .local_expiry_reported
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                log::error!(
                    "[security::handshake] the local identity {} has expired: no handshake is \
                     begun or advanced, and every authenticated session is ended",
                    local_guid
                );
                self.audit_authentication(&local_guid, AuthenticationOutcome::Revoked);
            }
        }
        for (guid, _, outcome) in &torn_down {
            self.audit_authentication(guid, *outcome);
            if let Some(hook) = self.on_torn_down.get() {
                hook(guid);
            }
        }
        for guid in audit_failures {
            self.audit_authentication(&guid, AuthenticationOutcome::Failed);
        }
        self.free_failed_of_unknown(now);

        actions
    }

    /// One step of the retry ladder for one session: queue its
    /// retransmission when a rung is due, and return the reason when the
    /// session has passed `SESSION_DEADLINE`.
    fn advance_ladder(
        guid: &GUID,
        state: &mut HandshakeState,
        now: Instant,
        actions: &mut Vec<HandshakeAction>,
    ) -> Option<String> {
        match state {
            HandshakeState::ReqSent {
                last_request,
                started_at,
                retries,
                ..
            } => {
                let elapsed = now.saturating_duration_since(*started_at);
                if elapsed > SESSION_DEADLINE {
                    return Some("AuthRequest deadline exceeded (30 s)".into());
                }
                if retry_due(*retries, elapsed) {
                    *retries += 1;
                    log::debug!(
                        "[security::handshake] retransmitting AuthRequest to {} \
                        (attempt {} of {})",
                        guid,
                        retries,
                        MAX_RETRIES
                    );
                    actions.push(HandshakeAction::SendRequest(*guid, last_request.clone()));
                }
                None
            }
            HandshakeState::ReplySent {
                last_reply,
                started_at,
                retries,
                ..
            } => {
                let elapsed = now.saturating_duration_since(*started_at);
                if elapsed > SESSION_DEADLINE {
                    return Some("AuthReply deadline exceeded (30 s)".into());
                }
                if retry_due(*retries, elapsed) {
                    *retries += 1;
                    log::debug!(
                        "[security::handshake] retransmitting AuthReply to {} \
                        (attempt {} of {})",
                        guid,
                        retries,
                        MAX_RETRIES
                    );
                    actions.push(HandshakeAction::SendReply(*guid, last_reply.clone()));
                }
                None
            }
            HandshakeState::AwaitingRequest {
                last_auth_request,
                started_at,
                retries,
                ..
            } => {
                let elapsed = now.saturating_duration_since(*started_at);
                if elapsed > SESSION_DEADLINE {
                    return Some("authentication request unanswered (30 s)".into());
                }
                if let Some(token) = last_auth_request {
                    if retry_due(*retries, elapsed) {
                        *retries += 1;
                        actions.push(HandshakeAction::SendAuthRequest(*guid, token.clone()));
                    }
                }
                None
            }
            HandshakeState::Complete { .. } | HandshakeState::Failed { .. } => None,
        }
    }

    // --------------------------------------------------------
    //  Internal handlers
    // --------------------------------------------------------

    /// An authentication request from `remote_guid` (DDS Security v1.1
    /// Sec.7.4.3.6.2, 9.3.2.4): a participant that needs a handshake with us,
    /// and is not the one that begins it, asks us to begin one.
    ///
    /// Honoured only when we are its initiator and hold a `Complete` session
    /// with it: that is the one case in which nothing else would make us
    /// begin, because a participant re-created under the same prefix within
    /// its lease is, to discovery, the same participant (its farewell on the
    /// plain topic is ignored, its announcements keep it alive), and `start`
    /// refuses to begin over a completed session. The new session runs next
    /// to the completed one, which keeps carrying the peer's traffic until the
    /// new one's AuthReply - signed by the peer, under the certificate it
    /// completed with, and answering with challenge2 = `future_challenge` -
    /// verifies (`handle_reply`).
    ///
    /// Without a session, `start` on the peer's announcement begins one; with
    /// one in progress, it completes or times out. Neither needs the request,
    /// and honouring it for a prefix discovery does not know would let anyone
    /// make us keep state for any prefix.
    ///
    /// Bounded: `REAUTHENTICATIONS_PER_INTERVAL` sessions per peer per
    /// `REAUTHENTICATION_INTERVAL`, never while one is in flight.
    fn handle_auth_request(
        &self,
        remote_guid: GUID,
        auth_req: AuthReqToken,
        local_guid: GUID,
        local_cert_der: &[u8],
    ) -> Result<HandshakeAction, SecurityError> {
        if !am_i_initiator(&local_guid, &remote_guid) {
            // Table 52: retain the peer's token for this attempt's
            // challenge1 check, even when its SPDP has not arrived yet.
            let mut sessions = self.sessions_mut();
            // A delayed announcement of an already accepted Request belongs
            // to that old attempt, even if it arrives after its deadline.
            if !self.nonce_seen(&auth_req.future_challenge) {
                sessions.remember_remote_future_challenge(remote_guid, auth_req.future_challenge);
            }
            return Ok(HandshakeAction::Ignored(
                remote_guid,
                "own AuthRequestMessageToken announcement cached for challenge1 cross-check".into(),
            ));
        }
        // Remembered whatever the state: when a parallel session is begun
        // on a forged request, the peer's own announcement, arriving while it
        // is in flight, is what its Reply answers (`handle_reply`).
        self.sessions_mut()
            .remember_remote_future_challenge(remote_guid, auth_req.future_challenge);
        let now = Instant::now();
        let ignored = |sessions: &Sessions| -> Option<&'static str> {
            let Some(HandshakeState::Complete {
                peer_challenge2,
                completed_at,
                ..
            }) = sessions.states.get(&remote_guid)
            else {
                return Some("no completed session: the announcement begins one");
            };
            // The responder asks as soon as it hears us, and we begin on its
            // announcement as well: the two cross, it answers our
            // AuthRequest with the challenge it announced, and its request
            // can still reach us after we completed (late, or retransmitted
            // by its ladder before our AuthRequest arrived). Honoured, it
            // re-keyed a pair that had just authenticated and took the one
            // re-keying of the interval, so a peer that really restarted
            // within the next 30 s waited them out unauthenticated.
            //
            // Only the challenge of the session of record is remembered: a
            // request of an EARLIER session (a previous incarnation of the
            // peer, delivered after the current one completed) carries
            // another challenge and is still honoured. It re-keys a pair
            // that works and spends the interval; it cannot be told from a
            // peer that restarted again without remembering every challenge
            // the peer ever announced, which an unsigned request would let
            // anyone grow.
            //
            // And only while the request can be one that crossed our
            // completion (`CROSSING_WINDOW`): the peer announces one
            // challenge per identity (Sec.9.3.3, Table 52), so a request it
            // sends after giving up on a session we completed - our AuthFinal
            // lost with every retransmission, `tick` - carries this same
            // challenge, and must begin a session, or the two sides hold two
            // secrets for good.
            if *peer_challenge2 == Some(auth_req.future_challenge)
                && now.saturating_duration_since(*completed_at) < CROSSING_WINDOW
            {
                return Some("the request the completed session answered, crossing it");
            }
            if sessions.superseding.contains_key(&remote_guid) {
                return Some("a new session is already in flight");
            }
            let began_in_interval =
                sessions
                    .reauthentications
                    .get(&remote_guid)
                    .map_or(0, |began| {
                        began
                            .iter()
                            .filter(|at| {
                                now.saturating_duration_since(**at) < REAUTHENTICATION_INTERVAL
                            })
                            .count()
                    });
            if began_in_interval >= REAUTHENTICATIONS_PER_INTERVAL {
                return Some("three new sessions per peer per 30 s");
            }
            None
        };
        if let Some(reason) = ignored(&self.handshakes.read()) {
            return Ok(HandshakeAction::Ignored(remote_guid, reason.into()));
        }

        // We already hold the peer's own announcement (it is what triggered
        // this call), so our local_auth_request_token toward it is TokenNIL:
        // challenge1 is a fresh nonce, not a future_challenge we announced
        // (DDS Security v1.1 Sec.9.3.3 Table 52, `begin_handshake_request`).
        let request = self.new_request(local_cert_der, &local_guid, new_nonce()?)?;
        let token = request.token.clone();
        {
            let mut sessions = self.sessions_mut();
            if let Some(reason) = ignored(&sessions) {
                return Ok(HandshakeAction::Ignored(remote_guid, reason.into()));
            }
            let began = sessions.reauthentications.entry(remote_guid).or_default();
            began.retain(|at| now.saturating_duration_since(*at) < REAUTHENTICATION_INTERVAL);
            began.push_back(now);
            sessions.begin_superseding(remote_guid);
            sessions.superseding.insert(
                remote_guid,
                request.into_state(vec![auth_req.future_challenge]),
            );
        }
        log::info!(
            "[security::handshake] {} asks to authenticate again: new session begun next to \
             the completed one",
            remote_guid
        );
        Ok(HandshakeAction::SendRequest(remote_guid, token))
    }

    fn handle_request(
        &self,
        remote_guid: GUID,
        req: AuthRequestToken,
        local_guid: GUID,
        local_cert_der: &[u8],
        local_key_pem: &[u8],
        ca_cert_pem: &[u8],
    ) -> Result<HandshakeAction, SecurityError> {
        // Role guard: a participant that is the Initiator toward this peer
        // must not act as Responder for an incoming AuthRequest.
        if am_i_initiator(&local_guid, &remote_guid) {
            return Err(SecurityError::AuthenticationFailed(
                "received AuthRequest from a peer this participant initiates toward (role collision, discarded)".into(),
            ));
        }

        // Replay protection.
        if self.nonce_seen(&req.challenge1) {
            return Err(SecurityError::AuthenticationFailed(
                "AuthRequest replay: challenge1 nonce already in window".into(),
            ));
        }
        self.handshakes
            .read()
            .validate_remote_challenge(&remote_guid, &req.challenge1)?;

        // A peer we completed with authenticates again only under the identity
        // it completed with. Checked before any work is spent on the request,
        // and again where the session is filed.
        Self::refuses_reauthentication(&self.handshakes.read().states, &remote_guid, &req)?;

        // An AuthRequest is signed by nobody, and answering it costs a chain
        // verification, a key pair and a signature: none is spent on a
        // participant discovery has not seen (its announcement begins the
        // handshake from our side too, and the initiator retransmits), past
        // the sessions this machine holds, nor past the responder budget of
        // the interval. Refused quietly: anyone can send one.
        if !self.participant_known(&remote_guid.prefix) {
            return Ok(HandshakeAction::Ignored(
                remote_guid,
                "AuthRequest from a participant discovery does not know".into(),
            ));
        }
        if !self
            .handshakes
            .read()
            .has_room_for(&remote_guid, self.max_sessions)
        {
            return Ok(HandshakeAction::Ignored(
                remote_guid,
                "AuthRequest past the most sessions this participant holds".into(),
            ));
        }
        if !self.take_responder_budget(Instant::now()) {
            return Ok(HandshakeAction::Ignored(
                remote_guid,
                "AuthRequest past the responder budget of the interval".into(),
            ));
        }

        // Validate initiator certificate.
        validate_cert_chain(
            &req.identity_cert_der,
            ca_cert_pem,
            self.revocation_list().as_deref(),
        )?;
        // And the participant it speaks for (DDS Security v1.1 Sec.9.3.3,
        // Table 52, begin_handshake_reply).
        Self::refuses_foreign_pdata(&remote_guid, &req.pdata, &req.identity_cert_der)?;
        // The signature algorithm it announces is its key's (Sec.9.3.2.5.1):
        // its AuthFinal is verified by it (`handle_final`).
        Dsign::announced(&req.dsign_algo, &req.identity_cert_der)?;

        // Suite policy, fail closed on both axes (TODO 2.3):
        // - an UNKNOWN advertised suite is refused, never answered with P-256
        //   material the initiator did not ask for;
        // - a KNOWN suite that differs from our own configured one is refused
        //   rather than silently adopted. The old behaviour ("responder adopts
        //   whatever the initiator advertises") made a downgrade invisible: a
        //   P-384-configured responder would complete a P-256 handshake and
        //   nothing anywhere would say so. Deployments that intend P-384 get
        //   it on both sides or get a loud authentication failure.
        let suite =
            KeyAgreementSuite::from_kagree_algo(algo_name(&req.kagree_algo)).ok_or_else(|| {
                SecurityError::CryptoError(format!(
                    "initiator advertised unsupported kagree_algo '{}' -- refusing the handshake",
                    req.kagree_algo
                ))
            })?;
        let our_suite =
            KeyAgreementSuite::from_kagree_algo(&self.kagree_algo).ok_or_else(|| {
                SecurityError::CryptoError(format!(
                    "unknown key_establishment_algorithm '{}' in local config",
                    self.kagree_algo
                ))
            })?;
        if suite != our_suite {
            return Err(SecurityError::AuthenticationFailed(format!(
                "key-agreement suite mismatch: initiator advertised '{}', local policy is \
                 '{}' -- refusing rather than downgrading",
                req.kagree_algo, self.kagree_algo
            )));
        }

        // Generate our ECDH keypair. Our challenge2 is the future_challenge
        // of our authentication request toward this identity (DDS Security
        // v1.1 Sec.9.3.3 Table 52, begin_handshake_reply: "use the value of
        // property named future_challenge found in the
        // local_auth_request_token to fill the property named challenge2"),
        // which the peer checks when it began on that request: the one
        // challenge we hold for the identity, generated now if we never
        // announced it. It does not change while the reply is signed with no
        // lock held, so an announcement handled meanwhile asks for the
        // session this reply answers.
        let (our_dh_pub, our_dh_priv) = EcdhKeyExchange::generate_keypair(suite)?;
        let hash_c1 = req.hash_c1()?;
        let our_nonce = self.sessions_mut().future_challenge(remote_guid)?;

        let mut reply = AuthReplyToken {
            responder_cert_der: local_cert_der.to_vec(),
            pdata: pdata::serialize_with_capabilities(&local_guid, self.local_capabilities),
            dsign_algo: Dsign::of_cert(local_cert_der)?.name().to_string(),
            kagree_algo: self.kagree_algo.clone(),
            hash_c1: Some(hash_c1),
            challenge1: req.challenge1,
            dh1: Some(req.dh1.clone()),
            challenge2: our_nonce,
            dh2: our_dh_pub.clone(),
            signature: Vec::new(),
            permissions_doc: Some(self.c_perm()),
        };
        // DDS Security v1.1 Sec.9.3.2.5.2 (Table 50, signature).
        let sign_input = reply_sign_input(
            &reply.hash_c2()?,
            &our_nonce,
            &our_dh_pub,
            &req.challenge1,
            &req.dh1,
            &hash_c1,
        )?;
        reply.signature = sign_bytes(&sign_input, local_key_pem)?;
        #[cfg(test)]
        self.parked();

        let mut sessions = self.sessions_mut();
        Self::refuses_reauthentication(&sessions.states, &remote_guid, &req)?;
        if !sessions.has_room_for(&remote_guid, self.max_sessions) {
            return Ok(HandshakeAction::Ignored(
                remote_guid,
                "AuthRequest past the most sessions this participant holds".into(),
            ));
        }

        // Commit replay admission only after every Request check passed.
        // Recheck under the session lock: another handler may have accepted
        // this nonce or received an announcement while we signed the reply.
        sessions.validate_remote_challenge(&remote_guid, &req.challenge1)?;
        if self.nonce_seen(&req.challenge1) {
            return Err(SecurityError::AuthenticationFailed(
                "AuthRequest replay: challenge1 nonce already in window".into(),
            ));
        }
        self.record_nonce(req.challenge1);
        sessions.remote_future_challenges.remove(&remote_guid);

        let session = HandshakeState::ReplySent {
            our_nonce,
            peer_nonce: req.challenge1,
            our_dh_priv,
            our_dh_pub,
            peer_dh_pub: req.dh1.clone(),
            suite,
            peer_cert: req.identity_cert_der.clone(),
            peer_permissions: req.permissions_document(),
            last_reply: reply.clone(),
            started_at: Instant::now(),
            retries: 0,
        };

        if sessions.verifying.contains_key(&remote_guid)
            || matches!(
                sessions.states.get(&remote_guid),
                Some(HandshakeState::Complete { .. } | HandshakeState::ReplySent { .. })
            )
        {
            // The session of record - completed, or in progress (its
            // AuthFinal possibly out of the table being verified) - keeps
            // its place until this one's AuthFinal verifies
            // (`handle_final`): an unsigned AuthRequest replaces nothing.
            // An in-progress one can still complete, and then this one is
            // forgotten.
            log::debug!(
                "[security::handshake] {} sent another AuthRequest; the session of record \
                 stays until one of the two completes",
                remote_guid
            );
            sessions.begin_superseding(remote_guid);
            sessions.superseding.insert(remote_guid, session);
        } else {
            sessions.begin(remote_guid);
            sessions.states.insert(remote_guid, session);
        }
        Ok(HandshakeAction::SendReply(remote_guid, reply))
    }

    /// Refuse an AuthRequest from a peer we completed with when it presents
    /// another certificate than the one it completed with.
    ///
    /// The request is signed by nobody. Without this, any certificate the CA
    /// issued could open a session under the prefix of a peer that already
    /// authenticated and, with its own key, complete it: the session of record
    /// would then belong to whoever asked last. Binding the participant to
    /// the certificate on FIRST contact is the 47-bit subject-name check of
    /// DDS Security v1.1 Sec.9.3.3 Table 52 (begin_handshake_reply),
    /// `refuses_foreign_pdata`; this one also holds for two certificates of
    /// one subject.
    fn refuses_reauthentication(
        states: &HashMap<GUID, HandshakeState>,
        remote_guid: &GUID,
        req: &AuthRequestToken,
    ) -> Result<(), SecurityError> {
        match states.get(remote_guid) {
            Some(HandshakeState::Complete { peer_cert, .. })
                if *peer_cert != req.identity_cert_der =>
            {
                Err(SecurityError::AuthenticationFailed(
                    "AuthRequest for an authenticated peer presents another certificate than \
                     the one it authenticated with: refused, the completed session stays"
                        .into(),
                ))
            }
            _ => Ok(()),
        }
    }

    /// Refuse a peer whose participant data (`c.pdata`) is not that of the
    /// participant its certificate names, or not that of `remote_guid`, the
    /// participant the handshake is with.
    ///
    /// DDS Security v1.1 Sec.9.3.3, Table 52, begin_handshake_reply: "The
    /// operation shall verify that the first bit of the participant_guid of
    /// the ParticipantBuiltinTopic data inside the c.pdata is set to 1 and
    /// that the following 47 bits match the first 47 bits of the SHA-256 hash
    /// of the SubjectName appearing in the IdentityCredential. If this
    /// verification fails, the operation shall fail"
    /// (`authentication::guid_binding`). Cyclone DDS (`validate_pdata`) and
    /// Fast DDS check it on the request and on the reply; so do we.
    ///
    /// The GUID must also be `remote_guid`'s (its prefix; the entity id is
    /// the participant's): every key and every verdict here is filed under
    /// the participant the messages come from, so participant data naming
    /// another participant, even one bound to the same certificate, would
    /// vouch for a participant the handshake does not authenticate. The
    /// prefix of the HDDS shape before the binding (its vendor id first) is
    /// no exception: HDDS before 1.5 cannot authenticate with this release.
    fn refuses_foreign_pdata(
        remote_guid: &GUID,
        pdata: &[u8],
        cert: &[u8],
    ) -> Result<(), SecurityError> {
        use crate::security::authentication::guid_binding::{
            binding_of, subject_name_der, PrefixBinding,
        };
        let named = pdata::participant_guid(pdata)?;
        if binding_of(&named.prefix, &subject_name_der(cert)?) != PrefixBinding::Bound {
            return Err(SecurityError::AuthenticationFailed(format!(
                "c.pdata names participant {}, which is not one its certificate names: bit 0 \
                 of its prefix is not 1 or bits 1 to 47 are not those of the certificate's \
                 subject hash (DDS Security v1.1 Sec.9.3.3, Table 52)",
                named
            )));
        }
        if named.prefix != remote_guid.prefix {
            return Err(SecurityError::AuthenticationFailed(format!(
                "c.pdata names participant {}, not {}, the participant the handshake is with",
                named, remote_guid
            )));
        }
        Ok(())
    }

    fn handle_reply(
        &self,
        remote_guid: GUID,
        rep: AuthReplyToken,
        // Initiator cert is not embedded in AuthFinal per DDS Security v1.1 sec. 9.3.4.3.
        _local_cert_der: &[u8],
        local_key_pem: &[u8],
        ca_cert_pem: &[u8],
    ) -> Result<HandshakeAction, SecurityError> {
        // Classify before touching the table. Removing first and asking
        // questions afterwards would let a duplicate AuthReply -- one the
        // responder's own retry ladder produced because our AuthFinal was
        // lost -- delete a Complete session together with the
        // MasterSharedSecret inside it.
        //
        // With a session begun on the peer's authentication request next to
        // the completed one (`handle_auth_request`), the reply that answers
        // ITS AuthRequest (same challenge1) is for it; any other is a
        // duplicate for the completed session.
        let (superseding, completed_peer_cert, completed_request) = {
            let sessions = self.handshakes.read();
            let for_parallel = matches!(
                sessions.superseding.get(&remote_guid),
                Some(HandshakeState::ReqSent { our_nonce, .. }) if rep.challenge1 == *our_nonce
            );
            match sessions.states.get(&remote_guid) {
                Some(HandshakeState::ReqSent { .. }) => (false, None, None),
                Some(HandshakeState::Complete {
                    peer_cert,
                    our_request,
                    ..
                }) => (for_parallel, Some(peer_cert.clone()), our_request.clone()),
                _ => {
                    return Err(SecurityError::AuthenticationFailed(
                        "received AuthReply without a matching ReqSent state".into(),
                    ));
                }
            }
        };

        if !superseding {
            if let Some(peer_cert) = completed_peer_cert {
                return self.resend_final_for_completed(
                    remote_guid,
                    rep,
                    &peer_cert,
                    completed_request.as_ref(),
                    local_key_pem,
                    ca_cert_pem,
                );
            }
        }

        // Take the ReqSent state out, whole, and the generation it belongs
        // to: what this reply completes is installed only if that session is
        // still the peer's when the work is done, and a reply refused puts it
        // back (`put_back_refused`).
        let (state, slot) = {
            let mut sessions = self.sessions_mut();
            let slot = if superseding {
                Slot::Superseding(sessions.superseding_generation(&remote_guid))
            } else {
                Slot::Record(sessions.generation(&remote_guid))
            };
            let table = if superseding {
                &mut sessions.superseding
            } else {
                &mut sessions.states
            };
            let taken = match table.remove(&remote_guid) {
                Some(state @ HandshakeState::ReqSent { .. }) => (state, slot),
                other => {
                    // The state changed between the two locks. Put back what
                    // we took rather than dropping a session on the floor.
                    if let Some(state) = other {
                        table.insert(remote_guid, state);
                    }
                    return Err(SecurityError::AuthenticationFailed(
                        "received AuthReply without a matching ReqSent state".into(),
                    ));
                }
            };
            sessions.taken_for_verification(remote_guid, slot);
            taken
        };
        let _verifying = Verifying::new(&self.handshakes, remote_guid, slot);
        #[cfg(test)]
        self.parked();

        let HandshakeState::ReqSent {
            our_nonce,
            our_dh_pub,
            expected_challenge2,
            last_request,
            ..
        } = &state
        else {
            return Err(SecurityError::AuthenticationFailed(
                "received AuthReply without a matching ReqSent state".into(),
            ));
        };
        let (our_nonce, our_dh_pub, expected_challenge2) =
            (*our_nonce, our_dh_pub.clone(), expected_challenge2.clone());
        let our_hash_c1 = last_request.hash_c1();

        // A reply that does not validate is refused: the session of record
        // is put back, a parallel one forgotten (`put_back_refused`).
        let refuse = |state: HandshakeState, reason: String| {
            self.put_back_refused(remote_guid, slot, state, reason, "AuthReply")
        };
        let our_hash_c1 = match our_hash_c1 {
            Ok(hash) => hash,
            Err(e) => return refuse(state, format!("hash_c1 of our AuthRequest: {}", e)),
        };
        // The hash of the request the responder answered, when it sends it
        // (optional, Table 50), is the hash of ours.
        if rep.hash_c1.is_some_and(|echo| echo != our_hash_c1) {
            return refuse(state, "AuthReply hash_c1 echo mismatch".to_string());
        }
        let hash_c2 = match rep.hash_c2() {
            Ok(hash) => hash,
            Err(e) => return refuse(state, format!("AuthReply hash_c2: {}", e)),
        };

        // Verify challenge1 echo.
        if rep.challenge1 != our_nonce {
            return refuse(state, "AuthReply challenge1 echo mismatch".to_string());
        }

        // The dh1 echo, when the responder sends it (optional, Table 50), is
        // ours.
        if rep.dh1.as_ref().is_some_and(|echo| *echo != our_dh_pub) {
            return refuse(state, "AuthReply dh1 echo mismatch".to_string());
        }

        // The peer asked us to begin this session and announced the challenge
        // it would answer with (DDS Security v1.1 Sec.9.3.2.5.2): the one
        // the session was begun on, or one it announced since. An
        // announcement is signed by nobody, so the session may have been
        // begun on a forged one; the peer's own, received while it was in
        // flight, is the one its Reply answers.
        if !expected_challenge2.is_empty()
            && !expected_challenge2.contains(&rep.challenge2)
            && !self
                .handshakes
                .read()
                .remote_future_challenges_of(&remote_guid)
                .contains(&rep.challenge2)
        {
            return refuse(
                state,
                "AuthReply challenge2 is not the future_challenge the peer announced".to_string(),
            );
        }

        // A new session next to a completed one stays with the identity that
        // completed (see `refuses_reauthentication` for the responder's side).
        if superseding && completed_peer_cert.as_deref() != Some(&rep.responder_cert_der[..]) {
            return refuse(
                state,
                "AuthReply for a new session presents another certificate than the completed \
                 one"
                .to_string(),
            );
        }

        // Validate responder certificate.
        if let Err(e) = validate_cert_chain(
            &rep.responder_cert_der,
            ca_cert_pem,
            self.revocation_list().as_deref(),
        ) {
            return refuse(state, format!("responder cert invalid: {}", e));
        }
        // The responder's participant data is checked as the initiator's is
        // (Table 52 has the responder check the initiator; the binding holds
        // for every participant, and Cyclone DDS and Fast DDS check the
        // reply's too).
        if let Err(e) =
            Self::refuses_foreign_pdata(&remote_guid, &rep.pdata, &rep.responder_cert_der)
        {
            return refuse(state, e.to_string());
        }

        // The signature algorithm the responder announces is its key's
        // (Sec.9.3.2.5.2), and its signature is verified by it.
        let dsign = match Dsign::announced(&rep.dsign_algo, &rep.responder_cert_der) {
            Ok(dsign) => dsign,
            Err(e) => return refuse(state, e.to_string()),
        };

        // The signature of Sec.9.3.2.5.2 (Table 50), over our own challenge1,
        // dh1 and hash_c1 and the responder's challenge2, dh2 and hash_c2:
        // a reply whose dh2 is not the one the responder signed is refused.
        let expected_input = match reply_sign_input(
            &hash_c2,
            &rep.challenge2,
            &rep.dh2,
            &our_nonce,
            &our_dh_pub,
            &our_hash_c1,
        ) {
            Ok(input) => input,
            Err(e) => return refuse(state, format!("AuthReply signature input: {}", e)),
        };
        match verify_sig(
            &expected_input,
            &rep.signature,
            &rep.responder_cert_der,
            dsign,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return refuse(state, "AuthReply signature verification failed".to_string());
            }
            Err(e) => {
                return refuse(state, format!("AuthReply signature error: {}", e));
            }
        }

        // The reply validated: the session is consumed from here (its
        // EphemeralPrivateKey goes into the ECDH).
        let HandshakeState::ReqSent {
            our_dh_priv, suite, ..
        } = state
        else {
            return Err(SecurityError::AuthenticationFailed(
                "received AuthReply without a matching ReqSent state".into(),
            ));
        };
        // Past this point a failure is the validated peer's: the session of
        // record is recorded as failed, a parallel one only forgotten.
        let fail = |reason: String| -> Result<HandshakeAction, SecurityError> {
            match slot {
                Slot::Superseding(_) => {
                    log::warn!(
                        "[security::handshake] new session with {} refused at AuthReply ({}); \
                         the completed session stays",
                        remote_guid,
                        reason
                    );
                    Err(SecurityError::AuthenticationFailed(reason))
                }
                Slot::Record(generation) => {
                    self.fail(&remote_guid, generation, reason.clone());
                    Ok(HandshakeAction::Failed(remote_guid, reason))
                }
            }
        };

        // Take ownership of rep.dh2 once; clone into the token, keep original for ECDH.
        let peer_permissions = rep.permissions_document();
        let peer_dh2 = rep.dh2;

        // Build AuthFinal, signed as Sec.9.3.2.5.3 (Table 51) defines.
        let final_input = final_sign_input(
            &our_hash_c1,
            &our_nonce,
            &our_dh_pub,
            &rep.challenge2,
            &peer_dh2,
            &hash_c2,
        )?;
        let final_sig = sign_bytes(&final_input, local_key_pem)?;

        let our_request = Some((our_nonce, our_dh_pub.clone(), our_hash_c1));
        let final_token = AuthFinalToken {
            hash_c1: Some(our_hash_c1),
            hash_c2: Some(hash_c2),
            challenge1: our_nonce,
            dh1: Some(our_dh_pub),
            dh2: Some(peer_dh2.clone()),
            challenge2: rep.challenge2,
            signature: final_sig,
        };

        // Derive MasterSharedSecret: ECDH(our_priv, responder_dh_pub) -> HKDF
        let shared_secret =
            match EcdhKeyExchange::derive_shared_secret(suite, our_dh_priv, &peer_dh2) {
                Ok(s) => s,
                Err(e) => {
                    return fail(format!("ECDH derivation failed: {}", e));
                }
            };
        let hkdf_salt: Vec<u8> = [our_nonce.as_slice(), rep.challenge2.as_slice()].concat();
        let master_secret = SessionKeyManager::derive_session_key_with_suite(
            suite,
            &shared_secret,
            &hkdf_salt,
            b"DDS Security v1.1 MasterSharedSecret",
        )?;

        // Retain the volatile-channel inputs in both completion paths.
        // Doing it at the pump's `Completed` arm instead would key only
        // responders: the initiator returns SendFinal without `Completed`.
        //
        // The volatile channel's own KxKeys (Table 67) need the
        // authentication protocol's `SharedSecret` (Table 53:
        // `SHA256(DHSharedSecret)`), not the `master_secret` above (HDDS's
        // own extra HKDF step over challenge1||challenge2). challenge1 is
        // the initiator's nonce (`our_nonce` here), challenge2 the
        // responder's (`rep.challenge2`).
        let kx_shared_secret = sha256_32(&shared_secret);
        let keys = PeerKeys::new(&kx_shared_secret, &our_nonce, &rep.challenge2);
        let peer_cert_not_after = not_after_unix(&rep.responder_cert_der)?;

        // Record Complete state _before_ returning SendFinal so that
        // `is_authenticated` returns true immediately after this call.
        let installed = self.install_if_current(
            &remote_guid,
            slot,
            HandshakeState::Complete {
                shared_secret: SharedSecret::from(master_secret),
                keys,
                peer_cert: rep.responder_cert_der.clone(),
                peer_permissions,
                completed_at: Instant::now(),
                our_request,
                peer_challenge2: Some(rep.challenge2),
                peer_cert_not_after,
            },
        );
        let Some(replaced_complete) = installed else {
            return Err(SecurityError::AuthenticationFailed(
                "the session this AuthReply answers was dropped or replaced while it was \
                 verified: nothing installed, no AuthFinal sent"
                    .into(),
            ));
        };
        self.audit_authentication(&remote_guid, AuthenticationOutcome::Success);
        self.authenticated(remote_guid, replaced_complete);

        Ok(HandshakeAction::SendFinal(remote_guid, final_token))
    }

    /// Re-emit AuthFinal for a peer we have already completed with.
    ///
    /// AuthFinal is the one leg of the handshake that no retry ladder can
    /// repair on its own: once we are `Complete` our `ReqSent` entry is gone,
    /// so nothing on our side is left to retransmit and `start()` will never
    /// fire for this peer again. What we do get is the responder's own
    /// retransmitted AuthReply -- and that message carries every field
    /// AuthFinal needs (sec. 9.3.4.3: challenge1, dh1, dh2, challenge2), so the
    /// token is rebuilt and re-signed rather than stored. The signature
    /// differs byte-for-byte from the first one, because ECDSA signing is
    /// randomised, and verifies identically.
    ///
    /// This path signs data taken straight from the incoming message, so it
    /// is pinned to the request of the completed session (its challenge1 and
    /// dh1) and to the certificate of the peer we completed with, and the
    /// reply is fully re-validated before anything is signed.
    fn resend_final_for_completed(
        &self,
        remote_guid: GUID,
        rep: AuthReplyToken,
        completed_peer_cert: &[u8],
        completed_request: Option<&([u8; 32], Vec<u8>, [u8; 32])>,
        local_key_pem: &[u8],
        ca_cert_pem: &[u8],
    ) -> Result<HandshakeAction, SecurityError> {
        // A duplicate of the reply to OUR request of the completed session,
        // and nothing else: this path signs data taken from the message, and
        // a reply to another request - the late reply of an abandoned
        // parallel session, a forgery - would otherwise make the peer
        // complete alone, on a secret we do not hold.
        let (our_hash_c1, our_dh1) = match completed_request {
            Some((challenge1, dh1, hash_c1))
                if rep.challenge1 == *challenge1
                    && rep.dh1.as_ref().is_none_or(|echo| echo == dh1)
                    && rep.hash_c1.is_none_or(|echo| echo == *hash_c1) =>
            {
                (*hash_c1, dh1.clone())
            }
            _ => {
                return Err(SecurityError::AuthenticationFailed(
                    "AuthReply answers no request of the completed session: no AuthFinal \
                     re-signed"
                        .into(),
                ));
            }
        };
        if rep.responder_cert_der != completed_peer_cert {
            return Err(SecurityError::AuthenticationFailed(
                "duplicate AuthReply presents a different certificate than the \
                 completed session"
                    .into(),
            ));
        }

        validate_cert_chain(
            &rep.responder_cert_der,
            ca_cert_pem,
            self.revocation_list().as_deref(),
        )?;

        let dsign = Dsign::announced(&rep.dsign_algo, &rep.responder_cert_der)?;
        let hash_c2 = rep.hash_c2()?;
        let expected_input = reply_sign_input(
            &hash_c2,
            &rep.challenge2,
            &rep.dh2,
            &rep.challenge1,
            &our_dh1,
            &our_hash_c1,
        )?;
        match verify_sig(
            &expected_input,
            &rep.signature,
            &rep.responder_cert_der,
            dsign,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return Err(SecurityError::AuthenticationFailed(
                    "duplicate AuthReply signature verification failed".into(),
                ));
            }
            Err(e) => {
                return Err(SecurityError::CryptoError(format!(
                    "duplicate AuthReply signature error: {}",
                    e
                )));
            }
        }

        let final_input = final_sign_input(
            &our_hash_c1,
            &rep.challenge1,
            &our_dh1,
            &rep.challenge2,
            &rep.dh2,
            &hash_c2,
        )?;
        let signature = sign_bytes(&final_input, local_key_pem)?;

        log::debug!(
            "[security::handshake] re-sending AuthFinal to {} (the first one never arrived)",
            remote_guid
        );

        Ok(HandshakeAction::SendFinal(
            remote_guid,
            AuthFinalToken {
                hash_c1: Some(our_hash_c1),
                hash_c2: Some(hash_c2),
                challenge1: rep.challenge1,
                dh1: Some(our_dh1),
                dh2: Some(rep.dh2),
                challenge2: rep.challenge2,
                signature,
            },
        ))
    }

    fn handle_final(
        &self,
        remote_guid: GUID,
        fin: AuthFinalToken,
        ca_cert_pem: &[u8],
    ) -> Result<HandshakeAction, SecurityError> {
        // A duplicate AuthFinal is ordinary traffic now that the initiator
        // answers our retransmitted AuthReply with a fresh one. Report the
        // completion we already have instead of removing the entry that holds
        // the MasterSharedSecret. Nothing is signed and no state changes on
        // this path, so it re-announces a fact rather than deciding one.
        //
        // A parallel session (`Sessions::superseding`) is completed by the
        // AuthFinal whose echoes are its own; any other AuthFinal is for the
        // session of record, in progress or (a duplicate) complete.
        let superseding = {
            let sessions = self.handshakes.read();
            let for_parallel = matches!(
                sessions.superseding.get(&remote_guid),
                Some(HandshakeState::ReplySent {
                    our_nonce,
                    peer_nonce,
                    our_dh_pub,
                    ..
                }) if fin.challenge1 == *peer_nonce
                    && fin.challenge2 == *our_nonce
                    && fin.dh2.as_ref().is_none_or(|echo| echo == our_dh_pub)
            );
            if for_parallel {
                true
            } else {
                match sessions.states.get(&remote_guid) {
                    Some(HandshakeState::ReplySent { .. }) => false,
                    Some(HandshakeState::Complete { shared_secret, .. }) => {
                        log::debug!(
                            "[security::handshake] duplicate AuthFinal from {}; session \
                             already complete",
                            remote_guid
                        );
                        return Ok(HandshakeAction::Completed(
                            remote_guid,
                            shared_secret.clone(),
                        ));
                    }
                    _ => {
                        return Err(SecurityError::AuthenticationFailed(
                            "received AuthFinal without a matching ReplySent state".into(),
                        ));
                    }
                }
            }
        };

        // Take the ReplySent state out, whole, and the generation it belongs
        // to (see `handle_reply`).
        let (state, slot) = {
            let mut sessions = self.sessions_mut();
            let slot = if superseding {
                Slot::Superseding(sessions.superseding_generation(&remote_guid))
            } else {
                Slot::Record(sessions.generation(&remote_guid))
            };
            let table = if superseding {
                &mut sessions.superseding
            } else {
                &mut sessions.states
            };
            let taken = match table.remove(&remote_guid) {
                Some(state @ HandshakeState::ReplySent { .. }) => (state, slot),
                other => {
                    // The state changed between the two locks. Put back what
                    // we took rather than dropping a session on the floor.
                    if let Some(state) = other {
                        table.insert(remote_guid, state);
                    }
                    return Err(SecurityError::AuthenticationFailed(
                        "received AuthFinal without a matching ReplySent state".into(),
                    ));
                }
            };
            sessions.taken_for_verification(remote_guid, slot);
            taken
        };
        let _verifying = Verifying::new(&self.handshakes, remote_guid, slot);
        #[cfg(test)]
        self.parked();

        let HandshakeState::ReplySent {
            our_nonce,
            peer_nonce,
            our_dh_pub,
            peer_dh_pub,
            peer_cert,
            last_reply,
            ..
        } = &state
        else {
            return Err(SecurityError::AuthenticationFailed(
                "received AuthFinal without a matching ReplySent state".into(),
            ));
        };
        let hashes = last_reply
            .hash_c2()
            .map(|hash_c2| (last_reply.hash_c1, hash_c2));
        // An AuthFinal that does not validate is refused: the session of
        // record is put back, a parallel one forgotten (`put_back_refused`).
        // A refused re-authentication is no evidence against the completed
        // session it raced.
        let refuse = |state: HandshakeState, reason: String| {
            self.put_back_refused(remote_guid, slot, state, reason, "AuthFinal")
        };

        // Verify challenge echoes.
        if fin.challenge1 != *peer_nonce {
            return refuse(state, "AuthFinal challenge1 echo mismatch".to_string());
        }
        if fin.challenge2 != *our_nonce {
            return refuse(state, "AuthFinal challenge2 echo mismatch".to_string());
        }
        // The dh echoes, when the initiator sends them (optional, Table 51),
        // are those of this session.
        if fin.dh2.as_ref().is_some_and(|echo| echo != our_dh_pub) {
            return refuse(state, "AuthFinal dh2 echo mismatch".to_string());
        }
        if fin.dh1.as_ref().is_some_and(|echo| echo != peer_dh_pub) {
            return refuse(state, "AuthFinal dh1 echo mismatch".to_string());
        }
        // The hashes, when the initiator sends them (optional, Table 51),
        // are those of our reply.
        let (hash_c1, hash_c2) = match hashes {
            Ok((Some(hash_c1), hash_c2)) => (hash_c1, hash_c2),
            Ok((None, _)) => {
                return refuse(state, "our AuthReply carries no hash_c1".to_string());
            }
            Err(e) => return refuse(state, format!("hash_c2 of our AuthReply: {}", e)),
        };
        if fin.hash_c1.is_some_and(|echo| echo != hash_c1) {
            return refuse(state, "AuthFinal hash_c1 echo mismatch".to_string());
        }
        if fin.hash_c2.is_some_and(|echo| echo != hash_c2) {
            return refuse(state, "AuthFinal hash_c2 echo mismatch".to_string());
        }

        // The signature of Sec.9.3.2.5.3 (Table 51), over the values of
        // this session as we hold them: the request's challenge1, dh1 and
        // hash_c1 as we received them, our challenge2, dh2 and hash_c2. An
        // initiator that signed another request's c. properties (one changed
        // on the way to us) is refused.
        let sign_input = match final_sign_input(
            &hash_c1,
            peer_nonce,
            peer_dh_pub,
            our_nonce,
            our_dh_pub,
            &hash_c2,
        ) {
            Ok(input) => input,
            Err(e) => return refuse(state, format!("AuthFinal signature input: {}", e)),
        };
        // By the algorithm of the initiator's key, which is the one its
        // request announced (`handle_request` refused any other).
        let dsign = match Dsign::of_cert(peer_cert) {
            Ok(dsign) => dsign,
            Err(e) => return refuse(state, e.to_string()),
        };
        match verify_sig(&sign_input, &fin.signature, peer_cert, dsign) {
            Ok(true) => {}
            Ok(false) => {
                return refuse(state, "AuthFinal signature verification failed".to_string());
            }
            Err(e) => {
                return refuse(state, format!("AuthFinal signature error: {}", e));
            }
        }

        // Re-validate initiator cert (expiry check at completion time).
        if let Err(e) =
            validate_cert_chain(peer_cert, ca_cert_pem, self.revocation_list().as_deref())
        {
            return refuse(
                state,
                format!("initiator cert re-validation failed at Final: {}", e),
            );
        }

        // The AuthFinal validated: the session is consumed from here (its
        // EphemeralPrivateKey goes into the ECDH).
        let HandshakeState::ReplySent {
            our_nonce,
            peer_nonce,
            our_dh_priv,
            peer_dh_pub,
            suite,
            peer_cert,
            peer_permissions,
            ..
        } = state
        else {
            return Err(SecurityError::AuthenticationFailed(
                "received AuthFinal without a matching ReplySent state".into(),
            ));
        };
        // Past this point a failure is the validated peer's: the session of
        // record is recorded as failed, a parallel one only forgotten.
        let fail = |reason: String| -> Result<HandshakeAction, SecurityError> {
            match slot {
                Slot::Superseding(_) => {
                    log::warn!(
                        "[security::handshake] parallel session with {} refused at AuthFinal \
                         ({}); the session of record stays",
                        remote_guid,
                        reason
                    );
                    Err(SecurityError::AuthenticationFailed(reason))
                }
                Slot::Record(generation) => {
                    self.fail(&remote_guid, generation, reason.clone());
                    Ok(HandshakeAction::Failed(remote_guid, reason))
                }
            }
        };

        // Derive shared secret: our_priv (responder) + peer's dh1 (initiator pub)
        let shared_secret =
            match EcdhKeyExchange::derive_shared_secret(suite, our_dh_priv, &peer_dh_pub) {
                Ok(s) => s,
                Err(e) => {
                    return fail(format!("ECDH derivation failed: {}", e));
                }
            };
        // Salt order: peer_nonce (challenge1) || our_nonce (challenge2)
        let hkdf_salt: Vec<u8> = [peer_nonce.as_slice(), our_nonce.as_slice()].concat();
        let master_secret = SessionKeyManager::derive_session_key_with_suite(
            suite,
            &shared_secret,
            &hkdf_salt,
            b"DDS Security v1.1 MasterSharedSecret",
        )?;

        let secret_for_caller = master_secret.clone();

        // Same derivation as the initiator's branch, off-lock. Both roles or
        // neither -- see `handle_reply`. challenge1 = peer_nonce (the
        // initiator's), challenge2 = our_nonce (ours, the responder's) --
        // same assignment the initiator's branch uses, so both sides agree
        // on the volatile channel's KxKeys (Table 67).
        let kx_shared_secret = sha256_32(&shared_secret);
        let keys = PeerKeys::new(&kx_shared_secret, &peer_nonce, &our_nonce);
        let peer_cert_not_after = not_after_unix(&peer_cert)?;

        let installed = self.install_if_current(
            &remote_guid,
            slot,
            HandshakeState::Complete {
                shared_secret: SharedSecret::from(master_secret),
                keys,
                peer_cert,
                peer_permissions,
                completed_at: Instant::now(),
                our_request: None,
                peer_challenge2: None,
                peer_cert_not_after,
            },
        );
        let Some(replaced_complete) = installed else {
            return Err(SecurityError::AuthenticationFailed(
                "the session this AuthFinal completes was dropped or replaced while it was \
                 verified: nothing installed"
                    .into(),
            ));
        };
        self.audit_authentication(&remote_guid, AuthenticationOutcome::Success);
        self.authenticated(remote_guid, replaced_complete);

        Ok(HandshakeAction::Completed(
            remote_guid,
            SharedSecret::from(secret_for_caller),
        ))
    }

    // --------------------------------------------------------
    //  Replay protection
    // --------------------------------------------------------

    fn nonce_seen(&self, nonce: &[u8; 32]) -> bool {
        self.recent_nonces.lock().contains(nonce)
    }

    fn record_nonce(&self, nonce: [u8; 32]) {
        let mut ring = self.recent_nonces.lock();
        if ring.len() >= REPLAY_WINDOW {
            ring.pop_front();
        }
        ring.push_back(nonce);
    }

    // --------------------------------------------------------
    //  Error helper
    // --------------------------------------------------------

    /// A reply to a message of ours (an AuthReply to our AuthRequest, an
    /// AuthFinal to our AuthReply) that does not validate: DDS Security v1.1
    /// Sec.8.3.2.9.1 rule 3, "If the plugin operation returns
    /// VALIDATION_NOT_OK, the implementation transitions back to the previous
    /// state that caused the message to be sent and resends the same
    /// message". The session of record `state`, taken out at `slot`, goes
    /// back to the table, and its cached message is sent again.
    ///
    /// Before, the session of record was failed: one forged reply with
    /// mismatched echoes or a bad signature, from anyone knowing the peer's
    /// prefix, ended the handshake in progress. Now the genuine reply that
    /// follows still completes it.
    ///
    /// Bounded: a resend here is a transmission of the retry ladder and
    /// spends one of its `MAX_RETRIES` rungs, so a peer that keeps answering
    /// badly (or a sender of forgeries) gets at most `MAX_RETRIES` resends per
    /// session, after which a refusal sends nothing; the session then ends at
    /// its `SESSION_DEADLINE` (`tick`), `Failed` and audited, as a session
    /// that never got a valid answer.
    ///
    /// Not put back: a session dropped or begun anew while it was verified
    /// (its generation is not the peer's any more), and a parallel session
    /// (`Slot::Superseding`), which is forgotten as before: the completed
    /// session of record stays the peer's, and a parallel session is only
    /// reached by a reply carrying its own echoes.
    fn put_back_refused(
        &self,
        remote_guid: GUID,
        slot: Slot,
        mut state: HandshakeState,
        reason: String,
        message: &str,
    ) -> Result<HandshakeAction, SecurityError> {
        let generation = match slot {
            Slot::Superseding(_) => {
                log::warn!(
                    "[security::handshake] new session with {} refused at {} ({}); the \
                     completed session stays",
                    remote_guid,
                    message,
                    reason
                );
                return Err(SecurityError::AuthenticationFailed(reason));
            }
            Slot::Record(generation) => generation,
        };
        let resend = {
            let mut sessions = self.sessions_mut();
            if sessions.generation(&remote_guid) != generation
                || sessions.states.contains_key(&remote_guid)
            {
                log::debug!(
                    "[security::handshake] {} from {} refused ({}); its session was dropped or \
                     replaced meanwhile",
                    message,
                    remote_guid,
                    reason
                );
                return Err(SecurityError::AuthenticationFailed(reason));
            }
            let resend = match &mut state {
                HandshakeState::ReqSent {
                    last_request,
                    retries,
                    ..
                } if *retries < MAX_RETRIES => {
                    *retries += 1;
                    Some(HandshakeAction::SendRequest(
                        remote_guid,
                        last_request.clone(),
                    ))
                }
                HandshakeState::ReplySent {
                    last_reply,
                    retries,
                    ..
                } if *retries < MAX_RETRIES => {
                    *retries += 1;
                    Some(HandshakeAction::SendReply(remote_guid, last_reply.clone()))
                }
                _ => None,
            };
            sessions.states.insert(remote_guid, state);
            resend
        };
        match resend {
            Some(action) => {
                log::warn!(
                    "[security::handshake] {} from {} refused ({}): the session goes on, its \
                     last message sent again",
                    message,
                    remote_guid,
                    reason
                );
                Ok(action)
            }
            // Debug only: past the bound anyone can send these, and a warning
            // per datagram is a log flood (`HandshakeAction::Ignored`).
            None => Ok(HandshakeAction::Ignored(
                remote_guid,
                format!(
                    "{} refused ({}): the session goes on, its resends spent",
                    message, reason
                ),
            )),
        }
    }

    /// Record the failure of the session of record taken out at
    /// `generation`, unless that session was dropped or replaced meanwhile:
    /// a late verdict on an old session must not overwrite the one that
    /// replaced it.
    fn fail(&self, guid: &GUID, generation: Option<u64>, reason: String) {
        let installed = self.install_if_current(
            guid,
            Slot::Record(generation),
            HandshakeState::Failed {
                reason,
                failed_at: Instant::now(),
            },
        );
        if installed.is_some() {
            self.audit_authentication(guid, AuthenticationOutcome::Failed);
        } else {
            log::debug!(
                "[security::handshake] failure of a superseded session with {} not recorded",
                guid
            );
        }
    }

    /// File `state` as `guid`'s session of record if the session the caller
    /// took out of its table (`slot`) is still the latest of that table.
    /// Returns `None`, having filed nothing, when it was dropped or a newer
    /// session began there meanwhile; otherwise whether the state filed
    /// replaced a `Complete` session.
    ///
    /// A parallel session that completes replaces the session of record and
    /// invalidates the work in flight for it; a session of record that
    /// completes forgets the parallel one.
    fn install_if_current(&self, guid: &GUID, slot: Slot, state: HandshakeState) -> Option<bool> {
        let mut sessions = self.sessions_mut();
        match slot {
            Slot::Record(generation) => {
                if sessions.generation(guid) != generation {
                    return None;
                }
                sessions.superseding.remove(guid);
                sessions.superseding_generations.remove(guid);
            }
            Slot::Superseding(generation) => {
                if generation.is_none() || sessions.superseding_generation(guid) != generation {
                    return None;
                }
                sessions.superseding_generations.remove(guid);
                sessions.begin(*guid);
            }
        }
        let replaced_complete = matches!(
            sessions.states.get(guid),
            Some(HandshakeState::Complete { .. })
        );
        if replaced_complete && matches!(&state, HandshakeState::Complete { .. }) {
            if let Some(prepare) = self.before_reauthentication.get() {
                if let Err(error) = prepare(*guid) {
                    log::error!(
                        "[security::handshake] cannot prepare replacement keys: {}",
                        error
                    );
                    return None;
                }
            }
        }
        sessions.states.insert(*guid, state);
        Some(replaced_complete)
    }

    fn audit_authentication(&self, guid: &GUID, outcome: AuthenticationOutcome) {
        audit::record_committed(
            &self.audit,
            &SecurityEvent::Authentication {
                participant_guid: guid.as_bytes(),
                outcome,
                timestamp: audit::timestamp_ns(),
            },
        );
    }

    /// Fail closed once the audit chain has lost a record: no handshake is
    /// started or advanced until the participant is rebuilt with a working
    /// chain. One atomic load, no I/O, no lock.
    /// Refuse to begin or advance a handshake under an expired local identity.
    /// A clock that cannot be read counts as expired (`certificate_has_expired`).
    fn refuse_if_local_identity_expired(&self) -> Result<(), SecurityError> {
        if let Some((_, not_after)) = self.local_identity.get() {
            if certificate_has_expired(*not_after, wall_clock_unix()) {
                return Err(SecurityError::AuthenticationFailed(
                    "the local identity certificate has expired: no handshake is begun or \
                     advanced (DDS Security v1.1 Sec.9.3.3, validate_local_identity)"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    fn refuse_if_audit_degraded(&self) -> Result<(), SecurityError> {
        if audit::is_degraded(&self.audit) {
            return Err(SecurityError::AuthenticationFailed(
                "audit chain degraded (a record was lost): refusing to establish or advance \
                 any handshake until this participant is rebuilt"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl Default for HandshakeMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
//  Local crypto shims
//
//  These inline the same logic as `security::authentication::x509::crypto`
//  and `security::authentication::x509::cert` which are private to the x509
//  module and cannot be reached via the module path from a sibling subtree.
//  The `security` feature gates real crypto; without it the stubs provide
//  deterministic behaviour for unit tests.
// ============================================================

/// Generate a 32-byte CSPRNG challenge nonce.
fn generate_challenge_nonce() -> Result<Vec<u8>, SecurityError> {
    #[cfg(feature = "security")]
    {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut nonce = vec![0u8; 32];
        rng.fill(&mut nonce).map_err(|_| {
            SecurityError::CryptoError(
                "SystemRandom failed to generate challenge nonce".to_string(),
            )
        })?;
        Ok(nonce)
    }
    #[cfg(not(feature = "security"))]
    {
        // Was: 32 bytes of 0x5A. A constant is not a nonce; a handshake built
        // on it replays.
        Err(SecurityError::CryptoError(
            "nonce generation requires the `security` feature; this build has no CSPRNG, and \
             a constant is not a nonce"
                .to_string(),
        ))
    }
}

/// Sign `data` with the PEM-encoded EC or RSA private key.
///
/// An EC key signs ECDSA-SHA256 "as specified in ANSI X9.62-2005" (DDS
/// Security v1.1 Sec.9.3.2.5.2), whose signature is the DER-encoded
/// Ecdsa-Sig-Value: what OpenSSL's EVP_DigestSign gives Cyclone DDS and
/// Fast DDS, and what they verify. The fixed-width r || s form is not
/// read by either.
fn sign_bytes(data: &[u8], private_key_pem: &[u8]) -> Result<Vec<u8>, SecurityError> {
    #[cfg(feature = "security")]
    {
        use ring::rand::SystemRandom;
        use ring::signature;

        let pem = ::pem::parse(private_key_pem).map_err(|e| {
            SecurityError::AuthenticationFailed(format!("failed to parse private key PEM: {}", e))
        })?;
        // The DER private key is wiped when this scope ends; the parsed PEM
        // keeps no copy of it.
        let der = zeroize::Zeroizing::new(pem.into_contents());

        if let Ok(kp) = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            der.as_slice(),
            &SystemRandom::new(),
        ) {
            let sig = kp.sign(&SystemRandom::new(), data).map_err(|e| {
                SecurityError::AuthenticationFailed(format!("ECDSA sign failed: {:?}", e))
            })?;
            return Ok(sig.as_ref().to_vec());
        }

        // RSASSA-PSS with SHA-256 and MGF1-SHA-256 (Sec.9.3.2.5.2), salt
        // of the digest's length (32): the specification fixes none, and
        // OpenSSL's auto-detecting verifier (Cyclone DDS, Fast DDS) reads
        // any, as `verify_sig` does (`pss`).
        if let Ok(kp) = signature::RsaKeyPair::from_pkcs8(der.as_slice()) {
            let mut sig = vec![0u8; kp.public().modulus_len()];
            kp.sign(
                &signature::RSA_PSS_SHA256,
                &SystemRandom::new(),
                data,
                &mut sig,
            )
            .map_err(|e| {
                SecurityError::AuthenticationFailed(format!("RSA sign failed: {:?}", e))
            })?;
            return Ok(sig);
        }

        Err(SecurityError::AuthenticationFailed(
            "unsupported private key format (EC/RSA required)".to_string(),
        ))
    }
    #[cfg(not(feature = "security"))]
    {
        // Was: `data` followed by the first 8 bytes of the private key, as Ok.
        let _ = (data, private_key_pem);
        Err(SecurityError::CryptoError(
            "signing requires the `security` feature; this build has no signer, and \
             returning the input as a signature would be a security decision nobody made"
                .to_string(),
        ))
    }
}

/// Verify `signature` over `data` with the public key of `cert_pem`, by
/// the algorithm `dsign` (which the caller has checked is the one of that
/// key, `Dsign::announced`).
///
/// Returns `Ok(true)` on success, `Ok(false)` on verification mismatch.
fn verify_sig(
    data: &[u8],
    signature: &[u8],
    cert_pem: &[u8],
    dsign: Dsign,
) -> Result<bool, SecurityError> {
    #[cfg(feature = "security")]
    {
        use ring::signature::{self, UnparsedPublicKey};
        use x509_parser::pem::parse_x509_pem;

        let (_, pem) = parse_x509_pem(cert_pem).map_err(|e| {
            SecurityError::CertificateInvalid(format!("failed to parse cert PEM: {:?}", e))
        })?;
        let cert = pem.parse_x509().map_err(|e| {
            SecurityError::CertificateInvalid(format!("failed to parse X.509 cert: {:?}", e))
        })?;
        match dsign {
            // The subjectPublicKey, an EC point (not the whole
            // SubjectPublicKeyInfo). DER only (`sign_bytes`): the
            // fixed-width form is no ECDSA-SHA256 signature of X9.62, and
            // no peer of this release sends one.
            Dsign::EcdsaSha256 => {
                let key = cert.public_key().subject_public_key.data.as_ref();
                Ok(
                    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, key)
                        .verify(data, signature)
                        .is_ok(),
                )
            }
            // Any salt length (`pss`): ring's RSA_PSS_2048_8192_SHA256
            // accepts the digest length only, and OpenSSL 1.1.1 and 3.0
            // (Cyclone DDS, Fast DDS) sign with the maximum by default.
            Dsign::RsassaPssSha256 => match cert.public_key().parsed() {
                Ok(x509_parser::public_key::PublicKey::RSA(key)) => {
                    Ok(super::pss::verify_pss_sha256_any_salt(
                        key.modulus,
                        key.exponent,
                        data,
                        signature,
                    ))
                }
                _ => Ok(false),
            },
        }
    }
    #[cfg(not(feature = "security"))]
    {
        // Was: a non-empty test reported as a verification result.
        let _ = (data, signature, cert_pem, dsign);
        Err(SecurityError::CryptoError(
            "signature verification requires the `security` feature; this build cannot \
             verify, and reporting a non-empty buffer as a valid signature would be a \
             security decision nobody made"
                .to_string(),
        ))
    }
}

/// A handshake signature algorithm, `c.dsign_algo` (DDS Security v1.1
/// Sec.9.3.2.5.1, Table 49): "If the Participant Identity uses a RSA Public
/// Key, then the c.dsign_algo shall be RSASSA-PSS-SHA256. If the
/// Participant Identity uses a EC Public Key, then the c.dsign_algo shall be
/// ECDSA-SHA256."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dsign {
    /// ECDSA over P-256 with SHA-256, ANSI X9.62-2005 (DER signature).
    EcdsaSha256,
    /// RSASSA-PSS of PKCS #1 v2.1, SHA-256 and MGF1-SHA-256.
    RsassaPssSha256,
}

impl Dsign {
    /// Its name in `c.dsign_algo`.
    fn name(self) -> &'static str {
        match self {
            Dsign::EcdsaSha256 => "ECDSA-SHA256",
            Dsign::RsassaPssSha256 => "RSASSA-PSS-SHA256",
        }
    }

    /// The algorithm of the key of the identity certificate `cert_pem`.
    fn of_cert(cert_pem: &[u8]) -> Result<Self, SecurityError> {
        use x509_parser::oid_registry::{OID_KEY_TYPE_EC_PUBLIC_KEY, OID_PKCS1_RSAENCRYPTION};
        use x509_parser::pem::parse_x509_pem;
        let (_, pem) = parse_x509_pem(cert_pem).map_err(|e| {
            SecurityError::CertificateInvalid(format!("failed to parse cert PEM: {:?}", e))
        })?;
        let cert = pem.parse_x509().map_err(|e| {
            SecurityError::CertificateInvalid(format!("failed to parse X.509 cert: {:?}", e))
        })?;
        let algorithm = &cert.public_key().algorithm.algorithm;
        if *algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
            Ok(Dsign::EcdsaSha256)
        } else if *algorithm == OID_PKCS1_RSAENCRYPTION {
            Ok(Dsign::RsassaPssSha256)
        } else {
            Err(SecurityError::CertificateInvalid(format!(
                "identity key algorithm {} is neither RSA nor EC (DDS Security v1.1 \
                 Sec.9.3.2.5.1)",
                algorithm
            )))
        }
    }

    /// The algorithm a peer announced in `c.dsign_algo`, `announced` as on
    /// the wire, if it is the one of the key of its certificate `cert_pem`.
    fn announced(announced: &str, cert_pem: &[u8]) -> Result<Self, SecurityError> {
        let of_cert = Self::of_cert(cert_pem)?;
        if algo_name(announced) != of_cert.name() {
            return Err(SecurityError::AuthenticationFailed(format!(
                "c.dsign_algo {:?} is not {}, the algorithm of the peer's identity key \
                 (DDS Security v1.1 Sec.9.3.2.5.1)",
                algo_name(announced),
                of_cert.name()
            )));
        }
        Ok(of_cert)
    }
}

/// Validate `cert_pem` against the CA bundle `ca_pem`.
///
/// One rule, one reader: this is the validator of
/// `authentication::x509::cert`, the one the x509 plugin also calls. Under the
/// `security` feature it performs the X.509 checks (validity window, the
/// identity's KeyUsage, that the trust anchor is a CA, issuer match, signature
/// verification, revocation). Without the feature it refuses.
fn validate_cert_chain(
    cert_pem: &[u8],
    ca_pem: &[u8],
    crl_der: Option<&[u8]>,
) -> Result<(), SecurityError> {
    crate::security::authentication::x509::cert::validate_certificate_chain(
        cert_pem, ca_pem, crl_der,
    )
}

// ============================================================
//  Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    //  Revocation on the live trust path
    //
    //  `validate_cert_chain` is what the real handshake calls before trusting
    //  a REMOTE peer's certificate - four times, from both roles. These
    //  tests pin its revocation logic.
    // -------------------------------------------------------------------

    #[test]
    #[cfg(feature = "security")]
    fn a_revoked_peer_certificate_is_refused() {
        use crate::security::test_pki::{
            REVOCATION_CA_PEM, REVOCATION_CRL_PEM, REVOCATION_REVOKED_IDENTITY_PEM,
        };

        // Without a list, the certificate is perfectly good: this is the state
        // of a machine that has no revocation list configured.
        validate_cert_chain(REVOCATION_REVOKED_IDENTITY_PEM, REVOCATION_CA_PEM, None)
            .expect("the certificate itself is valid and correctly issued");

        let err = validate_cert_chain(
            REVOCATION_REVOKED_IDENTITY_PEM,
            REVOCATION_CA_PEM,
            Some(REVOCATION_CRL_PEM),
        )
        .expect_err("a revoked certificate must not be trusted");
        assert!(
            format!("{}", err).contains("REVOKED"),
            "the refusal must say why, got: {}",
            err
        );
    }

    /// The same CRL must ADMIT the certificate it does not list, or the test
    /// above proves only that the check refuses everything.
    #[test]
    #[cfg(feature = "security")]
    fn a_peer_absent_from_the_list_is_admitted() {
        use crate::security::test_pki::{
            REVOCATION_CA_PEM, REVOCATION_CRL_PEM, REVOCATION_GOOD_IDENTITY_PEM,
        };

        validate_cert_chain(
            REVOCATION_GOOD_IDENTITY_PEM,
            REVOCATION_CA_PEM,
            Some(REVOCATION_CRL_PEM),
        )
        .expect("serial 02 is in no CRL and must be trusted");
    }

    /// And an empty list from the same CA admits the revoked one, which pins
    /// the refusal to the SERIAL being listed rather than to a CRL being
    /// present at all.
    #[test]
    #[cfg(feature = "security")]
    fn an_empty_list_refuses_nobody() {
        use crate::security::test_pki::{
            REVOCATION_CA_PEM, REVOCATION_EMPTY_CRL_PEM, REVOCATION_REVOKED_IDENTITY_PEM,
        };

        validate_cert_chain(
            REVOCATION_REVOKED_IDENTITY_PEM,
            REVOCATION_CA_PEM,
            Some(REVOCATION_EMPTY_CRL_PEM),
        )
        .expect("an empty CRL lists nobody, so it revokes nobody");
    }

    /// A stale list cannot prove non-revocation, so it is refused rather than
    /// honoured. The fixture expired one second after it was issued, so this
    /// does not depend on when the test runs.
    #[test]
    #[cfg(feature = "security")]
    fn a_stale_list_is_refused_rather_than_honoured() {
        use crate::security::test_pki::{
            REVOCATION_CA_PEM, REVOCATION_EXPIRED_CRL_PEM, REVOCATION_GOOD_IDENTITY_PEM,
        };

        // The GOOD certificate: this must fail because the LIST is stale, not
        // because the certificate is listed.
        let err = validate_cert_chain(
            REVOCATION_GOOD_IDENTITY_PEM,
            REVOCATION_CA_PEM,
            Some(REVOCATION_EXPIRED_CRL_PEM),
        )
        .expect_err("a CRL past its nextUpdate proves nothing");
        let text = format!("{}", err);
        assert!(text.contains("expired"), "got: {}", text);
        assert!(
            !text.contains("REVOKED"),
            "the reason must be staleness, not revocation: {}",
            text
        );
    }

    // -------------------------------------------------------------------
    //  HandshakeMachine::new() must use the ECDH default algorithm.
    // -------------------------------------------------------------------

    /// A session of record that begins forgets any parallel session: what
    /// was begun next to the old one has nothing to replace any more.
    #[test]
    fn a_session_of_record_that_begins_forgets_the_parallel_one() {
        let guid = GUID::new([0x21; 12], RTPS_ENTITYID_PARTICIPANT);
        let mut sessions = Sessions::default();
        sessions.begin_superseding(guid);
        sessions.superseding.insert(
            guid,
            HandshakeState::Failed {
                reason: "a parallel session".into(),
                failed_at: Instant::now(),
            },
        );
        sessions.begin(guid);
        assert!(sessions.superseding.is_empty());
        assert_eq!(sessions.superseding_generation(&guid), None);
    }

    /// The reply vector of `tokens::tests::sign_vector` (hash_c2 = 0x22..,
    /// challenge2 = 0xBB.., dh2 = 64 x 0x05 then 0x42, challenge1 = 0xAA..,
    /// dh1 = 64 x 0x04 then 0x41, hash_c1 = 0x11..), as `reply_sign_input`
    /// serializes it.
    fn reply_vector() -> Vec<u8> {
        let mut dh1 = vec![0x04; 65];
        dh1[64] = 0x41;
        let mut dh2 = vec![0x05; 65];
        dh2[64] = 0x42;
        reply_sign_input(
            &[0x22; 32],
            &[0xBB; 32],
            &dh2,
            &[0xAA; 32],
            &dh1,
            &[0x11; 32],
        )
        .expect("serialize")
    }

    /// A signature Cyclone DDS 0.11.0 made: its
    /// `create_validate_asymmetrical_signature` (libdds_security_auth.so,
    /// what its `create_signature` calls) over its own serialization of the
    /// reply vector, with the key of `test_pki::TEST_IDENTITY_KEY_PEM`. We
    /// verify it as a reply from Cyclone would be verified.
    const CYCLONE_REPLY_VECTOR_SIGNATURE: &str = "3045022057bd27022d56bebd3529889cd05f8a584fead5\
         987a44a0271a738f3b21bb919e02210093b3729b92f61ffdf4c6f63d7b068b05c7a6b9a1187bb04f1db79\
         b28288719a9";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn a_signature_cyclone_dds_made_over_the_reply_vector_verifies() {
        let cert = crate::security::test_pki::TEST_IDENTITY_CERT_PEM;
        let signature = unhex(CYCLONE_REPLY_VECTOR_SIGNATURE);
        let ecdsa = Dsign::EcdsaSha256;
        assert!(verify_sig(&reply_vector(), &signature, cert, ecdsa).expect("verify"));
        let mut other = reply_vector();
        other[100] ^= 1;
        assert!(!verify_sig(&other, &signature, cert, ecdsa).expect("verify"));
    }

    /// What we sign is the DER Ecdsa-Sig-Value of X9.62, as OpenSSL makes
    /// and verifies it, never the fixed-width r || s: a DER SEQUENCE of two
    /// INTEGERs, and nothing else accepted on verification.
    #[test]
    fn a_handshake_signature_is_der_encoded() {
        let key = crate::security::test_pki::TEST_IDENTITY_KEY_PEM;
        let cert = crate::security::test_pki::TEST_IDENTITY_CERT_PEM;
        let signature = sign_bytes(&reply_vector(), key).expect("sign");
        assert_eq!(signature[0], 0x30, "a DER SEQUENCE");
        assert_eq!(usize::from(signature[1]) + 2, signature.len());
        assert_eq!(signature[2], 0x02, "an INTEGER r");
        let ecdsa = Dsign::EcdsaSha256;
        assert!(verify_sig(&reply_vector(), &signature, cert, ecdsa).expect("verify"));

        let pem = ::pem::parse(key).expect("PEM");
        let rng = ring::rand::SystemRandom::new();
        let fixed = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pem.contents(),
            &rng,
        )
        .expect("key")
        .sign(&rng, &reply_vector())
        .expect("sign");
        assert!(
            !verify_sig(&reply_vector(), fixed.as_ref(), cert, ecdsa).expect("verify"),
            "a fixed-width r || s is no X9.62 signature"
        );
    }

    /// An RSASSA-PSS-SHA256 signature Cyclone DDS 0.11.0 made (its
    /// `create_validate_asymmetrical_signature`, OpenSSL 3.5.7) over its own
    /// serialization of the reply vector, with the key of
    /// `test_pki::RSA_IDENTITY_KEY_PEM`.
    const CYCLONE_RSA_REPLY_VECTOR_SIGNATURE: &str =
        "265a97c7d1f92e2773e53182aaf33693c4cf51c7ec1554086cc707d64cee880773747bb71536\
         a3a5a2e708c35d659f8245cef043eb701f77824be4a8c45c7d7ad815fde5db31a936aa51b34d\
         c5711fb3545c3ec383e50bf48d05af3e270f7776d17d53c9f438fa93e27fd7d97a68e498a363\
         ac1ff37b0cc8fa8f2e997d930603639422187a508b24ff8540a6f4762fec1d9e613812c190cb\
         db02129a6d42a80d64981a74ca0a70eeded3a05d1969f59808643637d0c0308b20dc9c369b36\
         b23b2202e575653a1293f896fe71338fc5e12742b9ce506881efcbb97a4c80c603698bce682b\
         df9e74d8da2da5eb036f961abc5d4f3cdc82b648d4ef7a27eb7ef4ce";

    #[test]
    fn an_rsassa_pss_signature_cyclone_dds_made_over_the_reply_vector_verifies() {
        let cert = crate::security::test_pki::RSA_IDENTITY_CERT_PEM;
        let signature = unhex(CYCLONE_RSA_REPLY_VECTOR_SIGNATURE);
        let pss = Dsign::RsassaPssSha256;
        assert!(verify_sig(&reply_vector(), &signature, cert, pss).expect("verify"));
        let mut other = reply_vector();
        other[100] ^= 1;
        assert!(!verify_sig(&other, &signature, cert, pss).expect("verify"));
        assert_eq!(Dsign::of_cert(cert).expect("RSA"), pss);
        assert_eq!(
            Dsign::of_cert(crate::security::test_pki::TEST_IDENTITY_CERT_PEM).expect("EC"),
            Dsign::EcdsaSha256
        );
    }

    /// DDS Security v1.1 Sec.9.3.2.5.2: "If the Participant Private Key is a
    /// RSA key, then ... The digital signature shall be computed using the
    /// RSASSA-PSS algorithm specified in PKCS #1 ... using SHA256 as hash
    /// function, and MGF1 with SHA256 (mgf1sha256) as mask generation
    /// function." Not PKCS#1 v1.5, which this signer used.
    #[test]
    fn an_rsa_identity_signs_rsassa_pss() {
        use crate::security::test_pki::{RSA_IDENTITY_CERT_PEM, RSA_IDENTITY_KEY_PEM};
        use ring::signature::{
            UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
        };
        use x509_parser::pem::parse_x509_pem;
        let signature = sign_bytes(&reply_vector(), RSA_IDENTITY_KEY_PEM).expect("sign");
        let (_, pem) = parse_x509_pem(RSA_IDENTITY_CERT_PEM).expect("PEM");
        let cert = pem.parse_x509().expect("X.509");
        let key = cert.public_key().subject_public_key.data.to_vec();
        assert!(
            UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &key)
                .verify(&reply_vector(), &signature)
                .is_ok(),
            "an RSASSA-PSS-SHA256 signature"
        );
        assert!(UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &key)
            .verify(&reply_vector(), &signature)
            .is_err());
    }

    #[test]
    fn new_machine_has_ecdh_default() {
        let m = HandshakeMachine::new();
        assert_eq!(
            m.kagree_algo, "ECDH+prime256v1-CEUM",
            "HandshakeMachine::new() must default to ECDH+prime256v1-CEUM"
        );
    }

    // -------------------------------------------------------------------
    //  with_kagree_algo stores the algorithm string verbatim.
    // -------------------------------------------------------------------

    #[test]
    fn with_kagree_algo_stores_value() {
        let m = HandshakeMachine::with_kagree_algo("DH+MODP-2048-256");
        assert_eq!(m.kagree_algo, "DH+MODP-2048-256");
    }

    // -------------------------------------------------------------------
    //  is_authenticated returns false for an unknown GUID (empty state).
    // -------------------------------------------------------------------

    #[test]
    fn is_authenticated_false_for_unknown_guid() {
        let m = HandshakeMachine::new();
        let guid = GUID::new([0xAB; 12], [0x00, 0x00, 0x01, 0xC1]);
        assert!(!m.is_authenticated(&guid));
    }

    // -------------------------------------------------------------------
    //  start() on the Initiator role emits a SendRequest with the
    //  configured kagree_algo string.
    // -------------------------------------------------------------------

    #[test]
    fn start_initiator_encodes_configured_kagree_algo() {
        // Initiator = local GUID prefix < remote GUID prefix (per am_i_initiator in state.rs).
        let local_guid = GUID::new([0x00; 12], [0x00, 0x00, 0x01, 0xC1]);
        let remote_guid = GUID::new([0xFF; 12], [0x00, 0x00, 0x01, 0xC1]);

        // A SUPPORTED non-default suite rides the AuthRequest verbatim.
        let m = HandshakeMachine::with_kagree_algo("ECDH+secp384r1-CEUM");
        let result = m.start(
            local_guid,
            remote_guid,
            crate::security::test_pki::TEST_IDENTITY_CERT_PEM,
            b"fake-key-pem",
        );

        match result {
            Ok(Some(HandshakeAction::SendRequest(_, token))) => {
                assert_eq!(
                    token.kagree_algo, "ECDH+secp384r1-CEUM",
                    "AuthRequest.kagree_algo must reflect the configured algorithm"
                );
            }
            Ok(None) => panic!("expected SendRequest (local is initiator), got None"),
            Ok(Some(other)) => panic!("unexpected action: {:?}", other),
            Err(e) => panic!("start() returned error: {}", e),
        }

        // An UNSUPPORTED configured suite fails loudly BEFORE any packet
        // leaves. "DH+MODP-2048-256" (spec-defined, unimplemented) must not
        // be advertised verbatim, which would promise the peer a suite this
        // build cannot perform.
        let m = HandshakeMachine::with_kagree_algo("DH+MODP-2048-256");
        let err = m
            .start(
                GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
                remote_guid,
                crate::security::test_pki::TEST_IDENTITY_CERT_PEM,
                b"fake-key-pem",
            )
            .expect_err("an unimplemented configured suite must refuse to start");
        assert!(
            format!("{}", err).contains("key_establishment_algorithm"),
            "the refusal must name the config field, got: {}",
            err
        );
    }

    /// `state_epoch` moves with every session change - discovery keys its
    /// admission verdicts on it - and stays on a timer pass with nothing due,
    /// which the timer thread runs periodically.
    #[test]
    #[cfg(feature = "security")]
    fn the_state_epoch_moves_with_the_sessions_and_not_with_an_idle_tick() {
        use crate::security::test_pki::{TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM};
        let machine = HandshakeMachine::new();
        let local = GUID::new([0x01; 12], RTPS_ENTITYID_PARTICIPANT);
        let remote = GUID::new([0x02; 12], RTPS_ENTITYID_PARTICIPANT);
        let idle = machine.state_epoch();
        let _ = machine.tick(Instant::now());
        assert_eq!(machine.state_epoch(), idle, "an idle pass changes nothing");
        let _ = machine
            .start(local, remote, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM)
            .expect("start");
        assert!(machine.has_session(&remote), "fixture: begun");
        let begun = machine.state_epoch();
        assert!(begun > idle, "a session begun moves it");
        let _ = machine.tick(Instant::now());
        assert_eq!(machine.state_epoch(), begun, "nothing due yet");
        let _ = machine.drop_handshake(&remote);
        assert!(machine.state_epoch() > begun, "a session dropped moves it");
    }
}

/// RSASSA-PSS-SHA256 verification against signatures made by OpenSSL
/// (`fixtures/README.md`, `pss/`): any salt length is read, nothing else
/// than PSS with SHA-256 and MGF1-SHA-256 is.
#[cfg(all(test, feature = "security"))]
mod pss_vectors {
    use super::*;
    use crate::security::test_pki::{RSA_IDENTITY_CERT_PEM, TEST_IDENTITY_CERT_PEM};

    const MSG: &[u8] = include_bytes!("../fixtures/pss/msg");

    fn verifies(signature: &[u8]) -> bool {
        verify_sig(
            MSG,
            signature,
            RSA_IDENTITY_CERT_PEM,
            Dsign::RsassaPssSha256,
        )
        .expect("verify")
    }

    /// Spec Sec.9.3.2.5.2: RSASSA-PSS, SHA-256, MGF1-SHA-256. Not PKCS#1
    /// v1.5, not MGF1-SHA1.
    #[test]
    fn v2_pss_rejects_pkcs1_v15_and_mgf1_sha1() {
        assert!(
            verifies(include_bytes!("../fixtures/pss/digest.sig")),
            "salt 32 (HDDS, Fast DDS, OpenSSL >= 3.1 default)"
        );
        assert!(
            verifies(include_bytes!("../fixtures/pss/default.sig")),
            "OpenSSL 3.5 default"
        );
        assert!(
            !verifies(include_bytes!("../fixtures/pss/pkcs1.sig")),
            "PKCS#1 v1.5 must be refused"
        );
        assert!(
            !verifies(include_bytes!("../fixtures/pss/mgf1sha1.sig")),
            "MGF1-SHA1 must be refused"
        );
    }

    /// The specification fixes no salt length; OpenSSL 1.1.1 and 3.0 sign
    /// with the MAXIMUM salt by default (Cyclone DDS uses that default).
    #[test]
    fn v2_pss_accepts_a_salt_length_other_than_32() {
        assert!(
            verifies(include_bytes!("../fixtures/pss/max.sig")),
            "PSS with the maximum salt (222, OpenSSL < 3.1 default) refused"
        );
        assert!(
            verifies(include_bytes!("../fixtures/pss/s20.sig")),
            "PSS with salt 20 refused"
        );
        assert!(
            verifies(include_bytes!("../fixtures/pss/s0.sig")),
            "PSS with no salt refused"
        );
        assert!(
            verifies(include_bytes!("../fixtures/pss/raw_ok.sig")),
            "the hand-built encoding, no defect"
        );
    }

    /// Each hand-built encoding is well formed but for one defect, its hash
    /// covering the salt it carries: only the check named refuses it.
    #[test]
    fn a_pss_encoding_with_one_defect_is_refused() {
        assert!(
            !verifies(include_bytes!("../fixtures/pss/raw_bad_trailer.sig")),
            "trailer 0xbd, not 0xbc (RFC 8017 9.1.2 step 4)"
        );
        assert!(
            !verifies(include_bytes!("../fixtures/pss/raw_bad_separator.sig")),
            "0x02 where the 0x01 separator goes (step 10)"
        );
        assert!(
            !verifies(include_bytes!("../fixtures/pss/raw_top_bit.sig")),
            "the unused top bit of maskedDB set (step 6)"
        );
    }

    fn from_hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
            .collect()
    }

    /// RSA-1024 modulus of a throwaway key (openssl 3.5.7 `genpkey`, the key
    /// not kept), exponent 65537.
    const N1024: &str = "AF554DDB6F6020D09847ED7F484EF4833104A868FAEBA0A5DDF3B7C3183DA5B8\
        32F8C91CDCC61152B1B31E7E0E26AD4ECEC9880E1364CEA7882AFB0B6893E435\
        BF6FFBF3AC5F1A40E8C6B19E13CBBEE258E7B062A9C6B76746C6ACAF082901D4\
        AC772092E3F7431ED0CE906F61E8B9A79BF8796BDD1260154DF35AA8EC1C0953";
    /// Its RSASSA-PSS-SHA256 signature of `pss/msg`, salt 32, which
    /// `openssl pkeyutl -verify` accepts.
    const S1024: &str = "3309361df2250ba8c608dd211658f74e163d950538c2dd272b2d769baa4c9825\
        2e63c3d36af564696d446472e7ebea6077fc16114cfdd707d041ff3d195c846d\
        0d66d30286283e6037d913383e53f4927d3423fe1c44aba6bbb9062b027720e4\
        31592c317e8ed1ea8fa99883e6533fc55b824df242cc2cbad3368f111b065430";

    /// ring's bounds for RSA_PSS_2048_8192_SHA256 hold: a valid signature
    /// under a 1024-bit key verifies nothing, nor one under an exponent of 1
    /// (where a signature is its own encoded message, forgeable by anyone).
    #[test]
    fn a_key_outside_the_accepted_bounds_verifies_nothing() {
        use super::super::pss::verify_pss_sha256_any_salt;
        let compact = |text: &str| text.split_whitespace().collect::<String>();
        assert!(!verify_pss_sha256_any_salt(
            &from_hex(&compact(N1024)),
            &[1, 0, 1],
            MSG,
            &from_hex(&compact(S1024)),
        ));

        let (_, pem) = x509_parser::pem::parse_x509_pem(RSA_IDENTITY_CERT_PEM).expect("PEM");
        let cert = pem.parse_x509().expect("X.509");
        let Ok(x509_parser::public_key::PublicKey::RSA(key)) = cert.public_key().parsed() else {
            panic!("fixture: an RSA key");
        };
        let signature: &[u8] = include_bytes!("../fixtures/pss/raw_ok.sig");
        assert!(
            verify_pss_sha256_any_salt(key.modulus, key.exponent, MSG, signature),
            "fixture: the vector verifies under its own key"
        );
        let n = num_bigint::BigUint::from_bytes_be(key.modulus);
        let em = num_bigint::BigUint::from_bytes_be(signature)
            .modpow(&num_bigint::BigUint::from_bytes_be(key.exponent), &n)
            .to_bytes_be();
        let mut forged = vec![0u8; 256 - em.len()];
        forged.extend_from_slice(&em);
        assert!(
            !verify_pss_sha256_any_salt(key.modulus, &[1], MSG, &forged),
            "exponent 1: the encoded message passes as its own signature"
        );
    }

    /// The signature, the message and the key all bind.
    #[test]
    fn a_pss_signature_binds_its_message_its_length_and_its_key() {
        let max: &[u8] = include_bytes!("../fixtures/pss/max.sig");
        let mut other = MSG.to_vec();
        other[0] ^= 1;
        assert!(
            !verify_sig(&other, max, RSA_IDENTITY_CERT_PEM, Dsign::RsassaPssSha256)
                .expect("verify"),
            "another message"
        );
        let mut flipped = max.to_vec();
        flipped[200] ^= 1;
        assert!(!verifies(&flipped), "a flipped bit");
        assert!(!verifies(&max[1..]), "one octet short");
        let mut long = vec![0u8];
        long.extend_from_slice(max);
        assert!(!verifies(&long), "one leading zero octet more than k");
        assert!(!verifies(&[0xff; 256]), "a signature not below the modulus");
        // s + n is s modulo n and still k octets for this vector: RSAVP1
        // must refuse it (RFC 8017 5.2.2 step 1), not reduce it.
        let default: &[u8] = include_bytes!("../fixtures/pss/default.sig");
        assert!(verifies(default), "fixture: the vector verifies");
        let (_, pem) = x509_parser::pem::parse_x509_pem(RSA_IDENTITY_CERT_PEM).expect("PEM");
        let cert = pem.parse_x509().expect("X.509");
        let Ok(x509_parser::public_key::PublicKey::RSA(key)) = cert.public_key().parsed() else {
            panic!("fixture: an RSA key");
        };
        let lifted = num_bigint::BigUint::from_bytes_be(default)
            + num_bigint::BigUint::from_bytes_be(key.modulus);
        let lifted = lifted.to_bytes_be();
        assert_eq!(lifted.len(), 256, "fixture: s + n still fits k octets");
        assert!(!verifies(&lifted), "s + n, congruent to a valid signature");
        assert!(
            !verify_sig(MSG, max, TEST_IDENTITY_CERT_PEM, Dsign::RsassaPssSha256).expect("verify"),
            "an EC key verifies no RSASSA-PSS signature"
        );
    }
}

#[cfg(test)]
mod key_generation_tests {
    #[test]
    fn a_volatile_key_lease_fences_session_replacement() {
        use crate::security::test_pki::{
            local_machine_with_completed_peer, TEST_IDENTITY_PREFIX_HEAD,
        };
        let mut ours = [1; 12];
        let mut peer = [2; 12];
        ours[..6].copy_from_slice(&TEST_IDENTITY_PREFIX_HEAD);
        peer[..6].copy_from_slice(&TEST_IDENTITY_PREFIX_HEAD);
        let machine = local_machine_with_completed_peer(ours, peer, None);
        machine
            .with_volatile_key_material(&peer, |_| {
                assert!(
                    machine.handshakes.try_write().is_none(),
                    "token installation must exclude session replacement"
                );
            })
            .expect("authenticated");
        assert!(machine.handshakes.try_write().is_some(), "lease released");
    }
}

#[cfg(all(test, feature = "security"))]
mod certificate_expiry_tests {
    //! A completed session ends when the peer certificate's `notAfter` passes,
    //! and only then. The clock is passed to `tick_at`, so no test sleeps.

    use super::*;
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::security::test_pki::{
        local_machine_with_completed_peer, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    // The peer's prefix is bound to its certificate (Table 52): an arbitrary
    // prefix is refused before any expiry is reached.
    fn peer_prefix() -> [u8; 12] {
        crate::security::test_pki::bound_test_prefix([0xA1; 6])
    }

    fn local_prefix() -> [u8; 12] {
        crate::security::test_pki::bound_test_prefix([0xA2; 6])
    }

    fn peer() -> GUID {
        GUID::new(peer_prefix(), RTPS_ENTITYID_PARTICIPANT)
    }

    #[test]
    fn the_session_stands_through_the_last_instant_of_validity() {
        let machine = local_machine_with_completed_peer(local_prefix(), peer_prefix(), None);
        let not_after = not_after_unix(TEST_IDENTITY_CERT_PEM).expect("fixture notAfter");

        // RFC 5280 4.1.2.5: the validity period runs through notAfter, inclusive.
        machine.tick_at(Instant::now(), Some(not_after));
        assert!(
            machine.is_authenticated(&peer()),
            "a session whose certificate is valid through notAfter must stand"
        );
    }

    #[test]
    fn a_session_is_torn_down_once_the_peer_certificate_has_expired() {
        let machine = local_machine_with_completed_peer(local_prefix(), peer_prefix(), None);
        let not_after = not_after_unix(TEST_IDENTITY_CERT_PEM).expect("fixture notAfter");
        let torn = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&torn);
        machine.set_on_torn_down(Box::new(move |guid| {
            assert_eq!(*guid, peer(), "the hook names the peer whose session ended");
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        let actions = machine.tick_at(Instant::now(), Some(not_after + 1));

        assert!(
            !machine.is_authenticated(&peer()),
            "an expired peer certificate must end the authenticated session"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, HandshakeAction::Failed(g, _) if *g == peer())),
            "the teardown is reported as a failure of that peer, got {:?}",
            actions
        );
        assert_eq!(torn.load(Ordering::SeqCst), 1, "discovery is told once");
    }

    #[test]
    fn a_torn_down_session_is_not_torn_down_again_on_the_next_pass() {
        let machine = local_machine_with_completed_peer(local_prefix(), peer_prefix(), None);
        let not_after = not_after_unix(TEST_IDENTITY_CERT_PEM).expect("fixture notAfter");
        let torn = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&torn);
        machine.set_on_torn_down(Box::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        machine.tick_at(Instant::now(), Some(not_after + 1));
        machine.tick_at(Instant::now(), Some(not_after + 2));

        assert_eq!(
            torn.load(Ordering::SeqCst),
            1,
            "one teardown, not one per pass"
        );
    }

    /// A clock that cannot be read cannot show the certificate is current: the
    /// session does not stand on that pass.
    #[test]
    fn an_unreadable_clock_ends_the_session_rather_than_keeping_it() {
        let machine = local_machine_with_completed_peer(local_prefix(), peer_prefix(), None);
        machine.tick_at(Instant::now(), None);
        assert!(!machine.is_authenticated(&peer()));
    }

    #[test]
    fn the_expiry_rule_is_strictly_after_not_after() {
        assert!(!certificate_has_expired(100, Some(99)));
        assert!(!certificate_has_expired(100, Some(100)));
        assert!(certificate_has_expired(100, Some(101)));
        assert!(certificate_has_expired(100, None));
    }

    /// A self-signed certificate whose notAfter is 2020-01-01: an expired
    /// identity, for the local side of the tests below.
    fn expired_identity_pem() -> Vec<u8> {
        let mut params =
            rcgen::CertificateParams::new(vec!["expired.test".to_string()]).expect("params");
        params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        let key = rcgen::KeyPair::generate().expect("key");
        params
            .self_signed(&key)
            .expect("self-signed")
            .pem()
            .into_bytes()
    }

    fn local() -> GUID {
        GUID::new(local_prefix(), RTPS_ENTITYID_PARTICIPANT)
    }

    /// 2030-01-01T00:00:00Z: after the expired identity's notAfter, before the
    /// fixture peer's.
    const YEAR_2030_UNIX: i64 = 1_893_456_000;

    /// The local identity's expiry ends every authenticated session, and only
    /// because of the local identity: the peer's certificate is still valid here.
    #[test]
    fn an_expired_local_identity_ends_every_authenticated_session() {
        let machine = local_machine_with_completed_peer(local_prefix(), peer_prefix(), None);
        machine
            .set_local_identity(local(), &expired_identity_pem())
            .expect("the local certificate parses");
        let torn = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&torn);
        machine.set_on_torn_down(Box::new(move |guid| {
            assert_eq!(*guid, peer(), "the hook names the peer whose session ended");
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        let actions = machine.tick_at(Instant::now(), Some(YEAR_2030_UNIX));

        assert!(!machine.is_authenticated(&peer()));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, HandshakeAction::Failed(g, reason) if *g == peer() && reason.contains("local identity"))),
            "the teardown names the local identity as its reason, got {:?}",
            actions
        );
        assert_eq!(torn.load(Ordering::SeqCst), 1, "discovery is told once");
    }

    /// Once the local identity has expired, no handshake is begun.
    #[test]
    fn an_expired_local_identity_refuses_to_begin_a_handshake() {
        let machine = HandshakeMachine::new();
        machine
            .set_local_identity(local(), &expired_identity_pem())
            .expect("the local certificate parses");
        let refused = machine.start(
            local(),
            peer(),
            TEST_IDENTITY_CERT_PEM,
            TEST_IDENTITY_KEY_PEM,
        );
        assert!(
            refused.is_err(),
            "a handshake under an expired identity is refused"
        );
    }

    /// Positive control: a valid local identity begins the handshake.
    #[test]
    fn a_valid_local_identity_begins_a_handshake() {
        let machine = HandshakeMachine::new();
        machine
            .set_local_identity(local(), TEST_IDENTITY_CERT_PEM)
            .expect("the local certificate parses");
        let begun = machine
            .start(
                local(),
                peer(),
                TEST_IDENTITY_CERT_PEM,
                TEST_IDENTITY_KEY_PEM,
            )
            .expect("a valid identity may begin");
        // Either begin action: the higher prefix asks the lower one to begin.
        assert!(
            matches!(
                begun,
                Some(HandshakeAction::SendRequest(..) | HandshakeAction::SendAuthRequest(..))
            ),
            "got {:?}",
            begun
        );
    }

    /// The expiry is audited as a revocation of the local identity, once.
    #[test]
    fn the_local_identity_expiry_is_audited_once() {
        let file = tempfile::NamedTempFile::new().expect("audit file");
        let logger = crate::security::audit::LoggingPlugin::with_file(file.path()).expect("open");
        let audit = std::sync::Arc::new(crate::security::audit::AuditChain::new(logger));
        let machine = HandshakeMachine::new().with_audit_logger(Some(audit));
        machine
            .set_local_identity(local(), &expired_identity_pem())
            .expect("the local certificate parses");

        machine.tick_at(Instant::now(), Some(YEAR_2030_UNIX));
        machine.tick_at(Instant::now(), Some(YEAR_2030_UNIX + 1));

        let audited = std::fs::read_to_string(file.path()).expect("read audit");
        assert_eq!(
            audited.matches("outcome: Revoked").count(),
            1,
            "one revocation record for the local identity, got: {}",
            audited
        );
    }
}

/// Revocation lists re-read from a file: the list in force, its reloads, and the
/// refusals that leave the last good list standing. Every PKI here is generated,
/// because a list has to be signed by the CA whose identities it revokes.
#[cfg(all(test, feature = "security"))]
mod revocation_reload_tests {
    use super::*;
    use crate::security::handshake::tokens::{encode_final, encode_reply, encode_request};
    use crate::security::revocation::RevocationFile;
    use std::io;
    use std::time::SystemTime;

    /// What the fake file holds and how often the machine read it.
    #[derive(Default)]
    struct FileState {
        modified: Option<SystemTime>,
        content: Vec<u8>,
        stat_fails: bool,
        reads: usize,
    }

    /// The machine's view of the file, the test's handle on the same state.
    struct FakeFile(Arc<Mutex<FileState>>);

    impl RevocationFile for FakeFile {
        fn modified(&self) -> io::Result<SystemTime> {
            let state = self.0.lock();
            match (state.stat_fails, state.modified) {
                (true, _) => Err(io::Error::other("the list file is gone")),
                (false, Some(at)) => Ok(at),
                (false, None) => Err(io::Error::other("no modification time")),
            }
        }

        fn read(&self) -> io::Result<Vec<u8>> {
            let mut state = self.0.lock();
            state.reads += 1;
            Ok(state.content.clone())
        }
    }

    /// The first `(mod)` instant, and each later one a second after it.
    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + seconds)
    }

    fn named(common_name: &str) -> rcgen::DistinguishedName {
        let mut name = rcgen::DistinguishedName::new();
        name.push(rcgen::DnType::CommonName, common_name);
        name
    }

    /// A CA that signs identities and CRLs.
    struct Ca {
        cert: rcgen::Certificate,
        key: rcgen::KeyPair,
    }

    impl Ca {
        fn new() -> Self {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
            params.distinguished_name = named("Reload CA");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            let key = rcgen::KeyPair::generate().expect("key");
            let cert = params.self_signed(&key).expect("self-signed");
            Self { cert, key }
        }

        fn pem(&self) -> Vec<u8> {
            self.cert.pem().into_bytes()
        }

        /// An identity `(certificate PEM, key PEM)` under this CA.
        fn identity(&self, common_name: &str) -> (Vec<u8>, Vec<u8>, rcgen::Certificate) {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
            params.distinguished_name = named(common_name);
            params.is_ca = rcgen::IsCa::ExplicitNoCa;
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            let key = rcgen::KeyPair::generate().expect("key");
            let cert = params
                .signed_by(&key, &self.cert, &self.key)
                .expect("issued");
            (
                cert.pem().into_bytes(),
                key.serialize_pem().into_bytes(),
                cert,
            )
        }

        /// A CRL of this CA listing `revoked`, current between `this_update` and
        /// `next_update`.
        fn crl(
            &self,
            revoked: &[&rcgen::Certificate],
            this_update: (i32, u8, u8),
            next_update: (i32, u8, u8),
        ) -> Vec<u8> {
            let entries = revoked
                .iter()
                .map(|cert| {
                    let serial = x509_parser::parse_x509_certificate(cert.der())
                        .expect("parses")
                        .1
                        .tbs_certificate
                        .raw_serial()
                        .to_vec();
                    rcgen::RevokedCertParams {
                        serial_number: rcgen::SerialNumber::from_slice(&serial),
                        revocation_time: rcgen::date_time_ymd(2021, 1, 1),
                        reason_code: None,
                        invalidity_date: None,
                    }
                })
                .collect();
            rcgen::CertificateRevocationListParams {
                this_update: rcgen::date_time_ymd(this_update.0, this_update.1, this_update.2),
                next_update: rcgen::date_time_ymd(next_update.0, next_update.1, next_update.2),
                crl_number: rcgen::SerialNumber::from(1u64),
                issuing_distribution_point: None,
                revoked_certs: entries,
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            }
            .signed_by(&self.cert, &self.key)
            .expect("CRL signed by the CA")
            .pem()
            .expect("PEM")
            .into_bytes()
        }
    }

    /// One side of a handshake: its identity and its GUID.
    struct Side {
        guid: GUID,
        cert: Vec<u8>,
        key: Vec<u8>,
    }

    fn side(cert: Vec<u8>, key: Vec<u8>) -> Side {
        // The prefix is bound to the subject (Table 52): bit 0 set, bits 1 to 47
        // those of the subject name's hash, the rest the holder's.
        let (_, pem) = x509_parser::pem::parse_x509_pem(&cert).expect("PEM");
        let (_, parsed) = x509_parser::parse_x509_certificate(&pem.contents).expect("X.509");
        let prefix = crate::security::authentication::guid_binding::adjusted_participant_prefix(
            parsed.subject().as_raw(),
            &[0x5A; 16],
        );
        let guid = GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT);
        Side { guid, cert, key }
    }

    /// Run the three-message handshake between `local` and a fresh peer, both
    /// sides under `ca`. Returns the peer's GUID; `local` ends `Complete`.
    fn complete_handshake(local: &HandshakeMachine, mine: &Side, theirs: &Side, ca: &[u8]) -> GUID {
        let peer = HandshakeMachine::new();
        let (init, init_side, resp, resp_side) = if mine.guid.prefix < theirs.guid.prefix {
            (local, mine, &peer, theirs)
        } else {
            (&peer, theirs, local, mine)
        };
        let request = match init
            .start(
                init_side.guid,
                resp_side.guid,
                &init_side.cert,
                &init_side.key,
            )
            .expect("start")
            .expect("the lower prefix begins")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected SendRequest, got {:?}", other),
        };
        let reply = match resp
            .on_message(
                init_side.guid,
                &request,
                resp_side.guid,
                &resp_side.cert,
                &resp_side.key,
                ca,
            )
            .expect("the request is accepted")
        {
            HandshakeAction::SendReply(_, token) => encode_reply(&token).expect("encode"),
            other => panic!("expected SendReply, got {:?}", other),
        };
        let final_token = match init
            .on_message(
                resp_side.guid,
                &reply,
                init_side.guid,
                &init_side.cert,
                &init_side.key,
                ca,
            )
            .expect("the reply is accepted")
        {
            HandshakeAction::SendFinal(_, token) => encode_final(&token).expect("encode"),
            other => panic!("expected SendFinal, got {:?}", other),
        };
        resp.on_message(
            init_side.guid,
            &final_token,
            resp_side.guid,
            &resp_side.cert,
            &resp_side.key,
            ca,
        )
        .expect("the final token completes the handshake");
        assert!(
            local.is_authenticated(&theirs.guid),
            "the fixture handshake must complete"
        );
        theirs.guid
    }

    /// A machine holding a completed session with a peer, and its list file.
    struct Fixture {
        machine: HandshakeMachine,
        file: Arc<Mutex<FileState>>,
        peer: GUID,
        peer_cert: rcgen::Certificate,
        ca: Ca,
        audit_file: tempfile::NamedTempFile,
    }

    /// The machine begins with an empty list, current, from the CA: nothing is
    /// revoked yet, and the file holds that list at `at(0)`.
    fn fixture() -> Fixture {
        let ca = Ca::new();
        let (local_cert, local_key, _) = ca.identity("Reload local");
        let (peer_cert_pem, peer_key, peer_cert) = ca.identity("Reload peer");
        let ca_pem = ca.pem();
        let empty_crl = ca.crl(&[], (2021, 1, 1), (2099, 1, 1));
        let file = Arc::new(Mutex::new(FileState {
            modified: Some(at(0)),
            content: empty_crl.clone(),
            stat_fails: false,
            reads: 0,
        }));
        let audit_file = tempfile::NamedTempFile::new().expect("audit file");
        let logger =
            crate::security::audit::LoggingPlugin::with_file(audit_file.path()).expect("open");
        let audit = Arc::new(crate::security::audit::AuditChain::new(logger));
        let machine = HandshakeMachine::new()
            .with_audit_logger(Some(audit))
            .with_shared_revocation(Arc::new(Mutex::new(Some(empty_crl))))
            .with_revocation_file(Some((
                Box::new(FakeFile(Arc::clone(&file))),
                ca_pem.clone(),
            )));
        let mine = side(local_cert, local_key);
        let theirs = side(peer_cert_pem, peer_key);
        let peer = complete_handshake(&machine, &mine, &theirs, &ca_pem);
        Fixture {
            machine,
            file,
            peer,
            peer_cert,
            ca,
            audit_file,
        }
    }

    fn set_file(file: &Arc<Mutex<FileState>>, content: Vec<u8>, seconds: u64) {
        let mut state = file.lock();
        state.content = content;
        state.modified = Some(at(seconds));
    }

    /// The audit records of a refused list, by the stable token they carry.
    fn refusals_in(audit: &tempfile::NamedTempFile, token: &str) -> usize {
        std::fs::read_to_string(audit.path())
            .expect("read audit")
            .matches(&format!("revocation_list_refused:{}", token))
            .count()
    }

    /// A reloaded list that lists the peer's certificate ends the session it
    /// authenticated, with a revocation reason and a revocation record.
    #[test]
    fn a_reloaded_list_that_revokes_the_peer_ends_its_session() {
        let f = fixture();
        f.machine.tick_at(Instant::now(), wall_clock_unix());
        assert!(
            f.machine.is_authenticated(&f.peer),
            "fixture: the peer is authenticated"
        );

        set_file(
            &f.file,
            f.ca.crl(&[&f.peer_cert], (2021, 1, 1), (2099, 1, 1)),
            1,
        );
        let actions = f.machine.tick_at(Instant::now(), wall_clock_unix());

        assert!(
            !f.machine.is_authenticated(&f.peer),
            "a listed peer is not authenticated"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                HandshakeAction::Failed(g, reason) if *g == f.peer && reason.contains("revoked")
            )),
            "the teardown names the revocation, got {:?}",
            actions
        );
        let audited = std::fs::read_to_string(f.audit_file.path()).expect("read audit");
        assert!(
            audited.contains("outcome: Revoked"),
            "the revocation is audited: {}",
            audited
        );
    }

    /// A stale list replaces the one in force, and ends no session: a list past
    /// its nextUpdate revokes nobody. It refuses new handshakes, which this does
    /// not test.
    #[test]
    fn a_stale_reloaded_list_is_kept_and_ends_no_session() {
        let f = fixture();
        let stale = f.ca.crl(&[], (2020, 1, 1), (2021, 1, 1));
        set_file(&f.file, stale.clone(), 1);

        f.machine.tick_at(Instant::now(), wall_clock_unix());

        assert!(
            f.machine.is_authenticated(&f.peer),
            "a stale list ends no session"
        );
        assert_eq!(
            f.machine.revocation_list(),
            Some(stale),
            "the reloaded list is in force"
        );
    }

    /// A file that fails to parse or verify leaves the last good list in force,
    /// and is refused, logged and audited once: not again on the same content.
    #[test]
    fn a_refused_reload_keeps_the_last_good_list_and_is_audited_once() {
        let f = fixture();
        let good = f.machine.revocation_list();
        set_file(&f.file, b"this is not a revocation list".to_vec(), 1);

        f.machine.tick_at(Instant::now(), wall_clock_unix());
        f.machine.tick_at(Instant::now(), wall_clock_unix());

        assert_eq!(
            f.machine.revocation_list(),
            good,
            "the last good list stays in force"
        );
        assert!(
            f.machine.is_authenticated(&f.peer),
            "a refused file ends no session"
        );
        assert_eq!(
            refusals_in(&f.audit_file, "verify_failed"),
            1,
            "one refusal record, not one per pass"
        );
    }

    /// The file is read when its modification time changes, not on every pass.
    #[test]
    fn an_unchanged_list_file_is_not_read_again() {
        let f = fixture();
        let reads_before = f.file.lock().reads;
        for _ in 0..3 {
            f.machine.tick_at(Instant::now(), wall_clock_unix());
        }
        assert_eq!(
            f.file.lock().reads,
            reads_before + 1,
            "read once, when first judged"
        );
    }

    /// A file that cannot be stat'ed is refused the same way, and reported once.
    #[test]
    fn a_missing_list_file_is_reported_once() {
        let f = fixture();
        let good = f.machine.revocation_list();
        f.file.lock().stat_fails = true;

        f.machine.tick_at(Instant::now(), wall_clock_unix());
        f.machine.tick_at(Instant::now(), wall_clock_unix());

        assert_eq!(f.machine.revocation_list(), good, "the list in force stays");
        assert!(f.machine.is_authenticated(&f.peer));
        assert_eq!(
            refusals_in(&f.audit_file, "stat_failed"),
            1,
            "one record for one continuing failure"
        );
    }

    /// The authentication plugin judges the local identity against the list the
    /// handshake machine reloads: one list in force, two readers. Built the way the
    /// participant builds them, from a configuration and its files.
    #[test]
    fn the_plugin_judges_the_local_identity_with_the_reloaded_list() {
        let ca = Ca::new();
        let (cert_pem, key_pem, cert) = ca.identity("Reload local, one list");
        let dir = tempfile::tempdir().expect("a directory for the fixture files");
        let write = |name: &str, bytes: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).expect("write a fixture file");
            path
        };
        let cert_path = write("identity.pem", &cert_pem);
        let key_path = write("identity_key.pem", &key_pem);
        let ca_path = write("ca.pem", &ca.pem());
        let crl_path = write("crl.pem", &ca.crl(&[], (2021, 1, 1), (2099, 1, 1)));
        let config = crate::security::config::SecurityConfig::builder()
            .identity_certificate(&cert_path)
            .private_key(&key_path)
            .ca_certificates(&ca_path)
            .check_certificate_revocation(true)
            .certificate_revocation_list(&crl_path)
            .build()
            .expect("the configuration is complete");
        let suite = crate::security::SecurityPluginSuite::new(config, 0).expect("the suite builds");
        suite
            .authentication()
            .validate_identity()
            .expect("unlisted: the local identity authenticates");

        // The file gains a CRL that lists the local identity, with a later
        // modification time; the handshake machine's next pass re-reads it.
        std::fs::write(&crl_path, ca.crl(&[&cert], (2021, 1, 1), (2099, 1, 1)))
            .expect("write the revoking list");
        std::fs::File::options()
            .write(true)
            .open(&crl_path)
            .expect("open the list file")
            .set_modified(at(1))
            .expect("set the modification time");
        suite.handshakes.tick_at(Instant::now(), wall_clock_unix());

        assert!(
            suite.authentication().validate_identity().is_err(),
            "the plugin must judge with the list the reload put in force"
        );
    }
}
