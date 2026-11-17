// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Handshake FSM states and role assignment.
//!
//! Per DDS Security v1.1 Sec.9.3.4 the participant with the lower GUID
//! (lexicographic order) initiates the handshake. This deterministic
//! convention avoids a collision where both sides simultaneously send
//! AuthRequest and neither responds.

use crate::core::discovery::GUID;
use crate::security::crypto::key_exchange::KeyAgreementSuite;
use crate::security::handshake::tokens::{AuthReplyToken, AuthReqToken, AuthRequestToken};
use ring::agreement::EphemeralPrivateKey;
use std::time::Instant;

/// The MasterSharedSecret of a completed handshake (DDS-Security v1.1 Sec.9.3.2,
/// after HDDS's HKDF step). Key material: the bytes are wiped when the last
/// copy drops, and `Debug` prints the length only, so a `{:?}` on a
/// `HandshakeAction` or on anything holding one never shows the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret(zeroize::Zeroizing<Vec<u8>>);

impl SharedSecret {
    /// The secret bytes, for a key schedule. Borrowed, never copied out.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<zeroize::Zeroizing<Vec<u8>>> for SharedSecret {
    fn from(bytes: zeroize::Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret(<redacted {} bytes>)", self.0.len())
    }
}

/// Role of the local participant in a handshake session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Sends AuthRequest first. Assigned when local GUID prefix < remote.
    Initiator,
    /// Waits for AuthRequest, sends AuthReply. Assigned when local > remote.
    Responder,
}

/// Per-peer handshake state machine.
///
/// Variants are ordered to match the 3-message protocol:
///
/// Initiator path:  None -> ReqSent -> Complete | Failed
/// Responder path:  None -> AwaitingRequest -> ReplySent -> Complete | Failed
///
/// `EphemeralPrivateKey` is not `Clone` (intentional from `ring`; ephemeral
/// keys must not be duplicated), so this enum is not `Clone`.
pub enum HandshakeState {
    /// We sent AuthRequest; waiting for AuthReply. (Initiator role)
    ReqSent {
        /// 32-byte challenge nonce we generated for this session.
        our_nonce: [u8; 32],
        /// Ephemeral ECDH private key (consumed on AuthFinal derivation).
        our_dh_priv: EphemeralPrivateKey,
        /// Uncompressed DH public key we published in the request.
        /// 65 bytes for P-256, 97 bytes for P-384.
        our_dh_pub: Vec<u8>,
        /// Key-agreement suite negotiated for this session.
        suite: KeyAgreementSuite,
        /// The AuthRequest exactly as first transmitted.
        ///
        /// Retained so the retry timer can retransmit it verbatim. Rebuilding
        /// the token instead would require the local certificate and pdata,
        /// which the machine does not own; retaining it keeps `tick()` free of
        /// any caller-supplied material. Retransmitting the *same* nonce is
        /// deliberate: a peer that already saw this request answers from its
        /// own `ReplySent` retry ladder, and a peer that never saw it has an
        /// empty replay window for this nonce.
        last_request: AuthRequestToken,
        /// Monotonic instant at which the request was first sent.
        started_at: Instant,
        /// Number of transmissions beyond the first (expires at `MAX_RETRIES`).
        retries: u8,
        /// The `future_challenge`s of the peer's authentication requests
        /// when this session was begun on them: the peer's challenge2 must
        /// be one of them (DDS Security v1.1 Sec.9.3.2.5.2). Empty when it
        /// was begun on none.
        expected_challenge2: Vec<[u8; 32]>,
    },

    /// We are the responder and wait for the peer's HandshakeRequest
    /// (DDS Security v1.1 Sec.7.4.3.6.2, 9.3.2.4). A peer in this state
    /// is not authenticated: its endpoints are held back. If its remote
    /// token arrived first, our local token is NIL (Table 52).
    AwaitingRequest {
        /// The local token's announced nonce; None when the local token is NIL.
        future_challenge: Option<[u8; 32]>,
        /// The local token exactly as first sent, if any, for the retry ladder.
        last_auth_request: Option<AuthReqToken>,
        /// Monotonic instant at which it was first sent.
        started_at: Instant,
        /// Number of transmissions beyond the first.
        retries: u8,
    },

    /// We received AuthRequest and sent AuthReply; waiting for AuthFinal.
    /// (Responder role)
    ReplySent {
        /// Our own generated challenge nonce (challenge2).
        our_nonce: [u8; 32],
        /// Initiator's challenge nonce (challenge1, echoed in our reply).
        peer_nonce: [u8; 32],
        /// Ephemeral ECDH private key (consumed on secret derivation at Final).
        our_dh_priv: EphemeralPrivateKey,
        /// Our uncompressed DH public key (65 bytes for P-256, 97 for P-384).
        our_dh_pub: Vec<u8>,
        /// Initiator's uncompressed DH public key (received in request).
        peer_dh_pub: Vec<u8>,
        /// Key-agreement suite negotiated for this session.
        suite: KeyAgreementSuite,
        /// Initiator's DER-encoded X.509 certificate (validated before reply).
        peer_cert: Vec<u8>,
        /// Initiator's signed permissions document (`c.perm`), if it sent one.
        /// Held here only to reach `Complete`, next to `peer_cert`.
        peer_permissions: Option<Vec<u8>>,
        /// The AuthReply exactly as first transmitted.
        ///
        /// Retained for the same reason as `ReqSent::last_request`, and with
        /// one more: rebuilding an AuthReply would mean re-signing it, so the
        /// machine would need the local private key on the timer path.
        last_reply: AuthReplyToken,
        /// Monotonic instant at which the reply was first sent.
        started_at: Instant,
        /// Number of transmissions beyond the first (expires at `MAX_RETRIES`).
        retries: u8,
    },

    /// Handshake completed successfully. Both sides have the same shared secret.
    Complete {
        /// ECDH-derived MasterSharedSecret, retained for inspection through
        /// `shared_secret_for`. Secure builtin writers use exchanged tokens.
        shared_secret: SharedSecret,
        /// Volatile-channel inputs (DDS-Security v1.1 Tables 67/68).
        /// Created alongside `shared_secret` in both handshake roles.
        keys: crate::security::crypto::peer_keys::PeerKeys,
        /// Remote participant's DER-encoded X.509 certificate (retained for
        /// access-control decisions after authentication completes).
        peer_cert: Vec<u8>,
        /// Remote participant's SIGNED permissions document (`c.perm`), as
        /// received, or `None` if it sent none.
        ///
        /// Retained for the same reason as `peer_cert` and used with it: the
        /// certificate says WHO the peer is, this says what it is allowed to
        /// do, and evaluating a grant needs both. `None` is load-bearing - a
        /// peer that sent no document is not a peer that sent an empty one,
        /// and only the access-control layer may decide what to do about it.
        peer_permissions: Option<Vec<u8>>,
        /// Monotonic instant of completion (for session-expiry tracking).
        completed_at: Instant,
        /// `notAfter` of the peer's certificate, Unix seconds, read at
        /// completion. `HandshakeMachine::tick` tears the session down once the
        /// wall clock is past it (DDS-Security v1.1 8.3.2.12; RFC 5280 4.1.2.5).
        peer_cert_not_after: i64,
        /// When we initiated this session: the challenge1, dh1 and hash_c1
        /// of our AuthRequest. A duplicate AuthReply is answered with a
        /// re-signed AuthFinal only when it echoes these - a reply to any
        /// other request (an abandoned parallel session, a forgery) completes
        /// nothing. `None` when we were the responder.
        our_request: Option<([u8; 32], Vec<u8>, [u8; 32])>,
        /// When we initiated this session: the challenge2 the peer's AuthReply
        /// carried. A peer that asked us to begin (an authentication request,
        /// DDS Security v1.1 Sec.7.4.3.6.2) answers with the future_challenge
        /// it announced there (Sec.9.3.2.5.2), so an authentication request
        /// carrying this value is the one this session already answered,
        /// arriving late or retransmitted - not a peer that came back.
        /// `None` when we were the responder.
        peer_challenge2: Option<[u8; 32]>,
    },

    /// Handshake failed; peer must not be granted access.
    Failed {
        /// Human-readable failure reason (for audit log / diagnostics).
        reason: String,
        /// Monotonic instant of failure (for rate-limiting re-handshake).
        failed_at: Instant,
    },
}

impl std::fmt::Debug for HandshakeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReqSent {
                retries,
                started_at,
                ..
            } => {
                write!(
                    f,
                    "ReqSent {{ retries: {}, age_ms: {} }}",
                    retries,
                    started_at.elapsed().as_millis()
                )
            }
            Self::AwaitingRequest {
                retries,
                started_at,
                ..
            } => {
                write!(
                    f,
                    "AwaitingRequest {{ retries: {}, age_ms: {} }}",
                    retries,
                    started_at.elapsed().as_millis()
                )
            }
            Self::ReplySent {
                retries,
                started_at,
                ..
            } => {
                write!(
                    f,
                    "ReplySent {{ retries: {}, age_ms: {} }}",
                    retries,
                    started_at.elapsed().as_millis()
                )
            }
            Self::Complete { completed_at, .. } => {
                write!(
                    f,
                    "Complete {{ age_ms: {} }}",
                    completed_at.elapsed().as_millis()
                )
            }
            Self::Failed { reason, .. } => {
                write!(f, "Failed {{ reason: {:?} }}", reason)
            }
        }
    }
}

/// Determine local role based on GUID comparison.
///
/// DDS Security v1.1 Sec.9.3.4: "The DomainParticipant with the lower GUID
/// (using lexicographical order) initiates the protocol", and Sec.9.3.3
/// Table 52 (validate_remote_identity): "If the remote_participant_guid >
/// local_participant_guid, the operation shall return
/// VALIDATION_PENDING_HANDSHAKE_REQUEST" - the local participant begins the
/// handshake request.
///
/// The specification contains no "higher GUID.prefix initiates" rule; electing
/// the opposite initiator would disagree with every conforming implementation.
///
/// Returns `true` when `local.prefix < remote.prefix` (lexicographic,
/// octet by octet). The two GUIDs compared are participant GUIDs, whose
/// entity ids are equal, so the prefix decides.
pub fn am_i_initiator(local: &GUID, remote: &GUID) -> bool {
    local.prefix < remote.prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shared_secret_prints_its_length_and_never_its_bytes() {
        let secret = SharedSecret::from(zeroize::Zeroizing::new(vec![0xA5; 32]));
        let shown = format!("{:?}", secret);
        assert!(shown.contains("32"), "the length is shown: {}", shown);
        assert!(
            !shown.contains("165"),
            "the bytes (0xA5 = 165) must not print: {}",
            shown
        );
    }

    #[test]
    fn initiator_is_the_lower_guid() {
        let high = GUID::new([0xFF; 12], [0, 0, 1, 0xC1]);
        let low = GUID::new([0x00; 12], [0, 0, 1, 0xC1]);
        assert!(am_i_initiator(&low, &high));
        assert!(!am_i_initiator(&high, &low));
        // Lexicographic: the first differing octet decides.
        let mut first = [0x00; 12];
        first[0] = 0x01;
        let mut last = [0xFF; 12];
        last[0] = 0x00;
        assert!(am_i_initiator(
            &GUID::new(last, [0, 0, 1, 0xC1]),
            &GUID::new(first, [0, 0, 1, 0xC1])
        ));
    }

    #[test]
    fn equal_guid_not_initiator() {
        let g = GUID::new([0x42; 12], [0, 0, 1, 0xC1]);
        // Tie: neither is initiator (both return false means responder; in
        // practice this cannot happen on the wire since two distinct
        // participants generate distinct GUID prefixes).
        assert!(!am_i_initiator(&g, &g));
    }
}
