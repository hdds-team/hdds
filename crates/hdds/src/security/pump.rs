// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Stateless-channel <-> HandshakeMachine bridge (DDS Security v1.1 gap C3).
//!
//! Provides two pumps:
//!
//! - `drain_incoming`: pops every pending `StatelessToken` from
//!   `StatelessChannel::rx_tokens`, dispatches each to
//!   `HandshakeMachine::on_message`, and converts the returned
//!   `HandshakeAction` back into an outgoing `StatelessToken` placed on
//!   `StatelessChannel::tx_tokens`.
//!
//! - `drain_outgoing`: pops every pending `StatelessToken` from
//!   `StatelessChannel::tx_tokens` and returns the raw bytes to the caller
//!   (the RTPS writer thread) for emission on the wire via the
//!   `BuiltinParticipantStatelessMessageWriter` (entity ID 0x000201C3).
//!
//! # Threading model
//!
//! Both functions are designed to be called from a single-threaded discovery
//! loop (the same thread that calls `StatelessChannel::push_incoming` on
//! every DATA submessage delivered to entity ID 0x000201C4). They hold no
//! locks across call sites; all internal synchronisation is inside the
//! `StatelessChannel` and `HandshakeMachine` impls.
//!
//! # Encoding
//!
//! Outgoing tokens are serialised via the `encode_request` / `encode_reply` /
//! `encode_final` helpers in `security::handshake::tokens`. The participant
//! GUID prefix is stored in `StatelessToken::remote_guid_prefix` so the RTPS
//! writer can stamp the INFO_DST submessage.
//!
//! # DDS Security spec references
//!
//! - sec. 7.4.5: ParticipantStatelessMessage channel properties (BEST_EFFORT,
//!   VOLATILE, NO_KEY, plaintext).
//! - sec. 9.3.4: 3-message PKI-DH handshake (AuthRequest / AuthReply / AuthFinal).
//! - sec. 9.3.4.2-4.6: Per-message requirements for challenge echoes and
//!   ECDH-derived MasterSharedSecret derivation.

#[cfg(feature = "security")]
pub use inner::*;

#[cfg(feature = "security")]
mod inner {
    use crate::core::discovery::GUID;
    use crate::security::handshake::{
        tokens::{encode_auth_req, encode_final, encode_reply, encode_request},
        HandshakeAction, HandshakeMachine,
    };
    use crate::security::stateless::{StatelessChannel, StatelessToken};
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    //  Inbound pump
    // -----------------------------------------------------------------------

    /// Local identity material needed for `HandshakeMachine::on_message`.
    ///
    /// These values come from `SecurityConfig` at participant startup and
    /// must be loaded into this struct by the caller (`secure_builtins` setup
    /// function) before registering the data callback.
    #[derive(Clone)]
    pub struct LocalIdentity {
        /// Our participant GUID (prefix + entity ID).
        pub guid: GUID,
        /// DER-encoded local identity certificate.
        pub cert_der: Vec<u8>,
        /// PEM-encoded local EC/RSA private key. Wiped on drop with every copy.
        pub key_pem: zeroize::Zeroizing<Vec<u8>>,
        /// PEM-encoded CA certificate bundle used to validate remote certs.
        pub ca_cert_pem: Vec<u8>,
    }

    /// Drain all pending tokens from the incoming queue and advance the
    /// `HandshakeMachine` state machine for each one.
    ///
    /// Any outgoing tokens produced by the machine (SendRequest / SendReply /
    /// SendFinal) are encoded and pushed onto `channel.tx_tokens` for
    /// subsequent emission by the RTPS writer thread.
    ///
    /// Authentication-completion events (Completed / Failed / Drop) are
    /// logged but not surfaced to the caller here; the caller may poll
    /// `machine.is_authenticated(remote_guid)` at any time.
    ///
    /// # Arguments
    ///
    /// - `channel`: the stateless tunnel shared between the RTPS layer and
    ///   the handshake driver.
    /// - `machine`: the PKI-DH state machine.
    /// - `identity`: local cert material forwarded to `on_message`.
    ///
    /// # Returns
    ///
    /// The number of tokens consumed from `rx_tokens`.
    pub fn drain_incoming(
        channel: &StatelessChannel,
        machine: &Arc<HandshakeMachine>,
        identity: &LocalIdentity,
    ) -> usize {
        let mut count = 0usize;

        while let Some(token) = channel.pop_incoming() {
            count += 1;
            let remote_guid = guid_from_prefix(token.remote_guid_prefix);

            match machine.on_message(
                remote_guid,
                &token.payload,
                identity.guid,
                &identity.cert_der,
                &identity.key_pem,
                &identity.ca_cert_pem,
            ) {
                Ok(action) => handle_action(action, channel),
                Err(e) => {
                    log::warn!(
                        "[security::pump] on_message failed for {:02x?}: {}",
                        token.remote_guid_prefix,
                        e
                    );
                }
            }
        }

        count
    }

    // -----------------------------------------------------------------------
    //  Timer pump
    // -----------------------------------------------------------------------

    /// Advance the handshake retry and expiry timers, queueing any resulting
    /// retransmission on `channel.tx_tokens`.
    ///
    /// `HandshakeMachine::tick` is purely a decision function: it returns the
    /// actions but sends nothing. This is the bridge that turns them into wire
    /// traffic, and it is the only reason the retry ladder in sec. 9.3.4.1 exists
    /// at runtime. It must be called periodically -- the
    /// `hdds-stateless-writer` thread owns that duty -- because nothing on the
    /// receive path can move a session that is waiting for a packet that was
    /// lost.
    ///
    /// # Arguments
    ///
    /// - `machine`: the PKI-DH state machine holding the per-peer timers.
    /// - `channel`: the stateless tunnel receiving the retransmissions.
    /// - `now`: the current instant. Taken as a parameter rather than read
    ///   from the clock so tests can drive the ladder without sleeping.
    ///
    /// # Returns
    ///
    /// The number of actions the tick produced (retransmissions plus
    /// expiries), for callers that want to log or meter timer activity.
    pub(crate) fn drive_timers(
        machine: &Arc<HandshakeMachine>,
        channel: &StatelessChannel,
        now: std::time::Instant,
    ) -> usize {
        let actions = machine.tick(now);
        let count = actions.len();
        for action in actions {
            handle_action(action, channel);
        }
        count
    }

    // -----------------------------------------------------------------------
    //  Outbound pump
    // -----------------------------------------------------------------------

    /// Drain all tokens queued on `tx_tokens` and return them as a list of
    /// `(remote_guid_prefix, raw_payload)` pairs.
    ///
    /// The RTPS writer thread consumes this list and emits one DATA submessage
    /// per entry on the `BuiltinParticipantStatelessMessageWriter` (entity ID
    /// `0x000201C3`). INFO_DST should be set to `remote_guid_prefix`.
    ///
    /// Returns an empty `Vec` when no tokens are pending (non-blocking).
    pub fn drain_outgoing(channel: &StatelessChannel) -> Vec<([u8; 12], Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(token) = channel.pop_outgoing() {
            out.push((token.remote_guid_prefix, token.payload));
        }
        out
    }

    // -----------------------------------------------------------------------
    //  HandshakeAction -> outgoing StatelessToken conversion
    // -----------------------------------------------------------------------

    /// Convert a `HandshakeAction` returned from `HandshakeMachine::start`,
    /// `start_and_announce`, or `on_message` into an outgoing
    /// `StatelessToken` and enqueue it on `channel.tx_tokens`.
    ///
    /// This is the **public(crate) entry point** used by `fsm/discovery.rs`
    /// (`handle_spdp`) to turn each action `machine.start_and_announce()`
    /// returns into a queued token without the call-site needing to know
    /// about `StatelessToken` or the encode helpers.
    ///
    /// `Completed`, `Failed`, and `Drop` actions are logged; they do not
    /// produce wire traffic.
    pub(crate) fn enqueue_action(action: HandshakeAction, channel: &StatelessChannel) {
        handle_action(action, channel);
    }

    /// Convert a `HandshakeAction` that produces a message into an outgoing
    /// `StatelessToken` and enqueue it.
    ///
    /// `Completed`, `Failed`, and `Drop` actions are logged; they do not
    /// produce wire traffic.
    fn handle_action(action: HandshakeAction, channel: &StatelessChannel) {
        match action {
            HandshakeAction::SendRequest(remote, token) => {
                // A token that cannot be encoded is not sent. There is no
                // partial or wrapped form of it that a peer could parse.
                let payload = match encode_request(&token) {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!(
                            "[security::pump] cannot encode AuthRequest for {}: {}",
                            remote,
                            e
                        );
                        return;
                    }
                };
                let st = StatelessToken {
                    remote_guid_prefix: remote.prefix,
                    payload,
                };
                if !channel.push_outgoing(st) {
                    log::warn!(
                        "[security::pump] outgoing queue full: dropped AuthRequest for {}",
                        remote
                    );
                } else {
                    log::debug!("[security::pump] queued AuthRequest for {}", remote);
                }
            }
            HandshakeAction::SendReply(remote, token) => {
                // A token that cannot be encoded is not sent. There is no
                // partial or wrapped form of it that a peer could parse.
                let payload = match encode_reply(&token) {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!(
                            "[security::pump] cannot encode AuthReply for {}: {}",
                            remote,
                            e
                        );
                        return;
                    }
                };
                let st = StatelessToken {
                    remote_guid_prefix: remote.prefix,
                    payload,
                };
                if !channel.push_outgoing(st) {
                    log::warn!(
                        "[security::pump] outgoing queue full: dropped AuthReply for {}",
                        remote
                    );
                } else {
                    log::debug!("[security::pump] queued AuthReply for {}", remote);
                }
            }
            HandshakeAction::SendFinal(remote, token) => {
                // A token that cannot be encoded is not sent. There is no
                // partial or wrapped form of it that a peer could parse.
                let payload = match encode_final(&token) {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!(
                            "[security::pump] cannot encode AuthFinal for {}: {}",
                            remote,
                            e
                        );
                        return;
                    }
                };
                let st = StatelessToken {
                    remote_guid_prefix: remote.prefix,
                    payload,
                };
                if !channel.push_outgoing(st) {
                    log::warn!(
                        "[security::pump] outgoing queue full: dropped AuthFinal for {}",
                        remote
                    );
                } else {
                    log::debug!(
                        "[security::pump] queued AuthFinal for {} (initiator now authenticated)",
                        remote
                    );
                }
            }
            HandshakeAction::Completed(remote, secret) => {
                log::info!(
                    "[security::pump] handshake Completed for {} (shared_secret {} bytes)",
                    remote,
                    secret.as_bytes().len()
                );
            }
            HandshakeAction::Failed(remote, reason) => {
                log::warn!(
                    "[security::pump] handshake Failed for {}: {}",
                    remote,
                    reason
                );
            }
            HandshakeAction::Drop(remote) => {
                log::debug!("[security::pump] handshake entry dropped for {}", remote);
            }
            HandshakeAction::SendAuthRequest(remote, token) => {
                let payload = match encode_auth_req(&token) {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!(
                            "[security::pump] cannot encode authentication request for {}: {}",
                            remote,
                            e
                        );
                        return;
                    }
                };
                let st = StatelessToken {
                    remote_guid_prefix: remote.prefix,
                    payload,
                };
                if !channel.push_outgoing(st) {
                    log::warn!(
                        "[security::pump] outgoing queue full: dropped authentication request \
                         for {}",
                        remote
                    );
                } else {
                    log::debug!(
                        "[security::pump] queued authentication request for {}",
                        remote
                    );
                }
            }
            HandshakeAction::Ignored(remote, reason) => {
                log::debug!(
                    "[security::pump] message from {} ignored: {}",
                    remote,
                    reason
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    //  Helper: build a participant GUID from a 12-byte prefix
    // -----------------------------------------------------------------------

    /// Reconstruct a participant GUID from its 12-byte prefix by appending
    /// the well-known ENTITYID_PARTICIPANT entity kind bytes.
    ///
    /// Per RTPS v2.5 Table 9.5 the built-in participant entity ID is
    /// `{0x00, 0x00, 0x01, 0xC1}`.
    fn guid_from_prefix(prefix: [u8; 12]) -> GUID {
        GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1])
    }
}

// ---------------------------------------------------------------------------
//  Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::security::stateless::{StatelessChannel, StatelessToken};

    // -----------------------------------------------------------------------
    //  StatelessChannel sanity: outgoing queue starts empty
    // -----------------------------------------------------------------------

    #[test]
    fn drain_outgoing_empty_channel_returns_empty() {
        let channel = StatelessChannel::new();
        assert_eq!(channel.outgoing_len(), 0);
        // When the security feature is enabled, drain_outgoing should
        // return an empty Vec for an empty channel.
        #[cfg(feature = "security")]
        {
            use super::inner::drain_outgoing;
            let result = drain_outgoing(&channel);
            assert!(result.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    //  drain_outgoing (security-gated): consumes all tokens from tx queue
    // -----------------------------------------------------------------------

    #[test]
    fn drain_outgoing_consumes_all_tokens() {
        let channel = StatelessChannel::new();

        for i in 0u8..3 {
            channel.push_outgoing(StatelessToken {
                remote_guid_prefix: [i; 12],
                payload: vec![i, i, i],
            });
        }
        assert_eq!(channel.outgoing_len(), 3);

        #[cfg(feature = "security")]
        {
            use super::inner::drain_outgoing;
            let tokens = drain_outgoing(&channel);
            assert_eq!(tokens.len(), 3);
            assert_eq!(channel.outgoing_len(), 0, "queue must be empty after drain");
        }
        #[cfg(not(feature = "security"))]
        {
            while channel.pop_outgoing().is_some() {}
            assert_eq!(channel.outgoing_len(), 0);
        }
    }

    // -----------------------------------------------------------------------
    //  Inbound + outbound round-trip via StatelessChannel:
    //  push a token to rx, drain it back from tx.
    // -----------------------------------------------------------------------

    #[test]
    fn stateless_channel_roundtrip_push_drain() {
        let channel = StatelessChannel::new();

        // Simulate the wire: push an outgoing token directly (bypass machine).
        let remote: [u8; 12] = [0x11; 12];
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        channel.push_outgoing(StatelessToken {
            remote_guid_prefix: remote,
            payload: payload.clone(),
        });

        // Drain outgoing (the writer thread path).
        #[cfg(feature = "security")]
        {
            use super::inner::drain_outgoing;
            let drained = drain_outgoing(&channel);
            assert_eq!(drained.len(), 1);
            assert_eq!(
                drained[0].0, remote,
                "remote_guid_prefix must survive round-trip"
            );
            assert_eq!(drained[0].1, payload, "payload must survive round-trip");
            assert_eq!(channel.outgoing_len(), 0, "queue must be empty after drain");
        }
        #[cfg(not(feature = "security"))]
        {
            let _ = channel.pop_outgoing();
            assert_eq!(channel.outgoing_len(), 0);
        }
    }

    // -----------------------------------------------------------------------
    //  enqueue_action(SendRequest) must push exactly one token onto tx_tokens
    // -----------------------------------------------------------------------

    #[cfg(feature = "security")]
    #[test]
    fn enqueue_action_send_request_populates_tx_tokens() {
        use super::inner::{drain_outgoing, enqueue_action};
        use crate::core::discovery::GUID;
        use crate::security::handshake::{tokens::AuthRequestToken, HandshakeAction};
        use crate::security::stateless::StatelessChannel;

        let channel = StatelessChannel::new();
        let remote_guid = GUID::new([0xAB; 12], [0x00, 0x00, 0x01, 0xC1]);
        let token = AuthRequestToken {
            identity_cert_der: vec![0x30, 0x82, 0x01],
            challenge1: [0xAA; 32],
            dh1: vec![0x04; 65],
            pdata: vec![1, 2, 3],
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            permissions_doc: None,
        };

        assert_eq!(channel.outgoing_len(), 0);
        enqueue_action(HandshakeAction::SendRequest(remote_guid, token), &channel);

        assert_eq!(
            channel.outgoing_len(),
            1,
            "SendRequest must produce one outgoing token"
        );

        let drained = drain_outgoing(&channel);
        assert_eq!(drained.len(), 1);
        // The remote_guid_prefix must match the GUID prefix used in the action.
        assert_eq!(
            drained[0].0, [0xAB; 12],
            "remote_guid_prefix must match GUID prefix"
        );
        // The payload must be non-empty (CDR-encoded DataHolder).
        assert!(
            !drained[0].1.is_empty(),
            "encoded AuthRequest payload must not be empty"
        );
    }

    // -----------------------------------------------------------------------
    //  drain_incoming / LocalIdentity: security-gated tests.
    //
    //  HandshakeMachine and LocalIdentity only compile with the `security`
    //  feature. The full round-trip test that exercises the crypto path
    //  (AuthRequest -> AuthReply -> AuthFinal) lives in
    //  `security::handshake::tests`; the tests here verify the pump
    //  plumbing layer independently.
    // -----------------------------------------------------------------------

    #[cfg(feature = "security")]
    mod security_tests {
        use super::super::inner::*;
        use crate::core::discovery::GUID;
        use crate::security::handshake::HandshakeMachine;
        use crate::security::stateless::StatelessChannel;
        use std::sync::Arc;

        fn responder_identity() -> LocalIdentity {
            LocalIdentity {
                guid: GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]),
                cert_der: vec![0x30, 0x82, 0x02],
                key_pem: zeroize::Zeroizing::new(
                    b"-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----\n"
                        .to_vec(),
                ),
                ca_cert_pem: b"-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n"
                    .to_vec(),
            }
        }

        // -------------------------------------------------------------------
        //  drain_incoming on empty channel -> 0 consumed
        // -------------------------------------------------------------------

        #[test]
        fn drain_incoming_empty_channel_returns_zero() {
            let channel = StatelessChannel::new();
            let machine = Arc::new(HandshakeMachine::new());
            let n = drain_incoming(&channel, &machine, &responder_identity());
            assert_eq!(n, 0, "empty channel must report 0 consumed tokens");
        }

        // -------------------------------------------------------------------
        //  drive_timers: a due retry must reach tx_tokens, not just the log.
        //
        //  This is the bridge that gap G14 was missing. `tick()` decides; it
        //  sends nothing. Until something carried its decisions to the
        //  channel, the whole sec. 9.3.4.1 retry ladder was dead code.
        // -------------------------------------------------------------------

        #[test]
        fn drive_timers_puts_the_retransmission_on_the_wire_queue() {
            use std::time::{Duration, Instant};

            let channel = StatelessChannel::new();
            let machine = Arc::new(HandshakeMachine::new());
            let local = GUID::new([0x01; 12], [0x00, 0x00, 0x01, 0xC1]);
            let remote = GUID::new([0xFF; 12], [0x00, 0x00, 0x01, 0xC1]);

            let action = machine
                .start(
                    local,
                    remote,
                    crate::security::test_pki::TEST_IDENTITY_CERT_PEM,
                    crate::security::test_pki::TEST_IDENTITY_KEY_PEM,
                )
                .expect("start must succeed")
                .expect("the lower GUID prefix takes the initiator role");
            enqueue_action(action, &channel);

            let original = drain_outgoing(&channel);
            assert_eq!(original.len(), 1, "the first AuthRequest is queued");

            assert_eq!(
                drive_timers(&machine, &channel, Instant::now()),
                0,
                "no rung is due yet"
            );
            assert_eq!(channel.outgoing_len(), 0);

            let now = Instant::now() + Duration::from_millis(1_100);
            assert_eq!(
                drive_timers(&machine, &channel, now),
                1,
                "the 1 s rung must produce one action"
            );

            let retransmitted = drain_outgoing(&channel);
            assert_eq!(
                retransmitted.len(),
                1,
                "a due retry must land on tx_tokens where the writer thread can see it"
            );
            assert_eq!(
                retransmitted[0].0, remote.prefix,
                "the retransmission must target the same peer"
            );
            assert_eq!(
                retransmitted[0].1, original[0].1,
                "the retransmitted payload must be byte-identical to the original"
            );
        }

        // -------------------------------------------------------------------
        //  drain_incoming: malformed payload -> error logged, 1 token
        //  consumed, outgoing queue stays empty (no reply produced).
        //
        //  Verifies that a bad payload doesn't crash the pump; the machine
        //  returns Err, the pump logs a warning and moves on.
        // -------------------------------------------------------------------

        #[test]
        fn drain_incoming_malformed_payload_no_crash() {
            use crate::security::stateless::StatelessToken;

            let channel = StatelessChannel::new();
            channel.push_incoming(StatelessToken {
                remote_guid_prefix: [0xAB; 12],
                payload: vec![0x00, 0x01, 0x02, 0x03], // not a valid DataHolder
            });

            let machine = Arc::new(HandshakeMachine::new());
            let n = drain_incoming(&channel, &machine, &responder_identity());

            assert_eq!(n, 1, "pump must consume the token even on parse error");
            assert_eq!(channel.incoming_len(), 0, "incoming queue must be empty");
            assert_eq!(
                channel.outgoing_len(),
                0,
                "no outgoing token must be produced for a parse error"
            );
        }
    }
}
