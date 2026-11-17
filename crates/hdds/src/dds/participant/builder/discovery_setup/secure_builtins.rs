// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bootstrap the 12 DDS-Security built-in endpoints (DDS Security v1.1 sec. 7.4.1.3).
//!
//! This module is the **enumeration / advertising** half of security wire-gap
//! #2. It registers the local participant's 12 secure builtin endpoint GUIDs
//! so they can be advertised in `PID_BUILTIN_ENDPOINT_SET` (bit field) and
//! exposed to the participant builder as a `SecureBuiltins` handle.
//!
//! The 4 secure tunnels (6 writer/reader pairs = 12 endpoint GUIDs):
//!
//! | Tunnel                               | Writer entity   | Reader entity   |
//! |--------------------------------------|-----------------|-----------------|
//! | SPDP secure                          | 0xff0101c2      | 0xff0101c7      |
//! | SEDP secure publications             | 0xff0003c2      | 0xff0003c7      |
//! | SEDP secure subscriptions            | 0xff0004c2      | 0xff0004c7      |
//! | ParticipantMessage secure (liveness) | 0xff0200c2      | 0xff0200c7      |
//! | ParticipantStatelessMessage (auth)   | 0x000201c3      | 0x000201c4      |
//! | ParticipantVolatileMessage secure    | 0xff0202c3      | 0xff0202c4      |
//!
//! # What this module does in v1
//!
//! - **Enumerates** the 12 local builtin GUIDs and returns them grouped by
//!   tunnel kind. The bits the SPDP announcement carries for the ones served
//!   are `protocol::discovery::constants::BUILTIN_ENDPOINT_SET_SECURITY`.
//! - **Creates** the `StatelessChannel` facade for the unencrypted PKI-DH
//!   handshake tunnel (gap #3 will consume the `tx_tokens` / `rx_tokens`
//!   queues to advance the actual handshake state machine).
//!
//! # What this module does NOT do in v1
//!
//! - Does NOT instantiate the underlying RTPS writers/readers. The existing
//!   `ReaderProxyRegistry` and `MatchedReadersRegistry` populate
//!   reactively when a peer is observed (via `on_data` / `on_heartbeat`).
//!   Pre-emptive proxy creation is a gap #4 chore.
//! - Does NOT encrypt or decrypt anything. SecureSubMsg wrapping is gap #4.
//! - Does NOT drive the PKI-DH handshake. That is gap #3.

#[cfg(feature = "security")]
use crate::core::discovery::guid::GUID;
// The 12 secure builtin entity ids, the endpoint bitmask and the tunnel type
// below are the security surface of this module: every consumer of them sits
// behind `feature = "security"`, so the declarations follow. Left ungated they
// are dead code on the DEFAULT feature set, which `clippy -D warnings` refuses
// (the all-features build, where these do not fire, would not catch it).
#[cfg(feature = "security")]
use crate::core::rtps_constants::{
    RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER,
    RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER,
    RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
    RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
    RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,
    RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER,
    RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
    RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
    RTPS_ENTITYID_SPDP_SECURE_READER, RTPS_ENTITYID_SPDP_SECURE_WRITER,
};

#[cfg(feature = "security")]
use crate::core::discovery::EndpointRegistry;
#[cfg(feature = "security")]
use crate::security::handshake::HandshakeMachine;
#[cfg(feature = "security")]
use crate::security::pump::LocalIdentity;
#[cfg(feature = "security")]
use crate::security::stateless::{StatelessChannel, StatelessToken};
#[cfg(feature = "security")]
use crate::security::stateless_writer::inner::StatelessWriterHandle;
#[cfg(feature = "security")]
use crate::security::SecurityPluginSuite;
#[cfg(feature = "security")]
use crate::transport::UdpTransport;
#[cfg(feature = "security")]
use std::sync::Arc;

// The bits these endpoints are announced under, and which of them are
// announced at all, are `protocol::discovery::constants::
// BUILTIN_ENDPOINT_SET_SECURITY`: one definition, read by the SPDP
// announcement and the discovery-server registration alike. Not every tunnel
// enumerated here is served, so not every one is announced.

/// Logical grouping of one secure tunnel (writer GUID + reader GUID).
#[cfg(feature = "security")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct SecureTunnel {
    /// Human-readable label for diagnostics.
    pub label: &'static str,
    /// Local writer GUID for this tunnel.
    pub writer_guid: GUID,
    /// Local reader GUID for this tunnel.
    pub reader_guid: GUID,
}

/// What [`SecureBuiltins::receive_volatile`] made of one SEC_PREFIX.
#[cfg(feature = "security")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VolatileOutcome {
    /// Not protected under the sender's KxKeys (another key id or
    /// transformation, or no KxKeys held because the sender has not
    /// authenticated): not this channel's, for the caller to route on.
    NotKx,
    /// Names the KxKeys' key id and did not open under them.
    Refused,
    /// Opened, and is a submessage this participant sealed itself, sent
    /// back under the peer's prefix: dropped, and nothing else.
    Reflected,
    /// Opened: a submessage of the volatile endpoints, handled.
    Opened(VolatileReceipt),
}

/// A volatile submessage [`SecureBuiltins::receive_volatile`] opened.
#[cfg(feature = "security")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VolatileReceipt {
    /// One past its SEC_POSTFIX, where a further envelope may begin.
    pub end: usize,
    /// Whether a key of the sender was installed.
    pub installed: bool,
    /// RTPS messages to send the sender in answer (an ACKNACK of our
    /// reader, or the repairs of our writer).
    pub replies: Vec<Vec<u8>>,
}

/// Handle returned by `setup_secure_builtins`. Owns the StatelessChannel,
/// the HandshakeMachine reference, and the local identity material needed to
/// drive the PKI-DH 3-message exchange.
///
/// Gap #3 bridge: callers pass incoming raw bytes from the
/// `BuiltinParticipantStatelessMessageReader` to `dispatch_stateless`.
/// Outgoing tokens are drained via `drain_outgoing` and emitted on the wire
/// by the `BuiltinParticipantStatelessMessageWriter`.
///
/// Gap #4 (SecureSubMsg de/encoder) will consume `tunnels` to know which
/// entity IDs trigger crypto transformation.
#[cfg(feature = "security")]
#[derive(Clone)]
pub(crate) struct SecureBuiltins {
    /// The 6 advertised tunnels (12 endpoint GUIDs total).
    pub tunnels: [SecureTunnel; 6],

    /// Plaintext authentication handshake channel (BEST_EFFORT, VOLATILE).
    pub stateless_channel: StatelessChannel,

    /// Shared PKI-DH handshake state machine.
    ///
    /// Passed in from `SecurityPluginSuite::handshakes` so that the same
    /// machine instance is shared with the SPDP handler (which calls
    /// `HandshakeMachine::start`) and the stateless pump (which calls
    /// `HandshakeMachine::on_message`).
    pub handshake_machine: Arc<HandshakeMachine>,

    /// Local identity material forwarded to `HandshakeMachine::on_message`.
    pub local_identity: LocalIdentity,

    /// The full plugin suite, for state that lives beside the machine --
    /// today that is `data_keys`, where volatile key distributions land.
    pub suite: Arc<SecurityPluginSuite>,
}

#[cfg(feature = "security")]
impl SecureBuiltins {
    /// Route a raw DATA payload from the `BuiltinParticipantStatelessMessageReader`
    /// into the `HandshakeMachine` and enqueue any outgoing reply token.
    ///
    /// # Arguments
    ///
    /// - `remote_guid_prefix`: the 12-byte GUID prefix extracted from the
    ///   RTPS INFO_SRC or the writer GUID of the DATA submessage.
    /// - `payload`: raw CDR bytes of the `ParticipantStatelessMessage`
    ///   DataHolder (the full serialised `StatelessToken` payload).
    pub fn dispatch_stateless(&self, remote_guid_prefix: [u8; 12], payload: Vec<u8>) {
        let pushed = self.stateless_channel.push_incoming(StatelessToken {
            remote_guid_prefix,
            payload,
        });
        if !pushed {
            log::warn!(
                "[security::secure_builtins] incoming stateless queue full, dropping token from {:02x?}",
                remote_guid_prefix
            );
            return;
        }
        // Drain synchronously: the stateless channel is tiny (max 16 entries)
        // and on_message is fast (no I/O). Synchronous drain avoids spawning
        // a dedicated background thread for the low-volume handshake path.
        let consumed = crate::security::pump::drain_incoming(
            &self.stateless_channel,
            &self.handshake_machine,
            &self.local_identity,
        );
        log::debug!(
            "[security::secure_builtins] drain_incoming consumed {} token(s) from {:02x?}",
            consumed,
            remote_guid_prefix
        );
    }

    /// Harvest all outgoing tokens queued by the `HandshakeMachine` and
    /// return them as `(remote_guid_prefix, raw_payload)` pairs ready for
    /// emission on the `BuiltinParticipantStatelessMessageWriter`.
    ///
    /// Returns an empty `Vec` when no tokens are pending.
    #[allow(dead_code)]
    pub fn drain_outgoing(&self) -> Vec<([u8; 12], Vec<u8>)> {
        crate::security::pump::drain_outgoing(&self.stateless_channel)
    }

    /// Open the SEC_PREFIX at `prefix_at` of `datagram`, sent by
    /// `remote_prefix`, as a submessage of the ParticipantVolatileMessage
    /// Secure endpoints, under OUR Table 67 KxKeys for that peer -- which
    /// exist only once the PKI-DH handshake completed, so an
    /// unauthenticated sender's traffic is never opened here.
    ///
    /// Every submessage of the two volatile endpoints is protected under
    /// that material (DDS Security v1.1 Sec.7.4.4.1, Table 17,
    /// Sec.8.5.1.9.2), and nothing else is: a SEC_PREFIX whose CryptoHeader
    /// names another key id or transformation is not this channel's
    /// ([`VolatileOutcome::NotKx`]), one that names the Kx key id and does
    /// not authenticate under it is [`VolatileOutcome::Refused`], and one
    /// that opens is this channel's, whatever it turns out to carry.
    ///
    /// What opened goes to the reliable pair (`volatile_channel`): a DATA,
    /// HEARTBEAT or GAP of the peer's volatile writer to our reader, an
    /// ACKNACK or NACK_FRAG of its reader to our writer. The changes the
    /// reader then delivers, in order, are handled here; the answers (an
    /// ACKNACK, or repairs) are the receipt's `replies`, for the caller to
    /// send to the peer.
    pub fn receive_volatile(
        &self,
        remote_prefix: [u8; 12],
        datagram: &[u8],
        prefix_at: usize,
    ) -> VolatileOutcome {
        use crate::security::crypto::secure_submessage::{
            decode_datawriter_submessage, DecodeRefusal,
        };
        use crate::security::crypto::volatile::parse_data;
        use crate::security::volatile_channel::{parse_control, Control, Delivery};
        let local = self.local_identity.guid.prefix;
        let now = std::time::Instant::now();
        let channel = &self.suite.volatile;
        let stats = &channel.stats;
        self.handshake_machine
            .with_volatile_key_material(&remote_prefix, |material| {
                let decoded = match decode_datawriter_submessage(&material, datagram, prefix_at) {
                    Ok(decoded) => decoded,
                    Err(DecodeRefusal::KeyNotHeld | DecodeRefusal::UnknownTransformation) => {
                        return VolatileOutcome::NotKx
                    }
                    Err(e) => {
                        log::debug!(
                            "[security::volatile] {:02x?}: a submessage under the volatile key id \
                             did not open: {:?}",
                            remote_prefix,
                            e
                        );
                        return VolatileOutcome::Refused;
                    }
                };
                // The KxKeys are one material for both ends of the pair
                // (DDS Security v1.1 Sec.9.5.2.1.2, Table 67): what we
                // sealed for the peer opens here too, when someone sends it
                // back under the peer's prefix. Taken for the peer's, a
                // DATA would mark its sequence number received and an
                // ACKNACK or HEARTBEAT would move the reliable state of the
                // wrong direction. Only the SessionId says it is ours.
                if material.sealed_under(decoded.session_id) {
                    stats.note_reflection_refused();
                    log::debug!(
                        "[security::volatile] {:02x?}: a submessage this participant sealed, \
                         sent back under the peer's prefix, drop",
                        remote_prefix
                    );
                    return VolatileOutcome::Reflected;
                }
                let session = material.fingerprint();
                // Serialize admission, replay bookkeeping and installation
                // with retries, while the authentication lease is held.
                let mut reader = channel.reader.lock();
                if reader.start_session(remote_prefix, session) {
                    self.suite.volatile_replay.reset(remote_prefix);
                    channel.reset_pending(remote_prefix);
                }
                let mut installed = false;
                let mut admit = |sn, payload: &[u8], repair| match self.deliver_volatile_message(
                    remote_prefix,
                    session,
                    sn,
                    repair,
                    payload,
                    now,
                ) {
                    Some(did_install) => {
                        installed |= did_install;
                        true
                    }
                    None => false,
                };
                let delivery = if let Some(data) = parse_data(&decoded.submessage) {
                    reader.on_data(
                        remote_prefix,
                        session,
                        data.sequence_number,
                        data.payload,
                        stats,
                        &mut admit,
                    )
                } else {
                    match parse_control(&decoded.submessage) {
                        Some(Control::Heartbeat {
                            first,
                            last,
                            count,
                            final_flag,
                        }) => reader.on_heartbeat(
                            &local,
                            remote_prefix,
                            &material,
                            first,
                            last,
                            count,
                            final_flag,
                            &mut admit,
                        ),
                        Some(Control::Gap {
                            start,
                            list_base,
                            list,
                        }) => reader.on_gap(
                            remote_prefix,
                            session,
                            start,
                            list_base,
                            &list,
                            &mut admit,
                        ),
                        Some(Control::AckNack {
                            base,
                            requested,
                            count,
                        }) => Delivery {
                            replies: channel.writer.lock().on_acknack(
                                &local,
                                remote_prefix,
                                &material,
                                now,
                                base,
                                &requested,
                                count,
                                stats,
                            ),
                            ..Delivery::default()
                        },
                        Some(Control::NackFrag { sn, count }) => Delivery {
                            replies: channel.writer.lock().on_nack_frag(
                                &local,
                                remote_prefix,
                                &material,
                                now,
                                sn,
                                count,
                                stats,
                            ),
                            ..Delivery::default()
                        },
                        None => {
                            stats.note_foreign_submessage_refused();
                            log::debug!(
                                "[security::volatile] {:02x?}: opened under the volatile key \
                                 material but is no submessage of the volatile endpoints, drop",
                                remote_prefix
                            );
                            Delivery::default()
                        }
                    }
                };
                VolatileOutcome::Opened(VolatileReceipt {
                    end: decoded.end,
                    installed,
                    replies: delivery.replies,
                })
            })
            .unwrap_or(VolatileOutcome::NotKx)
    }

    /// [`Self::receive_volatile`] of a bare protected submessage (what
    /// `seal` returns, its SEC_PREFIX at offset 0): whether a key was
    /// installed.
    #[cfg(test)]
    pub fn dispatch_volatile(&self, remote_guid_prefix: [u8; 12], envelope: &[u8]) -> bool {
        matches!(
            self.receive_volatile(remote_guid_prefix, envelope, 0),
            VolatileOutcome::Opened(VolatileReceipt {
                installed: true,
                ..
            })
        )
    }

    /// Note a clear (unprotected) DATA of the volatile endpoints, refused:
    /// the topic is submessage-protected (Sec.7.4.4.1, Table 17).
    pub fn refuse_clear_volatile(&self, remote_guid_prefix: [u8; 12]) {
        self.suite.volatile.stats.note_clear_refused();
        log::debug!(
            "[security::volatile] {:02x?}: a clear DATA of the volatile secure endpoints, refused",
            remote_guid_prefix
        );
    }

    /// Note a SEC_PREFIX under the volatile key id from an authenticated
    /// `remote_guid_prefix` that did not open under its KxKeys, refused.
    pub fn refuse_undecodable_volatile(&self, remote_guid_prefix: [u8; 12]) {
        self.suite.volatile.stats.note_undecodable();
        self.suite
            .data_keys
            .audit_open_failure_once(remote_guid_prefix);
    }

    /// One ParticipantVolatileMessageSecure sample from `remote_guid_prefix`
    /// (`payload`: its CDR ParticipantGenericMessage), received in order:
    /// route it on its class id. Returns whether a key was installed.
    ///
    /// Some reports a consumed sample and whether it installed material.
    /// None applies back-pressure: the DATA must remain unacknowledged.
    fn deliver_volatile_message(
        &self,
        remote_guid_prefix: [u8; 12],
        session: crate::security::volatile_channel::Session,
        writer_sn: i64,
        repair: bool,
        payload: &[u8],
        now: std::time::Instant,
    ) -> Option<bool> {
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::volatile::{
            decode_message, ParticipantKeyAnnouncement, ReaderKeyAnnouncement,
            WriterKeyAnnouncement, CLASS_DATAREADER_CRYPTO_TOKENS, CLASS_PARTICIPANT_CRYPTO_TOKENS,
            GUID_UNKNOWN,
        };

        let message = match decode_message(payload) {
            Ok(message) => message,
            Err(e) => {
                self.suite
                    .data_keys
                    .audit_open_failure_once(remote_guid_prefix);
                log::debug!(
                    "[security::volatile] malformed message from {:02x?}: {}",
                    remote_guid_prefix,
                    e
                );
                return Some(false);
            }
        };

        // Sec.7.4.4.4: a message whose destination_participant_guid is not
        // GUID_UNKNOWN is intended only for the volatile reader of the
        // participant it names (the reader's implied content filter).
        if message.destination_participant != GUID_UNKNOWN
            && message.destination_participant != self.local_identity.guid.as_bytes()
        {
            self.suite.volatile.stats.note_misaddressed_participant();
            log::debug!(
                "[security::volatile] {:02x?} addressed a message to participant {:02x?}, not \
                 to us, drop",
                remote_guid_prefix,
                message.destination_participant
            );
            return Some(false);
        }

        // Sec.7.4.4.3: one sequence counter per sending volatile writer,
        // shared by every message class it emits. A captured, otherwise
        // legitimately-signed envelope replayed later must not be
        // installed again -- it could roll a key back to one the sender
        // has since rotated away from.
        // New transport changes are inspected in order. Once a DATA is
        // deferred, its proxy authorizes only byte-identical repairs, even
        // if later messages have advanced the identity watermark.
        if !repair
            && !self
                .suite
                .volatile_replay
                .accept(remote_guid_prefix, message.sequence_number)
        {
            return Some(false);
        }

        if message.class_id == CLASS_PARTICIPANT_CRYPTO_TOKENS {
            let installed = match ParticipantKeyAnnouncement::from_message(&message) {
                Ok(announcement) => {
                    self.suite.participant_keys.install_remote(
                        remote_guid_prefix,
                        announcement.key_id,
                        crate::security::crypto::data_keys::WriterKey::new(
                            announcement.key,
                            announcement.master_salt,
                        ),
                    );
                    log::debug!(
                        "[security::volatile] installed participant key material from {:02x?} \
                         key_id={:#x}",
                        remote_guid_prefix,
                        announcement.key_id
                    );
                    true
                }
                Err(e) => {
                    self.suite
                        .data_keys
                        .audit_open_failure_once(remote_guid_prefix);
                    log::debug!(
                        "[security::volatile] malformed ParticipantCryptoTokens from {:02x?}: {}",
                        remote_guid_prefix,
                        e
                    );
                    false
                }
            };
            return Some(installed);
        }

        if message.class_id == CLASS_DATAREADER_CRYPTO_TOKENS {
            match ReaderKeyAnnouncement::from_message(&message) {
                Ok(announcement) => self.install_endpoint_tokens(
                    remote_guid_prefix,
                    session,
                    message.sequence_number,
                    writer_sn,
                    now,
                    announcement.reader_guid,
                    message.destination_endpoint,
                    announcement.key_id,
                    WriterKey::new(announcement.key, announcement.master_salt)
                        .with_transformation(announcement.transformation),
                ),
                Err(e) => {
                    self.suite
                        .data_keys
                        .audit_open_failure_once(remote_guid_prefix);
                    log::debug!(
                        "[security::volatile] malformed DatareaderCryptoTokens from {:02x?}: {}",
                        remote_guid_prefix,
                        e
                    );
                    Some(false)
                }
            }
        } else {
            match WriterKeyAnnouncement::from_message(&message) {
                Ok(announcement) => self.install_endpoint_tokens(
                    remote_guid_prefix,
                    session,
                    message.sequence_number,
                    writer_sn,
                    now,
                    announcement.writer_guid,
                    message.destination_endpoint,
                    announcement.key_id,
                    WriterKey::new(announcement.key, announcement.master_salt)
                        .with_transformation(announcement.transformation),
                ),
                Err(e) => {
                    self.suite
                        .data_keys
                        .audit_open_failure_once(remote_guid_prefix);
                    log::debug!(
                        "[security::volatile] unrecognized volatile message from {:02x?}: {}",
                        remote_guid_prefix,
                        e
                    );
                    Some(false)
                }
            }
        }
    }

    /// The CryptoTokens of the remote endpoint `source` (a
    /// DatawriterCryptoTokens' DataWriter or a DatareaderCryptoTokens'
    /// DataReader), carrying `key` under `key_id` and addressed to
    /// `destination`: installed when the addressing holds, held when it
    /// names a local endpoint not matched with `source` yet, refused (and
    /// counted) otherwise. None defers the transport acknowledgement;
    /// Some reports a consumed sample and whether installation succeeded.
    ///
    /// - `source` must belong to the peer that protected the message:
    ///   otherwise any authenticated participant could install keys under
    ///   ANOTHER participant's endpoint GUIDs and have its forged traffic
    ///   decode as theirs.
    /// - A secure builtin endpoint pairs 1:1 with its mirror
    ///   (`volatile::builtin_peer_entity_id`): the destination is that
    ///   mirror of ours, nothing else.
    /// - A USER endpoint's destination is one of our endpoints, of the kind
    ///   it addresses, matched with it (DDS Security v1.1 Sec.7.4.4.6.2-3,
    ///   `VolatileChannel::user_addressing`); GUID_UNKNOWN is no
    ///   destination.
    #[allow(clippy::too_many_arguments)]
    fn install_endpoint_tokens(
        &self,
        remote_guid_prefix: [u8; 12],
        session: crate::security::volatile_channel::Session,
        order: i64,
        writer_sn: i64,
        now: std::time::Instant,
        source: GUID,
        destination: [u8; 16],
        key_id: u64,
        key: crate::security::crypto::data_keys::WriterKey,
    ) -> Option<bool> {
        use crate::security::crypto::volatile::builtin_peer_entity_id;
        use crate::security::volatile_channel::{Addressing, PendingTokens, PENDING_MATCH_TIMEOUT};
        if source.prefix != remote_guid_prefix {
            log::warn!(
                "[security::volatile] peer {:02x?} announced a key for foreign endpoint {:?}, drop",
                remote_guid_prefix,
                source
            );
            return Some(false);
        }
        let ours = self.local_identity.guid.prefix;
        let addressing = match builtin_peer_entity_id(source.entity_id) {
            Some(mirrored) if destination == GUID::new(ours, mirrored).as_bytes() => {
                Addressing::Matched
            }
            Some(_) => Addressing::Refused,
            None => self
                .suite
                .volatile
                .user_addressing(&ours, &source, &destination),
        };
        match addressing {
            Addressing::Refused => {
                self.suite.volatile.stats.note_misaddressed_endpoint();
                log::warn!(
                    "[security::volatile] peer {:02x?} addressed the key of {:?} to {:02x?}, not \
                     a local endpoint matched with it, drop",
                    remote_guid_prefix,
                    source,
                    destination
                );
                Some(false)
            }
            Addressing::NotYetMatched => {
                let held = self.suite.volatile.hold(PendingTokens {
                    peer: remote_guid_prefix,
                    session,
                    order,
                    writer_sn,
                    source,
                    destination: GUID::from_bytes(destination),
                    key_id,
                    key,
                    deadline: now + PENDING_MATCH_TIMEOUT,
                });
                log::debug!(
                    "[security::volatile] key of {:?} for {:02x?}: not matched yet, held={}",
                    source,
                    destination,
                    held
                );
                None
            }
            Addressing::Matched => self.suite.volatile.install_tokens(
                &self.suite.data_keys,
                source,
                session,
                order,
                key_id,
                key,
            ),
        }
    }

    // There is deliberately no `decrypt_secure_sedp` / `encrypt_for_remote`
    // helper here: the live secure-SEDP path calls the crypto directly from
    // `spdp_handler` and the SecureSEDP callback arm, and a plausible-looking
    // helper nobody calls is how a reader concludes a path is wired when it
    // is not.

    /// Spawn the `BuiltinParticipantStatelessMessageWriter` background thread.
    ///
    /// The writer drains `stateless_channel.tx_tokens` at a 5 ms interval and
    /// emits each token as a complete RTPS packet (INFO_DST + INFO_TS + DATA
    /// with entity ID `0x000201C3`) via the UDP transport. Unicast delivery is
    /// preferred when the remote participant's address is in `endpoint_registry`;
    /// SPDP multicast is used as a fallback.
    ///
    /// The same thread also advances `handshake_machine`'s retry and expiry
    /// timers; it is the engine's only caller of `HandshakeMachine::tick`.
    ///
    /// # Arguments
    ///
    /// - `local_guid_prefix`: 12-byte GUID prefix of the local participant
    ///   (used in the RTPS packet header).
    /// - `transport`: UDP transport for sending packets.
    /// - `endpoint_registry`: live endpoint registry for remote address lookup.
    ///
    /// # Returns
    ///
    /// A `StatelessWriterHandle` that keeps the thread alive while held.
    /// The participant builder must store this handle for the participant
    /// lifetime; dropping it terminates the thread.
    pub fn spawn_stateless_writer(
        &self,
        local_guid_prefix: [u8; 12],
        transport: Arc<UdpTransport>,
        endpoint_registry: EndpointRegistry,
    ) -> StatelessWriterHandle {
        crate::security::stateless_writer::inner::spawn_stateless_writer(
            self.stateless_channel.clone(),
            local_guid_prefix,
            transport,
            endpoint_registry,
            self.suite.clone(),
        )
    }
}

#[cfg(feature = "security")]
impl std::fmt::Debug for SecureBuiltins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBuiltins")
            .field("tunnels", &self.tunnels)
            .field("stateless_channel", &self.stateless_channel)
            .field("handshake_machine", &"HandshakeMachine")
            .field("local_identity", &"LocalIdentity")
            .finish()
    }
}

/// Build the local secure-builtin GUID table for a participant.
///
/// Returns a `SecureBuiltins` handle. The handle's `stateless_channel`
/// is the PKI-DH authentication handshake tunnel. `dispatch_stateless`
/// pushes raw DATA payloads received on entity ID 0x000201C4 into the
/// `HandshakeMachine` and enqueues any outgoing reply tokens.
///
/// # Arguments
///
/// - `participant_guid_prefix` -- the local participant's 12-byte GUID
///   prefix. Each secure-builtin endpoint reuses this prefix and combines
///   it with the spec-defined entity ID per DDS Security v1.1 sec. 7.4.1.3.
/// - `security_suite` -- the security plugin suite. The handshake machine
///   (`SecurityPluginSuite::handshakes`) is shared with the DiscoveryFsm
///   (which calls `HandshakeMachine::start`) and with the stateless pump
///   (which calls `HandshakeMachine::on_message`). Identity cert and CA
///   bundle are loaded from `SecurityConfig` here; errors produce warnings
///   but do not abort setup (the machine will be a no-op without certs).
///
/// # Returns
///
/// `Ok(SecureBuiltins)` with all 6 tunnels initialised.
#[cfg(feature = "security")]
pub(crate) fn setup_secure_builtins(
    participant_guid_prefix: [u8; 12],
    security_suite: &Arc<SecurityPluginSuite>,
) -> Result<SecureBuiltins, crate::dds::Error> {
    log::debug!(
        "[security::secure_builtins] bootstrapping 12 secure builtin endpoints for participant {:02x?}",
        participant_guid_prefix
    );

    let tunnels = [
        SecureTunnel {
            label: "SPDP-secure",
            writer_guid: GUID::new(participant_guid_prefix, RTPS_ENTITYID_SPDP_SECURE_WRITER),
            reader_guid: GUID::new(participant_guid_prefix, RTPS_ENTITYID_SPDP_SECURE_READER),
        },
        SecureTunnel {
            label: "SEDP-secure-publications",
            writer_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            ),
            reader_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            ),
        },
        SecureTunnel {
            label: "SEDP-secure-subscriptions",
            writer_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
            ),
            reader_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
            ),
        },
        SecureTunnel {
            label: "ParticipantMessage-secure",
            writer_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER,
            ),
            reader_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,
            ),
        },
        SecureTunnel {
            label: "ParticipantStatelessMessage",
            writer_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER,
            ),
            reader_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER,
            ),
        },
        SecureTunnel {
            label: "ParticipantVolatileMessage-secure",
            writer_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
            ),
            reader_guid: GUID::new(
                participant_guid_prefix,
                RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
            ),
        },
    ];

    for t in tunnels.iter() {
        log::debug!(
            "[security::secure_builtins] registered tunnel {} (writer entity {:02x?}, reader entity {:02x?})",
            t.label,
            t.writer_guid.entity_id,
            t.reader_guid.entity_id
        );
    }

    let stateless_channel = StatelessChannel::new();

    // Build the LocalIdentity for the inbound pump. A read failure here is
    // FATAL, and the CA bundle is the reason it matters most: an empty bundle
    // is handed straight to validate_cert_chain, so every remote certificate
    // would be judged against an empty trust anchor set. Degrading to Vec::new()
    // is not survivable: the inbound leg is live.
    let read_identity_file =
        |path: &std::path::Path, what: &str| -> Result<Vec<u8>, crate::dds::Error> {
            let bytes = std::fs::read(path).map_err(|e| {
                crate::dds::Error::Config(format!("cannot read {} {}: {}", what, path.display(), e))
            })?;
            if bytes.is_empty() {
                return Err(crate::dds::Error::Config(format!(
                "{} {} is empty -- refusing to build a security pump that cannot validate anything",
                what,
                path.display()
            )));
            }
            Ok(bytes)
        };

    let cert_der = read_identity_file(
        security_suite.config().identity_certificate.as_path(),
        "identity_certificate",
    )?;
    let key_pem = read_identity_file(security_suite.config().private_key.as_path(), "private_key")?;
    let ca_cert_pem = read_identity_file(
        security_suite.config().ca_certificates.as_path(),
        "ca_certificates",
    )?;

    let local_guid = GUID::new(
        participant_guid_prefix,
        [0x00, 0x00, 0x01, 0xC1], // ENTITYID_PARTICIPANT
    );
    let local_identity = LocalIdentity {
        guid: local_guid,
        cert_der,
        key_pem: zeroize::Zeroizing::new(key_pem),
        ca_cert_pem,
    };

    let handshake_machine = security_suite.handshakes.clone();
    handshake_machine.set_local_identity(local_guid, &local_identity.cert_der)?;

    log::info!(
        "[security::secure_builtins] 12 secure builtin endpoints ready (announced bits = 0x{:08x}); stateless pump armed",
        crate::protocol::discovery::constants::BUILTIN_ENDPOINT_SET_SECURITY
    );

    Ok(SecureBuiltins {
        tunnels,
        stateless_channel,
        handshake_machine,
        local_identity,
        suite: security_suite.clone(),
    })
}

// Every test below exercises the secure builtin surface, which only exists
// under `feature = "security"`; the module follows its subject.
#[cfg(all(test, feature = "security"))]
mod tests {
    use super::*;

    /// The secure builtin endpoints announced are those served, under the
    /// bits DDS Security v1.1 Table 11 (Sec.7.4.1.4) gives them: SEDP secure
    /// 16-19, stateless 22-23, volatile 24-25. Not 20-21 (participant message
    /// secure) nor 26-27 (DCPSParticipantsSecure), whose general participant
    /// data updates are not served (only status changes are implemented), nor
    /// 28-29, which RTPS v2.5 Sec.9.3.2 gives to DCPSTopic.
    ///
    /// Asserting bit 28 as "PARTICIPANT_VOLATILE_SECURE_W" and bit 26 as set
    /// would defend a mask that sends peers to endpoints nobody reads and
    /// hides the volatile endpoints we do serve.
    #[test]
    fn the_secure_endpoints_announced_are_the_ones_served() {
        use crate::protocol::discovery::constants::BUILTIN_ENDPOINT_SET_SECURITY;
        let bit = |n: u32| BUILTIN_ENDPOINT_SET_SECURITY & (1 << n) != 0;
        for served in [16, 17, 18, 19, 22, 23, 24, 25] {
            assert!(bit(served), "bit {served} names an endpoint we serve");
        }
        for unserved in [20, 21, 26, 27, 28, 29] {
            assert!(
                !bit(unserved),
                "bit {unserved} names an endpoint nobody serves"
            );
        }
        assert_eq!(
            BUILTIN_ENDPOINT_SET_SECURITY & !0x0FFF_0000,
            0,
            "DDS-Security owns bits 16-27 and nothing else"
        );
    }

    #[test]
    fn entity_kind_bytes_per_spec() {
        // DDS Security v1.1 sec. 7.4.1.3: WITH_KEY tunnels use 0xC2 writers + 0xC7 readers,
        // NO_KEY tunnels use 0xC3 writers + 0xC4 readers.
        assert_eq!(RTPS_ENTITYID_SPDP_SECURE_WRITER[3], 0xC2);
        assert_eq!(RTPS_ENTITYID_SPDP_SECURE_READER[3], 0xC7);
        assert_eq!(
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER[3],
            0xC3
        );
        assert_eq!(
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER[3],
            0xC4
        );
        assert_eq!(
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER[3],
            0xC3
        );
        assert_eq!(
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER[3],
            0xC4
        );
    }

    #[test]
    fn vendor_secure_prefix_byte() {
        // 0xff vendor-secure namespace per DDS Security v1.1 sec. 7.4.1.3.
        assert_eq!(RTPS_ENTITYID_SPDP_SECURE_WRITER[0], 0xFF);
        assert_eq!(RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER[0], 0xFF);
        assert_eq!(RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER[0], 0xFF);
        assert_eq!(
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER[0],
            0xFF
        );
        assert_eq!(
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER[0],
            0xFF
        );
        // Stateless is the deliberate exception (plaintext handshake).
        assert_eq!(
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER[0],
            0x00
        );
        assert_eq!(
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER[0],
            0x00
        );
    }
    #[test]
    fn review_volatile_replay_guard_is_wired() {
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::volatile::WriterKeyAnnouncement;
        use crate::security::test_pki::*;
        use std::io::Write;
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        cert.write_all(TEST_IDENTITY_CERT_PEM).unwrap();
        key.write_all(TEST_IDENTITY_KEY_PEM).unwrap();
        ca.write_all(TEST_CA_CERT_PEM).unwrap();
        let config = crate::security::SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .enable_encryption(true)
            .build()
            .unwrap();
        let mut ours = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        ours.extend_from_slice(&[1; 6]);
        let ours: [u8; 12] = ours.try_into().unwrap();
        let mut peer = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        peer.extend_from_slice(&[2; 6]);
        let peer: [u8; 12] = peer.try_into().unwrap();
        let mut suite = SecurityPluginSuite::new(config, 0).unwrap();
        suite.handshakes = local_machine_with_completed_peer(ours, peer, None);
        let suite = Arc::new(suite);
        let builtins = setup_secure_builtins(ours, &suite).unwrap();
        let kx = suite.handshakes.volatile_key_material(&peer).unwrap();
        let (id, old) = WriterKey::mint().unwrap();
        let (_, new) = WriterKey::mint().unwrap();
        let writer = GUID::new(peer, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER);
        let remote_volatile = GUID::new(
            peer,
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        );
        let local_participant = GUID::new(ours, [0, 0, 1, 0xc1]);
        let envelope = |material: &WriterKey, sn| {
            WriterKeyAnnouncement {
                writer_guid: writer,
                key_id: u64::from(id),
                key: material.key.duplicate_for_store(),
                master_salt: material.salt.duplicate_for_store(),
                transformation: material.transformation,
            }
            .seal(
                &kx,
                &remote_volatile,
                &local_participant,
                // Builtin tunnels always know their peer's mirrored
                // reader: GUID_UNKNOWN is refused.
                GUID::new(ours, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER).as_bytes(),
                sn,
            )
            .unwrap()
        };
        let old_wire = envelope(&old, 1);
        let new_wire = envelope(&new, 2);
        assert!(builtins.dispatch_volatile(peer, &old_wire));
        assert!(builtins.dispatch_volatile(peer, &new_wire));
        assert!(
            !builtins.dispatch_volatile(peer, &old_wire),
            "old token envelope accepted after rekey"
        );
        // The same old message as a NEW change (writerSN 3, its
        // message_identity still 1): past the reliable reader, which
        // delivers it once in order, the guard refuses it.
        let old_message = {
            let decoded = crate::security::crypto::secure_submessage::decode_datawriter_submessage(
                &kx, &old_wire, 0,
            )
            .unwrap();
            crate::security::crypto::volatile::parse_data(&decoded.submessage)
                .unwrap()
                .payload
                .to_vec()
        };
        let relabelled =
            crate::security::crypto::volatile::protect_message(&kx, 3, &old_message).unwrap();
        let replays_before = suite.volatile_replay.replays_rejected();
        assert!(
            !builtins.dispatch_volatile(peer, &relabelled),
            "an old message identity under a new writerSN accepted after rekey"
        );
        assert_eq!(suite.volatile_replay.replays_rejected(), replays_before + 1);
        assert!(suite
            .data_keys
            .get_material(&writer, u64::from(id))
            .unwrap()
            .same_material(&new));
    }

    /// DDS Security v1.1 Sec.7.4.4.6.2 a
    /// DatawriterCryptoTokens whose `destination_endpoint_guid` names one of
    /// OUR local endpoints is only installed when it names the RIGHT one --
    /// the builtin tunnel's mirrored reader
    /// (`volatile::builtin_peer_entity_id`). GUID_UNKNOWN (no destination
    /// named) is still accepted unconditionally, as it always was for a
    /// plain USER writer's shared key.
    ///
    /// Mutant: dropping `destination_matches_ours` from `dispatch_volatile_
    /// with_material` would accept the misdirected envelope below exactly
    /// as readily as the correctly-addressed one -- the two assertions
    /// differ only in which GUID the SAME sender sealed for, so a missing
    /// check collapses them to the same (accepted) outcome.
    #[test]
    fn review_destination_endpoint_guid_mismatch_is_refused() {
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::volatile::WriterKeyAnnouncement;
        use crate::security::test_pki::*;
        use std::io::Write;
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        cert.write_all(TEST_IDENTITY_CERT_PEM).unwrap();
        key.write_all(TEST_IDENTITY_KEY_PEM).unwrap();
        ca.write_all(TEST_CA_CERT_PEM).unwrap();
        let config = crate::security::SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .enable_encryption(true)
            .build()
            .unwrap();
        let mut ours = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        ours.extend_from_slice(&[3; 6]);
        let ours: [u8; 12] = ours.try_into().unwrap();
        let mut peer = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        peer.extend_from_slice(&[4; 6]);
        let peer: [u8; 12] = peer.try_into().unwrap();
        let mut suite = SecurityPluginSuite::new(config, 0).unwrap();
        suite.handshakes = local_machine_with_completed_peer(ours, peer, None);
        let suite = Arc::new(suite);
        let builtins = setup_secure_builtins(ours, &suite).unwrap();
        let kx = suite.handshakes.volatile_key_material(&peer).unwrap();
        let (id, material) = WriterKey::mint().unwrap();
        let writer = GUID::new(peer, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER);
        let remote_volatile = GUID::new(
            peer,
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        );
        let local_participant = GUID::new(ours, [0, 0, 1, 0xc1]);
        let announcement = WriterKeyAnnouncement {
            writer_guid: writer,
            key_id: u64::from(id),
            key: material.key.duplicate_for_store(),
            master_salt: material.salt.duplicate_for_store(),
            transformation: material.transformation,
        };

        // Addressed to the wrong one of our endpoints (our SEDP
        // SUBSCRIPTIONS secure reader, not the publications one that
        // mirrors this writer): refused, nothing installed.
        let wrong_destination = GUID::new(ours, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER);
        let misdirected = announcement
            .seal(
                &kx,
                &remote_volatile,
                &local_participant,
                wrong_destination.as_bytes(),
                1,
            )
            .unwrap();
        assert!(
            !builtins.dispatch_volatile(peer, &misdirected),
            "a key addressed to another local endpoint must be refused"
        );
        assert!(suite
            .data_keys
            .get_material(&writer, u64::from(id))
            .is_none());

        // Addressed to the RIGHT one (the mirrored reader of this exact
        // tunnel): installed.
        let right_destination = GUID::new(ours, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER);
        let correctly_addressed = announcement
            .seal(
                &kx,
                &remote_volatile,
                &local_participant,
                right_destination.as_bytes(),
                2,
            )
            .unwrap();
        assert!(
            builtins.dispatch_volatile(peer, &correctly_addressed),
            "a key addressed to the matching local reader must be accepted"
        );
        assert!(suite
            .data_keys
            .get_material(&writer, u64::from(id))
            .unwrap()
            .same_material(&material));
    }

    /// A builtin announcement's `destination_endpoint_guid` of
    /// GUID_UNKNOWN is not accepted --
    /// the six builtin tunnels always know their peer's mirrored endpoint,
    /// so a sender that skips naming it is not making a legitimate
    /// one-key-many-readers choice (that's the USER-endpoint case), it is
    /// omitting information it always has.
    ///
    /// Also pins the USER-endpoint rule: GUID_UNKNOWN stays legitimate
    /// there (shared key, several matched peers); a NAMED destination must
    /// still be reachable -- this participant's own prefix, and the
    /// opposite entity kind from the one announced (a writer's token
    /// addresses a reader and vice versa). Naming another participant's
    /// prefix, or this participant's prefix under the SAME kind
    /// (writer-addresses-writer), is refused either way.
    #[test]
    fn review_destination_guid_rules_for_builtin_and_user_endpoints() {
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::volatile::{WriterKeyAnnouncement, GUID_UNKNOWN};
        use crate::security::test_pki::*;
        use std::io::Write;
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        cert.write_all(TEST_IDENTITY_CERT_PEM).unwrap();
        key.write_all(TEST_IDENTITY_KEY_PEM).unwrap();
        ca.write_all(TEST_CA_CERT_PEM).unwrap();
        let config = crate::security::SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .enable_encryption(true)
            .build()
            .unwrap();
        let mut ours = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        ours.extend_from_slice(&[5; 6]);
        let ours: [u8; 12] = ours.try_into().unwrap();
        let mut peer = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        peer.extend_from_slice(&[6; 6]);
        let peer: [u8; 12] = peer.try_into().unwrap();
        let mut suite = SecurityPluginSuite::new(config, 0).unwrap();
        suite.handshakes = local_machine_with_completed_peer(ours, peer, None);
        let suite = Arc::new(suite);
        let builtins = setup_secure_builtins(ours, &suite).unwrap();
        let kx = suite.handshakes.volatile_key_material(&peer).unwrap();
        let remote_volatile = GUID::new(
            peer,
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        );
        let local_participant = GUID::new(ours, [0, 0, 1, 0xc1]);
        let seal_for = |writer_guid: GUID, destination: [u8; 16], sn: i64| {
            let (id, material) = WriterKey::mint().unwrap();
            let wire = WriterKeyAnnouncement {
                writer_guid,
                key_id: u64::from(id),
                key: material.key.duplicate_for_store(),
                master_salt: material.salt.duplicate_for_store(),
                transformation: material.transformation,
            }
            .seal(&kx, &remote_volatile, &local_participant, destination, sn)
            .unwrap();
            (id, wire)
        };

        // Builtin writer, GUID_UNKNOWN: refused.
        let builtin_writer = GUID::new(peer, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER);
        let (builtin_id, builtin_unknown) = seal_for(builtin_writer, GUID_UNKNOWN, 1);
        assert!(
            !builtins.dispatch_volatile(peer, &builtin_unknown),
            "a builtin announcement naming no destination must be refused"
        );
        assert!(suite
            .data_keys
            .get_material(&builtin_writer, u64::from(builtin_id))
            .is_none());

        // User writer, GUID_UNKNOWN: refused -- Sec.7.4.4.6.2 names the
        // matched reader, however many readers share the key.
        let user_writer = GUID::new(peer, [0, 1, 2, 0x02]);
        let (user_id, user_unknown) = seal_for(user_writer, GUID_UNKNOWN, 2);
        assert!(
            !builtins.dispatch_volatile(peer, &user_unknown),
            "a user writer's key with no named destination is refused"
        );
        assert!(suite
            .data_keys
            .get_material(&user_writer, u64::from(user_id))
            .is_none());

        // User writer naming ANOTHER participant's reader: refused.
        let foreign_prefix = [0x77; 12];
        let foreign_reader = GUID::new(foreign_prefix, [0, 1, 2, 0x07]);
        let (user_id2, user_foreign) = seal_for(user_writer, foreign_reader.as_bytes(), 3);
        assert!(
            !builtins.dispatch_volatile(peer, &user_foreign),
            "a user writer's key addressed to ANOTHER participant's endpoint must be refused"
        );
        assert!(suite
            .data_keys
            .get_material(&user_writer, u64::from(user_id2))
            .is_none());

        // User writer naming one of OUR endpoints, but a WRITER (same
        // kind, not the opposite direction a writer's token should
        // address): refused.
        let our_other_writer = GUID::new(ours, [0, 1, 3, 0x02]);
        let (user_id3, user_wrong_kind) = seal_for(user_writer, our_other_writer.as_bytes(), 4);
        assert!(
            !builtins.dispatch_volatile(peer, &user_wrong_kind),
            "a writer's key addressed to another WRITER (same kind) must be refused"
        );
        assert!(suite
            .data_keys
            .get_material(&user_writer, u64::from(user_id3))
            .is_none());

        // User writer naming a reader of ours by its kind and prefix that
        // is no endpoint here (this participant has no match registry at
        // all): refused -- the destination must be a REAL local endpoint
        // matched with the writer (`user_tokens_must_name_a_local_reader_
        // matched_with_their_writer` covers the accepted case).
        let our_reader = GUID::new(ours, [0, 1, 3, 0x07]);
        let (user_id4, user_right_kind) = seal_for(user_writer, our_reader.as_bytes(), 5);
        assert!(
            !builtins.dispatch_volatile(peer, &user_right_kind),
            "a writer's key addressed to no endpoint of ours must be refused"
        );
        assert!(suite
            .data_keys
            .get_material(&user_writer, u64::from(user_id4))
            .is_none());
    }

    /// A user-reader announcement addressed to our participant entity
    /// `00 00 01 c1` must be refused, not accepted because 'not a reader'
    /// is treated as 'writer'. The participant entity id is neither a
    /// reader nor a writer (`is_reader_entity_id`'s own doc), so a binary
    /// `is_reader_entity_id(x) != is_reader_entity_id(y)` check would
    /// accept it as if it were the opposite kind of whatever was
    /// announced. The check therefore requires the EXPLICIT opposite kind
    /// (`is_writer_entity_id` alongside `is_reader_entity_id`).
    ///
    /// Mutant: reverting `destination_matches_ours`'s `None` arm to
    /// `is_reader_entity_id(announced) != is_reader_entity_id(destination)`
    /// makes this test's assertion fail (accepted instead of refused).
    #[test]
    fn a_user_readers_announcement_to_the_participant_entity_is_refused() {
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::volatile::WriterKeyAnnouncement;
        use crate::security::test_pki::*;
        use std::io::Write;
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        cert.write_all(TEST_IDENTITY_CERT_PEM).unwrap();
        key.write_all(TEST_IDENTITY_KEY_PEM).unwrap();
        ca.write_all(TEST_CA_CERT_PEM).unwrap();
        let config = crate::security::SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .enable_encryption(true)
            .build()
            .unwrap();
        let mut ours = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        ours.extend_from_slice(&[7; 6]);
        let ours: [u8; 12] = ours.try_into().unwrap();
        let mut peer = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        peer.extend_from_slice(&[8; 6]);
        let peer: [u8; 12] = peer.try_into().unwrap();
        let mut suite = SecurityPluginSuite::new(config, 0).unwrap();
        suite.handshakes = local_machine_with_completed_peer(ours, peer, None);
        let suite = Arc::new(suite);
        let builtins = setup_secure_builtins(ours, &suite).unwrap();
        let kx = suite.handshakes.volatile_key_material(&peer).unwrap();
        let remote_volatile = GUID::new(
            peer,
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        );
        let local_participant = GUID::new(ours, [0, 0, 1, 0xc1]);

        // A USER READER announcement (the opposite kind IS a writer, not
        // "anything that is not a reader"), addressed to OUR participant
        // entity id -- neither a reader nor a writer.
        let user_reader = GUID::new(peer, [0, 1, 2, 0x07]);
        let our_participant_entity = GUID::new(ours, [0, 0, 1, 0xc1]);
        let (id, material) = WriterKey::mint().unwrap();
        let wire = WriterKeyAnnouncement {
            writer_guid: user_reader,
            key_id: u64::from(id),
            key: material.key.duplicate_for_store(),
            master_salt: material.salt.duplicate_for_store(),
            transformation: material.transformation,
        }
        .seal(
            &kx,
            &remote_volatile,
            &local_participant,
            our_participant_entity.as_bytes(),
            1,
        )
        .unwrap();

        assert!(
            !builtins.dispatch_volatile(peer, &wire),
            "the participant entity id is neither a reader nor a writer: it must not pass as \
             \"the opposite kind\" of a user reader's own announcement"
        );
        assert!(suite
            .data_keys
            .get_material(&user_reader, u64::from(id))
            .is_none());
    }

    /// A stand-in for the match registry: each local endpoint, and what it
    /// is matched with.
    #[derive(Default)]
    struct Endpoints(parking_lot::Mutex<std::collections::HashMap<GUID, Vec<GUID>>>);

    impl crate::security::volatile_channel::LocalEndpoints for Arc<Endpoints> {
        fn matched_with(&self, local: &GUID) -> Option<Vec<GUID>> {
            self.0.lock().get(local).cloned()
        }
    }

    /// A participant `ours` with a completed handshake with `peer`, its
    /// secure builtins, and the match registry stand-in it reads.
    struct UserFixture {
        suite: Arc<SecurityPluginSuite>,
        builtins: SecureBuiltins,
        endpoints: Arc<Endpoints>,
        ours: [u8; 12],
        peer: [u8; 12],
        _files: Vec<tempfile::NamedTempFile>,
    }

    fn user_fixture(seed: u8) -> UserFixture {
        use crate::security::test_pki::*;
        use std::io::Write;
        let mut files = Vec::new();
        for pem in [
            TEST_IDENTITY_CERT_PEM,
            TEST_IDENTITY_KEY_PEM,
            TEST_CA_CERT_PEM,
        ] {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            f.write_all(pem).unwrap();
            files.push(f);
        }
        let config = crate::security::SecurityConfig::builder()
            .identity_certificate(files[0].path())
            .private_key(files[1].path())
            .ca_certificates(files[2].path())
            .enable_encryption(true)
            .build()
            .unwrap();
        let mut ours = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        ours.extend_from_slice(&[seed; 6]);
        let ours: [u8; 12] = ours.try_into().unwrap();
        let mut peer = TEST_IDENTITY_PREFIX_HEAD.to_vec();
        peer.extend_from_slice(&[seed + 1; 6]);
        let peer: [u8; 12] = peer.try_into().unwrap();
        let mut suite = SecurityPluginSuite::new(config, 0).unwrap();
        suite.handshakes = local_machine_with_completed_peer(ours, peer, None);
        let suite = Arc::new(suite);
        let builtins = setup_secure_builtins(ours, &suite).unwrap();
        let endpoints = Arc::new(Endpoints::default());
        suite
            .volatile
            .set_local_endpoints(Box::new(Arc::clone(&endpoints)));
        UserFixture {
            suite,
            builtins,
            endpoints,
            ours,
            peer,
            _files: files,
        }
    }

    impl UserFixture {
        /// A DatawriterCryptoTokens of the peer's writer `writer`, addressed
        /// to `destination`, as change `sn` of its volatile writer.
        fn writer_tokens(&self, writer: GUID, destination: [u8; 16], sn: i64) -> (u32, Vec<u8>) {
            use crate::security::crypto::data_keys::WriterKey;
            use crate::security::crypto::volatile::WriterKeyAnnouncement;
            let kx = self
                .suite
                .handshakes
                .volatile_key_material(&self.peer)
                .unwrap();
            let (id, material) = WriterKey::mint().unwrap();
            let wire = WriterKeyAnnouncement {
                writer_guid: writer,
                key_id: u64::from(id),
                key: material.key.duplicate_for_store(),
                master_salt: material.salt.duplicate_for_store(),
                transformation: material.transformation,
            }
            .seal(
                &kx,
                &GUID::new(
                    self.peer,
                    RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
                ),
                &GUID::new(self.ours, [0, 0, 1, 0xc1]),
                destination,
                sn,
            )
            .unwrap();
            (id, wire)
        }

        fn retry(&self, now: std::time::Instant) -> usize {
            self.suite
                .volatile
                .retry_pending(&self.suite.data_keys, &self.suite.handshakes, now)
        }

        /// Drive the production reader with a protected heartbeat and read
        /// the requested sequence numbers from its protected ACKNACK.
        fn acknowledgement(&self, count: u32) -> (i64, Vec<i64>) {
            self.acknowledgement_through(count, 1)
        }

        fn acknowledgement_through(&self, count: u32, last: u64) -> (i64, Vec<i64>) {
            use crate::security::crypto::secure_submessage::{
                decode_datawriter_submessage, encode_datawriter_submessage, first_secure_prefix,
            };
            use crate::security::volatile_channel::{parse_control, Control};
            let kx = self
                .suite
                .handshakes
                .volatile_key_material(&self.peer)
                .unwrap();
            let heartbeat = crate::protocol::rtps::encode_heartbeat(
                &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
                &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
                1,
                last,
                count,
            )
            .unwrap();
            let wire = encode_datawriter_submessage(&kx, &heartbeat).unwrap();
            let VolatileOutcome::Opened(receipt) =
                self.builtins.receive_volatile(self.peer, &wire, 0)
            else {
                panic!("heartbeat must open")
            };
            let reply = &receipt.replies[0];
            let decoded =
                decode_datawriter_submessage(&kx, reply, first_secure_prefix(reply).unwrap())
                    .unwrap();
            match parse_control(&decoded.submessage).unwrap() {
                Control::AckNack {
                    base, requested, ..
                } => (base, requested),
                other => panic!("expected ACKNACK, got {other:?}"),
            }
        }

        fn installed(&self, writer: &GUID, id: u32) -> bool {
            self.suite
                .data_keys
                .get_material(writer, u64::from(id))
                .is_some()
        }
    }

    /// DDS Security v1.1 Sec.9.5.2.1.2, Table 67: both ends of a pair seal
    /// their volatile channel with the same KxKeys, so what this participant
    /// sealed for the peer opens here as well. Sent back under the peer's
    /// prefix, our own ACKNACK must not be read as the peer's reader
    /// acknowledging our writer: it is dropped, and counted apart from what
    /// did not open. The peer's own submessages still open.
    ///
    /// Mutant: without the SessionId check in `receive_volatile`, the
    /// reflected ACKNACK opens.
    #[test]
    fn our_own_volatile_submessage_sent_back_is_dropped() {
        use crate::security::crypto::secure_submessage::first_secure_prefix;
        let f = user_fixture(0x61);
        let kx = f.suite.handshakes.volatile_key_material(&f.peer).unwrap();
        let heartbeat = crate::protocol::rtps::encode_heartbeat(
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
            1,
            1,
            1,
        )
        .unwrap();
        let wire = crate::security::crypto::secure_submessage::encode_datawriter_submessage(
            &kx, &heartbeat,
        )
        .unwrap();
        let VolatileOutcome::Opened(receipt) = f.builtins.receive_volatile(f.peer, &wire, 0) else {
            panic!("the peer's heartbeat opens")
        };
        let our_acknack = &receipt.replies[0];
        let at = first_secure_prefix(our_acknack).expect("our ACKNACK is protected");

        let undecodable_before = f.suite.volatile.stats.undecodable();
        assert!(matches!(
            f.builtins.receive_volatile(f.peer, our_acknack, at),
            VolatileOutcome::Reflected
        ));
        assert_eq!(f.suite.volatile.stats.reflection_refused(), 1);
        assert_eq!(f.suite.volatile.stats.undecodable(), undecodable_before);

        let heartbeat = crate::protocol::rtps::encode_heartbeat(
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
            1,
            1,
            2,
        )
        .unwrap();
        let wire = crate::security::crypto::secure_submessage::encode_datawriter_submessage(
            &kx, &heartbeat,
        )
        .unwrap();
        assert!(matches!(
            f.builtins.receive_volatile(f.peer, &wire, 0),
            VolatileOutcome::Opened(_)
        ));
    }

    /// DDS Security v1.1 Sec.7.4.4.6.2: a USER DataWriter's tokens name the
    /// DataReader that should receive them. On receipt the destination must
    /// be an endpoint of this participant, a reader, matched with the
    /// writer; GUID_UNKNOWN, an endpoint that does not exist here, or one
    /// not of the right kind is refused, and counted.
    ///
    /// Mutant: `user_addressing` answering `Matched` for an endpoint the
    /// registry does not know (`None`) installs the fourth key.
    #[test]
    fn user_tokens_must_name_a_local_reader_matched_with_their_writer() {
        let f = user_fixture(0x31);
        let writer = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let our_reader = GUID::new(f.ours, [0, 1, 3, 0x07]);
        let not_ours = GUID::new(f.ours, [0, 1, 9, 0x07]);
        f.endpoints.0.lock().insert(our_reader, vec![writer]);

        let cases: [(&str, [u8; 16]); 4] = [
            ("GUID_UNKNOWN", [0; 16]),
            (
                "another participant's reader",
                GUID::new([0x77; 12], [0, 1, 3, 0x07]).as_bytes(),
            ),
            (
                "one of our writers",
                GUID::new(f.ours, [0, 1, 3, 0x02]).as_bytes(),
            ),
            ("a reader that does not exist here", not_ours.as_bytes()),
        ];
        for (sn, (what, destination)) in (1..).zip(cases) {
            let (id, wire) = f.writer_tokens(writer, destination, sn);
            assert!(!f.builtins.dispatch_volatile(f.peer, &wire), "{what}");
            assert!(!f.installed(&writer, id), "{what}: nothing installed");
        }
        assert_eq!(f.suite.volatile.stats.misaddressed_endpoint_refused(), 4);
        assert_eq!(f.suite.volatile.pending(), 0, "none of them is held");

        let (id, wire) = f.writer_tokens(writer, our_reader.as_bytes(), 5);
        assert!(
            f.builtins.dispatch_volatile(f.peer, &wire),
            "addressed to our reader matched with the writer"
        );
        assert!(f.installed(&writer, id));
    }

    /// The tokens are written once the SENDER matched the destination; this
    /// participant matches the sender's endpoint on its own discovery,
    /// which can come second. Tokens addressed to a real local reader of the
    /// right kind not matched with the writer yet are held, and installed
    /// when the match comes.
    ///
    /// Mutant: `NotYetMatched` treated as `Refused` never installs the key.
    #[test]
    fn user_tokens_for_a_reader_not_matched_yet_are_installed_when_it_matches() {
        let f = user_fixture(0x41);
        let writer = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let our_reader = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(our_reader, vec![]);

        let (id, wire) = f.writer_tokens(writer, our_reader.as_bytes(), 1);
        assert!(!f.builtins.dispatch_volatile(f.peer, &wire));
        assert!(!f.installed(&writer, id), "not before the match");
        assert_eq!(f.suite.volatile.pending(), 1, "held");

        let now = std::time::Instant::now();
        assert_eq!(
            f.suite
                .volatile
                .retry_pending(&f.suite.data_keys, &f.suite.handshakes, now),
            0
        );
        f.endpoints.0.lock().insert(our_reader, vec![writer]);
        assert_eq!(
            f.suite
                .volatile
                .retry_pending(&f.suite.data_keys, &f.suite.handshakes, now),
            1
        );
        assert!(f.installed(&writer, id), "installed once matched");
        assert_eq!(f.suite.volatile.pending(), 0);
        assert_eq!(f.suite.volatile.stats.misaddressed_endpoint_refused(), 0);
    }

    /// Held tokens whose match does not come in time are refused and
    /// counted, not kept forever (`PENDING_MATCH_TIMEOUT`).
    ///
    /// Mutant: `retry_pending` never expiring a held entry keeps it held.
    #[test]
    fn user_tokens_held_past_their_deadline_are_refused_and_counted() {
        use crate::security::volatile_channel::PENDING_MATCH_TIMEOUT;
        let f = user_fixture(0x51);
        let writer = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let our_reader = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(our_reader, vec![]);
        let (id, wire) = f.writer_tokens(writer, our_reader.as_bytes(), 1);
        assert!(!f.builtins.dispatch_volatile(f.peer, &wire));
        assert_eq!(f.suite.volatile.pending(), 1);

        let later = std::time::Instant::now() + PENDING_MATCH_TIMEOUT;
        assert_eq!(
            f.suite
                .volatile
                .retry_pending(&f.suite.data_keys, &f.suite.handshakes, later),
            0
        );
        assert_eq!(f.suite.volatile.pending(), 0);
        assert_eq!(f.suite.volatile.stats.pending_expired(), 1);
        f.endpoints.0.lock().insert(our_reader, vec![writer]);
        assert_eq!(
            f.suite
                .volatile
                .retry_pending(&f.suite.data_keys, &f.suite.handshakes, later),
            0
        );
        assert!(
            !f.installed(&writer, id),
            "a match after the deadline installs nothing"
        );
    }
    /// DDS Security 7.4.4.2 and RTPS 8.4.12.2: resource refusal cannot
    /// acknowledge a change whose material cannot be installed or held.
    #[test]
    fn saturated_tokens_are_repaired_after_the_match() {
        use crate::security::crypto::secure_submessage::{
            first_secure_prefix, first_secure_prefix_from,
        };
        use crate::security::volatile_channel::{VolatileStats, WriterState, MAX_PENDING_PER_PEER};
        let f = user_fixture(0x61);
        let destination = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(destination, vec![]);
        let kx = f.suite.handshakes.volatile_key_material(&f.peer).unwrap();
        let now = std::time::Instant::now();
        let mut writer = WriterState::default();
        let mut tokens = Vec::new();
        let total = MAX_PENDING_PER_PEER as i64 + 1;
        for sn in 1..=total {
            let source = GUID::new(f.peer, [0, 1, sn as u8, 0x02]);
            let (id, wire) = f.writer_tokens(source, destination.as_bytes(), sn);
            writer
                .write(&f.peer, f.ours, &kx, now, |assigned| {
                    assert_eq!(assigned, sn);
                    Ok(wire.clone())
                })
                .unwrap();
            assert!(!f.builtins.dispatch_volatile(f.peer, &wire));
            tokens.push((source, id));
        }
        assert_eq!(f.suite.volatile.pending(), MAX_PENDING_PER_PEER);
        let (base, requested) = f.acknowledgement_through(1, total as u64);
        assert_eq!(
            (base, requested.clone()),
            (1, (1..=total).collect()),
            "held and refused DATA stay missing"
        );
        let stats = VolatileStats::default();
        let repairs = writer.on_acknack(&f.peer, f.ours, &kx, now, base, &requested, 1, &stats);
        assert_eq!(writer.unacked(&f.ours), total as usize);
        f.endpoints.0.lock().insert(
            destination,
            tokens.iter().map(|(source, _)| *source).collect(),
        );
        for packet in repairs {
            let mut at = first_secure_prefix(&packet);
            while let Some(prefix) = at {
                let VolatileOutcome::Opened(receipt) =
                    f.builtins.receive_volatile(f.peer, &packet, prefix)
                else {
                    panic!("repair must open")
                };
                at = first_secure_prefix_from(&packet, receipt.end);
            }
        }
        assert!(tokens.iter().all(|(source, id)| f.installed(source, *id)));
        let (base, requested) = f.acknowledgement_through(100, total as u64);
        assert_eq!((base, requested.clone()), (total + 1, vec![]));
        writer.on_acknack(&f.peer, f.ours, &kx, now, base, &requested, 2, &stats);
        assert_eq!(writer.unacked(&f.ours), 0, "purged only after installation");
        // Already installed copies are removed before expiry accounting.
        assert_eq!(f.retry(now + std::time::Duration::from_secs(31)), 0);
        assert_eq!(f.suite.volatile.pending(), 0);
        assert_eq!(f.suite.volatile.stats.pending_expired(), 0);
        assert_eq!(f.suite.volatile_replay.replays_rejected(), 0);
    }

    /// Reception and token installation are separate: an expired hold is
    /// consumed with a refusal, and a later match needs a fresh identity
    /// (DDS Security 7.4.4.2, 8.5.1.8.3; RTPS 8.4.12.2).
    #[test]
    fn expired_tokens_are_consumed_and_a_new_match_identity_can_install() {
        use crate::security::volatile_channel::PENDING_MATCH_TIMEOUT;
        let f = user_fixture(0x71);
        let source = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let destination = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(destination, vec![]);
        let (id, wire) = f.writer_tokens(source, destination.as_bytes(), 1);
        assert!(!f.builtins.dispatch_volatile(f.peer, &wire));
        assert_eq!(
            f.acknowledgement(1),
            (1, vec![1]),
            "held is not acknowledged"
        );
        f.endpoints.0.lock().insert(destination, vec![source]);
        assert_eq!(
            f.retry(std::time::Instant::now() + PENDING_MATCH_TIMEOUT),
            0
        );
        assert_eq!(f.suite.volatile.pending(), 0);
        assert_eq!(f.suite.volatile.stats.pending_expired(), 1);
        assert!(!f.installed(&source, id), "expiry precedes the match check");
        assert_eq!(f.acknowledgement(2), (2, vec![]));
        assert!(
            !f.builtins.dispatch_volatile(f.peer, &wire),
            "consumed DATA stays consumed"
        );
        assert!(!f.installed(&source, id));
        use crate::security::crypto::secure_submessage::decode_datawriter_submessage;
        use crate::security::crypto::volatile::{
            decode_message, parse_data, WriterKeyAnnouncement,
        };
        let kx = f.suite.handshakes.volatile_key_material(&f.peer).unwrap();
        let opened = decode_datawriter_submessage(&kx, &wire, 0).unwrap();
        let message = decode_message(parse_data(&opened.submessage).unwrap().payload).unwrap();
        let tokens = WriterKeyAnnouncement::from_message(&message).unwrap();
        let new_wire = tokens
            .seal(
                &kx,
                &GUID::new(
                    f.peer,
                    RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
                ),
                &GUID::new(f.ours, [0, 0, 1, 0xc1]),
                destination.as_bytes(),
                2,
            )
            .unwrap();
        assert!(f.builtins.dispatch_volatile(f.peer, &new_wire));
        assert!(
            f.installed(&source, id),
            "fresh identity installs unchanged material"
        );
        assert_eq!(f.acknowledgement_through(3, 2), (3, vec![]));
    }

    /// Deferred material is bound to the active authentication generation,
    /// even before a packet from that generation resets the reader.
    #[test]
    fn deferred_tokens_from_an_old_session_are_discarded_on_retry() {
        let f = user_fixture(0x81);
        let source = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let destination = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(destination, vec![]);
        let old_session = f
            .suite
            .handshakes
            .volatile_key_material(&f.peer)
            .unwrap()
            .fingerprint();
        let (old_id, old_wire) = f.writer_tokens(source, destination.as_bytes(), 1);
        assert!(!f.builtins.dispatch_volatile(f.peer, &old_wire));
        let retry_at = std::time::Instant::now();
        let new_machine =
            crate::security::test_pki::local_machine_with_completed_peer(f.ours, f.peer, None);
        assert_ne!(
            new_machine
                .volatile_key_material(&f.peer)
                .unwrap()
                .fingerprint(),
            old_session
        );
        f.endpoints.0.lock().insert(destination, vec![source]);
        assert_eq!(
            f.suite
                .volatile
                .retry_pending(&f.suite.data_keys, &new_machine, retry_at),
            0
        );
        assert_eq!(f.suite.volatile.pending(), 0);
        assert!(!f.installed(&source, old_id));
    }

    /// The receive transition clears deferred material before accepting
    /// messages under a different Kx fingerprint, with its own identities.
    #[test]
    fn deferred_tokens_are_cleared_when_the_reader_changes_session() {
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::volatile_channel::{PendingTokens, PENDING_MATCH_TIMEOUT};
        let f = user_fixture(0x83);
        let source = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let destination = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(destination, vec![source]);
        let (stale_id, stale_key) = WriterKey::mint().unwrap();
        assert!(f.suite.volatile.hold(PendingTokens {
            peer: f.peer,
            session: [0x55; 32],
            order: 1,
            writer_sn: 1,
            source,
            destination,
            key_id: stale_id.into(),
            key: stale_key,
            deadline: std::time::Instant::now() + PENDING_MATCH_TIMEOUT,
        }));
        f.suite
            .volatile
            .reader
            .lock()
            .start_session(f.peer, [0x55; 32]);
        f.suite.volatile_replay.accept(f.peer, 99);
        let (new_id, new_wire) = f.writer_tokens(source, destination.as_bytes(), 1);
        assert!(f.builtins.dispatch_volatile(f.peer, &new_wire));
        assert_eq!(f.suite.volatile.pending(), 0);
        assert!(f.installed(&source, new_id));
        assert!(!f.installed(&source, stale_id));
    }

    /// Message identity ordering also applies to deferred installation:
    /// an older deferred identity cannot replace newer endpoint material.
    #[test]
    fn deferred_tokens_cannot_replace_a_newer_installed_identity() {
        let f = user_fixture(0x85);
        let source = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let destination = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(destination, vec![]);
        let (stale_id, stale_wire) = f.writer_tokens(source, destination.as_bytes(), 1);
        assert!(!f.builtins.dispatch_volatile(f.peer, &stale_wire));
        f.endpoints.0.lock().insert(destination, vec![source]);
        let (new_id, new_wire) = f.writer_tokens(source, destination.as_bytes(), 2);
        assert!(f.builtins.dispatch_volatile(f.peer, &new_wire));
        assert!(
            !f.builtins.dispatch_volatile(f.peer, &stale_wire),
            "older repair is consumed without rollback"
        );
        assert_eq!(f.retry(std::time::Instant::now()), 0);
        assert!(!f.installed(&source, stale_id));
        assert!(
            f.installed(&source, new_id),
            "deferred material cannot roll the key back"
        );
        assert_eq!(f.suite.volatile.pending(), 0);
        assert_eq!(f.acknowledgement_through(1, 2), (3, vec![]));
    }

    /// A user match must not prevent later builtin keys from reaching the
    /// discovery path that establishes that match. Successful retry marks
    /// the original DATA received without miscounting its repair as replay.
    #[test]
    fn deferred_user_tokens_allow_later_builtin_keys_and_acknowledge_on_retry() {
        let f = user_fixture(0x87);
        let source = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let destination = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(destination, vec![]);
        let (id, wire) = f.writer_tokens(source, destination.as_bytes(), 1);
        assert!(!f.builtins.dispatch_volatile(f.peer, &wire));
        let builtin = GUID::new(f.peer, RTPS_ENTITYID_SPDP_SECURE_WRITER);
        let mirror = GUID::new(f.ours, RTPS_ENTITYID_SPDP_SECURE_READER);
        let (builtin_id, builtin_wire) = f.writer_tokens(builtin, mirror.as_bytes(), 2);
        assert!(f.builtins.dispatch_volatile(f.peer, &builtin_wire));
        assert!(f.installed(&builtin, builtin_id));
        assert_eq!(f.acknowledgement_through(1, 2), (1, vec![1]));
        f.endpoints.0.lock().insert(destination, vec![source]);
        assert_eq!(f.retry(std::time::Instant::now()), 1);
        assert!(
            f.installed(&source, id),
            "a newer identity for another endpoint cannot suppress these tokens"
        );
        assert_eq!(f.acknowledgement_through(2, 2), (3, vec![]));
        assert!(!f.builtins.dispatch_volatile(f.peer, &wire));
        assert_eq!(f.suite.volatile_replay.replays_rejected(), 0);
    }
    /// A SEDP dispose/unregister can precede discovery of the source. It
    /// still terminates the token's application hold (7.4.4.6.2).
    #[test]
    fn source_deleted_before_match_consumes_its_held_tokens() {
        use crate::core::discovery::multicast::DiscoveryFsm;
        let f = user_fixture(0x89);
        let source = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let destination = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(destination, vec![]);
        let (id, wire) = f.writer_tokens(source, destination.as_bytes(), 1);
        assert!(!f.builtins.dispatch_volatile(f.peer, &wire));
        assert_eq!(f.acknowledgement(1), (1, vec![1]));
        let mut discovery = DiscoveryFsm::new(GUID::new(f.ours, [0, 0, 1, 0xc1]), 30_000);
        discovery.set_volatile_suite(&f.suite);
        // Production SEDP lifecycle path, including a not-yet-known source.
        discovery.remove_remote_endpoint(source);
        assert_eq!(f.suite.volatile.pending(), 0);
        assert_eq!(f.suite.volatile.stats.pending_source_removed(), 1);
        assert_eq!(f.acknowledgement(2), (2, vec![]));
        assert!(!f.builtins.dispatch_volatile(f.peer, &wire));
        assert!(!f.installed(&source, id));
    }

    /// A remote endpoint that announced its deletion (a SEDP dispose or
    /// unregister) takes the key material its CryptoTokens installed with
    /// it: nothing it sends after its deletion opens here, and what each
    /// deleted endpoint held does not stay for as long as its participant
    /// lives. Another endpoint of the same participant keeps its own.
    #[test]
    fn a_deleted_remote_endpoints_key_material_goes_with_it() {
        use crate::core::discovery::multicast::DiscoveryFsm;
        let f = user_fixture(0x8d);
        let source = GUID::new(f.peer, [0, 1, 2, 0x02]);
        let other = GUID::new(f.peer, [0, 1, 4, 0x02]);
        let destination = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints
            .0
            .lock()
            .insert(destination, vec![source, other]);
        let (id, wire) = f.writer_tokens(source, destination.as_bytes(), 1);
        assert!(f.builtins.dispatch_volatile(f.peer, &wire));
        let (other_id, other_wire) = f.writer_tokens(other, destination.as_bytes(), 2);
        assert!(f.builtins.dispatch_volatile(f.peer, &other_wire));
        assert!(f.installed(&source, id) && f.installed(&other, other_id));

        let mut discovery = DiscoveryFsm::new(GUID::new(f.ours, [0, 0, 1, 0xc1]), 30_000);
        discovery.set_volatile_suite(&f.suite);
        discovery.remove_remote_endpoint(source);

        assert!(
            !f.installed(&source, id),
            "the deleted endpoint's key still opens its data"
        );
        assert!(f.installed(&other, other_id), "another endpoint's key went");
    }

    /// A bounded application deferral must release the reliable window,
    /// including DATA for which the hold queue had no space (7.4.4.2,
    /// RTPS 8.4.12.2). A new builtin key must then cross the same session.
    #[test]
    fn deferred_window_overflow_expires_and_a_new_builtin_key_is_distributed() {
        use crate::security::volatile_channel::{
            VolatileStats, WriteRefusal, WriterState, MAX_PENDING_PER_PEER, MAX_UNACKED_PER_READER,
            PENDING_MATCH_TIMEOUT,
        };
        let f = user_fixture(0x8b);
        let destination = GUID::new(f.ours, [0, 1, 3, 0x07]);
        f.endpoints.0.lock().insert(destination, vec![]);
        let kx = f.suite.handshakes.volatile_key_material(&f.peer).unwrap();
        let now = std::time::Instant::now();
        let mut writer = WriterState::default();
        let total = MAX_UNACKED_PER_READER as i64;
        for sn in 1..=total {
            let bytes = (sn as u32).to_be_bytes();
            let source = GUID::new(f.peer, [bytes[1], bytes[2], bytes[3], 0x02]);
            let (_, wire) = f.writer_tokens(source, destination.as_bytes(), sn);
            writer
                .write(&f.peer, f.ours, &kx, now, |assigned| {
                    assert_eq!(assigned, sn);
                    Ok(wire.clone())
                })
                .unwrap();
            assert!(!f.builtins.dispatch_volatile(f.peer, &wire));
        }
        assert_eq!(f.suite.volatile.pending(), MAX_PENDING_PER_PEER);
        let builtin = GUID::new(f.peer, RTPS_ENTITYID_SPDP_SECURE_WRITER);
        let mirror = GUID::new(f.ours, RTPS_ENTITYID_SPDP_SECURE_READER);
        let (id, wire) = f.writer_tokens(builtin, mirror.as_bytes(), total + 1);
        assert!(matches!(
            writer.write(&f.peer, f.ours, &kx, now, |_| Ok(wire.clone())),
            Err(WriteRefusal::Full)
        ));
        let (base, requested) = f.acknowledgement_through(1, total as u64);
        assert_eq!((base, requested), (1, (1..=total).collect()));
        let later = std::time::Instant::now() + PENDING_MATCH_TIMEOUT;
        assert_eq!(f.retry(later), 0);
        assert_eq!(f.suite.volatile.pending(), 0);
        assert_eq!(
            f.suite.volatile.stats.pending_expired(),
            total as u64,
            "both held and capacity-refused DATA have a terminal exit"
        );
        let (base, requested) = f.acknowledgement_through(2, total as u64);
        assert_eq!((base, requested.clone()), (total + 1, vec![]));
        writer.on_acknack(
            &f.peer,
            f.ours,
            &kx,
            later,
            base,
            &requested,
            1,
            &VolatileStats::default(),
        );
        assert_eq!(writer.unacked(&f.ours), 0);
        writer
            .write(&f.peer, f.ours, &kx, later, |assigned| {
                assert_eq!(assigned, total + 1);
                Ok(wire.clone())
            })
            .unwrap();
        assert!(f.builtins.dispatch_volatile(f.peer, &wire));
        assert!(f.installed(&builtin, id));
        let (base, requested) = f.acknowledgement_through(3, total as u64 + 1);
        assert_eq!((base, requested.clone()), (total + 2, vec![]));
        writer.on_acknack(
            &f.peer,
            f.ours,
            &kx,
            later,
            base,
            &requested,
            2,
            &VolatileStats::default(),
        );
        assert_eq!(writer.unacked(&f.ours), 0);
    }
}
