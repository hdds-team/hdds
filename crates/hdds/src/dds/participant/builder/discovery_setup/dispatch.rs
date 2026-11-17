// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Where a received discovery datagram goes.
//!
//! The decision is a value (`DiscoveryDispatch`) rather than a closure inside
//! `setup_discovery` capturing a long list of clones (the `DiscoveryFsm`, the
//! `TopicRegistry`, the dialect detector, the type-lookup handle, ...). A test
//! can therefore build one without building a whole participant, hand it a
//! datagram, and read what the FSM did; that is how the rule that a fragment
//! goes to reassembly WHATEVER kind its writer gives it (so that no
//! half-participant is registered from half an announcement) is pinned.
//!
//! The order of the two questions is the point and it is not an accident.
//! The classifier answers "what KIND" by looking at the WRITER of the
//! submessage, and a builtin writer's fragment is therefore named SPDP or
//! SEDP, not DataFrag. So asking the kind first sends a fragment to a parser
//! that reads it as a complete announcement. The SHAPE is asked first:
//! fragment metadata is published exactly when the classifier read a
//! DATA_FRAG (0x16), and that is the only question whose answer does not
//! depend on who sent it.

use std::sync::Arc;

use parking_lot::Mutex;

use super::fragment_handler::{handle_fragment, FragmentContext};
use super::heartbeat_handler::handle_heartbeat_packet;
use super::sedp_handler::handle_sedp_packet;
use super::spdp_handler::handle_spdp_packet;
use super::type_lookup_handler::handle_type_lookup_packet;
use super::SpdpSecurityTokens;

use super::super::entity_registry::SedpAnnouncementsCache;
use crate::core::discovery::multicast::{
    DiscoveryFsm, FragmentMetadata, Origin, PacketKind, SedpChannel,
};
use crate::core::discovery::{FragmentBuffer, SpdpPeerSet};
use crate::core::reader::ReaderProxyRegistry;
use crate::dds::participant::builder::discovery_setup::TypeLookupHandle;
use crate::engine::TopicRegistry;
use crate::transport::{PortMapping, UdpTransport};

/// What `DiscoveryDispatch::open_one_secure_envelope` resolved one
/// SEC_PREFIX envelope of a (possibly compound) secure SEDP datagram to.
#[cfg(feature = "security")]
enum SecureEnvelopeOutcome {
    /// A departure was delivered; `apply_sealed_participant_departure` has
    /// no "what follows" to preserve (Sec.7.4.1.6: the sealed departure is
    /// its own complete message). Stop scanning.
    Terminal,
    /// A secure SEDP DATA or a protected ACKNACK/NACK_FRAG was decoded and
    /// delivered; `end` is where this envelope's OWN content ended in the
    /// ORIGINAL datagram, where the caller resumes scanning for a FURTHER
    /// independently-protected envelope
    /// (`secure_submessage::first_secure_prefix_from`) rather than
    /// assuming the datagram held only one (a
    /// `[protected SEDP DATA][protected ACKNACK]` datagram must not
    /// return `Terminal` after the DATA and lose the ACKNACK -- the DATA
    /// handler's own "what precedes and follows it is unchanged" promise
    /// only ever covered PLAIN trailing bytes, like a HEARTBEAT, never a
    /// SECOND independently-encrypted envelope).
    Continues { end: usize },
    /// No candidate key material (writer or reader) is held AT ALL for
    /// this envelope's key id: the caller tries `park_sedp_awaiting_key`
    /// (which, itself, decides whether this sender is even expected to
    /// have tokens coming and increments `secure_sedp_undecodable` on its
    /// OWN refusal path when it is not -- see the note on
    /// [`Self::DecodeFailed`] for why that matters).
    NoKeyHeld,
    /// Candidate key material WAS held, but nothing it was tried against
    /// (departure, SEDP DATA, reader control) decoded or passed its
    /// binding/strength check. The caller counts this directly and never
    /// calls `park_sedp_awaiting_key`: that function's own "not expecting
    /// tokens" branch ALSO increments `secure_sedp_undecodable`, so
    /// calling it here -- when a key WAS held and simply failed to open --
    /// would double-count a single bad envelope (pinned by `review_
    /// unknown_key_must_not_pin_valid_data_forever` and
    /// `a_known_secure_key_with_a_bad_tag_is_dropped_and_counted`).
    DecodeFailed,
}

/// Everything a received discovery datagram may need, in one value.
///
/// Held behind an `Arc` by the callback the listeners are given. Every field
/// is cheap to clone or `Copy`; the handlers below take their arguments the
/// way they always did, so this type only owns what the dispatch captures.
pub(super) struct DiscoveryDispatch {
    /// This participant's own GUID prefix, for self-detection and for the
    /// source address of the ACKNACKs the handlers emit.
    pub our_guid_prefix: [u8; 12],
    pub transport: Arc<UdpTransport>,
    pub fsm: Arc<DiscoveryFsm>,
    pub registry: Arc<TopicRegistry>,
    pub sedp_cache: SedpAnnouncementsCache,
    /// Shared with the `ControlHandler`, so an ACKNACK's bitmapBase advances
    /// with actual SEDP DATA reception (RTPS v2.5 Sec.8.4.12.2).
    pub sedp_reader_registry: ReaderProxyRegistry,
    pub dialect_detector:
        Arc<std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>>,
    pub port_mapping: PortMapping,
    pub spdp_security_tokens: SpdpSecurityTokens,
    pub discovered_peers: Option<Arc<SpdpPeerSet>>,
    /// Reassembly buffer, keyed by (writer GUID, sequence number).
    pub fragment_buffer: Arc<Mutex<FragmentBuffer>>,
    pub type_lookup: TypeLookupHandle,
    /// The participant's liveliness: a ParticipantMessage of kind MANUAL
    /// renews its sender's MANUAL_BY_PARTICIPANT writers.
    pub liveliness: Option<Arc<crate::dds::liveliness::Shared>>,
    #[cfg(feature = "security")]
    pub secure_builtins: Option<super::secure_builtins::SecureBuiltins>,
    /// The `ControlHandler`'s channel, for a protected ACKNACK/NACK_FRAG
    /// this dispatch decodes (`dispatch_decoded_reader_control`) to rejoin
    /// the SAME processing a plaintext one goes through
    /// (`control::run_loop`), rather than duplicating that processing here.
    /// `None` until [`Self::set_control_tx`] runs (the channel is built
    /// AFTER this dispatch, `discovery_setup::mod`) and whenever the
    /// Two-Ring control channel is disabled; either way, a decoded message
    /// with nowhere to go is dropped, logged, never silently lost without a
    /// trace.
    #[cfg(feature = "security")]
    pub(super) control_tx: Mutex<
        Option<crossbeam::channel::Sender<crate::core::discovery::multicast::ControlMessage>>,
    >,
}

impl DiscoveryDispatch {
    /// Register the `ControlHandler`'s channel sender, once it exists
    /// (`discovery_setup::mod`: the channel is built after this dispatch).
    /// A decoded protected ACKNACK/NACK_FRAG reaches the exact same
    /// processing a plaintext one does by being pushed onto this same
    /// channel (`dispatch_decoded_reader_control`), never a parallel copy
    /// of that processing.
    #[cfg(feature = "security")]
    pub(super) fn set_control_tx(
        &self,
        tx: crossbeam::channel::Sender<crate::core::discovery::multicast::ControlMessage>,
    ) {
        *self.control_tx.lock() = Some(tx);
    }

    /// One submessage decoded by `secure_sedp::open_reader_control_packet`
    /// -- the ACKNACK or NACK_FRAG `submessage`, header included, and
    /// NOTHING else -- parsed and pushed onto the `ControlHandler` channel
    /// marked [`ControlMessage::protected`].
    ///
    /// The buffer built here is a minimal `[RTPS header][submessage]`:
    /// splicing the decoded submessage back into a copy of
    /// `datagram[..prefix_at]` and re-parsing THAT whole buffer would let
    /// any OTHER ACKNACK riding ahead of the SEC_PREFIX in the same
    /// datagram -- a CLEAR one, say -- inherit `.protected()` for free. `parse_all_acknack_submessages`/
    /// `parse_all_nack_frag_submessages` can only ever find the ONE
    /// submessage this buffer actually contains, so marking "every result"
    /// protected is provably marking only the bytes this function itself
    /// decoded.
    #[cfg(feature = "security")]
    fn dispatch_decoded_reader_control(&self, submessage: &[u8], remote_prefix: [u8; 12]) {
        use crate::core::discovery::multicast::control_parser::{
            parse_all_acknack_submessages, parse_all_nack_frag_submessages,
        };
        use crate::core::discovery::multicast::ControlMessage;
        // A real RTPS header (so diagnostics and `peer_guid_prefix`
        // extraction stay meaningful), the decoded submessage, and nothing
        // else: no sibling submessage of the original datagram can reach
        // the parsers below.
        let mut minimal = Vec::with_capacity(20 + submessage.len());
        minimal.extend_from_slice(b"RTPS");
        minimal.extend_from_slice(&[
            crate::core::rtps_constants::RTPS_VERSION_MAJOR,
            crate::core::rtps_constants::RTPS_VERSION_MINOR,
        ]);
        minimal.extend_from_slice(&crate::core::rtps_constants::HDDS_VENDOR_ID);
        minimal.extend_from_slice(&remote_prefix);
        minimal.extend_from_slice(submessage);

        let Some(tx) = self.control_tx.lock().clone() else {
            log::debug!(
                "[secure-sedp] decoded a protected ACKNACK/NACK_FRAG from {:02x?} but no \
                 control channel is registered: dropped",
                remote_prefix
            );
            return;
        };
        let mut delivered = 0usize;
        for info in parse_all_acknack_submessages(&minimal) {
            if let Some(msg) = ControlMessage::acknack(
                self.origin_for(remote_prefix),
                remote_prefix,
                info,
                &minimal,
            ) {
                delivered += usize::from(tx.try_send(msg.protected()).is_ok());
            }
        }
        for info in parse_all_nack_frag_submessages(&minimal) {
            if let Some(msg) = ControlMessage::nack_frag(
                self.origin_for(remote_prefix),
                remote_prefix,
                info,
                &minimal,
            ) {
                delivered += usize::from(tx.try_send(msg.protected()).is_ok());
            }
        }
        log::debug!(
            "[secure-sedp] decoded a protected ACKNACK/NACK_FRAG from {:02x?}, delivered {} \
             message(s) to the control channel",
            remote_prefix,
            delivered
        );
    }

    /// The `Origin` a reconstructed-from-SEC_PREFIX message carries onward:
    /// direct (`Origin::direct`), since the SEC_PREFIX was opened from a
    /// datagram this participant received itself (never relayed -- a
    /// protected control submessage of a secure builtin tunnel is unicast
    /// peer to peer). The address named is only this `Origin`'s source for
    /// logging/metrics purposes here; `control::run_loop`'s own reply-
    /// address resolution (`resolve_peer_metatraffic_addr`) re-derives the
    /// real destination from the FSM's locator record, not from this
    /// `Origin`.
    #[cfg(feature = "security")]
    fn origin_for(&self, remote_prefix: [u8; 12]) -> Origin {
        let addr = self
            .fsm
            .first_metatraffic_locator(&remote_prefix)
            .unwrap_or_else(|| {
                std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            });
        Origin::direct(addr)
    }

    /// Wire both replay and repair to the production dispatch. Weak captures
    /// prevent the FSM callbacks retaining their participant after teardown.
    #[cfg(feature = "security")]
    pub(super) fn arm_secure_sedp(self: &Arc<Self>) {
        let replay = Arc::downgrade(self);
        self.fsm
            .set_secure_sedp_replay(Box::new(move |kind, bytes, at, origin| {
                if let Some(dispatch) = replay.upgrade() {
                    dispatch.dispatch(kind, bytes, at, None, origin);
                }
            }));
        let repair = Arc::downgrade(self);
        self.fsm
            .set_secure_sedp_repair(Box::new(move |prefix, mask| {
                if let Some(dispatch) = repair.upgrade() {
                    dispatch.request_secure_sedp_repair(prefix, mask);
                }
            }));
    }

    #[cfg(feature = "security")]
    fn request_secure_sedp_repair(&self, prefix: [u8; 12], mask: u8) {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
        };
        static COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        let Some(addr) = self.fsm.first_metatraffic_locator(&prefix) else {
            return;
        };
        for (bit, writer) in [
            (1, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER),
            (2, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER),
        ] {
            if mask & bit == 0 {
                continue;
            }
            let mut reader = writer;
            reader[3] = 0xc7;
            // The ciphertext that overflowed cannot authenticate its sequence
            // number. Request from 1; the writer answers retained history and
            // GAPs, followed by its actual HEARTBEAT range.
            let packet = crate::protocol::builder::build_acknack_packet_with_final(
                self.our_guid_prefix,
                prefix,
                reader,
                writer,
                1,
                &[1],
                COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                false,
            );
            // This recovery ACKNACK must not go out in clear
            // unconditionally: `control::run_loop` refuses a clear ACKNACK
            // on a governance requiring submessage protection, so the
            // very peer this repair targets would discard the request
            // meant to recover it. Protect it under our reader key for
            // `writer`'s tunnel exactly as `control::send_sedp_acknack`
            // does, when that key has been minted; a peer requiring
            // protection with no local key yet cannot be served a working
            // repair request regardless (the key, once distributed, lets
            // the next sweep's repair through).
            let packet = match self.fsm.local_builtin_reader_material_for(&prefix, &writer) {
                Some(material) => {
                    match crate::security::crypto::secure_sedp::protect_reader_control_packet(
                        &packet, &material,
                    ) {
                        Some(protected) => protected,
                        None => {
                            log::warn!(
                                "[secure-sedp] could not protect the repair ACKNACK to {:02x?} \
                                 writer={:02x?}: not sent",
                                prefix,
                                writer
                            );
                            continue;
                        }
                    }
                }
                None => packet,
            };
            let _ = self.transport.send_to_endpoint(&packet, &addr);
        }
    }

    /// A datagram of the secure SEDP topic from `payload`'s sender.
    ///
    /// - Held behind what is held for that sender while its keys change
    ///   (`DiscoveryFsm::park_sedp`), and held itself when it has not
    ///   authenticated yet: the secure endpoints of a participant are matched
    ///   only after the authentication protocol succeeds (DDS Security v1.1
    ///   Sec.8.8.2.2).
    /// - A SEC_PREFIX at `cdr_offset`, from any authenticated participant:
    ///   decoded with the key material the sender's secure SEDP writer
    ///   announced in its DatawriterCryptoTokens, found by the sender's
    ///   prefix and the CryptoHeader's key id (Sec.8.5.1.9.6
    ///   `preprocess_secure_submsg`, Sec.8.8.9.2), and taken only as a DATA
    ///   of that writer meeting our discovery protection kind
    ///   (`secure_sedp::open_secure_sedp_as`). A key id nothing is held for
    ///   yet is a DATA whose writer's tokens have not arrived: held until a
    ///   key of that sender is installed (`park_sedp_awaiting_key`), and the
    ///   known-key datagrams proceed independently.
    /// - A SEC_PREFIX decoded with the key material of the sender's secure
    ///   participant writer is its departure
    ///   (`DiscoveryFsm::open_sealed_departure`, Sec.7.4.1.6).
    /// - Otherwise the NONE shape (`open_clear_secure_sedp`), accepted only
    ///   when governance requires no submessage protection.
    #[cfg(feature = "security")]
    fn handle_secure_sedp(&self, payload: &[u8], cdr_offset: usize, origin: Origin) {
        use crate::security::crypto::secure_sedp;
        use crate::security::crypto::secure_submessage::SEC_PREFIX;

        let Some(remote_prefix) = payload
            .get(8..20)
            .and_then(|p| <[u8; 12]>::try_from(p).ok())
        else {
            return;
        };
        // The ParticipantVolatileMessageSecure endpoints protect every
        // submessage under the sender's KxKeys (DDS Security v1.1
        // Sec.7.4.4.1, Sec.8.5.1.9.2), which need no CryptoToken: they are
        // read first, and never held behind secure SEDP waiting for a key,
        // because the keys secure SEDP waits for are what they carry.
        let mut cdr_offset = cdr_offset;
        loop {
            match self.open_volatile_envelope(payload, cdr_offset, remote_prefix) {
                Some(Some(end)) => {
                    match crate::security::crypto::secure_submessage::first_secure_prefix_from(
                        payload, end,
                    ) {
                        Some(next) => cdr_offset = next,
                        None => return,
                    }
                }
                Some(None) => return,
                None => break,
            }
        }
        // Behind what is held for this sender while its keys change, in
        // order (`DiscoveryFsm::park_sedp`).
        self.fsm.settle_parked_sedp(remote_prefix);
        if self.fsm.has_parked_sedp(&remote_prefix)
            && self.fsm.park_sedp(
                remote_prefix,
                PacketKind::SecureSEDP,
                payload,
                cdr_offset,
                origin,
            )
        {
            return;
        }
        if !self.fsm.is_peer_authenticated(&remote_prefix) {
            if self.fsm.park_sedp(
                remote_prefix,
                PacketKind::SecureSEDP,
                payload,
                cdr_offset,
                origin,
            ) {
                log::debug!(
                    "[secure-sedp] {:02x?} has not authenticated yet: held until its handshake \
                     completes",
                    remote_prefix
                );
            } else {
                log::debug!(
                    "[secure-sedp] {:02x?} has not authenticated, drop",
                    remote_prefix
                );
            }
            return;
        }
        let required = self
            .fsm
            .discovery_protection_kind()
            .unwrap_or(crate::security::access::ProtectionKind::Encrypt);

        if payload.get(cdr_offset) != Some(&SEC_PREFIX) {
            if !required.is_protected() {
                let at = super::sedp_handler::data_submessage_at(payload, cdr_offset);
                if let Some(departed) = at.and_then(|at| {
                    crate::protocol::builder::extract_participant_dispose_at(
                        payload,
                        at,
                        crate::core::rtps_constants::RTPS_ENTITYID_SPDP_SECURE_WRITER,
                    )
                }) {
                    super::spdp_handler::apply_sealed_participant_departure(
                        departed,
                        self.our_guid_prefix,
                        &self.fsm,
                        self.discovered_peers.as_deref(),
                    );
                    return;
                }
            }
            match secure_sedp::open_clear_secure_sedp(payload, cdr_offset, required) {
                Some(opened) => {
                    self.deliver_opened_sedp_data(opened.datagram, opened.payload_at, origin);
                }
                None => {
                    self.fsm
                        .metrics
                        .secure_sedp_undecodable
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    log::debug!("[secure-sedp] {:02x?}: did not open, drop", remote_prefix);
                }
            }
            return;
        }

        // DDS Security v1.1 does not forbid several independently-
        // protected control submessages in one RTPS message (a secure
        // SEDP publications ACKNACK and a subscriptions one, say,
        // possibly separated by an INFO_TS): `offset` advances past each
        // envelope this loop successfully opens, via `first_secure_prefix_
        // from`, instead of stopping after the first one.
        let mut offset = cdr_offset;
        loop {
            match self.open_one_secure_envelope(payload, offset, origin, remote_prefix, required) {
                SecureEnvelopeOutcome::Terminal => return,
                SecureEnvelopeOutcome::Continues { end } => {
                    match crate::security::crypto::secure_submessage::first_secure_prefix_from(
                        payload, end,
                    ) {
                        Some(next) => {
                            offset = next;
                            continue;
                        }
                        None => return,
                    }
                }
                SecureEnvelopeOutcome::NoKeyHeld => {
                    // `park_sedp_awaiting_key` decides on its own whether
                    // this sender is even expected to have tokens coming,
                    // and increments `secure_sedp_undecodable` ITSELF on
                    // its "not expecting any" refusal path -- never
                    // double-counted here.
                    if self
                        .fsm
                        .park_sedp_awaiting_key(remote_prefix, payload, offset, origin)
                    {
                        log::debug!(
                            "[secure-sedp] {:02x?}: no key material yet, held until its \
                             CryptoTokens arrive",
                            remote_prefix
                        );
                    } else {
                        log::debug!("[secure-sedp] {:02x?}: did not open, drop", remote_prefix);
                    }
                    return;
                }
                SecureEnvelopeOutcome::DecodeFailed => {
                    self.fsm
                        .metrics
                        .secure_sedp_undecodable
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    log::debug!("[secure-sedp] {:02x?}: did not open, drop", remote_prefix);
                    return;
                }
            }
        }
    }

    /// The SEC_PREFIX at `at` opened as a submessage of the volatile
    /// endpoints (`SecureBuiltins::receive_volatile`): `None` when it is
    /// not one (the secure SEDP path reads it), `Some(Some(end))` when it
    /// was handled and a further envelope may begin at `end`, `Some(None)`
    /// when it names the KxKeys and did not open under them -- refused and
    /// counted, unless secure SEDP holds key material of that very key id
    /// for the sender, in which case it is the secure SEDP path's -- or when
    /// it is a submessage this participant sealed, sent back.
    #[cfg(feature = "security")]
    fn open_volatile_envelope(
        &self,
        payload: &[u8],
        at: usize,
        remote_prefix: [u8; 12],
    ) -> Option<Option<usize>> {
        use super::secure_builtins::VolatileOutcome;
        let sbu = self.secure_builtins.as_ref()?;
        match sbu.receive_volatile(remote_prefix, payload, at) {
            VolatileOutcome::NotKx => None,
            // Our own submessage sent back: dropped without counting it as
            // one that did not open, which it is not.
            VolatileOutcome::Reflected => Some(None),
            VolatileOutcome::Opened(receipt) => {
                if !receipt.replies.is_empty() {
                    match self.fsm.first_metatraffic_locator(&remote_prefix) {
                        Some(addr) => {
                            for reply in &receipt.replies {
                                // A lost answer is asked for again: the
                                // pair is reliable on both legs.
                                let _ = self.transport.send_to_endpoint(reply, &addr);
                            }
                        }
                        None => log::debug!(
                            "[security::volatile] no metatraffic locator for {:02x?}: answer \
                             not sent",
                            remote_prefix
                        ),
                    }
                }
                if receipt.installed {
                    // A key material of that participant installed: what
                    // waited for it is handed back
                    // (`DiscoveryFsm::park_sedp_awaiting_key`).
                    self.fsm.replay_sedp_awaiting_key(remote_prefix);
                }
                Some(Some(receipt.end))
            }
            VolatileOutcome::Refused => {
                let key_id =
                    crate::security::crypto::secure_sedp::transformation_key_id_at(payload, at)?;
                if !self
                    .fsm
                    .remote_builtin_writer_materials(&remote_prefix, key_id)
                    .is_empty()
                    || !self
                        .fsm
                        .remote_builtin_reader_materials(&remote_prefix, key_id)
                        .is_empty()
                {
                    return None;
                }
                sbu.refuse_undecodable_volatile(remote_prefix);
                Some(None)
            }
        }
    }

    /// What one SEC_PREFIX envelope of `handle_secure_sedp`'s loop
    /// resolved to.
    #[cfg(feature = "security")]
    #[must_use]
    fn open_one_secure_envelope(
        &self,
        payload: &[u8],
        cdr_offset: usize,
        origin: Origin,
        remote_prefix: [u8; 12],
        required: crate::security::access::ProtectionKind,
    ) -> SecureEnvelopeOutcome {
        use crate::core::rtps_constants::RTPS_ENTITYID_SPDP_SECURE_WRITER;
        use crate::security::crypto::secure_sedp;

        // No readable CryptoHeader at all (malformed past the SEC_PREFIX
        // id itself): nothing to count or park, same as before this loop
        // existed.
        let Some(key_id) = secure_sedp::transformation_key_id_at(payload, cdr_offset) else {
            return SecureEnvelopeOutcome::Terminal;
        };
        // A volatile envelope behind a secure SEDP one in the same datagram.
        match self.open_volatile_envelope(payload, cdr_offset, remote_prefix) {
            Some(Some(end)) => return SecureEnvelopeOutcome::Continues { end },
            Some(None) => return SecureEnvelopeOutcome::Terminal,
            None => {}
        }
        let materials = self
            .fsm
            .remote_builtin_writer_materials(&remote_prefix, key_id);
        // DDS Security v1.1 Sec.8.8.9.3: a secure SEDP READER protects its
        // own ACKNACK/NACK_FRAG with a key of its own, announced in a
        // DatareaderCryptoTokens -- the mirror image of the writer
        // materials above. The SEC_PREFIX's key id does not say which
        // CryptoTokens class minted it, so both candidate sets are tried;
        // a wrong key simply fails to authenticate (below).
        let reader_materials = self
            .fsm
            .remote_builtin_reader_materials(&remote_prefix, key_id);
        if materials.is_empty() && reader_materials.is_empty() {
            return SecureEnvelopeOutcome::NoKeyHeld;
        }

        // The departure of the participant, on its secure participant
        // writer (DDS Security v1.1 Sec.7.4.1.6).
        if let Some(departed) = materials
            .iter()
            .filter(|(writer, _)| *writer == RTPS_ENTITYID_SPDP_SECURE_WRITER)
            .find_map(|(_, material)| {
                crate::core::discovery::multicast::DiscoveryFsm::open_sealed_departure(
                    payload, cdr_offset, material, required,
                )
            })
        {
            super::spdp_handler::apply_sealed_participant_departure(
                departed,
                self.our_guid_prefix,
                &self.fsm,
                self.discovered_peers.as_deref(),
            );
            return SecureEnvelopeOutcome::Terminal;
        }

        let opened_data = materials
            .iter()
            .filter(|(writer, _)| *writer != RTPS_ENTITYID_SPDP_SECURE_WRITER)
            .find_map(|(writer, material)| {
                secure_sedp::open_secure_sedp_as(payload, cdr_offset, material, writer, required)
            });
        if let Some(opened) = opened_data {
            self.deliver_opened_sedp_data(opened.datagram, opened.payload_at, origin);
            // `open_secure_sedp_as` stitches `datagram[decoded.end..stitch_end]`
            // into its returned datagram, where `stitch_end` stops at the
            // NEXT SEC_PREFIX rather than running to the end of the
            // original payload: a
            // further independently-protected envelope -- a protected
            // ACKNACK following this SEDP DATA, say -- is deliberately
            // left OUT of the synthetic datagram, so it must still be
            // picked up by the caller's loop, in the ORIGINAL payload,
            // via `opened.end` (the caller's own `first_secure_prefix_
            // from` check decides whether there is one; `Terminal` vs
            // `Continues` would otherwise just duplicate that check here).
            return SecureEnvelopeOutcome::Continues { end: opened.end };
        }

        if let Some(opened) = reader_materials.iter().find_map(|(reader, material)| {
            secure_sedp::open_reader_control_packet(payload, cdr_offset, material, reader, required)
        }) {
            self.dispatch_decoded_reader_control(&opened.submessage, remote_prefix);
            return SecureEnvelopeOutcome::Continues { end: opened.end };
        }

        SecureEnvelopeOutcome::DecodeFailed
    }

    /// Hand an opened secure SEDP DATA to the ordinary SEDP handler.
    #[cfg(feature = "security")]
    fn deliver_opened_sedp_data(
        &self,
        synthetic_packet: Vec<u8>,
        cdr_offset: usize,
        origin: Origin,
    ) {
        log::debug!(
            "[secure-sedp] opened SecureSEDP, len={} -> {}",
            synthetic_packet.len(),
            cdr_offset
        );
        handle_sedp_packet(
            &synthetic_packet,
            cdr_offset,
            self.fsm.clone(),
            self.registry.clone(),
            self.sedp_reader_registry.clone(),
            self.transport.clone(),
            self.sedp_cache.clone(),
            self.our_guid_prefix,
            self.type_lookup.clone(),
            origin,
            SedpChannel::Secure,
        );
    }

    /// A ParticipantMessageData (RTPS v2.5 Sec.9.6.3.1) at `cdr_offset`.
    fn handle_participant_message(&self, payload: &[u8], cdr_offset: usize, origin: Origin) {
        use crate::protocol::rtps::participant_message::{
            decode_participant_message_data, KIND_AUTOMATIC, KIND_MANUAL,
        };
        let message = payload
            .get(cdr_offset..)
            .and_then(decode_participant_message_data);
        let source = payload.get(8..20);
        match message {
            Some(message) if source == Some(&message.participant_guid_prefix[..]) => {
                // RTPS v2.5 Sec.8.4.13.3: our BuiltinParticipantMessageReader
                // answers this writer's HEARTBEAT (`control.rs`) against
                // what it has admitted; without recording the sequence
                // number here that answer never advances past "nothing
                // received yet", and a HEARTBEAT past our first assertion
                // is always answered as if it were missing.
                if let Some(sn) = crate::protocol::builder::extract_sequence_number(payload) {
                    self.fsm
                        .note_participant_message_received(&message.participant_guid_prefix, sn);
                }
                // Shared with the TCP/QUIC unicast router: see
                // `renew_liveliness_from_participant_message`'s own doc.
                if let Some(ref liveliness) = self.liveliness {
                    crate::core::discovery::multicast::control::renew_liveliness_from_participant_message(
                        &message, liveliness,
                    );
                }
                if message.kind != KIND_MANUAL && message.kind != KIND_AUTOMATIC {
                    log::trace!(
                        "[callback-builder] PARTICIPANT_MESSAGE of kind {:02x?} from {}: not a liveliness kind",
                        message.kind,
                        origin.from()
                    );
                }
            }
            Some(_) => log::debug!(
                "[callback-builder] PARTICIPANT_MESSAGE from {} names another participant: dropped",
                origin.from()
            ),
            None => log::debug!(
                "[callback-builder] PARTICIPANT_MESSAGE from {} does not decode: dropped",
                origin.from()
            ),
        }
    }

    /// Route one classified datagram.
    ///
    /// # Arguments
    /// - `packet_kind`: the kind the classifier elected for this datagram,
    ///   which it read off the WRITER of the submessage it chose.
    /// - `payload`: the full RTPS datagram, headers included - several
    ///   handlers read the source GUID prefix out of bytes 8..20.
    /// - `cdr_offset`: where the classifier found the serialized payload.
    /// - `frag_meta`: published exactly when the classifier read a DATA_FRAG.
    /// - `origin`: where the datagram came from, and where a reply may go
    ///   (RTPS 2.5 8.3.4, 8.3.8.10: `None` behind an INFO_SRC).
    pub(super) fn dispatch(
        &self,
        packet_kind: PacketKind,
        payload: &[u8],
        cdr_offset: usize,
        frag_meta: Option<FragmentMetadata>,
        origin: Origin,
    ) {
        // A user sample is its participant speaking: a liveness mark while
        // our probation may still purge it (`DiscoveryFsm::note_user_data`;
        // one relaxed atomic load once the probation is settled). A DATA_FRAG
        // of a builtin writer is named after that writer, never DataFrag.
        if matches!(packet_kind, PacketKind::Data | PacketKind::DataFrag) {
            self.fsm.note_user_data(payload);
        }

        // A fragment is a fragment whatever kind its writer gives it.
        //
        // The classifier publishes fragment metadata exactly when it read
        // a DATA_FRAG (0x16), and it names that submessage after its
        // WRITER - so a fragmented SPDP announcement arrives here with
        // kind SPDP. Sending it to `handle_spdp_packet` would parse one
        // fragment as if it were the whole announcement, yielding a
        // participant built from a truncated parameter list: the right
        // GUID, then a 100-second lease and domain 0 that are constants in
        // the partial parser, no locators and no security token - so no
        // endpoint would be registered for it and the PKI-DH handshake
        // would never be armed. The rest of the announcement, delivered a
        // moment later, would fail the CDR encapsulation check on bytes that
        // are the middle of a parameter list, and be dropped.
        //
        // The test is therefore the SHAPE of the submessage, not the kind of
        // its writer.
        if let Some(meta) = frag_meta {
            handle_fragment(
                meta,
                payload,
                self.fragment_buffer.clone(),
                &FragmentContext {
                    origin,
                    our_guid_prefix: self.our_guid_prefix,
                    transport: self.transport.clone(),
                    fsm: self.fsm.clone(),
                    registry: self.registry.clone(),
                    sedp_cache: self.sedp_cache.clone(),
                    dialect_detector: self.dialect_detector.clone(),
                    port_mapping: self.port_mapping,
                    spdp_security_tokens: &self.spdp_security_tokens,
                    discovered_peers: self.discovered_peers.as_deref(),
                    type_lookup: &self.type_lookup,
                    #[cfg(feature = "security")]
                    secure_builtins: self.secure_builtins.as_ref(),
                },
            );
            return;
        }

        // Dispatch to appropriate handler with CDR offset
        match packet_kind {
            PacketKind::SPDP => {
                handle_spdp_packet(
                    payload,
                    cdr_offset,
                    origin,
                    self.our_guid_prefix,
                    self.transport.clone(),
                    self.fsm.clone(),
                    self.sedp_cache.clone(),
                    self.dialect_detector.clone(),
                    self.port_mapping,
                    &self.spdp_security_tokens,
                    self.discovered_peers.as_deref(),
                );
            }
            PacketKind::SEDP => {
                // Behind what is held for this sender while its keys change,
                // in order (`DiscoveryFsm::park_sedp`).
                #[cfg(feature = "security")]
                if let Some(prefix) = payload
                    .get(8..20)
                    .and_then(|p| <[u8; 12]>::try_from(p).ok())
                {
                    self.fsm.settle_parked_sedp(prefix);
                    if self.fsm.has_parked_sedp(&prefix)
                        && self
                            .fsm
                            .park_sedp(prefix, PacketKind::SEDP, payload, cdr_offset, origin)
                    {
                        return;
                    }
                }
                // Pass SEDP reader registry for DATA notification
                // Pass transport, sedp_cache, our_guid_prefix, origin for OpenDDS re-announcements
                handle_sedp_packet(
                    payload,
                    cdr_offset,
                    self.fsm.clone(),
                    self.registry.clone(),
                    self.sedp_reader_registry.clone(),
                    self.transport.clone(),
                    self.sedp_cache.clone(),
                    self.our_guid_prefix,
                    self.type_lookup.clone(),
                    origin,
                    SedpChannel::Plain,
                );
            }
            PacketKind::DataFrag => {
                // Reachable only without fragment metadata: with it, the
                // delivery went to reassembly above, whatever its kind.
                log::debug!("[callback-builder] WARNING: DATA_FRAG without fragment metadata!");
            }
            // A DATA from a USER-DEFINED (or vendor-specific) writer. It is
            // the router's business, delivered to it by the rx ring; all
            // discovery takes from it is that its participant spoke (counted
            // above, `note_user_data`).
            //
            // It must not be handed to the SPDP and then the SEDP parser: that
            // would guess a payload's type instead of reading its writer's,
            // which is Sec.8.3.8.2 exactly inverted. A real participant
            // announcement carried by the application writer 0x00001202 would
            // REGISTER A PARTICIPANT, and a SEDP-shaped payload could register
            // a writer-GUID-to-topic mapping the same way.
            PacketKind::Data => {
                log::trace!(
                    "[callback-builder] user DATA from {}: the router's, not discovery's",
                    origin.from()
                );
            }
            // A DATA whose writer is a BUILTIN endpoint we do not implement
            // (RTPS v2.5 Sec.9.3.1.2 Table 9.1). Dropped by name and counted;
            // the id itself is in the classifier's debug line, which is what
            // names the cell if an interop pair fails on this.
            PacketKind::UnknownBuiltin => {
                self.fsm
                    .metrics
                    .unclaimed_builtin_data
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                log::debug!(
                    "[callback-builder] DATA from a builtin endpoint with no handler, from {}: dropped",
                    origin.from()
                );
            }
            PacketKind::TypeLookup => {
                handle_type_lookup_packet(&self.type_lookup, payload, cdr_offset, origin);
            }
            // RTPS v2.5 Sec.8.4.13. A liveliness assertion the peer sends on
            // its own behalf, whose payload is a CDR struct and not a
            // ParameterList. What protects us is that the CLASSIFIER names
            // it: until it did, the id belonged to no builtin endpoint, so the
            // datagram was named user `Data` and taken to a parser that tried
            // the SPDP and SEDP readers on whatever it was handed.
            //
            // Its datagram already renewed the sender's AUTOMATIC writers
            // (`PacketDispatch`, like any message of it); a MANUAL assertion
            // also renews its MANUAL_BY_PARTICIPANT writers (Sec.8.4.13.5).
            // Only a participant's own assertion counts: one naming another
            // participant than the message's source is dropped.
            PacketKind::ParticipantMessage => {
                self.handle_participant_message(payload, cdr_offset, origin);
            }
            // Handle HEARTBEAT for SEDP endpoints - respond with ACKNACK
            // Pass discovery FSM for peer metatraffic locator lookup
            PacketKind::Heartbeat => {
                handle_heartbeat_packet(
                    payload,
                    origin,
                    self.our_guid_prefix,
                    self.transport.clone(),
                    self.port_mapping.metatraffic_unicast, // fallback
                    self.fsm.clone(),                      // lookup peer's actual metatraffic port
                );
            }
            // PKI-DH handshake tokens on the plaintext
            // BuiltinParticipantStatelessMessageReader (entity 0x000201C4).
            // `dispatch_stateless` pushes the token into the HandshakeMachine
            // and enqueues any reply; the `hdds-stateless-writer` thread
            // (security::stateless_writer) drains tx_tokens every 5 ms and
            // puts them on the wire.
            PacketKind::Stateless => {
                #[cfg(feature = "security")]
                {
                    // Extract writer GUID prefix from the RTPS header (bytes 8-19)
                    // for use as the remote_guid_prefix passed to dispatch_stateless.
                    // A packet too short to carry a prefix cannot be attributed
                    // to a peer: dropping it beats keying handshake state under
                    // an all-zero GUID that every malformed packet would share.
                    if payload.len() < 20 {
                        log::debug!(
                            "[security::stateless] packet of {} bytes is too short to carry a GUID prefix, drop",
                            payload.len()
                        );
                        return;
                    }
                    let mut remote_prefix = [0u8; 12];
                    remote_prefix.copy_from_slice(&payload[8..20]);
                    // `payload` is the FULL RTPS datagram; the classifier
                    // located the serialized payload (`cdr_offset`), which
                    // begins with its encapsulation header.
                    if cdr_offset >= payload.len() {
                        log::debug!(
                            "[security::stateless] cdr_offset {} past end of {}-byte packet, drop",
                            cdr_offset,
                            payload.len()
                        );
                        return;
                    }
                    handle_stateless_sample(
                        &payload[cdr_offset..],
                        remote_prefix,
                        self.our_guid_prefix,
                        &self.fsm,
                        self.secure_builtins.as_ref(),
                    );
                }
                #[cfg(not(feature = "security"))]
                {
                    let _ = (payload, cdr_offset);
                }
            }
            // The secure SEDP topic: a datagram protected by DDS-Security
            // submessage protection (`cdr_offset` at its SEC_PREFIX, the
            // listener delivers those), the NONE shape of the secure SEDP
            // writers, or, from an HDDS 1.4.x peer only, a DATA of the secure
            // SEDP writers sealed in the legacy shape. What opens goes through
            // the normal handle_sedp_packet path, on the secure channel
            // (`handle_secure_sedp`).
            PacketKind::SecureSEDP => {
                #[cfg(feature = "security")]
                self.handle_secure_sedp(payload, cdr_offset, origin);
                #[cfg(not(feature = "security"))]
                {
                    let _ = (payload, cdr_offset, origin);
                }
            }
            // The NONE form uses the same topic and status decoder as
            // protected participant departures. Authentication and the
            // governance requirement are checked by handle_secure_sedp.
            PacketKind::SecureSPDP => {
                #[cfg(feature = "security")]
                self.handle_secure_sedp(payload, cdr_offset, origin);
                #[cfg(not(feature = "security"))]
                let _ = (payload, cdr_offset, origin);
            }
            // A CLEAR DATA of the ParticipantVolatileMessageSecure endpoints
            // (entity 0xff0202c3/c4). The topic is submessage-protected
            // (DDS Security v1.1 Sec.7.4.4.1, Table 17): its DATA travels
            // as a SEC_PREFIX the listener delivers to the secure arm
            // above, never in clear. Refused and counted.
            PacketKind::SecureVolatile => {
                #[cfg(feature = "security")]
                {
                    let prefix = payload
                        .get(8..20)
                        .and_then(|p| <[u8; 12]>::try_from(p).ok());
                    if let (Some(prefix), Some(sbu)) = (prefix, self.secure_builtins.as_ref()) {
                        sbu.refuse_clear_volatile(prefix);
                    }
                    let _ = cdr_offset;
                }
                #[cfg(not(feature = "security"))]
                {
                    let _ = (payload, cdr_offset);
                }
            }
            // Every kind the listener's gate (`wants_discovery_callback`) never
            // delivers here, NAMED rather than swept up by `_`. The two lists
            // are exhaustive for the same reason: a new `PacketKind` must not
            // compile until somebody decides, in both places, whether
            // discovery wants it. A wildcard at the gate is how the
            // DDS-Security handshake once stayed unreachable while its handler
            // here was complete.
            //
            // Control kinds go through the recv loop's control branches or the
            // rx ring to the demux router; context kinds are never elected to
            // name a datagram; the rest carry nothing for discovery.
            PacketKind::AckNack
            | PacketKind::Gap
            | PacketKind::NackFrag
            | PacketKind::HeartbeatFrag
            | PacketKind::Departure
            | PacketKind::InfoTs
            | PacketKind::InfoSrc
            | PacketKind::InfoDst
            | PacketKind::InfoReply
            | PacketKind::Pad
            | PacketKind::Invalid
            | PacketKind::Unknown => {}
        }
    }
}

/// A sample of the BuiltinParticipantStatelessMessageWriter of the
/// participant `remote_prefix`, whole (one DATA, or DATA_FRAG reassembled):
/// a ParticipantStatelessMessage (DDS Security v1.1 Sec.7.4.3.3) around a
/// handshake token, for this participant (or for any, all zeros), from a
/// writer of `remote_prefix`. Its token goes to the handshake.
#[cfg(feature = "security")]
pub(super) fn handle_stateless_sample(
    sample: &[u8],
    remote_prefix: [u8; 12],
    our_guid_prefix: [u8; 12],
    fsm: &DiscoveryFsm,
    secure_builtins: Option<&super::secure_builtins::SecureBuiltins>,
) {
    let message = match crate::security::generic_message::decode(sample) {
        Ok(message) => message,
        Err(e) => {
            log::debug!(
                "[security::stateless] from {:02x?}: {}, drop",
                remote_prefix,
                e
            );
            return;
        }
    };
    let destination = &message.destination_participant;
    if destination[..12] != our_guid_prefix && *destination != [0u8; 16] {
        log::debug!(
            "[security::stateless] from {:02x?}: for another participant, drop",
            remote_prefix
        );
        return;
    }
    if message.source_guid[..12] != remote_prefix {
        log::debug!(
            "[security::stateless] from {:02x?}: names another source, drop",
            remote_prefix
        );
        return;
    }
    let token_cdr = &message.token[..];

    // A handshake message is the participant speaking, as its HEARTBEATs and
    // samples are: a liveness mark. A peer we are authenticating may say
    // nothing else for the whole probation, and its purge as silent
    // (`DiscoveryFsm::fails_probation`) drops the session in progress; its
    // next announcement begins another, which spends its re-authentication of
    // the interval. Only a message whose token parses counts: any bytes on
    // the stateless reader under a known prefix must not keep that
    // participant alive.
    if crate::security::handshake::parse_token(token_cdr).is_ok() {
        fsm.touch_participant_by_prefix(&remote_prefix);
    }

    if let Some(sbu) = secure_builtins {
        sbu.dispatch_stateless(remote_prefix, token_cdr.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::super::wire_fixtures::*;
    use super::*;

    /// The P2P participant-message endpoints (RTPS v2.5 Sec.8.4.13), which
    /// our own `PID_BUILTIN_ENDPOINT_SET` asks every peer for.
    const PARTICIPANT_MESSAGE: Endpoints = Endpoints {
        reader: [0x00, 0x02, 0x00, 0xC7],
        writer: [0x00, 0x02, 0x00, 0xC2],
    };

    /// A DATA that carries no writer entity id announces no participant.
    ///
    /// The whole datagram is 76 octets. Its one DATA declares an eight-octet
    /// body, so the four octets the classifier reads as a writer entity id
    /// belong to what follows it - and here they spell the SPDP builtin
    /// participant writer, which is a thing any sender can arrange. End to
    /// end through this dispatch, **no participant may be registered**, from
    /// a submessage that names no writer at all.
    ///
    /// A DATA is what its writer says it is; here no writer field exists to
    /// be read, and a read bounded by the datagram instead of by the
    /// submessage would invent one. Two guards close it and the
    /// test needs both to stay honest: `classify_data` reads inside its own
    /// body, and the admission rule asks the submessage rather than the kind
    /// the misread produced.
    #[test]
    fn a_data_carrying_no_writer_id_announces_no_participant() {
        let (announced, cdr) = announcement_from(SENDER_PREFIX);

        let mut datagram = Vec::new();
        datagram.extend_from_slice(b"RTPS");
        datagram.extend_from_slice(&[0x02, 0x04, 0x01, 0x12]);
        datagram.extend_from_slice(&SENDER_PREFIX);
        datagram.push(0x15); // DATA
        datagram.push(0x01); // little-endian
        datagram.extend_from_slice(&8u16.to_le_bytes()); // a body of [24..32)
        datagram.extend_from_slice(&[0xAA; 8]);
        assert_eq!(datagram.len(), 32, "fixture: the DATA ends here");
        // Not part of the DATA. Read as its writerEntityId all the same.
        datagram.extend_from_slice(&[0x00, 0x01, 0x00, 0xC2]);
        datagram.extend_from_slice(&[0x00; 8]);
        assert_eq!(
            datagram.len(),
            SAMPLE_AT,
            "fixture: and the announcement must sit where the classifier \
             would compute the payload offset"
        );
        datagram.extend_from_slice(&cdr);

        let (kind, at, meta, _ctx) =
            crate::core::discovery::multicast::classifier::classify_rtps(&datagram);
        assert_eq!(
            kind,
            PacketKind::Unknown,
            "a DATA that stops before its own writer entity id names nothing"
        );

        // Fed anyway, with the offset the broken classifier handed over, so
        // this test still measures the dispatch and not just the classifier.
        let h = Harness::new();
        h.feed(kind, &datagram, at.unwrap_or(SAMPLE_AT), meta);

        assert!(
            h.dispatch.fsm.get_participants().is_empty(),
            "nothing in this datagram says {:?} exists",
            announced.participant_guid
        );
    }

    /// A DATA no builtin endpoint claimed is named user data and is not
    /// handed to a parser that guesses what it is by its content.
    ///
    /// The fixture is deliberately the WORST case rather than a realistic
    /// one: a real participant announcement, carried by the liveliness
    /// writer. Were that endpoint missing from the classifier's map, the
    /// datagram would be named `Data` and a content-guessing SPDP reader
    /// would accept it - registering a participant off a submessage that
    /// says nothing about any participant's existence. Any ParameterList
    /// carrying PID_PARTICIPANT_GUID (0x0050) does this, and a SEDP
    /// announcement carries one by interop requirement.
    ///
    /// RTPS types a submessage by its writer, never by its payload
    /// (Sec.8.3.8.2): the reader of a builtin endpoint knows what it reads
    /// because the endpoint says so, and 0x000200c2 says ParticipantMessage -
    /// a CDR struct, not a parameter list.
    #[test]
    fn a_liveliness_writer_never_announces_a_participant() {
        let (announced, cdr) = announcement_from(SENDER_PREFIX);
        let datagram = data_datagram(SENDER_PREFIX, &PARTICIPANT_MESSAGE, &cdr);

        let (kind, at, meta, _ctx) =
            crate::core::discovery::multicast::classifier::classify_rtps(&datagram);
        assert_eq!(
            kind,
            PacketKind::ParticipantMessage,
            "0x000200c2 is a builtin endpoint and the map has to know it"
        );

        let h = Harness::new();
        h.feed(kind, &datagram, at.unwrap_or(SAMPLE_AT), meta);

        assert!(
            h.dispatch.fsm.get_participants().is_empty(),
            "the liveliness writer said nothing about {:?} existing",
            announced.participant_guid
        );
    }

    /// A MANUAL ParticipantMessage of a participant renews its
    /// MANUAL_BY_PARTICIPANT writers (RTPS v2.5 Sec.8.4.13.5); an
    /// AUTOMATIC one, or one that names another participant than its
    /// sender, renews no manual lease.
    #[test]
    fn a_manual_participant_message_renews_its_manual_writers() {
        use crate::protocol::rtps::participant_message::{
            encode_participant_message_data, KIND_AUTOMATIC, KIND_MANUAL,
        };
        let h = Harness::new();
        let liveliness = h.dispatch.liveliness.clone().expect("fixture liveliness");
        let (_automatic, manual) = liveliness.remote(SENDER_PREFIX);
        let feed = |kind, named: [u8; 12]| {
            let cdr = encode_participant_message_data(&named, kind);
            let datagram = data_datagram(SENDER_PREFIX, &PARTICIPANT_MESSAGE, &cdr);
            let (pk, at, meta, _ctx) =
                crate::core::discovery::multicast::classifier::classify_rtps(&datagram);
            assert_eq!(pk, PacketKind::ParticipantMessage);
            h.feed(pk, &datagram, at.unwrap_or(SAMPLE_AT), meta);
        };
        let before = manual.last();
        std::thread::sleep(std::time::Duration::from_millis(2));
        feed(KIND_AUTOMATIC, SENDER_PREFIX);
        assert_eq!(manual.last(), before, "AUTOMATIC: no manual lease");
        let mut other = SENDER_PREFIX;
        other[0] ^= 0xFF;
        feed(KIND_MANUAL, other);
        assert_eq!(manual.last(), before, "another participant's assertion");
        feed(KIND_MANUAL, SENDER_PREFIX);
        assert!(manual.last() > before, "renewed");
    }

    /// The SHAPE of the submessage decides, not the kind of its writer.
    ///
    /// The classifier names a submessage after its WRITER, so a fragment of an
    /// SPDP announcement arrives here carrying kind SPDP - never DataFrag.
    /// Asking the kind first therefore handed one fragment to the parser as if
    /// it were a whole announcement, and what came out was a participant built
    /// from half its bytes: the right GUID, then a 100-second lease and domain
    /// 0 that are constants in the partial parser, no locator - so nothing
    /// could be routed to that peer - and no identity token, so under
    /// `require_authentication` it was rejected outright.
    ///
    /// The assertions are on VALUES rather than on a count, because the defect
    /// did not lose the participant: it replaced its fields with constants.
    #[test]
    fn a_fragment_named_spdp_by_its_writer_still_goes_to_reassembly() {
        let (announced, cdr) = announcement_from(SENDER_PREFIX);
        let (one, two, meta_one, meta_two) = two_fragments(SENDER_PREFIX, &SPDP, &cdr);

        // The discriminating field is the lease, and it must really lie past
        // the cut - otherwise this test passes without fragment 2 ever being
        // read. `build_spdp` decides the parameter order, so prove it here.
        let cut = fragment_cut(cdr.len());
        let lease_at = pid_offset(&cdr, 0x0002).expect("the announcement carries a lease");
        assert!(
            lease_at >= cut,
            "PID_PARTICIPANT_LEASE_DURATION sits at {lease_at}, before the cut at {cut}: \
             this fixture would pass without ever reading the second fragment"
        );

        let h = Harness::new();

        h.feed(PacketKind::SPDP, &one, FRAGMENT_AT, Some(meta_one));
        assert_eq!(
            h.dispatch.fsm.participant_count(),
            0,
            "one fragment is not an announcement, whatever kind the classifier \
             read off its writer"
        );

        h.feed(PacketKind::SPDP, &two, FRAGMENT_AT, Some(meta_two));
        let found = h.dispatch.fsm.get_participants();
        assert_eq!(
            found.len(),
            1,
            "the reassembled announcement names one peer"
        );
        let peer = &found[0];
        assert_eq!(peer.guid, announced.participant_guid);
        assert_eq!(
            peer.lease_duration_ms, 30_000,
            "the lease comes off the wire, not from the partial parser's 100 s constant"
        );
        assert_eq!(
            peer.endpoints, announced.metatraffic_unicast_locators,
            "the announced locator survives; an empty list here is what made the \
             receiver infer one from the source address"
        );
    }

    /// And the other half of the same rule: an announcement that FITS is read
    /// where it always was.
    ///
    /// Without this, "route on the shape" cannot be told from "always
    /// reassemble" - which would strand every unfragmented peer in a buffer
    /// waiting for a second fragment that is never coming.
    #[test]
    fn an_announcement_that_fits_one_datagram_is_read_at_once() {
        let (announced, cdr) = announcement_from(SENDER_PREFIX);
        let whole = data_datagram(SENDER_PREFIX, &SPDP, &cdr);
        let h = Harness::new();

        h.feed(PacketKind::SPDP, &whole, SAMPLE_AT, None);

        let found = h.dispatch.fsm.get_participants();
        assert_eq!(found.len(), 1, "a complete announcement names its peer now");
        assert_eq!(found[0].guid, announced.participant_guid);
        assert_eq!(
            found[0].lease_duration_ms, 30_000,
            "read from the wire, not from a partial parser"
        );
    }
    /// RTPS 2.5 8.3.4 / 8.3.8.10: the SPDP handler infers a metatraffic
    /// locator from the datagram's source address when the announcement
    /// carries none of its own -- but only when that address is a real
    /// reply locator. Behind an INFO_SRC it is only the forwarder's, and
    /// inferring from it would aim every reply at the relay instead of the
    /// participant the announcement names.
    /// RTPS v2.5 Sec.9.6.4.9: a participant that announces its departure
    /// (the dispose of its DCPSParticipant instance, no payload) leaves
    /// discovery through the same door its announcement came in by.
    #[test]
    fn a_participant_that_announces_its_departure_leaves_discovery() {
        let (_, cdr) = announcement_from(SENDER_PREFIX);
        let datagram = data_datagram(SENDER_PREFIX, &SPDP, &cdr);
        let harness = Harness::new();
        harness.feed(PacketKind::SPDP, &datagram, SAMPLE_AT, None);
        assert_eq!(
            harness.dispatch.fsm.get_participants().len(),
            1,
            "announced"
        );

        let departure = crate::core::discovery::multicast::build_spdp_dispose_packet(
            &crate::core::discovery::GUID::new(SENDER_PREFIX, [0x00, 0x00, 0x01, 0xC1]),
            9,
        );
        let mut at = None;
        crate::core::discovery::multicast::classifier::for_each_data_submessage(
            &departure,
            |data| at = Some(data.payload_offset),
        );
        harness.feed(PacketKind::SPDP, &departure, at.expect("one DATA"), None);
        assert!(
            harness.dispatch.fsm.get_participants().is_empty(),
            "the departure retired the participant"
        );
    }

    /// The key-only form (OpenDDS, Cyclone DDS to a reader that asks for no
    /// key hash) retires the participant too, through the same door, and is
    /// not read as an announcement that would keep it for 100 s.
    #[test]
    fn a_key_only_departure_leaves_discovery_too() {
        let (_, cdr) = announcement_from(SENDER_PREFIX);
        let datagram = data_datagram(SENDER_PREFIX, &SPDP, &cdr);
        let harness = Harness::new();
        harness.feed(PacketKind::SPDP, &datagram, SAMPLE_AT, None);
        assert_eq!(
            harness.dispatch.fsm.get_participants().len(),
            1,
            "announced"
        );

        let participant = crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 1, 0xC1]);
        let mut departure = Vec::new();
        departure.extend_from_slice(b"RTPS");
        departure.extend_from_slice(&[0x02, 0x04, 0x01, 0x03]);
        departure.extend_from_slice(&SENDER_PREFIX);
        // octetsToNextHeader 60: 20 + inline QoS 12 + serialized key 28.
        departure.extend_from_slice(&[0x15, 0x0b, 0x3c, 0x00, 0x00, 0x00, 0x10, 0x00]);
        departure.extend_from_slice(&[0x00, 0x01, 0x00, 0xc7, 0x00, 0x01, 0x00, 0xc2]);
        departure.extend_from_slice(&[0, 0, 0, 0, 9, 0, 0, 0]);
        departure.extend_from_slice(&[0x71, 0x00, 0x04, 0x00, 0, 0, 0, 0x03, 0x01, 0, 0, 0]);
        departure.extend_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x50, 0x00, 0x10, 0x00]);
        departure.extend_from_slice(&participant.as_bytes());
        departure.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let mut at = None;
        crate::core::discovery::multicast::classifier::for_each_data_submessage(
            &departure,
            |data| at = Some(data.payload_offset),
        );
        harness.feed(PacketKind::SPDP, &departure, at.expect("one DATA"), None);
        assert!(
            harness.dispatch.fsm.get_participants().is_empty(),
            "the key-only departure retired the participant"
        );
    }

    /// A participant that has said its farewell (`DiscoveryFsm::depart`)
    /// answers no announcement, whole or reassembled from fragments: either
    /// would be answered with an immediate SPDP reply and SEDP
    /// re-announcements, and the receiver would take us back for a lease.
    #[test]
    fn a_departed_participant_answers_no_announcement() {
        let (_, cdr) = announcement_from(SENDER_PREFIX);
        let whole = data_datagram(SENDER_PREFIX, &SPDP, &cdr);
        let (one, two, meta_one, meta_two) = two_fragments(SENDER_PREFIX, &SPDP, &cdr);

        let whole_h = Harness::new();
        whole_h.dispatch.fsm.depart();
        whole_h.feed(PacketKind::SPDP, &whole, SAMPLE_AT, None);
        assert_eq!(whole_h.dispatch.fsm.participant_count(), 0, "whole");

        let frag_h = Harness::new();
        frag_h.dispatch.fsm.depart();
        frag_h.feed(PacketKind::SPDP, &one, FRAGMENT_AT, Some(meta_one));
        frag_h.feed(PacketKind::SPDP, &two, FRAGMENT_AT, Some(meta_two));
        assert_eq!(
            frag_h.dispatch.fsm.participant_count(),
            0,
            "reassembled (`a_fragment_named_spdp_by_its_writer_still_goes_to_reassembly` \
             is the same feed, answered, before the farewell)"
        );
    }

    /// A participant that never ran the handshake with us: same domain, a
    /// prefix above ours like `SENDER_PREFIX`, no session.
    #[cfg(feature = "security")]
    const UNAUTHENTICATED_PREFIX: [u8; 12] = [0xCC; 12];

    /// The kind and offset the listener hands a datagram to discovery with
    /// (`MulticastListener` dispatch): a DDS-Security protected submessage
    /// at its SEC_PREFIX, as `SecureSEDP`; anything else as the classifier
    /// names it.
    #[cfg(feature = "security")]
    fn listener_delivery(
        datagram: &[u8],
    ) -> (
        PacketKind,
        usize,
        Option<crate::core::discovery::multicast::FragmentMetadata>,
    ) {
        if let Some(at) = crate::security::crypto::secure_submessage::first_secure_prefix(datagram)
        {
            return (PacketKind::SecureSEDP, at, None);
        }
        let (kind, at, meta, _) =
            crate::core::discovery::multicast::classifier::classify_rtps(datagram);
        (kind, at.unwrap_or(SAMPLE_AT), meta)
    }

    /// A dispatch whose FSM holds a `Complete` handshake with
    /// `SENDER_PREFIX` (a real one, `test_pki`), and which keeps unicast SPDP
    /// destinations, so the lease-0 path's peer bookkeeping is observable.
    #[cfg(feature = "security")]
    fn authenticated_harness() -> Harness {
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
        h.dispatch.discovered_peers = Some(Arc::new(crate::core::discovery::SpdpPeerSet::new()));
        h
    }

    /// The three plain-topic forms of `prefix`'s departure, each with the
    /// offset the classifier hands the handler: DATA(p[UD]) with a key hash,
    /// the key-only DATA(p[UD]), and the 1.4.x announcement with a lease of 0.
    #[cfg(feature = "security")]
    fn plain_departures(prefix: [u8; 12]) -> Vec<(&'static str, Vec<u8>, usize)> {
        let participant = crate::core::discovery::GUID::new(prefix, [0, 0, 1, 0xC1]);
        let key_hash =
            crate::core::discovery::multicast::build_spdp_dispose_packet(&participant, 9);

        let mut key_only = Vec::new();
        key_only.extend_from_slice(b"RTPS");
        key_only.extend_from_slice(&[0x02, 0x04, 0x01, 0x03]);
        key_only.extend_from_slice(&prefix);
        key_only.extend_from_slice(&[0x15, 0x0b, 0x3c, 0x00, 0x00, 0x00, 0x10, 0x00]);
        key_only.extend_from_slice(&[0x00, 0x01, 0x00, 0xc7, 0x00, 0x01, 0x00, 0xc2]);
        key_only.extend_from_slice(&[0, 0, 0, 0, 10, 0, 0, 0]);
        key_only.extend_from_slice(&[0x71, 0x00, 0x04, 0x00, 0, 0, 0, 0x03, 0x01, 0, 0, 0]);
        key_only.extend_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x50, 0x00, 0x10, 0x00]);
        key_only.extend_from_slice(&participant.as_bytes());
        key_only.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        let (mut farewell, _) = announcement_from(prefix);
        farewell.lease_duration_ms = 0;
        let lease_zero =
            crate::core::discovery::multicast::build_spdp_rtps_packet(&farewell, 11, None)
                .expect("a lease-0 announcement");

        [
            ("key hash", key_hash),
            ("key only", key_only),
            ("lease 0", lease_zero),
        ]
        .into_iter()
        .map(|(form, datagram)| {
            let mut at = None;
            crate::core::discovery::multicast::classifier::for_each_data_submessage(
                &datagram,
                |data| at = Some(data.payload_offset),
            );
            (form, datagram, at.expect("one DATA"))
        })
        .collect()
    }

    /// DDS Security v1.1 Sec.7.4.1.6: once authentication has completed, a
    /// participant ignores the dispose messages it receives on the plain
    /// DCPSParticipants topic from the authenticated participant. Anyone
    /// can send one under its prefix; honoured, one datagram removed an
    /// authenticated peer. None of the three forms retires it, nor takes it
    /// off the unicast SPDP destinations.
    #[cfg(feature = "security")]
    #[test]
    fn a_plain_departure_does_not_retire_an_authenticated_participant() {
        let h = authenticated_harness();
        let (_, cdr) = announcement_from(SENDER_PREFIX);
        h.feed(
            PacketKind::SPDP,
            &data_datagram(SENDER_PREFIX, &SPDP, &cdr),
            SAMPLE_AT,
            None,
        );
        let peers = h.dispatch.discovered_peers.clone().expect("peers");
        assert!(
            h.dispatch.fsm.is_participant_known(&SENDER_PREFIX),
            "fixture"
        );
        assert_eq!(peers.snapshot().len(), 1, "fixture: a unicast destination");

        for (form, datagram, at) in plain_departures(SENDER_PREFIX) {
            h.feed(PacketKind::SPDP, &datagram, at, None);
            assert!(
                h.dispatch.fsm.is_participant_known(&SENDER_PREFIX),
                "{form}: an authenticated participant does not leave by the plain topic"
            );
            assert_eq!(
                peers.snapshot().len(),
                1,
                "{form}: still a unicast SPDP destination"
            );
        }
    }

    /// The other side of the same rule: the departure of a participant that
    /// never authenticated is applied as before, in each form, by the same
    /// dispatch whose FSM holds a session with somebody else.
    #[cfg(feature = "security")]
    #[test]
    fn a_plain_departure_still_retires_a_participant_that_never_authenticated() {
        let (_, cdr) = announcement_from(UNAUTHENTICATED_PREFIX);
        let announcement = data_datagram(UNAUTHENTICATED_PREFIX, &SPDP, &cdr);
        for (form, datagram, at) in plain_departures(UNAUTHENTICATED_PREFIX) {
            let h = authenticated_harness();
            h.feed(PacketKind::SPDP, &announcement, SAMPLE_AT, None);
            assert!(
                h.dispatch.fsm.is_participant_known(&UNAUTHENTICATED_PREFIX),
                "{form}: fixture"
            );
            h.feed(PacketKind::SPDP, &datagram, at, None);
            assert!(
                !h.dispatch.fsm.is_participant_known(&UNAUTHENTICATED_PREFIX),
                "{form}: retired"
            );
            assert!(
                h.dispatch
                    .discovered_peers
                    .as_ref()
                    .expect("peers")
                    .snapshot()
                    .is_empty(),
                "{form}: no longer a unicast SPDP destination"
            );
        }
    }

    /// `SENDER_PREFIX`'s announcement as `announcement_from` makes it, moved:
    /// other locators, another lease and another vendor id.
    #[cfg(feature = "security")]
    fn a_moved_announcement(prefix: [u8; 12], lease_duration_ms: u64) -> Vec<u8> {
        let (mut moved, _) = announcement_from(prefix);
        moved.metatraffic_unicast_locators = vec!["198.51.100.9:7410".parse().expect("addr")];
        moved.default_unicast_locators = vec!["198.51.100.9:7411".parse().expect("addr")];
        moved.lease_duration_ms = lease_duration_ms;
        moved.vendor_id = Some(0x0101);
        let mut cdr = vec![0u8; 8192];
        let n = crate::protocol::discovery::build_spdp(&moved, &mut cdr).expect("build");
        cdr.truncate(n);
        cdr
    }

    /// What the dispatch holds about `SENDER_PREFIX`.
    #[cfg(feature = "security")]
    #[derive(Debug, PartialEq)]
    struct Held {
        /// Its admitted metatraffic locators and lease.
        admitted: Option<(Vec<std::net::SocketAddr>, u64)>,
        /// Its unicast locator in the endpoint registry.
        unicast: Option<std::net::SocketAddr>,
        vendor_id: Option<u16>,
        /// The SPDP destinations.
        destinations: Vec<std::net::SocketAddr>,
    }

    #[cfg(feature = "security")]
    fn what_is_held(h: &Harness) -> Held {
        let participant = crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 1, 0xC1]);
        Held {
            admitted: h.dispatch.fsm.admitted_locators_and_lease(&SENDER_PREFIX),
            unicast: h.dispatch.fsm.endpoint_registry().get(&participant),
            vendor_id: h.dispatch.fsm.vendor_id_for_participant(&participant),
            destinations: h
                .dispatch
                .discovered_peers
                .as_ref()
                .expect("peers")
                .snapshot(),
        }
    }

    /// DDS Security v1.1 Sec.7.4.1.6: once authenticated, a participant's
    /// plain announcements maintain its liveliness and change nothing else.
    /// One that moves it - other locators, an infinite lease, another vendor
    /// id - leaves its locators, its unicast address, its vendor id and its
    /// SPDP destination where they were, whole or reassembled from
    /// fragments. A datagram under its prefix must not redirect the
    /// handshake, the keys and the user data sent to it.
    #[cfg(feature = "security")]
    #[test]
    fn a_plain_announcement_does_not_move_an_authenticated_participant() {
        let (_, cdr) = announcement_from(SENDER_PREFIX);
        let first = data_datagram(SENDER_PREFIX, &SPDP, &cdr);
        let moved = a_moved_announcement(SENDER_PREFIX, u64::MAX);
        let whole = data_datagram(SENDER_PREFIX, &SPDP, &moved);
        let (one, two, meta_one, meta_two) = two_fragments(SENDER_PREFIX, &SPDP, &moved);

        for form in ["whole", "fragments"] {
            let h = authenticated_harness();
            h.feed(PacketKind::SPDP, &first, SAMPLE_AT, None);
            let before = what_is_held(&h);
            assert_eq!(
                before.admitted,
                Some((vec!["192.0.2.7:7410".parse().expect("addr")], 30_000)),
                "fixture"
            );
            assert_eq!(
                before.destinations.len(),
                1,
                "fixture: one SPDP destination"
            );

            if form == "whole" {
                h.feed(PacketKind::SPDP, &whole, SAMPLE_AT, None);
            } else {
                h.feed(PacketKind::SPDP, &one, FRAGMENT_AT, Some(meta_one));
                h.feed(PacketKind::SPDP, &two, FRAGMENT_AT, Some(meta_two));
            }
            assert_eq!(
                what_is_held(&h),
                before,
                "{form}: the announcement moved it"
            );
        }
    }

    /// The SPDP destination of an authenticated participant lives by its
    /// liveliness: a plain announcement keeps it, at the admitted locators,
    /// for the admitted lease.
    #[cfg(feature = "security")]
    #[test]
    fn an_authenticated_participants_destination_lives_by_its_liveliness() {
        let h = authenticated_harness();
        let short = a_moved_announcement(SENDER_PREFIX, 200);
        // Admitted at 198.51.100.9 for 200 ms.
        h.feed(
            PacketKind::SPDP,
            &data_datagram(SENDER_PREFIX, &SPDP, &short),
            SAMPLE_AT,
            None,
        );
        let peers = h.dispatch.discovered_peers.clone().expect("peers");
        let admitted = peers.snapshot();
        assert_eq!(admitted.len(), 1, "fixture");

        std::thread::sleep(std::time::Duration::from_millis(120));
        let (_, elsewhere) = announcement_from(SENDER_PREFIX);
        h.feed(
            PacketKind::SPDP,
            &data_datagram(SENDER_PREFIX, &SPDP, &elsewhere),
            SAMPLE_AT,
            None,
        );
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert_eq!(
            peers.snapshot(),
            admitted,
            "the destination must be kept alive, where it was admitted"
        );
    }

    /// A writer announcement of `prefix`, the serialized sample: `topic`,
    /// reached at `locator`.
    #[cfg(feature = "security")]
    fn a_writer_sample(prefix: [u8; 12], topic: &str, locator: &str) -> Vec<u8> {
        writer_sample(prefix, topic, "ShapeType", locator, None)
    }

    /// The same, with every field the caller's.
    #[cfg(feature = "security")]
    fn writer_sample(
        prefix: [u8; 12],
        topic: &str,
        type_name: &str,
        locator: &str,
        qos: Option<&crate::protocol::dialect::QosProfile>,
    ) -> Vec<u8> {
        use crate::protocol::dialect::{build_sedp_for_dialect, Dialect, Guid, SedpEndpointData};
        let locators: Vec<std::net::SocketAddr> = vec![locator.parse().expect("addr")];
        build_sedp_for_dialect(
            Dialect::Hdds,
            &SedpEndpointData {
                endpoint_guid: Guid {
                    prefix,
                    entity_id: [0x00, 0x00, 0x12, 0x02],
                },
                participant_guid: Guid {
                    prefix,
                    entity_id: [0x00, 0x00, 0x01, 0xc1],
                },
                topic_name: topic,
                type_name,
                unicast_locators: &locators,
                multicast_locators: &[],
                qos,
                type_object: None,
                user_data: None,
                hdds_shm_capability: None,
                hdds_peer_destination: false,
                group_entity_id: None,
                type_consistency: None,
                #[cfg(feature = "xtypes-structural-assignability")]
                type_information: None,
                emit_type_object_pid: true,
            },
        )
        .expect("build the announcement")
    }

    /// The same rule for an authenticated participant's endpoints, at the
    /// SEDP handler: a plain re-announcement of one of its writers under
    /// another topic and at another locator is refused before anything is
    /// registered from it - the topic its samples are routed to and the
    /// locator our ACKNACKs go to stay as admitted. The same re-announcement
    /// from a participant that never authenticated is taken, as before.
    #[cfg(feature = "security")]
    #[test]
    fn a_plain_reannouncement_does_not_move_an_authenticated_participants_writer() {
        for (prefix, authenticated) in [(SENDER_PREFIX, true), (UNAUTHENTICATED_PREFIX, false)] {
            let h = authenticated_harness();
            let (_, spdp) = announcement_from(prefix);
            h.feed(
                PacketKind::SPDP,
                &data_datagram(prefix, &SPDP, &spdp),
                SAMPLE_AT,
                None,
            );
            let writer = crate::core::discovery::GUID::new(prefix, [0x00, 0x00, 0x12, 0x02]);
            let feed = |datagram: Vec<u8>| {
                let (kind, at, meta, _) =
                    crate::core::discovery::multicast::classifier::classify_rtps(&datagram);
                h.feed(kind, &datagram, at.unwrap_or(SAMPLE_AT), meta);
            };
            let held = || {
                (
                    h.dispatch.registry.get_topic_by_guid(&writer.as_bytes()),
                    h.dispatch
                        .fsm
                        .endpoint_registry()
                        .get_writer_locator(&writer),
                )
            };

            let whole = |topic: &str, locator: &str| {
                data_datagram(
                    prefix,
                    &SEDP_PUBLICATIONS,
                    &a_writer_sample(prefix, topic, locator),
                )
            };
            feed(whole("Square", "192.0.2.7:7411"));
            let admitted = (
                Some("Square".to_string()),
                Some("192.0.2.7:7411".parse().expect("addr")),
            );
            assert_eq!(held(), admitted, "fixture");

            if authenticated {
                // Reassembled from fragments: the same refusal.
                let sample = a_writer_sample(prefix, "Triangle", "203.0.113.5:7411");
                let (one, two, meta_one, meta_two) =
                    two_fragments(prefix, &SEDP_PUBLICATIONS, &sample);
                h.feed(PacketKind::SEDP, &one, FRAGMENT_AT, Some(meta_one));
                h.feed(PacketKind::SEDP, &two, FRAGMENT_AT, Some(meta_two));
                assert_eq!(
                    held(),
                    admitted,
                    "reassembled: an authenticated peer's writer was moved"
                );
            }

            feed(whole("Circle", "198.51.100.9:7411"));
            if authenticated {
                assert_eq!(held(), admitted, "an authenticated peer's writer was moved");
            } else {
                assert_eq!(
                    held(),
                    (
                        Some("Circle".to_string()),
                        Some("198.51.100.9:7411".parse().expect("addr"))
                    ),
                    "a participant that never authenticated is followed as before"
                );
            }
        }
    }

    /// The rest of the same rule (DDS Security v1.1 Sec.7.4.1.7, 7.4.1.8): a
    /// plain re-announcement of an authenticated participant's writer that
    /// keeps its topic and locator but changes its QoS or its type, and a
    /// plain dispose of it, change nothing (one extra
    /// PID_OWNERSHIP_STRENGTH would block the writer at the router for good,
    /// and a dispose would unmatch it). The dispose the participant seals on the
    /// secure topic is applied.
    #[cfg(feature = "security")]
    #[test]
    fn plain_changes_and_disposes_of_an_authenticated_participants_writer_change_nothing() {
        use crate::core::discovery::multicast::SedpEndpointKind;
        use crate::protocol::dialect::Dialect;
        // The control: the same datagrams from a participant that never
        // authenticated do change it, so the probe is a real one.
        for (prefix, authenticated) in [(SENDER_PREFIX, true), (UNAUTHENTICATED_PREFIX, false)] {
            let h = authenticated_harness();
            let (_, spdp) = announcement_from(prefix);
            h.feed(
                PacketKind::SPDP,
                &data_datagram(prefix, &SPDP, &spdp),
                SAMPLE_AT,
                None,
            );
            // A local reader on the topic, so that an ownership change has
            // something to be incompatible with: its entry in the match
            // registry, which judges each (writer, reader) pair.
            let reg = std::sync::Arc::new(
                crate::dds::match_notification::MatchNotificationRegistry::new(
                    &h.dispatch.fsm,
                    OUR_PREFIX,
                ),
            );
            h.dispatch.fsm.set_match_registry(reg.clone());
            let reader = reg.register_reader_with_lifespan(
                "Square".into(),
                crate::dds::QoS::default(),
                crate::dds::cdr_negotiation::Xcdr1Encoding::native(),
                None,
                |_, _, _, _, _| {},
                None,
                None,
                None,
                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
                crate::transport::shm::ShmPolicy::default(),
            );
            let writer = crate::core::discovery::GUID::new(prefix, [0x00, 0x00, 0x12, 0x02]);
            let feed = |datagram: &[u8]| {
                let (kind, at, meta) = listener_delivery(datagram);
                h.feed(kind, datagram, at, meta);
            };
            let publish = |sample: Vec<u8>| data_datagram(prefix, &SEDP_PUBLICATIONS, &sample);
            feed(&publish(writer_sample(
                prefix,
                "Square",
                "ShapeType",
                "192.0.2.7:7411",
                None,
            )));
            assert!(
                h.dispatch.fsm.current_endpoint("Square", &writer).is_some(),
                "fixture: admitted"
            );
            let refused = || reg.is_writer_refused_by(&writer.as_bytes(), reader.id());
            assert!(!refused(), "fixture");

            // Same topic, type and locator; EXCLUSIVE ownership, strength 7.
            let exclusive = crate::protocol::dialect::QosProfile {
                ownership_kind: 1,
                ownership_strength: 7,
                ..Default::default()
            };
            feed(&publish(writer_sample(
                prefix,
                "Square",
                "ShapeType",
                "192.0.2.7:7411",
                Some(&exclusive),
            )));
            assert_eq!(
                refused(),
                !authenticated,
                "authenticated {}: a plain EXCLUSIVE ownership refuses the writer to the reader",
                authenticated
            );

            feed(&publish(writer_sample(
                prefix,
                "Square",
                "OtherType",
                "192.0.2.7:7411",
                None,
            )));
            let type_name = h
                .dispatch
                .fsm
                .current_endpoint("Square", &writer)
                .expect("known")
                .type_name;
            assert_eq!(
                type_name == "ShapeType",
                authenticated,
                "authenticated {}: a plain announcement changes the type ({})",
                authenticated,
                type_name
            );

            // After the announcements (`data_datagram` numbers them 7): the
            // dispose is the writer's next change.
            let dispose = crate::core::discovery::multicast::build_sedp_dispose_packet(
                &writer,
                SedpEndpointKind::Writer,
                &prefix,
                Some(&OUR_PREFIX),
                8,
                Dialect::Hdds,
            );
            feed(&dispose);
            assert_eq!(
                h.dispatch.fsm.current_endpoint("Square", &writer).is_some(),
                authenticated,
                "authenticated {}: a plain dispose unmatches the writer",
                authenticated
            );

            if authenticated {
                // The participant's own dispose, sealed as it seals, in the
                // shape it announced.
                let sealed = crate::security::crypto::secure_sedp::protect_sedp_packet(
                    &dispose,
                    &h.dispatch.fsm.sender_sedp_keys_for_tests(prefix),
                )
                .expect("sealed");
                feed(&sealed);
                assert!(
                    h.dispatch.fsm.current_endpoint("Square", &writer).is_none(),
                    "the sealed dispose is applied"
                );
            }
        }
    }

    /// DDS-Security v1.1 Sec.9.4.1.2.5.4 requires submessage protection.
    /// SPDP capabilities cannot permit a payload-only shape.
    #[cfg(feature = "security")]
    #[test]
    fn a_secure_dispose_requires_submessage_protection_whatever_spdp_announces() {
        use crate::core::discovery::multicast::SedpEndpointKind;
        use crate::protocol::dialect::Dialect;
        use crate::security::crypto::secure_sedp::protect_sedp_packet;
        for (vendor_id, caps) in [
            (Some(0x0112), None),
            (
                Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
                Some(crate::protocol::group::LOCAL_CAPABILITIES),
            ),
            (Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16), None),
        ] {
            for legacy in [false, true] {
                let h = authenticated_harness();
                let (mut data, _) = announcement_from(SENDER_PREFIX);
                data.vendor_id = vendor_id;
                data.hdds_capabilities = caps;
                let mut spdp = vec![0u8; 8192];
                let n = crate::protocol::discovery::build_spdp(&data, &mut spdp).expect("build");
                spdp.truncate(n);
                // `build_spdp` writes our own PID_VENDORID (0x0016); the
                // announcement of another vendor carries its own.
                let vendor_at = spdp
                    .windows(6)
                    .position(|w| w == [0x16, 0x00, 0x04, 0x00, 0x01, 0x1a])
                    .expect("fixture: PID_VENDORID")
                    + 4;
                spdp[vendor_at..vendor_at + 2]
                    .copy_from_slice(&vendor_id.expect("fixture").to_be_bytes());
                h.feed(
                    PacketKind::SPDP,
                    &data_datagram(SENDER_PREFIX, &SPDP, &spdp),
                    SAMPLE_AT,
                    None,
                );
                let writer =
                    crate::core::discovery::GUID::new(SENDER_PREFIX, [0x00, 0x00, 0x12, 0x02]);
                let feed = |datagram: &[u8]| {
                    let (kind, at, meta) = listener_delivery(datagram);
                    h.feed(kind, datagram, at, meta);
                };
                feed(&data_datagram(
                    SENDER_PREFIX,
                    &SEDP_PUBLICATIONS,
                    &writer_sample(SENDER_PREFIX, "Square", "ShapeType", "192.0.2.7:7411", None),
                ));
                assert!(
                    h.dispatch.fsm.current_endpoint("Square", &writer).is_some(),
                    "fixture: admitted"
                );

                let dispose = crate::core::discovery::multicast::build_sedp_dispose_packet(
                    &writer,
                    SedpEndpointKind::Writer,
                    &SENDER_PREFIX,
                    Some(&OUR_PREFIX),
                    2,
                    Dialect::Hdds,
                );
                let sealed = if legacy {
                    // The retired wire shape: only the body is encrypted, with
                    // PID_STATUS_INFO hidden where inline QoS should be.
                    let key = [0x33; 32];
                    let nonce = [0x44; 12];
                    let id = 0x6365_7353_5043_4553u64;
                    let (writer_at, body_at) =
                        crate::security::crypto::secure_sedp::find_data_cdr_bounds(&dispose)
                            .expect("DATA frame");
                    let data_at = writer_at - 12;
                    assert_eq!(&dispose[writer_at..writer_at + 4], &[0, 0, 3, 0xc2]);
                    let ciphertext = crate::security::crypto::AesGcmCipher::new(&key)
                        .unwrap()
                        .encrypt(&dispose[body_at..], &nonce, &id.to_le_bytes())
                        .unwrap();
                    let mut wire = dispose[..body_at].to_vec();
                    wire[writer_at] = 0xff;
                    wire.extend_from_slice(&id.to_le_bytes());
                    wire.extend_from_slice(&nonce);
                    wire.extend_from_slice(&ciphertext);
                    let length = u16::try_from(wire.len() - data_at - 4).unwrap();
                    wire[data_at + 2..data_at + 4].copy_from_slice(&length.to_le_bytes());
                    Some(wire)
                } else {
                    protect_sedp_packet(
                        &dispose,
                        &h.dispatch.fsm.receive_sedp_writer_keys_for_tests(
                            SENDER_PREFIX,
                            crate::security::crypto::secure_submessage::Transformation::Aes256Gcm,
                        ),
                    )
                }
                .expect("sealed");
                feed(&sealed);
                let applied = h.dispatch.fsm.current_endpoint("Square", &writer).is_none();
                assert_eq!(
                    applied, !legacy,
                    "vendor {:?} capabilities {:?}, legacy shape {}",
                    vendor_id, caps, legacy
                );
            }
        }
    }

    /// A dispose older than the announcement applied about its endpoint is
    /// stale and changes nothing; the next change does (RTPS v2.5
    /// Sec.8.4.12, `DiscoveryFsm::admits_sedp_change`). Plain topic, a
    /// participant that never authenticated.
    #[cfg(feature = "security")]
    #[test]
    fn a_dispose_older_than_the_announcement_applied_changes_nothing() {
        use crate::core::discovery::multicast::SedpEndpointKind;
        use crate::protocol::dialect::Dialect;
        let h = Harness::new();
        let (_, spdp) = announcement_from(SENDER_PREFIX);
        h.feed(
            PacketKind::SPDP,
            &data_datagram(SENDER_PREFIX, &SPDP, &spdp),
            SAMPLE_AT,
            None,
        );
        let writer = crate::core::discovery::GUID::new(SENDER_PREFIX, [0x00, 0x00, 0x12, 0x02]);
        let feed = |datagram: &[u8]| {
            let (kind, at, meta, _) =
                crate::core::discovery::multicast::classifier::classify_rtps(datagram);
            h.feed(kind, datagram, at.unwrap_or(SAMPLE_AT), meta);
        };
        // `data_datagram` numbers it 7.
        feed(&data_datagram(
            SENDER_PREFIX,
            &SEDP_PUBLICATIONS,
            &writer_sample(SENDER_PREFIX, "Square", "ShapeType", "192.0.2.7:7411", None),
        ));
        assert!(
            h.dispatch.fsm.current_endpoint("Square", &writer).is_some(),
            "fixture"
        );
        let dispose = |sn: u64| {
            crate::core::discovery::multicast::build_sedp_dispose_packet(
                &writer,
                SedpEndpointKind::Writer,
                &SENDER_PREFIX,
                Some(&OUR_PREFIX),
                sn,
                Dialect::Hdds,
            )
        };
        feed(&dispose(6));
        assert!(
            h.dispatch.fsm.current_endpoint("Square", &writer).is_some(),
            "an older dispose is stale"
        );
        feed(&dispose(8));
        assert!(h.dispatch.fsm.current_endpoint("Square", &writer).is_none());
    }

    /// A sealed SEDP datagram that does not decrypt under the key we hold is
    /// dropped - unless the peer's keys are changing (a re-authentication
    /// in flight), in which case it was sealed under the new key one message
    /// before we hold it, and is held until the keys settle.
    /// DDS Security v1.1 Sec.7.4.1.6: an authenticated participant's
    /// departure on the plain topic is ignored, and the one it seals on the
    /// secure participant endpoints retires it.
    #[cfg(feature = "security")]
    #[test]
    fn an_authenticated_participant_leaves_by_its_sealed_departure_not_the_plain_one() {
        let mut h = Harness::new();
        let machine = crate::security::test_pki::local_machine_with_completed_peer(
            OUR_PREFIX,
            SENDER_PREFIX,
            None,
        );
        Arc::get_mut(&mut h.dispatch.fsm)
            .expect("the harness is the FSM's only owner")
            .set_handshake_machine(
                Arc::clone(&machine),
                crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
                crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
            );
        std::sync::Arc::get_mut(&mut h.dispatch.fsm)
            .expect("the harness is the FSM's only owner")
            .register_builtin_writer_keys_for_tests();
        let (_, spdp) = announcement_from(SENDER_PREFIX);
        h.feed(
            PacketKind::SPDP,
            &data_datagram(SENDER_PREFIX, &SPDP, &spdp),
            SAMPLE_AT,
            None,
        );
        assert!(
            h.dispatch.fsm.is_participant_known(&SENDER_PREFIX),
            "fixture"
        );
        let sender = crate::core::discovery::GUID::new(
            SENDER_PREFIX,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        let feed = |datagram: &[u8], expected: PacketKind| {
            let (kind, at, meta, _) =
                crate::core::discovery::multicast::classifier::classify_rtps(datagram);
            assert_eq!(kind, expected, "fixture");
            h.feed(kind, datagram, at.unwrap_or(SAMPLE_AT), meta);
        };

        feed(
            &crate::core::discovery::multicast::build_spdp_dispose_packet(&sender, 2),
            PacketKind::SPDP,
        );
        assert!(
            h.dispatch.fsm.is_participant_known(&SENDER_PREFIX),
            "the plain departure of an authenticated participant is ignored"
        );

        // Its secure participant writer's key material, received in its
        // DatawriterCryptoTokens, and the departure it protects with it.
        let (key_id, material) =
            crate::security::crypto::data_keys::WriterKey::mint().expect("mint");
        let sealing = material.submessage_material(key_id);
        let sealed = crate::core::discovery::multicast::fsm::sealed_departure_datagram(
            &sealing,
            sender,
            crate::security::access::ProtectionKind::Encrypt,
        )
        .expect("protected");
        // Before its tokens: held, owed; it does not retire it yet.
        let (kind, at, meta) = listener_delivery(&sealed);
        assert_eq!(kind, PacketKind::SecureSEDP, "fixture: at its SEC_PREFIX");
        h.feed(kind, &sealed, at, meta);
        assert!(
            h.dispatch.fsm.is_participant_known(&SENDER_PREFIX),
            "no key material yet"
        );
        assert!(h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX));
        h.dispatch.fsm.receive_writer_key_for_tests(
            SENDER_PREFIX,
            crate::core::rtps_constants::RTPS_ENTITYID_SPDP_SECURE_WRITER,
            u64::from(key_id),
            material,
        );
        // Handed back once its key is installed, through the dispatch again.
        let replayed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&replayed);
        h.dispatch
            .fsm
            .set_secure_sedp_replay(Box::new(move |kind, datagram, at, _| {
                seen.lock()
                    .expect("lock")
                    .push((kind, datagram.to_vec(), at));
            }));
        h.dispatch.fsm.replay_sedp_awaiting_key(SENDER_PREFIX);
        let replayed = std::mem::take(&mut *replayed.lock().expect("lock"));
        assert_eq!(replayed.len(), 1, "the held departure");
        let (kind, datagram, at) = &replayed[0];
        assert_eq!(datagram, &sealed);
        h.feed(*kind, datagram, *at, None);
        assert!(
            !h.dispatch.fsm.is_participant_known(&SENDER_PREFIX),
            "its sealed departure retires it"
        );
        assert!(!machine.has_session(&sender), "and its session with it");
    }

    /// A secure SEDP DATA protected under a key material whose
    /// DatawriterCryptoTokens have not arrived is owed, not lost
    /// (`secure_sedp`, "SEDP that arrives before the writer's tokens"): held,
    /// then retried when tokens arrive. Known-key traffic proceeds without
    /// waiting for unknown keys; sequence admission prevents a delayed
    /// announcement from undoing a newer authenticated dispose.
    ///
    /// Dropping rather than parking undecodable traffic loses the held
    /// announcement; bypassing sequence admission resurrects the endpoint.
    #[cfg(feature = "security")]
    #[test]
    fn secure_sedp_before_its_writers_tokens_is_held_and_applied_when_they_arrive() {
        use crate::core::discovery::multicast::SedpEndpointKind;
        use crate::protocol::dialect::Dialect;
        use crate::security::crypto::secure_sedp::protect_sedp_packet;
        let h = authenticated_harness();
        let (_, spdp) = announcement_from(SENDER_PREFIX);
        h.feed(
            PacketKind::SPDP,
            &data_datagram(SENDER_PREFIX, &SPDP, &spdp),
            SAMPLE_AT,
            None,
        );
        // The sender's secure SEDP writers' key material, minted and not yet
        // received here.
        let (keys, announced) =
            crate::core::discovery::multicast::fsm::mint_sedp_writer_keys_for_tests(
                crate::security::crypto::secure_submessage::Transformation::Aes256Gcm,
            );
        let writer = crate::core::discovery::GUID::new(SENDER_PREFIX, [0x00, 0x00, 0x12, 0x02]);
        let announce = protect_sedp_packet(
            &data_datagram(
                SENDER_PREFIX,
                &SEDP_PUBLICATIONS,
                &writer_sample(SENDER_PREFIX, "Square", "ShapeType", "192.0.2.7:7411", None),
            ),
            &keys,
        )
        .expect("protect");
        let dispose = protect_sedp_packet(
            &crate::core::discovery::multicast::build_sedp_dispose_packet(
                &writer,
                SedpEndpointKind::Writer,
                &SENDER_PREFIX,
                Some(&OUR_PREFIX),
                8,
                Dialect::Hdds,
            ),
            &keys,
        )
        .expect("protect");
        let feed = |datagram: &[u8]| {
            let (kind, at, meta) = listener_delivery(datagram);
            h.feed(kind, datagram, at, meta);
        };

        feed(&announce);
        assert!(
            h.dispatch.fsm.current_endpoint("Square", &writer).is_none(),
            "no key material yet: not applied"
        );
        assert!(
            h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX),
            "held, owed rather than lost"
        );
        assert!(
            !h.dispatch.fsm.has_parked_sedp(&SENDER_PREFIX),
            "not held as a datagram of a participant whose keys are changing"
        );

        // The plain SEDP of the participant is about other endpoints: not held.
        let open_writer =
            crate::core::discovery::GUID::new(SENDER_PREFIX, [0x00, 0x00, 0x13, 0x02]);
        let mut open_sample =
            writer_sample(SENDER_PREFIX, "Circle", "ShapeType", "192.0.2.7:7411", None);
        // The fixture names its writer 0x00001202; this endpoint is another.
        if let Some(at) = open_sample
            .windows(4)
            .position(|w| w == [0x00, 0x00, 0x12, 0x02])
        {
            open_sample[at..at + 4].copy_from_slice(&[0x00, 0x00, 0x13, 0x02]);
        }
        feed(&data_datagram(
            SENDER_PREFIX,
            &SEDP_PUBLICATIONS,
            &open_sample,
        ));
        assert!(
            h.dispatch
                .fsm
                .current_endpoint("Circle", &open_writer)
                .is_some(),
            "the plain SEDP is not held behind the secure one"
        );

        let replayed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&replayed);
        h.dispatch
            .fsm
            .set_secure_sedp_replay(Box::new(move |kind, datagram, at, origin| {
                seen.lock()
                    .expect("lock")
                    .push((kind, datagram.to_vec(), at, origin));
            }));
        // The later dispose can open immediately after token installation.
        // Replaying the older announcement must not resurrect the endpoint.
        for (entity, key_id, material) in announced {
            h.dispatch
                .fsm
                .receive_writer_key_for_tests(SENDER_PREFIX, entity, key_id, material);
        }
        feed(&dispose);
        assert!(
            h.dispatch.fsm.current_endpoint("Square", &writer).is_none(),
            "fixture: nothing applied yet"
        );
        h.dispatch.fsm.replay_sedp_awaiting_key(SENDER_PREFIX);
        let replayed = std::mem::take(&mut *replayed.lock().expect("lock"));
        assert_eq!(
            replayed.len(),
            1,
            "only the undecodable announcement waited"
        );
        assert_eq!(replayed[0].1, announce);
        assert!(!h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX));
        let (kind, datagram, at, origin) = &replayed[0];
        h.dispatch.dispatch(*kind, datagram, *at, None, *origin);
        assert!(
            h.dispatch.fsm.current_endpoint("Square", &writer).is_none(),
            "an older queued announcement cannot resurrect a disposed endpoint"
        );
    }

    /// A participant the security policy refuses (here: no identity token
    /// where authentication is required) is not made an SPDP destination,
    /// whole or reassembled. The handler did not read the FSM's verdict, and
    /// went on to answer it like any other: a destination for our SPDP, the
    /// discovery handshake, our SEDP in the clear.
    #[cfg(feature = "security")]
    #[test]
    fn a_participant_the_policy_refuses_is_not_answered() {
        struct RefuseAll;
        impl crate::core::discovery::multicast::SecurityValidator for RefuseAll {
            fn validate_identity(
                &self,
                _participant_guid: crate::core::discovery::GUID,
                _identity_token: &[u8],
            ) -> Result<(), String> {
                Err("refused by the test".to_string())
            }
        }
        let (_, cdr) = announcement_from(SENDER_PREFIX);
        let whole = data_datagram(SENDER_PREFIX, &SPDP, &cdr);
        let (one, two, meta_one, meta_two) = two_fragments(SENDER_PREFIX, &SPDP, &cdr);

        for form in ["whole", "fragments"] {
            let mut h = Harness::new();
            Arc::get_mut(&mut h.dispatch.fsm)
                .expect("the harness is the FSM's only owner")
                .set_security_validator(Arc::new(RefuseAll), true);
            h.dispatch.discovered_peers =
                Some(Arc::new(crate::core::discovery::SpdpPeerSet::new()));
            if form == "whole" {
                h.feed(PacketKind::SPDP, &whole, SAMPLE_AT, None);
            } else {
                h.feed(PacketKind::SPDP, &one, FRAGMENT_AT, Some(meta_one));
                h.feed(PacketKind::SPDP, &two, FRAGMENT_AT, Some(meta_two));
            }
            assert!(
                !h.dispatch.fsm.is_participant_known(&SENDER_PREFIX),
                "{form}: fixture, refused"
            );
            assert!(
                h.dispatch
                    .discovered_peers
                    .as_ref()
                    .expect("peers")
                    .snapshot()
                    .is_empty(),
                "{form}: a refused participant was made an SPDP destination"
            );
        }
    }

    #[test]
    fn a_relayed_spdp_with_no_locator_of_its_own_infers_nothing() {
        let (_, cdr) = announcement_without_metatraffic_locator_from(SENDER_PREFIX);
        let datagram = data_datagram(SENDER_PREFIX, &SPDP, &cdr);

        // Direct: the handler infers one from the address it was handed.
        let direct = Harness::new();
        direct.feed_from(
            PacketKind::SPDP,
            &datagram,
            SAMPLE_AT,
            None,
            "198.51.100.9:7410".parse().unwrap(),
        );
        let found = direct.dispatch.fsm.get_participants();
        assert_eq!(found.len(), 1, "a complete announcement names its peer");
        assert_eq!(
            found[0].endpoints.len(),
            1,
            "direct: a metatraffic locator is inferred from the source"
        );
        assert_eq!(
            found[0].endpoints[0].ip(),
            "198.51.100.9".parse::<std::net::IpAddr>().unwrap(),
            "inferred from the address the datagram was actually handed with"
        );

        // Relayed: the same announcement, behind an INFO_SRC naming the same
        // peer, forwarded by a DIFFERENT address. Before RTPS 2.5 8.3.8.10
        // was honoured, this address would have been inferred as the peer's
        // metatraffic locator too.
        let relayed = Harness::new();
        relayed.feed_relayed_from(
            PacketKind::SPDP,
            &datagram,
            SAMPLE_AT,
            None,
            "203.0.113.44:9999".parse().unwrap(),
        );
        let found = relayed.dispatch.fsm.get_participants();
        assert_eq!(found.len(), 1, "the peer is still registered");
        assert!(
            found[0].endpoints.is_empty(),
            "relayed: no metatraffic locator may be inferred from the forwarder's \
             address, got {:?}",
            found[0].endpoints
        );
    }

    /// RTPS 2.5 8.3.8.9: an INFO_REPLY sets the Receiver's reply locator,
    /// which only a Reliable StatelessWriter reads (8.4.8.2.6). It is not a
    /// locator of the participant: an SPDP announcement with no metatraffic
    /// locator of its own, behind an INFO_REPLY naming another address, is
    /// inferred one from its sender exactly as without it, on both doors
    /// (whole and reassembled from fragments).
    #[test]
    fn an_spdp_behind_an_info_reply_does_not_infer_the_locator_it_names() {
        let (_, cdr) = announcement_without_metatraffic_locator_from(SENDER_PREFIX);
        let whole = data_datagram(SENDER_PREFIX, &SPDP, &cdr);
        let (one, two, meta_one, meta_two) = two_fragments(SENDER_PREFIX, &SPDP, &cdr);
        let sender: std::net::SocketAddr = "198.51.100.9:7410".parse().unwrap();
        let named: std::net::SocketAddrV4 = "192.0.2.77:7999".parse().unwrap();
        let origin = Origin::direct(sender).replying_to(Some(named));

        for form in ["whole", "fragments"] {
            let h = Harness::new();
            if form == "whole" {
                h.feed_with_origin(PacketKind::SPDP, &whole, SAMPLE_AT, None, origin);
            } else {
                h.feed_with_origin(PacketKind::SPDP, &one, FRAGMENT_AT, Some(meta_one), origin);
                h.feed_with_origin(PacketKind::SPDP, &two, FRAGMENT_AT, Some(meta_two), origin);
            }
            let found = h.dispatch.fsm.get_participants();
            assert_eq!(found.len(), 1, "{form}: the announcement names its peer");
            assert_eq!(found[0].endpoints.len(), 1, "{form}: one inferred locator");
            assert_eq!(
                found[0].endpoints[0].ip(),
                sender.ip(),
                "{form}: inferred from the sender"
            );
            assert_ne!(
                found[0].endpoints[0],
                std::net::SocketAddr::V4(named),
                "{form}: never the INFO_REPLY locator"
            );
        }
    }

    /// The same rule (RTPS 2.5 8.3.4 / 8.3.8.10), on the OTHER door an SPDP
    /// announcement with no locator of its own can arrive by: reassembled
    /// from fragments (`handle_spdp_from_fragments`'s own inference site).
    /// `a_relayed_spdp_with_no_locator_of_its_own_infers_nothing` above only
    /// ever drives the whole-datagram path; a fragmented announcement never
    /// reaches that function at all.
    #[test]
    fn a_relayed_spdp_reassembled_from_fragments_infers_nothing() {
        let (_, cdr) = announcement_without_metatraffic_locator_from(SENDER_PREFIX);
        let (one, two, meta_one, meta_two) = two_fragments(SENDER_PREFIX, &SPDP, &cdr);
        let forwarder: std::net::SocketAddr = "203.0.113.45:9999".parse().unwrap();

        let relayed = Harness::new();
        relayed.feed_relayed_from(
            PacketKind::SPDP,
            &one,
            FRAGMENT_AT,
            Some(meta_one),
            forwarder,
        );
        relayed.feed_relayed_from(
            PacketKind::SPDP,
            &two,
            FRAGMENT_AT,
            Some(meta_two),
            forwarder,
        );

        let found = relayed.dispatch.fsm.get_participants();
        assert_eq!(
            found.len(),
            1,
            "the reassembled announcement names its peer"
        );
        assert!(
            found[0].endpoints.is_empty(),
            "relayed: no metatraffic locator may be inferred from the forwarder's \
             address, got {:?}",
            found[0].endpoints
        );
    }

    /// A getTypes request too big for one datagram is still a getTypes
    /// request.
    ///
    /// A TypeObject is the largest sample discovery ever carries, so the
    /// fragmented form is the ordinary form here, not an edge case. Since
    /// the classifier learned to name a DATA_FRAG after its WRITER, such a
    /// request arrives with kind TypeLookup and goes to reassembly on its
    /// shape - correctly. What was missing was the other end: the
    /// reassembled sample is dispatched by writer, and the two TypeLookup
    /// writers had no arm there, so every fragmented request was put back
    /// together correctly and then dropped with a log line saying it was
    /// "not a discovery announcement".
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_fragmented_get_types_request_is_answered() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
        peer.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("a read timeout");
        let peer_addr = peer.local_addr().expect("the peer address");

        let h = Harness::serving_the_get_types_request();
        let (one, two, meta_one, meta_two) =
            two_fragments(SENDER_PREFIX, &TYPELOOKUP_REQUEST, &get_types_request());
        let mut buf = [0u8; 4096];

        h.feed_from(
            PacketKind::TypeLookup,
            &one,
            FRAGMENT_AT,
            Some(meta_one),
            peer_addr,
        );
        assert!(
            peer.recv_from(&mut buf).is_err(),
            "half a request is not a request: an answer here would mean fragment 1 \
             was read as if it were whole"
        );

        h.feed_from(
            PacketKind::TypeLookup,
            &two,
            FRAGMENT_AT,
            Some(meta_two),
            peer_addr,
        );
        let (n, from) = peer
            .recv_from(&mut buf)
            .expect("the reassembled request is answered");
        assert_eq!(
            from.ip(),
            peer_addr.ip(),
            "the answer comes back over the loopback it was asked on"
        );
        assert_is_a_get_types_reply_for(&buf[..n], SENDER_PREFIX);
    }

    /// And the other half of the same rule: a request that FITS is answered
    /// where it always was.
    ///
    /// Without this, "a reassembled sample leaves by its writer's door"
    /// cannot be told from "the TypeLookup door was rewired", and a change
    /// that sent every unfragmented request to reassembly - where it would
    /// wait forever for a second fragment - would pass the test above.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn a_get_types_request_that_fits_one_datagram_is_answered_at_once() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a peer socket");
        peer.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("a read timeout");
        let peer_addr = peer.local_addr().expect("the peer address");

        let h = Harness::serving_the_get_types_request();
        let whole = data_datagram(SENDER_PREFIX, &TYPELOOKUP_REQUEST, &get_types_request());

        h.feed_from(PacketKind::TypeLookup, &whole, SAMPLE_AT, None, peer_addr);

        let mut buf = [0u8; 4096];
        let (n, _) = peer
            .recv_from(&mut buf)
            .expect("a complete request is answered now");
        assert_is_a_get_types_reply_for(&buf[..n], SENDER_PREFIX);
    }

    /// The SEDP Topic writer (DCPSTopic, RTPS v2.5 Table 9.1). A BUILTIN
    /// endpoint - entityKind 0xc2 - that this implementation does not have.
    /// Written as a literal, like every other fixture here: there is no
    /// constant for it in the tree, which is the point.
    const SEDP_TOPIC: Endpoints = Endpoints {
        reader: [0x00, 0x00, 0x02, 0xC7],
        writer: [0x00, 0x00, 0x02, 0xC2],
    };

    /// Feed one announcement carried by one writer, and report what the
    /// participant database and the unclaimed-builtin counter say afterwards.
    fn what_a_writer_gets_registered(ep: &Endpoints, sample: &[u8]) -> (PacketKind, usize, u64) {
        let datagram = data_datagram(SENDER_PREFIX, ep, sample);
        let (kind, at, meta, _ctx) =
            crate::core::discovery::multicast::classifier::classify_rtps(&datagram);
        let h = Harness::new();
        h.feed(kind, &datagram, at.unwrap_or(SAMPLE_AT), meta);
        (
            kind,
            h.dispatch.fsm.participant_count(),
            h.dispatch
                .fsm
                .metrics
                .unclaimed_builtin_data
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// A DATA is what its WRITER says it is (RTPS v2.5 Sec.8.3.8.2).
    ///
    /// `handle_data_packet` asked the payload instead. Every DATA no builtin
    /// endpoint claimed went to it, and it tried the SPDP reader, then the
    /// SEDP reader, on whatever it was handed - so the writer stopped
    /// mattering altogether. Through this dispatch without the fix,
    /// with ONE real participant announcement carried by three writers:
    ///
    /// | writer | what got registered |
    /// |---|---|
    /// | `0x000100c2`, the SPDP writer | the participant, lease 30000 |
    /// | `0x000002c2`, the DCPSTopic writer | the participant, lease 30000 |
    /// | `0x00001202`, an application writer | the participant, lease 30000 |
    ///
    /// The third row is the whole finding: an ordinary user-topic writer
    /// announced a peer into our discovery database. A peer only has to put
    /// a parameter list carrying PID_PARTICIPANT_GUID on any topic at all.
    ///
    /// The control row is here so "0 participants" cannot pass for the wrong
    /// reason: the same bytes down the same door with the RIGHT writer must
    /// still register the peer.
    #[test]
    fn only_the_participant_writer_announces_a_participant() {
        let (_announced, spdp) = announcement_from(SENDER_PREFIX);

        let (kind, registered, counted) = what_a_writer_gets_registered(&SPDP, &spdp);
        assert_eq!(kind, PacketKind::SPDP);
        assert_eq!(
            registered, 1,
            "the control: this fixture IS a participant announcement"
        );
        assert_eq!(counted, 0);

        let (kind, registered, counted) = what_a_writer_gets_registered(&SEDP_TOPIC, &spdp);
        assert_eq!(
            kind,
            PacketKind::UnknownBuiltin,
            "0x000002c2 is a builtin entity id (entityKind 0xc2) with no handler here"
        );
        assert_eq!(
            registered, 0,
            "the DCPSTopic writer does not get to announce participants"
        );
        assert_eq!(counted, 1, "and the drop is counted, not silent");

        let (kind, registered, counted) = what_a_writer_gets_registered(&A_USER_ENDPOINT, &spdp);
        assert_eq!(
            kind,
            PacketKind::Data,
            "an application writer's DATA stays user data - the router's business"
        );
        assert_eq!(
            registered, 0,
            "an application writer announced a peer into the discovery database"
        );
        assert_eq!(
            counted, 0,
            "user data is not an unclaimed builtin and must not be counted as one"
        );
    }

    /// The same door, with an ENDPOINT announcement instead of a participant
    /// one, because the two failed differently and only one of them looks
    /// wrong in a log.
    ///
    /// A SEDP announcement carries PID_PARTICIPANT_GUID by interop
    /// requirement (FastDDS wants it), so `parse_spdp_partial`
    /// ACCEPTED it and returned before the SEDP reader was ever tried. What
    /// it returned was the partial parser's constants: measured, a
    /// participant with a 100-SECOND lease and NOT ONE LOCATOR - visible,
    /// unanswerable, and alive in the database ten times longer than the
    /// peer said it would be.
    #[test]
    fn an_endpoint_announcement_is_not_a_participant_announcement_either() {
        use crate::protocol::dialect::{build_sedp_for_dialect, Dialect, Guid, SedpEndpointData};
        let sedp = build_sedp_for_dialect(
            Dialect::Hdds,
            &SedpEndpointData {
                endpoint_guid: Guid {
                    prefix: SENDER_PREFIX,
                    entity_id: [0x00, 0x00, 0x12, 0x02],
                },
                participant_guid: Guid {
                    prefix: SENDER_PREFIX,
                    entity_id: [0x00, 0x00, 0x01, 0xc1],
                },
                topic_name: "Square",
                type_name: "ShapeType",
                unicast_locators: &[],
                multicast_locators: &[],
                qos: None,
                type_object: None,
                user_data: None,
                hdds_shm_capability: None,
                hdds_peer_destination: false,
                group_entity_id: None,
                type_consistency: None,
                #[cfg(feature = "xtypes-structural-assignability")]
                type_information: None,
                emit_type_object_pid: true,
            },
        )
        .expect("build the announcement");

        // The control: carried by the writer that owns it, it is read as an
        // endpoint announcement and no participant appears.
        let (kind, registered, _) = what_a_writer_gets_registered(&SEDP_PUBLICATIONS, &sedp);
        assert_eq!(kind, PacketKind::SEDP);
        assert_eq!(registered, 0);

        let (kind, registered, counted) = what_a_writer_gets_registered(&SEDP_TOPIC, &sedp);
        assert_eq!(kind, PacketKind::UnknownBuiltin);
        assert_eq!(registered, 0, "no participant with a fabricated lease");
        assert_eq!(counted, 1);

        let (kind, registered, counted) = what_a_writer_gets_registered(&A_USER_ENDPOINT, &sedp);
        assert_eq!(kind, PacketKind::Data);
        assert_eq!(registered, 0);
        assert_eq!(counted, 0);
    }

    /// A participant first heard during our probation, kept on one mark,
    /// that then sends nothing but user DATA - best-effort samples, no
    /// HEARTBEAT, no announcement for seconds - is alive: its samples are
    /// marks. It must not be purged by the silence rule of the probation
    /// (`PROBATION_SILENCE_MS`), which would count as a departure of its
    /// writers while they deliver.
    #[test]
    fn a_participant_in_probation_that_sends_user_data_is_not_purged_as_silent() {
        let h = Harness::new();
        let fsm = &h.dispatch.fsm;
        let (announced, _) = announcement_from(SENDER_PREFIX);
        let participant = announced.participant_guid;
        fsm.handle_spdp(announced);
        user_data_probation(&h, true);
        assert!(
            fsm.has_participant(&participant),
            "a participant whose writers deliver was purged as silent"
        );
    }

    /// The same participant, authenticating with us: its handshake messages
    /// on the stateless topic are marks as its samples are. Purged as silent
    /// meanwhile, it lost the session in progress, and its next announcement
    /// began another that spent its re-authentication of the interval.
    #[cfg(feature = "security")]
    #[test]
    fn a_participant_in_probation_that_only_handshakes_is_not_purged_as_silent() {
        assert!(
            stateless_probation(&stateless_message(SENDER_PREFIX, OUR_PREFIX)),
            "a participant whose handshake messages arrive was purged as silent"
        );
    }

    /// A ParticipantStatelessMessage (DDS Security v1.1 Sec.7.4.3.3) from the
    /// stateless writer of `source`, to the participant `destination`,
    /// carrying an authentication request token.
    #[cfg(feature = "security")]
    fn stateless_message(source: [u8; 12], destination: [u8; 12]) -> Vec<u8> {
        let token = crate::security::handshake::tokens::encode_auth_req(
            &crate::security::handshake::tokens::AuthReqToken {
                future_challenge: [0x5E; 32],
            },
        )
        .expect("encode");
        let guid = |prefix: [u8; 12], entity: [u8; 4]| {
            let mut g = [0u8; 16];
            g[..12].copy_from_slice(&prefix);
            g[12..].copy_from_slice(&entity);
            g
        };
        crate::security::generic_message::encode(
            &guid(source, [0x00, 0x02, 0x01, 0xC3]),
            1,
            &guid(destination, [0x00, 0x00, 0x01, 0xC1]),
            &token,
        )
        .expect("encode")
    }

    /// A handshake message for another participant, or naming another source
    /// than the participant it comes from, is dropped: no liveness mark.
    #[cfg(feature = "security")]
    #[test]
    fn a_stateless_message_for_another_participant_or_from_another_source_is_no_mark() {
        assert!(
            !stateless_probation(&stateless_message(SENDER_PREFIX, [0x33; 12])),
            "a message for another participant was taken"
        );
        assert!(
            !stateless_probation(&stateless_message([0x44; 12], OUR_PREFIX)),
            "a message naming another source was taken"
        );
    }

    /// The bare token HDDS before 1.5 sent, without its envelope, is no
    /// ParticipantStatelessMessage.
    #[cfg(feature = "security")]
    #[test]
    fn a_bare_token_is_no_stateless_message() {
        let token = crate::security::handshake::tokens::encode_auth_req(
            &crate::security::handshake::tokens::AuthReqToken {
                future_challenge: [0x5E; 32],
            },
        )
        .expect("encode");
        assert!(!stateless_probation(&token), "a bare token was taken");
    }

    /// The other side: bytes on the stateless reader that do not parse as a
    /// handshake token are no liveness mark, or anyone sending garbage under
    /// a known prefix would keep a dead participant alive.
    #[cfg(feature = "security")]
    #[test]
    fn bytes_on_the_stateless_reader_that_are_no_token_are_no_mark() {
        assert!(
            !stateless_probation(&[0x00, 0x01, 0x00, 0x00]),
            "a participant whose stateless datagrams are no token was kept"
        );
    }

    /// Drive the probation of `SENDER_PREFIX`, heard at our start: one mark
    /// before the boundary (150 ms after we heard it), then `sample` on the
    /// stateless topic through the dispatch at 450, 750 and 1050 ms, and
    /// nothing else; judged at 1300 ms, more than `PROBATION_SILENCE_MS`
    /// after the mark. Returns whether the participant was kept.
    #[cfg(feature = "security")]
    fn stateless_probation(sample: &[u8]) -> bool {
        stateless_probation_of(&[(data_datagram(SENDER_PREFIX, &STATELESS, sample), None)])
    }

    /// The stateless topic's endpoints.
    #[cfg(feature = "security")]
    const STATELESS: super::super::wire_fixtures::Endpoints =
        super::super::wire_fixtures::Endpoints {
            reader: [0x00, 0x02, 0x01, 0xC4],
            writer: [0x00, 0x02, 0x01, 0xC3],
        };

    /// A handshake message too large for one DATA arrives as DATA_FRAG (an
    /// AuthReply of Cyclone DDS, its certificate, permissions document and
    /// participant data, is five fragments): reassembled, it is a handshake
    /// message as a DATA is. Seen live: reassembled, then dropped as "not a
    /// discovery announcement", so no fragmented handshake message ever
    /// reached the handshake.
    #[cfg(feature = "security")]
    #[test]
    fn a_fragmented_handshake_message_is_a_handshake_message() {
        let (one, two, meta_one, meta_two) = two_fragments(
            SENDER_PREFIX,
            &STATELESS,
            &stateless_message(SENDER_PREFIX, OUR_PREFIX),
        );
        assert!(
            stateless_probation_of(&[(one, Some(meta_one)), (two, Some(meta_two))]),
            "a participant whose fragmented handshake messages arrive was purged as silent"
        );
    }

    /// `stateless_probation`, the datagrams of each delivery given.
    #[cfg(feature = "security")]
    fn stateless_probation_of(
        datagrams: &[(
            Vec<u8>,
            Option<crate::core::discovery::multicast::FragmentMetadata>,
        )],
    ) -> bool {
        use std::time::Duration;
        let h = Harness::new();
        let fsm = &h.dispatch.fsm;
        let (announced, _) = announcement_from(SENDER_PREFIX);
        let participant = announced.participant_guid;
        fsm.handle_spdp(announced);
        let at = |ms: u64| {
            let due = Duration::from_millis(ms);
            let now = fsm.uptime();
            if due > now {
                std::thread::sleep(due - now);
            }
        };
        at(150);
        fsm.touch_participant_by_prefix(&SENDER_PREFIX);
        at(260);
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done(), "fixture: past the boundary");
        for ms in [450, 750, 1_050] {
            at(ms);
            for (datagram, meta) in datagrams {
                h.feed(PacketKind::Stateless, datagram, SAMPLE_AT, *meta);
            }
        }
        at(1_300);
        fsm.maybe_complete_probation();
        fsm.has_participant(&participant)
    }

    /// The mirror, and the fixture's control: the same participant, sending
    /// nothing after its one mark, is purged by the silence rule.
    #[test]
    fn a_participant_in_probation_that_sends_nothing_is_still_purged_as_silent() {
        let h = Harness::new();
        let fsm = &h.dispatch.fsm;
        let (announced, _) = announcement_from(SENDER_PREFIX);
        let participant = announced.participant_guid;
        fsm.handle_spdp(announced);
        user_data_probation(&h, false);
        assert!(
            !fsm.has_participant(&participant),
            "silent for a second without becoming eligible: purged"
        );
    }

    /// Drive the probation of `SENDER_PREFIX`, heard at our start: one mark
    /// before the boundary (a HEARTBEAT, 150 ms after we heard it), then,
    /// when `sends_data`, user DATA through the dispatch at 450, 750 and
    /// 1050 ms, and nothing else; the probation is judged at 1300 ms, more
    /// than `PROBATION_SILENCE_MS` after the mark.
    fn user_data_probation(h: &Harness, sends_data: bool) {
        use std::time::Duration;
        let fsm = &h.dispatch.fsm;
        let at = |ms: u64| {
            let due = Duration::from_millis(ms);
            let now = fsm.uptime();
            if due > now {
                std::thread::sleep(due - now);
            }
        };
        let sample = data_datagram(SENDER_PREFIX, &A_USER_ENDPOINT, &[0x00, 0x01, 0x00, 0x00]);
        at(150);
        fsm.touch_participant_by_prefix(&SENDER_PREFIX);
        at(260);
        fsm.maybe_complete_probation();
        assert!(fsm.is_probation_done(), "fixture: past the boundary");
        for ms in [450, 750, 1_050] {
            at(ms);
            if sends_data {
                h.feed(PacketKind::Data, &sample, SAMPLE_AT, None);
            }
        }
        at(1_300);
        fsm.maybe_complete_probation();
    }
}

#[cfg(all(test, feature = "security"))]
mod verify_dispatch_attack_tests {
    use super::super::wire_fixtures::*;
    use crate::core::discovery::multicast::PacketKind;
    use std::sync::Arc;

    fn delivery(d: &[u8]) -> (PacketKind, usize) {
        if let Some(at) = crate::security::crypto::secure_submessage::first_secure_prefix(d) {
            return (PacketKind::SecureSEDP, at);
        }
        let (k, at, _, _) = crate::core::discovery::multicast::classifier::classify_rtps(d);
        (k, at.unwrap_or(SAMPLE_AT))
    }

    fn authenticated() -> Harness {
        let mut h = Harness::new();
        let machine = crate::security::test_pki::local_machine_with_completed_peer(
            OUR_PREFIX,
            SENDER_PREFIX,
            None,
        );
        std::sync::Arc::get_mut(&mut h.dispatch.fsm)
            .expect("only owner")
            .set_handshake_machine(
                machine,
                crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
                crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
            );
        std::sync::Arc::get_mut(&mut h.dispatch.fsm)
            .expect("the harness is the FSM's only owner")
            .register_builtin_writer_keys_for_tests();
        h
    }

    fn sample() -> Vec<u8> {
        sample_of("Square")
    }

    fn sample_of(topic_name: &str) -> Vec<u8> {
        use crate::protocol::dialect::{build_sedp_for_dialect, Dialect, Guid, SedpEndpointData};
        let locators: Vec<std::net::SocketAddr> = vec!["192.0.2.7:7411".parse().unwrap()];
        build_sedp_for_dialect(
            Dialect::Hdds,
            &SedpEndpointData {
                endpoint_guid: Guid {
                    prefix: SENDER_PREFIX,
                    entity_id: [0, 0, 0x12, 0x02],
                },
                participant_guid: Guid {
                    prefix: SENDER_PREFIX,
                    entity_id: [0, 0, 1, 0xc1],
                },
                topic_name,
                type_name: "ShapeType",
                unicast_locators: &locators,
                multicast_locators: &[],
                qos: None,
                type_object: None,
                user_data: None,
                hdds_shm_capability: None,
                hdds_peer_destination: false,
                group_entity_id: None,
                type_consistency: None,
                #[cfg(feature = "xtypes-structural-assignability")]
                type_information: None,
                emit_type_object_pid: true,
            },
        )
        .unwrap()
    }

    /// Exercises the protected repair branch with local reader keys.
    /// `review_sixteenth_datagram_bound_must_not_lose_endpoint_seventeen`
    /// drives
    /// `request_secure_sedp_repair` end to end, but its harness never
    /// registers OUR builtin reader keys -- so `local_builtin_reader_
    /// material_for` returns `None` there, the repair ACKNACK goes out
    /// under the `None => packet` (clear) fallback, and that test's own
    /// `parse_all_acknack_submessages(&buf[..size])` on the raw bytes
    /// quietly parses a CLEAR repair, never the protected branch. This
    /// test isolates that branch directly: register the reader keys
    /// first, call `request_secure_sedp_repair` for both secure SEDP
    /// writers, and require the captured bytes to need a SEC_PREFIX
    /// decode -- a plain `parse_all_acknack_submessages` on them must find
    /// NOTHING, and the decode must succeed and show the real missing
    /// range.
    #[test]
    fn request_secure_sedp_repair_protects_the_recovery_acknack_when_a_reader_key_exists() {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
        };
        use crate::security::access::ProtectionKind;
        use crate::security::crypto::secure_sedp::open_reader_control_packet;
        use crate::security::crypto::secure_submessage::first_secure_prefix;
        use crate::security::crypto::volatile::builtin_peer_entity_id;
        use std::net::UdpSocket;
        use std::time::Duration;

        let mut h = authenticated();
        Arc::get_mut(&mut h.dispatch.fsm)
            .expect("the harness is the FSM's only owner")
            .register_builtin_reader_keys_for_tests();

        let repairs = UdpSocket::bind("127.0.0.1:0").expect("bind repairs socket");
        repairs
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let mut peer = announcement_from(SENDER_PREFIX).0;
        peer.metatraffic_unicast_locators = vec![repairs.local_addr().expect("local addr")];
        h.dispatch.fsm.handle_spdp(peer);

        // mask bits 1|2: both secure SEDP writers (`request_secure_sedp_
        // repair`'s own doc).
        h.dispatch.request_secure_sedp_repair(SENDER_PREFIX, 0b11);

        let mut seen_writers = Vec::new();
        let mut buf = [0u8; 2048];
        for _ in 0..2 {
            let size = repairs.recv(&mut buf).expect("a repair ACKNACK per writer");
            let datagram = &buf[..size];

            assert!(
                crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages(
                    datagram
                )
                .is_empty(),
                "a plain scanner must find NOTHING: the ACKNACK must not sit in the clear"
            );
            let prefix_at = first_secure_prefix(datagram)
                .expect("the repair ACKNACK must be SEC_PREFIX-wrapped");

            // The candidate writer is whichever of the two this envelope's
            // own reader material was minted for; `open_reader_control_
            // packet` itself rejects the wrong pairing (findings 3/4 of the
            // first round), so trying both and keeping whichever opens is
            // not a weaker check than knowing the answer up front.
            let opened = [
                RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
                RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
            ]
            .into_iter()
            .find_map(|writer| {
                let material = h
                    .dispatch
                    .fsm
                    .local_builtin_reader_material_for(&SENDER_PREFIX, &writer)?;
                let reader = builtin_peer_entity_id(writer)?;
                open_reader_control_packet(
                    datagram,
                    prefix_at,
                    &material,
                    &reader,
                    ProtectionKind::None,
                )
                .map(|o| (writer, o))
            });
            let (writer, opened) = opened
                .expect("the repair ACKNACK must decode under one of our two builtin reader keys");
            seen_writers.push(writer);

            let decoded = {
                // A real RTPS header, as `dispatch_decoded_reader_
                // control`'s own minimal buffer builds it -- a
                // zero-filled 20 bytes fails `parse_all_acknack_
                // submessages`' own `&packet[0..4] != b"RTPS"` guard.
                let mut minimal = Vec::with_capacity(20 + opened.submessage.len());
                minimal.extend_from_slice(b"RTPS");
                minimal.extend_from_slice(&[
                    crate::core::rtps_constants::RTPS_VERSION_MAJOR,
                    crate::core::rtps_constants::RTPS_VERSION_MINOR,
                ]);
                minimal.extend_from_slice(&crate::core::rtps_constants::HDDS_VENDOR_ID);
                minimal.extend_from_slice(&SENDER_PREFIX);
                minimal.extend_from_slice(&opened.submessage);
                crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages(
                    &minimal,
                )
            };
            assert_eq!(decoded.len(), 1, "exactly one decoded ACKNACK");
            assert_eq!(decoded[0].bitmap_base, 1);
            assert!(
                !decoded[0].missing_ranges.is_empty(),
                "the repair must name a real missing range, not a pure ACK"
            );
        }
        seen_writers.sort_unstable();
        let mut expected = vec![
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
        ];
        expected.sort_unstable();
        assert_eq!(seen_writers, expected, "both secure writers got a repair");
    }

    /// A CLEAR subscriptions ACKNACK
    /// prepended ahead of a genuinely encrypted publications one, in the
    /// SAME datagram, must not acquire "protected" status from the
    /// envelope that follows it.
    ///
    /// Built independently: a hand-assembled `[RTPS header][clear
    /// ACKNACK(SUB)][SEC_PREFIX-protected ACKNACK(PUB)]` datagram, fed
    /// through `handle_secure_sedp` exactly as the listener would deliver
    /// it (`first_secure_prefix` finds the SEC_PREFIX, which sits AFTER
    /// the clear ACKNACK). Asserts on the `ControlMessage`s that actually
    /// reach the control channel: exactly one, the PUBLICATIONS ACKNACK,
    /// marked protected; the prepended clear SUBSCRIPTIONS ACKNACK never
    /// reaches this channel at all via this path (the datagram offset this
    /// dispatch was given starts AFTER it).
    ///
    /// Mutant: reverting `dispatch_decoded_reader_control` to splice the
    /// decoded submessage back into a copy of `datagram[..prefix_at]` (the
    /// wrong approach) and re-parse THAT -- delivers TWO
    /// messages here, both marked protected, the clear one included.
    #[test]
    fn review_finding_1_only_the_decoded_envelopes_own_bytes_are_marked_protected() {
        use crate::core::discovery::multicast::ControlMessage;
        use crate::core::rtps_constants::{
            HDDS_VENDOR_ID, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER, RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR,
        };
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::secure_sedp::protect_reader_control_packet;

        let mut h = authenticated();
        std::sync::Arc::get_mut(&mut h.dispatch.fsm)
            .expect("only owner")
            .register_builtin_reader_keys_for_tests();

        let (key_id, material) = WriterKey::mint().expect("mint");
        let protect_material = material.submessage_material(key_id);
        h.dispatch.fsm.receive_writer_key_for_tests(
            SENDER_PREFIX,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            u64::from(key_id),
            material,
        );

        let build_acknack = |reader: [u8; 4], writer: [u8; 4]| {
            let mut sub = vec![0x06u8, 0x03];
            let mut body = Vec::new();
            body.extend_from_slice(&reader);
            body.extend_from_slice(&writer);
            body.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
            body.extend_from_slice(&[0, 0, 0, 0]);
            // Count_t, LE: flags 0x03 declares E=1, and every multi-byte
            // field of this submessage follows that (the count must not be
            // written big-endian under a little-endian flag).
            body.extend_from_slice(&7u32.to_le_bytes());
            sub.extend_from_slice(&(body.len() as u16).to_le_bytes());
            sub.extend_from_slice(&body);
            sub
        };

        // The encrypted half: protect the publications ACKNACK on its own
        // minimal `[header][ACKNACK]`, then take just the SEC_ bytes.
        let mut pub_plain = vec![0u8; 20];
        pub_plain.extend_from_slice(&build_acknack(
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
        ));
        let pub_protected =
            protect_reader_control_packet(&pub_plain, &protect_material).expect("protect");

        // The attack datagram: real header, then a CLEAR subscriptions
        // ACKNACK, then the genuinely-encrypted publications one.
        let mut datagram = Vec::new();
        datagram.extend_from_slice(b"RTPS");
        datagram.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
        datagram.extend_from_slice(&HDDS_VENDOR_ID);
        datagram.extend_from_slice(&SENDER_PREFIX);
        datagram.extend_from_slice(&build_acknack(
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
        ));
        datagram.extend_from_slice(&pub_protected[20..]);

        let (tx, rx) = crossbeam::channel::unbounded();
        h.dispatch.set_control_tx(tx);

        let (kind, at) = delivery(&datagram);
        assert_eq!(
            kind,
            crate::core::discovery::multicast::PacketKind::SecureSEDP,
            "fixture: a SEC_PREFIX is present"
        );
        h.feed(kind, &datagram, at, None);

        let mut delivered: Vec<ControlMessage> = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            delivered.push(msg);
        }
        assert_eq!(
            delivered.len(),
            1,
            "exactly the one genuinely-decoded ACKNACK must reach the control channel"
        );
        assert!(
            delivered[0].was_protected(),
            "the publications ACKNACK must be marked protected"
        );
        let an = delivered[0].acknack.as_ref().expect("an ACKNACK");
        assert_eq!(
            an.writer_entity_id, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            "the delivered message must be the PUBLICATIONS one, never the prepended clear \
             SUBSCRIPTIONS one"
        );
    }

    /// Tests through PRODUCTION dispatch (a compound test that opens
    /// envelopes itself would not catch the removal of the production
    /// loop):
    /// `a_compound_datagram_yields_both_protected_acknacks_in_order`
    /// (`secure_sedp.rs`) proves `first_secure_prefix_from` CAN locate a
    /// second envelope, but it calls `open_reader_control_packet` itself
    /// for both: it would still pass if `handle_secure_sedp`'s own loop
    /// (`SecureEnvelopeOutcome::Continues`) were deleted entirely. This
    /// test feeds a REAL `[SEC_PREFIX PUB ACKNACK][SEC_PREFIX SUB ACKNACK]`
    /// datagram through `h.feed` -- the same entry point the listener
    /// uses -- and requires BOTH to reach the control channel.
    ///
    /// Mutant: reverting the loop to `return SecureEnvelopeOutcome::
    /// Terminal` unconditionally after the first envelope (instead of
    /// `Continues`, which lets `handle_secure_sedp` look for a further
    /// `first_secure_prefix_from`) delivers only ONE message here.
    #[test]
    fn two_independently_protected_acknacks_both_reach_production_dispatch() {
        use crate::core::discovery::multicast::ControlMessage;
        use crate::core::rtps_constants::{
            HDDS_VENDOR_ID, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER, RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR,
        };
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::secure_sedp::protect_reader_control_packet;

        let mut h = authenticated();
        std::sync::Arc::get_mut(&mut h.dispatch.fsm)
            .expect("only owner")
            .register_builtin_reader_keys_for_tests();

        // The sender's two reader keys -- one per secure SEDP tunnel --
        // both installed, so both envelopes decode.
        let (pub_key_id, pub_key) = WriterKey::mint().expect("mint");
        let pub_material = pub_key.submessage_material(pub_key_id);
        h.dispatch.fsm.receive_writer_key_for_tests(
            SENDER_PREFIX,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            u64::from(pub_key_id),
            pub_key,
        );
        let (sub_key_id, sub_key) = WriterKey::mint().expect("mint");
        let sub_material = sub_key.submessage_material(sub_key_id);
        h.dispatch.fsm.receive_writer_key_for_tests(
            SENDER_PREFIX,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
            u64::from(sub_key_id),
            sub_key,
        );

        let build_acknack = |reader: [u8; 4], writer: [u8; 4]| {
            let mut sub = vec![0x06u8, 0x03];
            let mut body = Vec::new();
            body.extend_from_slice(&reader);
            body.extend_from_slice(&writer);
            body.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
            body.extend_from_slice(&[0, 0, 0, 0]);
            body.extend_from_slice(&7u32.to_le_bytes());
            sub.extend_from_slice(&(body.len() as u16).to_le_bytes());
            sub.extend_from_slice(&body);
            sub
        };
        let protect = |reader: [u8; 4], writer: [u8; 4], material| {
            let mut plain = vec![0u8; 20];
            plain.extend_from_slice(&build_acknack(reader, writer));
            protect_reader_control_packet(&plain, material).expect("protect")
        };
        let pub_protected = protect(
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            &pub_material,
        );
        let sub_protected = protect(
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
            &sub_material,
        );

        let mut datagram = Vec::new();
        datagram.extend_from_slice(b"RTPS");
        datagram.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
        datagram.extend_from_slice(&HDDS_VENDOR_ID);
        datagram.extend_from_slice(&SENDER_PREFIX);
        datagram.extend_from_slice(&pub_protected[20..]);
        datagram.extend_from_slice(&sub_protected[20..]);

        let (tx, rx) = crossbeam::channel::unbounded();
        h.dispatch.set_control_tx(tx);

        let (kind, at) = delivery(&datagram);
        assert_eq!(
            kind,
            crate::core::discovery::multicast::PacketKind::SecureSEDP,
            "fixture: a SEC_PREFIX is present"
        );
        h.feed(kind, &datagram, at, None);

        let mut delivered: Vec<ControlMessage> = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            delivered.push(msg);
        }
        assert_eq!(
            delivered.len(),
            2,
            "both independently-protected envelopes must reach the control channel"
        );
        assert!(
            delivered.iter().all(ControlMessage::was_protected),
            "both must be marked protected"
        );
        let mut writers: Vec<_> = delivered
            .iter()
            .filter_map(|m| m.acknack.as_ref())
            .map(|an| an.writer_entity_id)
            .collect();
        writers.sort_unstable();
        let mut expected = vec![
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
        ];
        expected.sort_unstable();
        assert_eq!(writers, expected);
    }

    /// The sibling test above only ever combines two ACKNACKs, so it
    /// cannot catch a defect specific to the SEDP-DATA arm of
    /// `open_one_secure_envelope` (which must not return `Terminal`
    /// unconditionally). This test combines a protected SEDP DATA
    /// with a protected ACKNACK in ONE datagram and requires BOTH to be
    /// applied: the DATA registers the announced endpoint, the ACKNACK
    /// reaches the control channel.
    ///
    /// Mutant: reverting the SEDP-DATA success arm to `return
    /// SecureEnvelopeOutcome::Terminal` unconditionally (instead of
    /// checking for a further envelope via `opened.end`) makes the
    /// endpoint register but the ACKNACK never arrive.
    #[test]
    fn a_protected_sedp_data_followed_by_a_protected_acknack_both_apply() {
        use crate::core::discovery::multicast::ControlMessage;
        use crate::core::rtps_constants::{
            HDDS_VENDOR_ID, RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER, RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR,
        };
        use crate::security::crypto::secure_sedp::{
            protect_reader_control_packet, protect_sedp_packet,
        };

        let mut h = authenticated();
        std::sync::Arc::get_mut(&mut h.dispatch.fsm)
            .expect("only owner")
            .register_builtin_reader_keys_for_tests();

        // The sender's participant must be known to discovery before its
        // SEDP announcement is accepted (standard SPDP-before-SEDP
        // ordering), same fixture as `verify_replayed_protected_
        // announcement_after_dispose`.
        let (mut spdp_data, _) = announcement_from(SENDER_PREFIX);
        spdp_data.vendor_id = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
        spdp_data.hdds_capabilities = Some(crate::protocol::group::LOCAL_CAPABILITIES);
        h.dispatch.fsm.handle_spdp(spdp_data);

        // The sender's own secure publications writer key, so the DATA
        // decodes; its reader key, so the ACKNACK does too.
        let writer_keys = h.dispatch.fsm.sender_sedp_keys_for_tests(SENDER_PREFIX);
        let (reader_key_id, reader_key) =
            crate::security::crypto::data_keys::WriterKey::mint().expect("mint");
        let reader_material = reader_key.submessage_material(reader_key_id);
        h.dispatch.fsm.receive_writer_key_for_tests(
            SENDER_PREFIX,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            u64::from(reader_key_id),
            reader_key,
        );

        // `protect_sedp_packet` renames the PLAIN writer/reader entity ids
        // to their secure form itself (`sedp_entity_in`): it is given the
        // plain SEDP DATA a regular announcement would be, exactly as
        // `verify_replayed_protected_announcement_after_dispose` does.
        let plain_data = data_datagram(SENDER_PREFIX, &SEDP_PUBLICATIONS, &sample());
        let protected_data = protect_sedp_packet(&plain_data, &writer_keys).expect("protect DATA");

        let mut acknack = vec![0x06u8, 0x03];
        let mut body = Vec::new();
        body.extend_from_slice(&RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER);
        body.extend_from_slice(&RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER);
        body.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.extend_from_slice(&7u32.to_le_bytes());
        acknack.extend_from_slice(&(body.len() as u16).to_le_bytes());
        acknack.extend_from_slice(&body);
        let mut acknack_plain = vec![0u8; 20];
        acknack_plain.extend_from_slice(&acknack);
        let protected_acknack = protect_reader_control_packet(&acknack_plain, &reader_material)
            .expect("protect ACKNACK");

        let mut datagram = Vec::new();
        datagram.extend_from_slice(b"RTPS");
        datagram.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
        datagram.extend_from_slice(&HDDS_VENDOR_ID);
        datagram.extend_from_slice(&SENDER_PREFIX);
        datagram.extend_from_slice(&protected_data[20..]);
        datagram.extend_from_slice(&protected_acknack[20..]);

        let (tx, rx) = crossbeam::channel::unbounded();
        h.dispatch.set_control_tx(tx);

        let (kind, at) = delivery(&datagram);
        assert_eq!(
            kind,
            crate::core::discovery::multicast::PacketKind::SecureSEDP,
            "fixture: a SEC_PREFIX is present"
        );
        h.feed(kind, &datagram, at, None);

        let writer_guid = crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 0x12, 0x02]);
        assert!(
            h.dispatch
                .fsm
                .current_endpoint("Square", &writer_guid)
                .is_some(),
            "the protected SEDP DATA must be applied"
        );

        let mut delivered: Vec<ControlMessage> = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            delivered.push(msg);
        }
        assert_eq!(
            delivered.len(),
            1,
            "the protected ACKNACK after the protected DATA must also reach the control \
             channel"
        );
        assert!(delivered[0].was_protected());
    }

    /// A captured spec-shape protected SEDP announcement (SN 7), replayed
    /// after the participant's protected dispose (SN 8) of the same writer,
    /// under the same keys: does it bring the disposed writer back?
    #[test]
    fn verify_replayed_protected_announcement_after_dispose() {
        use crate::core::discovery::multicast::SedpEndpointKind;
        use crate::protocol::dialect::Dialect;
        use crate::security::crypto::secure_sedp::protect_sedp_packet;
        let h = authenticated();
        let (mut spdp_data, _) = announcement_from(SENDER_PREFIX);
        spdp_data.vendor_id = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
        spdp_data.hdds_capabilities = Some(crate::protocol::group::LOCAL_CAPABILITIES);
        h.dispatch.fsm.handle_spdp(spdp_data);
        let keys = h.dispatch.fsm.receive_sedp_writer_keys_for_tests(
            SENDER_PREFIX,
            crate::security::crypto::secure_submessage::Transformation::Aes256Gcm,
        );
        let writer = crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 0x12, 0x02]);
        let feed = |d: &[u8]| {
            let (k, at) = delivery(d);
            h.feed(k, d, at, None);
        };
        let announce = protect_sedp_packet(
            &data_datagram(SENDER_PREFIX, &SEDP_PUBLICATIONS, &sample()),
            &keys,
        )
        .expect("protect");
        feed(&announce);
        assert!(
            h.dispatch.fsm.current_endpoint("Square", &writer).is_some(),
            "fixture"
        );
        let dispose = crate::core::discovery::multicast::build_sedp_dispose_packet(
            &writer,
            SedpEndpointKind::Writer,
            &SENDER_PREFIX,
            Some(&OUR_PREFIX),
            8,
            Dialect::Hdds,
        );
        feed(&protect_sedp_packet(&dispose, &keys).unwrap());
        assert!(
            h.dispatch.fsm.current_endpoint("Square", &writer).is_none(),
            "disposed"
        );
        // Replay of the old (SN 7) protected announcement.
        feed(&announce);
        assert!(
            h.dispatch.fsm.current_endpoint("Square", &writer).is_none(),
            "REPLAY: a stale protected SN 7 announcement resurrected the writer disposed at SN 8"
        );
    }

    /// A harness whose participant runs a governance document: topic `Open`
    /// on the regular SEDP topics, every other on the secure ones, the secure
    /// discovery writers protected by `kind`; SENDER authenticated and
    /// announcing the spec shape.
    fn governed(kind: crate::security::access::ProtectionKind) -> Harness {
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
        let mut h = authenticated();
        std::sync::Arc::get_mut(&mut h.dispatch.fsm)
            .expect("only owner")
            .set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
                domains: vec![0],
                domain_ranges: vec![],
                allow_unauthenticated: false,
                enable_join_access_control: true,
                discovery_protection_kind: kind,
                liveliness_protection_kind: ProtectionKind::None,
                rtps_protection_kind: ProtectionKind::None,
                topic_rules: vec![topic("Open", false), topic("*", true)],
            })));
        // Our writers' key material, of the transformation the governance
        // names (`register_builtin_writer_keys`).
        std::sync::Arc::get_mut(&mut h.dispatch.fsm)
            .expect("only owner")
            .register_builtin_writer_keys_for_tests();
        let (mut spdp_data, _) = announcement_from(SENDER_PREFIX);
        spdp_data.vendor_id = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
        spdp_data.hdds_capabilities = Some(crate::protocol::group::LOCAL_CAPABILITIES);
        // `announcement_from`'s own `participant_security_info` is a
        // deliberately distinctive, is_valid-clear dummy value for an
        // unrelated fixture (field-corruption detection); it decodes to
        // "nothing protected" and would mismatch this governance's own
        // `discovery_protection_kind` (Sec.9.4.2.4, `admit_spdp`). SENDER
        // runs the SAME governance here, so it announces the matching mask.
        spdp_data.participant_security_info = Some(
            crate::security::access::ParticipantSecurityAttributes::from_kinds(
                false,
                true,
                kind,
                ProtectionKind::None,
                ProtectionKind::None,
            )
            .security_info_le(),
        );
        h.dispatch.fsm.handle_spdp(spdp_data);
        h
    }

    /// A secure announcement is read only when it is at least as protected
    /// as our discovery protection kind asks (`protection_satisfies`): with
    /// ENCRYPT, the NONE and SIGN shapes of an authenticated participant are
    /// dropped and the ENCRYPT one applied; with NONE, all three are read.
    #[test]
    fn a_secure_announcement_weaker_than_our_discovery_protection_is_dropped() {
        use crate::security::access::ProtectionKind;
        use crate::security::crypto::secure_sedp::protect_sedp_packet_as;
        let writer = crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 0x12, 0x02]);
        for (ours, theirs, applied) in [
            (ProtectionKind::Encrypt, ProtectionKind::None, false),
            (ProtectionKind::Encrypt, ProtectionKind::Sign, false),
            (ProtectionKind::Encrypt, ProtectionKind::Encrypt, true),
            (ProtectionKind::None, ProtectionKind::None, true),
            (ProtectionKind::None, ProtectionKind::Sign, true),
            (ProtectionKind::Sign, ProtectionKind::Sign, true),
        ] {
            let h = governed(ours);
            // The sender's writers' key material, of the transformation its
            // own discovery protection names (Table 59).
            let transformation = if theirs.is_protected() && !theirs.is_encrypted() {
                crate::security::crypto::secure_submessage::Transformation::Aes256Gmac
            } else {
                crate::security::crypto::secure_submessage::Transformation::Aes256Gcm
            };
            let keys = h
                .dispatch
                .fsm
                .receive_sedp_writer_keys_for_tests(SENDER_PREFIX, transformation);
            let announce = protect_sedp_packet_as(
                &data_datagram(SENDER_PREFIX, &SEDP_PUBLICATIONS, &sample()),
                &keys,
                theirs,
            )
            .expect("protect");
            let (kind, at) = delivery(&announce);
            assert_eq!(kind, PacketKind::SecureSEDP, "{:?}", theirs);
            h.feed(kind, &announce, at, None);
            assert_eq!(
                h.dispatch.fsm.current_endpoint("Square", &writer).is_some(),
                applied,
                "ours {:?}, theirs {:?}",
                ours,
                theirs
            );
            assert_eq!(
                h.dispatch.fsm.ignores_plain_sedp_about(&writer),
                applied,
                "what was applied from a secure topic is changed only there"
            );
        }
    }

    /// A plain announcement of a topic our governance protects is not
    /// applied, from an authenticated participant either; one of a topic it
    /// leaves open is.
    #[test]
    fn a_plain_announcement_of_a_protected_topic_is_not_applied() {
        let h = governed(crate::security::access::ProtectionKind::Encrypt);
        let writer = crate::core::discovery::GUID::new(SENDER_PREFIX, [0x00, 0x00, 0x12, 0x02]);
        let feed = |datagram: &[u8]| {
            let (kind, at) = delivery(datagram);
            h.feed(kind, datagram, at, None);
        };
        feed(&data_datagram(
            SENDER_PREFIX,
            &SEDP_PUBLICATIONS,
            &sample_of("Square"),
        ));
        assert!(h.dispatch.fsm.current_endpoint("Square", &writer).is_none());
        feed(&data_datagram(
            SENDER_PREFIX,
            &SEDP_PUBLICATIONS,
            &sample_of("Open"),
        ));
        assert!(h.dispatch.fsm.current_endpoint("Open", &writer).is_some());
    }
    fn review_harness() -> Harness {
        let h = authenticated();
        h.dispatch
            .fsm
            .handle_spdp(announcement_from(SENDER_PREFIX).0);
        h
    }

    fn review_feed(h: &Harness, bytes: &[u8]) {
        let (kind, at) = delivery(bytes);
        h.feed(kind, bytes, at, None);
    }

    fn review_wire(keys: &crate::security::crypto::secure_sedp::SedpWriterKeys) -> Vec<u8> {
        crate::security::crypto::secure_sedp::protect_sedp_packet(
            &data_datagram(SENDER_PREFIX, &SEDP_PUBLICATIONS, &sample_of("Review")),
            keys,
        )
        .expect("protect")
    }

    #[test]
    fn review_reauthentication_must_retire_old_writer_material() {
        use crate::security::crypto::secure_submessage::Transformation;
        let h = review_harness();
        let old = h
            .dispatch
            .fsm
            .receive_sedp_writer_keys_for_tests(SENDER_PREFIX, Transformation::Aes256Gcm);
        let wire = review_wire(&old);
        let writer = crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 0x12, 2]);
        review_feed(&h, &wire);
        assert!(h.dispatch.fsm.current_endpoint("Review", &writer).is_some());
        h.dispatch.fsm.peer_authenticated(
            crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 1, 0xc1]),
            true,
        );
        assert!(h.dispatch.fsm.current_endpoint("Review", &writer).is_none());
        let old_id = u64::from(u32::from_be_bytes(old.publications.key_id()));
        assert!(
            h.dispatch
                .fsm
                .remote_builtin_writer_materials(&SENDER_PREFIX, old_id)
                .is_empty(),
            "old keys must be retired before replacement writer tokens arrive"
        );
        let _new = h
            .dispatch
            .fsm
            .receive_sedp_writer_keys_for_tests(SENDER_PREFIX, Transformation::Aes256Gcm);
        review_feed(&h, &wire);
        assert!(h.dispatch.fsm.current_endpoint("Review", &writer).is_none(),
            "captured old DATA resurrected the forgotten endpoint after reauthentication and new tokens");
    }

    #[test]
    fn review_departure_must_release_remote_writer_material() {
        use crate::security::crypto::secure_submessage::Transformation;
        let h = review_harness();
        let old = h
            .dispatch
            .fsm
            .receive_sedp_writer_keys_for_tests(SENDER_PREFIX, Transformation::Aes256Gcm);
        let key_id = u64::from(u32::from_be_bytes(old.publications.key_id()));
        assert!(!h
            .dispatch
            .fsm
            .remote_builtin_writer_materials(&SENDER_PREFIX, key_id)
            .is_empty());
        let wire = review_wire(&old);
        review_feed(&h, &{
            let mut b = wire;
            b[28] ^= 0x80;
            b
        });
        assert!(!h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX));
        h.dispatch
            .fsm
            .remove_participant(crate::core::discovery::GUID::new(
                SENDER_PREFIX,
                [0, 0, 1, 0xc1],
            ));
        assert!(
            !h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX),
            "datagram queue cleanup works"
        );
        assert!(
            h.dispatch
                .fsm
                .remote_builtin_writer_materials(&SENDER_PREFIX, key_id)
                .is_empty(),
            "departed participant's writer key material remains installed"
        );
    }
    #[test]
    fn review_stripped_first_capability_must_not_select_legacy_for_current_peer() {
        let h = authenticated();
        let mut first = announcement_from(SENDER_PREFIX).0;
        first.vendor_id = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
        first.hdds_capabilities = Some(
            crate::protocol::group::LOCAL_CAPABILITIES
                & !crate::protocol::group::CAP_SPEC_SECURE_SEDP,
        );
        h.dispatch.fsm.handle_spdp(first.clone());
        assert!(h.dispatch.fsm.sedp_keys_for(&SENDER_PREFIX).is_some());
        first.hdds_capabilities = Some(crate::protocol::group::LOCAL_CAPABILITIES);
        h.dispatch.fsm.handle_spdp(first);
        assert!(
            h.dispatch.fsm.sedp_keys_for(&SENDER_PREFIX).is_some(),
            "an authenticated peer retains its builtin writer material"
        );
    }

    #[test]
    fn review_unknown_key_must_not_pin_valid_data_forever() {
        use crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER;
        use crate::security::crypto::secure_submessage::Transformation;
        let h = review_harness();
        let (keys, announcements) =
            crate::core::discovery::multicast::fsm::mint_sedp_writer_keys_for_tests(
                Transformation::Aes256Gcm,
            );
        let valid = review_wire(&keys);
        let mut bogus = valid.clone();
        bogus[28] ^= 0x80;
        review_feed(&h, &bogus);
        review_feed(&h, &valid);
        let replayed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = replayed.clone();
        h.dispatch
            .fsm
            .set_secure_sedp_replay(Box::new(move |kind, bytes, at, origin| {
                seen.lock()
                    .unwrap()
                    .push((kind, bytes.to_vec(), at, origin));
            }));
        let mut rest = Vec::new();
        for (entity, id, material) in announcements {
            if entity == RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER {
                h.dispatch
                    .fsm
                    .receive_writer_key_for_tests(SENDER_PREFIX, entity, id, material);
            } else {
                rest.push((entity, id, material));
            }
        }
        h.dispatch.fsm.replay_sedp_awaiting_key(SENDER_PREFIX);
        let held = std::mem::take(&mut *replayed.lock().unwrap());
        assert_eq!(held.len(), 2);
        for (kind, bytes, at, origin) in held {
            h.dispatch.dispatch(kind, &bytes, at, None, origin);
        }
        let writer = crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 0x12, 2]);
        assert!(h.dispatch.fsm.current_endpoint("Review", &writer).is_some(),
            "an unknown id cannot block a writer whose own tokens arrived, even while other writers' tokens are pending");
        for (entity, id, material) in rest {
            h.dispatch
                .fsm
                .receive_writer_key_for_tests(SENDER_PREFIX, entity, id, material);
        }
        h.dispatch.fsm.replay_sedp_awaiting_key(SENDER_PREFIX);
        let held = std::mem::take(&mut *replayed.lock().unwrap());
        assert_eq!(held.len(), 1, "only the unresolved id remains");
        for (kind, bytes, at, origin) in held {
            h.dispatch.dispatch(kind, &bytes, at, None, origin);
        }
        assert_eq!(
            h.dispatch
                .fsm
                .metrics
                .secure_sedp_undecodable
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(!h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX));
    }

    #[test]
    fn a_known_secure_key_with_a_bad_tag_is_dropped_and_counted() {
        let h = review_harness();
        let keys = h.dispatch.fsm.receive_sedp_writer_keys_for_tests(
            SENDER_PREFIX,
            crate::security::crypto::secure_submessage::Transformation::Aes256Gcm,
        );
        let valid = review_wire(&keys);
        let mut bad = valid.clone();
        let at = bad.len() - 5;
        bad[at] ^= 1;
        review_feed(&h, &bad);
        assert!(!h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX));
        assert_eq!(
            h.dispatch
                .fsm
                .metrics
                .secure_sedp_undecodable
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        review_feed(&h, &valid);
        assert!(h
            .dispatch
            .fsm
            .current_endpoint(
                "Review",
                &crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 0x12, 2])
            )
            .is_some());
    }
    #[test]
    fn review_sixteenth_datagram_bound_must_not_lose_endpoint_seventeen() {
        use crate::core::discovery::multicast::{
            ControlHandler, ControlMessage, DiscoveryFsm, Origin, SedpEndpointKind, SedpHistory,
        };
        use crate::core::discovery::GUID;
        use crate::security::crypto::data_keys::DataKeyStore;
        use crate::security::crypto::secure_submessage::Transformation;
        use std::net::UdpSocket;
        use std::sync::{Arc, RwLock};
        use std::time::{Duration, Instant};

        let h = authenticated();
        let nacks = UdpSocket::bind("127.0.0.1:0").unwrap();
        let repairs = UdpSocket::bind("127.0.0.1:0").unwrap();
        nacks
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        repairs
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut spdp = announcement_from(SENDER_PREFIX).0;
        spdp.metatraffic_unicast_locators = vec![nacks.local_addr().unwrap()];
        h.dispatch.fsm.handle_spdp(spdp);
        let (keys, announcements) =
            crate::core::discovery::multicast::fsm::mint_sedp_writer_keys_for_tests(
                Transformation::Aes256Gcm,
            );
        let mut packets = Vec::new();
        let mut history = SedpHistory::new();
        for i in 0..17u8 {
            let mut sample = sample_of("Review");
            let old = GUID::new(SENDER_PREFIX, [0, 0, 0x12, 2]).as_bytes();
            let at = sample.windows(16).position(|w| w == old).unwrap();
            sample[at + 14] = 0x20 + i;
            history.announce(
                crate::protocol::discovery::parse_sedp(&sample).unwrap(),
                SedpEndpointKind::Writer,
            );
            let mut plain = data_datagram(SENDER_PREFIX, &SEDP_PUBLICATIONS, &sample);
            plain[40..44].copy_from_slice(&(u32::from(i) + 1).to_le_bytes());
            packets.push(
                crate::security::crypto::secure_sedp::protect_sedp_packet(&plain, &keys).unwrap(),
            );
        }
        for _ in 0..5 {
            for p in &packets {
                review_feed(&h, p);
            }
        }
        assert!(h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX));
        assert_eq!(
            h.dispatch
                .fsm
                .metrics
                .secure_sedp_queue_overflow
                .load(std::sync::atomic::Ordering::Relaxed),
            69
        );

        // A real writer-side history and control loop answer the reader's
        // actual ACKNACK datagrams, not a scripted resend of packet 17.
        let mut sender = DiscoveryFsm::new(GUID::new(SENDER_PREFIX, [0, 0, 1, 0xc1]), 30_000);
        sender.set_handshake_machine(
            crate::security::test_pki::local_machine_with_completed_peer(
                SENDER_PREFIX,
                OUR_PREFIX,
                None,
            ),
            crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
            crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        let store = Arc::new(DataKeyStore::new());
        sender.register_builtin_writer_keys(store.clone()).unwrap();
        for (entity, id, material) in announcements {
            store
                .insert(GUID::new(SENDER_PREFIX, entity), id, material.duplicate())
                .unwrap();
            h.dispatch
                .fsm
                .receive_writer_key_for_tests(SENDER_PREFIX, entity, id, material);
        }
        let mut peer = announcement_from(OUR_PREFIX).0;
        peer.metatraffic_unicast_locators = vec![repairs.local_addr().unwrap()];
        sender.handle_spdp(peer);
        let sender = Arc::new(sender);
        let handler = ControlHandler::spawn_with_topic_registry(
            h.dispatch.transport.clone(),
            SENDER_PREFIX,
            7400,
            crate::core::reader::ReaderProxyRegistry::new(),
            crate::core::reader::ReaderProxyRegistry::new(),
            h.dispatch.registry.clone(),
            sender,
            Arc::new(RwLock::new(history)),
        );
        let dispatch = Arc::new(h.dispatch);
        dispatch.arm_secure_sedp();
        dispatch.fsm.replay_sedp_awaiting_key(SENDER_PREFIX);
        let last = GUID::new(SENDER_PREFIX, [0, 0, 0x30, 2]);
        assert!(dispatch.fsm.current_endpoint("Review", &last).is_none());
        let mut buf = [0u8; 8192];
        let mut seen_writers = Vec::new();
        for _ in 0..2 {
            let size = nacks
                .recv(&mut buf)
                .expect("overflow owes a NACK after tokens");
            let an =
                crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages(
                    &buf[..size],
                );
            assert_eq!(an.len(), 1);
            assert_eq!(an[0].bitmap_base, 1);
            assert!(!an[0].missing_ranges.is_empty());
            seen_writers.push(an[0].writer_entity_id);
            let msg = ControlMessage::acknack(
                Origin::direct(repairs.local_addr().unwrap()),
                OUR_PREFIX,
                an.into_iter().next().unwrap(),
                &buf[..size],
            )
            .unwrap();
            assert!(handler.try_send(msg));
        }
        assert_eq!(seen_writers, vec![[0xff, 0, 3, 0xc2], [0xff, 0, 4, 0xc2]]);
        let mut delivered = 0;
        while delivered < 17 {
            let size = repairs
                .recv(&mut buf)
                .expect("secure writer must repair all retained endpoints");
            if crate::security::crypto::secure_submessage::first_secure_prefix(&buf[..size])
                .is_some()
            {
                let (kind, at) = delivery(&buf[..size]);
                dispatch.dispatch(
                    kind,
                    &buf[..size],
                    at,
                    None,
                    Origin::direct(nacks.local_addr().unwrap()),
                );
                delivered += 1;
            }
        }
        for i in 0..17u8 {
            assert!(
                dispatch
                    .fsm
                    .current_endpoint("Review", &GUID::new(SENDER_PREFIX, [0, 0, 0x20 + i, 2]))
                    .is_some(),
                "endpoint {i} absent after reliable repair"
            );
        }
        // Lost requests/replies leave the obligation alive. Clock injection
        // advances the retry deterministically, then synchronized writers
        // cancel their individual obligations.
        let now = Instant::now() + Duration::from_secs(2);
        dispatch.fsm.retry_secure_sedp_repairs(now);
        for _ in 0..2 {
            nacks
                .recv(&mut buf)
                .expect("repair retries until synchronization");
        }
        dispatch
            .fsm
            .finish_secure_sedp_repair(&SENDER_PREFIX, &[0xff, 0, 3, 0xc2]);
        dispatch
            .fsm
            .finish_secure_sedp_repair(&SENDER_PREFIX, &[0xff, 0, 4, 0xc2]);
        dispatch
            .fsm
            .retry_secure_sedp_repairs(now + Duration::from_secs(2));
        nacks.set_nonblocking(true).unwrap();
        assert_eq!(
            nacks.recv(&mut buf).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        handler.shutdown();
    }
    #[test]
    fn replacement_authentication_refreshes_the_local_builtin_writer_generation() {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER, RTPS_ENTITYID_SPDP_SECURE_WRITER,
        };
        let h = review_harness();
        let writers = [
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
            RTPS_ENTITYID_SPDP_SECURE_WRITER,
        ];
        let old: Vec<_> = writers
            .iter()
            .map(|w| h.dispatch.fsm.local_builtin_writer_key_for_tests(*w))
            .collect();
        h.dispatch.fsm.peer_authenticated(
            crate::core::discovery::GUID::new(SENDER_PREFIX, [0, 0, 1, 0xc1]),
            true,
        );
        for (writer, (old_id, old_key)) in writers.iter().zip(old) {
            let (new_id, new_key) = h.dispatch.fsm.local_builtin_writer_key_for_tests(*writer);
            assert_ne!(old_id, new_id);
            assert!(!old_key.same_material(&new_key));
            assert_eq!(old_key.transformation, new_key.transformation);
        }
    }
}
