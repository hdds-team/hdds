// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Secure SEDP uses DDS-Security 1.1 submessage protection.
//!
//! The whole DATA, including inline QoS and writer sequence number, is
//! protected as SEC_PREFIX / SEC_BODY / SEC_POSTFIX (Sec.9.5.3.3.4.5).
//! HDDS releases before 1.5 cannot authenticate and have no alternate codec.
//!
//! # Where the key material comes from
//!
//! From the secure SEDP writers themselves, as the specification has it:
//! each secure builtin writer gets its own key material
//! (`register_local_datawriter`, Sec.8.8.8.3, Table 70; AES256_GCM for an
//! encrypting discovery protection, AES256_GMAC for a signing one, Table
//! 59 `is_discovery_encrypted`) and sends it to each authenticated
//! participant as a DatawriterCryptoTokens message over the volatile secure
//! channel (Sec.8.8.9.2, Table 71; `crypto::volatile::WriterKeyAnnouncement`).
//! This participant ENCODES its SEDP with its own writers' material
//! ([`SedpWriterKeys`]), and DECODES a peer's with the material that peer's
//! writer announced, found by the sender's prefix and the CryptoHeader's
//! `transformation_key_id` (`preprocess_secure_submsg`, Sec.8.5.1.9.6 and
//! Table 72) - never with a key both sides derive. Nothing on this route
//! reads the handshake's shared secret.
//!
//! # SEDP that arrives before the writer's tokens
//!
//! The tokens and the SEDP they protect travel on different endpoints, so a
//! protected SEDP DATA can arrive before the DatawriterCryptoTokens of its
//! writer. Its key id names material the receiver does not hold:
//! `preprocess_secure_submsg` cannot match it to a writer, and the
//! submessage cannot be decoded yet (Sec.8.5.1.9.6: the operation identifies
//! the sending endpoint from the key material the plugin holds). The
//! specification does not order the two; what it makes of the DATA is a
//! change of a reliable writer the reader has not received, which the
//! writer still owes (DDSI-RTPS v2.5 Sec.8.4.2.2-8.4.2.3: missing changes
//! are requested and repaired, never positively acknowledged as received).
//! The receiver holds such a datagram
//! (`DiscoveryFsm::park_sedp_awaiting_key`), and hands it back when a key
//! from that participant is installed. The sender narrows the window: it
//! announces its writers' key material as soon as a handshake completes
//! (`stateless_writer`), over the reliable volatile channel, which repairs
//! a lost announcement on the receiver's request (`volatile_channel`).
//!
#[cfg(feature = "security")]
pub use inner::*;

#[cfg(feature = "security")]
mod inner {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// How many secure SEDP announcements this process REFUSED to send
    /// because protection returned `None` while writer key material
    /// was held. Terminal, never reset: a refusal is a
    /// deterministic property of that endpoint's SEDP body (the encrypted
    /// body no longer fits `octetsToNextHeader`), so it recurs on every
    /// retry and every re-announcement, and a counter that only grows is
    /// what makes a silent retry loop visible from outside.
    static WRAP_REFUSALS: AtomicU64 = AtomicU64::new(0);

    /// Record one refusal and return the running total.
    pub fn note_wrap_refusal() -> u64 {
        WRAP_REFUSALS
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    /// The running total of refusals (see [`note_wrap_refusal`]).
    pub fn wrap_refusals() -> u64 {
        WRAP_REFUSALS.load(Ordering::Relaxed)
    }
    /// Internal detail type: result of scanning an RTPS packet for its DATA submessage.
    ///
    /// Fields:
    /// - `writer_eid_off`: absolute byte offset of the writer entity ID within the packet
    /// - `cdr_start`: absolute byte offset where the CDR payload begins
    /// - `submsg_start`: absolute byte offset where the DATA submessage header starts
    /// - `e_flag`: true when the E (little-endian) flag is set in the submessage flags byte
    struct DataSubmsgInfo {
        writer_eid_off: usize,
        cdr_start: usize,
        submsg_start: usize,
        e_flag: bool,
    }

    /// Locate the DATA submessage in an RTPS packet.
    ///
    /// RTPS submessage framing (RTPS v2.5 Sec.9.4.1):
    /// - byte 0: submessage kind
    /// - byte 1: flags (bit 0 = E = little-endian)
    /// - bytes 2-3: octetsToNextHeader (LE when E=1)
    ///
    /// DATA (kind 0x15) body layout (after the 4-byte header):
    /// - extraFlags        2 bytes
    /// - octetsToInlineQos 2 bytes
    /// - readerEntityId    4 bytes
    /// - writerEntityId    4 bytes  <- writer_eid_off = submsg_start + 12
    /// - writerSeqNum      8 bytes
    /// - (inline QoS, if any)
    /// - CDR payload       <- cdr_start = submsg_start + 8 + octetsToInlineQos
    fn find_data_submsg(packet: &[u8]) -> Option<DataSubmsgInfo> {
        const RTPS_HEADER_LEN: usize = 20;
        const DATA_KIND: u8 = 0x15;
        const DATA_FLAGS_E: u8 = 0x01;

        if packet.len() < RTPS_HEADER_LEN + 4 {
            return None;
        }

        let mut off = RTPS_HEADER_LEN;
        while off + 4 <= packet.len() {
            let kind = packet[off];
            let flags = packet[off + 1];
            let e = (flags & DATA_FLAGS_E) != 0;
            let submsg_len = if e {
                u16::from_le_bytes([packet[off + 2], packet[off + 3]]) as usize
            } else {
                u16::from_be_bytes([packet[off + 2], packet[off + 3]]) as usize
            };

            if kind == DATA_KIND {
                // Need at least DATA header(4) + extraFlags(2) + otiQos(2) = 8 bytes
                if off + 8 > packet.len() {
                    return None;
                }
                let oti = if e {
                    u16::from_le_bytes([packet[off + 6], packet[off + 7]]) as usize
                } else {
                    u16::from_be_bytes([packet[off + 6], packet[off + 7]]) as usize
                };

                // 4(hdr) + 2(extra) + 2(oti_field) + 4(readerEID)
                let writer_eid_off = off + 12;
                // 4(hdr) + 2(extra) + 2(oti_field) + oti_value
                let cdr_start = off + 8 + oti;

                if cdr_start > packet.len() || writer_eid_off + 4 > packet.len() {
                    return None;
                }
                return Some(DataSubmsgInfo {
                    writer_eid_off,
                    cdr_start,
                    submsg_start: off,
                    e_flag: e,
                });
            }

            // Advance past this submessage (length 0 means padding/end-of-packet)
            if submsg_len == 0 {
                break;
            }
            off += 4 + submsg_len;
        }
        None
    }

    /// Walk an RTPS packet to locate the DATA submessage and return
    /// `(writer_eid_offset, cdr_start_offset)` within the packet, or `None`
    /// if no DATA submessage is found or the packet is malformed.
    pub fn find_data_cdr_bounds(packet: &[u8]) -> Option<(usize, usize)> {
        let info = find_data_submsg(packet)?;
        Some((info.writer_eid_off, info.cdr_start))
    }

    /// The key material of this participant's two secure SEDP writers,
    /// SEDPbuiltinPublicationsSecureWriter and
    /// SEDPbuiltinSubscriptionsSecureWriter (Sec.7.4.5), each its own
    /// (module docs): what [`protect_sedp_packet_as`] protects their DATA
    /// with.
    pub struct SedpWriterKeys {
        /// SEDPbuiltinPublicationsSecureWriter (`ff.00.03.c2`).
        pub publications: crate::security::crypto::secure_submessage::WriterKeyMaterial,
        /// SEDPbuiltinSubscriptionsSecureWriter (`ff.00.04.c2`).
        pub subscriptions: crate::security::crypto::secure_submessage::WriterKeyMaterial,
    }

    impl std::fmt::Debug for SedpWriterKeys {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SedpWriterKeys")
                .field("publications", &self.publications)
                .field("subscriptions", &self.subscriptions)
                .finish()
        }
    }

    /// The discovery protection a SEDP change goes out under: governance
    /// alone decides it. Without a governance document the endpoint's
    /// announced `is_discovery_protected` describes the payload plane and
    /// says nothing of discovery - a participant without access control has
    /// no topic rule to answer it from - so it is dropped and `None` keeps
    /// the no-governance posture: sealed to an authenticated participant, in
    /// clear to any other. With a document the endpoint attribute stands.
    ///
    /// Idempotent, so the paths that must know the decision before routing
    /// (a repair that answers on the secure writer, a GAP) ask this one
    /// function rather than repeat the rule.
    pub fn governed_discovery_protected(
        governed: bool,
        endpoint_discovery_protected: Option<bool>,
    ) -> Option<bool> {
        if governed {
            endpoint_discovery_protected
        } else {
            None
        }
    }

    impl SedpWriterKeys {
        /// The material of the secure writer that sends what the plain SEDP
        /// writer `plain_writer` announces (`00.00.03.c2` or `00.00.04.c2`),
        /// `None` for any other writer.
        fn for_plain_writer(
            &self,
            plain_writer: &[u8],
        ) -> Option<&crate::security::crypto::secure_submessage::WriterKeyMaterial> {
            match plain_writer {
                [0x00, 0x00, 0x03, 0xc2] => Some(&self.publications),
                [0x00, 0x00, 0x04, 0xc2] => Some(&self.subscriptions),
                _ => None,
            }
        }
    }

    /// Writer key material for tests: both writers from `seed`, distinct
    /// keys, salts and key ids, under `transformation`.
    #[cfg(test)]
    pub(crate) fn test_writer_keys(
        seed: u8,
        transformation: crate::security::crypto::secure_submessage::Transformation,
    ) -> SedpWriterKeys {
        use crate::security::crypto::secure_submessage::WriterKeyMaterial;
        SedpWriterKeys {
            publications: WriterKeyMaterial::new([seed; 32], [seed ^ 0x0F; 32], [0, 3, 0, seed])
                .with_transformation(transformation),
            subscriptions: WriterKeyMaterial::new(
                [seed ^ 0xF0; 32],
                [seed ^ 0xFF; 32],
                [0, 4, 0, seed],
            )
            .with_transformation(transformation),
        }
    }

    /// The plain SEDP entity id `id` in the secure namespace, or back:
    /// SEDPbuiltinPublications/Subscriptions writer and reader, `{00,00,03}`
    /// and `{00,00,04}` against `{ff,00,03}` and `{ff,00,04}` (DDS-Security
    /// 1.1 Sec.7.3.7.1, Table 9). Any other id is left as it is.
    fn sedp_entity_in(id: &mut [u8], secure: bool) {
        let (from, to) = if secure { (0x00, 0xff) } else { (0xff, 0x00) };
        if id.len() == 4
            && id[0] == from
            && id[1] == 0x00
            && matches!(id[2], 0x03 | 0x04)
            && matches!(id[3], 0xc2 | 0xc7)
        {
            id[0] = to;
        }
    }

    /// The plain SEDP datagram `packet` as this participant's secure SEDP
    /// writer sends it under DDS-Security 1.1 submessage protection (module
    /// docs), encrypted: [`protect_sedp_packet_as`] with ENCRYPT.
    pub fn protect_sedp_packet(packet: &[u8], keys: &SedpWriterKeys) -> Option<Vec<u8>> {
        protect_sedp_packet_as(
            packet,
            keys,
            crate::security::access::ProtectionKind::Encrypt,
        )
    }

    /// The plain SEDP datagram `packet` as this participant's secure SEDP
    /// writer sends it under the discovery protection `kind`
    /// (Sec.9.4.1.2.5.4: the secure discovery writers are protected "as
    /// specified in 9.4.1.2.2 with regards to the RTPS SubMessages"): its
    /// first DATA, renamed to the secure SEDP writer and reader and given an
    /// explicit length, then
    ///
    /// - NONE: left as it is - "no cryptographic transformation is applied"
    ///   (Sec.9.4.1.2.1); it is still the secure writer's DATA;
    /// - SIGN: between a SEC_PREFIX and a SEC_POSTFIX carrying its AES-GMAC
    ///   (Sec.9.5.3.3.4.5, authentication only);
    /// - ENCRYPT: replaced by the SEC_PREFIX / SEC_BODY / SEC_POSTFIX of
    ///   AES-GCM.
    ///
    /// Each under the key material of the secure writer that sends it
    /// (`keys`), whose transformation is the one `kind` names (it was minted
    /// from it, `DiscoveryFsm::register_builtin_writer_keys`).
    ///
    /// What precedes and follows it is unchanged. `None` when there is no
    /// DATA, or it is not one of the two SEDP writers', or it cannot be
    /// protected (the transformation failed, a body octetsToNextHeader cannot
    /// carry, a key material of another transformation than `kind`, or an
    /// origin-authenticating `kind`, which governance refuses at load: its
    /// receiver-specific keys are per remote reader, Table 70); the caller
    /// then does not send it.
    pub fn protect_sedp_packet_as(
        packet: &[u8],
        keys: &SedpWriterKeys,
        kind: crate::security::access::ProtectionKind,
    ) -> Option<Vec<u8>> {
        use crate::security::crypto::secure_submessage::{
            encode_datawriter_submessage, Transformation,
        };
        if kind.is_origin_authenticated() {
            return None;
        }
        let info = find_data_submsg(packet)?;
        let end = find_data_submsg_end(packet)?;
        // octetsToNextHeader 0 runs to the end of the message.
        let end = if end == info.submsg_start + 4 {
            packet.len()
        } else {
            end
        };
        let mut data = packet.get(info.submsg_start..end)?.to_vec();
        let material = keys.for_plain_writer(data.get(12..16)?)?;
        sedp_entity_in(&mut data[8..12], true);
        sedp_entity_in(&mut data[12..16], true);
        // The DATA is no longer the last submessage of the message once it
        // is read back between its neighbours, or sits before a
        // SEC_POSTFIX: its length is written out.
        let body = u16::try_from(data.len() - 4).ok()?;
        data[2..4].copy_from_slice(&if info.e_flag {
            body.to_le_bytes()
        } else {
            body.to_be_bytes()
        });
        let protected = if kind.is_protected() {
            let transformation = if kind.is_encrypted() {
                Transformation::Aes256Gcm
            } else {
                Transformation::Aes256Gmac
            };
            if material.transformation() != transformation {
                return None;
            }
            encode_datawriter_submessage(material, &data).ok()?
        } else {
            data.clone()
        };
        let mut out = Vec::with_capacity(packet.len() + protected.len() - data.len());
        out.extend_from_slice(&packet[..info.submsg_start]);
        out.extend_from_slice(&protected);
        out.extend_from_slice(&packet[end..]);
        Some(out)
    }

    /// Whether a secure SEDP DATA protected as `observed` meets the
    /// discovery protection `required` of the receiving participant: at
    /// least as strong - NONE, then SIGN, then ENCRYPT, which authenticates
    /// too - and origin-authenticated when that is required.
    ///
    /// The other way round would let a forger downgrade: a participant whose
    /// governance asks ENCRYPT would read a clear DATA anybody can write under
    /// an authenticated participant's prefix.
    #[must_use]
    pub fn protection_satisfies(
        observed: crate::security::access::ProtectionKind,
        required: crate::security::access::ProtectionKind,
    ) -> bool {
        use crate::security::access::ProtectionKind;
        let rank = |kind: ProtectionKind| match kind {
            ProtectionKind::None => 0,
            ProtectionKind::Sign | ProtectionKind::SignWithOriginAuthentication => 1,
            ProtectionKind::Encrypt | ProtectionKind::EncryptWithOriginAuthentication => 2,
        };
        rank(observed) >= rank(required)
            && (!required.is_origin_authenticated() || observed.is_origin_authenticated())
    }

    /// A secure SEDP datagram read back ([`open_secure_sedp_as`]).
    #[derive(Debug)]
    pub struct OpenedSedp {
        /// The plain SEDP datagram the discovery consumer reads.
        pub datagram: Vec<u8>,
        /// The offset of its DATA's serialized payload.
        pub payload_at: usize,
        /// The protection it was received under.
        pub protection: crate::security::access::ProtectionKind,
        /// One past this envelope's own content in the ORIGINAL datagram
        /// (`decoded.end` for [`open_secure_sedp_as`]; the whole datagram's
        /// length for [`open_clear_secure_sedp`], which has no envelope to
        /// bound). The caller resumes scanning for a FURTHER
        /// independently-protected envelope from here
        /// (`secure_submessage::first_secure_prefix_from`) rather than
        /// assuming a compound datagram holds only one.
        pub end: usize,
    }

    /// The `transformation_key_id` of the CryptoHeader of the SEC_PREFIX at
    /// `prefix_at` (Sec.9.5.2.3), as the `u64` writer key stores file it
    /// (`CryptoTransformKeyId` read big endian), before anything is
    /// verified: which key material the sender says it used.
    #[must_use]
    pub fn transformation_key_id_at(datagram: &[u8], prefix_at: usize) -> Option<u64> {
        if datagram.get(prefix_at) != Some(&crate::security::crypto::secure_submessage::SEC_PREFIX)
        {
            return None;
        }
        let id: [u8; 4] = datagram
            .get(prefix_at + 8..prefix_at + 12)?
            .try_into()
            .ok()?;
        Some(u64::from(u32::from_be_bytes(id)))
    }

    /// The datagram `datagram`, whose SEC_PREFIX is at `offset`, read as the
    /// secure builtin writer `writer` (its entity id) of the sender protects
    /// it under `material`, that writer's key material received in its
    /// DatawriterCryptoTokens: decoded under the transformation the material
    /// names (`decode_datawriter_submessage` refuses a CryptoHeader of
    /// another kind or key id), then required to be a DATA OF THAT WRITER,
    /// and to meet `required` ([`protection_satisfies`]). The plain SEDP
    /// datagram the discovery consumer reads, ids back in the plain
    /// namespace. `None` when any of it fails.
    ///
    /// The writer check is what binds the key to the endpoint: a key
    /// material is one writer's, and a DATA it decodes that names another
    /// writer is not taken as that other writer's.
    pub fn open_secure_sedp_as(
        datagram: &[u8],
        offset: usize,
        material: &crate::security::crypto::secure_submessage::WriterKeyMaterial,
        writer: &[u8; 4],
        required: crate::security::access::ProtectionKind,
    ) -> Option<OpenedSedp> {
        use crate::security::access::ProtectionKind;
        use crate::security::crypto::secure_submessage::{
            decode_datawriter_submessage, Transformation, SEC_PREFIX,
        };

        if datagram.get(offset) != Some(&SEC_PREFIX) {
            return None;
        }
        let decoded = decode_datawriter_submessage(material, datagram, offset).ok()?;
        let protection = match decoded.transformation {
            Transformation::Aes256Gcm => ProtectionKind::Encrypt,
            Transformation::Aes256Gmac => ProtectionKind::Sign,
        };
        if !protection_satisfies(protection, required) {
            return None;
        }
        let mut data = decoded.submessage;
        if data.first() != Some(&0x15) || data.len() < 24 || data[12..16] != writer[..] {
            return None;
        }
        sedp_entity_in(&mut data[8..12], false);
        sedp_entity_in(&mut data[12..16], false);
        // What precedes and follows this envelope is unchanged, UP TO the
        // next independently-protected envelope, if any: a HEARTBEAT in
        // clear right after this DATA is legitimate trailing receiver
        // traffic and belongs in the synthetic packet handed to the plain
        // SEDP handler, but a SECOND SEC_PREFIX right after it is a
        // DIFFERENT envelope entirely (an ACKNACK, say) -- stitching its
        // still-opaque ciphertext into a "plain SEDP" packet would hand
        // the ordinary handler bytes it cannot make sense of, and lose the
        // later envelope outright. The
        // caller resumes its OWN scan from `end` instead.
        let stitch_end = crate::security::crypto::secure_submessage::first_secure_prefix_from(
            datagram,
            decoded.end,
        )
        .unwrap_or(datagram.len());
        let mut out = Vec::with_capacity(datagram.len());
        out.extend_from_slice(&datagram[..offset]);
        out.extend_from_slice(&data);
        out.extend_from_slice(&datagram[decoded.end..stitch_end]);
        let layout = crate::protocol::builder::data_submessage_layout(&out, offset)?;
        Some(OpenedSedp {
            datagram: out,
            payload_at: layout.payload,
            protection,
            end: decoded.end,
        })
    }

    /// The NONE shape of secure SEDP (Sec.9.4.1.2.1: "no cryptographic
    /// transformation is applied"): a clear DATA of a secure SEDP writer at
    /// payload offset `offset`, and nothing protected in the datagram (a
    /// SEC_PREFIX is read by [`open_secure_sedp_as`], from its own offset:
    /// the DATA a SIGN-protected datagram carries in clear is never taken
    /// without its MAC). `None` unless `required` is NONE.
    pub fn open_clear_secure_sedp(
        datagram: &[u8],
        offset: usize,
        required: crate::security::access::ProtectionKind,
    ) -> Option<OpenedSedp> {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
        };
        use crate::security::access::ProtectionKind;
        use crate::security::crypto::secure_submessage::first_secure_prefix;

        if !protection_satisfies(ProtectionKind::None, required)
            || first_secure_prefix(datagram).is_some()
        {
            return None;
        }
        let info = find_data_submsg(datagram)?;
        let writer = datagram.get(info.writer_eid_off..info.writer_eid_off + 4)?;
        let layout = crate::protocol::builder::data_submessage_layout(datagram, info.submsg_start)?;
        if layout.payload != offset
            || (writer != RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER
                && writer != RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER)
        {
            return None;
        }
        let mut out = datagram.to_vec();
        sedp_entity_in(
            &mut out[info.writer_eid_off - 4..info.writer_eid_off],
            false,
        );
        sedp_entity_in(
            &mut out[info.writer_eid_off..info.writer_eid_off + 4],
            false,
        );
        let end = out.len();
        Some(OpenedSedp {
            datagram: out,
            payload_at: offset,
            protection: ProtectionKind::None,
            end,
        })
    }

    /// The datagram one SEDP change goes to one participant as, or `None`
    /// when that participant is to get the change's sequence number as a GAP
    /// on the regular SEDP writer instead.
    ///
    /// `endpoint_discovery_protected` is the endpoint's `is_discovery_protected`
    /// (DDS-Security v1.1 Table 29): "If is_discovery_protected is TRUE, then
    /// discovery information for that entity shall be sent using the
    /// SEDPbuiltinPublicationsSecureWriter SEDPbuiltinSubscriptionsSecureWriter.
    /// If is_discovery_protected is FALSE, then discovery information for that
    /// entity shall be sent using the SEDPbuiltinPublicationsWriter or
    /// SEDPbuiltinSubscriptionsWriter." The secure writers are protected by the
    /// participant's `discovery_kind` (Sec.9.4.1.2.5.4), NONE included: NONE
    /// still sends on the secure writer, untransformed. `keys` is what SEDP to
    /// an authenticated participant is sealed with, `None` for any other.
    ///
    /// - Not protected: the regular writer, in clear, to everyone.
    /// - Protected, to an authenticated participant: the secure writer, as
    ///   the participant's keys and `discovery_kind` say.
    /// - Protected, to a participant that has not authenticated: nothing.
    ///   Sec.8.8.2.1: for an unauthenticated participant "the
    ///   DomainParticipant shall match only the regular builtin Endpoints
    ///   ... and not the builtin secure Endpoints"; Sec.8.8.2.2 matches them
    ///   only after the authentication protocol succeeds. The number becomes
    ///   a GAP on the regular writer so its reader does not wait for it.
    /// - `governed` false (the participant runs no governance document),
    ///   whatever the endpoint announces: the attribute says what protects the
    ///   endpoint's payload, never where its discovery goes
    ///   ([`governed_discovery_protected`]), so the change is sealed to an
    ///   authenticated participant, encrypted, and in clear to any other -
    ///   what this release has always done.
    ///
    /// A datagram with no DATA (a GAP) goes as it is. A change that had to be
    /// sealed and could not be is not sent in clear: `None`, logged.
    pub fn sedp_datagram_for(
        packet: Vec<u8>,
        endpoint_discovery_protected: Option<bool>,
        governed: bool,
        keys: Option<&SedpWriterKeys>,
        discovery_kind: crate::security::access::ProtectionKind,
        peer_prefix: &[u8; 12],
    ) -> Option<Vec<u8>> {
        let discovery_protected =
            governed_discovery_protected(governed, endpoint_discovery_protected);
        if find_data_cdr_bounds(&packet).is_none() {
            return Some(packet);
        }
        let sealed = match (discovery_protected, keys) {
            (Some(false), _) | (None, None) => return Some(packet),
            (Some(true), None) => return None,
            (None, Some(writers)) => protect_sedp_packet(&packet, writers),
            (Some(true), Some(writers)) => protect_sedp_packet_as(&packet, writers, discovery_kind),
        };
        if sealed.is_none() {
            let refusals = note_wrap_refusal();
            log::error!(
                "[secure-sedp] SEDP to authenticated peer {:02x?} could not be sealed: not \
                 sent (refusal #{} in this process)",
                peer_prefix,
                refusals
            );
        }
        sealed
    }

    /// Return the byte offset immediately AFTER the DATA submessage body.
    ///
    /// Reads `octetsToNextHeader` from the packet before protection.
    fn find_data_submsg_end(packet: &[u8]) -> Option<usize> {
        let info = find_data_submsg(packet)?;
        // Re-read octetsToNextHeader from the actual packet bytes (may be updated).
        let off = info.submsg_start;
        if off + 4 > packet.len() {
            return None;
        }
        let submsg_len = if info.e_flag {
            u16::from_le_bytes([packet[off + 2], packet[off + 3]]) as usize
        } else {
            u16::from_be_bytes([packet[off + 2], packet[off + 3]]) as usize
        };
        Some(off + 4 + submsg_len)
    }

    /// Submessage id `id` (RTPS v2.5 Table 8.13) at or after the RTPS
    /// header, `(start, end)` -- `start` at its 4-octet header, `end`
    /// exclusive. `None` when absent, or a declared length runs past the
    /// datagram (a malformed submessage never yields a false match).
    fn find_submessage(packet: &[u8], id: u8) -> Option<(usize, usize)> {
        const RTPS_HEADER_LEN: usize = 20;
        const FLAG_E: u8 = 0x01;
        let mut off = RTPS_HEADER_LEN;
        while off + 4 <= packet.len() {
            let flags = packet[off + 1];
            let declared = if flags & FLAG_E != 0 {
                u16::from_le_bytes([packet[off + 2], packet[off + 3]])
            } else {
                u16::from_be_bytes([packet[off + 2], packet[off + 3]])
            };
            let end = if declared == 0 {
                packet.len()
            } else {
                off + 4 + usize::from(declared)
            };
            if end > packet.len() {
                return None;
            }
            if packet[off] == id {
                return Some((off, end));
            }
            off = end;
        }
        None
    }

    /// ACKNACK submessage id (RTPS v2.5 Table 8.13).
    const ACKNACK_ID: u8 = 0x06;
    /// NACK_FRAG submessage id (RTPS v2.5 Table 8.13).
    const NACK_FRAG_ID: u8 = 0x12;

    /// Our own ACKNACK or NACK_FRAG `packet` (as `control::
    /// build_acknack_packet_with_final` built it: RTPS header, INFO_DST,
    /// then the one control submessage), protected under `material` -- our
    /// builtin secure reader's submessage-protection key -- per DDS
    /// Security v1.1 Sec.8.8.9.3: the control submessage replaced by the
    /// SEC_PREFIX/SEC_BODY/SEC_POSTFIX of `encode_datareader_submessage`.
    /// What precedes it (the RTPS header and INFO_DST, receiver state,
    /// DDSI-RTPS v2.5 Sec.8.3.7.9) is unchanged -- the same "what precedes
    /// and follows it is unchanged" rule [`protect_sedp_packet_as`] applies
    /// on the writer's side of this same tunnel.
    ///
    /// `None` when the packet carries neither submessage, or protection
    /// fails (the caller then does not send it: a writer that requires
    /// protection must not receive this reader's ACKNACK in clear instead).
    pub fn protect_reader_control_packet(
        packet: &[u8],
        material: &crate::security::crypto::secure_submessage::WriterKeyMaterial,
    ) -> Option<Vec<u8>> {
        use crate::security::crypto::secure_submessage::encode_datareader_submessage;
        let (start, end) = find_submessage(packet, ACKNACK_ID)
            .or_else(|| find_submessage(packet, NACK_FRAG_ID))?;
        let submessage = packet.get(start..end)?;
        let protected = encode_datareader_submessage(material, submessage).ok()?;
        let mut out = Vec::with_capacity(packet.len() - submessage.len() + protected.len());
        out.extend_from_slice(&packet[..start]);
        out.extend_from_slice(&protected);
        out.extend_from_slice(&packet[end..]);
        Some(out)
    }

    /// What [`open_reader_control_packet`] recovered.
    #[derive(Debug)]
    pub struct OpenedReaderControl {
        /// The decoded ACKNACK or NACK_FRAG, header included, exactly as
        /// the reader built it -- never spliced into a copy of the
        /// surrounding datagram (see the function's own docs for why: a
        /// caller re-parsing a bigger buffer can pick up a submessage this
        /// decode never touched).
        pub submessage: Vec<u8>,
        /// One past the SEC_POSTFIX in the ORIGINAL `datagram`: where a
        /// caller handling a compound datagram (DDS-Security v1.1 does not
        /// forbid several independently-protected control submessages in
        /// one RTPS message) resumes its own scan, e.g. with
        /// `secure_submessage::first_secure_prefix_from`. Never silently
        /// swallowed: the caller decides what happens to `datagram[end..]`,
        /// this function only reports where its own envelope ended.
        pub end: usize,
    }

    /// The ACKNACK or NACK_FRAG `datagram`'s SEC_PREFIX at `prefix_at`
    /// (`secure_submessage::first_secure_prefix`/`_from`), opened as the
    /// mirror image of [`protect_reader_control_packet`]: decoded under
    /// `material` -- the sender's announced DatareaderCryptoTokens key
    /// (`DiscoveryFsm::remote_builtin_reader_materials`) -- and returned as
    /// JUST that one decoded submessage plus where its envelope ended.
    ///
    /// Deliberately NOT spliced back into a copy of `datagram`: an earlier
    /// version did (`datagram[..prefix_at]` followed by the decoded bytes)
    /// and handed the result to a generic multi-submessage ACKNACK/NACK_FRAG
    /// parser, which happily picked up ANY OTHER submessage riding in
    /// `datagram[..prefix_at]` too -- a CLEAR ACKNACK prepended ahead of a
    /// genuinely encrypted one inherited that envelope's "protected" status
    /// for free. The only bytes this function's caller may ever mark
    /// protected are the ones returned here.
    ///
    /// `reader` is the entity id of the CANDIDATE reader whose key material
    /// this is (`DiscoveryFsm::remote_builtin_reader_materials` hands back
    /// one candidate at a time); `required` is this participant's discovery
    /// protection kind. `None` when:
    /// - the envelope does not decode under `material` at all;
    /// - what it protects is not an ACKNACK or a NACK_FRAG;
    /// - its OWN transformation does not meet `required`
    ///   ([`protection_satisfies`], the same rule [`open_secure_sedp_as`]
    ///   applies on the writer side -- Sec.9.4.1.2.2);
    /// - the decoded submessage's `readerId` does not name `reader`, or its
    ///   `writerId` does not name that reader's mirrored builtin writer
    ///   (Sec.8.5.1.9.6 `preprocess_secure_submsg`: the operation identifies
    ///   the sending endpoint from the key material the plugin holds, and a
    ///   decode that merely verifies under SOME key is not yet proof of
    ///   WHICH endpoint sent it -- the same reasoning
    ///   `open_secure_sedp_as`'s `data[12..16] != writer` check applies to a
    ///   DATA's embedded writer id).
    pub fn open_reader_control_packet(
        datagram: &[u8],
        prefix_at: usize,
        material: &crate::security::crypto::secure_submessage::WriterKeyMaterial,
        reader: &[u8; 4],
        required: crate::security::access::ProtectionKind,
    ) -> Option<OpenedReaderControl> {
        use crate::security::access::ProtectionKind;
        use crate::security::crypto::secure_submessage::{
            decode_datareader_submessage, Transformation,
        };
        let decoded = decode_datareader_submessage(material, datagram, prefix_at).ok()?;
        let protection = match decoded.transformation {
            Transformation::Aes256Gcm => ProtectionKind::Encrypt,
            Transformation::Aes256Gmac => ProtectionKind::Sign,
        };
        if !protection_satisfies(protection, required) {
            return None;
        }
        if !matches!(
            decoded.submessage.first(),
            Some(&ACKNACK_ID) | Some(&NACK_FRAG_ID)
        ) {
            return None;
        }
        // ACKNACK (Sec.8.3.8.1) and NACK_FRAG (Sec.8.3.8.12) agree on this
        // much of their layout: a 4-octet submessage header, then
        // readerId(4), writerId(4).
        let reader_id = decoded.submessage.get(4..8)?;
        if reader_id != reader.as_slice() {
            return None;
        }
        let our_writer = crate::security::crypto::volatile::builtin_peer_entity_id(*reader)?;
        let writer_id = decoded.submessage.get(8..12)?;
        if writer_id != our_writer.as_slice() {
            return None;
        }
        Some(OpenedReaderControl {
            submessage: decoded.submessage,
            end: decoded.end,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "security")]
    mod security_tests {
        use super::super::inner::*;
        use crate::security::access::ProtectionKind;
        use crate::security::crypto::secure_submessage::Transformation;

        const PUBLICATIONS_SECURE_WRITER: [u8; 4] = [0xff, 0x00, 0x03, 0xc2];

        /// A valid RTPS DATA under the regular publications writer.
        fn plain_sedp_datagram(payload: &[u8]) -> Vec<u8> {
            use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};

            // DATA body: extraFlags 2 + octetsToInlineQos 2 + readerEntityId 4
            // + writerEntityId 4 + writerSN 8, then the serialized payload.
            const DATA_FIXED_BODY: usize = 20;
            const CDR_OFFSET: usize = 20 + 4 + DATA_FIXED_BODY;

            let mut plain = vec![0u8; 20];
            plain[0..4].copy_from_slice(b"RTPS");
            plain[4] = RTPS_VERSION_MAJOR;
            plain[5] = RTPS_VERSION_MINOR;
            plain[6..8].copy_from_slice(&crate::protocol::constants::HDDS_VENDOR_ID);
            plain[8..20].copy_from_slice(&[0x11u8; 12]);
            plain.push(0x15); // DATA
            plain.push(0x05); // E | D: little-endian DATA, no inline QoS
            plain.extend_from_slice(&((DATA_FIXED_BODY + payload.len()) as u16).to_le_bytes());
            plain.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
            plain.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
            plain.extend_from_slice(&[0x00, 0x00, 0x03, 0xC7]); // readerEntityId
            plain.extend_from_slice(&[0x00, 0x00, 0x03, 0xC2]); // writerEntityId
            plain.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]); // writerSN
            plain.extend_from_slice(payload);
            assert_eq!(
                plain.len(),
                CDR_OFFSET + payload.len(),
                "fixture: the payload must start where the callers say it does"
            );

            plain
        }

        /// A DATA that is the last submessage of its message may declare
        /// octetsToNextHeader 0 (DDSI-RTPS v2.5 Sec.9.4.5.1.3). Protected, it
        /// is read back between the submessages around it, so it carries its
        /// length: the HEARTBEAT the sender appends after protecting it is
        /// still a HEARTBEAT after the peer opens it, not part of the DATA.
        #[test]
        fn a_last_data_declaring_no_length_is_protected_with_its_length() {
            let payload: Vec<u8> = (0..40u8).collect();
            // The plain datagram alone: header, DATA, no HEARTBEAT.
            let mut plain = plain_sedp_datagram(&payload);
            plain.truncate(20 + 4 + 20 + payload.len());
            let declared = plain.clone();
            plain[22..24].copy_from_slice(&0u16.to_le_bytes());

            let keys = test_writer_keys(0x42, Transformation::Aes256Gcm);
            let mut wire = protect_sedp_packet(&plain, &keys).expect("protect");
            let mut heartbeat = vec![0x07u8, 0x01];
            heartbeat.extend_from_slice(&28u16.to_le_bytes());
            heartbeat.extend_from_slice(&[0xAAu8; 28]);
            wire.extend_from_slice(&heartbeat);

            let opened = open_secure_sedp_as(
                &wire,
                20,
                &keys.publications,
                &PUBLICATIONS_SECURE_WRITER,
                ProtectionKind::Encrypt,
            )
            .expect("open");
            let (opened, at) = (opened.datagram, opened.payload_at);
            let mut expected = declared;
            expected.extend_from_slice(&heartbeat);
            assert_eq!(
                opened, expected,
                "the DATA's length written out, the HEARTBEAT after it"
            );
            assert_eq!(at, 44, "its payload");
        }

        /// A key material is one writer's: what it decodes is read only as a
        /// DATA of that writer. The same protection around a DATA of another
        /// writer - the secure participant writer, or the other secure SEDP
        /// writer - decodes, and is not read.
        ///
        /// Mutant: the `data[12..16] != writer` check removed from
        /// `open_secure_sedp_as` fails the two refusals.
        #[test]
        fn a_protected_data_of_another_writer_is_not_read_as_that_writers() {
            let payload: Vec<u8> = (0..40u8).collect();
            let plain = plain_sedp_datagram(&payload);
            let keys = test_writer_keys(0x42, Transformation::Aes256Gcm);
            let material = &keys.publications;
            let protect_as = |reader: [u8; 4], writer: [u8; 4]| {
                let mut data = plain[20..20 + 4 + 20 + payload.len()].to_vec();
                data[8..12].copy_from_slice(&reader);
                data[12..16].copy_from_slice(&writer);
                let mut wire = plain[..20].to_vec();
                wire.extend_from_slice(
                    &crate::security::crypto::secure_submessage::encode_datawriter_submessage(
                        material, &data,
                    )
                    .expect("protect"),
                );
                assert!(
                    crate::security::crypto::secure_submessage::decode_datawriter_submessage(
                        material, &wire, 20
                    )
                    .is_ok(),
                    "fixture: it decodes"
                );
                wire
            };
            let open = |wire: &[u8]| {
                open_secure_sedp_as(
                    wire,
                    20,
                    material,
                    &PUBLICATIONS_SECURE_WRITER,
                    ProtectionKind::Encrypt,
                )
            };
            assert!(
                open(&protect_as(
                    [0xff, 0x01, 0x01, 0xc7],
                    [0xff, 0x01, 0x01, 0xc2]
                ))
                .is_none(),
                "the secure participant writer's DATA"
            );
            assert!(
                open(&protect_as(
                    [0xff, 0x00, 0x04, 0xc7],
                    [0xff, 0x00, 0x04, 0xc2]
                ))
                .is_none(),
                "the subscriptions writer's DATA under the publications writer's key"
            );
            // The writer whose key it is, as the control.
            assert!(open(&protect_as(
                [0xff, 0x00, 0x03, 0xc7],
                [0xff, 0x00, 0x03, 0xc2]
            ))
            .is_some());
        }

        /// Each participant's writers have their own key material: what one
        /// participant protects opens under the material it announced, and
        /// not under another participant's - our own included.
        #[test]
        fn a_datagram_opens_only_under_its_senders_material() {
            let payload: Vec<u8> = (0..40u8).collect();
            let plain = plain_sedp_datagram(&payload);
            let plain = plain[..20 + 4 + 20 + payload.len()].to_vec();
            let sender = test_writer_keys(0x11, Transformation::Aes256Gcm);
            let ours = test_writer_keys(0x22, Transformation::Aes256Gcm);
            let wire = protect_sedp_packet(&plain, &sender).expect("protect");
            let open = |material| {
                open_secure_sedp_as(
                    &wire,
                    20,
                    material,
                    &PUBLICATIONS_SECURE_WRITER,
                    ProtectionKind::Encrypt,
                )
            };
            assert!(open(&sender.publications).is_some());
            assert!(open(&ours.publications).is_none());
            assert_eq!(
                transformation_key_id_at(&wire, 20),
                Some(u64::from(u32::from_be_bytes(sender.publications.key_id()))),
                "the CryptoHeader names the sender's writer key id"
            );
        }

        #[test]
        fn find_data_cdr_bounds_no_data_returns_none() {
            // RTPS header only (20 bytes), no submessages
            let packet = vec![0u8; 20];
            assert!(find_data_cdr_bounds(&packet).is_none());
        }

        #[test]
        fn find_data_cdr_bounds_finds_data_submessage() {
            // Minimal RTPS packet: header + DATA submessage with octetsToInlineQos=16
            // Layout: hdr(20) + submsg_hdr(4) + extraFlags(2) + oti(2) + body(16) + cdr(10)
            let body_len: u16 = (2 + 2 + 16 + 10) as u16;
            let total = 20 + 4 + body_len as usize;
            let mut packet = vec![0u8; total];
            packet[20] = 0x15; // DATA kind
            packet[21] = 0x01; // E-flag (LE)
            let len_bytes = body_len.to_le_bytes();
            packet[22] = len_bytes[0];
            packet[23] = len_bytes[1];
            // octetsToInlineQos = 16 at DATA body offset 2..4
            packet[26] = 16;
            packet[27] = 0;

            let (writer_eid_off, cdr_start) = find_data_cdr_bounds(&packet).unwrap();
            assert_eq!(writer_eid_off, 20 + 12); // submsg_start + 12
            assert_eq!(cdr_start, 20 + 8 + 16); // submsg_start + 8 + oti_value
        }
    }
}

#[cfg(all(test, feature = "security"))]
mod authenticated_header_tests {
    use super::*;

    /// DDS-Security v1.1 Sec.9.5.3.3.4.5 protects the entire DATA,
    /// including the writer sequence number and flags.
    #[test]
    fn a_modified_protected_submessage_cannot_change_the_opened_data() {
        let prefix = [0x44u8; 12];
        let mut p = b"RTPS".to_vec();
        p.extend_from_slice(&[2, 5, 1, 0x1a]);
        p.extend_from_slice(&prefix);
        let sample = [0u8, 3, 0, 0, 1, 0, 0, 0];
        let body = 20 + sample.len();
        p.extend_from_slice(&[0x15, 0x05]);
        p.extend_from_slice(&(body as u16).to_le_bytes());
        p.extend_from_slice(&[0, 0, 16, 0, 0, 0, 3, 0xc7, 0, 0, 3, 0xc2]);
        p.extend_from_slice(&[0, 0, 0, 0, 7, 0, 0, 0]);
        p.extend_from_slice(&sample);

        let keys = test_writer_keys(
            0x33,
            crate::security::crypto::secure_submessage::Transformation::Aes256Gcm,
        );
        let open = |wire: &[u8]| {
            open_secure_sedp_as(
                wire,
                20,
                &keys.publications,
                &[0xff, 0x00, 0x03, 0xc2],
                crate::security::access::ProtectionKind::Encrypt,
            )
            .map(|opened| opened.datagram)
        };
        let prot = protect_sedp_packet(&p, &keys).expect("spec seal");
        let good = open(&prot).expect("opens");
        for i in 24..prot.len() {
            let mut f = prot.clone();
            f[i] ^= 0x01;
            if let Some(o) = open(&f) {
                assert_eq!(o, good, "spec shape: octet {} changed the output", i);
            }
        }
    }
}

/// The discovery protection kinds on the secure SEDP writer (DDS-Security
/// v1.1 Sec.9.4.1.2.5.4 with 9.4.1.2.1, 9.4.1.2.2, 9.5.3.3.4.5), read from
/// the octets.
#[cfg(all(test, feature = "security"))]
mod protection_kind_tests {
    use super::*;
    use crate::security::access::ProtectionKind;

    use crate::security::crypto::secure_submessage::Transformation;

    const SENDER: [u8; 12] = [0x11; 12];
    const WRITER: [u8; 4] = [0xff, 0x00, 0x03, 0xc2];

    /// The writers' key material for the protection `kind`: AES256_GMAC
    /// for SIGN, AES256_GCM otherwise (Table 59).
    fn keys(transformation: Transformation) -> SedpWriterKeys {
        test_writer_keys(0x42, transformation)
    }

    fn transformation_of(kind: ProtectionKind) -> Transformation {
        if kind.is_encrypted() || !kind.is_protected() {
            Transformation::Aes256Gcm
        } else {
            Transformation::Aes256Gmac
        }
    }

    /// RTPS header, then a DATA of the plain publications writer whose
    /// payload is 40 octets, then a HEARTBEAT the protection leaves alone.
    fn plain() -> (Vec<u8>, Vec<u8>) {
        let mut p = b"RTPS".to_vec();
        p.extend_from_slice(&[2, 5, 0x01, 0x1a]);
        p.extend_from_slice(&SENDER);
        p.extend_from_slice(&[0x15, 0x05]); // DATA, E | D
        p.extend_from_slice(&60u16.to_le_bytes());
        p.extend_from_slice(&[0, 0, 16, 0]);
        p.extend_from_slice(&[0x00, 0x00, 0x03, 0xc7]);
        p.extend_from_slice(&[0x00, 0x00, 0x03, 0xc2]);
        p.extend_from_slice(&[0, 0, 0, 0, 3, 0, 0, 0]);
        p.extend((0..40u8).map(|i| i ^ 0x5a));
        let mut heartbeat = vec![0x07u8, 0x01, 28, 0];
        heartbeat.extend_from_slice(&[0xAA; 28]);
        let mut with_hb = p.clone();
        with_hb.extend_from_slice(&heartbeat);
        (with_hb, heartbeat)
    }

    fn protect(kind: ProtectionKind) -> Vec<u8> {
        protect_sedp_packet_as(&plain().0, &keys(transformation_of(kind)), kind).expect("protects")
    }

    /// NONE: the secure writer's DATA, in clear, nothing around it.
    #[test]
    fn none_is_the_secure_writers_data_untransformed() {
        let (plain, heartbeat) = plain();
        let wire = protect(ProtectionKind::None);
        assert_eq!(wire.len(), plain.len());
        assert_eq!(wire[20], 0x15, "a DATA");
        assert_eq!(&wire[28..32], &[0xff, 0x00, 0x03, 0xc7], "secure reader");
        assert_eq!(&wire[32..36], &[0xff, 0x00, 0x03, 0xc2], "secure writer");
        assert_eq!(&wire[44..84], &plain[44..84], "payload in clear");
        assert_eq!(&wire[84..], heartbeat.as_slice());
    }

    /// A clear secure DATA follows RTPS v2.5 Sec.9.4.5.3: its inline QoS
    /// precedes the serialized key, and the classifier and decoder agree
    /// on the payload offset (DDS-Security v1.1 Sec.9.4.1.2.5.4, NONE).
    #[test]
    fn none_preserves_inline_qos_and_reports_the_serialized_payload() {
        use crate::core::discovery::multicast::{
            build_sedp_dispose_packet, classifier::classify_rtps, SedpEndpointKind,
        };
        use crate::core::discovery::GUID;
        let prefix = [0x33; 12];
        let endpoint = GUID::new(prefix, [0, 0, 0x12, 2]);
        let plain = build_sedp_dispose_packet(
            &endpoint,
            SedpEndpointKind::Writer,
            &prefix,
            None,
            2,
            crate::protocol::dialect::Dialect::Hdds,
        );
        let wire = protect_sedp_packet_as(
            &plain,
            &keys(Transformation::Aes256Gcm),
            ProtectionKind::None,
        )
        .expect("NONE retains a clear secure DATA");
        let (_, payload, _, _) = classify_rtps(&wire);
        let payload = payload.expect("the classifier finds the serialized key");
        let info = find_data_cdr_bounds(&wire).unwrap();
        assert!(
            payload > info.1,
            "inline QoS comes before the serialized key"
        );
        let opened = open_clear_secure_sedp(&wire, payload, ProtectionKind::None)
            .expect("clear secure DATA with inline QoS");
        assert_eq!(opened.payload_at, payload);
        assert_eq!(opened.datagram, plain);
        assert_eq!(&wire[payload..payload + 4], &[0, 3, 0, 0]);
    }

    /// SIGN: SEC_PREFIX, the secure writer's DATA in clear, SEC_POSTFIX
    /// (Sec.9.5.3.3.4.5, "authentication only"), with kind AES256_GMAC.
    #[test]
    fn sign_is_the_data_between_a_prefix_and_a_postfix() {
        let (plain, heartbeat) = plain();
        let wire = protect(ProtectionKind::Sign);
        assert_eq!(wire[20], 0x31, "SEC_PREFIX");
        assert_eq!(&wire[24..28], &[0, 0, 0, 3], "AES256_GMAC");
        assert_eq!(wire[44], 0x15, "the DATA follows the CryptoHeader");
        assert_eq!(&wire[52..56], &[0xff, 0x00, 0x03, 0xc7]);
        assert_eq!(&wire[56..60], &[0xff, 0x00, 0x03, 0xc2]);
        assert_eq!(&wire[68..108], &plain[44..84], "payload in clear");
        assert_eq!(wire[108], 0x32, "SEC_POSTFIX");
        assert_eq!(&wire[108 + 20..108 + 24], &[0, 0, 0, 0], "no receiver MAC");
        assert_eq!(&wire[108 + 24..], heartbeat.as_slice());
    }

    /// ENCRYPT: SEC_PREFIX, SEC_BODY, SEC_POSTFIX, kind AES256_GCM, and
    /// the payload nowhere in clear.
    #[test]
    fn encrypt_is_a_prefix_a_body_and_a_postfix() {
        let (plain, _) = plain();
        let wire = protect(ProtectionKind::Encrypt);
        assert_eq!(wire[20], 0x31);
        assert_eq!(&wire[24..28], &[0, 0, 0, 4], "AES256_GCM");
        assert_eq!(wire[44], 0x30, "SEC_BODY");
        assert!(
            !wire.windows(40).any(|w| w == &plain[44..84]),
            "the payload does not appear"
        );
    }

    /// The WITH_ORIGIN_AUTHENTICATION kinds are not produced: their
    /// receiver-specific keys are per remote reader (Table 70), which one
    /// key material per writer cannot give; governance refuses them at load.
    #[test]
    fn origin_authentication_is_not_produced() {
        for kind in [
            ProtectionKind::SignWithOriginAuthentication,
            ProtectionKind::EncryptWithOriginAuthentication,
        ] {
            assert!(
                protect_sedp_packet_as(&plain().0, &keys(transformation_of(kind)), kind).is_none(),
                "{:?}",
                kind
            );
        }
    }

    /// A key material of another transformation than the kind asks is not
    /// used: a SIGN datagram is not made with an encrypting material.
    #[test]
    fn a_material_of_another_transformation_than_the_kind_is_refused() {
        assert!(protect_sedp_packet_as(
            &plain().0,
            &keys(Transformation::Aes256Gcm),
            ProtectionKind::Sign
        )
        .is_none());
        assert!(protect_sedp_packet_as(
            &plain().0,
            &keys(Transformation::Aes256Gmac),
            ProtectionKind::Encrypt
        )
        .is_none());
    }

    fn open(wire: &[u8], required: ProtectionKind) -> Option<OpenedSedp> {
        match wire[20] {
            0x31 => {
                let transformation = if wire[24..28] == [0, 0, 0, 3] {
                    Transformation::Aes256Gmac
                } else {
                    Transformation::Aes256Gcm
                };
                open_secure_sedp_as(
                    wire,
                    20,
                    &keys(transformation).publications,
                    &WRITER,
                    required,
                )
            }
            _ => open_clear_secure_sedp(wire, 44, required),
        }
    }

    /// Known answer, computed outside this crate (Python `cryptography`:
    /// HMAC-SHA256 and AESGCM, from the formulas of Sec.9.5.3.3.3 and
    /// Sec.9.5.3.3.4.5 and the layouts of Sec.9.5.2.3-9.5.2.5): the DATA of
    /// [`plain`], renamed to the secure SEDP writer and reader, protected
    /// under the writer key material `master_sender_key = 00..1f`,
    /// `master_salt = 20..3f`, `sender_key_id = 0a0b0c0d`, session id 1, IV
    /// suffix 7. A receiver holding that material - what the writer's
    /// DatawriterCryptoTokens carry - reads back the plain datagram; under
    /// the same key with another salt, or under another participant's
    /// material, it does not.
    #[test]
    fn a_secure_sedp_datagram_computed_outside_opens_under_the_announced_material() {
        use crate::security::crypto::secure_submessage::WriterKeyMaterial;
        let hex = concat!(
            "525450530205011a11111111111111111111111131011400000000040a0b0c0d",
            "0000000100000000000000073001440000000040dd069c59d362c2aca6e9d70e",
            "11fa8d49ec9154ba979f1d21c3fbfd646076a5c3b5121a064fcbac6ea6943bd9",
            "d47a7cab51e0da36f6103869623a86870cf9e9eb32011400757e5fe196bd453e",
            "4e50c23acb9cf1d50000000007011c00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let wire: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        let mut key = [0u8; 32];
        let mut salt = [0u8; 32];
        for i in 0..32u8 {
            key[usize::from(i)] = i;
            salt[usize::from(i)] = 32 + i;
        }
        let id = [0x0a, 0x0b, 0x0c, 0x0d];
        assert_eq!(transformation_key_id_at(&wire, 20), Some(0x0a0b_0c0d));
        let announced = WriterKeyMaterial::new(key, salt, id);
        let opened = open_secure_sedp_as(&wire, 20, &announced, &WRITER, ProtectionKind::Encrypt)
            .expect("opens under the announced material");
        assert_eq!(opened.datagram, plain().0);
        assert_eq!(opened.payload_at, 44);
        assert_eq!(opened.protection, ProtectionKind::Encrypt);

        let resalted = WriterKeyMaterial::new(key, [0u8; 32], id);
        assert!(
            open_secure_sedp_as(&wire, 20, &resalted, &WRITER, ProtectionKind::Encrypt).is_none(),
            "the salt is part of the material"
        );
        assert!(
            open_secure_sedp_as(
                &wire,
                20,
                &keys(Transformation::Aes256Gcm).publications,
                &WRITER,
                ProtectionKind::Encrypt
            )
            .is_none(),
            "another participant's material"
        );
    }

    /// Every kind opens to the plain datagram, ids back in the plain
    /// namespace, the HEARTBEAT after it, and says what it was.
    #[test]
    fn every_kind_opens_to_the_plain_datagram() {
        let (plain, _) = plain();
        for kind in [
            ProtectionKind::None,
            ProtectionKind::Sign,
            ProtectionKind::Encrypt,
        ] {
            let opened = open(&protect(kind), kind).unwrap_or_else(|| panic!("{:?}", kind));
            assert_eq!(opened.datagram, plain, "{:?}", kind);
            assert_eq!(opened.payload_at, 44, "{:?}", kind);
            assert_eq!(opened.protection, kind);
        }
    }

    /// A receiver whose governance asks more than a datagram carries does
    /// not read it: no downgrade by sending a weaker shape.
    #[test]
    fn a_weaker_protection_than_required_is_refused() {
        use ProtectionKind::*;
        assert!(open(&protect(None), Sign).is_none());
        assert!(open(&protect(None), Encrypt).is_none());
        assert!(open(&protect(Sign), Encrypt).is_none());
        assert!(open(&protect(Encrypt), EncryptWithOriginAuthentication).is_none());
        assert!(open(&protect(Sign), SignWithOriginAuthentication).is_none());
        // Stronger than required is read.
        assert!(open(&protect(Encrypt), Sign).is_some());
        assert!(open(&protect(Encrypt), None).is_some());
    }

    /// The DATA a SIGN datagram carries in clear is never taken without
    /// its MAC: not by the NONE path, and not once anything of it changed.
    #[test]
    fn the_clear_data_of_a_signed_datagram_is_never_read_unverified() {
        let wire = protect(ProtectionKind::Sign);
        assert!(
            open_clear_secure_sedp(&wire, 44 + 24, ProtectionKind::None).is_none(),
            "at the DATA's own payload offset"
        );
        for at in [44, 52, 60, 68, 100] {
            let mut t = wire.clone();
            t[at] ^= 0x01;
            assert!(open(&t, ProtectionKind::None).is_none(), "octet {}", at);
        }
    }

    /// The NONE shape of another writer than the secure SEDP ones is not
    /// read as SEDP.
    #[test]
    fn a_clear_data_of_another_writer_is_not_secure_sedp() {
        let mut wire = protect(ProtectionKind::None);
        wire[32..36].copy_from_slice(&[0xff, 0x01, 0x01, 0xc2]);
        assert!(open(&wire, ProtectionKind::None).is_none());
    }

    #[test]
    fn the_protection_order() {
        use ProtectionKind::*;
        let all = [
            None,
            Sign,
            Encrypt,
            SignWithOriginAuthentication,
            EncryptWithOriginAuthentication,
        ];
        for kind in all {
            assert!(protection_satisfies(kind, kind), "{:?}", kind);
            assert!(protection_satisfies(kind, None), "{:?}", kind);
        }
        assert!(!protection_satisfies(Sign, Encrypt));
        assert!(protection_satisfies(Encrypt, Sign));
        assert!(!protection_satisfies(Encrypt, SignWithOriginAuthentication));
        assert!(protection_satisfies(
            EncryptWithOriginAuthentication,
            SignWithOriginAuthentication
        ));
        assert!(!protection_satisfies(SignWithOriginAuthentication, Encrypt));
    }

    // -----------------------------------------------------------------
    //  protect_reader_control_packet / open_reader_control_packet
    //  (DDS Security v1.1 Sec.8.8.9.3)
    // -----------------------------------------------------------------

    fn reader_material(seed: u8) -> crate::security::crypto::secure_submessage::WriterKeyMaterial {
        crate::security::crypto::secure_submessage::WriterKeyMaterial::new(
            [seed; 32],
            [seed ^ 0x5A; 32],
            [0, 0, 2, seed],
        )
    }

    /// `[RTPS header][INFO_DST][ACKNACK]`, as `control::
    /// build_acknack_packet_with_final` builds it.
    fn plain_acknack_packet() -> Vec<u8> {
        crate::protocol::builder::build_acknack_packet_with_final(
            [0x11; 12],
            [0x22; 12],
            [0xff, 0x00, 0x03, 0xc7],
            [0xff, 0x00, 0x03, 0xc2],
            1,
            &[1],
            7,
            false,
        )
    }

    /// The RTPS header and INFO_DST are receiver state (DDSI-RTPS v2.5
    /// Sec.8.3.7.9): unchanged by protection, exactly as
    /// `protect_sedp_packet_as`'s "what precedes and follows it is
    /// unchanged" rule holds for the writer's side of this tunnel.
    ///
    /// Mutant: slicing from the wrong offset (off by the INFO_DST's own
    /// length) would still produce SOME SEC_PREFIX-shaped bytes that
    /// `open_reader_control_packet` might even decode, but the header
    /// comparison below catches it directly: the prefix bytes would differ.
    #[test]
    fn protect_reader_control_packet_leaves_the_header_and_info_dst_untouched() {
        let plain = plain_acknack_packet();
        let material = reader_material(0x30);
        let protected = protect_reader_control_packet(&plain, &material).expect("protect");

        // INFO_DST is id 0x0e, a fixed 16-octet submessage (4-octet header +
        // 12-octet prefix) right after the 20-octet RTPS header.
        let unprotected_prefix_len = 20 + 16;
        assert_eq!(
            &protected[..unprotected_prefix_len],
            &plain[..unprotected_prefix_len],
            "the RTPS header and INFO_DST must be byte-identical"
        );
        assert_eq!(
            protected[20], 0x0e,
            "fixture: INFO_DST is still the first submessage"
        );
        assert_eq!(
            protected[unprotected_prefix_len],
            crate::security::crypto::secure_submessage::SEC_PREFIX,
            "the ACKNACK must be replaced by a SEC_PREFIX"
        );
    }

    /// The SEDP publications secure reader's entity id, matching
    /// `plain_acknack_packet`'s readerId.
    const PUB_READER: [u8; 4] = [0xff, 0x00, 0x03, 0xc7];
    /// Its mirrored builtin writer, matching `plain_acknack_packet`'s
    /// writerId.
    const PUB_WRITER: [u8; 4] = [0xff, 0x00, 0x03, 0xc2];
    /// The SEDP subscriptions secure reader -- a DIFFERENT builtin tunnel,
    /// used to pin the endpoint-binding checks (see below).
    const SUB_READER: [u8; 4] = [0xff, 0x00, 0x04, 0xc7];

    fn open_reader(
        datagram: &[u8],
        prefix_at: usize,
        material: &crate::security::crypto::secure_submessage::WriterKeyMaterial,
        reader: [u8; 4],
    ) -> Option<OpenedReaderControl> {
        open_reader_control_packet(
            datagram,
            prefix_at,
            material,
            &reader,
            ProtectionKind::Encrypt,
        )
    }

    /// Round trip: what `protect_reader_control_packet` produces,
    /// `open_reader_control_packet` opens back to exactly the ACKNACK
    /// submessage the reader built (header included), ending where the
    /// SEC_POSTFIX ends in the original datagram.
    #[test]
    fn protect_then_open_reader_control_packet_round_trips_to_the_plain_acknack() {
        let plain = plain_acknack_packet();
        let material = reader_material(0x31);
        let protected = protect_reader_control_packet(&plain, &material).expect("protect");

        let prefix_at = crate::security::crypto::secure_submessage::first_secure_prefix(&protected)
            .expect("a SEC_PREFIX");
        let opened = open_reader(&protected, prefix_at, &material, PUB_READER).expect("open");

        assert_eq!(
            opened.end,
            protected.len(),
            "nothing follows the SEC_POSTFIX in this fixture"
        );

        // What the submessage decodes to is byte-identical to the plain
        // ACKNACK the reader built, nothing more, nothing less: rebuild a
        // minimal [header][submessage] buffer the way the caller
        // (`dispatch_decoded_reader_control`) does, and parse THAT alone.
        let mut minimal = plain[..20].to_vec();
        minimal.extend_from_slice(&opened.submessage);
        let parsed =
            crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages(
                &minimal,
            );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].writer_entity_id, PUB_WRITER);
        assert_eq!(parsed[0].reader_entity_id, PUB_READER);
        assert_eq!(parsed[0].bitmap_base, 1);
    }

    /// Mutant: a `decode_datareader_submessage` call that used the WRONG
    /// key material (e.g. a writer's instead of the reader's own) must be
    /// refused, never silently accepted under the wrong key.
    #[test]
    fn open_reader_control_packet_refuses_a_key_it_does_not_hold() {
        let plain = plain_acknack_packet();
        let sender = reader_material(0x32);
        let protected = protect_reader_control_packet(&plain, &sender).expect("protect");
        let prefix_at = crate::security::crypto::secure_submessage::first_secure_prefix(&protected)
            .expect("a SEC_PREFIX");

        let wrong_key = reader_material(0x99);
        assert!(open_reader(&protected, prefix_at, &wrong_key, PUB_READER).is_none());
    }

    /// `open_reader_control_packet` only reads what it protects as an
    /// ACKNACK or a NACK_FRAG (Sec.8.8.9.3 names those two, never a HEARTBEAT
    /// or a DATA): a SEC_PREFIX that opens cleanly but protects some other
    /// submessage kind must not be reinterpreted as either.
    ///
    /// A filler body such as `[0xAA; 28]` would ALSO fail the
    /// readerId/writerId checks further down (`0xAAAAAAAA` matches neither
    /// `PUB_READER` nor its mirrored writer), so deleting the
    /// `matches!(decoded.submessage.first(), ...)` check this test claims to
    /// isolate would still leave the test passing. This fixture's body
    /// carries `PUB_READER`/`PUB_WRITER` at exactly
    /// the offsets an ACKNACK would, so those two checks would PASS if
    /// reached: only the submessage-kind check (reading byte 0, 0x07 here)
    /// stands between this HEARTBEAT and acceptance.
    ///
    /// Mutant: dropping the `matches!(decoded.submessage.first(), ...)`
    /// check would accept this HEARTBEAT as if it were an ACKNACK, and the
    /// caller would hand a HEARTBEAT's bytes to `parse_all_acknack_
    /// submessages`, which cannot make sense of them (a silent
    /// misinterpretation, not a loud refusal).
    #[test]
    fn open_reader_control_packet_refuses_a_protected_submessage_that_is_not_acknack_or_nack_frag()
    {
        use crate::security::crypto::secure_submessage::encode_datareader_submessage;
        let mut heartbeat = vec![0x07u8, 0x01]; // HEARTBEAT, little-endian
        heartbeat.extend_from_slice(&28u16.to_le_bytes());
        heartbeat.extend_from_slice(&PUB_READER); // would-be readerId: matches
        heartbeat.extend_from_slice(&PUB_WRITER); // would-be writerId: matches too
        heartbeat.extend_from_slice(&[0xAAu8; 20]); // the rest: irrelevant filler

        let material = reader_material(0x33);
        let protected_hb = encode_datareader_submessage(&material, &heartbeat).expect("protect");
        let mut datagram = vec![0u8; 20];
        datagram.extend_from_slice(&protected_hb);

        assert!(open_reader(&datagram, 20, &material, PUB_READER).is_none());
    }

    /// `protect_reader_control_packet` on a packet carrying neither an
    /// ACKNACK nor a NACK_FRAG (a HEARTBEAT, say) has nothing to protect.
    #[test]
    fn protect_reader_control_packet_is_none_without_an_acknack_or_nack_frag() {
        let mut packet = vec![0u8; 20];
        packet.push(0x07); // HEARTBEAT
        packet.push(0x01);
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&[0xAAu8; 28]);
        assert!(protect_reader_control_packet(&packet, &reader_material(0x34)).is_none());
    }

    // -----------------------------------------------------------------
    //  Endpoint binding and governance strength on the reader-control
    //  open path.
    // -----------------------------------------------------------------

    /// A correctly-signed ACKNACK from the WRONG reader -- one
    /// whose own key happens to decode it (an attacker would need the
    /// matching key to produce a validly-authenticated envelope, but a
    /// sloppier implementation might only check "does SOME candidate key
    /// decode this", not "does this specific candidate's reader identity
    /// match what the bytes claim"). Built independently: encode under the
    /// SUBSCRIPTIONS reader's key material, but its CONTENT (readerId,
    /// writerId) claims the PUBLICATIONS reader -- the two are swapped
    /// relative to what `open` is told to check against.
    ///
    /// Mutant: deleting the `reader_id != reader.as_slice()` check lets
    /// this decode and be read as `SUB_READER`'s traffic.
    ///
    /// The envelope's writerId is `PUB_WRITER` (from `plain_acknack_packet`),
    /// which is NOT `SUB_READER`'s mirrored writer either -- so deleting
    /// ONLY the readerId check still leaves this refused by the writerId
    /// check right after it, and the test would pass for the wrong
    /// reason. `a_readerid_mismatch_with_a_writerid_that_would_otherwise_
    /// pass` below is the isolating version: same claim, but with a
    /// writerId chosen so that check alone would NOT refuse it, leaving
    /// the readerId check as the only thing standing in the way. This
    /// test is kept as a realistic-shape case (both halves of the
    /// binding wrong at once, the common real-world case), the other as
    /// the mutant-isolating proof.
    #[test]
    fn open_reader_control_packet_refuses_a_readerid_mismatch() {
        let plain = plain_acknack_packet(); // readerId = PUB_READER, writerId = PUB_WRITER
        let material = reader_material(0x40);
        let protected = protect_reader_control_packet(&plain, &material).expect("protect");
        let prefix_at = crate::security::crypto::secure_submessage::first_secure_prefix(&protected)
            .expect("a SEC_PREFIX");

        // Decodes fine under `material` (it is the right key), but the
        // CALLER is checking it against SUB_READER, not the PUB_READER the
        // bytes actually name.
        assert!(
            open_reader(&protected, prefix_at, &material, SUB_READER).is_none(),
            "a decodable envelope whose readerId names a DIFFERENT reader must be refused"
        );
        // Sanity: the SAME envelope under the RIGHT reader id is accepted.
        assert!(open_reader(&protected, prefix_at, &material, PUB_READER).is_some());
    }

    /// The isolating version of the test above: readerId names
    /// `PUB_READER`, but the writerId is `SUB_WRITER_FOR_TEST` -- the
    /// mirrored builtin writer of the candidate `SUB_READER` this test
    /// opens against. If the readerId check were deleted, the writerId
    /// check would PASS (SUB_READER's own mirror matches), so only the
    /// readerId check can be what refuses this envelope.
    ///
    /// Mutant: deleting `reader_id != reader.as_slice()` makes this test
    /// fail (accepted instead of refused) -- the one the test above
    /// cannot catch.
    #[test]
    fn a_readerid_mismatch_with_a_writerid_that_would_otherwise_pass() {
        use crate::security::crypto::secure_submessage::encode_datareader_submessage;
        let mut acknack = vec![0x06u8, 0x03];
        let mut body = Vec::new();
        body.extend_from_slice(&PUB_READER); // readerId: NOT the SUB_READER candidate
        body.extend_from_slice(&SUB_WRITER_FOR_TEST); // writerId: SUB_READER's OWN mirror
        body.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        body.extend_from_slice(&[0, 0, 0, 0]);
        // Count_t, LE: this submessage declares E=1 (flags 0x03) and every
        // multi-byte field follows that, Count_t included (a big-endian
        // count under a little-endian flag would be harmless here, since
        // `open_reader_control_packet` never reads Count_t, but wrong on its
        // own terms).
        body.extend_from_slice(&9u32.to_le_bytes());
        acknack.extend_from_slice(&(body.len() as u16).to_le_bytes());
        acknack.extend_from_slice(&body);

        let material = reader_material(0x44);
        let protected = encode_datareader_submessage(&material, &acknack).expect("protect");
        let mut datagram = vec![0u8; 20];
        datagram.extend_from_slice(&protected);

        assert!(
            open_reader(&datagram, 20, &material, SUB_READER).is_none(),
            "the writerId alone would pass against SUB_READER's mirror; only the readerId \
             mismatch may refuse this"
        );
    }

    /// writerId half: an ACKNACK whose readerId matches the
    /// candidate but whose writerId names some OTHER writer (not that
    /// reader's own mirrored builtin writer) must be refused too -- hand
    /// built so `encode_datareader_submessage` never validates the
    /// content, only `open_reader_control_packet`'s own check does.
    #[test]
    fn open_reader_control_packet_refuses_a_writerid_mismatch() {
        use crate::security::crypto::secure_submessage::encode_datareader_submessage;
        let mut acknack = vec![0x06u8, 0x03];
        let mut body = Vec::new();
        body.extend_from_slice(&PUB_READER); // readerId: matches the candidate
        body.extend_from_slice(&SUB_WRITER_FOR_TEST); // writerId: WRONG mirrored writer
        body.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        body.extend_from_slice(&[0, 0, 0, 0]);
        // Count_t, LE (same correction as above: flags 0x03 declares E=1).
        body.extend_from_slice(&7u32.to_le_bytes());
        acknack.extend_from_slice(&(body.len() as u16).to_le_bytes());
        acknack.extend_from_slice(&body);

        let material = reader_material(0x41);
        let protected = encode_datareader_submessage(&material, &acknack).expect("protect");
        let mut datagram = vec![0u8; 20];
        datagram.extend_from_slice(&protected);

        assert!(open_reader(&datagram, 20, &material, PUB_READER).is_none());
    }

    /// The subscriptions secure writer -- deliberately NOT publications',
    /// so the writerId-mismatch fixture above names a real builtin writer
    /// that is simply the wrong one for `PUB_READER`.
    const SUB_WRITER_FOR_TEST: [u8; 4] = [0xff, 0x00, 0x04, 0xc2];

    /// The reader-control open path must apply the same
    /// governance protection-strength rule the writer path does
    /// (`open_secure_sedp_as`'s `protection_satisfies` call). A SIGNED
    /// (AES-GMAC) ACKNACK must be refused when local governance requires
    /// ENCRYPT.
    ///
    /// Mutant: dropping the `protection_satisfies` call accepts this SIGN
    /// envelope under an ENCRYPT requirement.
    #[test]
    fn open_reader_control_packet_enforces_the_required_protection_strength() {
        use crate::security::crypto::secure_submessage::Transformation;
        let plain = plain_acknack_packet();
        let gmac_material = crate::security::crypto::secure_submessage::WriterKeyMaterial::new(
            [0x42; 32],
            [0x42 ^ 0x5A; 32],
            [0, 0, 2, 0x42],
        )
        .with_transformation(Transformation::Aes256Gmac);
        let protected =
            protect_reader_control_packet(&plain, &gmac_material).expect("protect (SIGN)");
        let prefix_at = crate::security::crypto::secure_submessage::first_secure_prefix(&protected)
            .expect("a SEC_PREFIX");

        assert!(
            open_reader_control_packet(
                &protected,
                prefix_at,
                &gmac_material,
                &PUB_READER,
                ProtectionKind::Encrypt,
            )
            .is_none(),
            "a SIGN envelope must be refused when ENCRYPT is required"
        );
        assert!(
            open_reader_control_packet(
                &protected,
                prefix_at,
                &gmac_material,
                &PUB_READER,
                ProtectionKind::Sign,
            )
            .is_some(),
            "the same envelope must be accepted when SIGN is all that is required"
        );
    }

    /// Sender half: `protect_reader_control_packet` leaves
    /// everything after the control submessage it protects untouched, so a
    /// caller protecting ONE of several control submessages of a compound
    /// datagram does not have to re-derive the rest.
    #[test]
    fn protect_reader_control_packet_leaves_what_follows_untouched() {
        let mut plain = plain_acknack_packet();
        let trailer = [0xEEu8; 8];
        plain.extend_from_slice(&trailer);
        let protected =
            protect_reader_control_packet(&plain, &reader_material(0x43)).expect("protect");
        assert_eq!(&protected[protected.len() - 8..], &trailer);
    }

    /// Receiver half: a compound datagram carrying TWO
    /// independently-protected ACKNACKs (publications, then
    /// subscriptions, separated by nothing but their own framing) must
    /// yield the SECOND one too, found via `first_secure_prefix_from`
    /// starting at the first envelope's own `end`. Built independently of
    /// `protect_reader_control_packet` (which only ever protects one
    /// submessage per call): two separate `encode_datareader_submessage`
    /// calls concatenated by hand.
    #[test]
    fn a_compound_datagram_yields_both_protected_acknacks_in_order() {
        use crate::security::crypto::secure_submessage::{
            encode_datareader_submessage, first_secure_prefix, first_secure_prefix_from,
        };
        let build_acknack = |reader: [u8; 4], writer: [u8; 4], count: u32| {
            let mut sub = vec![0x06u8, 0x03];
            let mut body = Vec::new();
            body.extend_from_slice(&reader);
            body.extend_from_slice(&writer);
            body.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
            body.extend_from_slice(&[0, 0, 0, 0]);
            // Count_t, LE: `sub`'s flags declare E=1 (0x03); `to_be_bytes`
            // here would be wrong on its own terms, harmless only because
            // this check never reads it.
            body.extend_from_slice(&count.to_le_bytes());
            sub.extend_from_slice(&(body.len() as u16).to_le_bytes());
            sub.extend_from_slice(&body);
            sub
        };
        let pub_material = reader_material(0x50);
        let sub_material = reader_material(0x51);
        let pub_protected =
            encode_datareader_submessage(&pub_material, &build_acknack(PUB_READER, PUB_WRITER, 1))
                .expect("protect pub");
        let sub_protected = encode_datareader_submessage(
            &sub_material,
            &build_acknack(SUB_READER, SUB_WRITER_FOR_TEST, 2),
        )
        .expect("protect sub");

        let mut datagram = vec![0u8; 20];
        datagram.extend_from_slice(&pub_protected);
        datagram.extend_from_slice(&sub_protected);

        let first_at = first_secure_prefix(&datagram).expect("first envelope");
        let first =
            open_reader(&datagram, first_at, &pub_material, PUB_READER).expect("open first");
        assert_eq!(
            first.submessage[4..8],
            PUB_READER,
            "the first envelope is the publications ACKNACK"
        );
        assert_eq!(first.end, 20 + pub_protected.len());

        let second_at =
            first_secure_prefix_from(&datagram, first.end).expect("a second SEC_PREFIX");
        assert_eq!(
            second_at, first.end,
            "the second envelope starts right where the first ended"
        );
        let second = open_reader_control_packet(
            &datagram,
            second_at,
            &sub_material,
            &SUB_READER,
            ProtectionKind::Encrypt,
        )
        .expect("open second");
        assert_eq!(
            second.submessage[4..8],
            SUB_READER,
            "the second envelope is the subscriptions ACKNACK"
        );
        assert_eq!(
            second.end,
            datagram.len(),
            "nothing follows the second envelope"
        );
    }
}
