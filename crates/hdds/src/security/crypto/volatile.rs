// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `DatawriterCryptoTokens` over the `ParticipantVolatileMessageSecure`
//! channel (DDS Security v1.1 Sec.7.4.4, builtin entities 0xff0202c3/c4).
//!
//! # What travels here and why
//!
//! The data plane uses ONE symmetric key per WRITER: the writer encrypts one
//! ciphertext and every subscriber decrypts it with the same key (per-destination
//! encryption in the writer loop would be bypassed by the engine's one-to-N
//! send paths). That
//! key has to REACH each subscriber, and [`WriterKeyAnnouncement`] carries it
//! as a real `ParticipantGenericMessage` (Sec.7.4.4.3) of class
//! `GMCLASSID_SECURITY_DATAWRITER_CRYPTO_TOKENS` (Sec.7.4.4.6.2), its
//! `message_data` one `CryptoToken` of class `DDS:Crypto:AES_GCM_GMAC`
//! (Table 66, `crypto::crypto_token`).
//!
//! `source_endpoint_guid` is the writer whose key this is (Sec.7.4.4.6.2:
//! "the GUID_t of the DataWriter that will be using the CryptoToken values
//! to encode the data it sends"). `destination_endpoint_guid` is "the
//! GUID_t of the DataReader that should receive the CryptoToken values":
//! one message per matched reader. For the six secure BUILTIN tunnels
//! (`secure_builtins`) a writer and its peer's mirrored reader pair 1:1 by
//! construction (`builtin_peer_entity_id`). A plain USER DataWriter under
//! HDDS's one-key-per-writer design (above) may be matched with several
//! readers of one peer, which all decode with the SAME key: the key
//! material is shared, the addressing is not -- each matched reader gets
//! its own message naming it (`stateless_writer::distribute`). A receiver
//! installs the key only when the destination is one of its endpoints of
//! the right kind matched with the source (`SecureBuiltins::
//! install_endpoint_tokens`, `VolatileChannel::user_addressing`).
//!
//! `sender_key_id` is four octets (Sec.9.5.2.1.1), as is the key id in
//! the CryptoHeader of each protected payload and submessage. The store
//! widens ids to u64 without changing their value. The writer mints a
//! random master salt with its key; both are distributed and used to derive
//! the session keys of Sec.9.5.3.3.3.
//!
//! # The DATA submessage is protected per spec, Table 67 keyed
//!
//! `ParticipantVolatileMessageSecure` is a topic whose endpoints have
//! `is_submessage_protected` (Sec.7.4.4.1, Table 17): the DATA submessage
//! that carries the CDR `ParticipantGenericMessage` is itself replaced by
//! `secure_submessage::encode_datawriter_submessage` (SEC_PREFIX / SEC_BODY /
//! SEC_POSTFIX, Sec.9.5.3.3.4.5), the same codec secure SEDP uses. For this
//! one writer the receiving key material is the peer's Table 67 KxKeys
//! (Sec.8.5.1.9.2: "the DatareaderCryptoHandle list has ONE element
//! containing KxKey material"; `crypto::kx_keys`,
//! `PeerKeys::volatile_key_material`), derived from the authentication
//! SharedSecret and both handshake challenges. Both peers derive the SAME
//! material independently (Sec.9.3.4.3): nothing about the key itself is
//! exchanged, only the messages it protects.
//!
//! # Wire shape
//!
//! ```text
//! SEC_PREFIX  CryptoHeader(AES256_GCM, key_id=0, session_id, iv_suffix)
//! SEC_BODY    AES-256-GCM(                        key = peer's KxKeys
//!     DATA(readerId = 0xff0202c4, writerId = 0xff0202c3, writerSN = seq,
//!          serializedPayload = CDR ParticipantGenericMessage {
//!                          message_identity        = (volatile writer GUID, seq)
//!                          related_message_identity = {GUID_UNKNOWN, 0}
//!                          destination_participant_guid = peer
//!                          destination_endpoint_guid    = the matched reader
//!                          source_endpoint_guid         = the data writer
//!                          message_class_id    = "dds.sec.datawriter_crypto_tokens"
//!                          message_data = [ CryptoToken {
//!                              class_id = "DDS:Crypto:AES_GCM_GMAC"
//!                              binary_properties = [("dds.cryp.keymat", <KeyMaterial_AES_GCM_GMAC>)]
//!                          } ]
//!                      })
//! )
//! SEC_POSTFIX common_mac
//! ```
//!
//! The SEC_PREFIX sits directly in the RTPS message, after the INFO_DST
//! naming the peer and an INFO_TS: there is no clear DATA around it, and
//! nothing private inside it. The `KeyMaterial_AES_GCM_GMAC` bytes inside
//! the one CryptoToken are the literal, big-endian layout Table 66
//! specifies.

use crate::core::discovery::GUID;
use crate::core::rtps_constants::{
    RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
    RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
};
use crate::security::crypto::crypto_token::{
    KeyMaterialAesGcmGmac, TRANSFORMATION_KIND_AES256_GCM,
};
use crate::security::crypto::peer_keys::SecretKey;
use crate::security::crypto::secure_submessage::{
    decode_datawriter_submessage, encode_datawriter_submessage, Transformation, WriterKeyMaterial,
};
use crate::security::generic_message::{decode_tokens, encode_tokens, GenericMessage};
use crate::security::SecurityError;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// `GMCLASSID_SECURITY_PARTICIPANT_CRYPTO_TOKENS` (Sec.7.4.4.5).
pub(crate) const CLASS_PARTICIPANT_CRYPTO_TOKENS: &str = "dds.sec.participant_crypto_tokens";
/// `GMCLASSID_SECURITY_DATAWRITER_CRYPTO_TOKENS` (Sec.7.4.4.5).
const CLASS_DATAWRITER_CRYPTO_TOKENS: &str = "dds.sec.datawriter_crypto_tokens";
/// `GMCLASSID_SECURITY_DATAREADER_CRYPTO_TOKENS` (Sec.7.4.4.5).
pub(crate) const CLASS_DATAREADER_CRYPTO_TOKENS: &str = "dds.sec.datareader_crypto_tokens";

/// GUID_UNKNOWN (RTPS v2.5 Sec.9.3.1.5): the destination and source
/// endpoint of a ParticipantCryptoTokens message (Sec.7.4.4.6.1), and a
/// destination participant meaning "any" (Sec.7.4.4.4). Never a valid
/// destination of an endpoint's CryptoTokens (Sec.7.4.4.6.2-3).
pub(crate) const GUID_UNKNOWN: [u8; 16] = [0; 16];

/// The builtin secure tunnel's PEER entity id of `entity_id`, when
/// `entity_id` is one of the six tunnels' writer or reader ids
/// (`secure_builtins::setup_secure_builtins`): a WITH_KEY writer (`0xC2`)
/// pairs with a WITH_KEY reader (`0xC7`) and a NO_KEY writer (`0xC3`) with a
/// NO_KEY reader (`0xC4`), DDS Security v1.1 Sec.7.4.1.3 -- always exactly
/// one peer, never ambiguous, because every builtin tunnel matches its
/// writer to its mirrored reader 1:1 by construction. `None` for a plain
/// USER writer or reader entity id (no `0xC0` bits set): those can be
/// matched to several peers of the same participant, so no single entity id
/// names "the" peer (the module docs above).
#[must_use]
pub(crate) fn builtin_peer_entity_id(entity_id: [u8; 4]) -> Option<[u8; 4]> {
    let peer_kind = match entity_id[3] {
        0xC2 => 0xC7,
        0xC7 => 0xC2,
        0xC3 => 0xC4,
        0xC4 => 0xC3,
        _ => return None,
    };
    let mut peer = entity_id;
    peer[3] = peer_kind;
    Some(peer)
}

/// Whether `entity_id` is a READER entity id (RTPS v2.5 Sec.9.3.1.2:
/// `ENTITY_KIND_USER_READER_NO_KEY` 0x04, `ENTITY_KIND_USER_READER_WITH_KEY`
/// 0x07, both also with the builtin `0xC0` bits set, 0xC4/0xC7). The `0xC0`
/// bits name "builtin", not the reader/writer split, so they are masked off
/// before the comparison: a WRITER entity id never has low byte 0x04 or
/// 0x07, builtin or not (`ENTITY_KIND_USER_WRITER_WITH_KEY` 0x02,
/// `ENTITY_KIND_USER_WRITER_NO_KEY` 0x03, and their builtin forms 0xC2/0xC3).
#[must_use]
pub(crate) fn is_reader_entity_id(entity_id: [u8; 4]) -> bool {
    matches!(entity_id[3] & 0x3F, 0x04 | 0x07)
}

/// Whether `entity_id` is a WRITER entity id (RTPS v2.5 Sec.9.3.1.2:
/// `ENTITY_KIND_USER_WRITER_WITH_KEY` 0x02, `ENTITY_KIND_USER_WRITER_NO_KEY`
/// 0x03, builtin or not). The complement of [`is_reader_entity_id`] is NOT
/// "is a writer": the participant entity id (`ENTITYID_PARTICIPANT`,
/// `0x000001c1`), and several other non-endpoint kinds, are neither a
/// reader nor a writer, and a destination check that only asked "not a
/// reader" would treat one of them as a valid writer address.
#[must_use]
pub(crate) fn is_writer_entity_id(entity_id: [u8; 4]) -> bool {
    matches!(entity_id[3] & 0x3F, 0x02 | 0x03)
}

/// `ENTITYID_UNKNOWN` (RTPS v2.5 Sec.9.3.1.2): a DATA, HEARTBEAT or GAP
/// may name it as its readerId when it is meant for every matched reader.
const ENTITYID_UNKNOWN: [u8; 4] = [0; 4];

/// DATA submessage id (RTPS v2.5 Sec.9.4.5.1.1, Table 9.13).
const DATA_ID: u8 = 0x15;
/// DATA submessage flags (RTPS v2.5 Sec.9.4.5.3): E, Q, D, K.
const FLAG_E: u8 = 0x01;
const FLAG_Q: u8 = 0x02;
const FLAG_D: u8 = 0x04;
const FLAG_K: u8 = 0x08;
/// `PID_SENTINEL` (RTPS v2.5 Table 9.12): ends an inline QoS list.
const PID_SENTINEL: u16 = 0x0001;

/// Protect one `ParticipantVolatileMessageSecure` sample for one peer: the
/// DATA submessage (RTPS v2.5 Sec.8.3.7.2) of the
/// `BuiltinParticipantVolatileMessageSecureWriter`, change
/// `sequence_number`, addressed to the peer's volatile reader and carrying
/// `message` (one CDR-encapsulated `ParticipantGenericMessage`) as its
/// serialized payload, replaced as a whole by `encode_datawriter_submessage`
/// under the peer's Table 67 material (module docs). What comes back is the
/// SEC_PREFIX/SEC_BODY/SEC_POSTFIX triple that takes the DATA's place in
/// the RTPS message.
pub(crate) fn protect_message(
    material: &WriterKeyMaterial,
    sequence_number: i64,
    message: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    let sn = u64::try_from(sequence_number)
        .ok()
        .filter(|sn| *sn > 0)
        .ok_or_else(|| {
            SecurityError::CryptoError(format!(
                "volatile writer sequence number {} is not a valid RTPS sequence number",
                sequence_number
            ))
        })?;
    let data = crate::protocol::rtps::encode_data(
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        sn,
        message,
    )
    .map_err(|e| SecurityError::CryptoError(format!("volatile DATA: {:?}", e)))?;
    encode_datawriter_submessage(material, &data)
}

/// The change one volatile-channel DATA submessage carries: its writerSN
/// and its serialized payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VolatileData<'a> {
    /// writerSN (RTPS v2.5 Sec.8.3.7.2), the sequence number of the change.
    pub sequence_number: i64,
    /// serializedPayload: a CDR-encapsulated `ParticipantGenericMessage`.
    pub payload: &'a [u8],
}

/// Read `submessage` (one complete RTPS submessage, header included, as
/// `decode_datawriter_submessage` returns it) as a DATA of the
/// `BuiltinParticipantVolatileMessageSecureWriter` (writerId `0xff0202c3`)
/// for its reader (readerId `0xff0202c4`, or `ENTITYID_UNKNOWN`). `None`
/// for any other submessage, any other endpoint pair, a DATA without a
/// payload (D flag clear) or carrying a key only (K flag), or one whose
/// lengths do not fit. An inline QoS (Q flag) is skipped, not refused.
#[must_use]
pub(crate) fn parse_data(submessage: &[u8]) -> Option<VolatileData<'_>> {
    let head = submessage.get(..4)?;
    if head[0] != DATA_ID {
        return None;
    }
    let flags = head[1];
    let le = flags & FLAG_E != 0;
    if flags & FLAG_D == 0 || flags & FLAG_K != 0 {
        return None;
    }
    let u16_at = |at: usize| -> Option<u16> {
        let b: [u8; 2] = submessage.get(at..at + 2)?.try_into().ok()?;
        Some(if le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let u32_at = |at: usize| -> Option<u32> {
        let b: [u8; 4] = submessage.get(at..at + 4)?.try_into().ok()?;
        Some(if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let declared = usize::from(u16_at(2)?);
    let end = if declared == 0 {
        submessage.len()
    } else {
        4usize.checked_add(declared)?
    };
    if end > submessage.len() {
        return None;
    }
    let reader_id: [u8; 4] = submessage.get(8..12)?.try_into().ok()?;
    let writer_id: [u8; 4] = submessage.get(12..16)?.try_into().ok()?;
    if writer_id != RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER
        || (reader_id != RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER
            && reader_id != ENTITYID_UNKNOWN)
    {
        return None;
    }
    let high = u32_at(16)?;
    let low = u32_at(20)?;
    // SequenceNumber_t.high is signed (RTPS v2.5 Sec.9.4.2.5).
    let high = i32::from_le_bytes(high.to_le_bytes());
    let sequence_number = (i64::from(high) << 32) | i64::from(low);
    // octetsToInlineQos counts from the octet right after itself (offset 8).
    let mut at = 8usize.checked_add(usize::from(u16_at(6)?))?;
    if flags & FLAG_Q != 0 {
        loop {
            let pid = u16_at(at)?;
            let len = usize::from(u16_at(at + 2)?);
            at = at.checked_add(4)?.checked_add(len)?;
            if at > end {
                return None;
            }
            if pid == PID_SENTINEL {
                break;
            }
        }
    }
    let payload = submessage.get(at..end)?;
    Some(VolatileData {
        sequence_number,
        payload,
    })
}

/// Decode `payload` (the serialized payload of a volatile DATA) as a
/// `ParticipantGenericMessage`, without yet deciding what its
/// `message_class_id` means: the dispatcher then routes on
/// `message.class_id` to [`WriterKeyAnnouncement::from_message`],
/// [`ReaderKeyAnnouncement::from_message`] or
/// [`ParticipantKeyAnnouncement::from_message`].
pub(crate) fn decode_message(payload: &[u8]) -> Result<GenericMessage, SecurityError> {
    decode_tokens(payload).map_err(|e| {
        SecurityError::CryptoError(format!(
            "volatile DATA: malformed ParticipantGenericMessage: {}",
            e
        ))
    })
}

/// Open one protected volatile DATA, as [`protect_message`] built it
/// (`envelope` starts at its SEC_PREFIX), and decode the message it
/// carries: decode under `material`, read the DATA ([`parse_data`]),
/// decode its payload ([`decode_message`]).
pub(crate) fn open_message(
    material: &WriterKeyMaterial,
    envelope: &[u8],
) -> Result<GenericMessage, SecurityError> {
    let decoded = decode_datawriter_submessage(material, envelope, 0)
        .map_err(|e| SecurityError::CryptoError(format!("volatile submessage refused: {:?}", e)))?;
    let data = parse_data(&decoded.submessage).ok_or_else(|| {
        SecurityError::CryptoError(
            "volatile submessage: not a DATA of the volatile secure writer".into(),
        )
    })?;
    decode_message(data.payload)
}

/// The one `CryptoToken` of `message.tokens`, decoded as a
/// `KeyMaterial_AES_GCM_GMAC`. Shared by both announcement kinds: each
/// carries exactly one token (Sec.7.4.4.6.1, Sec.7.4.4.6.2).
fn one_keymat(
    message: &GenericMessage,
    what: &str,
) -> Result<KeyMaterialAesGcmGmac, SecurityError> {
    let [token] = message.tokens.as_slice() else {
        return Err(SecurityError::CryptoError(format!(
            "{}: expected exactly one CryptoToken, got {}",
            what,
            message.tokens.len()
        )));
    };
    KeyMaterialAesGcmGmac::from_crypto_token(token)
}

/// The `master_salt` of a received key material: 32 octets, the length the
/// 256-bit transformations derive their session keys with (Sec.9.5.3.3.3).
/// Any other length is refused rather than padded or truncated: a salt the
/// receiver reshaped is not the salt the sender derives with.
fn salt_of(keymat: &KeyMaterialAesGcmGmac, what: &str) -> Result<SecretKey, SecurityError> {
    let salt: [u8; 32] = keymat.master_salt.as_slice().try_into().map_err(|_| {
        SecurityError::CryptoError(format!(
            "{}: master_salt is {} octets, expected 32",
            what,
            keymat.master_salt.len()
        ))
    })?;
    Ok(SecretKey::from_bytes(salt))
}

/// Per-source-participant replay guard for the volatile channel.
///
/// `message_identity.sequence_number` "shall start with the value set to
/// one and be incremented for each different message sent by the
/// BuiltinParticipantVolatileMessageSecureWriter" (Sec.7.4.4.3) -- ONE
/// counter per sending participant, shared by every message class that
/// writer emits (ParticipantCryptoTokens and DatawriterCryptoTokens
/// alike). `decode_tokens` reads it but a caller has to act on it: without
/// this guard, a captured, legitimately-signed old envelope replayed later
/// would be installed again by [`super::data_keys::DataKeyStore::insert`]
/// or [`super::participant_keys::ParticipantKeyStore::install_remote`]
/// exactly as if it had just arrived -- rolling a key back to one the
/// sender has since rotated away from.
///
/// Keyed by the 12-byte GUID prefix, for the lifetime of one KxKeys
/// session: the reliable reader delivers a peer's changes once and in
/// order within a session, and this guard is the second line under it (a
/// change of a new sequence number carrying an old message identity). A
/// message protected under a session's KxKeys cannot be opened under any
/// other, so when the reader starts a new session with the peer
/// (`volatile_channel`, `Delivery::session_reset`) the mark is forgotten
/// ([`Self::reset`]): a peer whose volatile writer counts from one again
/// under new KxKeys is not refused as a replay of itself.
pub(crate) struct ReplaySequenceGuard {
    highest_accepted: RwLock<HashMap<[u8; 12], i64>>,
    replays_rejected: AtomicU64,
}

impl ReplaySequenceGuard {
    pub(crate) fn new() -> Self {
        Self {
            highest_accepted: RwLock::new(HashMap::new()),
            replays_rejected: AtomicU64::new(0),
        }
    }

    /// `true` when `sequence_number` is strictly greater than every
    /// sequence number previously accepted from `peer_prefix` (and records
    /// it as the new high-water mark); `false` when it is a replay (at or
    /// below the stored mark), in which case nothing is recorded and the
    /// rejection counter advances.
    pub(crate) fn accept(&self, peer_prefix: [u8; 12], sequence_number: i64) -> bool {
        let mut highest = self.highest_accepted.write();
        let is_fresh = match highest.get(&peer_prefix) {
            Some(&previous) => sequence_number > previous,
            None => true,
        };
        if is_fresh {
            highest.insert(peer_prefix, sequence_number);
        } else {
            drop(highest);
            self.replays_rejected.fetch_add(1, Ordering::Relaxed);
        }
        is_fresh
    }

    /// Forget `peer_prefix`'s high-water mark: the peer authenticated
    /// again, under other KxKeys, and nothing protected under the old ones
    /// can be opened any more -- a replay of it cannot reach this guard --
    /// while the peer's new volatile writer may count from one again.
    pub(crate) fn reset(&self, peer_prefix: [u8; 12]) {
        self.highest_accepted.write().remove(&peer_prefix);
    }

    /// Total envelopes refused as replays since construction, across every
    /// peer. Monotonic; a counter for operator visibility, not a per-peer
    /// lookup.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn replays_rejected(&self) -> u64 {
        self.replays_rejected.load(Ordering::Relaxed)
    }
}

impl Default for ReplaySequenceGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// One writer's data-plane key, announced to one authenticated peer as a
/// `DatawriterCryptoTokens` message.
///
/// The key rides in a [`SecretKey`], so every decoded copy zeroizes on drop
/// and cannot leak through `{:?}`.
pub struct WriterKeyAnnouncement {
    /// The writer this key belongs to (`source_endpoint_guid` on the wire).
    /// Receivers file the key under `(writer_guid, key_id)` -- the pair is
    /// the lookup key, never a globally-unique id (two writers may pick
    /// the same random key id).
    pub writer_guid: GUID,
    /// Writer-chosen four-octet sender key id, widened for the store.
    pub key_id: u64,
    /// The AES-256-GCM data-plane key itself (`master_sender_key`).
    pub key: SecretKey,
    /// The writer's `master_salt` (module docs).
    pub master_salt: SecretKey,
    /// The `transformation_kind` the writer applies under this material
    /// (Table 70: chosen by the writer's protection kind).
    pub transformation: Transformation,
}

impl WriterKeyAnnouncement {
    /// Protect this announcement for one peer, as a
    /// `GMCLASSID_SECURITY_DATAWRITER_CRYPTO_TOKENS` message.
    ///
    /// `material` is that peer's Table 67 KxKeys
    /// (`PeerKeys::volatile_key_material`): the same announcement sent to
    /// two peers produces two unrelated ciphertexts, and a third
    /// authenticated participant cannot read a distribution that was not
    /// addressed to it. `local_volatile_writer` is this participant's own
    /// `BuiltinParticipantVolatileMessageSecureWriter` GUID
    /// (`message_identity.source_guid`, Sec.7.4.4.3); `sequence_number` is
    /// that writer's own RTPS sequence number for this change, the SAME
    /// value the DATA submessage carries as its writerSN. What comes back
    /// is that DATA, protected ([`protect_message`]). `destination_
    /// endpoint` is the matched reader this message is for (module docs);
    /// the caller decides, this method only writes whatever it is given.
    pub fn seal(
        &self,
        material: &WriterKeyMaterial,
        local_volatile_writer: &GUID,
        destination_participant: &GUID,
        destination_endpoint: [u8; 16],
        sequence_number: i64,
    ) -> Result<Vec<u8>, SecurityError> {
        let sender_key_id = u32::try_from(self.key_id).map_err(|_| {
            SecurityError::CryptoError(format!(
                "writer key id {:#x} does not fit CryptoTransformKeyId (octet[4]); refusing to \
                 announce a key whose wire id would desynchronize from the id on its real traffic",
                self.key_id
            ))
        })?;
        let keymat = KeyMaterialAesGcmGmac {
            transformation_kind: self.transformation.kind(),
            master_salt: self.master_salt.as_bytes().to_vec(),
            sender_key_id: sender_key_id.to_be_bytes(),
            master_sender_key: self.key.as_bytes().to_vec(),
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        let token = keymat.to_crypto_token()?;

        let envelope = encode_tokens(
            &local_volatile_writer.as_bytes(),
            sequence_number,
            &destination_participant.as_bytes(),
            &destination_endpoint,
            &self.writer_guid.as_bytes(),
            CLASS_DATAWRITER_CRYPTO_TOKENS,
            &[token],
        )?;

        protect_message(material, sequence_number, &envelope)
    }

    /// Open and parse an announcement received from a peer: `secured_bytes`
    /// is the protected DATA [`Self::seal`] returns.
    ///
    /// `material` is OUR Table 67 KxKeys for that peer (the derivation is
    /// symmetric, so both sides hold the same material independently).
    ///
    /// Returns `Err` on parse failure, tag mismatch, wrong class id, wrong
    /// token count, or a key material whose length does not fit AES-256.
    /// Nothing is installed on a partial parse.
    pub fn open(material: &WriterKeyMaterial, secured_bytes: &[u8]) -> Result<Self, SecurityError> {
        let message = open_message(material, secured_bytes)?;
        Self::from_message(&message)
    }

    /// Interpret an already-decrypted [`GenericMessage`] as a
    /// `DatawriterCryptoTokens` announcement. The dispatcher calls this
    /// after [`open_message`] once it has seen `message.class_id`.
    pub(crate) fn from_message(message: &GenericMessage) -> Result<Self, SecurityError> {
        if message.class_id != CLASS_DATAWRITER_CRYPTO_TOKENS {
            return Err(SecurityError::CryptoError(format!(
                "WriterKeyAnnouncement: unexpected message_class_id '{}'",
                message.class_id
            )));
        }
        let keymat = one_keymat(message, "WriterKeyAnnouncement")?;

        let key_bytes: [u8; 32] = keymat
            .master_sender_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                SecurityError::CryptoError(format!(
                    "WriterKeyAnnouncement: master_sender_key is {} octets, expected 32",
                    keymat.master_sender_key.len()
                ))
            })?;
        let key_id = u64::from(u32::from_be_bytes(keymat.sender_key_id));
        let master_salt = salt_of(&keymat, "WriterKeyAnnouncement")?;
        let transformation =
            Transformation::of_kind(keymat.transformation_kind).ok_or_else(|| {
                SecurityError::CryptoError(format!(
                    "WriterKeyAnnouncement: transformation_kind {:02x?} is neither AES256_GMAC \
                     nor AES256_GCM",
                    keymat.transformation_kind
                ))
            })?;

        Ok(Self {
            writer_guid: GUID::from_bytes(message.source_endpoint),
            key_id,
            key: SecretKey::from_bytes(key_bytes),
            master_salt,
            transformation,
        })
    }
}

/// One reader's submessage-protection key, announced to one authenticated
/// peer as a `DatareaderCryptoTokens` message (Sec.7.4.4.6.2, Sec.8.8.9.3).
///
/// A reader whose topic's `metadata_protection_kind` is not NONE protects
/// its own ACKNACK and NACK_FRAG submessages with
/// `encode_datareader_submessage` (`secure_submessage`), under a key it
/// mints itself (`register_local_datareader`, Table 71) -- never the
/// writer's key, which protects the opposite direction. Every matched
/// writer must hold this key before it can decode that reader's control
/// traffic, exactly as every matched reader must hold a writer's key
/// before it can decode that writer's DATA ([`WriterKeyAnnouncement`]): the
/// two announcements are mirror images, Sec.7.4.4.6.2 naming one message
/// class for each (`CLASS_DATAWRITER_CRYPTO_TOKENS` /
/// `CLASS_DATAREADER_CRYPTO_TOKENS`), riding the same
/// `ParticipantVolatileMessageSecure` channel.
///
/// The key rides in a [`SecretKey`], so every decoded copy zeroizes on drop
/// and cannot leak through `{:?}`.
pub struct ReaderKeyAnnouncement {
    /// The reader this key belongs to (`source_endpoint_guid` on the wire).
    /// Receivers file the key under `(reader_guid, key_id)` in the SAME
    /// store `WriterKeyAnnouncement` files writer keys in
    /// (`data_keys::DataKeyStore` is keyed by GUID, not by role): a reader
    /// and a writer of the same participant never share a GUID, so there
    /// is nothing to disambiguate.
    pub reader_guid: GUID,
    /// Reader-chosen key id, `CryptoTransformKeyId` width (32 bits) from
    /// the start -- same reasoning as [`WriterKeyAnnouncement::key_id`].
    pub key_id: u64,
    /// The AES-256 submessage-protection key itself (`master_sender_key`
    /// in Table 66's naming, even though a reader, not a "sender" of data,
    /// holds it: Table 66's field names are the builtin plugin's, shared
    /// by both CryptoToken kinds).
    pub key: SecretKey,
    /// The reader's `master_salt` (see [`WriterKeyAnnouncement::master_salt`]).
    pub master_salt: SecretKey,
    /// The `transformation_kind` the reader applies under this material
    /// (Table 71: chosen by the reader's protection kind).
    pub transformation: Transformation,
}

impl ReaderKeyAnnouncement {
    /// Encrypt this announcement for one peer, as a
    /// `GMCLASSID_SECURITY_DATAREADER_CRYPTO_TOKENS` message. Same
    /// parameters as [`WriterKeyAnnouncement::seal`], same reasons:
    /// `destination_endpoint` is the matched WRITER this message is for.
    pub fn seal(
        &self,
        material: &WriterKeyMaterial,
        local_volatile_writer: &GUID,
        destination_participant: &GUID,
        destination_endpoint: [u8; 16],
        sequence_number: i64,
    ) -> Result<Vec<u8>, SecurityError> {
        let sender_key_id = u32::try_from(self.key_id).map_err(|_| {
            SecurityError::CryptoError(format!(
                "reader key id {:#x} does not fit CryptoTransformKeyId (octet[4]); refusing to \
                 announce a key whose wire id would desynchronize from the id on its real traffic",
                self.key_id
            ))
        })?;
        let keymat = KeyMaterialAesGcmGmac {
            transformation_kind: self.transformation.kind(),
            master_salt: self.master_salt.as_bytes().to_vec(),
            sender_key_id: sender_key_id.to_be_bytes(),
            master_sender_key: self.key.as_bytes().to_vec(),
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        let token = keymat.to_crypto_token()?;

        let envelope = encode_tokens(
            &local_volatile_writer.as_bytes(),
            sequence_number,
            &destination_participant.as_bytes(),
            &destination_endpoint,
            &self.reader_guid.as_bytes(),
            CLASS_DATAREADER_CRYPTO_TOKENS,
            &[token],
        )?;

        protect_message(material, sequence_number, &envelope)
    }

    /// Decrypt and parse an announcement received from a peer. Same
    /// contract as [`WriterKeyAnnouncement::open`].
    pub fn open(material: &WriterKeyMaterial, secured_bytes: &[u8]) -> Result<Self, SecurityError> {
        let message = open_message(material, secured_bytes)?;
        Self::from_message(&message)
    }

    /// Interpret an already-decrypted [`GenericMessage`] as a
    /// `DatareaderCryptoTokens` announcement. The dispatcher calls this
    /// after [`open_message`] once it has seen `message.class_id`.
    pub(crate) fn from_message(message: &GenericMessage) -> Result<Self, SecurityError> {
        if message.class_id != CLASS_DATAREADER_CRYPTO_TOKENS {
            return Err(SecurityError::CryptoError(format!(
                "ReaderKeyAnnouncement: unexpected message_class_id '{}'",
                message.class_id
            )));
        }
        let keymat = one_keymat(message, "ReaderKeyAnnouncement")?;

        let key_bytes: [u8; 32] = keymat
            .master_sender_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                SecurityError::CryptoError(format!(
                    "ReaderKeyAnnouncement: master_sender_key is {} octets, expected 32",
                    keymat.master_sender_key.len()
                ))
            })?;
        let key_id = u64::from(u32::from_be_bytes(keymat.sender_key_id));
        let master_salt = salt_of(&keymat, "ReaderKeyAnnouncement")?;
        let transformation =
            Transformation::of_kind(keymat.transformation_kind).ok_or_else(|| {
                SecurityError::CryptoError(format!(
                    "ReaderKeyAnnouncement: transformation_kind {:02x?} is neither AES256_GMAC \
                     nor AES256_GCM",
                    keymat.transformation_kind
                ))
            })?;

        Ok(Self {
            reader_guid: GUID::from_bytes(message.source_endpoint),
            key_id,
            key: SecretKey::from_bytes(key_bytes),
            master_salt,
            transformation,
        })
    }
}

impl std::fmt::Debug for ReaderKeyAnnouncement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReaderKeyAnnouncement")
            .field("reader_guid", &self.reader_guid)
            .field("key_id", &self.key_id)
            .field("transformation", &self.transformation)
            .field("key", &self.key)
            .field("master_salt", &self.master_salt)
            .finish()
    }
}

/// This participant's own key material, announced to one authenticated
/// peer as a `ParticipantCryptoTokens` message (Sec.7.4.4.6.1,
/// Sec.8.8.9.1): the key material of `encode_rtps_message` /
/// `decode_rtps_message`, which protect whole RTPS messages between the two
/// DomainParticipants (Table 70, `register_matched_remote_participant`;
/// Table 71). Not the key material of secure discovery: each secure builtin
/// writer announces its own in a `DatawriterCryptoTokens` message
/// ([`WriterKeyAnnouncement`], Sec.8.8.9.2).
///
/// Both `destination_endpoint_guid` and `source_endpoint_guid` are
/// GUID_UNKNOWN on the wire (Sec.7.4.4.6.1: this message targets the whole
/// participant, not one endpoint).
pub struct ParticipantKeyAnnouncement {
    /// Writer-chosen key id, `CryptoTransformKeyId` width (32 bits) from
    /// the start -- no narrowing concern here, unlike
    /// [`WriterKeyAnnouncement::key_id`], because nothing elsewhere needs
    /// this id wider than the wire allows.
    pub key_id: u32,
    /// The participant's `master_sender_key`.
    pub key: SecretKey,
    /// The participant's `master_salt` (module docs).
    pub master_salt: SecretKey,
}

impl ParticipantKeyAnnouncement {
    /// Encrypt this announcement for one peer, as a
    /// `GMCLASSID_SECURITY_PARTICIPANT_CRYPTO_TOKENS` message. Same
    /// parameters as [`WriterKeyAnnouncement::seal`], same reasons.
    pub fn seal(
        &self,
        material: &WriterKeyMaterial,
        local_volatile_writer: &GUID,
        destination_participant: &GUID,
        sequence_number: i64,
    ) -> Result<Vec<u8>, SecurityError> {
        let keymat = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: self.master_salt.as_bytes().to_vec(),
            sender_key_id: self.key_id.to_be_bytes(),
            master_sender_key: self.key.as_bytes().to_vec(),
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        let token = keymat.to_crypto_token()?;

        let envelope = encode_tokens(
            &local_volatile_writer.as_bytes(),
            sequence_number,
            &destination_participant.as_bytes(),
            &[0; 16], // destination_endpoint_guid: GUID_UNKNOWN (Sec.7.4.4.6.1)
            &[0; 16], // source_endpoint_guid: GUID_UNKNOWN (Sec.7.4.4.6.1)
            CLASS_PARTICIPANT_CRYPTO_TOKENS,
            &[token],
        )?;

        protect_message(material, sequence_number, &envelope)
    }

    /// Decrypt and parse an announcement received from a peer. Same
    /// contract as [`WriterKeyAnnouncement::open`].
    pub fn open(material: &WriterKeyMaterial, secured_bytes: &[u8]) -> Result<Self, SecurityError> {
        let message = open_message(material, secured_bytes)?;
        Self::from_message(&message)
    }

    /// Interpret an already-decrypted [`GenericMessage`] as a
    /// `ParticipantCryptoTokens` announcement.
    pub(crate) fn from_message(message: &GenericMessage) -> Result<Self, SecurityError> {
        if message.class_id != CLASS_PARTICIPANT_CRYPTO_TOKENS {
            return Err(SecurityError::CryptoError(format!(
                "ParticipantKeyAnnouncement: unexpected message_class_id '{}'",
                message.class_id
            )));
        }
        let keymat = one_keymat(message, "ParticipantKeyAnnouncement")?;

        let key_bytes: [u8; 32] = keymat
            .master_sender_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                SecurityError::CryptoError(format!(
                    "ParticipantKeyAnnouncement: master_sender_key is {} octets, expected 32",
                    keymat.master_sender_key.len()
                ))
            })?;
        let key_id = u32::from_be_bytes(keymat.sender_key_id);
        let master_salt = salt_of(&keymat, "ParticipantKeyAnnouncement")?;

        Ok(Self {
            key_id,
            key: SecretKey::from_bytes(key_bytes),
            master_salt,
        })
    }
}

impl std::fmt::Debug for ParticipantKeyAnnouncement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParticipantKeyAnnouncement")
            .field("key_id", &self.key_id)
            .field("key", &self.key)
            .field("master_salt", &self.master_salt)
            .finish()
    }
}

impl std::fmt::Debug for WriterKeyAnnouncement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key field redacts itself; keep the metadata visible for logs.
        f.debug_struct("WriterKeyAnnouncement")
            .field("writer_guid", &self.writer_guid)
            .field("key_id", &self.key_id)
            .field("transformation", &self.transformation)
            .field("key", &self.key)
            .field("master_salt", &self.master_salt)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::crypto::kx_keys;

    fn announcement() -> WriterKeyAnnouncement {
        WriterKeyAnnouncement {
            writer_guid: GUID::from_bytes([
                0x01, 0x1A, 0xC0, 0xA8, 0x01, 0x14, 0x00, 0x0D, 0xF9, 0x4B, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x03,
            ]),
            // Realistic: `dds::writer::builder` mints key ids within 32
            // bits from the start (see the module docs) precisely so this
            // fits `sender_key_id` losslessly.
            key_id: 0xCAFE_0001,
            key: SecretKey::from_bytes([0x42; 32]),
            master_salt: SecretKey::from_bytes([0x24; 32]),
            transformation: Transformation::Aes256Gcm,
        }
    }

    fn volatile_writer() -> GUID {
        GUID::from_bytes([
            0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0xff, 0x02,
            0x02, 0xc3,
        ])
    }

    fn destination_participant() -> GUID {
        GUID::from_bytes([
            0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x00, 0x00,
            0x01, 0xc1,
        ])
    }

    fn seal_for_test(
        announcement: &WriterKeyAnnouncement,
        material: &WriterKeyMaterial,
    ) -> Vec<u8> {
        announcement
            .seal(
                material,
                &volatile_writer(),
                &destination_participant(),
                GUID_UNKNOWN,
                1,
            )
            .expect("seal")
    }

    /// Table 67 KxKeys for a fake peer, seeded from `seed`.
    fn material(seed: u8) -> WriterKeyMaterial {
        kx_keys::derive(&[seed; 32], &[seed ^ 0x11; 32], &[seed ^ 0x22; 32])
    }

    /// DDS Security v1.1 Sec.7.4.4.1 (Table 17, `is_submessage_protected`)
    /// and Sec.9.5.3.3.4.5: what goes on the wire for one announcement is
    /// the volatile writer's DATA submessage itself, protected as a whole
    /// -- SEC_PREFIX(CryptoHeader), SEC_BODY(CryptoContent), SEC_POSTFIX
    /// (CryptoFooter) -- and the plaintext under the SEC_BODY is a
    /// complete RTPS DATA (readerId 0xff0202c4, writerId 0xff0202c3,
    /// writerSN = the message's sequence number) whose serialized payload
    /// is the CDR ParticipantGenericMessage, nothing else.
    ///
    /// The bytes are read here without this crate's decoder: the headers by
    /// hand, the session key by Sec.9.5.3.3.3's formula over `ring`'s HMAC,
    /// and the CryptoContent with `ring`'s AES-256-GCM. The expected DATA
    /// is written out octet by octet.
    ///
    /// Mutant: `seal` wrapping the bare message (no DATA header around it)
    /// fails the DATA header comparison; `protect_message` swapping the
    /// reader and writer entity ids fails it too.
    #[test]
    fn the_wire_is_the_protected_data_submessage_itself() {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
        use ring::hmac;

        let master_key = [0x31u8; 32];
        let master_salt = [0x42u8; 32];
        let kx = WriterKeyMaterial::new(master_key, master_salt, [0, 0, 0, 0]);
        let sequence_number = 0x0000_0001_0000_0007_i64;
        let wire = announcement()
            .seal(
                &kx,
                &volatile_writer(),
                &destination_participant(),
                GUID_UNKNOWN,
                sequence_number,
            )
            .expect("seal");

        // SEC_PREFIX: id 0x31, E flag, octetsToNextHeader 20 (LE), then the
        // CryptoHeader: transformation_kind AES256_GCM, key id 0 (Table 67).
        assert_eq!(&wire[0..4], &[0x31, 0x01, 20, 0]);
        assert_eq!(
            &wire[4..8],
            &[0, 0, 0, 4],
            "CRYPTO_TRANSFORMATION_KIND_AES256_GCM"
        );
        assert_eq!(&wire[8..12], &[0, 0, 0, 0], "Table 67: sender_key_id = 0");
        let session_id: [u8; 4] = wire[12..16].try_into().expect("session id");
        let iv_suffix: [u8; 8] = wire[16..24].try_into().expect("iv suffix");

        // SEC_BODY: id 0x30, then CryptoContent = length (BE) + ciphertext.
        assert_eq!(wire[24], 0x30);
        let body_len = usize::from(u16::from_le_bytes([wire[26], wire[27]]));
        let content_len =
            usize::try_from(u32::from_be_bytes(wire[28..32].try_into().expect("len")))
                .expect("usize");
        let ciphertext = &wire[32..32 + content_len];
        let postfix_at = 28 + body_len;
        assert_eq!(wire[postfix_at], 0x32, "SEC_POSTFIX follows the SEC_BODY");
        let common_mac = &wire[postfix_at + 4..postfix_at + 20];
        assert_eq!(
            wire.len(),
            postfix_at + 24,
            "nothing after the CryptoFooter"
        );

        // SessionKey = HMAC256(MasterKey, "SessionKey" | MasterSalt | SessionId).
        let mut label = b"SessionKey".to_vec();
        label.extend_from_slice(&master_salt);
        label.extend_from_slice(&session_id);
        let session_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &master_key), &label);
        let key =
            LessSafeKey::new(UnboundKey::new(&AES_256_GCM, session_key.as_ref()).expect("AES key"));
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&session_id);
        nonce[4..].copy_from_slice(&iv_suffix);
        let mut in_out = ciphertext.to_vec();
        in_out.extend_from_slice(common_mac);
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut in_out,
            )
            .expect("the CryptoContent opens under the session key of the material");

        let message = encode_tokens(
            &volatile_writer().as_bytes(),
            sequence_number,
            &destination_participant().as_bytes(),
            &GUID_UNKNOWN,
            &announcement().writer_guid.as_bytes(),
            CLASS_DATAWRITER_CRYPTO_TOKENS,
            &[],
        )
        .expect("encode_tokens");
        let body = plain.len() - 4; // octetsToNextHeader: the DATA minus its header
        let mut expected_header = vec![0x15, 0x05];
        expected_header.extend_from_slice(&u16::try_from(body).expect("u16").to_le_bytes());
        expected_header.extend_from_slice(&[0, 0, 16, 0]); // extraFlags, octetsToInlineQos
        expected_header.extend_from_slice(&[0xff, 0x02, 0x02, 0xc4]); // readerId
        expected_header.extend_from_slice(&[0xff, 0x02, 0x02, 0xc3]); // writerId
        expected_header.extend_from_slice(&1i32.to_le_bytes()); // writerSN.high
        expected_header.extend_from_slice(&7u32.to_le_bytes()); // writerSN.low
        assert_eq!(
            &plain[..24],
            &expected_header[..],
            "the DATA submessage header"
        );
        // The payload is the CDR ParticipantGenericMessage: its fixed part
        // (everything before message_data's token) is byte for byte the
        // one encode_tokens writes for the same fields.
        let fixed = message.len() - 4; // minus the empty sequence's length
        assert_eq!(&plain[24..24 + fixed], &message[..fixed]);
        assert_eq!(
            &plain[24 + fixed..24 + fixed + 4],
            &1u32.to_le_bytes(),
            "message_data carries exactly one CryptoToken"
        );
    }

    #[test]
    fn seal_open_roundtrip_preserves_every_field() {
        let key_material = material(0x11);
        let original = announcement();

        let sealed = seal_for_test(&original, &key_material);
        let opened = WriterKeyAnnouncement::open(&key_material, &sealed).expect("open");

        assert_eq!(opened.writer_guid, original.writer_guid);
        assert_eq!(
            opened.key_id, original.key_id,
            "key_id must round-trip losslessly: it must still match the id the writer \
             stamps on its real sealed traffic"
        );
        assert_eq!(opened.key.as_bytes(), original.key.as_bytes());
        assert_eq!(
            opened.master_salt.as_bytes(),
            original.master_salt.as_bytes()
        );
        assert_eq!(opened.transformation, original.transformation);
    }

    /// Table 70: the transformation_kind is the writer's protection kind,
    /// and travels in the token: a signing writer's GMAC kind arrives as
    /// GMAC. Mutant: `seal` writing AES256_GCM whatever the transformation
    /// fails it.
    #[test]
    fn a_signing_writers_transformation_kind_round_trips() {
        let kx = material(0x15);
        let mut signing = announcement();
        signing.transformation = Transformation::Aes256Gmac;
        let opened = WriterKeyAnnouncement::open(&kx, &seal_for_test(&signing, &kx)).expect("open");
        assert_eq!(opened.transformation, Transformation::Aes256Gmac);
    }

    /// A submessage protected by `encode_datawriter_submessage` under the
    /// material `(key, salt, key_id)`, and whether `decode_datawriter_submessage`
    /// opens it under `(key, other_salt, key_id)`.
    fn decodes_under(
        key: &[u8; 32],
        salt: &[u8; 32],
        other_salt: &[u8; 32],
        key_id: u32,
    ) -> Result<(), crate::security::crypto::secure_submessage::DecodeRefusal> {
        let sender = WriterKeyMaterial::new(*key, *salt, key_id.to_be_bytes());
        let receiver = WriterKeyMaterial::new(*key, *other_salt, key_id.to_be_bytes());
        let data = crate::protocol::rtps::encode_data(
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
            1,
            &[0x5C; 20],
        )
        .expect("DATA");
        let protected = encode_datawriter_submessage(&sender, &data).expect("encode");
        decode_datawriter_submessage(&receiver, &protected, 0).map(|_| ())
    }

    /// Sec.9.5.3.3.3: the session keys are `HMAC256(MasterKey, "SessionKey" |
    /// MasterSalt | SessionId)`, so the salt a receiver files from a
    /// DatawriterCryptoTokens message must be the writer's own. Two materials
    /// that differ only by their salt do not decode each other's submessages,
    /// and the material rebuilt from the received token decodes the writer's.
    ///
    /// Mutant: `seal` writing 32 zero octets as `master_salt` (what it did
    /// before) fails the first assertion.
    #[test]
    fn the_announced_salt_is_the_salt_the_receiver_decodes_with() {
        let kx = material(0x12);
        let original = announcement();
        let opened =
            WriterKeyAnnouncement::open(&kx, &seal_for_test(&original, &kx)).expect("open");
        let key_id = u32::try_from(original.key_id).expect("32-bit id");
        assert_eq!(
            decodes_under(
                original.key.as_bytes(),
                original.master_salt.as_bytes(),
                opened.master_salt.as_bytes(),
                key_id,
            ),
            Ok(()),
            "the receiver's material, rebuilt from the token, must decode the writer's submessage"
        );
        assert_eq!(
            decodes_under(
                original.key.as_bytes(),
                original.master_salt.as_bytes(),
                &[0u8; 32],
                key_id,
            ),
            Err(crate::security::crypto::secure_submessage::DecodeRefusal::NotAuthentic),
            "the same key under another salt derives other session keys"
        );
    }

    /// The same rule for ParticipantCryptoTokens.
    ///
    /// Mutant: `ParticipantKeyAnnouncement::seal` writing a zero salt fails
    /// the assertion.
    #[test]
    fn the_announced_participant_salt_is_the_salt_the_receiver_decodes_with() {
        let kx = material(0x13);
        let original = participant_announcement();
        let opened =
            ParticipantKeyAnnouncement::open(&kx, &seal_participant_for_test(&original, &kx))
                .expect("open");
        assert_eq!(
            decodes_under(
                original.key.as_bytes(),
                original.master_salt.as_bytes(),
                opened.master_salt.as_bytes(),
                original.key_id,
            ),
            Ok(())
        );
    }

    /// A `master_salt` that is not 32 octets is refused, not reshaped.
    #[test]
    fn a_salt_of_another_length_is_refused() {
        let kx = material(0x14);
        let keymat = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: vec![0x01; 16],
            sender_key_id: [0, 0, 0, 1],
            master_sender_key: vec![0x07; 32],
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        let token = keymat.to_crypto_token().expect("to_crypto_token");
        let envelope = encode_tokens(
            &volatile_writer().as_bytes(),
            1,
            &destination_participant().as_bytes(),
            &[0; 16],
            &announcement().writer_guid.as_bytes(),
            CLASS_DATAWRITER_CRYPTO_TOKENS,
            &[token],
        )
        .expect("encode_tokens");
        let sealed = protect_message(&kx, 1, &envelope).expect("protect");
        let refused = WriterKeyAnnouncement::open(&kx, &sealed).expect_err("refused");
        assert!(refused.to_string().contains("master_salt"), "{}", refused);
    }

    /// The wire key id is really `CryptoTransformKeyId` (`octet[4]`,
    /// Sec.9.5.2.1.1), 32 bits: a `key_id` that does not fit is refused,
    /// not silently narrowed (which would desynchronize the announced id
    /// from the one the writer actually stamps on its sealed traffic).
    #[test]
    fn a_key_id_that_does_not_fit_32_bits_is_refused() {
        let key_material = material(0x44);
        let too_wide = WriterKeyAnnouncement {
            writer_guid: announcement().writer_guid,
            key_id: 0x1_0000_0000,
            key: SecretKey::from_bytes([0x09; 32]),
            master_salt: SecretKey::from_bytes([0x90; 32]),
            transformation: Transformation::Aes256Gcm,
        };
        assert!(
            too_wide
                .seal(
                    &key_material,
                    &volatile_writer(),
                    &destination_participant(),
                    GUID_UNKNOWN,
                    1
                )
                .is_err(),
            "a key id past u32::MAX must be refused, not narrowed"
        );
    }

    /// A peer that authenticated with US cannot read a distribution addressed
    /// to someone ELSE: per-peer KxKeys are the access-control boundary of
    /// the whole channel.
    #[test]
    fn a_different_peers_key_material_cannot_open_the_envelope() {
        let for_peer_a = material(0xAA);
        let for_peer_b = material(0xBB);

        let sealed = seal_for_test(&announcement(), &for_peer_a);
        assert!(
            WriterKeyAnnouncement::open(&for_peer_b, &sealed).is_err(),
            "an envelope sealed for one peer opened with another peer's key material"
        );
    }

    /// The metatraffic key and the volatile channel's KxKeys are different
    /// TYPES (`SecretKey` vs `WriterKeyMaterial`), derived by unrelated
    /// algorithms (HKDF-plus-salt vs Table 67's HMAC recipe): the type
    /// system, not a runtime check, is what prevents mixing them up.
    #[test]
    fn a_tampered_envelope_is_rejected() {
        let key_material = material(0x33);
        let mut sealed = seal_for_test(&announcement(), &key_material);
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(WriterKeyAnnouncement::open(&key_material, &sealed).is_err());
    }

    /// Flipping any octet of the protected envelope (CryptoHeader, content,
    /// or MAC) must be caught -- not just the last byte of the previous test.
    #[test]
    fn every_octet_flip_is_caught() {
        let key_material = material(0x55);
        let sealed = seal_for_test(&announcement(), &key_material);
        for at in 0..sealed.len() {
            let mut flipped = sealed.clone();
            flipped[at] ^= 0x01;
            assert!(
                WriterKeyAnnouncement::open(&key_material, &flipped).is_err(),
                "octet {} flipped still opened",
                at
            );
        }
    }

    /// The message_class_id is really Sec.7.4.4.5's
    /// GMCLASSID_SECURITY_DATAWRITER_CRYPTO_TOKENS: a mutant that answers
    /// any OTHER class id must be refused, not silently accepted.
    #[test]
    fn a_wrong_message_class_id_is_refused() {
        let key_material = material(0x66);
        let keymat = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: vec![0u8; 32],
            sender_key_id: [0, 0, 0, 1],
            master_sender_key: vec![0x07; 32],
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        let token = keymat.to_crypto_token().expect("to_crypto_token");
        let envelope = encode_tokens(
            &volatile_writer().as_bytes(),
            1,
            &destination_participant().as_bytes(),
            &[0; 16],
            &announcement().writer_guid.as_bytes(),
            "dds.sec.datareader_crypto_tokens", // wrong class on purpose
            &[token],
        )
        .expect("encode_tokens");
        let sealed = protect_message(&key_material, 1, &envelope).expect("protect");
        assert!(WriterKeyAnnouncement::open(&key_material, &sealed).is_err());
    }

    /// Sec.7.4.4.6.2: the message_data of a DatawriterCryptoTokens message
    /// is a sequence, but HDDS's one-key-per-writer design (the module
    /// docs) only ever sends ONE CryptoToken in it. A well-formed message
    /// carrying two, from a peer that is not supposed to send more than
    /// one, is refused -- not silently accepted on its first token, which
    /// would make a second, differently-keyed token invisible and leave
    /// the receiver guessing which one the sender actually meant.
    #[test]
    fn two_tokens_on_a_datawriter_crypto_tokens_message_is_refused() {
        let key_material = material(0xDD);
        let keymat = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: vec![0u8; 32],
            sender_key_id: [0, 0, 0, 1],
            master_sender_key: vec![0x08; 32],
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        let token = keymat.to_crypto_token().expect("to_crypto_token");
        let envelope = encode_tokens(
            &volatile_writer().as_bytes(),
            1,
            &destination_participant().as_bytes(),
            &[0; 16],
            &announcement().writer_guid.as_bytes(),
            CLASS_DATAWRITER_CRYPTO_TOKENS,
            &[token.clone(), token],
        )
        .expect("encode_tokens");
        let sealed = protect_message(&key_material, 1, &envelope).expect("protect");
        assert!(
            WriterKeyAnnouncement::open(&key_material, &sealed).is_err(),
            "a DatawriterCryptoTokens message carrying two CryptoTokens must be refused"
        );
    }

    fn participant_announcement() -> ParticipantKeyAnnouncement {
        ParticipantKeyAnnouncement {
            key_id: 0xBEEF_0001,
            key: SecretKey::from_bytes([0x5A; 32]),
            master_salt: SecretKey::from_bytes([0xA5; 32]),
        }
    }

    fn seal_participant_for_test(
        announcement: &ParticipantKeyAnnouncement,
        material: &WriterKeyMaterial,
    ) -> Vec<u8> {
        announcement
            .seal(material, &volatile_writer(), &destination_participant(), 1)
            .expect("seal")
    }

    #[test]
    fn participant_announcement_seal_open_roundtrip_preserves_every_field() {
        let key_material = material(0x77);
        let original = participant_announcement();

        let sealed = seal_participant_for_test(&original, &key_material);
        let opened = ParticipantKeyAnnouncement::open(&key_material, &sealed).expect("open");

        assert_eq!(opened.key_id, original.key_id);
        assert_eq!(opened.key.as_bytes(), original.key.as_bytes());
        assert_eq!(
            opened.master_salt.as_bytes(),
            original.master_salt.as_bytes()
        );
    }

    /// Both endpoint GUIDs of a ParticipantCryptoTokens message are
    /// GUID_UNKNOWN (Sec.7.4.4.6.1), unlike DatawriterCryptoTokens'
    /// `source_endpoint_guid`: pinned at the wire level, not just by type.
    #[test]
    fn participant_announcement_endpoint_guids_are_unknown_on_the_wire() {
        let key_material = material(0x88);
        let sealed = seal_participant_for_test(&participant_announcement(), &key_material);
        let message = open_message(&key_material, &sealed).expect("open_message");
        assert_eq!(message.destination_endpoint, [0; 16]);
        assert_eq!(message.source_endpoint, [0; 16]);
    }

    /// Mutant: the two announcement kinds must not be interchangeable. If
    /// the class id check were ever dropped, a DatawriterCryptoTokens
    /// message would be misread as a participant key material (or vice
    /// versa) and installed in the WRONG store.
    #[test]
    fn a_writer_announcement_is_not_a_participant_announcement_and_vice_versa() {
        let key_material = material(0x99);

        let writer_sealed = seal_for_test(&announcement(), &key_material);
        assert!(
            ParticipantKeyAnnouncement::open(&key_material, &writer_sealed).is_err(),
            "a DatawriterCryptoTokens envelope opened as ParticipantCryptoTokens"
        );

        let participant_sealed =
            seal_participant_for_test(&participant_announcement(), &key_material);
        assert!(
            WriterKeyAnnouncement::open(&key_material, &participant_sealed).is_err(),
            "a ParticipantCryptoTokens envelope opened as DatawriterCryptoTokens"
        );
    }

    #[test]
    fn participant_announcement_debug_redacts_the_key_material() {
        let rendered = format!("{:?}", participant_announcement());
        assert!(rendered.contains("redacted"), "got: {}", rendered);
        assert!(
            !rendered.to_lowercase().contains("0x5a, 0x5a") && !rendered.contains("90, 90"),
            "Debug leaked key bytes: {}",
            rendered
        );
    }

    #[test]
    fn debug_redacts_the_key_material() {
        let rendered = format!("{:?}", announcement());
        assert!(rendered.contains("redacted"), "got: {}", rendered);
        assert!(
            !rendered.contains("66, 66") && !rendered.to_lowercase().contains("0x42, 0x42"),
            "Debug leaked key bytes: {}",
            rendered
        );
    }

    /// Sec.7.4.4.3: a fresh (strictly increasing) sequence number from a
    /// peer is accepted and becomes the new high-water mark; a replay (at
    /// or below it) is refused and counted.
    ///
    /// Mutant: `accept`'s comparison changed from `sequence_number >
    /// previous` to `>=` (the off-by-one that would accept an exact
    /// replay) -- caught live by the "exact same sequence number again"
    /// assertion below, reverted.
    #[test]
    fn a_replay_is_refused_and_a_fresh_sequence_is_accepted() {
        let guard = ReplaySequenceGuard::new();
        let peer = [0x11; 12];

        assert!(guard.accept(peer, 1), "the first sequence must be fresh");
        assert!(
            guard.accept(peer, 2),
            "a strictly increasing sequence must be fresh"
        );
        assert_eq!(guard.replays_rejected(), 0);

        assert!(
            !guard.accept(peer, 2),
            "the exact same sequence number again must be refused as a replay"
        );
        assert!(
            !guard.accept(peer, 1),
            "an OLDER sequence number must be refused as a replay"
        );
        assert_eq!(
            guard.replays_rejected(),
            2,
            "both replays above must be counted"
        );

        // The high-water mark did not move backward: 3 is still fresh.
        assert!(
            guard.accept(peer, 3),
            "3 must still be fresh after the mark reached 2"
        );
    }

    /// A peer that restarts gets a fresh, independently random GUID
    /// prefix (HDDS never reuses one): a DIFFERENT prefix has no entry
    /// here and starts fresh, even at a sequence number a DIFFERENT peer
    /// already passed.
    #[test]
    fn a_different_peer_prefix_starts_fresh() {
        let guard = ReplaySequenceGuard::new();
        let peer_a = [0xAA; 12];
        let peer_b = [0xBB; 12];

        assert!(guard.accept(peer_a, 100));
        assert!(
            guard.accept(peer_b, 1),
            "a different peer prefix must start fresh, independent of what peer_a reached"
        );
        assert!(
            !guard.accept(peer_a, 50),
            "peer_a's own replay must still be refused"
        );
    }

    // -------------------------------------------------------------------
    //  builtin_peer_entity_id (DDS Security v1.1 Sec.7.4.1.3)
    // -------------------------------------------------------------------

    /// Table of the six builtin tunnels: a WITH_KEY writer/reader pair by
    /// `0xC2`/`0xC7`, a NO_KEY pair by `0xC3`/`0xC4`, both directions.
    ///
    /// Mutant: swapping the `0xC2 => 0xC7` arm for `0xC2 => 0xC4` (pairing a
    /// WITH_KEY writer with a NO_KEY reader) must fail every assertion
    /// below, since none of these fixed vectors would still match.
    #[test]
    fn builtin_peer_entity_id_mirrors_writer_and_reader_both_ways() {
        let sedp_pub_secure_writer = [0xff, 0x00, 0x03, 0xc2];
        let sedp_pub_secure_reader = [0xff, 0x00, 0x03, 0xc7];
        let volatile_secure_writer = [0xff, 0x02, 0x02, 0xc3];
        let volatile_secure_reader = [0xff, 0x02, 0x02, 0xc4];

        assert_eq!(
            builtin_peer_entity_id(sedp_pub_secure_writer),
            Some(sedp_pub_secure_reader)
        );
        assert_eq!(
            builtin_peer_entity_id(sedp_pub_secure_reader),
            Some(sedp_pub_secure_writer),
            "the mapping is its own inverse"
        );
        assert_eq!(
            builtin_peer_entity_id(volatile_secure_writer),
            Some(volatile_secure_reader)
        );
        assert_eq!(
            builtin_peer_entity_id(volatile_secure_reader),
            Some(volatile_secure_writer)
        );
    }

    /// A plain USER writer or reader entity id (no `0xC0` bits) names no
    /// single peer: several readers of a peer participant may match the
    /// same USER writer, so `None`, never a guess.
    #[test]
    fn builtin_peer_entity_id_is_none_for_a_user_entity_id() {
        assert_eq!(builtin_peer_entity_id([0, 0, 1, 0x02]), None); // user WITH_KEY writer
        assert_eq!(builtin_peer_entity_id([0, 0, 1, 0x07]), None); // user WITH_KEY reader
        assert_eq!(builtin_peer_entity_id([0, 0, 1, 0xc1]), None); // ENTITYID_PARTICIPANT
    }

    /// Mutant: masking with `0xFF` instead of `0x3F` (forgetting to drop the
    /// builtin bits) would make every builtin READER (0xC4/0xC7) read as
    /// "not a reader", since `0xC4 & 0x3F == 0x04` only holds after the
    /// mask -- these fixed vectors catch that directly.
    #[test]
    fn is_reader_entity_id_distinguishes_writer_from_reader_builtin_and_user() {
        for reader in [
            [0, 0, 1, 0x04],          // user NO_KEY reader
            [0, 0, 1, 0x07],          // user WITH_KEY reader
            [0xff, 0x00, 0x03, 0xc7], // SEDP publications secure reader
            [0xff, 0x02, 0x02, 0xc4], // volatile secure reader
        ] {
            assert!(is_reader_entity_id(reader), "{:02x?} is a reader", reader);
        }
        for writer in [
            [0, 0, 1, 0x02],          // user WITH_KEY writer
            [0, 0, 1, 0x03],          // user NO_KEY writer
            [0xff, 0x00, 0x03, 0xc2], // SEDP publications secure writer
            [0xff, 0x02, 0x02, 0xc3], // volatile secure writer
            [0, 0, 1, 0xc1],          // ENTITYID_PARTICIPANT
        ] {
            assert!(
                !is_reader_entity_id(writer),
                "{:02x?} is not a reader",
                writer
            );
        }
    }

    // -------------------------------------------------------------------
    //  ReaderKeyAnnouncement (DDS Security v1.1 Sec.7.4.4.6.2, Sec.8.8.9.3)
    // -------------------------------------------------------------------

    fn reader_announcement() -> ReaderKeyAnnouncement {
        ReaderKeyAnnouncement {
            reader_guid: GUID::from_bytes([
                0x01, 0x1A, 0xC0, 0xA8, 0x01, 0x14, 0x00, 0x0D, 0xF9, 0x4B, 0x00, 0x00, 0xff, 0x00,
                0x03, 0xc7,
            ]),
            key_id: 0xBEEF_0002,
            key: SecretKey::from_bytes([0x61; 32]),
            master_salt: SecretKey::from_bytes([0x62; 32]),
            transformation: Transformation::Aes256Gcm,
        }
    }

    fn seal_reader_for_test(
        announcement: &ReaderKeyAnnouncement,
        material: &WriterKeyMaterial,
        destination_endpoint: [u8; 16],
    ) -> Vec<u8> {
        announcement
            .seal(
                material,
                &volatile_writer(),
                &destination_participant(),
                destination_endpoint,
                1,
            )
            .expect("seal")
    }

    #[test]
    fn reader_announcement_seal_open_roundtrip_preserves_every_field() {
        let key_material = material(0xA1);
        let original = reader_announcement();

        let sealed = seal_reader_for_test(&original, &key_material, GUID_UNKNOWN);
        let opened = ReaderKeyAnnouncement::open(&key_material, &sealed).expect("open");

        assert_eq!(opened.reader_guid, original.reader_guid);
        assert_eq!(opened.key_id, original.key_id);
        assert_eq!(opened.key.as_bytes(), original.key.as_bytes());
        assert_eq!(
            opened.master_salt.as_bytes(),
            original.master_salt.as_bytes()
        );
        assert_eq!(opened.transformation, original.transformation);
    }

    /// A ReaderKeyAnnouncement is addressed to the matched WRITER (not a
    /// reader, unlike WriterKeyAnnouncement's destination): the module docs'
    /// mirror-image relationship, pinned on the wire.
    #[test]
    fn reader_announcement_can_carry_a_named_destination_writer() {
        let key_material = material(0xA2);
        let destination = GUID::new([0x77; 12], [0xff, 0x00, 0x03, 0xc2]);
        let sealed = seal_reader_for_test(
            &reader_announcement(),
            &key_material,
            destination.as_bytes(),
        );
        let message = open_message(&key_material, &sealed).expect("open_message");
        assert_eq!(message.destination_endpoint, destination.as_bytes());
    }

    /// Mutant: the two CryptoTokens message classes must not be
    /// interchangeable, same reasoning as the writer/participant check
    /// above -- a ReaderKeyAnnouncement installed as a writer's key (or
    /// vice versa) would file submessage-protection material under the
    /// wrong endpoint's GUID.
    #[test]
    fn a_reader_announcement_is_not_a_writer_announcement_and_vice_versa() {
        let key_material = material(0xA3);

        let reader_sealed =
            seal_reader_for_test(&reader_announcement(), &key_material, GUID_UNKNOWN);
        assert!(
            WriterKeyAnnouncement::open(&key_material, &reader_sealed).is_err(),
            "a DatareaderCryptoTokens envelope opened as DatawriterCryptoTokens"
        );

        let writer_sealed = seal_for_test(&announcement(), &key_material);
        assert!(
            ReaderKeyAnnouncement::open(&key_material, &writer_sealed).is_err(),
            "a DatawriterCryptoTokens envelope opened as DatareaderCryptoTokens"
        );
    }

    #[test]
    fn reader_announcement_debug_redacts_the_key_material() {
        let rendered = format!("{:?}", reader_announcement());
        assert!(rendered.contains("redacted"), "got: {}", rendered);
        assert!(
            !rendered.contains("97, 97") && !rendered.to_lowercase().contains("0x61, 0x61"),
            "Debug leaked key bytes: {}",
            rendered
        );
    }

    /// Sec.9.5.3.3.3: same salt-sensitivity rule as the writer side
    /// (`the_announced_salt_is_the_salt_the_receiver_decodes_with`), here for
    /// a reader's submessage-protection key: the salt a receiver files from
    /// a DatareaderCryptoTokens message must be the reader's own.
    #[test]
    fn the_announced_reader_salt_is_the_salt_the_receiver_decodes_with() {
        let kx = material(0xA4);
        let original = reader_announcement();
        let opened =
            ReaderKeyAnnouncement::open(&kx, &seal_reader_for_test(&original, &kx, GUID_UNKNOWN))
                .expect("open");
        let key_id = u32::try_from(original.key_id).expect("32-bit id");
        assert_eq!(
            decodes_under(
                original.key.as_bytes(),
                original.master_salt.as_bytes(),
                opened.master_salt.as_bytes(),
                key_id,
            ),
            Ok(()),
            "the receiver's material, rebuilt from the token, must decode the reader's submessage"
        );
    }
}
