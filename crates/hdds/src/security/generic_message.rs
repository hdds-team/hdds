// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The ParticipantStatelessMessage envelope (DDS Security v1.1 Sec.7.4.3.3,
//! Sec.7.4.3.4): what a DATA of the BuiltinParticipantStatelessMessageWriter
//! carries around a handshake token.
//!
//! ```text
//! struct MessageIdentity { GUID_t source_guid; long long sequence_number; };
//! struct ParticipantGenericMessage {
//!     MessageIdentity message_identity;
//!     MessageIdentity related_message_identity;
//!     GUID_t          destination_participant_guid;
//!     GUID_t          destination_endpoint_guid;
//!     GUID_t          source_endpoint_guid;
//!     string          message_class_id;
//!     DataHolderSeq   message_data;
//! };
//! ```
//!
//! serialized as CDR behind its encapsulation header, as any sample. The
//! message_class_id is "dds.sec.auth_request" for an
//! AuthRequestMessageToken and "dds.sec.auth" for the three handshake
//! messages (Sec.7.4.3.5), and message_data carries the one token.
//!
//! HDDS before 1.5 put the bare token, with no encapsulation header and no
//! envelope, in the DATA: no other implementation could read it (Cyclone DDS
//! refuses it as a sample that does not deserialize), nor could HDDS read
//! theirs.
//!
//! [`encode`] / [`decode`] are the Stateless-channel special case of the
//! struct above: exactly one token, both endpoint GUIDs GUID_UNKNOWN, and
//! the class id inferred from the token's own class id. [`encode_tokens`] /
//! [`decode_tokens`] are the general form the ParticipantVolatileMessageSecure
//! channel needs (Sec.7.4.4.3): a `CryptoTokenSeq` of arbitrary length, real
//! destination/source endpoint GUIDs, and the three
//! GMCLASSID_SECURITY_*_CRYPTO_TOKENS class ids (Sec.7.4.4.5). They do not
//! replace `encode`/`decode`; every existing caller of those keeps calling
//! them unchanged.

use crate::protocol::discovery::spdp::data_holder::{serialize_data_holder, DataHolder};
use crate::security::SecurityError;

/// message_class_id of an AuthRequestMessageToken (Sec.7.4.3.5,
/// GMCLASSID_SECURITY_AUTH_REQUEST).
pub(crate) const CLASS_AUTH_REQUEST: &str = "dds.sec.auth_request";
/// message_class_id of a handshake message (Sec.7.4.3.5,
/// GMCLASSID_SECURITY_AUTH_HANDSHAKE).
pub(crate) const CLASS_AUTH_HANDSHAKE: &str = "dds.sec.auth";

/// The class id of an AuthRequestMessageToken (Table 48).
const AUTH_REQUEST_TOKEN_CLASS: &str = "DDS:Auth:PKI-DH:1.0+AuthReq";

/// CDR_BE and CDR_LE encapsulation identifiers (DDSI-RTPS Sec.10.2).
const CDR_BE: [u8; 2] = [0x00, 0x00];
const CDR_LE: [u8; 2] = [0x00, 0x01];

/// A received ParticipantStatelessMessage, what the handshake reads of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatelessMessage {
    /// message_identity.source_guid: the writer (or participant) that sent it.
    pub source_guid: [u8; 16],
    /// destination_participant_guid: the participant it is for, all zeros
    /// for any.
    pub destination_participant: [u8; 16],
    /// message_class_id.
    pub class_id: String,
    /// message_data[0], the token, serialized as `handshake::parse_token`
    /// reads it.
    pub token: Vec<u8>,
}

/// The ParticipantStatelessMessage carrying `token` (a serialized
/// DataHolder, as `handshake::tokens` encodes it) from the writer
/// `source_writer`, its `sequence_number`, to the participant
/// `destination_participant`, behind a CDR_LE encapsulation header. The
/// class id follows the token's: "dds.sec.auth_request" for an
/// AuthRequestMessageToken, "dds.sec.auth" for any other.
pub(crate) fn encode(
    source_writer: &[u8; 16],
    sequence_number: i64,
    destination_participant: &[u8; 16],
    token: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    let holder = Reader::new(token, false).data_holder()?;
    let class_id = if holder.class_id == AUTH_REQUEST_TOKEN_CLASS {
        CLASS_AUTH_REQUEST
    } else {
        CLASS_AUTH_HANDSHAKE
    };
    let mut out = Vec::with_capacity(4 + 96 + 32 + token.len());
    out.extend_from_slice(&CDR_LE);
    out.extend_from_slice(&[0, 0]);
    // message_identity, then related_message_identity (none).
    out.extend_from_slice(source_writer);
    out.extend_from_slice(&sequence_number.to_le_bytes());
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&0i64.to_le_bytes());
    out.extend_from_slice(destination_participant);
    // destination_endpoint_guid, source_endpoint_guid: unknown.
    out.extend_from_slice(&[0; 32]);
    let len = u32::try_from(class_id.len() + 1)
        .map_err(|_| SecurityError::AuthenticationFailed("class id too long".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(class_id.as_bytes());
    out.push(0);
    pad4(&mut out);
    out.extend_from_slice(&1u32.to_le_bytes());
    // The holder starts 4-aligned, as its own serialization assumes.
    out.extend_from_slice(token);
    Ok(out)
}

/// Read a ParticipantStatelessMessage from the serialized payload of a DATA
/// (its encapsulation header first), little or big endian.
pub(crate) fn decode(payload: &[u8]) -> Result<StatelessMessage, SecurityError> {
    let header = payload
        .get(..4)
        .ok_or_else(|| malformed("no encapsulation header"))?;
    let big_endian = match [header[0], header[1]] {
        CDR_BE => true,
        CDR_LE => false,
        other => {
            return Err(malformed(&format!(
                "encapsulation {:02x?} is neither CDR_BE nor CDR_LE",
                other
            )))
        }
    };
    let mut r = Reader::new(&payload[4..], big_endian);
    let source_guid = r.guid()?;
    let _sequence_number = r.u64()?;
    let _related_guid = r.guid()?;
    let _related_sequence = r.u64()?;
    let destination_participant = r.guid()?;
    let _destination_endpoint = r.guid()?;
    let _source_endpoint = r.guid()?;
    let class_id = r.string()?;
    let count = r.u32()?;
    if count == 0 {
        return Err(malformed("message_data carries no token"));
    }
    let holder = r.data_holder()?;
    let token = serialize_data_holder(
        &holder.class_id,
        &holder.properties,
        &holder.binary_properties,
    )
    .map_err(|e| malformed(&format!("{:?}", e)))?;
    Ok(StatelessMessage {
        source_guid,
        destination_participant,
        class_id,
        token,
    })
}

fn malformed(why: &str) -> SecurityError {
    SecurityError::AuthenticationFailed(format!("malformed ParticipantStatelessMessage: {}", why))
}

/// A decoded `ParticipantGenericMessage` in its general form (Sec.7.4.4.3):
/// every field [`decode`] discards, and any number of tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenericMessage {
    /// message_identity.source_guid.
    pub source_guid: [u8; 16],
    /// message_identity.sequence_number: "shall start with the value set
    /// to one and be incremented for each different message sent by the
    /// BuiltinParticipantVolatileMessageSecureWriter" (Sec.7.4.4.3) --
    /// kept so a caller can refuse a replayed (at-or-below-highest-seen)
    /// envelope; [`decode`] does not expose it (the Stateless channel's
    /// handshake tokens have their own nonce-based replay protection).
    pub sequence_number: i64,
    /// destination_participant_guid.
    pub destination_participant: [u8; 16],
    /// destination_endpoint_guid (GUID_UNKNOWN when the message targets
    /// the whole participant, Sec.7.4.4.6.1).
    pub destination_endpoint: [u8; 16],
    /// source_endpoint_guid (GUID_UNKNOWN for participant-level material,
    /// Sec.7.4.4.6.1).
    pub source_endpoint: [u8; 16],
    /// message_class_id.
    pub class_id: String,
    /// message_data: each entry is one token, serialized as a DataHolder
    /// (as [`decode`]'s single `token` field is).
    pub tokens: Vec<Vec<u8>>,
}

/// General `ParticipantGenericMessage` encode (Sec.7.4.4.3): `tokens` is
/// the `message_data` sequence (a `CryptoTokenSeq` for the
/// GMCLASSID_SECURITY_*_CRYPTO_TOKENS classes, Sec.7.4.4.5), each entry
/// already serialized as a DataHolder (`serialize_data_holder`'s output,
/// which leaves the buffer 4-aligned -- consecutive tokens need no extra
/// padding between them). `related_message_identity` is always
/// `{GUID_UNKNOWN, 0}`: nothing this module builds answers an earlier
/// message.
///
/// [`encode`] is the one-token, GUID_UNKNOWN-endpoints special case of
/// this; it is not rebuilt on top of this function so that its own wire
/// bytes stay the ones its own tests pin, unconditionally.
pub(crate) fn encode_tokens(
    source_writer: &[u8; 16],
    sequence_number: i64,
    destination_participant: &[u8; 16],
    destination_endpoint: &[u8; 16],
    source_endpoint: &[u8; 16],
    class_id: &str,
    tokens: &[Vec<u8>],
) -> Result<Vec<u8>, SecurityError> {
    let mut out = Vec::with_capacity(4 + 96 + 32 + tokens.iter().map(Vec::len).sum::<usize>());
    out.extend_from_slice(&CDR_LE);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(source_writer);
    out.extend_from_slice(&sequence_number.to_le_bytes());
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&0i64.to_le_bytes());
    out.extend_from_slice(destination_participant);
    out.extend_from_slice(destination_endpoint);
    out.extend_from_slice(source_endpoint);
    let len = u32::try_from(class_id.len() + 1)
        .map_err(|_| SecurityError::AuthenticationFailed("class id too long".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(class_id.as_bytes());
    out.push(0);
    pad4(&mut out);
    let count = u32::try_from(tokens.len())
        .map_err(|_| SecurityError::AuthenticationFailed("too many tokens".into()))?;
    out.extend_from_slice(&count.to_le_bytes());
    for token in tokens {
        out.extend_from_slice(token);
    }
    Ok(out)
}

/// General `ParticipantGenericMessage` decode: any number of tokens, the
/// endpoint GUIDs [`decode`] discards. Little or big endian.
pub(crate) fn decode_tokens(payload: &[u8]) -> Result<GenericMessage, SecurityError> {
    let header = payload
        .get(..4)
        .ok_or_else(|| malformed("no encapsulation header"))?;
    let big_endian = match [header[0], header[1]] {
        CDR_BE => true,
        CDR_LE => false,
        other => {
            return Err(malformed(&format!(
                "encapsulation {:02x?} is neither CDR_BE nor CDR_LE",
                other
            )))
        }
    };
    let mut r = Reader::new(&payload[4..], big_endian);
    let source_guid = r.guid()?;
    let sequence_number = r.u64()? as i64;
    let _related_guid = r.guid()?;
    let _related_sequence = r.u64()?;
    let destination_participant = r.guid()?;
    let destination_endpoint = r.guid()?;
    let source_endpoint = r.guid()?;
    let class_id = r.string()?;
    let count = r.u32()?;
    // A hard cap, the same spirit as `data_holder`'s property count cap:
    // a legitimate CryptoTokenSeq carries one or two entries.
    if count > 64 {
        return Err(malformed("message_data carries an implausible token count"));
    }
    let mut tokens = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let holder = r.data_holder()?;
        let token = serialize_data_holder(
            &holder.class_id,
            &holder.properties,
            &holder.binary_properties,
        )
        .map_err(|e| malformed(&format!("{:?}", e)))?;
        tokens.push(token);
    }
    Ok(GenericMessage {
        source_guid,
        sequence_number,
        destination_participant,
        destination_endpoint,
        source_endpoint,
        class_id,
        tokens,
    })
}

fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// A CDR reader over `bytes`, alignment counted from their start (the
/// first octet after the encapsulation header).
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    big_endian: bool,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], big_endian: bool) -> Self {
        Self {
            bytes,
            at: 0,
            big_endian,
        }
    }

    fn take(&mut self, n: usize, align: usize) -> Result<&'a [u8], SecurityError> {
        self.at = self.at.next_multiple_of(align);
        let slice = self
            .at
            .checked_add(n)
            .and_then(|end| self.bytes.get(self.at..end))
            .ok_or_else(|| malformed("truncated"))?;
        self.at += n;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, SecurityError> {
        let b: [u8; 4] = self.take(4, 4)?.try_into().map_err(|_| malformed("u32"))?;
        Ok(if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    fn u64(&mut self) -> Result<u64, SecurityError> {
        let b: [u8; 8] = self.take(8, 8)?.try_into().map_err(|_| malformed("u64"))?;
        Ok(if self.big_endian {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    }

    fn guid(&mut self) -> Result<[u8; 16], SecurityError> {
        self.take(16, 1)?.try_into().map_err(|_| malformed("GUID"))
    }

    fn len(&mut self) -> Result<usize, SecurityError> {
        let n = usize::try_from(self.u32()?).map_err(|_| malformed("length"))?;
        // Nothing here is longer than what is left: a length that says
        // otherwise is refused before anything is allocated for it.
        if n > self.bytes.len().saturating_sub(self.at) {
            return Err(malformed("a length runs past the end"));
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, SecurityError> {
        let n = self.len()?;
        let raw = self.take(n, 1)?;
        let text = raw
            .strip_suffix(&[0])
            .ok_or_else(|| malformed("a string without its NUL"))?;
        String::from_utf8(text.to_vec()).map_err(|_| malformed("a string that is not UTF-8"))
    }

    fn octets(&mut self) -> Result<Vec<u8>, SecurityError> {
        let n = self.len()?;
        Ok(self.take(n, 1)?.to_vec())
    }

    /// A DataHolder (Sec.7.2.4): class_id, properties (name, value),
    /// binary properties (name, octets); `propagate` is not serialized.
    fn data_holder(&mut self) -> Result<DataHolder, SecurityError> {
        let class_id = self.string()?;
        let count = self.len()?;
        let mut properties = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            properties.push((self.string()?, self.string()?, true));
        }
        let count = self.len()?;
        let mut binary_properties = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            binary_properties.push((self.string()?, self.octets()?, true));
        }
        Ok(DataHolder {
            class_id,
            properties,
            binary_properties,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::handshake::tokens::{encode_auth_req, AuthReqToken};

    fn writer() -> [u8; 16] {
        let mut g = [0x11; 16];
        g[12..].copy_from_slice(&[0x00, 0x02, 0x01, 0xC3]);
        g
    }

    fn participant() -> [u8; 16] {
        let mut g = [0x22; 16];
        g[12..].copy_from_slice(&[0x00, 0x00, 0x01, 0xC1]);
        g
    }

    fn auth_req() -> Vec<u8> {
        encode_auth_req(&AuthReqToken {
            future_challenge: [0x5C; 32],
        })
        .expect("encode")
    }

    /// The layout of Sec.7.4.3.3, octet by octet, little endian behind
    /// CDR_LE: two message identities (the related one empty), three GUIDs,
    /// the class id, one DataHolder.
    #[test]
    fn the_envelope_is_the_participant_generic_message() {
        let token = auth_req();
        let bytes = encode(&writer(), 7, &participant(), &token).expect("encode");
        assert_eq!(&bytes[..4], &[0x00, 0x01, 0x00, 0x00]);
        let body = &bytes[4..];
        assert_eq!(&body[..16], &writer());
        assert_eq!(&body[16..24], &7i64.to_le_bytes());
        assert_eq!(&body[24..48], &[0; 24]);
        assert_eq!(&body[48..64], &participant());
        assert_eq!(&body[64..96], &[0; 32]);
        assert_eq!(&body[96..100], &21u32.to_le_bytes());
        assert_eq!(&body[100..121], b"dds.sec.auth_request\0");
        assert_eq!(&body[121..124], &[0; 3]);
        assert_eq!(&body[124..128], &1u32.to_le_bytes());
        assert_eq!(&body[128..], &token[..]);

        let back = decode(&bytes).expect("decode");
        assert_eq!(back.source_guid, writer());
        assert_eq!(back.destination_participant, participant());
        assert_eq!(back.class_id, CLASS_AUTH_REQUEST);
        assert_eq!(back.token, token);
    }

    /// A big-endian message (CDR_BE) is read as well, its token handed on
    /// as `parse_token` reads it.
    #[test]
    fn a_big_endian_message_is_read() {
        let mut be = vec![0x00, 0x00, 0x00, 0x00];
        be.extend_from_slice(&writer());
        be.extend_from_slice(&3u64.to_be_bytes());
        be.extend_from_slice(&[0; 24]);
        be.extend_from_slice(&participant());
        be.extend_from_slice(&[0; 32]);
        be.extend_from_slice(&13u32.to_be_bytes());
        be.extend_from_slice(b"dds.sec.auth\0");
        be.extend_from_slice(&[0; 3]);
        be.extend_from_slice(&1u32.to_be_bytes());
        // DataHolder: class id, no property, one binary property.
        let class = b"DDS:Auth:PKI-DH:1.0+AuthReq\0";
        be.extend_from_slice(&(class.len() as u32).to_be_bytes());
        be.extend_from_slice(class);
        while !(be.len() - 4).is_multiple_of(4) {
            be.push(0);
        }
        be.extend_from_slice(&0u32.to_be_bytes());
        be.extend_from_slice(&1u32.to_be_bytes());
        be.extend_from_slice(&17u32.to_be_bytes());
        be.extend_from_slice(b"future_challenge\0");
        while !(be.len() - 4).is_multiple_of(4) {
            be.push(0);
        }
        be.extend_from_slice(&32u32.to_be_bytes());
        be.extend_from_slice(&[0x5C; 32]);
        let back = decode(&be).expect("decode");
        assert_eq!(back.class_id, CLASS_AUTH_HANDSHAKE);
        assert_eq!(back.token, auth_req());
    }

    #[test]
    fn a_malformed_message_is_refused() {
        let good = encode(&writer(), 1, &participant(), &auth_req()).expect("encode");
        for (bytes, what) in [
            (good[..3].to_vec(), "no header"),
            ([&[0x00, 0x02, 0, 0][..], &good[4..]].concat(), "PL_CDR_BE"),
            (good[..good.len() - 1].to_vec(), "truncated token"),
            (good[..128].to_vec(), "no message_data"),
            (
                {
                    let mut b = good.clone();
                    b[128..132].copy_from_slice(&0u32.to_le_bytes());
                    b
                },
                "an empty message_data",
            ),
            (
                {
                    let mut b = good.clone();
                    b[100..104].copy_from_slice(&u32::MAX.to_le_bytes());
                    b
                },
                "a class id longer than the message",
            ),
        ] {
            assert!(decode(&bytes).is_err(), "{}", what);
        }
    }

    fn endpoint() -> [u8; 16] {
        let mut g = [0x33; 16];
        g[12..].copy_from_slice(&[0x00, 0x00, 0x01, 0x02]);
        g
    }

    fn a_token(tag: u8) -> Vec<u8> {
        crate::protocol::discovery::spdp::data_holder::serialize_data_holder(
            "DDS:Crypto:AES_GCM_GMAC",
            &[],
            &[("dds.cryp.keymat".to_string(), vec![tag; 4], true)],
        )
        .expect("encode")
    }

    /// The general form, octet by octet: real destination_endpoint_guid
    /// and source_endpoint_guid (where `encode` always wrote GUID_UNKNOWN),
    /// a message_class_id of the test's choosing, and two tokens back
    /// to back with no padding between them (each DataHolder leaves itself
    /// 4-aligned).
    #[test]
    fn encode_tokens_carries_real_endpoint_guids_and_every_token() {
        let t1 = a_token(0x01);
        let t2 = a_token(0x02);
        let bytes = encode_tokens(
            &writer(),
            9,
            &participant(),
            &endpoint(),
            &writer(),
            "dds.sec.datawriter_crypto_tokens",
            &[t1.clone(), t2.clone()],
        )
        .expect("encode_tokens");

        assert_eq!(&bytes[..4], &[0x00, 0x01, 0x00, 0x00]);
        let body = &bytes[4..];
        assert_eq!(&body[..16], &writer());
        assert_eq!(&body[16..24], &9i64.to_le_bytes());
        assert_eq!(&body[24..48], &[0; 24], "related_message_identity is empty");
        assert_eq!(&body[48..64], &participant());
        assert_eq!(&body[64..80], &endpoint(), "destination_endpoint_guid");
        assert_eq!(&body[80..96], &writer(), "source_endpoint_guid");
        let class = b"dds.sec.datawriter_crypto_tokens\0";
        let class_len = u32::from_le_bytes([body[96], body[97], body[98], body[99]]) as usize;
        assert_eq!(class_len, class.len());
        assert_eq!(&body[100..100 + class.len()], &class[..]);
        let mut at = 100 + class.len();
        while !at.is_multiple_of(4) {
            assert_eq!(body[at], 0);
            at += 1;
        }
        let count = u32::from_le_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]);
        assert_eq!(count, 2);
        at += 4;
        assert_eq!(&body[at..at + t1.len()], &t1[..]);
        at += t1.len();
        assert_eq!(&body[at..at + t2.len()], &t2[..]);
        at += t2.len();
        assert_eq!(bytes.len(), 4 + at);

        let decoded = decode_tokens(&bytes).expect("decode_tokens");
        assert_eq!(decoded.source_guid, writer());
        assert_eq!(decoded.sequence_number, 9);
        assert_eq!(decoded.destination_participant, participant());
        assert_eq!(decoded.destination_endpoint, endpoint());
        assert_eq!(decoded.source_endpoint, writer());
        assert_eq!(decoded.class_id, "dds.sec.datawriter_crypto_tokens");
        assert_eq!(decoded.tokens, vec![t1, t2]);
    }

    /// Zero tokens round-trips too (the general decoder does not enforce
    /// "at least one", unlike `decode`): a caller that cares checks
    /// `tokens.is_empty()` itself.
    #[test]
    fn encode_tokens_with_no_tokens_round_trips() {
        let bytes = encode_tokens(
            &writer(),
            1,
            &participant(),
            &[0; 16],
            &[0; 16],
            "dds.sec.participant_crypto_tokens",
            &[],
        )
        .expect("encode_tokens");
        let decoded = decode_tokens(&bytes).expect("decode_tokens");
        assert!(decoded.tokens.is_empty());
    }

    /// Mutant: a token count that does not match the number of tokens
    /// actually appended must be refused (either a short read sees the
    /// next token's bytes as more of the current one, or there is nothing
    /// left to read).
    #[test]
    fn a_wrong_token_count_is_refused() {
        let t1 = a_token(0x01);
        let mut bytes = encode_tokens(
            &writer(),
            1,
            &participant(),
            &[0; 16],
            &[0; 16],
            "dds.sec.datawriter_crypto_tokens",
            &[t1],
        )
        .expect("encode_tokens");
        // The count field sits right before the first token; overstate it.
        let count_at = bytes.len() - a_token(0x01).len() - 4;
        bytes[count_at..count_at + 4].copy_from_slice(&2u32.to_le_bytes());
        assert!(decode_tokens(&bytes).is_err());
    }

    /// A token count beyond the plausibility cap is refused outright.
    #[test]
    fn an_implausible_token_count_is_refused() {
        let mut bytes = encode_tokens(
            &writer(),
            1,
            &participant(),
            &[0; 16],
            &[0; 16],
            "dds.sec.datawriter_crypto_tokens",
            &[],
        )
        .expect("encode_tokens");
        let count_at = bytes.len() - 4;
        bytes[count_at..count_at + 4].copy_from_slice(&65u32.to_le_bytes());
        assert!(decode_tokens(&bytes).is_err());
    }
}
