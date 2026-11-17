// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PKI-DH handshake token encode/decode.
//!
//! Implements the three ParticipantStatelessMessage token types per
//! DDS Security v1.1 sec. 9.3.2 and sec. 9.3.4:
//!
//! - `AuthRequestToken`  class_id `"DDS:Auth:PKI-DH:1.0+Req"` (Table 49)
//! - `AuthReplyToken`    class_id `"DDS:Auth:PKI-DH:1.0+Reply"` (Table 50)
//! - `AuthFinalToken`    class_id `"DDS:Auth:PKI-DH:1.0+Final"` (Table 51)
//!
//! # Wire Format
//!
//! Each token is serialized as a DataHolder (DDS Security v1.1 sec. 7.2.4) using
//! the same CDR helpers from `protocol::discovery::spdp::data_holder`. String
//! properties use CDR string encoding; binary values (certs, nonces, DH keys,
//! signatures) use CDR octet-sequence encoding.
//!
//! # Binary Property Names (Sec.9.3.2.5)
//!
//! `c.id`          -- the identity certificate
//! `c.perm`        -- the sender's SIGNED permissions document, verbatim;
//!                    sent always, empty without access control (read it
//!                    through `permissions_document`)
//! `c.pdata`       -- the sender's ParticipantBuiltinTopicData
//! `c.dsign_algo`  -- digital signature algorithm identifier
//! `c.kagree_algo` -- key agreement algorithm identifier
//! `hash_c1`       -- SHA-256 of the request's `c.` properties (`hash_c`)
//! `hash_c2`       -- SHA-256 of the reply's `c.` properties (`hash_c`)
//! `challenge1`    -- 32-byte initiator nonce
//! `dh1`           -- initiator's uncompressed DH public key
//! `challenge2`    -- 32-byte responder nonce
//! `dh2`           -- responder's uncompressed DH public key
//! `signature`     -- see below
//!
//! # Signed bytes
//!
//! AuthReply signature (Sec.9.3.2.5.2, Table 50): the CDR Big Endian
//!   BinaryPropertySeq hash_c2, challenge2, dh2, challenge1, dh1, hash_c1
//!   (`reply_sign_input`).
//! AuthFinal signature (Sec.9.3.2.5.3, Table 51): the CDR Big Endian
//!   BinaryPropertySeq hash_c1, challenge1, dh1, challenge2, dh2, hash_c2
//!   (`final_sign_input`).

use crate::protocol::discovery::spdp::data_holder::{parse_data_holder, serialize_data_holder};
use crate::security::SecurityError;

/// AuthRequest token -- initiator sends first (DDS Security v1.1 sec. 9.3.4.2).
#[derive(Debug, Clone)]
pub struct AuthRequestToken {
    /// Responder's DER-encoded X.509 identity certificate.
    pub identity_cert_der: Vec<u8>,
    /// 32-byte initiator challenge nonce.
    pub challenge1: [u8; 32],
    /// Initiator's uncompressed DH public key.
    /// 65 bytes for P-256 (`ECDH+prime256v1-CEUM`), 97 bytes for P-384
    /// (`ECDH+secp384r1-CEUM`).
    pub dh1: Vec<u8>,
    /// The sender's ParticipantBuiltinTopicData (`c.pdata`), as on the wire
    /// (`handshake::pdata`).
    pub pdata: Vec<u8>,
    /// `c.dsign_algo`, e.g. `"ECDSA-SHA256"`, verbatim as on the wire: it is
    /// an input of `hash_c1`, so a terminating NUL a peer sent stays (read
    /// it through `algo_name`).
    pub dsign_algo: String,
    /// `c.kagree_algo`, e.g. `"ECDH+prime256v1-CEUM"`, verbatim as on the
    /// wire (see `dsign_algo`).
    pub kagree_algo: String,
    /// The `c.perm` property as on the wire, an input of `hash_c1`: the
    /// sender's signed permissions document, verbatim.
    ///
    /// Tables 49 and 50 list it unconditionally, and HDDS sends it always,
    /// empty when it runs without access control (as Cyclone DDS does, which
    /// sends a lone NUL). `None`: the peer sent no `c.perm` at all, as Fast
    /// DDS does without access control; accepted, Sec.9.3.3 Table 52 keeps
    /// the property "if present". The document itself, which access control
    /// judges, is `permissions_document`: no document is neither an empty
    /// one nor one granting nothing.
    pub permissions_doc: Option<Vec<u8>>,
}

/// AuthReply token -- responder sends after verifying request (sec. 9.3.4.4).
#[derive(Debug, Clone)]
pub struct AuthReplyToken {
    /// Responder's DER-encoded X.509 identity certificate.
    pub responder_cert_der: Vec<u8>,
    /// The responder's ParticipantBuiltinTopicData (`c.pdata`).
    pub pdata: Vec<u8>,
    /// `c.dsign_algo`, verbatim as on the wire (see
    /// `AuthRequestToken::dsign_algo`).
    pub dsign_algo: String,
    /// `c.kagree_algo`, verbatim as on the wire.
    pub kagree_algo: String,
    /// `hash_c1`: the hash of the request this reply answers, as the
    /// responder computed it. Optional on the wire (Table 50); the initiator
    /// signs and checks its own value, and refuses a reply whose echo
    /// differs from it.
    pub hash_c1: Option<[u8; 32]>,
    /// Echo of initiator's challenge1 nonce (for verification).
    pub challenge1: [u8; 32],
    /// 32-byte responder challenge nonce (challenge2).
    pub challenge2: [u8; 32],
    /// Echo of the initiator's DH public key dh1. Optional on the wire
    /// (Table 50, "Inclusion of the dh1 property is optional"): the
    /// initiator signs and derives over its own dh1, and refuses a reply
    /// whose echo, when present, differs from it.
    /// 65 bytes for P-256, 97 bytes for P-384.
    pub dh1: Option<Vec<u8>>,
    /// Responder's uncompressed DH public key.
    /// 65 bytes for P-256, 97 bytes for P-384.
    pub dh2: Vec<u8>,
    /// The signature of Sec.9.3.2.5.2 (`reply_sign_input`).
    pub signature: Vec<u8>,
    /// The `c.perm` property as on the wire, an input of `hash_c2` (see
    /// `AuthRequestToken::permissions_doc`).
    pub permissions_doc: Option<Vec<u8>>,
}

/// AuthFinal token -- initiator sends to close handshake (sec. 9.3.4.6).
#[derive(Debug, Clone)]
pub struct AuthFinalToken {
    /// `hash_c1` echo, optional on the wire (Table 51): checked when present.
    pub hash_c1: Option<[u8; 32]>,
    /// `hash_c2` echo, optional on the wire (Table 51): checked when present.
    pub hash_c2: Option<[u8; 32]>,
    /// Echo of challenge1 (round-trip for responder verification).
    pub challenge1: [u8; 32],
    /// Echo of challenge2 (round-trip for responder verification).
    pub challenge2: [u8; 32],
    /// Echo of dh1 (initiator DH pub), optional on the wire (Table 51):
    /// checked when present. 65 bytes for P-256, 97 bytes for P-384.
    pub dh1: Option<Vec<u8>>,
    /// Echo of dh2 (responder DH pub), optional on the wire (Table 51):
    /// checked when present. 65 bytes for P-256, 97 bytes for P-384.
    pub dh2: Option<Vec<u8>>,
    /// The signature of Sec.9.3.2.5.3 (`final_sign_input`).
    pub signature: Vec<u8>,
}

/// Authentication request token -- sent by a participant that needs a
/// handshake with a peer but is not the one that begins it (DDS Security
/// v1.1 Sec.9.3.2.4, Table 48; Sec.7.4.3.6.2). The peer that receives it
/// begins the handshake, and the challenge2 of that handshake must equal
/// `future_challenge` (Sec.9.3.2.5.1 / 9.3.2.5.2).
#[derive(Debug, Clone)]
pub struct AuthReqToken {
    /// 32-byte nonce the sender will use as its challenge.
    pub future_challenge: [u8; 32],
}

/// Parsed variant from [`parse_token`].
#[derive(Debug, Clone)]
pub enum TokenKind {
    AuthReq(AuthReqToken),
    Request(AuthRequestToken),
    Reply(AuthReplyToken),
    Final(AuthFinalToken),
}

// ============================================================
//  Class ID constants (DDS Security v1.1 sec. 9.3.2)
// ============================================================

/// DDS Security v1.1 Table 48 (Sec.9.3.2.4), verbatim.
pub(crate) const CLASS_ID_AUTH_REQ: &str = "DDS:Auth:PKI-DH:1.0+AuthReq";
/// DDS Security v1.1 Table 49 (Sec.9.3.2.5.1), verbatim.
pub(crate) const CLASS_ID_REQUEST: &str = "DDS:Auth:PKI-DH:1.0+Req";
/// DDS Security v1.1 Table 50 (Sec.9.3.2.5.2), verbatim.
pub(crate) const CLASS_ID_REPLY: &str = "DDS:Auth:PKI-DH:1.0+Reply";
/// DDS Security v1.1 Table 51 (Sec.9.3.2.5.3), verbatim.
pub(crate) const CLASS_ID_FINAL: &str = "DDS:Auth:PKI-DH:1.0+Final";

/// The class ids HDDS releases before 1.5 put on their handshake messages
/// in place of those of Tables 49 to 51. Those releases also sign another
/// input than Sec.9.3.2.5.2 and Sec.9.3.2.5.3 define, one that leaves the
/// responder's DH public key unsigned, so a message carrying one is refused
/// by name rather than as an unknown class: the peer cannot authenticate
/// with this release, and the log says why.
const PRE_1_5_CLASS_IDS: [&str; 3] = [
    "DDS:Auth:PKI-DH:1.0+AuthRequest",
    "DDS:Auth:PKI-DH:1.0+AuthReply",
    "DDS:Auth:PKI-DH:1.0+AuthFinal",
];

/// What a handshake message from an HDDS release before 1.5 is refused
/// with (`PRE_1_5_CLASS_IDS`).
pub(crate) const PRE_1_5_HANDSHAKE: &str =
    "peer uses the pre-1.5 handshake signature (HDDS before 1.5 signs neither its DH \
     public key nor hash_c1/hash_c2, DDS Security v1.1 Sec.9.3.2.5.2): refused, upgrade \
     the peer";

/// Serialize a handshake token, refusing one whose CDR length words would
/// wrap. Length prefixes in a DataHolder are 32 bits; writing them with
/// `as u32` would truncate silently, and no test builds a two-gigabyte token
/// to notice. The error path is what makes the guarantee checkable rather
/// than assumed.
fn encode_holder(
    class_id: &str,
    properties: &[(String, String, bool)],
    binary: &[(String, Vec<u8>, bool)],
) -> Result<Vec<u8>, SecurityError> {
    serialize_data_holder(class_id, properties, binary).map_err(|e| {
        SecurityError::AuthenticationFailed(format!(
            "handshake token does not fit its CDR length fields: {:?}",
            e
        ))
    })
}

// ============================================================
//  Encode helpers
// ============================================================

/// Encode `AuthReqToken` as a DataHolder CDR byte vector: the class id of
/// Table 48 and one binary property, `future_challenge`.
pub fn encode_auth_req(tok: &AuthReqToken) -> Result<Vec<u8>, SecurityError> {
    encode_holder(
        CLASS_ID_AUTH_REQ,
        &[],
        &[(
            "future_challenge".to_string(),
            tok.future_challenge.to_vec(),
            true,
        )],
    )
}

/// The `c.` properties of a request or reply in the order of Tables 49 and
/// 50, as they go on the wire and into `hash_c`: `c.perm` as it came, absent
/// when it did not.
fn c_properties<'a>(
    cert: &'a [u8],
    perm: Option<&'a [u8]>,
    pdata: &'a [u8],
    dsign_algo: &'a str,
    kagree_algo: &'a str,
) -> Vec<(&'static str, &'a [u8])> {
    let mut props = vec![("c.id", cert)];
    if let Some(perm) = perm {
        props.push(("c.perm", perm));
    }
    props.push(("c.pdata", pdata));
    props.push(("c.dsign_algo", dsign_algo.as_bytes()));
    props.push(("c.kagree_algo", kagree_algo.as_bytes()));
    props
}

fn owned(props: Vec<(&'static str, &[u8])>) -> Vec<(String, Vec<u8>, bool)> {
    props
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_vec(), true))
        .collect()
}

/// The permissions document a `c.perm` value carries: none when the
/// property is absent, empty, or a lone NUL (what Cyclone DDS sends without
/// access control), else the value without the one NUL that terminates the
/// C string Cyclone DDS sends it as.
fn permissions_document(c_perm: Option<&[u8]>) -> Option<Vec<u8>> {
    let raw = c_perm?;
    let document = raw.strip_suffix(&[0]).unwrap_or(raw);
    (!document.is_empty()).then(|| document.to_vec())
}

impl AuthRequestToken {
    /// The sender's permissions document, if its `c.perm` carries one
    /// (`permissions_doc`).
    pub fn permissions_document(&self) -> Option<Vec<u8>> {
        permissions_document(self.permissions_doc.as_deref())
    }

    fn c_properties(&self) -> Vec<(&'static str, &[u8])> {
        c_properties(
            &self.identity_cert_der,
            self.permissions_doc.as_deref(),
            &self.pdata,
            &self.dsign_algo,
            &self.kagree_algo,
        )
    }

    /// `hash_c1` of this request (Table 49).
    pub fn hash_c1(&self) -> Result<[u8; 32], SecurityError> {
        hash_c(&self.c_properties())
    }
}

impl AuthReplyToken {
    /// The responder's permissions document, if its `c.perm` carries one.
    pub fn permissions_document(&self) -> Option<Vec<u8>> {
        permissions_document(self.permissions_doc.as_deref())
    }

    fn c_properties(&self) -> Vec<(&'static str, &[u8])> {
        c_properties(
            &self.responder_cert_der,
            self.permissions_doc.as_deref(),
            &self.pdata,
            &self.dsign_algo,
            &self.kagree_algo,
        )
    }

    /// `hash_c2` of this reply (Table 50).
    pub fn hash_c2(&self) -> Result<[u8; 32], SecurityError> {
        hash_c(&self.c_properties())
    }
}

/// An algorithm identifier read from `c.dsign_algo` or `c.kagree_algo`:
/// a peer may send it NUL-terminated (Cyclone DDS does, Fast DDS does not),
/// and one terminating NUL is no part of the name.
pub fn algo_name(raw: &str) -> &str {
    raw.strip_suffix('\0').unwrap_or(raw)
}

/// Encode `AuthRequestToken` as a DataHolder CDR byte vector, its binary
/// properties in the order of Table 49.
pub fn encode_request(tok: &AuthRequestToken) -> Result<Vec<u8>, SecurityError> {
    let mut binary = owned(tok.c_properties());
    binary.push(("hash_c1".to_string(), tok.hash_c1()?.to_vec(), true));
    binary.push(("dh1".to_string(), tok.dh1.to_vec(), true));
    binary.push(("challenge1".to_string(), tok.challenge1.to_vec(), true));
    encode_holder(CLASS_ID_REQUEST, &[], &binary)
}

/// Encode `AuthReplyToken` as a DataHolder CDR byte vector, its binary
/// properties in the order of Table 50.
pub fn encode_reply(tok: &AuthReplyToken) -> Result<Vec<u8>, SecurityError> {
    let mut binary = owned(tok.c_properties());
    binary.push(("hash_c2".to_string(), tok.hash_c2()?.to_vec(), true));
    binary.push(("dh2".to_string(), tok.dh2.to_vec(), true));
    if let Some(hash_c1) = tok.hash_c1 {
        binary.push(("hash_c1".to_string(), hash_c1.to_vec(), true));
    }
    if let Some(dh1) = &tok.dh1 {
        binary.push(("dh1".to_string(), dh1.clone(), true));
    }
    binary.push(("challenge1".to_string(), tok.challenge1.to_vec(), true));
    binary.push(("challenge2".to_string(), tok.challenge2.to_vec(), true));
    binary.push(("signature".to_string(), tok.signature.clone(), true));
    encode_holder(CLASS_ID_REPLY, &[], &binary)
}

/// Encode `AuthFinalToken` as a DataHolder CDR byte vector, its binary
/// properties in the order of Table 51.
pub fn encode_final(tok: &AuthFinalToken) -> Result<Vec<u8>, SecurityError> {
    let mut binary = Vec::new();
    if let Some(hash_c1) = tok.hash_c1 {
        binary.push(("hash_c1".to_string(), hash_c1.to_vec(), true));
    }
    if let Some(hash_c2) = tok.hash_c2 {
        binary.push(("hash_c2".to_string(), hash_c2.to_vec(), true));
    }
    if let Some(dh1) = &tok.dh1 {
        binary.push(("dh1".to_string(), dh1.clone(), true));
    }
    if let Some(dh2) = &tok.dh2 {
        binary.push(("dh2".to_string(), dh2.clone(), true));
    }
    binary.push(("challenge1".to_string(), tok.challenge1.to_vec(), true));
    binary.push(("challenge2".to_string(), tok.challenge2.to_vec(), true));
    binary.push(("signature".to_string(), tok.signature.clone(), true));
    encode_holder(CLASS_ID_FINAL, &[], &binary)
}

// ============================================================
//  Decode
// ============================================================

/// Parse a DataHolder CDR blob into a `TokenKind`.
///
/// Returns `Err(SecurityError::AuthenticationFailed)` for any
/// truncation, missing required field, wrong length, or unknown class_id.
pub fn parse_token(bytes: &[u8]) -> Result<TokenKind, SecurityError> {
    let holder = parse_data_holder(bytes).ok_or_else(|| {
        SecurityError::AuthenticationFailed("malformed DataHolder CDR in stateless token".into())
    })?;

    match holder.class_id.as_str() {
        CLASS_ID_AUTH_REQ => Ok(TokenKind::AuthReq(AuthReqToken {
            future_challenge: fixed_bytes(
                "future_challenge",
                get_bin(&holder, "future_challenge")?,
            )?,
        })),
        CLASS_ID_REQUEST => parse_request(&holder).map(TokenKind::Request),
        CLASS_ID_REPLY => parse_reply(&holder).map(TokenKind::Reply),
        CLASS_ID_FINAL => parse_final(&holder).map(TokenKind::Final),
        other if PRE_1_5_CLASS_IDS.contains(&other) => Err(SecurityError::AuthenticationFailed(
            format!("{} (class_id {:?})", PRE_1_5_HANDSHAKE, other),
        )),
        other => Err(SecurityError::AuthenticationFailed(format!(
            "unknown handshake class_id {:?}",
            other
        ))),
    }
}

// ============================================================
//  Private parse helpers
// ============================================================

/// Look up a binary property by name.
/// Read a binary property that MAY be absent.
///
/// Distinct from `get_bin` on purpose: a missing optional property is a fact
/// about the peer, not a parse failure, and the two must not collapse into one
/// another. `get_bin` refusing the token is right for `c.id`; it would be
/// wrong for `c.perm`, which some peers never send.
fn get_bin_optional<'a>(
    holder: &'a crate::protocol::discovery::spdp::data_holder::DataHolder,
    name: &str,
) -> Option<&'a [u8]> {
    holder
        .binary_properties
        .iter()
        .find(|(n, _, _)| n == name)
        .map(|(_, v, _)| v.as_slice())
}

fn get_bin<'a>(
    holder: &'a crate::protocol::discovery::spdp::data_holder::DataHolder,
    name: &str,
) -> Result<&'a [u8], SecurityError> {
    holder
        .binary_properties
        .iter()
        .find(|(n, _, _)| n == name)
        .map(|(_, v, _)| v.as_slice())
        .ok_or_else(|| {
            SecurityError::AuthenticationFailed(format!(
                "missing binary property {:?} in token",
                name
            ))
        })
}

/// Read a binary property carrying text (`c.dsign_algo`, `c.kagree_algo`),
/// verbatim: it is an input of `hash_c`.
fn get_text(
    holder: &crate::protocol::discovery::spdp::data_holder::DataHolder,
    name: &str,
) -> Result<String, SecurityError> {
    String::from_utf8(get_bin(holder, name)?.to_vec()).map_err(|_| {
        SecurityError::AuthenticationFailed(format!("binary property {:?} is not text", name))
    })
}

/// Read an optional hash property (`hash_c1`, `hash_c2`): absent is a fact,
/// any length but 32 a malformed token.
fn get_hash(
    holder: &crate::protocol::discovery::spdp::data_holder::DataHolder,
    name: &str,
) -> Result<Option<[u8; 32]>, SecurityError> {
    get_bin_optional(holder, name)
        .map(|raw| fixed_bytes(name, raw))
        .transpose()
}

/// Refuse a token whose `hash_c1`/`hash_c2` is present and is not the hash
/// of its own `c.` properties: Tables 49 and 50 define the value, so one
/// that differs is a malformed token (a peer serializing its properties
/// otherwise than we read them), never one to sign over.
fn check_own_hash(
    name: &str,
    sent: Option<[u8; 32]>,
    computed: [u8; 32],
) -> Result<(), SecurityError> {
    match sent {
        Some(sent) if sent != computed => Err(SecurityError::AuthenticationFailed(format!(
            "{} is not the hash of the token's c. properties",
            name
        ))),
        _ => Ok(()),
    }
}

/// Extract a fixed-size array from a slice, returning an error if length mismatches.
fn fixed_bytes<const N: usize>(name: &str, raw: &[u8]) -> Result<[u8; N], SecurityError> {
    raw.try_into().map_err(|_| {
        SecurityError::AuthenticationFailed(format!(
            "field {:?}: expected {} bytes, got {}",
            name,
            N,
            raw.len()
        ))
    })
}

/// Validate and copy a DH public key from the wire.
///
/// Accepts uncompressed P-256 (65 bytes) and P-384 (97 bytes) points.
/// Rejects any other length with an informative error.
fn parse_dh_key(name: &str, raw: &[u8]) -> Result<Vec<u8>, SecurityError> {
    const P256_LEN: usize = 65;
    const P384_LEN: usize = 97;
    if raw.len() != P256_LEN && raw.len() != P384_LEN {
        return Err(SecurityError::AuthenticationFailed(format!(
            "field {:?}: expected {} (P-256) or {} (P-384) bytes, got {}",
            name,
            P256_LEN,
            P384_LEN,
            raw.len()
        )));
    }
    Ok(raw.to_vec())
}

/// Read an optional DH public key echo (the reply's dh1, the final's dh1 and
/// dh2): absent is the peer's right, a present one is checked as any key.
fn get_dh_key_optional(
    holder: &crate::protocol::discovery::spdp::data_holder::DataHolder,
    name: &str,
) -> Result<Option<Vec<u8>>, SecurityError> {
    get_bin_optional(holder, name)
        .map(|raw| parse_dh_key(name, raw))
        .transpose()
}

fn parse_request(
    holder: &crate::protocol::discovery::spdp::data_holder::DataHolder,
) -> Result<AuthRequestToken, SecurityError> {
    let cert_der = get_bin(holder, "c.id")?.to_vec();
    let challenge1_raw = get_bin(holder, "challenge1")?;
    let dh1_raw = get_bin(holder, "dh1")?;
    let pdata = get_bin(holder, "c.pdata")?.to_vec();

    let token = AuthRequestToken {
        identity_cert_der: cert_der,
        challenge1: fixed_bytes("challenge1", challenge1_raw)?,
        dh1: parse_dh_key("dh1", dh1_raw)?,
        pdata,
        dsign_algo: get_text(holder, "c.dsign_algo")?,
        kagree_algo: get_text(holder, "c.kagree_algo")?,
        permissions_doc: get_bin_optional(holder, "c.perm").map(<[u8]>::to_vec),
    };
    check_own_hash("hash_c1", get_hash(holder, "hash_c1")?, token.hash_c1()?)?;
    Ok(token)
}

fn parse_reply(
    holder: &crate::protocol::discovery::spdp::data_holder::DataHolder,
) -> Result<AuthReplyToken, SecurityError> {
    let cert_der = get_bin(holder, "c.id")?.to_vec();
    let challenge1_raw = get_bin(holder, "challenge1")?;
    let challenge2_raw = get_bin(holder, "challenge2")?;
    let dh2_raw = get_bin(holder, "dh2")?;
    let signature = get_bin(holder, "signature")?.to_vec();

    let token = AuthReplyToken {
        responder_cert_der: cert_der,
        pdata: get_bin(holder, "c.pdata")?.to_vec(),
        dsign_algo: get_text(holder, "c.dsign_algo")?,
        kagree_algo: get_text(holder, "c.kagree_algo")?,
        hash_c1: get_hash(holder, "hash_c1")?,
        challenge1: fixed_bytes("challenge1", challenge1_raw)?,
        dh1: get_dh_key_optional(holder, "dh1")?,
        challenge2: fixed_bytes("challenge2", challenge2_raw)?,
        dh2: parse_dh_key("dh2", dh2_raw)?,
        signature,
        permissions_doc: get_bin_optional(holder, "c.perm").map(<[u8]>::to_vec),
    };
    check_own_hash("hash_c2", get_hash(holder, "hash_c2")?, token.hash_c2()?)?;
    Ok(token)
}

fn parse_final(
    holder: &crate::protocol::discovery::spdp::data_holder::DataHolder,
) -> Result<AuthFinalToken, SecurityError> {
    let challenge1_raw = get_bin(holder, "challenge1")?;
    let challenge2_raw = get_bin(holder, "challenge2")?;
    let signature = get_bin(holder, "signature")?.to_vec();

    Ok(AuthFinalToken {
        hash_c1: get_hash(holder, "hash_c1")?,
        hash_c2: get_hash(holder, "hash_c2")?,
        challenge1: fixed_bytes("challenge1", challenge1_raw)?,
        dh1: get_dh_key_optional(holder, "dh1")?,
        dh2: get_dh_key_optional(holder, "dh2")?,
        challenge2: fixed_bytes("challenge2", challenge2_raw)?,
        signature,
    })
}

// ============================================================
//  hash_c and the signed BinaryPropertySeq (Sec.9.3.2.5)
// ============================================================

/// The CDR Big Endian serialization of a BinaryPropertySeq holding
/// `props`, in that order: what `hash_c1`/`hash_c2` hash and what the
/// signatures of Sec.9.3.2.5.2 and Sec.9.3.2.5.3 sign.
///
/// A BinaryProperty_t serializes its `name` (a CDR string: length counting
/// the terminating NUL, the bytes, the NUL) and its `value` (an octet
/// sequence); its `propagate` member is not serialized (Sec.7.2.2). Each
/// length is a 4-byte aligned unsigned long, the alignment counted from the
/// start of the sequence; nothing pads the end. Cyclone DDS
/// (`DDS_Security_Serialize_BinaryPropertyArray`) and Fast DDS
/// (`CDRMessage::addBinaryProperty`, its last one without final padding)
/// produce these bytes, and `tests` pins them against Cyclone's.
pub fn binary_property_seq_be(props: &[(&str, &[u8])]) -> Result<Vec<u8>, SecurityError> {
    fn put_len(out: &mut Vec<u8>, len: usize) -> Result<(), SecurityError> {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        let len = u32::try_from(len).map_err(|_| {
            SecurityError::AuthenticationFailed(
                "handshake property does not fit a CDR length".into(),
            )
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        Ok(())
    }
    let mut out = Vec::new();
    put_len(&mut out, props.len())?;
    for (name, value) in props {
        put_len(&mut out, name.len() + 1)?;
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        put_len(&mut out, value.len())?;
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// `hash_c1` / `hash_c2` (Tables 49 and 50): "SHA-256 hash of the CDR Big
/// Endian serialization of a BinaryPropertySeq object containing all the
/// properties above that start with "c." placed in the same order as they
/// appear above" - the `c.` properties the token carries, `c_properties`.
fn hash_c(c_props: &[(&str, &[u8])]) -> Result<[u8; 32], SecurityError> {
    let digest = ring::digest::digest(&ring::digest::SHA256, &binary_property_seq_be(c_props)?);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    Ok(hash)
}

// ============================================================
//  Signature input construction helpers (public for machine.rs)
// ============================================================

/// The bytes the AuthReply signature signs, DDS Security v1.1
/// Sec.9.3.2.5.2, Table 50: "the CDR Big Endian serialization of a
/// BinaryPropertySeq object containing the properties: hash_c2,
/// challenge2, dh2, challenge1, dh1, and hash_c1, placed in that order",
/// every one of them "even if some of the optional properties do not
/// appear separately". The arguments are in that order.
///
/// The signer hashes them (ECDSA-SHA256). HDDS before 1.5 signed
/// `c.id || challenge1 || dh1 || challenge2` instead: dh2 unsigned, so an
/// on-path attacker could replace it with a key of its own.
pub fn reply_sign_input(
    hash_c2: &[u8; 32],
    challenge2: &[u8; 32],
    dh2: &[u8],
    challenge1: &[u8; 32],
    dh1: &[u8],
    hash_c1: &[u8; 32],
) -> Result<Vec<u8>, SecurityError> {
    binary_property_seq_be(&[
        ("hash_c2", hash_c2),
        ("challenge2", challenge2),
        ("dh2", dh2),
        ("challenge1", challenge1),
        ("dh1", dh1),
        ("hash_c1", hash_c1),
    ])
}

/// The bytes the AuthFinal signature signs, DDS Security v1.1
/// Sec.9.3.2.5.3, Table 51: "the CDR Big Endian serialization of a
/// BinaryPropertySeq object containing the properties: hash_c1,
/// challenge1, dh1, challenge2, dh2, and hash_c2, placed in that order",
/// every one of them whether or not it appears in the message. The
/// arguments are in that order.
///
/// HDDS before 1.5 signed `challenge1 || dh1 || dh2 || challenge2`: no
/// hash, so neither side's `c.` properties (its permissions document, its
/// participant data) were vouched for by its key.
pub fn final_sign_input(
    hash_c1: &[u8; 32],
    challenge1: &[u8; 32],
    dh1: &[u8],
    challenge2: &[u8; 32],
    dh2: &[u8],
    hash_c2: &[u8; 32],
) -> Result<Vec<u8>, SecurityError> {
    binary_property_seq_be(&[
        ("hash_c1", hash_c1),
        ("challenge1", challenge1),
        ("dh1", dh1),
        ("challenge2", challenge2),
        ("dh2", dh2),
        ("hash_c2", hash_c2),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_request() -> AuthRequestToken {
        AuthRequestToken {
            identity_cert_der: vec![0x30, 0x82, 0x01],
            challenge1: [0xAA; 32],
            dh1: vec![0x04; 65], // P-256 uncompressed public key
            pdata: vec![1, 2, 3],
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            permissions_doc: None,
        }
    }

    fn dummy_reply() -> AuthReplyToken {
        AuthReplyToken {
            responder_cert_der: vec![0x30, 0x82, 0x02],
            pdata: Vec::new(),
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            hash_c1: None,
            challenge1: [0xAA; 32],
            dh1: Some(vec![0x04; 65]),
            challenge2: [0xBB; 32],
            dh2: vec![0x05; 65],
            signature: vec![0xCC; 64],
            permissions_doc: None,
        }
    }

    fn dummy_final() -> AuthFinalToken {
        AuthFinalToken {
            hash_c1: None,
            hash_c2: None,
            challenge1: [0xAA; 32],
            dh1: Some(vec![0x04; 65]),
            dh2: Some(vec![0x05; 65]),
            challenge2: [0xBB; 32],
            signature: vec![0xDD; 64],
        }
    }

    #[test]
    fn an_authentication_request_round_trips_under_the_class_id_of_table_48() {
        let token = AuthReqToken {
            future_challenge: [0x5C; 32],
        };
        let bytes = encode_auth_req(&token).expect("encode");
        let holder = parse_data_holder(&bytes).expect("a DataHolder");
        assert_eq!(holder.class_id, "DDS:Auth:PKI-DH:1.0+AuthReq");
        match parse_token(&bytes).expect("parse") {
            TokenKind::AuthReq(back) => assert_eq!(back.future_challenge, [0x5C; 32]),
            other => panic!("expected AuthReq, got {:?}", other),
        }
    }

    #[test]
    fn encode_decode_request_round_trip() {
        let tok = dummy_request();
        let bytes = encode_request(&tok).expect("encode");
        let parsed = parse_token(&bytes).expect("parse_token failed");
        match parsed {
            TokenKind::Request(r) => {
                assert_eq!(r.identity_cert_der, tok.identity_cert_der);
                assert_eq!(r.challenge1, tok.challenge1);
                assert_eq!(r.dh1, tok.dh1);
                assert_eq!(r.pdata, tok.pdata);
                assert_eq!(r.dsign_algo, tok.dsign_algo);
                assert_eq!(r.kagree_algo, tok.kagree_algo);
            }
            _ => panic!("expected Request variant"),
        }
    }

    #[test]
    fn encode_decode_reply_round_trip() {
        let tok = dummy_reply();
        let bytes = encode_reply(&tok).expect("encode");
        let parsed = parse_token(&bytes).expect("parse_token failed");
        match parsed {
            TokenKind::Reply(r) => {
                assert_eq!(r.responder_cert_der, tok.responder_cert_der);
                assert_eq!(r.challenge1, tok.challenge1);
                assert_eq!(r.dh1, tok.dh1);
                assert_eq!(r.challenge2, tok.challenge2);
                assert_eq!(r.dh2, tok.dh2);
                assert_eq!(r.signature, tok.signature);
            }
            _ => panic!("expected Reply variant"),
        }
    }

    #[test]
    fn encode_decode_final_round_trip() {
        let tok = dummy_final();
        let bytes = encode_final(&tok).expect("encode");
        let parsed = parse_token(&bytes).expect("parse_token failed");
        match parsed {
            TokenKind::Final(f) => {
                assert_eq!(f.challenge1, tok.challenge1);
                assert_eq!(f.challenge2, tok.challenge2);
                assert_eq!(f.dh1, tok.dh1);
                assert_eq!(f.dh2, tok.dh2);
                assert_eq!(f.signature, tok.signature);
            }
            _ => panic!("expected Final variant"),
        }
    }

    /// Tables 49 to 51 name the three handshake messages "+Req", "+Reply"
    /// and "+Final". Pinned on the bytes, not on the constants: a test that
    /// compared against `CLASS_ID_REQUEST` would pass whatever it says.
    #[test]
    fn the_handshake_messages_carry_the_class_ids_of_tables_49_to_51() {
        let class_of = |bytes: Vec<u8>| parse_data_holder(&bytes).expect("a DataHolder").class_id;
        assert_eq!(
            class_of(encode_request(&dummy_request()).expect("encode")),
            "DDS:Auth:PKI-DH:1.0+Req"
        );
        assert_eq!(
            class_of(encode_reply(&dummy_reply()).expect("encode")),
            "DDS:Auth:PKI-DH:1.0+Reply"
        );
        assert_eq!(
            class_of(encode_final(&dummy_final()).expect("encode")),
            "DDS:Auth:PKI-DH:1.0+Final"
        );
    }

    /// A message under a class id of HDDS before 1.5 is refused by name.
    #[test]
    fn a_pre_1_5_handshake_message_is_refused_by_name() {
        for class_id in PRE_1_5_CLASS_IDS {
            let bytes = serialize_data_holder(class_id, &[], &[]).expect("encode");
            let err = parse_token(&bytes).expect_err("a pre-1.5 message is refused");
            assert!(
                err.to_string().contains("pre-1.5 handshake signature"),
                "{}: {}",
                class_id,
                err
            );
        }
        let bytes = serialize_data_holder("DDS:Unknown:1.0", &[], &[]).expect("encode");
        let err = parse_token(&bytes).expect_err("unknown class");
        assert!(!err.to_string().contains("pre-1.5"), "{}", err);
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// The `c.` properties of the foreign vector: odd lengths on every
    /// value, an empty one, an algorithm without NUL (as Fast DDS sends it)
    /// and one with (as Cyclone DDS does).
    fn foreign_vector_request() -> AuthRequestToken {
        AuthRequestToken {
            identity_cert_der: vec![1, 2, 3, 4, 5],
            challenge1: [0xAA; 32],
            dh1: vec![0x04; 65],
            pdata: Vec::new(),
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM\0".to_string(),
            permissions_doc: Some(vec![0x50, 0x51, 0x52]),
        }
    }

    /// hash_c1 against Cyclone DDS 0.11.0: the same five properties
    /// serialized by `DDS_Security_Serialize_BinaryPropertyArray` of
    /// /opt/cyclonedds/lib/libddsc.so and hashed with OpenSSL's SHA256 give
    /// 145 bytes hashing to the digest below. A vector from our own encoder
    /// would only ratify our own layout.
    #[test]
    fn hash_c1_is_the_hash_cyclone_dds_computes() {
        let token = foreign_vector_request();
        let seq = binary_property_seq_be(&token.c_properties()).expect("serialize");
        assert_eq!(seq.len(), 145);
        let expected = "d4e1d7b479f156a8c03853e279b82fd73d2ff13570bf2c12e6866feac5b8fdf8";
        assert_eq!(sha256_hex(&seq), expected);
        let hash: String = token
            .hash_c1()
            .expect("hash")
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(hash, expected);
    }

    /// The c. properties go on the wire under the names of Table 49, and
    /// the receiver hashes them as they came, terminating NUL included.
    #[test]
    fn a_request_hashes_its_c_properties_as_they_came() {
        let token = foreign_vector_request();
        let bytes = encode_request(&token).expect("encode");
        let holder = parse_data_holder(&bytes).expect("a DataHolder");
        let names: Vec<&str> = holder
            .binary_properties
            .iter()
            .map(|(n, _, _)| n.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "c.id",
                "c.perm",
                "c.pdata",
                "c.dsign_algo",
                "c.kagree_algo",
                "hash_c1",
                "dh1",
                "challenge1"
            ]
        );
        assert!(
            holder.properties.is_empty(),
            "Table 49 has no string property"
        );
        match parse_token(&bytes).expect("parse") {
            TokenKind::Request(back) => {
                assert_eq!(back.kagree_algo, "ECDH+prime256v1-CEUM\0");
                assert_eq!(algo_name(&back.kagree_algo), "ECDH+prime256v1-CEUM");
                assert_eq!(
                    back.hash_c1().expect("hash"),
                    token.hash_c1().expect("hash")
                );
            }
            other => panic!("expected a Request, got {:?}", other),
        }
    }

    /// A hash_c1 or hash_c2 that is not the hash of the token's own c.
    /// properties is a malformed token; an absent one is the peer's right
    /// (Tables 49 and 50: optional).
    #[test]
    fn a_token_whose_hash_is_not_its_own_is_refused() {
        let swap = |bytes: &[u8], name: &str, value: Option<Vec<u8>>| {
            let mut holder = parse_data_holder(bytes).expect("a DataHolder");
            holder.binary_properties.retain(|(n, _, _)| n != name);
            if let Some(value) = value {
                holder
                    .binary_properties
                    .push((name.to_string(), value, true));
            }
            serialize_data_holder(&holder.class_id, &[], &holder.binary_properties).expect("encode")
        };
        let request = encode_request(&foreign_vector_request()).expect("encode");
        let err = parse_token(&swap(&request, "hash_c1", Some(vec![0; 32])))
            .expect_err("a wrong hash_c1");
        assert!(err.to_string().contains("hash_c1"), "{}", err);
        assert!(parse_token(&swap(&request, "hash_c1", None)).is_ok());

        let reply = encode_reply(&dummy_reply()).expect("encode");
        let err =
            parse_token(&swap(&reply, "hash_c2", Some(vec![0; 32]))).expect_err("a wrong hash_c2");
        assert!(err.to_string().contains("hash_c2"), "{}", err);
        assert!(parse_token(&swap(&reply, "hash_c2", None)).is_ok());
    }

    /// `c.perm` as a document: an empty value or a lone NUL (Cyclone DDS
    /// sends "" as a C string when it runs without access control) is no
    /// document, and the NUL that terminates the document Cyclone DDS sends
    /// is no part of it; the raw value stays what `hash_c1` hashes.
    #[test]
    fn an_empty_c_perm_is_no_permissions_document() {
        let with = |perm: Option<&[u8]>| AuthRequestToken {
            permissions_doc: perm.map(<[u8]>::to_vec),
            ..foreign_vector_request()
        };
        assert_eq!(with(None).permissions_document(), None);
        assert_eq!(with(Some(b"")).permissions_document(), None);
        assert_eq!(with(Some(b"\0")).permissions_document(), None);
        assert_eq!(
            with(Some(b"MIME\0")).permissions_document().as_deref(),
            Some(&b"MIME"[..])
        );
        assert_ne!(
            with(Some(b"")).hash_c1().expect("hash"),
            with(None).hash_c1().expect("hash"),
            "an empty c.perm is hashed as sent"
        );
        let reply = AuthReplyToken {
            permissions_doc: Some(b"\0".to_vec()),
            ..dummy_reply()
        };
        assert_eq!(reply.permissions_document(), None);
    }

    #[test]
    fn parse_token_rejects_truncated_bytes() {
        assert!(parse_token(&[]).is_err());
        assert!(parse_token(&[0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn parse_token_rejects_unknown_class_id() {
        let bytes = serialize_data_holder("DDS:Unknown:1.0", &[], &[]).expect("encode");
        assert!(parse_token(&bytes).is_err());
    }

    #[test]
    fn parse_request_missing_field_returns_err() {
        // Encode a request without the challenge1 field.
        let bytes = serialize_data_holder(
            CLASS_ID_REQUEST,
            &[],
            &[
                ("c.dsign_algo".to_string(), b"ECDSA-SHA256".to_vec(), true),
                (
                    "c.kagree_algo".to_string(),
                    b"ECDH+prime256v1-CEUM".to_vec(),
                    true,
                ),
                ("c.id".to_string(), vec![0x30], true),
                // challenge1 intentionally omitted
                ("dh1".to_string(), vec![0x04; 65], true),
                ("c.pdata".to_string(), vec![1, 2], true),
            ],
        )
        .expect("encode");
        assert!(parse_token(&bytes).is_err());
    }

    /// The six values of the foreign signature vectors: hash_c1 = 0x11..,
    /// hash_c2 = 0x22.., challenge1 = 0xAA.., challenge2 = 0xBB.., dh1 =
    /// 64 x 0x04 then 0x41, dh2 = 64 x 0x05 then 0x42.
    struct SignVector {
        hash_c1: [u8; 32],
        hash_c2: [u8; 32],
        challenge1: [u8; 32],
        challenge2: [u8; 32],
        dh1: Vec<u8>,
        dh2: Vec<u8>,
    }

    fn sign_vector() -> SignVector {
        let mut dh1 = vec![0x04; 65];
        dh1[64] = 0x41;
        let mut dh2 = vec![0x05; 65];
        dh2[64] = 0x42;
        SignVector {
            hash_c1: [0x11; 32],
            hash_c2: [0x22; 32],
            challenge1: [0xAA; 32],
            challenge2: [0xBB; 32],
            dh1,
            dh2,
        }
    }

    /// The reply's signed bytes against Cyclone DDS 0.11.0: the six
    /// properties hash_c2, challenge2, dh2, challenge1, dh1, hash_c1,
    /// serialized by `DDS_Security_Serialize_BinaryPropertyArray` (what its
    /// `create_signature` and `validate_signature` sign and verify), are
    /// 364 bytes hashing to the digest below.
    #[test]
    fn the_reply_signs_the_bytes_cyclone_dds_signs() {
        let v = sign_vector();
        let input = reply_sign_input(
            &v.hash_c2,
            &v.challenge2,
            &v.dh2,
            &v.challenge1,
            &v.dh1,
            &v.hash_c1,
        )
        .expect("serialize");
        assert_eq!(input.len(), 364);
        assert_eq!(
            sha256_hex(&input),
            "f422782c3297bd381f6fa6c5d46cbf3d71cda431c3761628e9fea2039e6b0701"
        );
    }

    /// The final's signed bytes against Cyclone DDS 0.11.0, as for the
    /// reply: hash_c1, challenge1, dh1, challenge2, dh2, hash_c2 serialized
    /// by its `DDS_Security_Serialize_BinaryPropertyArray`.
    #[test]
    fn the_final_signs_the_bytes_cyclone_dds_signs() {
        let v = sign_vector();
        let input = final_sign_input(
            &v.hash_c1,
            &v.challenge1,
            &v.dh1,
            &v.challenge2,
            &v.dh2,
            &v.hash_c2,
        )
        .expect("serialize");
        assert_eq!(input.len(), 364);
        assert_eq!(
            sha256_hex(&input),
            "1b645466bd28a51674a03ba7d430c5bca1e2704cc02bd0ca0aa36c65970586d0"
        );
    }

    #[test]
    fn parse_request_dh_wrong_length_returns_err() {
        // dh1 with 32 bytes: not a valid P-256 (65) or P-384 (97) key.
        let bytes = serialize_data_holder(
            CLASS_ID_REQUEST,
            &[],
            &[
                ("c.dsign_algo".to_string(), b"ECDSA-SHA256".to_vec(), true),
                (
                    "c.kagree_algo".to_string(),
                    b"ECDH+prime256v1-CEUM".to_vec(),
                    true,
                ),
                ("c.id".to_string(), vec![0x30], true),
                ("challenge1".to_string(), vec![0; 32], true),
                ("dh1".to_string(), vec![0x04; 32], true), // wrong: neither 65 nor 97
                ("c.pdata".to_string(), vec![1], true),
            ],
        )
        .expect("encode");
        assert!(parse_token(&bytes).is_err());
    }

    #[test]
    fn parse_request_dh_p384_length_accepted() {
        // dh1 with 97 bytes: valid P-384 key size.
        let bytes = serialize_data_holder(
            CLASS_ID_REQUEST,
            &[],
            &[
                ("c.dsign_algo".to_string(), b"ECDSA-SHA256".to_vec(), true),
                (
                    "c.kagree_algo".to_string(),
                    b"ECDH+secp384r1-CEUM".to_vec(),
                    true,
                ),
                ("c.id".to_string(), vec![0x30], true),
                ("challenge1".to_string(), vec![0; 32], true),
                ("dh1".to_string(), vec![0x04; 97], true), // valid P-384 size
                ("c.pdata".to_string(), vec![1], true),
            ],
        )
        .expect("encode");
        let parsed = parse_token(&bytes).expect("P-384 dh1 length should be accepted");
        match parsed {
            TokenKind::Request(r) => {
                assert_eq!(r.dh1.len(), 97);
                assert_eq!(r.kagree_algo, "ECDH+secp384r1-CEUM");
            }
            _ => panic!("expected Request variant"),
        }
    }
}
