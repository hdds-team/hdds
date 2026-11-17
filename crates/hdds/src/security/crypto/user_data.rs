// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SerializedPayload protection, DDS-Security 1.1 Sec.9.5.3.3.4.1-4.
//! The CryptoHeader, CryptoContent and CryptoFooter replace the complete
//! SerializedPayload, including its encapsulation. Protection is selected
//! from endpoint attributes by the caller, never by inspecting sample bytes.

use super::data_keys::WriterKey;
use super::secure_submessage::{gcm, next_initialization_vector, Transformation};
use crate::security::SecurityError;
use ring::aead::Aad;

fn malformed() -> SecurityError {
    SecurityError::CryptoError("invalid protected SerializedPayload".into())
}

/// The announced sender_key_id in a complete protected SerializedPayload.
/// Validate its crypto elements before looking up the announced material.
/// Call only after the writer's attributes selected payload protection.
pub fn secured_payload_key_id(payload: &[u8]) -> Result<u64, SecurityError> {
    let kind = payload
        .get(..4)
        .ok_or_else(malformed)?
        .try_into()
        .map_err(|_| malformed())?;
    let transformation = Transformation::of_kind(kind).ok_or_else(malformed)?;
    Ok(u64::from(
        parse_crypto_elements(transformation, payload)?.key_id,
    ))
}

struct CryptoElements<'a> {
    key_id: u32,
    session: [u8; 4],
    suffix: [u8; 8],
    content: &'a [u8],
    common_mac: &'a [u8],
}

fn parse_crypto_elements(
    transformation: Transformation,
    payload: &[u8],
) -> Result<CryptoElements<'_>, SecurityError> {
    if payload.len() < 40 || payload[..4] != transformation.kind() {
        return Err(malformed());
    }
    let (start, len) = match transformation {
        Transformation::Aes256Gcm => {
            let n = u32::from_be_bytes(
                payload
                    .get(20..24)
                    .ok_or_else(malformed)?
                    .try_into()
                    .map_err(|_| malformed())?,
            );
            (24usize, usize::try_from(n).map_err(|_| malformed())?)
        }
        Transformation::Aes256Gmac => (20, payload.len().checked_sub(40).ok_or_else(malformed)?),
    };
    if len < 4 {
        return Err(malformed());
    }
    let end = start.checked_add(len).ok_or_else(malformed)?;
    let mac_end = end.checked_add(16).ok_or_else(malformed)?;
    let count = mac_end.checked_add(3).ok_or_else(malformed)? & !3;
    if count.checked_add(4) != Some(payload.len()) || payload.get(count..) != Some(&[0, 0, 0, 0]) {
        return Err(malformed());
    }
    Ok(CryptoElements {
        key_id: u32::from_be_bytes(payload[4..8].try_into().map_err(|_| malformed())?),
        session: payload[8..12].try_into().map_err(|_| malformed())?,
        suffix: payload[12..20].try_into().map_err(|_| malformed())?,
        content: payload.get(start..end).ok_or_else(malformed)?,
        common_mac: payload.get(end..mac_end).ok_or_else(malformed)?,
    })
}

/// Protect the complete SerializedPayload using the announced master material.
/// SIGN takes a four-aligned payload including its declared CDR padding,
/// because its unchanged content has no separate length field.
pub fn encode_serialized_payload(
    key_id: u64,
    material: &WriterKey,
    serialized_payload: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    let (session, suffix) = next_initialization_vector(serialized_payload.len())?;
    encode_with_iv(key_id, material, serialized_payload, session, suffix)
}

fn encode_with_iv(
    key_id: u64,
    material: &WriterKey,
    plaintext: &[u8],
    session: [u8; 4],
    suffix: [u8; 8],
) -> Result<Vec<u8>, SecurityError> {
    if plaintext.len() < 4
        || (material.transformation == Transformation::Aes256Gmac
            && !plaintext.len().is_multiple_of(4))
    {
        return Err(malformed());
    }
    let id = u32::try_from(key_id).map_err(|_| malformed())?;
    let m = material.submessage_material(id);
    let (key, nonce) = gcm(*m.session_key(session), session, suffix)?;
    let mut content = plaintext.to_vec();
    let tag = match material.transformation {
        Transformation::Aes256Gcm => {
            key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut content)
        }
        Transformation::Aes256Gmac => {
            key.seal_in_place_separate_tag(nonce, Aad::from(plaintext), &mut [])
        }
    }
    .map_err(|_| malformed())?;
    let mut out = Vec::with_capacity(44 + content.len() + 3);
    out.extend_from_slice(&material.transformation.kind());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&session);
    out.extend_from_slice(&suffix);
    if material.transformation == Transformation::Aes256Gcm {
        out.extend_from_slice(
            &u32::try_from(content.len())
                .map_err(|_| malformed())?
                .to_be_bytes(),
        );
    }
    out.extend_from_slice(&content);
    // common_mac is octet[16], aligned to one; only the following
    // sequence length needs four-byte CDR alignment (Sec.9.5.2.5).
    out.extend_from_slice(tag.as_ref());
    out.resize(out.len().next_multiple_of(4), 0);
    out.extend_from_slice(&0u32.to_be_bytes());
    Ok(out)
}

/// Decode using this writer's announced key, salt and transformation kind.
/// The tag authenticates the complete SerializedPayload with empty GCM AAD.
pub fn decode_serialized_payload(
    key_id: u64,
    material: &WriterKey,
    payload: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    let elements = parse_crypto_elements(material.transformation, payload)?;
    if u64::from(elements.key_id) != key_id {
        return Err(malformed());
    }
    let CryptoElements {
        key_id: id,
        session,
        suffix,
        content,
        common_mac,
    } = elements;
    let (key, nonce) = gcm(
        *material.submessage_material(id).session_key(session),
        session,
        suffix,
    )?;
    let mut in_out = if material.transformation == Transformation::Aes256Gcm {
        content.to_vec()
    } else {
        Vec::new()
    };
    in_out.extend_from_slice(common_mac);
    let aad = if material.transformation == Transformation::Aes256Gmac {
        Aad::from(content)
    } else {
        Aad::from(&[][..])
    };
    let plain = key
        .open_in_place(nonce, aad, &mut in_out)
        .map_err(|_| malformed())?;
    Ok(if material.transformation == Transformation::Aes256Gmac {
        content.to_vec()
    } else {
        plain.to_vec()
    })
}

/// The attributes also announced by SEDP when encryption is configured
/// without governance. A governance document always takes precedence.
pub(crate) fn endpoint_security_info(
    suite: &crate::security::SecurityPluginSuite,
    topic: &str,
) -> Result<crate::protocol::discovery::EndpointSecurityInfo, SecurityError> {
    use crate::protocol::discovery::EndpointSecurityInfo as Info;
    if let Some(access) = suite.access_control() {
        return access.endpoint_attributes(topic).map(|a| a.security_info());
    }
    let encrypted = suite.cryptographic().is_some();
    Ok(Info {
        endpoint_security_attributes: Info::IS_VALID
            | if encrypted {
                Info::IS_PAYLOAD_PROTECTED | Info::IS_KEY_PROTECTED
            } else {
                0
            },
        plugin_endpoint_security_attributes: Info::IS_VALID
            | if encrypted {
                Info::PLUGIN_IS_PAYLOAD_ENCRYPTED
            } else {
                0
            },
    })
}

/// Recover the representation and exact sample body after authentication.
pub(crate) fn serialized_body(
    payload: &[u8],
) -> Result<(Vec<u8>, crate::dds::CdrVersion), SecurityError> {
    let header = payload.get(..4).ok_or_else(malformed)?;
    let repr = u16::from_be_bytes([header[0], header[1]]);
    let version = crate::dds::cdr_negotiation::cdr_version_from_representation_id(repr)
        .map_err(|_| malformed())?;
    let end = payload
        .len()
        .checked_sub(usize::from(header[3] & 3))
        .filter(|end| *end >= 4)
        .ok_or_else(malformed)?;
    Ok((payload[4..end].to_vec(), version))
}

#[cfg(test)]
#[path = "user_data_tests.rs"]
mod tests;
