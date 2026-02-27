// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::core::discovery::guid::GUID;
use crate::security::SecurityError;

#[cfg(feature = "security")]
use ring::digest::{digest, SHA256};
#[cfg(feature = "security")]
use ring::signature::{self, UnparsedPublicKey};
#[cfg(feature = "security")]
use x509_parser::{pem::parse_x509_pem, prelude::*};

/// Validate that the participant certificate chains up to the trusted CA set.
#[cfg(feature = "security")]
pub(crate) fn validate_certificate_chain(
    participant_cert_pem: &[u8],
    ca_certs_pem: &[u8],
) -> Result<(), SecurityError> {
    let participant_cert = parse_certificate(participant_cert_pem)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let not_before = participant_cert.validity().not_before.timestamp();
    let not_after = participant_cert.validity().not_after.timestamp();

    if now < not_before as u64 {
        return Err(SecurityError::CertificateInvalid(
            "Certificate not yet valid (notBefore)".to_string(),
        ));
    }

    if now > not_after as u64 {
        return Err(SecurityError::CertificateExpired);
    }

    if let Some(ext) = participant_cert
        .get_extension_unique(&oid_registry::OID_X509_EXT_KEY_USAGE)
        .map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "Failed to parse KeyUsage extension: {:?}",
                e
            ))
        })?
    {
        let key_usage = ext.parsed_extension();
        if let x509_parser::extensions::ParsedExtension::KeyUsage(ku) = key_usage {
            if !ku.digital_signature() {
                return Err(SecurityError::CertificateInvalid(
                    "Certificate KeyUsage does not include digitalSignature".to_string(),
                ));
            }
        }
    }

    let pem_blocks = ::pem::parse_many(ca_certs_pem).map_err(|e| {
        SecurityError::CertificateInvalid(format!("Failed to parse CA certs: {}", e))
    })?;

    let ca_der_data: Vec<Vec<u8>> = pem_blocks
        .into_iter()
        .map(|block| block.contents().to_vec())
        .collect();

    if ca_der_data.is_empty() {
        return Err(SecurityError::CertificateInvalid(
            "No CA certificates in trust store".to_string(),
        ));
    }

    let mut ca_certs = Vec::new();
    for der_data in &ca_der_data {
        let (_, ca_cert) = X509Certificate::from_der(der_data).map_err(|e| {
            SecurityError::CertificateInvalid(format!("Failed to parse CA cert: {:?}", e))
        })?;
        ca_certs.push(ca_cert);
    }

    let issuer = participant_cert.issuer();
    let issuer_cert = ca_certs
        .iter()
        .find(|ca| ca.subject() == issuer)
        .ok_or_else(|| {
            SecurityError::CertificateInvalid(
                "Certificate issuer not found in CA trust store".to_string(),
            )
        })?;

    // For ECDSA verification with ring, we need the full SubjectPublicKeyInfo DER encoding,
    // not just the raw key bytes. The .raw field contains only the BIT STRING content (65 bytes
    // for uncompressed P-256), but ring expects the complete SPKI structure including algorithm OID.
    let issuer_public_key_spki = &issuer_cert.public_key().subject_public_key.data;
    let signature = participant_cert.signature_value.as_ref();
    let tbs_certificate = participant_cert.tbs_certificate.as_ref();

    // Try RSA first (for RSA certificates)
    let rsa_public_key = UnparsedPublicKey::new(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        issuer_public_key_spki.as_ref(),
    );
    if let Ok(()) = rsa_public_key.verify(tbs_certificate, signature) {
        return Ok(());
    }

    // Try ECDSA P-256 (for EC certificates)
    let ecdsa_public_key = UnparsedPublicKey::new(
        &signature::ECDSA_P256_SHA256_ASN1,
        issuer_public_key_spki.as_ref(),
    );
    if let Ok(()) = ecdsa_public_key.verify(tbs_certificate, signature) {
        return Ok(());
    }

    Err(SecurityError::CertificateInvalid(
        "Certificate signature verification failed (tried RSA and ECDSA P-256)".to_string(),
    ))
}

#[cfg(not(feature = "security"))]
pub(crate) fn validate_certificate_chain(
    _participant_cert_pem: &[u8],
    _ca_certs_pem: &[u8],
) -> Result<(), SecurityError> {
    Ok(())
}

#[cfg(feature = "security")]
pub(crate) fn parse_certificate(
    certificate_pem: &[u8],
) -> Result<X509Certificate<'static>, SecurityError> {
    let (_, pem) = parse_x509_pem(certificate_pem).map_err(|e| {
        SecurityError::CertificateInvalid(format!("Failed to parse X.509 PEM: {:?}", e))
    })?;

    // KNOWN LIMITATION: Memory leak due to x509_parser's borrowing design.
    //
    // x509_parser::X509Certificate<'a> borrows the input buffer for its lifetime.
    // We cannot return a certificate that borrows local data, so we leak the buffer
    // to obtain a 'static lifetime. This is acceptable because:
    // 1. Certificates are loaded once at participant startup (not in hot paths)
    // 2. The leaked memory is small (~1-4KB per certificate) and bounded
    //
    // MISSING FEATURE: Owned certificate handling via x509-cert or rcgen crate
    // would eliminate this leak entirely.
    #[allow(clippy::box_default)]
    let contents: Vec<u8> = pem.contents.to_vec();
    let contents_static: &'static [u8] = Box::leak(contents.into_boxed_slice());

    x509_parser::parse_x509_certificate(contents_static)
        .map(|(_, cert)| cert)
        .map_err(|e| {
            SecurityError::CertificateInvalid(format!("Failed to parse X.509 certificate: {:?}", e))
        })
}

#[cfg(feature = "security")]
pub(crate) fn parse_subject_name(certificate_pem: &[u8]) -> Result<String, SecurityError> {
    let cert = parse_certificate(certificate_pem)?;

    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                if let Ok(cn) = attr.attr_value().as_str() {
                    return Ok(cn.to_string());
                }
            }
        }
    }

    Err(SecurityError::CertificateInvalid(
        "Certificate has no Common Name (CN)".to_string(),
    ))
}

#[cfg(not(feature = "security"))]
pub(crate) fn parse_subject_name(certificate_pem: &[u8]) -> Result<String, SecurityError> {
    let cert_str = String::from_utf8_lossy(certificate_pem);
    if cert_str.contains("CN=") {
        for line in cert_str.lines() {
            if let Some(cn_start) = line.find("CN=") {
                let cn = &line[cn_start + 3..];
                let cn_end = cn.find(',').unwrap_or(cn.len());
                return Ok(cn[..cn_end].trim().to_string());
            }
        }
    }
    Ok("unknown".to_string())
}

#[cfg(feature = "security")]
pub(crate) fn get_expiration_time(certificate_pem: &[u8]) -> Result<u64, SecurityError> {
    let cert = parse_certificate(certificate_pem)?;
    let not_after = cert.validity().not_after;
    let timestamp = not_after.timestamp();

    if timestamp < 0 {
        return Err(SecurityError::CertificateInvalid(
            "Certificate expiration time is before Unix epoch".to_string(),
        ));
    }

    Ok(timestamp as u64)
}

#[cfg(not(feature = "security"))]
pub(crate) fn get_expiration_time(_certificate_pem: &[u8]) -> Result<u64, SecurityError> {
    Ok(4_102_444_800)
}

/// Derive a deterministic GUID from an X.509 certificate.
///
/// The GUID is computed by hashing the certificate's DER-encoded content with SHA-256,
/// then using the first 12 bytes as the GUID prefix. The entity ID is set to
/// ENTITYID_PARTICIPANT (0x00, 0x00, 0x01, 0xC1).
///
/// This ensures that:
/// - Same certificate always produces the same GUID
/// - Different certificates produce different GUIDs (collision-resistant)
/// - GUID is cryptographically tied to the certificate identity
#[cfg(feature = "security")]
pub(crate) fn derive_guid_from_certificate(certificate_pem: &[u8]) -> Result<GUID, SecurityError> {
    // Parse PEM to get DER content
    let (_, pem) = parse_x509_pem(certificate_pem).map_err(|e| {
        SecurityError::CertificateInvalid(format!(
            "Failed to parse PEM for GUID derivation: {:?}",
            e
        ))
    })?;

    // Hash the DER-encoded certificate with SHA-256
    let hash = digest(&SHA256, &pem.contents);
    let hash_bytes = hash.as_ref();

    // Use first 12 bytes of hash as GUID prefix
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&hash_bytes[0..12]);

    // ENTITYID_PARTICIPANT per RTPS spec
    let entity_id = [0x00, 0x00, 0x01, 0xC1];

    Ok(GUID::new(prefix, entity_id))
}

#[cfg(not(feature = "security"))]
pub(crate) fn derive_guid_from_certificate(_certificate_pem: &[u8]) -> Result<GUID, SecurityError> {
    // Without security feature, return a zero GUID
    Ok(GUID::zero())
}
