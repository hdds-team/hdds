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

/// Longest path accepted, leaf and trust anchor included.
#[cfg(feature = "security")]
const MAX_CHAIN_LENGTH: usize = 8;

/// Validate that the participant certificate chains up to the trusted CA set,
/// and, when a revocation list is given, that no certificate on the path has
/// been revoked by its own issuer.
///
/// DDS-Security v1.1 Sec.9.3.1.3 requires an identity certificate "that chains
/// up to the Identity CA", so the path is built rather than assumed to be one
/// link long. Intermediate certificates come from the rest of
/// `participant_cert_pem` (what the peer presents after its own certificate);
/// the trust anchors are `ca_certs_pem`. Every link is checked: its signature,
/// the validity period of the leaf and of each intermediate, that each issuer
/// is a CA (RFC 5280 4.2.1.9, 4.2.1.3) and that its pathLenConstraint allows
/// the intermediates below it (RFC 5280 4.2.1.9, 6.1.4(l)). The revocation list
/// is checked LAST, one link at a time, against each link's issuer.
#[cfg(feature = "security")]
pub(crate) fn validate_certificate_chain(
    participant_cert_pem: &[u8],
    ca_certs_pem: &[u8],
    revocation_list: Option<&[u8]>,
) -> Result<(), SecurityError> {
    let path = build_path(participant_cert_pem, ca_certs_pem)?;
    if let Some(crl) = revocation_list {
        for link in path.windows(2) {
            let (_, subject) = X509Certificate::from_der(&link[0]).map_err(|e| {
                SecurityError::CertificateInvalid(format!(
                    "Failed to parse X.509 certificate: {:?}",
                    e
                ))
            })?;
            let (_, issuer) = X509Certificate::from_der(&link[1]).map_err(|e| {
                SecurityError::CertificateInvalid(format!("Failed to parse CA cert: {:?}", e))
            })?;
            crate::security::revocation::check(&subject, &issuer, crl)?;
        }
    }

    Ok(())
}

/// The path from the identity to a trust anchor, leaf first, with every check
/// that needs no revocation list: the leaf's validity period and KeyUsage, and
/// each link's issuer (see `validate_certificate_chain`).
#[cfg(feature = "security")]
fn build_path(
    participant_cert_pem: &[u8],
    ca_certs_pem: &[u8],
) -> Result<Vec<Vec<u8>>, SecurityError> {
    let (_, pem) = parse_x509_pem(participant_cert_pem).map_err(|e| {
        SecurityError::CertificateInvalid(format!("Failed to parse X.509 PEM: {:?}", e))
    })?;
    let leaf_der = pem.contents.to_vec();
    let presented = presented_intermediates(participant_cert_pem)?;

    let anchors: Vec<Vec<u8>> = ::pem::parse_many(ca_certs_pem)
        .map_err(|e| SecurityError::CertificateInvalid(format!("Failed to parse CA certs: {}", e)))?
        .into_iter()
        .map(|block| block.contents().to_vec())
        .collect();
    if anchors.is_empty() {
        return Err(SecurityError::CertificateInvalid(
            "No CA certificates in trust store".to_string(),
        ));
    }

    // A clock error is an error, never `now = 0`.
    let now = crate::security::revocation::unix_now_seconds()?;
    {
        let (_, leaf) = X509Certificate::from_der(&leaf_der).map_err(|e| {
            SecurityError::CertificateInvalid(format!("Failed to parse X.509 certificate: {:?}", e))
        })?;
        check_validity(&leaf, now)?;
        // The identity certificate signs the handshake messages, so a KeyUsage
        // that is present must assert digitalSignature (RFC 5280 4.2.1.3).
        // Absent KeyUsage places no restriction.
        if let Some(ku) = key_usage_of(&leaf)? {
            if !ku.digital_signature() {
                return Err(SecurityError::CertificateInvalid(
                    "Certificate KeyUsage does not include digitalSignature".to_string(),
                ));
            }
        }
    }

    find_path(&mut vec![leaf_der], &presented, &anchors, now)
}

/// Whether `crl` lists a certificate on the path of `participant_cert_pem` as
/// revoked, by that certificate's own issuer.
///
/// Only a listed answer counts. A stale list, or a link no authentic list
/// speaks for, is not a revocation. This is for ending sessions that a newly
/// loaded list revokes: an `Err` means the path or the list could not be judged,
/// and the caller keeps the session.
#[cfg(feature = "security")]
pub(crate) fn path_is_listed(
    participant_cert_pem: &[u8],
    ca_certs_pem: &[u8],
    crl: &[u8],
) -> Result<bool, SecurityError> {
    let path = build_path(participant_cert_pem, ca_certs_pem)?;
    for link in path.windows(2) {
        let (_, subject) = X509Certificate::from_der(&link[0]).map_err(|e| {
            SecurityError::CertificateInvalid(format!("Failed to parse X.509 certificate: {:?}", e))
        })?;
        let (_, issuer) = X509Certificate::from_der(&link[1]).map_err(|e| {
            SecurityError::CertificateInvalid(format!("Failed to parse CA cert: {:?}", e))
        })?;
        if crate::security::revocation::examine(&subject, &issuer, crl)?
            .revoked
            .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The DER bodies of the certificates after the first block of `pem`: what a
/// peer presents beyond its identity certificate.
#[cfg(feature = "security")]
fn presented_intermediates(pem: &[u8]) -> Result<Vec<Vec<u8>>, SecurityError> {
    let blocks = ::pem::parse_many(pem).map_err(|e| {
        SecurityError::CertificateInvalid(format!("Failed to parse X.509 PEM: {}", e))
    })?;
    Ok(blocks
        .iter()
        .skip(1)
        .map(|block| block.contents().to_vec())
        .collect())
}

/// Not yet valid, or expired: RFC 5280 4.1.2.5 makes notAfter inclusive.
#[cfg(feature = "security")]
fn check_validity(cert: &X509Certificate<'_>, now: i64) -> Result<(), SecurityError> {
    if now < cert.validity().not_before.timestamp() {
        return Err(SecurityError::CertificateInvalid(
            "Certificate not yet valid (notBefore)".to_string(),
        ));
    }
    if now > cert.validity().not_after.timestamp() {
        return Err(SecurityError::CertificateExpired);
    }
    Ok(())
}

/// Extend `path` (leaf first) to a trust anchor, backtracking over candidate
/// issuers. Returns the whole path, leaf first and anchor last. When no path
/// exists, returns the reason the most promising candidate was refused, or
/// that no issuer was found.
#[cfg(feature = "security")]
fn find_path(
    path: &mut Vec<Vec<u8>>,
    presented: &[Vec<u8>],
    anchors: &[Vec<u8>],
    now: i64,
) -> Result<Vec<Vec<u8>>, SecurityError> {
    let current = {
        let last = path.last().map(Vec::as_slice).unwrap_or_default();
        Signed::of(last)?
    };
    let mut refused: Option<SecurityError> = None;

    for (pool, is_anchor) in [(anchors, true), (presented, false)] {
        for candidate in pool {
            let issuer = match X509Certificate::from_der(candidate) {
                Ok((_, issuer)) => issuer,
                Err(e) => {
                    // An unparsable trust anchor is skipped, as it always was; an
                    // unparsable intermediate a peer sent is a refusal.
                    if !is_anchor {
                        refused.get_or_insert(SecurityError::CertificateInvalid(format!(
                            "Failed to parse intermediate certificate: {:?}",
                            e
                        )));
                    }
                    continue;
                }
            };
            if issuer.subject().as_raw() != current.issuer.as_slice() {
                continue;
            }
            if !signed_by(&issuer, &current) {
                continue;
            }
            // Every certificate below this issuer is an intermediate of the path
            // (the leaf is not one).
            let below = path.len() - 1;
            if let Err(e) = issuer_may_sign_certificates(&issuer, below) {
                refused.get_or_insert(e);
                continue;
            }
            if is_anchor {
                let mut full = path.clone();
                full.push(candidate.clone());
                return Ok(full);
            }
            if let Err(e) = check_validity(&issuer, now) {
                refused.get_or_insert(e);
                continue;
            }
            if path.iter().any(|known| known == candidate) || path.len() >= MAX_CHAIN_LENGTH {
                refused.get_or_insert(SecurityError::CertificateInvalid(format!(
                    "certificate path is longer than {} certificates or repeats one",
                    MAX_CHAIN_LENGTH
                )));
                continue;
            }
            path.push(candidate.clone());
            match find_path(path, presented, anchors, now) {
                Ok(full) => return Ok(full),
                Err(e) => {
                    path.pop();
                    refused.get_or_insert(e);
                }
            }
        }
    }

    Err(refused.unwrap_or_else(|| {
        SecurityError::CertificateInvalid(
            "Certificate issuer not found in CA trust store, or its signature does not verify \
             against any such CA"
                .to_string(),
        )
    }))
}

/// What a link needs of the certificate it proves: its signed bytes, its
/// signature and the name of its issuer.
#[cfg(feature = "security")]
struct Signed {
    tbs: Vec<u8>,
    signature: Vec<u8>,
    issuer: Vec<u8>,
}

#[cfg(feature = "security")]
impl Signed {
    fn of(der: &[u8]) -> Result<Self, SecurityError> {
        let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
            SecurityError::CertificateInvalid(format!("Failed to parse X.509 certificate: {:?}", e))
        })?;
        Ok(Self {
            tbs: cert.tbs_certificate.as_ref().to_vec(),
            signature: cert.signature_value.as_ref().to_vec(),
            issuer: cert.issuer().as_raw().to_vec(),
        })
    }
}

/// Whether `issuer` signed the certificate `subject` describes. ECDSA P-256 and
/// RSA are both tried; ring wants the raw key bytes of the SubjectPublicKeyInfo.
#[cfg(feature = "security")]
fn signed_by(issuer: &X509Certificate<'_>, subject: &Signed) -> bool {
    let key = issuer.public_key().subject_public_key.data.as_ref();
    UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, key)
        .verify(&subject.tbs, &subject.signature)
        .is_ok()
        || UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, key)
            .verify(&subject.tbs, &subject.signature)
            .is_ok()
}

/// The KeyUsage extension of `cert`, if it has one (RFC 5280 4.2.1.3).
/// A duplicate or unparsable extension is an error, never "absent".
#[cfg(feature = "security")]
fn key_usage_of(
    cert: &X509Certificate<'_>,
) -> Result<Option<x509_parser::extensions::KeyUsage>, SecurityError> {
    let ext = cert
        .get_extension_unique(&oid_registry::OID_X509_EXT_KEY_USAGE)
        .map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "Failed to parse KeyUsage extension: {:?}",
                e
            ))
        })?;
    Ok(match ext.map(|ext| ext.parsed_extension()) {
        Some(x509_parser::extensions::ParsedExtension::KeyUsage(ku)) => Some(*ku),
        Some(_) => {
            return Err(SecurityError::CertificateInvalid(
                "KeyUsage extension did not parse as KeyUsage".to_string(),
            ))
        }
        None => None,
    })
}

/// Whether `ca` may verify certificate signatures: the two rules a trust
/// anchor must meet before its key is used for that.
///
/// - RFC 5280 4.2.1.9: "If the basic constraints extension is not present ...
///   or the extension is present but the cA boolean is not asserted, then the
///   certified public key MUST NOT be used to verify certificate signatures."
/// - RFC 5280 4.2.1.3: "If the keyCertSign bit is asserted, then the cA bit in
///   the basic constraints extension MUST also be asserted", and the key is
///   used for certificate signatures only if keyCertSign is set, when a
///   KeyUsage extension is present.
///
/// The pathLenConstraint of the same extension (RFC 5280 4.2.1.9, 6.1.4(l)):
/// when it is present, at most that many intermediate CA certificates may
/// follow `ca` in a path, and `intermediates_below` counts them for this path.
#[cfg(feature = "security")]
fn issuer_may_sign_certificates(
    ca: &X509Certificate<'_>,
    intermediates_below: usize,
) -> Result<(), SecurityError> {
    let basic = ca
        .get_extension_unique(&oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)
        .map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "Failed to parse BasicConstraints extension of issuer [{}]: {:?}",
                ca.subject(),
                e
            ))
        })?;
    let is_ca = matches!(
        basic.map(|ext| ext.parsed_extension()),
        Some(x509_parser::extensions::ParsedExtension::BasicConstraints(bc)) if bc.ca
    );
    if !is_ca {
        return Err(SecurityError::CertificateInvalid(format!(
            "issuer [{}] is not a CA: its basicConstraints cA is not TRUE, so it may not sign \
             certificates (RFC 5280 4.2.1.9)",
            ca.subject()
        )));
    }
    if let Some(ku) = key_usage_of(ca)? {
        if !ku.key_cert_sign() {
            return Err(SecurityError::CertificateInvalid(format!(
                "issuer [{}] has a KeyUsage without keyCertSign, so it may not sign \
                 certificates (RFC 5280 4.2.1.3)",
                ca.subject()
            )));
        }
    }
    let path_len = match basic.map(|ext| ext.parsed_extension()) {
        Some(x509_parser::extensions::ParsedExtension::BasicConstraints(bc)) => {
            bc.path_len_constraint
        }
        _ => None,
    };
    if let Some(allowed) = path_len {
        if intermediates_below > allowed as usize {
            return Err(SecurityError::CertificateInvalid(format!(
                "issuer [{}] has pathLenConstraint {}, which allows at most {} intermediate CA \
                 certificate(s) below it; this path has {} (RFC 5280 4.2.1.9)",
                ca.subject(),
                allowed,
                allowed,
                intermediates_below
            )));
        }
    }
    Ok(())
}

/// Without the `security` feature there is no X.509 parser, so nothing can be
/// validated here - and a function that cannot validate says so rather than
/// returning `Ok`. See the body.
#[cfg(not(feature = "security"))]
pub(crate) fn validate_certificate_chain(
    participant_cert_pem: &[u8],
    ca_certs_pem: &[u8],
    revocation_list: Option<&[u8]>,
) -> Result<(), SecurityError> {
    // Was: `Ok(())` for any bytes - a trust decision returned without an
    // X.509 parser present to make it.
    let _ = (participant_cert_pem, ca_certs_pem, revocation_list);
    Err(SecurityError::AuthenticationFailed(
        "certificate chain validation requires the `security` feature; this build has no \
         X.509 parser, and reporting an unexamined certificate as trusted would be a \
         security decision nobody made"
            .to_string(),
    ))
}

#[cfg(feature = "security")]
pub(crate) fn with_certificate<R>(
    certificate_pem: &[u8],
    f: impl FnOnce(&X509Certificate<'_>) -> Result<R, SecurityError>,
) -> Result<R, SecurityError> {
    let (_, pem) = parse_x509_pem(certificate_pem).map_err(|e| {
        SecurityError::CertificateInvalid(format!("Failed to parse X.509 PEM: {:?}", e))
    })?;
    // The parsed certificate borrows the decoded DER, so it is handed to `f`
    // instead of returned. It used to be returned as `'static` over a leaked
    // copy of the DER, and the remote certificate of every handshake request
    // goes through here: each handshake leaked its certificate.
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).map_err(|e| {
        SecurityError::CertificateInvalid(format!("Failed to parse X.509 certificate: {:?}", e))
    })?;
    f(&cert)
}

#[cfg(feature = "security")]
pub(crate) fn parse_subject_name(certificate_pem: &[u8]) -> Result<String, SecurityError> {
    with_certificate(certificate_pem, |cert| {
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
    })
}

#[cfg(not(feature = "security"))]
pub(crate) fn parse_subject_name(certificate_pem: &[u8]) -> Result<String, SecurityError> {
    // Was: a substring search for "CN=" over the raw PEM, falling back to the
    // literal "unknown". The subject name is what an access-control grant is
    // matched against, so a guess here is a guess about which permissions
    // apply.
    let _ = certificate_pem;
    Err(SecurityError::AuthenticationFailed(
        "reading a certificate subject requires the `security` feature; this build has no \
         X.509 parser, and a substring guess is not an identity"
            .to_string(),
    ))
}

#[cfg(feature = "security")]
pub(crate) fn get_expiration_time(certificate_pem: &[u8]) -> Result<u64, SecurityError> {
    let timestamp = with_certificate(certificate_pem, |cert| {
        Ok(cert.validity().not_after.timestamp())
    })?;

    if timestamp < 0 {
        return Err(SecurityError::CertificateInvalid(
            "Certificate expiration time is before Unix epoch".to_string(),
        ));
    }

    Ok(timestamp as u64)
}

#[cfg(not(feature = "security"))]
pub(crate) fn get_expiration_time(certificate_pem: &[u8]) -> Result<u64, SecurityError> {
    // Was: `Ok(4_102_444_800)` - the year 2100, i.e. "never expires", which is
    // what `IdentityHandle::is_expired()` would then report for any input.
    let _ = certificate_pem;
    Err(SecurityError::AuthenticationFailed(
        "reading a certificate expiry requires the `security` feature; this build has no \
         X.509 parser, and reporting a certificate as valid until 2100 would be a security \
         decision nobody made"
            .to_string(),
    ))
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
pub(crate) fn derive_guid_from_certificate(certificate_pem: &[u8]) -> Result<GUID, SecurityError> {
    // Was: `Ok(GUID::zero())`. Beyond the security question that is a
    // CORRECTNESS defect - every participant on such a build derives the SAME
    // GUID, so discovery and endpoint matching collide. Observed, not
    // inferred: a default-features program calling the public
    // `X509AuthenticationPlugin::validate_identity()` printed
    // `GUID(00.00.00.00.00.00.00.00.00.00.00.00.00.00.00.00)`.
    let _ = certificate_pem;
    Err(SecurityError::AuthenticationFailed(
        "GUID derivation requires the `security` feature; this build has no digest for it, \
         and a zero GUID collides with every other participant"
            .to_string(),
    ))
}

#[cfg(all(test, feature = "security"))]
mod tests {
    //! Chain rules, each proved from both sides: the refusal a mutant of the
    //! rule would let through, and a positive control that the rule does not
    //! refuse a conforming certificate. Certificates are made with `rcgen`, the
    //! way `transport::tcp::tls_test_pki` makes its own: `IsCa` and
    //! `KeyUsagePurpose` are set explicitly, so the extension under test is the
    //! only thing that differs between the cases.

    use super::validate_certificate_chain;
    use crate::security::SecurityError;
    use rcgen::KeyUsagePurpose as Usage;
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    use rcgen::{CertificateRevocationListParams, RevokedCertParams, SerialNumber};

    fn named(common_name: &str) -> DistinguishedName {
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        name
    }

    /// A self-signed certificate: a CA when `is_ca`, with `usages` as its
    /// KeyUsage (no KeyUsage extension when `usages` is empty).
    fn root(common_name: &str, is_ca: IsCa, usages: Vec<Usage>) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name = named(common_name);
        params.is_ca = is_ca;
        params.key_usages = usages;
        let key = KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("self-signed");
        (cert, key)
    }

    /// A certificate for `common_name`, signed by `issuer`.
    fn issued(
        common_name: &str,
        is_ca: IsCa,
        usages: Vec<Usage>,
        issuer: (&rcgen::Certificate, &KeyPair),
    ) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name = named(common_name);
        params.is_ca = is_ca;
        params.key_usages = usages;
        let key = KeyPair::generate().expect("key");
        let cert = params
            .signed_by(&key, issuer.0, issuer.1)
            .expect("signed by the issuer");
        (cert, key)
    }

    fn ca_usages() -> Vec<Usage> {
        vec![Usage::KeyCertSign, Usage::CrlSign]
    }

    fn identity_usages() -> Vec<Usage> {
        vec![Usage::DigitalSignature]
    }

    fn ca_bundle(certs: &[&rcgen::Certificate]) -> Vec<u8> {
        certs.iter().flat_map(|c| c.pem().into_bytes()).collect()
    }

    #[test]
    fn an_identity_signed_by_a_proper_ca_is_accepted() {
        let (ca, ca_key) = root(
            "Chain CA",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_usages(),
        );
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&ca, &ca_key),
        );
        validate_certificate_chain(id.pem().as_bytes(), &ca_bundle(&[&ca]), None)
            .expect("a CA with cA TRUE and keyCertSign signs an identity: accepted");
    }

    /// RFC 5280 4.2.1.9: a key whose basicConstraints does not assert cA "MUST
    /// NOT be used to verify certificate signatures". A leaf placed in the
    /// trust store must not vouch for a certificate beneath it.
    #[test]
    fn a_leaf_in_the_trust_store_may_not_issue_a_certificate() {
        let (leaf, leaf_key) = root("Leaf in trust store", IsCa::ExplicitNoCa, identity_usages());
        let (child, _) = issued(
            "Child of a leaf",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&leaf, &leaf_key),
        );
        let err = validate_certificate_chain(child.pem().as_bytes(), &ca_bundle(&[&leaf]), None)
            .expect_err("a non-CA must not be an issuer");
        assert!(
            err.to_string().contains("not a CA"),
            "the refusal must name the cause, got: {}",
            err
        );
    }

    /// RFC 5280 4.2.1.3: keyCertSign "MUST also" come with cA TRUE, and when a
    /// KeyUsage is present the key signs certificates only with keyCertSign.
    #[test]
    fn a_ca_whose_key_usage_lacks_keycertsign_may_not_sign() {
        let (ca, ca_key) = root(
            "CA without keyCertSign",
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![Usage::DigitalSignature],
        );
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&ca, &ca_key),
        );
        let err = validate_certificate_chain(id.pem().as_bytes(), &ca_bundle(&[&ca]), None)
            .expect_err("KeyUsage without keyCertSign cannot sign certificates");
        assert!(err.to_string().contains("keyCertSign"), "got: {}", err);
    }

    /// Positive control for the rule above: with no KeyUsage extension at all,
    /// RFC 5280 4.2.1.3 imposes no restriction, so the CA is accepted.
    #[test]
    fn a_ca_without_any_key_usage_extension_is_accepted() {
        let (ca, ca_key) = root(
            "CA without KeyUsage",
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![],
        );
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&ca, &ca_key),
        );
        validate_certificate_chain(id.pem().as_bytes(), &ca_bundle(&[&ca]), None)
            .expect("no KeyUsage restricts nothing");
    }

    /// DDS-Security v1.1 9.3.3 has the identity certificate verified; the
    /// handshake signature it protects is a digital signature (RFC 5280 4.2.1.3),
    /// so a KeyUsage that is present must assert digitalSignature.
    #[test]
    fn an_identity_whose_key_usage_lacks_digital_signature_is_refused() {
        let (ca, ca_key) = root(
            "Chain CA",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_usages(),
        );
        let (id, _) = issued(
            "Encipher-only identity",
            IsCa::ExplicitNoCa,
            vec![Usage::KeyEncipherment],
            (&ca, &ca_key),
        );
        let err = validate_certificate_chain(id.pem().as_bytes(), &ca_bundle(&[&ca]), None)
            .expect_err("an identity that cannot sign is refused");
        assert!(err.to_string().contains("digitalSignature"), "got: {}", err);
    }

    #[test]
    fn an_identity_without_any_key_usage_is_not_refused_for_it() {
        let (ca, ca_key) = root(
            "Chain CA",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_usages(),
        );
        let (id, _) = issued("Identity", IsCa::ExplicitNoCa, vec![], (&ca, &ca_key));
        validate_certificate_chain(id.pem().as_bytes(), &ca_bundle(&[&ca]), None)
            .expect("absent KeyUsage is no restriction");
    }

    /// A CA that rolled its key keeps its name. The trust store may hold a
    /// same-named entry first that did not sign this certificate: the entry that
    /// verifies the signature is the issuer, whatever comes before it.
    #[test]
    fn a_same_named_anchor_that_did_not_sign_does_not_hide_the_real_ca() {
        let (real, real_key) = root(
            "Rolled CA",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_usages(),
        );
        let (old, _) = root("Rolled CA", IsCa::ExplicitNoCa, identity_usages());
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&real, &real_key),
        );
        validate_certificate_chain(id.pem().as_bytes(), &ca_bundle(&[&old, &real]), None)
            .expect("the CA that signed it is in the store, second");
    }

    /// `issued`, with a notAfter in 2020: an expired certificate.
    fn issued_expired(
        common_name: &str,
        is_ca: IsCa,
        issuer: (&rcgen::Certificate, &KeyPair),
    ) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name = named(common_name);
        params.is_ca = is_ca;
        params.key_usages = ca_usages();
        params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        let key = KeyPair::generate().expect("key");
        let cert = params
            .signed_by(&key, issuer.0, issuer.1)
            .expect("signed by the issuer");
        (cert, key)
    }

    fn ca_is(limit: Option<u8>) -> IsCa {
        match limit {
            Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
            None => IsCa::Ca(BasicConstraints::Unconstrained),
        }
    }

    /// The identity presented with `intermediates` after it, as a peer sends it.
    fn presented(leaf: &rcgen::Certificate, intermediates: &[&rcgen::Certificate]) -> Vec<u8> {
        let mut pem = leaf.pem().into_bytes();
        for cert in intermediates {
            pem.extend(cert.pem().into_bytes());
        }
        pem
    }

    /// Depth 2: root, one subordinate CA, the identity. The subordinate is
    /// presented by the peer and is not in the trust store.
    #[test]
    fn an_identity_chaining_through_one_subordinate_ca_is_accepted() {
        let (root, root_key) = root("Chain root", ca_is(None), ca_usages());
        let (sub, sub_key) = issued("Subordinate", ca_is(None), ca_usages(), (&root, &root_key));
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&sub, &sub_key),
        );
        validate_certificate_chain(&presented(&id, &[&sub]), &ca_bundle(&[&root]), None)
            .expect("the path identity, subordinate, root is complete");
    }

    /// Depth 3: root, two subordinate CAs, the identity, all presented.
    #[test]
    fn an_identity_chaining_through_two_subordinate_cas_is_accepted() {
        let (root, root_key) = root("Chain root", ca_is(None), ca_usages());
        let (sub1, sub1_key) = issued(
            "Subordinate 1",
            ca_is(None),
            ca_usages(),
            (&root, &root_key),
        );
        let (sub2, sub2_key) = issued(
            "Subordinate 2",
            ca_is(None),
            ca_usages(),
            (&sub1, &sub1_key),
        );
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&sub2, &sub2_key),
        );
        validate_certificate_chain(&presented(&id, &[&sub2, &sub1]), &ca_bundle(&[&root]), None)
            .expect("the path identity, sub2, sub1, root is complete");
    }

    /// The intermediate is needed: without it the identity does not chain.
    #[test]
    fn an_identity_whose_intermediate_is_not_presented_is_refused() {
        let (root, root_key) = root("Chain root", ca_is(None), ca_usages());
        let (sub, sub_key) = issued("Subordinate", ca_is(None), ca_usages(), (&root, &root_key));
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&sub, &sub_key),
        );
        validate_certificate_chain(id.pem().as_bytes(), &ca_bundle(&[&root]), None).expect_err(
            "nothing in the trust store or the presentation vouches for the subordinate",
        );
    }

    /// RFC 5280 4.2.1.9: root pathLenConstraint 1 allows one intermediate below
    /// it. Path below root: sub1, sub2. That is two: refused.
    #[test]
    fn a_pathlen_constraint_below_the_allowed_depth_is_refused() {
        let (root, root_key) = root("Chain root", ca_is(Some(1)), ca_usages());
        let (sub1, sub1_key) = issued(
            "Subordinate 1",
            ca_is(None),
            ca_usages(),
            (&root, &root_key),
        );
        let (sub2, sub2_key) = issued(
            "Subordinate 2",
            ca_is(None),
            ca_usages(),
            (&sub1, &sub1_key),
        );
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&sub2, &sub2_key),
        );
        let err = validate_certificate_chain(
            &presented(&id, &[&sub2, &sub1]),
            &ca_bundle(&[&root]),
            None,
        )
        .expect_err("two intermediates under a pathLenConstraint of one");
        assert!(
            err.to_string().contains("pathLenConstraint"),
            "got: {}",
            err
        );
    }

    /// Positive control for the rule above: the same path under a root that
    /// allows two intermediates is accepted.
    #[test]
    fn a_pathlen_constraint_that_allows_the_depth_is_accepted() {
        let (root, root_key) = root("Chain root", ca_is(Some(2)), ca_usages());
        let (sub1, sub1_key) = issued(
            "Subordinate 1",
            ca_is(None),
            ca_usages(),
            (&root, &root_key),
        );
        let (sub2, sub2_key) = issued(
            "Subordinate 2",
            ca_is(None),
            ca_usages(),
            (&sub1, &sub1_key),
        );
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&sub2, &sub2_key),
        );
        validate_certificate_chain(&presented(&id, &[&sub2, &sub1]), &ca_bundle(&[&root]), None)
            .expect("two intermediates under a pathLenConstraint of two");
    }

    /// The intermediate between root and identity has pathLenConstraint 0 and
    /// still issues the identity, with a further CA between them: refused.
    #[test]
    fn an_intermediate_with_pathlen_zero_below_another_ca_is_refused() {
        let (root, root_key) = root("Chain root", ca_is(None), ca_usages());
        let (sub1, sub1_key) = issued(
            "Subordinate 1",
            ca_is(Some(0)),
            ca_usages(),
            (&root, &root_key),
        );
        let (sub2, sub2_key) = issued(
            "Subordinate 2",
            ca_is(None),
            ca_usages(),
            (&sub1, &sub1_key),
        );
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&sub2, &sub2_key),
        );
        let err = validate_certificate_chain(
            &presented(&id, &[&sub2, &sub1]),
            &ca_bundle(&[&root]),
            None,
        )
        .expect_err("sub1 allows no CA below it, sub2 is one");
        assert!(
            err.to_string().contains("pathLenConstraint"),
            "got: {}",
            err
        );
    }

    /// A certificate that is not a CA may not issue the identity, even when the
    /// peer presents it as an intermediate.
    #[test]
    fn a_non_ca_presented_as_an_intermediate_is_refused() {
        let (root, root_key) = root("Chain root", ca_is(None), ca_usages());
        let (mid, mid_key) = issued(
            "Not a CA",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&root, &root_key),
        );
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&mid, &mid_key),
        );
        let err = validate_certificate_chain(&presented(&id, &[&mid]), &ca_bundle(&[&root]), None)
            .expect_err("a leaf may not issue certificates");
        assert!(err.to_string().contains("not a CA"), "got: {}", err);
    }

    /// Every intermediate's validity period counts, not only the identity's.
    #[test]
    fn an_expired_intermediate_is_refused() {
        let (root, root_key) = root("Chain root", ca_is(None), ca_usages());
        let (sub, sub_key) = issued_expired("Expired subordinate", ca_is(None), (&root, &root_key));
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&sub, &sub_key),
        );
        let err = validate_certificate_chain(&presented(&id, &[&sub]), &ca_bundle(&[&root]), None)
            .expect_err("the subordinate expired in 2020");
        assert!(
            matches!(err, SecurityError::CertificateExpired),
            "got: {:?}",
            err
        );
    }

    /// A CRL from `issuer` listing each certificate in `revoked` (current until 2099).
    fn crl_for(
        issuer: (&rcgen::Certificate, &KeyPair),
        revoked: &[&rcgen::Certificate],
    ) -> Vec<u8> {
        let entries = revoked
            .iter()
            .map(|cert| {
                let serial = x509_parser::parse_x509_certificate(cert.der())
                    .expect("the revoked certificate parses")
                    .1
                    .tbs_certificate
                    .raw_serial()
                    .to_vec();
                RevokedCertParams {
                    serial_number: SerialNumber::from_slice(&serial),
                    revocation_time: rcgen::date_time_ymd(2021, 1, 1),
                    reason_code: None,
                    invalidity_date: None,
                }
            })
            .collect();
        CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2021, 1, 1),
            next_update: rcgen::date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: entries,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(issuer.0, issuer.1)
        .expect("CRL signed by its issuer")
        .pem()
        .expect("CRL is PEM-encodable")
        .into_bytes()
    }

    /// Revocation is checked on every link. The subordinate is revoked by the
    /// root's list; the identity is clean. Only a check of each link refuses it.
    #[test]
    fn a_revoked_intermediate_refuses_the_identity_it_issued() {
        let (root, root_key) = root("Chain root", ca_is(None), ca_usages());
        let (sub, sub_key) = issued("Subordinate", ca_is(None), ca_usages(), (&root, &root_key));
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&sub, &sub_key),
        );
        let mut crls = crl_for((&root, &root_key), &[&sub]);
        crls.extend(crl_for((&sub, &sub_key), &[]));
        let err =
            validate_certificate_chain(&presented(&id, &[&sub]), &ca_bundle(&[&root]), Some(&crls))
                .expect_err("the subordinate is revoked by the root");
        assert!(err.to_string().contains("REVOKED"), "got: {}", err);
    }

    /// Positive control: the same chain with the root's list naming nobody
    /// is accepted.
    #[test]
    fn an_intermediate_the_root_has_not_revoked_is_accepted() {
        let (root, root_key) = root("Chain root", ca_is(None), ca_usages());
        let (sub, sub_key) = issued("Subordinate", ca_is(None), ca_usages(), (&root, &root_key));
        let (id, _) = issued(
            "Identity",
            IsCa::ExplicitNoCa,
            identity_usages(),
            (&sub, &sub_key),
        );
        let mut crls = crl_for((&root, &root_key), &[]);
        crls.extend(crl_for((&sub, &sub_key), &[]));
        validate_certificate_chain(&presented(&id, &[&sub]), &ca_bundle(&[&root]), Some(&crls))
            .expect("nothing on the path is revoked");
    }
}
